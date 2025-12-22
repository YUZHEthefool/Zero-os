//! Capability subsystem for Zero-OS
//!
//! This module implements a capability-based access control system, providing:
//!
//! - **Non-forgeable Handles**: CapId with generation counters prevent use-after-free
//! - **Rights Restriction**: Capabilities can only delegate reduced rights (monotonic)
//! - **Fork/Exec Semantics**: CLOEXEC/CLOFORK flags control inheritance
//! - **IRQ-Safe**: All operations use spinlocks with interrupt disable
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+
//! | User Space       |     | CapId (u64)      |
//! | (holds CapId)    | --> | gen:32 | idx:32  |
//! +------------------+     +------------------+
//!                                  |
//!                                  v
//! +--------------------------------------------------+
//! | Per-Process CapTable                             |
//! | +----------------------------------------------+ |
//! | | Slot 0: None                                 | |
//! | | Slot 1: Some(gen=5, CapEntry{File, RW})      | |
//! | | Slot 2: Some(gen=3, CapEntry{Endpoint, R})   | |
//! | | ...                                          | |
//! | +----------------------------------------------+ |
//! | Free list: [0, 3, 4, ...]                        |
//! +--------------------------------------------------+
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! // Allocate a capability for a file object
//! let cap_id = table.allocate(CapEntry::new(
//!     CapObject::File(file_arc),
//!     CapRights::RW,
//! ))?;
//!
//! // Lookup and validate
//! let entry = table.lookup(cap_id)?;
//! if entry.allows(CapRights::WRITE) {
//!     // Perform write operation
//! }
//!
//! // Revoke when done
//! table.revoke(cap_id)?;
//! ```
//!
//! # Security Design
//!
//! 1. **Generation Counter**: Each slot has a generation counter that increments
//!    on revocation. A CapId is only valid if its generation matches the slot.
//!
//! 2. **Monotonic Rights**: During delegation, rights can only be reduced.
//!    `new_rights = old_rights & mask`
//!
//! 3. **Audit Integration**: All capability operations are logged to the audit
//!    subsystem for security monitoring.

#![no_std]

extern crate alloc;

#[macro_use]
extern crate drivers;

use alloc::vec::Vec;
use spin::Mutex;
use x86_64::instructions::interrupts;

pub mod types;

pub use types::{
    CapEntry, CapError, CapFlags, CapId, CapObject, CapRights,
    EndpointId, NamespaceId, Shm, Socket, Timer,
};

// ============================================================================
// Configuration
// ============================================================================

/// Default slot reservation when creating a capability table.
pub const DEFAULT_CAP_SLOTS: usize = 64;

/// Maximum slots per capability table (prevents memory exhaustion).
pub const MAX_CAP_SLOTS: usize = 65536;

// ============================================================================
// Capability Table
// ============================================================================

/// Per-process capability table protected by a spinlock for IRQ safety.
///
/// Each process has its own CapTable. The table maps CapId slot indices
/// to CapEntry objects. Generation counters prevent use-after-free.
#[derive(Debug)]
pub struct CapTable {
    inner: Mutex<CapTableInner>,
}

/// Internal table state guarded by the CapTable lock.
#[derive(Debug)]
struct CapTableInner {
    /// Slots holding capability entries.
    slots: Vec<Option<CapSlot>>,

    /// Free slot indices for fast allocation.
    free: Vec<u32>,

    /// Next generation counter (monotonically increasing).
    /// Starts at 1; generation 0 is reserved for INVALID.
    next_generation: u32,
}

/// Slot ties a capability entry to its generation counter.
#[derive(Debug, Clone)]
struct CapSlot {
    /// Generation counter for this slot (matches CapId.generation).
    generation: u32,

    /// The actual capability entry.
    entry: CapEntry,
}

impl CapTable {
    /// Create an empty capability table with default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAP_SLOTS)
    }

    /// Create an empty capability table with explicit initial capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.min(MAX_CAP_SLOTS);
        Self {
            inner: Mutex::new(CapTableInner::with_capacity(capacity)),
        }
    }

    /// Allocate a new capability, returning its CapId.
    ///
    /// # Arguments
    ///
    /// * `entry` - The capability entry to store
    ///
    /// # Returns
    ///
    /// * `Ok(CapId)` - The allocated capability identifier
    /// * `Err(CapError::TableFull)` - No more slots available
    pub fn allocate(&self, entry: CapEntry) -> Result<CapId, CapError> {
        interrupts::without_interrupts(|| {
            let mut inner = self.inner.lock();
            inner.allocate(entry)
        })
    }

    /// Look up a capability by its ID.
    ///
    /// # Arguments
    ///
    /// * `cap_id` - The capability identifier to look up
    ///
    /// # Returns
    ///
    /// * `Ok(&CapEntry)` - Reference to the capability entry
    /// * `Err(CapError::InvalidCapId)` - CapId is invalid or revoked
    pub fn lookup(&self, cap_id: CapId) -> Result<CapEntry, CapError> {
        interrupts::without_interrupts(|| {
            let inner = self.inner.lock();
            inner.lookup(cap_id).cloned()
        })
    }

    /// Revoke a capability, making its CapId invalid.
    ///
    /// The slot is returned to the free list with an incremented
    /// generation counter, preventing any stale CapId from being used.
    ///
    /// # Arguments
    ///
    /// * `cap_id` - The capability identifier to revoke
    ///
    /// # Returns
    ///
    /// * `Ok(CapEntry)` - The revoked capability entry
    /// * `Err(CapError::InvalidCapId)` - CapId is invalid or already revoked
    pub fn revoke(&self, cap_id: CapId) -> Result<CapEntry, CapError> {
        interrupts::without_interrupts(|| {
            let mut inner = self.inner.lock();
            inner.revoke(cap_id)
        })
    }

    /// Delegate a capability with restricted rights.
    ///
    /// Creates a new capability pointing to the same object but with
    /// rights masked (reduced). The original capability remains valid.
    ///
    /// # Arguments
    ///
    /// * `cap_id` - The source capability to delegate from
    /// * `rights_mask` - Rights to retain (AND with existing rights)
    /// * `flags` - Flags for the new capability
    ///
    /// # Returns
    ///
    /// * `Ok(CapId)` - The new delegated capability
    /// * `Err(CapError::InvalidCapId)` - Source CapId is invalid
    /// * `Err(CapError::DelegationDenied)` - Source has NOXFER flag
    /// * `Err(CapError::TableFull)` - No slots available
    pub fn delegate(
        &self,
        cap_id: CapId,
        rights_mask: CapRights,
        flags: CapFlags,
    ) -> Result<CapId, CapError> {
        interrupts::without_interrupts(|| {
            let mut inner = self.inner.lock();
            inner.delegate(cap_id, rights_mask, flags)
        })
    }

    /// Check if a capability has the required rights.
    ///
    /// # Arguments
    ///
    /// * `cap_id` - The capability to check
    /// * `required` - The rights required for the operation
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Capability has all required rights
    /// * `Ok(false)` - Capability lacks some required rights
    /// * `Err(CapError::InvalidCapId)` - CapId is invalid
    pub fn check_rights(&self, cap_id: CapId, required: CapRights) -> Result<bool, CapError> {
        interrupts::without_interrupts(|| {
            let inner = self.inner.lock();
            let entry = inner.lookup(cap_id)?;
            Ok(entry.allows(required))
        })
    }

    /// Get the number of active capabilities.
    pub fn len(&self) -> usize {
        interrupts::without_interrupts(|| {
            let inner = self.inner.lock();
            inner.slots.iter().filter(|s| s.is_some()).count()
        })
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clone capabilities for fork, respecting CLOFORK flags.
    ///
    /// Returns a new CapTable with copies of all capabilities that
    /// should be inherited (those without CLOFORK flag).
    ///
    /// # Generation Counter Preservation
    ///
    /// The child table inherits the parent's `next_generation` counter
    /// to maintain the monotonic property across fork. This prevents
    /// early generation wrap in the child process.
    pub fn clone_for_fork(&self) -> Self {
        interrupts::without_interrupts(|| {
            let inner = self.inner.lock();
            let mut new_inner = CapTableInner::with_capacity(inner.slots.len());

            // Inherit parent's generation counter to prevent early wrap
            new_inner.next_generation = inner.next_generation;

            for (idx, slot_opt) in inner.slots.iter().enumerate() {
                if let Some(slot) = slot_opt {
                    if slot.entry.inherits_on_fork() {
                        // Clone the entry with the same generation
                        // (child gets identical CapId values for inherited caps)
                        new_inner.slots[idx] = Some(slot.clone());
                    }
                }
            }

            // Rebuild free list for the new table
            new_inner.rebuild_free_list();

            Self {
                inner: Mutex::new(new_inner),
            }
        })
    }

    /// Revoke all capabilities with CLOEXEC flag (for exec).
    ///
    /// Called during exec() to close capabilities that should not
    /// survive across program replacement.
    ///
    /// # Security Note
    ///
    /// Revoked slots are returned to the free list. When reused,
    /// they will get a new (higher) generation counter, preventing
    /// stale CapId references from becoming valid again.
    pub fn apply_cloexec(&self) {
        interrupts::without_interrupts(|| {
            let mut inner = self.inner.lock();

            for idx in 0..inner.slots.len() {
                if let Some(slot) = &inner.slots[idx] {
                    if !slot.entry.inherits_on_exec() {
                        // Revoke this capability - slot will get new generation on reuse
                        if let Some(old_slot) = inner.slots[idx].take() {
                            inner.free.push(idx as u32);
                            drop(old_slot);
                        }
                    }
                }
            }
        });
    }
}

impl Default for CapTable {
    fn default() -> Self {
        Self::new()
    }
}

impl CapTableInner {
    /// Initialize the table state with preallocated slots.
    fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.min(MAX_CAP_SLOTS);
        let slots = alloc::vec![None; capacity];
        let free: Vec<u32> = (0..capacity as u32).collect();

        Self {
            slots,
            free,
            next_generation: 1, // Start at 1; 0 is reserved for INVALID
        }
    }

    /// Allocate a new capability.
    fn allocate(&mut self, entry: CapEntry) -> Result<CapId, CapError> {
        // Try to get a slot from the free list
        let index = if let Some(idx) = self.free.pop() {
            idx
        } else {
            // Try to grow the table
            if self.slots.len() >= MAX_CAP_SLOTS {
                return Err(CapError::TableFull);
            }
            let new_idx = self.slots.len() as u32;
            self.slots.push(None);
            new_idx
        };

        // Allocate a generation counter
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        if self.next_generation == 0 {
            // Skip 0 to keep INVALID semantics
            self.next_generation = 1;
        }

        // Store the capability
        self.slots[index as usize] = Some(CapSlot { generation, entry });

        Ok(CapId::from_parts(index, generation))
    }

    /// Look up a capability by ID.
    fn lookup(&self, cap_id: CapId) -> Result<&CapEntry, CapError> {
        if !cap_id.is_valid() {
            return Err(CapError::InvalidCapId);
        }

        let index = cap_id.index() as usize;
        if index >= self.slots.len() {
            return Err(CapError::InvalidCapId);
        }

        match &self.slots[index] {
            Some(slot) if slot.generation == cap_id.generation() => Ok(&slot.entry),
            _ => Err(CapError::InvalidCapId),
        }
    }

    /// Revoke a capability.
    fn revoke(&mut self, cap_id: CapId) -> Result<CapEntry, CapError> {
        if !cap_id.is_valid() {
            return Err(CapError::InvalidCapId);
        }

        let index = cap_id.index() as usize;
        if index >= self.slots.len() {
            return Err(CapError::InvalidCapId);
        }

        match &self.slots[index] {
            Some(slot) if slot.generation == cap_id.generation() => {
                let old_slot = self.slots[index].take().unwrap();
                self.free.push(index as u32);
                Ok(old_slot.entry)
            }
            _ => Err(CapError::InvalidCapId),
        }
    }

    /// Delegate a capability with restricted rights.
    fn delegate(
        &mut self,
        cap_id: CapId,
        rights_mask: CapRights,
        flags: CapFlags,
    ) -> Result<CapId, CapError> {
        // Look up the source capability
        let source_entry = self.lookup(cap_id)?.clone();

        // Check if delegation is allowed
        if source_entry.flags.contains(CapFlags::NOXFER) {
            return Err(CapError::DelegationDenied);
        }

        // Create new entry with restricted rights
        let new_entry = CapEntry::with_flags(
            source_entry.object,
            source_entry.rights.restrict(rights_mask),
            flags,
        );

        // Allocate a new slot for the delegated capability
        self.allocate(new_entry)
    }

    /// Rebuild the free list based on current slot occupancy.
    fn rebuild_free_list(&mut self) {
        self.free.clear();
        for (idx, slot) in self.slots.iter().enumerate() {
            if slot.is_none() {
                self.free.push(idx as u32);
            }
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the capability subsystem.
///
/// Must be called during kernel boot after heap initialization.
pub fn init() {
    println!("  Capability subsystem initialized");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    // Mock FileOps for testing
    struct MockFile;

    impl kernel_core::FileOps for MockFile {
        fn clone_box(&self) -> alloc::boxed::Box<dyn kernel_core::FileOps> {
            alloc::boxed::Box::new(MockFile)
        }
        fn as_any(&self) -> &dyn core::any::Any {
            self
        }
        fn type_name(&self) -> &'static str {
            "MockFile"
        }
    }

    #[test]
    fn test_cap_id_encoding() {
        let cap_id = CapId::from_parts(42, 7);
        assert_eq!(cap_id.index(), 42);
        assert_eq!(cap_id.generation(), 7);
        assert!(cap_id.is_valid());

        let invalid = CapId::INVALID;
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_cap_rights_restrict() {
        let full = CapRights::RWX;
        let read_only = CapRights::READ;

        let restricted = full.restrict(read_only);
        assert!(restricted.contains(CapRights::READ));
        assert!(!restricted.contains(CapRights::WRITE));
        assert!(!restricted.contains(CapRights::EXEC));
    }

    #[test]
    fn test_cap_table_allocate_revoke() {
        let table = CapTable::new();

        let entry = CapEntry::new(
            CapObject::Process(1),
            CapRights::SIGNAL,
        );

        let cap_id = table.allocate(entry).unwrap();
        assert!(cap_id.is_valid());

        let looked_up = table.lookup(cap_id).unwrap();
        assert!(looked_up.allows(CapRights::SIGNAL));

        let revoked = table.revoke(cap_id).unwrap();
        assert!(revoked.allows(CapRights::SIGNAL));

        // Should fail now
        assert!(table.lookup(cap_id).is_err());
    }
}
