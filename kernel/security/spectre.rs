//! Spectre/Meltdown Mitigations for Zero-OS
//!
//! This module provides detection and enablement of CPU mitigations for
//! speculative execution vulnerabilities:
//!
//! - **IBRS** (Indirect Branch Restricted Speculation)
//! - **IBPB** (Indirect Branch Predictor Barrier)
//! - **STIBP** (Single Thread Indirect Branch Predictors)
//! - **Retpoline** detection
//!
//! # Security Background
//!
//! Spectre and Meltdown are classes of vulnerabilities that exploit CPU
//! speculative execution to leak sensitive data. This module enables
//! hardware mitigations where available.
//!
//! # CPU Support Detection
//!
//! Uses CPUID leaf 7, subleaf 0 (EDX) to detect:
//! - Bit 26: IBRS/IBPB support
//! - Bit 27: STIBP support
//! - Bit 29: IA32_ARCH_CAPABILITIES MSR support
//!
//! # Usage
//!
//! ```rust,ignore
//! // Initialize mitigations during boot
//! let status = spectre::init()?;
//! if status.hardened() {
//!     println!("Speculative execution hardening enabled");
//! }
//! ```

use x86_64::registers::model_specific::Msr;

/// Status of speculative execution mitigations.
#[derive(Debug, Clone, Copy)]
pub struct MitigationStatus {
    /// IBRS supported by CPU
    pub ibrs_supported: bool,
    /// IBRS currently enabled
    pub ibrs_enabled: bool,
    /// IBPB supported by CPU
    pub ibpb_supported: bool,
    /// STIBP supported by CPU
    pub stibp_supported: bool,
    /// STIBP currently enabled
    pub stibp_enabled: bool,
    /// Compiler retpoline support (compile-time feature)
    pub retpoline_compiler: bool,
    /// Retpoline required (no hardware mitigation)
    pub retpoline_required: bool,
    /// SSBD (Speculative Store Bypass Disable) supported
    pub ssbd_supported: bool,
    /// SSBD enabled
    pub ssbd_enabled: bool,
}

impl MitigationStatus {
    /// Create an empty (no mitigations) status.
    pub fn empty() -> Self {
        MitigationStatus {
            ibrs_supported: false,
            ibrs_enabled: false,
            ibpb_supported: false,
            stibp_supported: false,
            stibp_enabled: false,
            retpoline_compiler: false,
            retpoline_required: false,
            ssbd_supported: false,
            ssbd_enabled: false,
        }
    }

    /// Check if at least one mitigation path is active.
    ///
    /// Returns true if the system has adequate protection against
    /// speculative execution attacks.
    pub fn hardened(&self) -> bool {
        // Branch prediction protection
        let branch_protected =
            self.ibrs_enabled || self.stibp_enabled || self.retpoline_compiler;

        // If retpoline is required but not compiled in, and no hardware fix
        if self.retpoline_required && !self.retpoline_compiler && !self.ibrs_enabled {
            return false;
        }

        branch_protected
    }

    /// Check if any mitigation was enabled.
    pub fn any_enabled(&self) -> bool {
        self.ibrs_enabled || self.stibp_enabled || self.ssbd_enabled
    }

    /// Get a human-readable summary.
    pub fn summary(&self) -> &'static str {
        if self.hardened() {
            "Hardened"
        } else if self.any_enabled() {
            "Partial"
        } else {
            "Vulnerable"
        }
    }
}

/// Errors encountered while enabling mitigations.
#[derive(Debug)]
pub enum SpectreError {
    /// Feature not supported by CPU
    Unsupported(&'static str),
    /// MSR is not available
    MsrUnavailable(&'static str),
    /// Error reading/writing MSR
    MsrIo(&'static str),
    /// Retpoline required but not available
    RetpolineRequired,
}

// ============================================================================
// MSR Constants
// ============================================================================

/// IA32_SPEC_CTRL MSR - Speculation control
const IA32_SPEC_CTRL: u32 = 0x48;
/// IA32_PRED_CMD MSR - Predictor command (write-only)
const IA32_PRED_CMD: u32 = 0x49;
/// IA32_ARCH_CAPABILITIES MSR - Architecture capabilities
const IA32_ARCH_CAPABILITIES: u32 = 0x10A;

// IA32_SPEC_CTRL bits
const SPEC_CTRL_IBRS: u64 = 1 << 0;  // Indirect Branch Restricted Speculation
const SPEC_CTRL_STIBP: u64 = 1 << 1; // Single Thread Indirect Branch Predictors
const SPEC_CTRL_SSBD: u64 = 1 << 2;  // Speculative Store Bypass Disable

// IA32_PRED_CMD bits
const PRED_CMD_IBPB: u64 = 1 << 0;   // Indirect Branch Predictor Barrier

// IA32_ARCH_CAPABILITIES bits
const ARCH_CAP_RDCL_NO: u64 = 1 << 0;     // Not susceptible to Meltdown
const ARCH_CAP_IBRS_ALL: u64 = 1 << 1;    // IBRS covers all predictors
const ARCH_CAP_RSBA: u64 = 1 << 2;        // RSB Alternate (needs mitigation)
const ARCH_CAP_SKIP_L1DFL: u64 = 1 << 3;  // Skip L1D flush on VMENTRY
const ARCH_CAP_SSB_NO: u64 = 1 << 4;      // Not susceptible to SSB
const ARCH_CAP_MDS_NO: u64 = 1 << 5;      // Not susceptible to MDS

// ============================================================================
// Detection Functions
// ============================================================================

/// Detect CPU support for Spectre/Meltdown mitigations.
pub fn detect() -> MitigationStatus {
    let (_, _, _, edx) = cpuid_7_0();

    // IBRS/IBPB support (bit 26)
    let ibrs_ibpb = (edx & (1 << 26)) != 0;
    // STIBP support (bit 27)
    let stibp = (edx & (1 << 27)) != 0;
    // SSBD support (bit 31)
    let ssbd = (edx & (1 << 31)) != 0;
    // IA32_ARCH_CAPABILITIES support (bit 29)
    let has_arch_cap = (edx & (1 << 29)) != 0;

    let mut retpoline_required = !ibrs_ibpb;

    // Check architecture capabilities for better mitigation info
    if has_arch_cap {
        if let Some(capabilities) = read_arch_capabilities() {
            // IBRS_ALL means hardware fully mitigates branch prediction attacks
            if (capabilities & ARCH_CAP_IBRS_ALL) != 0 {
                retpoline_required = false;
            }
            // RDCL_NO means not susceptible to Meltdown
            // SSB_NO means not susceptible to Speculative Store Bypass
            // MDS_NO means not susceptible to Microarchitectural Data Sampling
        }
    }

    MitigationStatus {
        ibrs_supported: ibrs_ibpb,
        ibrs_enabled: false,
        ibpb_supported: ibrs_ibpb,
        stibp_supported: stibp,
        stibp_enabled: false,
        retpoline_compiler: cfg!(feature = "retpoline"),
        retpoline_required,
        ssbd_supported: ssbd,
        ssbd_enabled: false,
    }
}

/// Get detailed CPU vulnerability information.
pub fn get_vulnerabilities() -> VulnerabilityInfo {
    let (_, _, _, edx) = cpuid_7_0();
    let has_arch_cap = (edx & (1 << 29)) != 0;

    let mut info = VulnerabilityInfo {
        meltdown_susceptible: true,
        spectre_v1_susceptible: true,  // Always assume susceptible
        spectre_v2_susceptible: true,
        ssb_susceptible: true,
        mds_susceptible: true,
    };

    if has_arch_cap {
        if let Some(cap) = read_arch_capabilities() {
            info.meltdown_susceptible = (cap & ARCH_CAP_RDCL_NO) == 0;
            info.ssb_susceptible = (cap & ARCH_CAP_SSB_NO) == 0;
            info.mds_susceptible = (cap & ARCH_CAP_MDS_NO) == 0;
            // IBRS_ALL helps with Spectre v2
            if (cap & ARCH_CAP_IBRS_ALL) != 0 {
                info.spectre_v2_susceptible = false;
            }
        }
    }

    info
}

/// CPU vulnerability information.
#[derive(Debug, Clone, Copy)]
pub struct VulnerabilityInfo {
    pub meltdown_susceptible: bool,
    pub spectre_v1_susceptible: bool,
    pub spectre_v2_susceptible: bool,
    pub ssb_susceptible: bool,
    pub mds_susceptible: bool,
}

// ============================================================================
// Initialization and Control Functions
// ============================================================================

/// Initialize available Spectre/Meltdown mitigations.
///
/// This function:
/// 1. Detects CPU capabilities
/// 2. Enables IBRS if supported
/// 3. Enables STIBP if supported
/// 4. Issues IBPB to clear predictor state
/// 5. Enables SSBD if supported
///
/// # Returns
///
/// `MitigationStatus` on success, `SpectreError` if critical mitigation fails.
pub fn init() -> Result<MitigationStatus, SpectreError> {
    let mut status = detect();

    // Enable IBRS (Indirect Branch Restricted Speculation)
    if status.ibrs_supported {
        if enable_ibrs().is_ok() {
            status.ibrs_enabled = true;
        }
    }

    // Enable STIBP (Single Thread Indirect Branch Predictors)
    if status.stibp_supported {
        if enable_stibp().is_ok() {
            status.stibp_enabled = true;
        }
    }

    // Issue IBPB to clear any existing predictor state
    if status.ibpb_supported {
        let _ = issue_ibpb();
    }

    // Enable SSBD (Speculative Store Bypass Disable)
    if status.ssbd_supported {
        if enable_ssbd().is_ok() {
            status.ssbd_enabled = true;
        }
    }

    // Check if we have adequate protection
    if status.retpoline_required && !status.retpoline_compiler && !status.ibrs_enabled {
        return Err(SpectreError::RetpolineRequired);
    }

    Ok(status)
}

/// Enable IBRS by setting IA32_SPEC_CTRL.IBRS.
///
/// IBRS restricts indirect branch prediction to prevent cross-privilege
/// speculation attacks.
pub fn enable_ibrs() -> Result<(), SpectreError> {
    let status = detect();
    if !status.ibrs_supported {
        return Err(SpectreError::Unsupported("IBRS not supported"));
    }

    unsafe {
        let mut msr = Msr::new(IA32_SPEC_CTRL);
        let current = msr.read();
        msr.write(current | SPEC_CTRL_IBRS);
    }

    Ok(())
}

/// Disable IBRS (not recommended for production).
pub fn disable_ibrs() -> Result<(), SpectreError> {
    unsafe {
        let mut msr = Msr::new(IA32_SPEC_CTRL);
        let current = msr.read();
        msr.write(current & !SPEC_CTRL_IBRS);
    }
    Ok(())
}

/// Enable STIBP for single-threaded indirect branch prediction isolation.
///
/// STIBP prevents one logical processor from controlling the branch
/// prediction of a sibling logical processor.
pub fn enable_stibp() -> Result<(), SpectreError> {
    let status = detect();
    if !status.stibp_supported {
        return Err(SpectreError::Unsupported("STIBP not supported"));
    }

    unsafe {
        let mut msr = Msr::new(IA32_SPEC_CTRL);
        let current = msr.read();
        msr.write(current | SPEC_CTRL_STIBP);
    }

    Ok(())
}

/// Enable SSBD (Speculative Store Bypass Disable).
///
/// Prevents speculative bypass of store operations that could leak data.
pub fn enable_ssbd() -> Result<(), SpectreError> {
    let status = detect();
    if !status.ssbd_supported {
        return Err(SpectreError::Unsupported("SSBD not supported"));
    }

    unsafe {
        let mut msr = Msr::new(IA32_SPEC_CTRL);
        let current = msr.read();
        msr.write(current | SPEC_CTRL_SSBD);
    }

    Ok(())
}

/// Issue an Indirect Branch Predictor Barrier.
///
/// Clears all indirect branch predictors, preventing cross-context
/// speculation attacks. Should be called on context switches to
/// untrusted code.
pub fn issue_ibpb() -> Result<(), SpectreError> {
    let status = detect();
    if !status.ibpb_supported {
        return Err(SpectreError::Unsupported("IBPB not supported"));
    }

    unsafe {
        let mut msr = Msr::new(IA32_PRED_CMD);
        msr.write(PRED_CMD_IBPB);
    }

    Ok(())
}

/// Issue IBPB if supported (no error on unsupported).
///
/// Convenience function for context switch code that wants to
/// issue IBPB when available without handling errors.
#[inline]
pub fn try_ibpb() {
    let _ = issue_ibpb();
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

/// Read IA32_ARCH_CAPABILITIES MSR if available.
fn read_arch_capabilities() -> Option<u64> {
    let (_, _, _, edx) = cpuid_7_0();
    if (edx & (1 << 29)) == 0 {
        return None;
    }

    unsafe {
        let msr = Msr::new(IA32_ARCH_CAPABILITIES);
        Some(msr.read())
    }
}

/// Execute CPUID leaf 7, subleaf 0.
fn cpuid_7_0() -> (u32, u32, u32, u32) {
    let mut eax: u32;
    let mut ebx: u32;
    let mut ecx: u32;
    let mut edx: u32;

    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 7",
            "mov ecx, 0",
            "cpuid",
            "mov {0:e}, eax",
            "mov {1:e}, ebx",
            "mov {2:e}, ecx",
            "mov {3:e}, edx",
            "pop rbx",
            out(reg) eax,
            out(reg) ebx,
            out(reg) ecx,
            out(reg) edx,
            options(nomem, nostack)
        );
    }

    (eax, ebx, ecx, edx)
}

/// Check current SPEC_CTRL MSR value.
pub fn read_spec_ctrl() -> u64 {
    unsafe {
        let msr = Msr::new(IA32_SPEC_CTRL);
        msr.read()
    }
}
