//! 进程间通信 (IPC) 系统
//!
//! 实现基于能力的端点通信，提供：
//! - 每进程端点命名空间隔离
//! - 基于能力的访问控制（allowed_senders）
//! - 不可伪造的发送者身份（自动从current_pid获取）
//! - 有界消息队列（防止OOM）
//! - 背压机制（队列满时返回错误）

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::process::{self, ProcessId};

/// 端点标识符类型
pub type EndpointId = u64;

/// 每个端点的最大消息数量（背压阈值）
const MAX_MESSAGES_PER_ENDPOINT: usize = 64;

/// 每个进程可注册的最大端点数
const MAX_ENDPOINTS_PER_PROCESS: usize = 32;

/// 单条消息最大数据长度（字节）
const MAX_MESSAGE_SIZE: usize = 4096;

/// IPC消息
#[derive(Debug, Clone)]
pub struct Message {
    /// 发送者进程ID（由系统自动填充，不可伪造）
    pub sender: ProcessId,
    /// 消息数据
    pub data: Vec<u8>,
}

/// 接收到的消息
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// 发送者进程ID
    pub sender: ProcessId,
    /// 消息数据
    pub data: Vec<u8>,
}

/// IPC错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// 没有当前进程上下文
    NoCurrentProcess,
    /// 端点不存在
    EndpointNotFound,
    /// 访问被拒绝（无发送权限或非端点所有者）
    AccessDenied,
    /// 消息队列已满（背压）
    QueueFull,
    /// 消息过大
    MessageTooLarge,
    /// 端点数量超限
    TooManyEndpoints,
}

/// IPC端点
///
/// 每个端点属于一个进程（owner），只有owner可以接收消息。
/// 发送权限通过allowed_senders白名单控制。
#[derive(Debug)]
struct Endpoint {
    /// 端点所有者进程ID
    owner: ProcessId,
    /// 允许发送消息的进程ID集合
    allowed_senders: BTreeSet<ProcessId>,
    /// 消息队列
    queue: VecDeque<Message>,
}

impl Endpoint {
    /// 创建新端点
    fn new(owner: ProcessId, allowed_senders: &[ProcessId]) -> Self {
        let mut allowed = BTreeSet::new();
        // 所有者总是可以发送（给自己）
        allowed.insert(owner);
        for pid in allowed_senders {
            allowed.insert(*pid);
        }

        Endpoint {
            owner,
            allowed_senders: allowed,
            queue: VecDeque::new(),
        }
    }

    /// 检查进程是否有发送权限
    fn can_send(&self, sender: ProcessId) -> bool {
        self.allowed_senders.contains(&sender)
    }

    /// 授权另一个进程发送
    fn grant_access(&mut self, pid: ProcessId) {
        self.allowed_senders.insert(pid);
    }

    /// 撤销另一个进程的发送权限
    fn revoke_access(&mut self, pid: ProcessId) {
        // 所有者权限不可撤销
        if pid != self.owner {
            self.allowed_senders.remove(&pid);
        }
    }

    /// 推送消息到队列
    fn push_message(&mut self, msg: Message) -> Result<(), IpcError> {
        if self.queue.len() >= MAX_MESSAGES_PER_ENDPOINT {
            return Err(IpcError::QueueFull);
        }
        self.queue.push_back(msg);
        Ok(())
    }
}

/// 全局端点注册表
#[derive(Default)]
struct EndpointRegistry {
    /// 每进程端点表: ProcessId -> (EndpointId -> Endpoint)
    per_process: BTreeMap<ProcessId, BTreeMap<EndpointId, Endpoint>>,
    /// 端点到所有者的索引: EndpointId -> ProcessId
    owner_index: BTreeMap<EndpointId, ProcessId>,
}

impl EndpointRegistry {
    /// 注册新端点
    fn register_endpoint(
        &mut self,
        owner: ProcessId,
        allowed_senders: &[ProcessId],
    ) -> Result<EndpointId, IpcError> {
        // 检查端点数量限制
        let process_endpoints = self.per_process.entry(owner).or_default();
        if process_endpoints.len() >= MAX_ENDPOINTS_PER_PROCESS {
            return Err(IpcError::TooManyEndpoints);
        }

        let endpoint_id = NEXT_ENDPOINT_ID.fetch_add(1, Ordering::SeqCst);
        let endpoint = Endpoint::new(owner, allowed_senders);

        process_endpoints.insert(endpoint_id, endpoint);
        self.owner_index.insert(endpoint_id, owner);

        Ok(endpoint_id)
    }

    /// 获取端点的可变引用
    fn endpoint_mut(&mut self, endpoint_id: EndpointId) -> Option<&mut Endpoint> {
        let owner = *self.owner_index.get(&endpoint_id)?;
        self.per_process
            .get_mut(&owner)
            .and_then(|table| table.get_mut(&endpoint_id))
    }

    /// 获取端点的不可变引用
    fn endpoint(&self, endpoint_id: EndpointId) -> Option<&Endpoint> {
        let owner = *self.owner_index.get(&endpoint_id)?;
        self.per_process
            .get(&owner)
            .and_then(|table| table.get(&endpoint_id))
    }

    /// 删除端点
    fn remove_endpoint(&mut self, endpoint_id: EndpointId) -> bool {
        if let Some(owner) = self.owner_index.remove(&endpoint_id) {
            if let Some(table) = self.per_process.get_mut(&owner) {
                table.remove(&endpoint_id);
                return true;
            }
        }
        false
    }

    /// 清理进程的所有端点（进程退出时调用）
    fn cleanup_process(&mut self, pid: ProcessId) {
        if let Some(endpoints) = self.per_process.remove(&pid) {
            for endpoint_id in endpoints.keys() {
                self.owner_index.remove(endpoint_id);
            }
        }
    }
}

/// 下一个可用的端点ID
static NEXT_ENDPOINT_ID: AtomicU64 = AtomicU64::new(1);

lazy_static::lazy_static! {
    /// 全局端点注册表
    static ref ENDPOINTS: Mutex<EndpointRegistry> = Mutex::new(EndpointRegistry::default());
}

/// 初始化IPC系统
pub fn init() {
    println!("IPC system initialized (capability-based endpoints)");
}

/// 注册新端点
///
/// 当前进程成为端点的所有者，只有所有者可以接收消息。
///
/// # Arguments
///
/// * `allowed_senders` - 允许发送消息的进程ID列表（所有者自动包含）
///
/// # Returns
///
/// 成功返回端点ID，失败返回错误
///
/// # Errors
///
/// * `NoCurrentProcess` - 无当前进程上下文
/// * `TooManyEndpoints` - 端点数量超过限制
pub fn register_endpoint(allowed_senders: &[ProcessId]) -> Result<EndpointId, IpcError> {
    let owner = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    ENDPOINTS.lock().register_endpoint(owner, allowed_senders)
}

/// 发送消息到端点
///
/// 发送者身份自动从当前进程获取，不可伪造。
///
/// # Arguments
///
/// * `endpoint_id` - 目标端点ID
/// * `data` - 消息数据
///
/// # Returns
///
/// 成功返回`Ok(())`，失败返回错误
///
/// # Errors
///
/// * `NoCurrentProcess` - 无当前进程上下文
/// * `EndpointNotFound` - 端点不存在
/// * `AccessDenied` - 当前进程无发送权限
/// * `QueueFull` - 端点消息队列已满
/// * `MessageTooLarge` - 消息数据超过大小限制
pub fn send_message(endpoint_id: EndpointId, data: Vec<u8>) -> Result<(), IpcError> {
    // 自动获取发送者身份（不可伪造）
    let sender = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;

    // 检查消息大小
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(IpcError::MessageTooLarge);
    }

    let mut registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint_mut(endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    // 检查发送权限
    if !endpoint.can_send(sender) {
        return Err(IpcError::AccessDenied);
    }

    endpoint.push_message(Message { sender, data })
}

/// 接收消息
///
/// 只有端点所有者可以接收消息。
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
///
/// # Returns
///
/// * `Ok(Some(msg))` - 成功接收消息
/// * `Ok(None)` - 队列为空
/// * `Err(...)` - 发生错误
///
/// # Errors
///
/// * `NoCurrentProcess` - 无当前进程上下文
/// * `EndpointNotFound` - 端点不存在
/// * `AccessDenied` - 当前进程不是端点所有者
pub fn receive_message(endpoint_id: EndpointId) -> Result<Option<ReceivedMessage>, IpcError> {
    let receiver = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;

    let mut registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint_mut(endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    // 只有所有者可以接收
    if endpoint.owner != receiver {
        return Err(IpcError::AccessDenied);
    }

    Ok(endpoint.queue.pop_front().map(|msg| ReceivedMessage {
        sender: msg.sender,
        data: msg.data,
    }))
}

/// 授权进程发送权限
///
/// 只有端点所有者可以授权。
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
/// * `pid` - 要授权的进程ID
pub fn grant_access(endpoint_id: EndpointId, pid: ProcessId) -> Result<(), IpcError> {
    let owner = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;

    let mut registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint_mut(endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    if endpoint.owner != owner {
        return Err(IpcError::AccessDenied);
    }

    endpoint.grant_access(pid);
    Ok(())
}

/// 撤销进程发送权限
///
/// 只有端点所有者可以撤销。所有者自身的权限不可撤销。
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
/// * `pid` - 要撤销权限的进程ID
pub fn revoke_access(endpoint_id: EndpointId, pid: ProcessId) -> Result<(), IpcError> {
    let owner = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;

    let mut registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint_mut(endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    if endpoint.owner != owner {
        return Err(IpcError::AccessDenied);
    }

    endpoint.revoke_access(pid);
    Ok(())
}

/// 删除端点
///
/// 只有端点所有者可以删除。
pub fn destroy_endpoint(endpoint_id: EndpointId) -> Result<(), IpcError> {
    let owner = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;

    let registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint(endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    if endpoint.owner != owner {
        return Err(IpcError::AccessDenied);
    }

    drop(registry);
    ENDPOINTS.lock().remove_endpoint(endpoint_id);
    Ok(())
}

/// 清理进程的所有端点（进程退出时调用）
///
/// 此函数应在进程终止时由进程管理子系统调用。
pub fn cleanup_process_endpoints(pid: ProcessId) {
    ENDPOINTS.lock().cleanup_process(pid);
}

/// 获取端点队列中的消息数量
pub fn get_queue_length(endpoint_id: EndpointId) -> Result<usize, IpcError> {
    let receiver = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;

    let registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint(endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    // 只有所有者可以查看队列状态
    if endpoint.owner != receiver {
        return Err(IpcError::AccessDenied);
    }

    Ok(endpoint.queue.len())
}
