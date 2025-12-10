#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;

pub use kernel_core::process;

pub mod ipc;

pub use ipc::{
    cleanup_process_endpoints,
    destroy_endpoint,
    grant_access,
    receive_message,
    register_endpoint,
    revoke_access,
    send_message,
    EndpointId,
    IpcError,
    Message,
    ReceivedMessage,
};

/// 初始化IPC子系统
///
/// 注册进程清理回调，确保进程退出时自动清理其IPC端点。
pub fn init() {
    // 注册IPC清理回调到进程管理子系统
    kernel_core::register_ipc_cleanup(cleanup_process_endpoints);
    ipc::init();
}
