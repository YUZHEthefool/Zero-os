//! 系统调用演示模块

use kernel_core::syscall::{syscall_dispatcher, SyscallNumber};

/// 演示基础系统调用
pub fn demo_basic_syscalls() {
    println!("\n=== Basic Syscalls Demo ===\n");
    
    // 演示1: getpid系统调用
    println!("1. Testing sys_getpid...");
    let pid = syscall_dispatcher(
        SyscallNumber::GetPid as u64,
        0, 0, 0, 0, 0, 0
    );
    if pid >= 0 {
        println!("   ✓ Current PID: {}", pid);
    } else {
        println!("   ✗ Failed with error code: {}", pid);
    }
    
    // 演示2: getppid系统调用
    println!("\n2. Testing sys_getppid...");
    let ppid = syscall_dispatcher(
        SyscallNumber::GetPPid as u64,
        0, 0, 0, 0, 0, 0
    );
    if ppid >= 0 {
        println!("   ✓ Parent PID: {}", ppid);
    } else {
        println!("   ✗ Failed with error code: {}", ppid);
    }
    
    // 演示3: write系统调用
    println!("\n3. Testing sys_write...");
    let msg = b"Hello from syscall!\n";
    let result = syscall_dispatcher(
        SyscallNumber::Write as u64,
        1,  // stdout
        msg.as_ptr() as u64,
        msg.len() as u64,
        0, 0, 0
    );
    if result >= 0 {
        println!("   ✓ Wrote {} bytes", result);
    } else {
        println!("   ✗ Failed with error code: {}", result);
    }
    
    println!("\n✓ Basic syscalls demo completed!\n");
}

/// 演示进程管理系统调用
pub fn demo_process_syscalls() {
    println!("\n=== Process Management Syscalls Demo ===\n");
    
    // 演示1: fork系统调用
    println!("1. Testing sys_fork...");
    let child_pid = syscall_dispatcher(
        SyscallNumber::Fork as u64,
        0, 0, 0, 0, 0, 0
    );
    if child_pid >= 0 {
        println!("   ✓ Forked child process with PID: {}", child_pid);
    } else {
        println!("   ✗ Fork failed with error code: {}", child_pid);
    }
    
    // 演示2: yield系统调用
    println!("\n2. Testing sys_yield...");
    let result = syscall_dispatcher(
        SyscallNumber::Yield as u64,
        0, 0, 0, 0, 0, 0
    );
    if result >= 0 {
        println!("   ✓ Yielded CPU successfully");
    } else {
        println!("   ✗ Yield failed with error code: {}", result);
    }
    
    println!("\n✓ Process management syscalls demo completed!\n");
}

/// 演示错误处理
pub fn demo_error_handling() {
    println!("\n=== Error Handling Demo ===\n");
    
    // 演示1: 无效的文件描述符
    println!("1. Testing invalid file descriptor...");
    let msg = b"test";
    let result = syscall_dispatcher(
        SyscallNumber::Write as u64,
        999,  // 无效的fd
        msg.as_ptr() as u64,
        msg.len() as u64,
        0, 0, 0
    );
    if result < 0 {
        println!("   ✓ Correctly returned error code: {} (EBADF)", result);
    } else {
        println!("   ✗ Should have failed but returned: {}", result);
    }
    
    // 演示2: 空指针
    println!("\n2. Testing null pointer...");
    let result = syscall_dispatcher(
        SyscallNumber::Write as u64,
        1,
        0,  // null pointer
        10,
        0, 0, 0
    );
    if result < 0 {
        println!("   ✓ Correctly returned error code: {} (EFAULT)", result);
    } else {
        println!("   ✗ Should have failed but returned: {}", result);
    }
    
    // 演示3: 未实现的系统调用
    println!("\n3. Testing unimplemented syscall...");
    let result = syscall_dispatcher(
        SyscallNumber::Exec as u64,
        0, 0, 0, 0, 0, 0
    );
    if result < 0 {
        println!("   ✓ Correctly returned error code: {} (ENOSYS)", result);
    } else {
        println!("   ✗ Should have failed but returned: {}", result);
    }
    
    println!("\n✓ Error handling demo completed!\n");
}

/// 演示系统调用性能
pub fn demo_syscall_performance() {
    println!("\n=== Syscall Performance Demo ===\n");
    
    println!("1. Benchmarking getpid (lightweight syscall)...");
    let iterations = 1000;
    
    for i in 0..iterations {
        let _pid = syscall_dispatcher(
            SyscallNumber::GetPid as u64,
            0, 0, 0, 0, 0, 0
        );
        
        if i % 100 == 0 {
            print!(".");
        }
    }
    println!("\n   ✓ Completed {} getpid calls", iterations);
    
    println!("\n2. Benchmarking write (I/O syscall)...");
    let msg = b"x";
    for i in 0..100 {
        let _result = syscall_dispatcher(
            SyscallNumber::Write as u64,
            1,
            msg.as_ptr() as u64,
            msg.len() as u64,
            0, 0, 0
        );
        
        if i % 10 == 0 {
            print!(".");
        }
    }
    println!("\n   ✓ Completed 100 write calls");
    
    println!("\n✓ Performance demo completed!\n");
}

/// 运行所有系统调用演示
pub fn run_all_demos() {
    demo_basic_syscalls();
    demo_process_syscalls();
    demo_error_handling();
    demo_syscall_performance();
}