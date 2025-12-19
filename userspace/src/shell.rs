//! Zero-OS Simple Shell
//!
//! A minimal interactive shell for Zero-OS that demonstrates:
//! - Keyboard input via sys_read
//! - Command parsing
//! - Built-in commands
//!
//! ## Commands
//!
//! - `help` - Show available commands
//! - `echo <text>` - Print text to stdout
//! - `pid` - Show current process ID
//! - `ppid` - Show parent process ID
//! - `clear` - Clear screen (VGA)
//! - `exit` - Exit the shell
//!
//! ## Example Session
//!
//! ```text
//! Zero-OS Shell v0.1
//! Type 'help' for available commands.
//!
//! $ help
//! Available commands:
//!   help  - Show this help message
//!   echo  - Print text (echo <text>)
//!   pid   - Show current process ID
//!   ppid  - Show parent process ID
//!   clear - Clear screen
//!   exit  - Exit shell
//!
//! $ echo Hello, World!
//! Hello, World!
//!
//! $ pid
//! PID: 1
//!
//! $ exit
//! Goodbye!
//! ```

#![no_std]
#![no_main]

use userspace::libc::{
    getchar, memset, print, print_int, println, putchar, strcmp, strlen, strncmp,
};
use userspace::syscall::{sys_exit, sys_getpid, sys_getppid};

/// Maximum command line length
const MAX_CMD_LEN: usize = 128;

/// Shell prompt string
const PROMPT: &str = "$ ";

/// Welcome banner
const BANNER: &str = "\n\
================================\n\
   Zero-OS Shell v0.1\n\
================================\n\
Type 'help' for available commands.\n\
";

/// Help message
const HELP_MSG: &str = "\
Available commands:\n\
  help  - Show this help message\n\
  echo  - Print text (echo <text>)\n\
  pid   - Show current process ID\n\
  ppid  - Show parent process ID\n\
  clear - Clear screen\n\
  exit  - Exit shell\n\
";

/// Program entry point
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Print welcome banner
    print(BANNER);

    // Command buffer
    let mut cmd_buf = [0u8; MAX_CMD_LEN];

    // Main shell loop
    loop {
        // Print prompt
        print(PROMPT);

        // Read command line
        let len = read_line(&mut cmd_buf);

        // Skip empty lines
        if len == 0 {
            continue;
        }

        // Parse and execute command
        execute_command(&cmd_buf[..len]);
    }
}

/// Read a line of input from stdin.
///
/// Returns the number of characters read (excluding null terminator).
fn read_line(buf: &mut [u8]) -> usize {
    let max = buf.len().saturating_sub(1);
    let mut i = 0;

    while i < max {
        // Poll for input with throttled yields to reduce syscall overhead
        let c = loop {
            let ch = getchar();
            if ch >= 0 {
                break ch as u8;
            }
            // Yield to let other processes run and reduce CPU spin
            // The kernel will reschedule us when input arrives
            unsafe {
                let _ = userspace::syscall::sys_yield();
            }
        };

        match c {
            // Enter - end of line
            b'\n' | b'\r' => {
                putchar(b'\n');
                break;
            }
            // Backspace
            0x7F | 0x08 => {
                if i > 0 {
                    i -= 1;
                    // Echo backspace sequence
                    putchar(0x08);
                    putchar(b' ');
                    putchar(0x08);
                }
            }
            // Ctrl+C - cancel line
            0x03 => {
                println("^C");
                return 0;
            }
            // Ctrl+D - EOF (exit on empty line)
            0x04 => {
                if i == 0 {
                    println("");
                    do_exit();
                }
            }
            // Printable character
            _ if c >= 0x20 && c < 0x7F => {
                buf[i] = c;
                i += 1;
                putchar(c);
            }
            // Ignore other characters
            _ => {}
        }
    }

    // Null terminate
    buf[i] = 0;
    i
}

/// Execute a command.
fn execute_command(cmd: &[u8]) {
    // Skip leading whitespace
    let cmd = skip_whitespace(cmd);

    if cmd.is_empty() || cmd[0] == 0 {
        return;
    }

    // Match commands
    unsafe {
        if strncmp(cmd.as_ptr(), b"help\0".as_ptr(), 4) == 0 && is_end(cmd, 4) {
            do_help();
        } else if strncmp(cmd.as_ptr(), b"echo \0".as_ptr(), 5) == 0 {
            do_echo(&cmd[5..]);
        } else if strncmp(cmd.as_ptr(), b"echo\0".as_ptr(), 4) == 0 && is_end(cmd, 4) {
            println(""); // echo with no args prints newline
        } else if strncmp(cmd.as_ptr(), b"pid\0".as_ptr(), 3) == 0 && is_end(cmd, 3) {
            do_pid();
        } else if strncmp(cmd.as_ptr(), b"ppid\0".as_ptr(), 4) == 0 && is_end(cmd, 4) {
            do_ppid();
        } else if strncmp(cmd.as_ptr(), b"clear\0".as_ptr(), 5) == 0 && is_end(cmd, 5) {
            do_clear();
        } else if strncmp(cmd.as_ptr(), b"exit\0".as_ptr(), 4) == 0 && is_end(cmd, 4) {
            do_exit();
        } else {
            // Unknown command
            print("Unknown command: ");
            print_until_space(cmd);
            println("");
            println("Type 'help' for available commands.");
        }
    }
}

/// Skip leading whitespace in a byte slice.
fn skip_whitespace(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || s[i] == b'\t') {
        i += 1;
    }
    &s[i..]
}

/// Check if position `n` in command is end of word (space, null, or end of slice).
fn is_end(cmd: &[u8], n: usize) -> bool {
    n >= cmd.len() || cmd[n] == 0 || cmd[n] == b' ' || cmd[n] == b'\t'
}

/// Print bytes until space or null terminator.
fn print_until_space(s: &[u8]) {
    for &c in s {
        if c == 0 || c == b' ' || c == b'\t' {
            break;
        }
        putchar(c);
    }
}

// ============================================================================
// Command Implementations
// ============================================================================

/// Show help message.
fn do_help() {
    print(HELP_MSG);
}

/// Echo text to stdout.
fn do_echo(args: &[u8]) {
    let args = skip_whitespace(args);
    for &c in args {
        if c == 0 {
            break;
        }
        putchar(c);
    }
    putchar(b'\n');
}

/// Show current PID.
fn do_pid() {
    let pid = unsafe { sys_getpid() };
    print("PID: ");
    print_int(pid as i64);
    println("");
}

/// Show parent PID.
fn do_ppid() {
    let ppid = unsafe { sys_getppid() };
    print("PPID: ");
    print_int(ppid as i64);
    println("");
}

/// Clear screen (send VGA clear escape or newlines).
fn do_clear() {
    // Simple clear: print many newlines
    // A proper implementation would use ANSI escape codes or direct VGA access
    for _ in 0..25 {
        println("");
    }
}

/// Exit the shell.
fn do_exit() -> ! {
    println("Goodbye!");
    unsafe {
        sys_exit(0);
    }
}
