//! System Call Interface
//!
//! All kernel services are accessed through system calls.
//! The syscall ABI uses:
//! - RAX: syscall number
//! - RDI, RSI, RDX, R10, R8, R9: arguments
//! - RAX: return value (or error code)

use crate::{KernelResult, KernelError};

/// System call numbers
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syscall {
    /// Invalid/null syscall
    Null = 0,

    // IPC (1-99)
    /// Send message to endpoint
    Send = 1,
    /// Receive message from endpoint
    Recv = 2,
    /// Send and receive (call)
    Call = 3,
    /// Reply to caller
    Reply = 4,
    /// Wait on notification
    Wait = 5,
    /// Signal notification
    Signal = 6,

    // Capability (100-199)
    /// Create capability
    CapCreate = 100,
    /// Delete capability
    CapDelete = 101,
    /// Copy capability
    CapCopy = 102,
    /// Mint capability (derive with reduced rights)
    CapMint = 103,
    /// Revoke capability
    CapRevoke = 104,

    // Memory (200-299)
    /// Map memory
    MemMap = 200,
    /// Unmap memory
    MemUnmap = 201,
    /// Change protection
    MemProtect = 202,
    /// Allocate physical frame
    MemAlloc = 203,
    /// Free physical frame
    MemFree = 204,

    // Thread (300-399)
    /// Create thread
    ThreadCreate = 300,
    /// Suspend thread
    ThreadSuspend = 301,
    /// Resume thread
    ThreadResume = 302,
    /// Get thread ID
    ThreadId = 303,
    /// Yield CPU
    Yield = 304,
    /// Exit thread
    ThreadExit = 305,

    // Process (400-499)
    /// Create process
    ProcessCreate = 400,
    /// Kill process
    ProcessKill = 401,
    /// Wait for process
    ProcessWait = 402,
    /// Get process ID
    ProcessId = 403,

    // Time (500-599)
    /// Get system time
    TimeGet = 500,
    /// Sleep
    Sleep = 501,

    // Debug (900-999)
    /// Debug print
    DebugPrint = 900,
    /// Kernel info
    KernelInfo = 901,
}

impl TryFrom<u64> for Syscall {
    type Error = KernelError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Syscall::Null),
            1 => Ok(Syscall::Send),
            2 => Ok(Syscall::Recv),
            3 => Ok(Syscall::Call),
            4 => Ok(Syscall::Reply),
            5 => Ok(Syscall::Wait),
            6 => Ok(Syscall::Signal),
            100 => Ok(Syscall::CapCreate),
            101 => Ok(Syscall::CapDelete),
            102 => Ok(Syscall::CapCopy),
            103 => Ok(Syscall::CapMint),
            104 => Ok(Syscall::CapRevoke),
            200 => Ok(Syscall::MemMap),
            201 => Ok(Syscall::MemUnmap),
            202 => Ok(Syscall::MemProtect),
            203 => Ok(Syscall::MemAlloc),
            204 => Ok(Syscall::MemFree),
            300 => Ok(Syscall::ThreadCreate),
            301 => Ok(Syscall::ThreadSuspend),
            302 => Ok(Syscall::ThreadResume),
            303 => Ok(Syscall::ThreadId),
            304 => Ok(Syscall::Yield),
            305 => Ok(Syscall::ThreadExit),
            400 => Ok(Syscall::ProcessCreate),
            401 => Ok(Syscall::ProcessKill),
            402 => Ok(Syscall::ProcessWait),
            403 => Ok(Syscall::ProcessId),
            500 => Ok(Syscall::TimeGet),
            501 => Ok(Syscall::Sleep),
            900 => Ok(Syscall::DebugPrint),
            901 => Ok(Syscall::KernelInfo),
            _ => Err(KernelError::InvalidArgument),
        }
    }
}

/// Syscall handler
///
/// Called from the syscall interrupt handler with:
/// - num: syscall number (from RAX)
/// - args: arguments (RDI, RSI, RDX, R10, R8, R9)
///
/// Returns value to put in RAX
pub fn handle(num: u64, args: [u64; 6]) -> u64 {
    let syscall = match Syscall::try_from(num) {
        Ok(s) => s,
        Err(_) => return error_code(KernelError::InvalidArgument),
    };

    let result = match syscall {
        Syscall::Null => Ok(0),

        // IPC
        Syscall::Send => handle_send(args[0], args[1]),
        Syscall::Recv => handle_recv(args[0]),
        Syscall::Yield => {
            crate::sys::scheduler::yield_current();
            Ok(0)
        }

        // Debug
        Syscall::DebugPrint => handle_debug_print(args[0], args[1]),

        // Not implemented
        _ => Err(KernelError::InvalidArgument),
    };

    match result {
        Ok(v) => v,
        Err(e) => error_code(e),
    }
}

/// Convert error to syscall return code
fn error_code(err: KernelError) -> u64 {
    // Negative values indicate errors
    let code: i64 = match err {
        KernelError::OutOfMemory => -1,
        KernelError::InvalidCapability => -2,
        KernelError::PermissionDenied => -3,
        KernelError::NotFound => -4,
        KernelError::AlreadyExists => -5,
        KernelError::InvalidArgument => -6,
        KernelError::WouldBlock => -7,
        KernelError::Interrupted => -8,
        KernelError::IpcFailed => -9,
        KernelError::HardwareError => -10,
    };
    code as u64
}

// Syscall implementations

fn handle_send(endpoint: u64, msg_ptr: u64) -> KernelResult<u64> {
    // Validate endpoint capability
    // Copy message from user space
    // Call IPC send

    log::trace!("Send to endpoint {} from {:#x}", endpoint, msg_ptr);

    // Placeholder
    Ok(0)
}

fn handle_recv(endpoint: u64) -> KernelResult<u64> {
    // Validate endpoint capability
    // Block until message arrives
    // Copy message to user space

    log::trace!("Recv from endpoint {}", endpoint);

    // Placeholder
    Err(KernelError::WouldBlock)
}

fn handle_debug_print(ptr: u64, len: u64) -> KernelResult<u64> {
    // Copy string from user space and print

    if len > 1024 {
        return Err(KernelError::InvalidArgument);
    }

    // In real implementation, copy from user space
    log::info!("User debug: (ptr={:#x}, len={})", ptr, len);

    Ok(0)
}

/// Initialize syscall handler
pub fn init() {
    // Set up SYSCALL/SYSRET MSRs
    // This is x86_64 specific

    // STAR MSR: segments for syscall/sysret
    // LSTAR MSR: syscall entry point
    // SFMASK MSR: flags to clear on syscall

    log::debug!("Syscall interface initialized");
}
