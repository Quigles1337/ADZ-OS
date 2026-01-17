//! Thread Management
//!
//! A thread is the unit of scheduling:
//! - CPU context (registers, stack pointer)
//! - Belongs to a process
//! - Priority level
//! - State (running, ready, blocked)

use crate::KernelResult;

/// Thread ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadId(pub u32);

impl ThreadId {
    /// Get raw value
    pub fn value(&self) -> u32 {
        self.0
    }
}

/// Thread state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Ready to run
    Ready,
    /// Currently running
    Running,
    /// Blocked on IPC send
    BlockedSend,
    /// Blocked on IPC receive
    BlockedRecv,
    /// Blocked on notification
    BlockedNotify,
    /// Blocked on reply
    BlockedReply,
    /// Sleeping (timed wait)
    Sleeping,
    /// Suspended by debugger
    Suspended,
    /// Thread has exited
    Exited,
}

/// Saved CPU context for thread switching
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Context {
    // Callee-saved registers
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // Instruction and stack pointers
    pub rip: u64,
    pub rsp: u64,

    // Flags
    pub rflags: u64,

    // Segment registers (for user mode)
    pub cs: u64,
    pub ss: u64,
}

impl Context {
    /// Create kernel-mode context
    pub fn kernel(entry: u64, stack: u64) -> Self {
        Self {
            rip: entry,
            rsp: stack,
            rflags: 0x202, // Interrupts enabled
            cs: 0x08,      // Kernel code segment
            ss: 0x10,      // Kernel data segment
            ..Default::default()
        }
    }

    /// Create user-mode context
    pub fn user(entry: u64, stack: u64) -> Self {
        Self {
            rip: entry,
            rsp: stack,
            rflags: 0x202,
            cs: 0x1B,      // User code segment (ring 3)
            ss: 0x23,      // User data segment (ring 3)
            ..Default::default()
        }
    }
}

/// Thread structure
#[derive(Debug)]
pub struct Thread {
    /// Thread ID
    pub id: ThreadId,
    /// Owning process ID
    pub process_id: u32,
    /// Thread state
    pub state: ThreadState,
    /// Priority (0-255, lower = higher priority)
    pub priority: u8,
    /// Saved context
    pub context: Context,
    /// Kernel stack pointer
    pub kernel_stack: u64,
    /// Kernel stack size
    pub kernel_stack_size: usize,
    /// Time slice remaining
    pub time_slice: u32,
    /// Total CPU time used (ticks)
    pub cpu_time: u64,
    /// IPC buffer pointer (for message passing)
    pub ipc_buffer: u64,
}

impl Thread {
    /// Create new thread
    pub fn new(id: ThreadId, process_id: u32, entry: u64, priority: u8) -> Self {
        // Allocate kernel stack (in real implementation)
        let kernel_stack_size = 16 * 1024; // 16 KB kernel stack
        let kernel_stack = 0; // Would be allocated

        Self {
            id,
            process_id,
            state: ThreadState::Ready,
            priority,
            context: Context::user(entry, 0x7FFF_FFFF_F000), // Top of user stack
            kernel_stack,
            kernel_stack_size,
            time_slice: 10,
            cpu_time: 0,
            ipc_buffer: 0,
        }
    }

    /// Check if thread is runnable
    pub fn is_runnable(&self) -> bool {
        matches!(self.state, ThreadState::Ready | ThreadState::Running)
    }

    /// Check if thread is blocked
    pub fn is_blocked(&self) -> bool {
        matches!(
            self.state,
            ThreadState::BlockedSend
                | ThreadState::BlockedRecv
                | ThreadState::BlockedNotify
                | ThreadState::BlockedReply
                | ThreadState::Sleeping
        )
    }
}

/// Context switch between two threads
///
/// # Safety
/// - Both contexts must be valid
/// - Must be called with interrupts disabled
#[unsafe(naked)]
pub unsafe extern "C" fn switch_context(_old: *mut Context, _new: *const Context) {
    core::arch::naked_asm!(
        // Save old context
        "mov [rdi + 0x00], rbx",
        "mov [rdi + 0x08], rbp",
        "mov [rdi + 0x10], r12",
        "mov [rdi + 0x18], r13",
        "mov [rdi + 0x20], r14",
        "mov [rdi + 0x28], r15",
        "mov [rdi + 0x38], rsp",

        // Save return address as RIP
        "mov rax, [rsp]",
        "mov [rdi + 0x30], rax",

        // Load new context
        "mov rbx, [rsi + 0x00]",
        "mov rbp, [rsi + 0x08]",
        "mov r12, [rsi + 0x10]",
        "mov r13, [rsi + 0x18]",
        "mov r14, [rsi + 0x20]",
        "mov r15, [rsi + 0x28]",
        "mov rsp, [rsi + 0x38]",

        // Jump to new RIP
        "push [rsi + 0x30]",
        "ret",
    );
}
