//! Core Kernel Services
//!
//! Provides fundamental kernel services:
//! - Process management
//! - Thread management
//! - Scheduler
//! - System calls

pub mod process;
pub mod scheduler;
pub mod syscall;
pub mod thread;

pub use process::{Process, ProcessId};
pub use thread::{Thread, ThreadId, ThreadState};
pub use scheduler::Scheduler;
