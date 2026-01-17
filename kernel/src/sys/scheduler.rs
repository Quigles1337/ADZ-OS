//! Scheduler
//!
//! Priority-based preemptive scheduler with:
//! - 256 priority levels (0 = highest, 255 = idle)
//! - Round-robin within same priority
//! - Time slice based preemption
//!
//! # Scheduling Algorithm
//!
//! 1. Always run highest priority runnable thread
//! 2. Round-robin among threads of same priority
//! 3. Time slice exhaustion causes reschedule
//! 4. Blocking causes immediate reschedule

use crate::{KernelResult, KernelError, MAX_CPUS};
use super::thread::{Thread, ThreadId, ThreadState};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;

/// Number of priority levels
pub const NUM_PRIORITIES: usize = 256;

/// Default time slice (in timer ticks)
pub const DEFAULT_TIME_SLICE: u32 = 10;

/// Idle priority
pub const IDLE_PRIORITY: u8 = 255;

/// Global scheduler
static SCHEDULER: Mutex<Option<Scheduler>> = Mutex::new(None);

/// Per-CPU scheduler state
#[derive(Debug)]
pub struct CpuState {
    /// Current running thread
    pub current: Option<ThreadId>,
    /// Idle thread for this CPU
    pub idle_thread: ThreadId,
    /// CPU ID
    pub cpu_id: usize,
    /// Remaining time slice
    pub time_remaining: u32,
    /// Need reschedule flag
    pub need_resched: bool,
}

/// Scheduler
pub struct Scheduler {
    /// Run queues (one per priority level)
    run_queues: [VecDeque<ThreadId>; NUM_PRIORITIES],
    /// All threads in the system
    threads: Vec<Thread>,
    /// Per-CPU state
    cpus: [Option<CpuState>; MAX_CPUS],
    /// Number of active CPUs
    num_cpus: usize,
    /// Next thread ID
    next_tid: u32,
}

impl Scheduler {
    /// Create new scheduler
    pub fn new() -> Self {
        const EMPTY_QUEUE: VecDeque<ThreadId> = VecDeque::new();
        const EMPTY_CPU: Option<CpuState> = None;

        Self {
            run_queues: [EMPTY_QUEUE; NUM_PRIORITIES],
            threads: Vec::new(),
            cpus: [EMPTY_CPU; MAX_CPUS],
            num_cpus: 1,
            next_tid: 1,
        }
    }

    /// Add thread to run queue
    pub fn enqueue(&mut self, tid: ThreadId) {
        if let Some(thread) = self.get_thread_mut(tid) {
            if thread.state == ThreadState::Ready {
                let priority = thread.priority as usize;
                if !self.run_queues[priority].contains(&tid) {
                    self.run_queues[priority].push_back(tid);
                }
            }
        }
    }

    /// Remove thread from run queue
    pub fn dequeue(&mut self, tid: ThreadId) {
        if let Some(thread) = self.get_thread(tid) {
            let priority = thread.priority as usize;
            self.run_queues[priority].retain(|&t| t != tid);
        }
    }

    /// Get next thread to run
    pub fn pick_next(&mut self) -> Option<ThreadId> {
        // Find highest priority non-empty queue
        for priority in 0..NUM_PRIORITIES {
            if let Some(tid) = self.run_queues[priority].pop_front() {
                return Some(tid);
            }
        }
        None
    }

    /// Create new thread
    pub fn create_thread(
        &mut self,
        process_id: u32,
        entry: u64,
        priority: u8,
    ) -> KernelResult<ThreadId> {
        let tid = ThreadId(self.next_tid);
        self.next_tid += 1;

        let thread = Thread::new(tid, process_id, entry, priority);
        self.threads.push(thread);

        // Add to run queue
        self.enqueue(tid);

        log::debug!("Created thread {:?} for process {}", tid, process_id);

        Ok(tid)
    }

    /// Get thread by ID
    pub fn get_thread(&self, tid: ThreadId) -> Option<&Thread> {
        self.threads.iter().find(|t| t.id == tid)
    }

    /// Get mutable thread by ID
    pub fn get_thread_mut(&mut self, tid: ThreadId) -> Option<&mut Thread> {
        self.threads.iter_mut().find(|t| t.id == tid)
    }

    /// Block a thread
    pub fn block(&mut self, tid: ThreadId, reason: ThreadState) {
        self.dequeue(tid);
        if let Some(thread) = self.get_thread_mut(tid) {
            thread.state = reason;
        }
    }

    /// Unblock a thread
    pub fn unblock(&mut self, tid: ThreadId) {
        if let Some(thread) = self.get_thread_mut(tid) {
            thread.state = ThreadState::Ready;
            self.enqueue(tid);
        }
    }

    /// Handle timer tick
    pub fn timer_tick(&mut self, cpu: usize) {
        if let Some(ref mut cpu_state) = self.cpus[cpu] {
            if cpu_state.time_remaining > 0 {
                cpu_state.time_remaining -= 1;
            }

            if cpu_state.time_remaining == 0 {
                cpu_state.need_resched = true;
            }
        }
    }

    /// Schedule (called from timer interrupt or explicit yield)
    pub fn schedule(&mut self, cpu: usize) {
        let current = self.cpus[cpu].as_ref().and_then(|c| c.current);

        // Put current thread back in run queue (if runnable)
        if let Some(tid) = current {
            if let Some(thread) = self.get_thread(tid) {
                if thread.state == ThreadState::Running {
                    // Still runnable, put back in queue
                    if let Some(t) = self.get_thread_mut(tid) {
                        t.state = ThreadState::Ready;
                    }
                    self.enqueue(tid);
                }
            }
        }

        // Pick next thread
        if let Some(next_tid) = self.pick_next() {
            if let Some(thread) = self.get_thread_mut(next_tid) {
                thread.state = ThreadState::Running;
            }

            if let Some(ref mut cpu_state) = self.cpus[cpu] {
                cpu_state.current = Some(next_tid);
                cpu_state.time_remaining = DEFAULT_TIME_SLICE;
                cpu_state.need_resched = false;
            }

            // In real implementation, switch to next thread's context
            log::trace!("CPU {} switching to thread {:?}", cpu, next_tid);
        } else {
            // No runnable threads, run idle
            if let Some(ref mut cpu_state) = self.cpus[cpu] {
                cpu_state.current = Some(cpu_state.idle_thread);
            }
        }
    }

    /// Initialize CPU state
    pub fn init_cpu(&mut self, cpu: usize, idle_thread: ThreadId) {
        self.cpus[cpu] = Some(CpuState {
            current: None,
            idle_thread,
            cpu_id: cpu,
            time_remaining: DEFAULT_TIME_SLICE,
            need_resched: false,
        });

        if cpu >= self.num_cpus {
            self.num_cpus = cpu + 1;
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize scheduler
pub fn init() -> KernelResult<()> {
    let mut sched = Scheduler::new();

    // Create idle thread for BSP
    let idle_tid = sched.create_thread(0, 0, IDLE_PRIORITY)?;
    sched.init_cpu(0, idle_tid);

    *SCHEDULER.lock() = Some(sched);

    log::debug!("Scheduler initialized");
    Ok(())
}

/// Start the scheduler (never returns)
pub fn start() -> ! {
    log::info!("Starting scheduler...");

    // Enable interrupts and wait
    unsafe {
        core::arch::asm!("sti");
    }

    loop {
        // Check if reschedule needed
        {
            let mut guard = SCHEDULER.lock();
            if let Some(ref mut sched) = *guard {
                if let Some(ref cpu_state) = sched.cpus[0] {
                    if cpu_state.need_resched {
                        sched.schedule(0);
                    }
                }
            }
        }

        crate::hlt();
    }
}

/// Create thread (public interface)
pub fn create_thread(process_id: u32, entry: u64, priority: u8) -> KernelResult<ThreadId> {
    SCHEDULER.lock()
        .as_mut()
        .ok_or(KernelError::NotFound)?
        .create_thread(process_id, entry, priority)
}

/// Block current thread
pub fn block_current(reason: ThreadState) {
    // In real implementation, get current thread from CPU state
}

/// Yield current thread
pub fn yield_current() {
    let mut guard = SCHEDULER.lock();
    if let Some(ref mut sched) = *guard {
        sched.schedule(0);
    }
}

/// Timer tick handler
pub fn timer_tick() {
    let mut guard = SCHEDULER.lock();
    if let Some(ref mut sched) = *guard {
        sched.timer_tick(0);
    }
}
