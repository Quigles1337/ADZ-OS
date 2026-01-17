//! Process Management
//!
//! A process is a protection domain with:
//! - Virtual address space
//! - Capability space
//! - One or more threads

use crate::{KernelResult, KernelError, MAX_PROCESSES};
use crate::mm::AddressSpace;
use crate::caps::CapabilitySet;
use super::thread::ThreadId;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

/// Process ID type
pub type ProcessId = u32;

/// Global process table
static PROCESS_TABLE: Mutex<ProcessTable> = Mutex::new(ProcessTable::new());

/// Process state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Being created
    Creating,
    /// Ready to run
    Ready,
    /// Running (has at least one running thread)
    Running,
    /// Blocked (all threads blocked)
    Blocked,
    /// Zombie (terminated, waiting for parent)
    Zombie,
    /// Dead (fully cleaned up)
    Dead,
}

/// Process structure
pub struct Process {
    /// Process ID
    pub id: ProcessId,
    /// Process name
    pub name: String,
    /// Process state
    pub state: ProcessState,
    /// Parent process ID
    pub parent: Option<ProcessId>,
    /// Child processes
    pub children: Vec<ProcessId>,
    /// Threads in this process
    pub threads: Vec<ThreadId>,
    /// Address space
    pub address_space: Option<AddressSpace>,
    /// Capabilities
    pub capabilities: CapabilitySet,
    /// Exit code (if zombie)
    pub exit_code: Option<i32>,
}

impl Process {
    /// Create new process
    pub fn new(id: ProcessId, name: &str) -> Self {
        Self {
            id,
            name: String::from(name),
            state: ProcessState::Creating,
            parent: None,
            children: Vec::new(),
            threads: Vec::new(),
            address_space: None,
            capabilities: CapabilitySet::new(),
            exit_code: None,
        }
    }

    /// Add thread to process
    pub fn add_thread(&mut self, tid: ThreadId) {
        if !self.threads.contains(&tid) {
            self.threads.push(tid);
        }
    }

    /// Remove thread from process
    pub fn remove_thread(&mut self, tid: ThreadId) {
        self.threads.retain(|&t| t != tid);
    }

    /// Add child process
    pub fn add_child(&mut self, pid: ProcessId) {
        if !self.children.contains(&pid) {
            self.children.push(pid);
        }
    }

    /// Check if process has any runnable threads
    pub fn has_runnable_threads(&self) -> bool {
        !self.threads.is_empty()
    }
}

/// Process table
struct ProcessTable {
    processes: Vec<Option<Process>>,
    next_pid: ProcessId,
}

impl ProcessTable {
    const fn new() -> Self {
        Self {
            processes: Vec::new(),
            next_pid: 1,
        }
    }

    fn allocate(&mut self) -> KernelResult<ProcessId> {
        if self.processes.len() >= MAX_PROCESSES {
            return Err(KernelError::OutOfMemory);
        }

        let pid = self.next_pid;
        self.next_pid += 1;

        // Extend if needed
        while self.processes.len() <= pid as usize {
            self.processes.push(None);
        }

        Ok(pid)
    }

    fn get(&self, pid: ProcessId) -> Option<&Process> {
        self.processes.get(pid as usize).and_then(|p| p.as_ref())
    }

    fn get_mut(&mut self, pid: ProcessId) -> Option<&mut Process> {
        self.processes.get_mut(pid as usize).and_then(|p| p.as_mut())
    }

    fn insert(&mut self, process: Process) {
        let pid = process.id as usize;
        while self.processes.len() <= pid {
            self.processes.push(None);
        }
        self.processes[pid] = Some(process);
    }
}

/// Create a new process
pub fn create(
    name: &str,
    image_start: u64,
    image_size: u64,
    capabilities: CapabilitySet,
) -> KernelResult<ProcessId> {
    let mut table = PROCESS_TABLE.lock();

    let pid = table.allocate()?;
    let mut process = Process::new(pid, name);

    // Create address space
    let phys_offset = crate::PHYS_MEM_OFFSET;
    let mut addr_space = AddressSpace::new(phys_offset)?;

    // Map the process image
    // In real implementation, parse ELF and map sections appropriately
    let virt_start = crate::mm::VirtAddr::new(0x40_0000); // Standard user code location
    let phys_start = crate::mm::PhysAddr::new(image_start);

    addr_space.map_range(
        virt_start,
        phys_start,
        image_size as usize,
        crate::mm::PageFlags::USER_CODE,
    )?;

    // Create user stack
    let stack_size = 1024 * 1024; // 1 MB stack
    let stack_top = crate::mm::VirtAddr::new(0x7FFF_FFFF_F000);
    let stack_bottom = crate::mm::VirtAddr::new(stack_top.as_u64() - stack_size as u64);

    // Allocate physical pages for stack
    for offset in (0..stack_size).step_by(crate::PAGE_SIZE) {
        let virt = crate::mm::VirtAddr::new(stack_bottom.as_u64() + offset as u64);
        let phys = crate::mm::PhysAddr::new(crate::mm::alloc_frame()?);
        addr_space.map_page(virt, phys, crate::mm::PageFlags::USER_DATA)?;
    }

    process.address_space = Some(addr_space);
    process.capabilities = capabilities;
    process.state = ProcessState::Ready;

    // Create main thread
    let entry_point = virt_start.as_u64();
    let tid = crate::sys::scheduler::create_thread(pid, entry_point, 128)?;
    process.add_thread(tid);

    table.insert(process);

    log::info!("Created process {} ({}) with thread {:?}", pid, name, tid);

    Ok(pid)
}

/// Get process by ID
pub fn get(pid: ProcessId) -> Option<ProcessId> {
    PROCESS_TABLE.lock().get(pid).map(|p| p.id)
}

/// Terminate a process
pub fn terminate(pid: ProcessId, exit_code: i32) -> KernelResult<()> {
    let mut table = PROCESS_TABLE.lock();

    let process = table.get_mut(pid).ok_or(KernelError::NotFound)?;
    process.state = ProcessState::Zombie;
    process.exit_code = Some(exit_code);

    // In real implementation:
    // - Kill all threads
    // - Release address space
    // - Notify parent
    // - Reparent children to init

    log::info!("Process {} terminated with code {}", pid, exit_code);

    Ok(())
}

/// Wait for child process
pub fn wait(parent_pid: ProcessId) -> KernelResult<(ProcessId, i32)> {
    let table = PROCESS_TABLE.lock();

    let parent = table.get(parent_pid).ok_or(KernelError::NotFound)?;

    // Find zombie child
    for &child_pid in &parent.children {
        if let Some(child) = table.get(child_pid) {
            if child.state == ProcessState::Zombie {
                if let Some(code) = child.exit_code {
                    return Ok((child_pid, code));
                }
            }
        }
    }

    Err(KernelError::WouldBlock)
}
