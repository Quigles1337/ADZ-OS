//! μKernel: Capability-Based Microkernel for μOS
//!
//! A minimal microkernel implementing:
//! - Capability-based security
//! - Message-passing IPC
//! - Memory isolation
//! - Minimal trusted computing base
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     User Space                              │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐│
//! │  │   VFS    │ │ NetStack │ │ Display  │ │   Applications   ││
//! │  │  Server  │ │  Server  │ │  Server  │ │                  ││
//! │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────────┬─────────┘│
//! │       │            │            │                 │          │
//! │  ═════╪════════════╪════════════╪═════════════════╪═════════ │
//! │       │    IPC     │            │                 │          │
//! │       ▼            ▼            ▼                 ▼          │
//! ├─────────────────────────────────────────────────────────────┤
//! │                      μKernel                                │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
//! │  │ Capabilities │  │     IPC      │  │ Memory Manager   │   │
//! │  │    System    │  │   Subsystem  │  │ (Physical/Virt)  │   │
//! │  └──────────────┘  └──────────────┘  └──────────────────┘   │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
//! │  │  Scheduler   │  │   Drivers    │  │   μ-Crypto       │   │
//! │  │              │  │ (Timer, IRQ) │  │  Integration     │   │
//! │  └──────────────┘  └──────────────┘  └──────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]
#![warn(missing_docs)]

extern crate alloc;

pub mod boot;
pub mod caps;
pub mod sys;
pub mod drivers;
pub mod ipc;
pub mod mm;

use core::panic::PanicInfo;

/// Kernel version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Kernel name
pub const NAME: &str = "μKernel";

/// Page size (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Kernel virtual base address
pub const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Physical memory offset for direct mapping
pub const PHYS_MEM_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 256;

/// Maximum number of processes
pub const MAX_PROCESSES: usize = 65536;

/// Kernel result type
pub type KernelResult<T> = Result<T, KernelError>;

/// Kernel error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelError {
    /// Out of memory
    OutOfMemory,
    /// Invalid capability
    InvalidCapability,
    /// Permission denied
    PermissionDenied,
    /// Resource not found
    NotFound,
    /// Resource already exists
    AlreadyExists,
    /// Invalid argument
    InvalidArgument,
    /// Operation would block
    WouldBlock,
    /// Interrupted
    Interrupted,
    /// IPC failure
    IpcFailed,
    /// Hardware error
    HardwareError,
}

/// Panic handler
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Use serial output if available
    if let Some(location) = info.location() {
        log::error!(
            "KERNEL PANIC at {}:{}: {}",
            location.file(),
            location.line(),
            info.message()
        );
    } else {
        log::error!("KERNEL PANIC: {}", info.message());
    }

    // Halt the CPU
    loop {
        unsafe {
            core::arch::asm!("cli; hlt");
        }
    }
}

/// Allocation error handler
#[alloc_error_handler]
fn alloc_error(layout: alloc::alloc::Layout) -> ! {
    panic!("Allocation failed: {:?}", layout);
}

/// Halt the CPU
#[inline]
pub fn hlt() {
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}

/// Halt loop - halt and loop forever
pub fn halt_loop() -> ! {
    loop {
        hlt();
    }
}

// ============================================================================
// Kernel Entry Point
// ============================================================================

/// Kernel entry point (called from bootloader)
///
/// Boot sequence:
/// 1. UEFI/BIOS loads bootloader
/// 2. Bootloader loads kernel at 1MB physical
/// 3. Bootloader sets up initial page tables (identity + higher-half)
/// 4. Bootloader jumps to _start in long mode
/// 5. _start initializes BSS, stack, and calls kernel_init
/// 6. kernel_init initializes subsystems and starts scheduler
#[no_mangle]
pub extern "C" fn _start(boot_info: &'static boot::BootInfo) -> ! {
    // Initialize BSS section
    unsafe { boot::init_bss(); }

    // Early serial init for debugging
    drivers::serial::init();
    drivers::serial::init_logger();

    log::info!("{} v{} starting...", NAME, VERSION);
    log::info!("Boot info at {:p}", boot_info);

    // Initialize kernel subsystems
    if let Err(e) = kernel_init(boot_info) {
        log::error!("Kernel initialization failed: {:?}", e);
        halt_loop();
    }

    log::info!("Kernel initialized successfully");

    // Start the scheduler (never returns)
    sys::scheduler::start()
}

/// Initialize all kernel subsystems
fn kernel_init(boot_info: &'static boot::BootInfo) -> KernelResult<()> {
    // Phase 1: Memory Management
    log::info!("Initializing memory management...");
    mm::init(boot_info)?;

    // Phase 2: Interrupt Handling
    log::info!("Initializing interrupts...");
    drivers::interrupts::init();

    // Phase 3: Timer
    log::info!("Initializing timer...");
    drivers::timer::init();

    // Phase 4: Capability System
    log::info!("Initializing capability system...");
    caps::init()?;

    // Phase 5: IPC Subsystem
    log::info!("Initializing IPC...");
    ipc::init()?;

    // Phase 6: Scheduler
    log::info!("Initializing scheduler...");
    sys::scheduler::init()?;

    // Phase 7: Create init process
    log::info!("Creating init process...");
    create_init_process(boot_info)?;

    Ok(())
}

/// Create the first user-space process (init)
fn create_init_process(boot_info: &'static boot::BootInfo) -> KernelResult<()> {
    // Find init module in boot info
    let init_module = boot_info.modules.iter()
        .find(|m| m.name == "init")
        .ok_or(KernelError::NotFound)?;

    log::info!("Loading init from {:?}", init_module);

    // Create process with full capabilities (init is trusted)
    let pid = sys::process::create(
        "init",
        init_module.start,
        init_module.size,
        caps::CapabilitySet::full(),
    )?;

    log::info!("Init process created with PID {}", pid);

    Ok(())
}
