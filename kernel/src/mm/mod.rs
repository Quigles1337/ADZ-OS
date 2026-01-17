//! Memory Management Subsystem
//!
//! Provides physical and virtual memory management:
//! - Physical frame allocator (bitmap-based)
//! - Virtual address space management
//! - Page table manipulation
//! - Kernel heap allocator
//!
//! # Address Space Layout
//!
//! ```text
//! Virtual Address Space (48-bit canonical):
//!
//! 0xFFFF_FFFF_FFFF_FFFF ┌──────────────────────┐
//!                       │    Kernel Stack      │
//! 0xFFFF_FFFF_8000_0000 ├──────────────────────┤
//!                       │    Kernel Image      │  (-2GB)
//! 0xFFFF_8000_0000_0000 ├──────────────────────┤
//!                       │  Physical Memory Map │  (direct mapping)
//! 0x0000_8000_0000_0000 ├──────────────────────┤
//!                       │    (non-canonical)   │
//! 0x0000_7FFF_FFFF_FFFF ├──────────────────────┤
//!                       │    User Space        │
//! 0x0000_0000_0000_0000 └──────────────────────┘
//! ```

pub mod frame;
pub mod heap;
pub mod page;
pub mod virt;

use crate::{boot::BootInfo, KernelResult, KernelError, PAGE_SIZE};
use spin::Mutex;

pub use frame::FrameAllocator;
pub use heap::KernelHeap;
pub use page::{PageTable, PageTableEntry, PageFlags, ENTRIES_PER_TABLE};
pub use virt::{AddressSpace, VirtualRegion};

/// Global frame allocator
static FRAME_ALLOCATOR: Mutex<Option<FrameAllocator>> = Mutex::new(None);

/// Global kernel heap
#[global_allocator]
static KERNEL_HEAP: KernelHeap = KernelHeap::new();

/// Initialize memory management
pub fn init(boot_info: &'static BootInfo) -> KernelResult<()> {
    log::debug!("Memory map has {} regions", boot_info.memory_map.regions.len());
    log::debug!("Total usable memory: {} MB",
        boot_info.memory_map.usable_memory() / (1024 * 1024));

    // Initialize frame allocator
    let mut allocator = FrameAllocator::new(&boot_info.memory_map)?;

    // Mark kernel regions as used
    mark_kernel_regions(&mut allocator)?;

    log::debug!("Frame allocator: {} free frames", allocator.free_frames());

    *FRAME_ALLOCATOR.lock() = Some(allocator);

    // Initialize kernel heap
    let heap_start = crate::boot::heap_start();
    let heap_size = 16 * 1024 * 1024; // 16 MB initial heap

    unsafe {
        KERNEL_HEAP.init(heap_start as *mut u8, heap_size);
    }

    log::debug!("Kernel heap initialized: {} MB at {:#x}",
        heap_size / (1024 * 1024), heap_start);

    Ok(())
}

/// Mark kernel-occupied regions as used
fn mark_kernel_regions(allocator: &mut FrameAllocator) -> KernelResult<()> {
    let (text_start, text_end) = crate::boot::text_range();
    let (data_start, data_end) = crate::boot::data_range();
    let (bss_start, bss_end) = crate::boot::bss_range();
    let (stack_start, stack_end) = crate::boot::stack_range();

    // Convert to physical addresses and mark as used
    // (assuming identity mapping during boot)
    allocator.mark_range_used(text_start, text_end)?;
    allocator.mark_range_used(data_start, data_end)?;
    allocator.mark_range_used(bss_start, bss_end)?;
    allocator.mark_range_used(stack_start, stack_end)?;

    Ok(())
}

/// Allocate a physical frame
pub fn alloc_frame() -> KernelResult<u64> {
    FRAME_ALLOCATOR.lock()
        .as_mut()
        .ok_or(KernelError::OutOfMemory)?
        .allocate()
}

/// Free a physical frame
pub fn free_frame(addr: u64) -> KernelResult<()> {
    FRAME_ALLOCATOR.lock()
        .as_mut()
        .ok_or(KernelError::OutOfMemory)?
        .deallocate(addr)
}

/// Allocate contiguous physical frames
pub fn alloc_frames(count: usize) -> KernelResult<u64> {
    FRAME_ALLOCATOR.lock()
        .as_mut()
        .ok_or(KernelError::OutOfMemory)?
        .allocate_contiguous(count)
}

/// Get number of free frames
pub fn free_frame_count() -> usize {
    FRAME_ALLOCATOR.lock()
        .as_ref()
        .map(|a| a.free_frames())
        .unwrap_or(0)
}

/// Physical address type (newtype for type safety)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    /// Create new physical address
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Get raw address value
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Align down to page boundary
    pub const fn align_down(self) -> Self {
        Self(self.0 & !(PAGE_SIZE as u64 - 1))
    }

    /// Align up to page boundary
    pub const fn align_up(self) -> Self {
        Self((self.0 + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1))
    }

    /// Check if aligned to page boundary
    pub const fn is_aligned(self) -> bool {
        self.0 & (PAGE_SIZE as u64 - 1) == 0
    }
}

/// Virtual address type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// Create new virtual address
    pub const fn new(addr: u64) -> Self {
        // Ensure canonical form (sign-extend bit 47)
        let addr = if addr & (1 << 47) != 0 {
            addr | 0xFFFF_0000_0000_0000
        } else {
            addr & 0x0000_FFFF_FFFF_FFFF
        };
        Self(addr)
    }

    /// Get raw address value
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Align down to page boundary
    pub const fn align_down(self) -> Self {
        Self(self.0 & !(PAGE_SIZE as u64 - 1))
    }

    /// Align up to page boundary
    pub const fn align_up(self) -> Self {
        Self::new((self.0 + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1))
    }

    /// Check if aligned
    pub const fn is_aligned(self) -> bool {
        self.0 & (PAGE_SIZE as u64 - 1) == 0
    }

    /// Get page table indices for this address
    pub fn page_table_indices(self) -> [usize; 4] {
        [
            ((self.0 >> 39) & 0x1FF) as usize, // PML4
            ((self.0 >> 30) & 0x1FF) as usize, // PDPT
            ((self.0 >> 21) & 0x1FF) as usize, // PD
            ((self.0 >> 12) & 0x1FF) as usize, // PT
        ]
    }

    /// Check if this is a user-space address
    pub const fn is_user(self) -> bool {
        self.0 < 0x0000_8000_0000_0000
    }

    /// Check if this is a kernel-space address
    pub const fn is_kernel(self) -> bool {
        self.0 >= 0xFFFF_8000_0000_0000
    }
}
