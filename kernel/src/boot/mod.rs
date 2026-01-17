//! Boot Module
//!
//! Handles early boot initialization and boot information parsing.
//!
//! # Boot Protocol
//!
//! The kernel expects to be loaded by a compatible bootloader that provides:
//! - Physical memory map
//! - Framebuffer info (optional)
//! - Initial ramdisk modules
//! - ACPI tables pointer

use crate::{PAGE_SIZE, KERNEL_VIRT_BASE};

/// Boot information passed from bootloader
#[repr(C)]
#[derive(Debug)]
pub struct BootInfo {
    /// Magic number for validation
    pub magic: u64,
    /// Memory map entries
    pub memory_map: MemoryMap,
    /// Framebuffer info (if available)
    pub framebuffer: Option<FramebufferInfo>,
    /// Loaded modules (initrd, etc.)
    pub modules: &'static [Module],
    /// ACPI RSDP address
    pub rsdp_addr: Option<u64>,
    /// Physical memory offset for direct mapping
    pub phys_mem_offset: u64,
}

/// Boot magic number
pub const BOOT_MAGIC: u64 = 0x4D55_4F53_424F_4F54; // "MUOSBOOT"

impl BootInfo {
    /// Validate boot info
    pub fn validate(&self) -> bool {
        self.magic == BOOT_MAGIC
    }
}

/// Memory map from bootloader
#[repr(C)]
#[derive(Debug)]
pub struct MemoryMap {
    /// Memory regions
    pub regions: &'static [MemoryRegion],
}

impl MemoryMap {
    /// Get total usable memory
    pub fn usable_memory(&self) -> u64 {
        self.regions.iter()
            .filter(|r| r.kind == MemoryRegionKind::Usable)
            .map(|r| r.size)
            .sum()
    }

    /// Iterate over usable regions
    pub fn usable_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.regions.iter().filter(|r| r.kind == MemoryRegionKind::Usable)
    }
}

/// A region of physical memory
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Physical start address
    pub start: u64,
    /// Size in bytes
    pub size: u64,
    /// Region type
    pub kind: MemoryRegionKind,
}

impl MemoryRegion {
    /// End address (exclusive)
    pub fn end(&self) -> u64 {
        self.start + self.size
    }

    /// Check if address is in this region
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }
}

/// Memory region types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionKind {
    /// Usable RAM
    Usable = 1,
    /// Reserved by firmware
    Reserved = 2,
    /// ACPI reclaimable
    AcpiReclaimable = 3,
    /// ACPI NVS
    AcpiNvs = 4,
    /// Bad memory
    BadMemory = 5,
    /// Bootloader reclaimable
    BootloaderReclaimable = 6,
    /// Kernel and modules
    Kernel = 7,
    /// Framebuffer
    Framebuffer = 8,
}

/// Framebuffer information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical address of framebuffer
    pub address: u64,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Bytes per scanline
    pub pitch: u32,
    /// Bits per pixel
    pub bpp: u8,
    /// Pixel format
    pub format: PixelFormat,
}

/// Pixel format
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// RGB (red in lowest bits)
    Rgb = 0,
    /// BGR (blue in lowest bits)
    Bgr = 1,
    /// Other/unknown
    Other = 255,
}

/// Boot module (initrd, etc.)
#[repr(C)]
#[derive(Debug)]
pub struct Module {
    /// Module name
    pub name: &'static str,
    /// Physical start address
    pub start: u64,
    /// Size in bytes
    pub size: u64,
}

/// Symbols from linker script
extern "C" {
    static __bss_start: u8;
    static __bss_end: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __data_start: u8;
    static __data_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __stack_bottom: u8;
    static __stack_top: u8;
    static __heap_start: u8;
    static __kernel_end: u8;
}

/// Initialize BSS section to zero
///
/// # Safety
/// Must only be called once during early boot
pub unsafe fn init_bss() {
    let bss_start = &__bss_start as *const u8 as *mut u8;
    let bss_end = &__bss_end as *const u8;
    let bss_size = bss_end as usize - bss_start as usize;

    core::ptr::write_bytes(bss_start, 0, bss_size);
}

/// Get kernel text section range
pub fn text_range() -> (u64, u64) {
    unsafe {
        let start = &__text_start as *const u8 as u64;
        let end = &__text_end as *const u8 as u64;
        (start, end)
    }
}

/// Get kernel data section range
pub fn data_range() -> (u64, u64) {
    unsafe {
        let start = &__data_start as *const u8 as u64;
        let end = &__data_end as *const u8 as u64;
        (start, end)
    }
}

/// Get kernel BSS section range
pub fn bss_range() -> (u64, u64) {
    unsafe {
        let start = &__bss_start as *const u8 as u64;
        let end = &__bss_end as *const u8 as u64;
        (start, end)
    }
}

/// Get kernel heap start address
pub fn heap_start() -> u64 {
    unsafe { &__heap_start as *const u8 as u64 }
}

/// Get kernel end address
pub fn kernel_end() -> u64 {
    unsafe { &__kernel_end as *const u8 as u64 }
}

/// Get stack range
pub fn stack_range() -> (u64, u64) {
    unsafe {
        let bottom = &__stack_bottom as *const u8 as u64;
        let top = &__stack_top as *const u8 as u64;
        (bottom, top)
    }
}

/// Convert physical address to virtual (using direct mapping)
#[inline]
pub fn phys_to_virt(phys: u64, phys_offset: u64) -> u64 {
    phys + phys_offset
}

/// Convert virtual address to physical
#[inline]
pub fn virt_to_phys(virt: u64, phys_offset: u64) -> u64 {
    virt - phys_offset
}
