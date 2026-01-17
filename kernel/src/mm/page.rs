//! Page Table Management
//!
//! 4-level page tables for x86_64:
//! - PML4 (Page Map Level 4)
//! - PDPT (Page Directory Pointer Table)
//! - PD (Page Directory)
//! - PT (Page Table)

use crate::{PAGE_SIZE, KernelResult, KernelError};
use super::{PhysAddr, VirtAddr};
use bitflags::bitflags;

/// Number of entries per page table
pub const ENTRIES_PER_TABLE: usize = 512;

bitflags! {
    /// Page table entry flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PageFlags: u64 {
        /// Page is present in memory
        const PRESENT = 1 << 0;
        /// Page is writable
        const WRITABLE = 1 << 1;
        /// Page is accessible from user mode
        const USER = 1 << 2;
        /// Write-through caching
        const WRITE_THROUGH = 1 << 3;
        /// Disable caching
        const NO_CACHE = 1 << 4;
        /// Page has been accessed
        const ACCESSED = 1 << 5;
        /// Page has been written to
        const DIRTY = 1 << 6;
        /// Huge page (2MB or 1GB)
        const HUGE = 1 << 7;
        /// Global (not flushed on CR3 switch)
        const GLOBAL = 1 << 8;
        /// No execute (requires NXE bit in EFER)
        const NO_EXECUTE = 1 << 63;
    }
}

impl PageFlags {
    /// Kernel code flags (read-only, executable)
    pub const KERNEL_CODE: Self = Self::PRESENT.union(Self::GLOBAL);

    /// Kernel data flags (read-write, no execute)
    pub const KERNEL_DATA: Self = Self::PRESENT.union(Self::WRITABLE).union(Self::GLOBAL).union(Self::NO_EXECUTE);

    /// Kernel read-only flags
    pub const KERNEL_RODATA: Self = Self::PRESENT.union(Self::GLOBAL).union(Self::NO_EXECUTE);

    /// User code flags
    pub const USER_CODE: Self = Self::PRESENT.union(Self::USER);

    /// User data flags
    pub const USER_DATA: Self = Self::PRESENT.union(Self::WRITABLE).union(Self::USER).union(Self::NO_EXECUTE);
}

/// Page table entry
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// Create empty entry
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create entry with address and flags
    pub fn new(addr: PhysAddr, flags: PageFlags) -> Self {
        Self((addr.as_u64() & 0x000F_FFFF_FFFF_F000) | flags.bits())
    }

    /// Get flags
    pub fn flags(&self) -> PageFlags {
        PageFlags::from_bits_truncate(self.0)
    }

    /// Get physical address
    pub fn addr(&self) -> PhysAddr {
        PhysAddr::new(self.0 & 0x000F_FFFF_FFFF_F000)
    }

    /// Check if entry is present
    pub fn is_present(&self) -> bool {
        self.flags().contains(PageFlags::PRESENT)
    }

    /// Check if entry is a huge page
    pub fn is_huge(&self) -> bool {
        self.flags().contains(PageFlags::HUGE)
    }

    /// Check if entry is unused
    pub fn is_unused(&self) -> bool {
        self.0 == 0
    }

    /// Set flags
    pub fn set_flags(&mut self, flags: PageFlags) {
        self.0 = (self.0 & 0x000F_FFFF_FFFF_F000) | flags.bits();
    }

    /// Set address
    pub fn set_addr(&mut self, addr: PhysAddr) {
        self.0 = (addr.as_u64() & 0x000F_FFFF_FFFF_F000) | (self.0 & !0x000F_FFFF_FFFF_F000);
    }

    /// Clear entry
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

impl core::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PageTableEntry")
            .field("addr", &format_args!("{:#x}", self.addr().as_u64()))
            .field("flags", &self.flags())
            .finish()
    }
}

/// Page table (512 entries)
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [PageTableEntry; ENTRIES_PER_TABLE],
}

impl PageTable {
    /// Create empty page table
    pub const fn new() -> Self {
        const EMPTY: PageTableEntry = PageTableEntry::empty();
        Self {
            entries: [EMPTY; ENTRIES_PER_TABLE],
        }
    }

    /// Get entry by index
    pub fn entry(&self, index: usize) -> &PageTableEntry {
        &self.entries[index]
    }

    /// Get mutable entry by index
    pub fn entry_mut(&mut self, index: usize) -> &mut PageTableEntry {
        &mut self.entries[index]
    }

    /// Iterate over entries
    pub fn iter(&self) -> impl Iterator<Item = &PageTableEntry> {
        self.entries.iter()
    }

    /// Iterate mutably over entries
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut PageTableEntry> {
        self.entries.iter_mut()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            entry.clear();
        }
    }
}

impl core::ops::Index<usize> for PageTable {
    type Output = PageTableEntry;

    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

impl core::ops::IndexMut<usize> for PageTable {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.entries[index]
    }
}

/// Page table walker for translating addresses
pub struct PageTableWalker {
    phys_offset: u64,
}

impl PageTableWalker {
    /// Create new walker with physical memory offset
    pub fn new(phys_offset: u64) -> Self {
        Self { phys_offset }
    }

    /// Translate virtual address to physical
    pub fn translate(&self, pml4: &PageTable, virt: VirtAddr) -> Option<PhysAddr> {
        let indices = virt.page_table_indices();

        // Walk PML4
        let pml4e = &pml4[indices[0]];
        if !pml4e.is_present() {
            return None;
        }

        let pdpt = self.table_from_entry(pml4e)?;

        // Walk PDPT
        let pdpte = &pdpt[indices[1]];
        if !pdpte.is_present() {
            return None;
        }
        if pdpte.is_huge() {
            // 1GB page
            let offset = virt.as_u64() & 0x3FFF_FFFF;
            return Some(PhysAddr::new(pdpte.addr().as_u64() + offset));
        }

        let pd = self.table_from_entry(pdpte)?;

        // Walk PD
        let pde = &pd[indices[2]];
        if !pde.is_present() {
            return None;
        }
        if pde.is_huge() {
            // 2MB page
            let offset = virt.as_u64() & 0x1F_FFFF;
            return Some(PhysAddr::new(pde.addr().as_u64() + offset));
        }

        let pt = self.table_from_entry(pde)?;

        // Walk PT
        let pte = &pt[indices[3]];
        if !pte.is_present() {
            return None;
        }

        // 4KB page
        let offset = virt.as_u64() & 0xFFF;
        Some(PhysAddr::new(pte.addr().as_u64() + offset))
    }

    /// Get page table from entry's physical address
    fn table_from_entry(&self, entry: &PageTableEntry) -> Option<&PageTable> {
        if !entry.is_present() {
            return None;
        }

        let virt = entry.addr().as_u64() + self.phys_offset;
        unsafe { Some(&*(virt as *const PageTable)) }
    }
}

/// Flush TLB for a single page
pub fn flush_tlb(addr: VirtAddr) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) addr.as_u64(), options(nostack, preserves_flags));
    }
}

/// Flush entire TLB (by reloading CR3)
pub fn flush_tlb_all() {
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack));
    }
}
