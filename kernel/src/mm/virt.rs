//! Virtual Address Space Management
//!
//! Each process has its own address space, managed here.

use super::{VirtAddr, PhysAddr, PageTable, PageFlags, ENTRIES_PER_TABLE};
use crate::{PAGE_SIZE, KernelResult, KernelError};
use alloc::vec::Vec;

/// Virtual memory region
#[derive(Debug, Clone)]
pub struct VirtualRegion {
    /// Start address
    pub start: VirtAddr,
    /// Size in bytes
    pub size: usize,
    /// Protection flags
    pub flags: PageFlags,
    /// Region type
    pub kind: RegionKind,
}

/// Region types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Kernel code
    KernelCode,
    /// Kernel data
    KernelData,
    /// Kernel heap
    KernelHeap,
    /// Kernel stack
    KernelStack,
    /// User code
    UserCode,
    /// User data
    UserData,
    /// User heap
    UserHeap,
    /// User stack
    UserStack,
    /// Memory-mapped file
    MappedFile,
    /// Shared memory
    Shared,
    /// Guard page (unmapped, for stack overflow detection)
    Guard,
}

impl VirtualRegion {
    /// Create new region
    pub fn new(start: VirtAddr, size: usize, flags: PageFlags, kind: RegionKind) -> Self {
        Self { start, size, flags, kind }
    }

    /// End address (exclusive)
    pub fn end(&self) -> VirtAddr {
        VirtAddr::new(self.start.as_u64() + self.size as u64)
    }

    /// Check if address is in this region
    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr.as_u64() >= self.start.as_u64() && addr.as_u64() < self.end().as_u64()
    }

    /// Check if regions overlap
    pub fn overlaps(&self, other: &VirtualRegion) -> bool {
        self.start.as_u64() < other.end().as_u64() &&
        other.start.as_u64() < self.end().as_u64()
    }
}

/// Address space for a process
pub struct AddressSpace {
    /// PML4 physical address
    pml4_phys: PhysAddr,
    /// Virtual memory regions
    regions: Vec<VirtualRegion>,
    /// Physical memory offset for kernel access
    phys_offset: u64,
}

impl AddressSpace {
    /// Create new empty address space
    pub fn new(phys_offset: u64) -> KernelResult<Self> {
        // Allocate PML4
        let pml4_phys = PhysAddr::new(super::alloc_frame()?);

        // Clear PML4
        let pml4_virt = pml4_phys.as_u64() + phys_offset;
        unsafe {
            let pml4 = &mut *(pml4_virt as *mut PageTable);
            pml4.clear();
        }

        Ok(Self {
            pml4_phys,
            regions: Vec::new(),
            phys_offset,
        })
    }

    /// Get PML4 physical address (for CR3)
    pub fn pml4_phys(&self) -> PhysAddr {
        self.pml4_phys
    }

    /// Map a page
    pub fn map_page(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> KernelResult<()> {
        let indices = virt.page_table_indices();
        let phys_offset = self.phys_offset;

        // Helper to get table reference from physical address
        let get_table = |paddr: u64| -> &'static mut PageTable {
            unsafe { &mut *((paddr + phys_offset) as *mut PageTable) }
        };

        // Helper to clear a page
        let clear_page = |paddr: u64| {
            unsafe {
                core::ptr::write_bytes((paddr + phys_offset) as *mut u8, 0, PAGE_SIZE);
            }
        };

        let pml4 = get_table(self.pml4_phys.as_u64());

        // PDPT
        if !pml4[indices[0]].is_present() {
            let pdpt_phys = super::alloc_frame()?;
            clear_page(pdpt_phys);
            pml4[indices[0]] = super::PageTableEntry::new(
                PhysAddr::new(pdpt_phys),
                PageFlags::PRESENT | PageFlags::WRITABLE | (flags & PageFlags::USER),
            );
        }
        let pdpt_phys = pml4[indices[0]].addr().as_u64();
        let pdpt = get_table(pdpt_phys);

        // PD
        if !pdpt[indices[1]].is_present() {
            let pd_phys = super::alloc_frame()?;
            clear_page(pd_phys);
            pdpt[indices[1]] = super::PageTableEntry::new(
                PhysAddr::new(pd_phys),
                PageFlags::PRESENT | PageFlags::WRITABLE | (flags & PageFlags::USER),
            );
        }
        let pd_phys = pdpt[indices[1]].addr().as_u64();
        let pd = get_table(pd_phys);

        // PT
        if !pd[indices[2]].is_present() {
            let pt_phys = super::alloc_frame()?;
            clear_page(pt_phys);
            pd[indices[2]] = super::PageTableEntry::new(
                PhysAddr::new(pt_phys),
                PageFlags::PRESENT | PageFlags::WRITABLE | (flags & PageFlags::USER),
            );
        }
        let pt_phys = pd[indices[2]].addr().as_u64();
        let pt = get_table(pt_phys);

        // Map the page
        if pt[indices[3]].is_present() {
            return Err(KernelError::AlreadyExists);
        }

        pt[indices[3]] = super::PageTableEntry::new(phys, flags);

        Ok(())
    }

    /// Unmap a page
    pub fn unmap_page(&mut self, virt: VirtAddr) -> KernelResult<PhysAddr> {
        let indices = virt.page_table_indices();
        let phys_offset = self.phys_offset;

        let get_table = |paddr: u64| -> &'static mut PageTable {
            unsafe { &mut *((paddr + phys_offset) as *mut PageTable) }
        };

        let pml4 = get_table(self.pml4_phys.as_u64());

        if !pml4[indices[0]].is_present() {
            return Err(KernelError::NotFound);
        }
        let pdpt = get_table(pml4[indices[0]].addr().as_u64());

        if !pdpt[indices[1]].is_present() {
            return Err(KernelError::NotFound);
        }
        let pd = get_table(pdpt[indices[1]].addr().as_u64());

        if !pd[indices[2]].is_present() {
            return Err(KernelError::NotFound);
        }
        let pt = get_table(pd[indices[2]].addr().as_u64());

        if !pt[indices[3]].is_present() {
            return Err(KernelError::NotFound);
        }

        let phys = pt[indices[3]].addr();
        pt[indices[3]].clear();

        // Flush TLB for this page
        super::page::flush_tlb(virt);

        Ok(phys)
    }

    /// Map a range of pages
    pub fn map_range(
        &mut self,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        size: usize,
        flags: PageFlags,
    ) -> KernelResult<()> {
        let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;

        for i in 0..pages {
            let virt = VirtAddr::new(virt_start.as_u64() + (i * PAGE_SIZE) as u64);
            let phys = PhysAddr::new(phys_start.as_u64() + (i * PAGE_SIZE) as u64);
            self.map_page(virt, phys, flags)?;
        }

        Ok(())
    }

    /// Add a region
    pub fn add_region(&mut self, region: VirtualRegion) -> KernelResult<()> {
        // Check for overlaps
        for existing in &self.regions {
            if existing.overlaps(&region) {
                return Err(KernelError::AlreadyExists);
            }
        }

        self.regions.push(region);
        Ok(())
    }

    /// Find region containing address
    pub fn find_region(&self, addr: VirtAddr) -> Option<&VirtualRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Activate this address space (load CR3)
    pub fn activate(&self) {
        unsafe {
            core::arch::asm!(
                "mov cr3, {}",
                in(reg) self.pml4_phys.as_u64(),
                options(nostack)
            );
        }
    }

    // Helper functions

    fn pml4_mut(&mut self) -> &mut PageTable {
        let virt = self.pml4_phys.as_u64() + self.phys_offset;
        unsafe { &mut *(virt as *mut PageTable) }
    }

    fn table_from_entry_mut(&self, entry: &super::PageTableEntry) -> &mut PageTable {
        let virt = entry.addr().as_u64() + self.phys_offset;
        unsafe { &mut *(virt as *mut PageTable) }
    }

    fn clear_page(&self, phys: u64) {
        let virt = phys + self.phys_offset;
        unsafe {
            core::ptr::write_bytes(virt as *mut u8, 0, PAGE_SIZE);
        }
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // TODO: Free all page tables and mapped pages
        // For now, just log
        log::debug!("Address space dropped, PML4 at {:?}", self.pml4_phys);
    }
}
