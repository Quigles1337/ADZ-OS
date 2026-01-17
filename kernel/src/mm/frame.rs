//! Physical Frame Allocator
//!
//! Bitmap-based allocator for physical memory frames.

use crate::{boot::MemoryMap, KernelResult, KernelError, PAGE_SIZE};
use alloc::vec;
use alloc::vec::Vec;

/// Physical frame allocator using a bitmap
pub struct FrameAllocator {
    /// Bitmap of frame usage (1 = free, 0 = used)
    bitmap: Vec<u64>,
    /// Base physical address
    base: u64,
    /// Total number of frames
    total_frames: usize,
    /// Number of free frames
    free_count: usize,
    /// Next frame to check (for allocation speedup)
    next_free: usize,
}

impl FrameAllocator {
    /// Create new frame allocator from memory map
    pub fn new(memory_map: &MemoryMap) -> KernelResult<Self> {
        // Find highest usable address to size our bitmap
        let max_addr = memory_map.regions.iter()
            .filter(|r| r.kind == crate::boot::MemoryRegionKind::Usable)
            .map(|r| r.end())
            .max()
            .ok_or(KernelError::OutOfMemory)?;

        let total_frames = (max_addr as usize) / PAGE_SIZE;
        let bitmap_size = (total_frames + 63) / 64; // 64 bits per entry

        // Initialize bitmap with all frames marked as used
        let mut bitmap = vec![0u64; bitmap_size];
        let mut free_count = 0;

        // Mark usable regions as free
        for region in memory_map.usable_regions() {
            let start_frame = (region.start as usize) / PAGE_SIZE;
            let end_frame = (region.end() as usize) / PAGE_SIZE;

            for frame in start_frame..end_frame {
                let idx = frame / 64;
                let bit = frame % 64;
                if idx < bitmap.len() {
                    bitmap[idx] |= 1 << bit;
                    free_count += 1;
                }
            }
        }

        Ok(Self {
            bitmap,
            base: 0,
            total_frames,
            free_count,
            next_free: 0,
        })
    }

    /// Allocate a single frame
    pub fn allocate(&mut self) -> KernelResult<u64> {
        // Start searching from hint
        let start = self.next_free / 64;

        for i in 0..self.bitmap.len() {
            let idx = (start + i) % self.bitmap.len();
            let entry = self.bitmap[idx];

            if entry != 0 {
                // Find first set bit
                let bit = entry.trailing_zeros() as usize;
                let frame = idx * 64 + bit;

                // Clear bit (mark as used)
                self.bitmap[idx] &= !(1 << bit);
                self.free_count -= 1;
                self.next_free = frame + 1;

                let addr = (frame * PAGE_SIZE) as u64 + self.base;
                return Ok(addr);
            }
        }

        Err(KernelError::OutOfMemory)
    }

    /// Allocate contiguous frames
    pub fn allocate_contiguous(&mut self, count: usize) -> KernelResult<u64> {
        if count == 0 {
            return Err(KernelError::InvalidArgument);
        }

        if count == 1 {
            return self.allocate();
        }

        // Search for contiguous free frames
        let mut run_start = 0;
        let mut run_length = 0;

        for frame in 0..self.total_frames {
            let idx = frame / 64;
            let bit = frame % 64;

            if self.bitmap[idx] & (1 << bit) != 0 {
                // Frame is free
                if run_length == 0 {
                    run_start = frame;
                }
                run_length += 1;

                if run_length >= count {
                    // Found enough contiguous frames
                    for f in run_start..run_start + count {
                        let fidx = f / 64;
                        let fbit = f % 64;
                        self.bitmap[fidx] &= !(1 << fbit);
                    }
                    self.free_count -= count;
                    self.next_free = run_start + count;

                    let addr = (run_start * PAGE_SIZE) as u64 + self.base;
                    return Ok(addr);
                }
            } else {
                // Frame is used, reset run
                run_length = 0;
            }
        }

        Err(KernelError::OutOfMemory)
    }

    /// Deallocate a frame
    pub fn deallocate(&mut self, addr: u64) -> KernelResult<()> {
        if addr < self.base {
            return Err(KernelError::InvalidArgument);
        }

        let frame = ((addr - self.base) as usize) / PAGE_SIZE;

        if frame >= self.total_frames {
            return Err(KernelError::InvalidArgument);
        }

        let idx = frame / 64;
        let bit = frame % 64;

        // Check if already free
        if self.bitmap[idx] & (1 << bit) != 0 {
            log::warn!("Double free of frame at {:#x}", addr);
            return Err(KernelError::InvalidArgument);
        }

        // Mark as free
        self.bitmap[idx] |= 1 << bit;
        self.free_count += 1;

        // Update hint if this is earlier
        if frame < self.next_free {
            self.next_free = frame;
        }

        Ok(())
    }

    /// Mark a range of addresses as used
    pub fn mark_range_used(&mut self, start: u64, end: u64) -> KernelResult<()> {
        let start_frame = (start as usize) / PAGE_SIZE;
        let end_frame = ((end as usize) + PAGE_SIZE - 1) / PAGE_SIZE;

        for frame in start_frame..end_frame {
            if frame < self.total_frames {
                let idx = frame / 64;
                let bit = frame % 64;

                if self.bitmap[idx] & (1 << bit) != 0 {
                    self.bitmap[idx] &= !(1 << bit);
                    self.free_count -= 1;
                }
            }
        }

        Ok(())
    }

    /// Get number of free frames
    pub fn free_frames(&self) -> usize {
        self.free_count
    }

    /// Get total number of frames
    pub fn total_frames(&self) -> usize {
        self.total_frames
    }
}
