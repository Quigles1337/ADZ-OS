//! Kernel Heap Allocator
//!
//! Simple bump allocator for early boot, replaced by more sophisticated
//! allocator after full initialization.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use spin::Mutex;

/// Kernel heap allocator
pub struct KernelHeap {
    inner: Mutex<HeapInner>,
}

struct HeapInner {
    heap_start: *mut u8,
    heap_size: usize,
    next: usize,
    allocations: usize,
}

// Safety: The heap is protected by a mutex
unsafe impl Send for HeapInner {}
unsafe impl Sync for KernelHeap {}

impl KernelHeap {
    /// Create new uninitialized heap
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(HeapInner {
                heap_start: null_mut(),
                heap_size: 0,
                next: 0,
                allocations: 0,
            }),
        }
    }

    /// Initialize the heap
    ///
    /// # Safety
    /// - heap_start must point to valid, unused memory
    /// - heap_size bytes starting at heap_start must be available
    pub unsafe fn init(&self, heap_start: *mut u8, heap_size: usize) {
        let mut inner = self.inner.lock();
        inner.heap_start = heap_start;
        inner.heap_size = heap_size;
        inner.next = 0;
        inner.allocations = 0;
    }

    /// Get heap statistics
    pub fn stats(&self) -> HeapStats {
        let inner = self.inner.lock();
        HeapStats {
            total: inner.heap_size,
            used: inner.next,
            free: inner.heap_size - inner.next,
            allocations: inner.allocations,
        }
    }
}

/// Heap statistics
#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    /// Total heap size
    pub total: usize,
    /// Used bytes
    pub used: usize,
    /// Free bytes
    pub free: usize,
    /// Number of allocations
    pub allocations: usize,
}

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut inner = self.inner.lock();

        if inner.heap_start.is_null() {
            return null_mut();
        }

        // Align up
        let align = layout.align();
        let size = layout.size();

        let alloc_start = (inner.next + align - 1) & !(align - 1);
        let alloc_end = alloc_start + size;

        if alloc_end > inner.heap_size {
            return null_mut();
        }

        inner.next = alloc_end;
        inner.allocations += 1;

        inner.heap_start.add(alloc_start)
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator doesn't deallocate
        // In production, use a proper allocator like linked_list_allocator
        let mut inner = self.inner.lock();
        inner.allocations = inner.allocations.saturating_sub(1);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Simple realloc: allocate new, copy, don't free old (bump allocator)
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_ptr = self.alloc(new_layout);

        if !new_ptr.is_null() {
            let copy_size = core::cmp::min(layout.size(), new_size);
            core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
        }

        new_ptr
    }
}
