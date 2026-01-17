//! Interrupt Handling
//!
//! Sets up the Interrupt Descriptor Table (IDT) and handlers.

use spin::Mutex;
use lazy_static::lazy_static;

/// Interrupt vector numbers
pub mod vectors {
    pub const DIVIDE_ERROR: u8 = 0;
    pub const DEBUG: u8 = 1;
    pub const NMI: u8 = 2;
    pub const BREAKPOINT: u8 = 3;
    pub const OVERFLOW: u8 = 4;
    pub const BOUND_RANGE: u8 = 5;
    pub const INVALID_OPCODE: u8 = 6;
    pub const DEVICE_NOT_AVAILABLE: u8 = 7;
    pub const DOUBLE_FAULT: u8 = 8;
    pub const INVALID_TSS: u8 = 10;
    pub const SEGMENT_NOT_PRESENT: u8 = 11;
    pub const STACK_SEGMENT: u8 = 12;
    pub const GENERAL_PROTECTION: u8 = 13;
    pub const PAGE_FAULT: u8 = 14;
    pub const X87_FPU: u8 = 16;
    pub const ALIGNMENT_CHECK: u8 = 17;
    pub const MACHINE_CHECK: u8 = 18;
    pub const SIMD_FP: u8 = 19;

    // Hardware interrupts (PIC remapped)
    pub const PIC_TIMER: u8 = 32;
    pub const PIC_KEYBOARD: u8 = 33;
    pub const PIC_CASCADE: u8 = 34;
    pub const PIC_COM2: u8 = 35;
    pub const PIC_COM1: u8 = 36;
    pub const PIC_LPT2: u8 = 37;
    pub const PIC_FLOPPY: u8 = 38;
    pub const PIC_LPT1: u8 = 39;
    pub const PIC_RTC: u8 = 40;
    pub const PIC_FREE1: u8 = 41;
    pub const PIC_FREE2: u8 = 42;
    pub const PIC_FREE3: u8 = 43;
    pub const PIC_MOUSE: u8 = 44;
    pub const PIC_FPU: u8 = 45;
    pub const PIC_ATA1: u8 = 46;
    pub const PIC_ATA2: u8 = 47;

    // Syscall
    pub const SYSCALL: u8 = 0x80;
}

/// Interrupt stack frame pushed by CPU
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InterruptFrame {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// IDT entry
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn empty() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn set_handler(&mut self, handler: u64, selector: u16, ist: u8, dpl: u8) {
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = selector;
        self.ist = ist;
        // Present, interrupt gate, DPL
        self.type_attr = 0x80 | (dpl << 5) | 0x0E;
        self.reserved = 0;
    }
}

/// IDT
#[repr(C, align(16))]
struct Idt {
    entries: [IdtEntry; 256],
}

impl Idt {
    const fn new() -> Self {
        Self {
            entries: [IdtEntry::empty(); 256],
        }
    }

    fn set_handler(&mut self, vector: u8, handler: u64) {
        self.entries[vector as usize].set_handler(handler, 0x08, 0, 0);
    }

    fn load(&self) {
        #[repr(C, packed)]
        struct IdtPtr {
            limit: u16,
            base: u64,
        }

        let ptr = IdtPtr {
            limit: (core::mem::size_of::<Idt>() - 1) as u16,
            base: self as *const _ as u64,
        };

        unsafe {
            core::arch::asm!("lidt [{}]", in(reg) &ptr, options(readonly, nostack));
        }
    }
}

static IDT: Mutex<Idt> = Mutex::new(Idt::new());

/// Initialize interrupt handling
pub fn init() {
    // Remap PIC to vectors 32-47
    init_pic();

    let mut idt = IDT.lock();

    // Exception handlers
    idt.set_handler(vectors::DIVIDE_ERROR, divide_error_handler as u64);
    idt.set_handler(vectors::DEBUG, debug_handler as u64);
    idt.set_handler(vectors::BREAKPOINT, breakpoint_handler as u64);
    idt.set_handler(vectors::INVALID_OPCODE, invalid_opcode_handler as u64);
    idt.set_handler(vectors::DOUBLE_FAULT, double_fault_handler as u64);
    idt.set_handler(vectors::GENERAL_PROTECTION, general_protection_handler as u64);
    idt.set_handler(vectors::PAGE_FAULT, page_fault_handler as u64);

    // Hardware interrupt handlers
    idt.set_handler(vectors::PIC_TIMER, timer_handler as u64);
    idt.set_handler(vectors::PIC_KEYBOARD, keyboard_handler as u64);

    idt.load();

    log::debug!("IDT loaded");
}

/// Initialize PIC (8259)
fn init_pic() {
    const PIC1_CMD: u16 = 0x20;
    const PIC1_DATA: u16 = 0x21;
    const PIC2_CMD: u16 = 0xA0;
    const PIC2_DATA: u16 = 0xA1;

    unsafe {
        // ICW1: Initialize
        outb(PIC1_CMD, 0x11);
        outb(PIC2_CMD, 0x11);

        // ICW2: Vector offset
        outb(PIC1_DATA, 32); // IRQ 0-7 -> vectors 32-39
        outb(PIC2_DATA, 40); // IRQ 8-15 -> vectors 40-47

        // ICW3: Cascade
        outb(PIC1_DATA, 4); // IRQ2 has slave
        outb(PIC2_DATA, 2); // Slave ID 2

        // ICW4: 8086 mode
        outb(PIC1_DATA, 0x01);
        outb(PIC2_DATA, 0x01);

        // Mask all except timer
        outb(PIC1_DATA, 0xFE); // Enable IRQ0 (timer)
        outb(PIC2_DATA, 0xFF);
    }
}

/// Send EOI to PIC
fn pic_eoi(irq: u8) {
    const PIC1_CMD: u16 = 0x20;
    const PIC2_CMD: u16 = 0xA0;

    unsafe {
        if irq >= 8 {
            outb(PIC2_CMD, 0x20);
        }
        outb(PIC1_CMD, 0x20);
    }
}

// Interrupt handlers

extern "x86-interrupt" fn divide_error_handler(frame: InterruptFrame) {
    log::error!("DIVIDE ERROR at {:#x}", frame.rip);
    loop { crate::hlt(); }
}

extern "x86-interrupt" fn debug_handler(frame: InterruptFrame) {
    log::debug!("Debug exception at {:#x}", frame.rip);
}

extern "x86-interrupt" fn breakpoint_handler(frame: InterruptFrame) {
    log::debug!("Breakpoint at {:#x}", frame.rip);
}

extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptFrame) {
    log::error!("INVALID OPCODE at {:#x}", frame.rip);
    loop { crate::hlt(); }
}

extern "x86-interrupt" fn double_fault_handler(frame: InterruptFrame, _error: u64) -> ! {
    log::error!("DOUBLE FAULT at {:#x}", frame.rip);
    loop { crate::hlt(); }
}

extern "x86-interrupt" fn general_protection_handler(frame: InterruptFrame, error: u64) {
    log::error!("GENERAL PROTECTION FAULT at {:#x}, error={:#x}", frame.rip, error);
    loop { crate::hlt(); }
}

extern "x86-interrupt" fn page_fault_handler(frame: InterruptFrame, error: u64) {
    let cr2: u64;
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack));
    }

    log::error!(
        "PAGE FAULT at {:#x}, addr={:#x}, error={:#x}",
        frame.rip, cr2, error
    );
    loop { crate::hlt(); }
}

extern "x86-interrupt" fn timer_handler(_frame: InterruptFrame) {
    // Call scheduler timer tick
    crate::sys::scheduler::timer_tick();

    pic_eoi(0);
}

extern "x86-interrupt" fn keyboard_handler(_frame: InterruptFrame) {
    // Read scancode
    let scancode: u8;
    unsafe {
        scancode = inb(0x60);
    }

    log::trace!("Keyboard: scancode={:#x}", scancode);

    pic_eoi(1);
}

// Port I/O

#[inline]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        in("dx") port,
        out("al") value,
        options(nomem, nostack, preserves_flags)
    );
    value
}
