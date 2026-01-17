//! Device Drivers
//!
//! Minimal drivers for kernel operation:
//! - Serial (UART 16550) for debug output
//! - Interrupts (PIC/APIC)
//! - Timer (PIT/APIC timer)

pub mod interrupts;
pub mod serial;
pub mod timer;
