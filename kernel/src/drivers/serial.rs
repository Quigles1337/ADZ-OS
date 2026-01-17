//! Serial Port Driver (UART 16550)
//!
//! Provides debug output via COM1.

use spin::Mutex;
use core::fmt::{self, Write};

/// COM1 port address
const COM1: u16 = 0x3F8;

/// Serial port
pub struct SerialPort {
    port: u16,
}

impl SerialPort {
    /// Create new serial port
    pub const fn new(port: u16) -> Self {
        Self { port }
    }

    /// Initialize the serial port
    pub fn init(&mut self) {
        unsafe {
            // Disable interrupts
            outb(self.port + 1, 0x00);

            // Enable DLAB (set baud rate divisor)
            outb(self.port + 3, 0x80);

            // Set divisor to 1 (115200 baud)
            outb(self.port + 0, 0x01);
            outb(self.port + 1, 0x00);

            // 8 bits, no parity, one stop bit
            outb(self.port + 3, 0x03);

            // Enable FIFO, clear them, with 14-byte threshold
            outb(self.port + 2, 0xC7);

            // IRQs enabled, RTS/DSR set
            outb(self.port + 4, 0x0B);

            // Set in loopback mode, test the serial chip
            outb(self.port + 4, 0x1E);

            // Test serial chip (send byte 0xAE and check if serial returns same byte)
            outb(self.port + 0, 0xAE);

            // Check if serial is faulty (i.e. not same byte as sent)
            if inb(self.port + 0) != 0xAE {
                return;
            }

            // If serial is not faulty, set it in normal operation mode
            outb(self.port + 4, 0x0F);
        }
    }

    /// Check if transmit buffer is empty
    fn is_transmit_empty(&self) -> bool {
        unsafe { inb(self.port + 5) & 0x20 != 0 }
    }

    /// Write a byte
    pub fn write_byte(&mut self, byte: u8) {
        // Wait for transmit buffer to be empty
        while !self.is_transmit_empty() {
            core::hint::spin_loop();
        }

        unsafe {
            outb(self.port, byte);
        }
    }

    /// Write a string
    pub fn write_str(&mut self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        SerialPort::write_str(self, s);
        Ok(())
    }
}

/// Global serial port
static SERIAL: Mutex<SerialPort> = Mutex::new(SerialPort::new(COM1));

/// Initialize serial port
pub fn init() {
    SERIAL.lock().init();
}

/// Print to serial port
pub fn print(args: fmt::Arguments) {
    SERIAL.lock().write_fmt(args).unwrap();
}

/// Print macro for serial output
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::drivers::serial::print(format_args!($($arg)*))
    };
}

/// Println macro for serial output
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
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

/// Logger implementation for log crate
pub struct SerialLogger;

impl log::Log for SerialLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            serial_println!(
                "[{:5}] {}:{}: {}",
                record.level(),
                record.file().unwrap_or("?"),
                record.line().unwrap_or(0),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

/// Global logger instance
static LOGGER: SerialLogger = SerialLogger;

/// Initialize logger
pub fn init_logger() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Debug);
}
