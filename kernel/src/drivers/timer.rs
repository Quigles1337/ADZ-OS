//! Timer Driver (PIT 8253/8254)
//!
//! Programmable Interval Timer for system tick.

use spin::Mutex;

/// PIT frequency (Hz)
const PIT_FREQUENCY: u32 = 1193182;

/// Target tick rate (Hz)
const TICK_RATE: u32 = 100;

/// PIT ports
const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;

/// Timer state
struct Timer {
    /// Ticks since boot
    ticks: u64,
    /// Tick rate in Hz
    rate: u32,
}

impl Timer {
    const fn new() -> Self {
        Self {
            ticks: 0,
            rate: TICK_RATE,
        }
    }

    fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
    }
}

static TIMER: Mutex<Timer> = Mutex::new(Timer::new());

/// Initialize the PIT
pub fn init() {
    let divisor = PIT_FREQUENCY / TICK_RATE;

    unsafe {
        // Channel 0, lobyte/hibyte, rate generator
        outb(PIT_COMMAND, 0x36);

        // Set divisor
        outb(PIT_CHANNEL0, (divisor & 0xFF) as u8);
        outb(PIT_CHANNEL0, ((divisor >> 8) & 0xFF) as u8);
    }

    log::debug!("PIT initialized at {} Hz", TICK_RATE);
}

/// Get ticks since boot
pub fn ticks() -> u64 {
    TIMER.lock().ticks
}

/// Get tick rate in Hz
pub fn rate() -> u32 {
    TIMER.lock().rate
}

/// Get uptime in milliseconds
pub fn uptime_ms() -> u64 {
    let timer = TIMER.lock();
    (timer.ticks * 1000) / timer.rate as u64
}

/// Get uptime in seconds
pub fn uptime_secs() -> u64 {
    let timer = TIMER.lock();
    timer.ticks / timer.rate as u64
}

/// Called from timer interrupt
pub fn on_tick() {
    TIMER.lock().tick();
}

/// Sleep for approximately the given number of milliseconds
/// (busy wait - only for early boot)
pub fn sleep_ms(ms: u64) {
    let target = ticks() + (ms * rate() as u64) / 1000;
    while ticks() < target {
        core::hint::spin_loop();
    }
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
