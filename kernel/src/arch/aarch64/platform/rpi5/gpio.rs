//! RP1 GPIO Driver for Raspberry Pi 5
//!
//! The RP1 GPIO controller manages the 28 user-accessible GPIO pins
//! on the Raspberry Pi 5's 40-pin header.
//!
//! Each GPIO pin has:
//! - Function select (input, output, or alternate functions)
//! - Output level control
//! - Input level reading
//! - Pull-up/pull-down configuration
//! - Event detection (edges, levels)

use super::memory_map::RP1_GPIO_BASE;
use super::mmio::MmioReg;

/// GPIO function select values
///
/// Each GPIO pin can be configured to one of several functions.
/// The available alternate functions depend on the specific pin.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpioFunction {
    /// Input mode
    Input = 0,
    /// Output mode
    Output = 1,
    /// Alternate function 0 (varies by pin)
    Alt0 = 4,
    /// Alternate function 1
    Alt1 = 5,
    /// Alternate function 2
    Alt2 = 6,
    /// Alternate function 3
    Alt3 = 7,
    /// Alternate function 4
    Alt4 = 3,
    /// Alternate function 5
    Alt5 = 2,
}

/// GPIO pull-up/pull-down configuration
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpioPull {
    /// No pull-up or pull-down
    None = 0,
    /// Pull-down resistor enabled
    Down = 1,
    /// Pull-up resistor enabled
    Up = 2,
}

/// RP1 GPIO register offsets per pin
///
/// Each GPIO pin has a set of registers at a fixed stride.
mod reg {
    /// GPIO status register (read-only)
    pub const STATUS: usize = 0x00;
    /// GPIO control register
    pub const CTRL: usize = 0x04;
}

/// Register stride per GPIO pin (8 bytes per pin)
const GPIO_REG_STRIDE: usize = 0x08;

/// Control register bit fields
mod ctrl {
    /// Function select mask (bits 4:0)
    pub const FUNCSEL_MASK: u32 = 0x1F;
    /// Output override (bit 13)
    pub const OUTOVER_SHIFT: u32 = 13;
    /// Output enable override (bit 15)
    #[allow(dead_code)]
    pub const OEOVER_SHIFT: u32 = 15;
}

/// Status register bit fields (from Linux pinctrl-rp1.c)
mod status {
    /// Input level (bit 17)
    pub const LEVEL_BIT: u32 = 17;
    /// Falling edge event detected (bit 20)
    pub const EVENT_FALLING: u32 = 1 << 20;
    /// Rising edge event detected (bit 21)
    pub const EVENT_RISING: u32 = 1 << 21;
    /// Low level event detected (bit 22)
    #[allow(dead_code)]
    pub const EVENT_LOW: u32 = 1 << 22;
    /// High level event detected (bit 23)
    #[allow(dead_code)]
    pub const EVENT_HIGH: u32 = 1 << 23;
    /// Mask for all raw event bits
    pub const EVENT_MASK: u32 = 0xF << 20;
}

/// Control register interrupt enable bits (from Linux pinctrl-rp1.c)
mod irq_ctrl {
    /// Enable falling edge interrupt (bit 20)
    pub const IRQEN_FALLING: u32 = 1 << 20;
    /// Enable rising edge interrupt (bit 21)
    pub const IRQEN_RISING: u32 = 1 << 21;
    /// Enable low level interrupt (bit 22)
    #[allow(dead_code)]
    pub const IRQEN_LOW: u32 = 1 << 22;
    /// Enable high level interrupt (bit 23)
    #[allow(dead_code)]
    pub const IRQEN_HIGH: u32 = 1 << 23;
    /// IRQ reset - write 1 to clear pending interrupt (bit 28)
    pub const IRQRESET: u32 = 1 << 28;
}

/// RP1 GPIO Driver
pub struct Rp1Gpio {
    base: usize,
}

impl Rp1Gpio {
    /// Number of GPIO pins available
    pub const NUM_PINS: u8 = 28;

    /// Create a new GPIO instance
    ///
    /// # Safety
    ///
    /// Must be called only once. The GPIO hardware must be accessible
    /// at the configured address.
    pub const unsafe fn new() -> Self {
        Self {
            base: RP1_GPIO_BASE,
        }
    }

    /// Set the function of a GPIO pin
    ///
    /// # Panics
    ///
    /// Panics if pin number is >= 28
    pub fn set_function(&self, pin: u8, func: GpioFunction) {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);

        let ctrl = self.reg_ctrl(pin);
        ctrl.modify(|v| (v & !ctrl::FUNCSEL_MASK) | (func as u32));
    }

    /// Get the current function of a GPIO pin
    pub fn get_function(&self, pin: u8) -> u32 {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);

        self.reg_ctrl(pin).read() & ctrl::FUNCSEL_MASK
    }

    /// Set a GPIO pin high (output mode)
    ///
    /// The pin must be configured as an output first.
    pub fn set_high(&self, pin: u8) {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);

        let ctrl = self.reg_ctrl(pin);
        // Set output override to drive high (value 3 = high)
        ctrl.modify(|v| v | (3 << ctrl::OUTOVER_SHIFT));
    }

    /// Set a GPIO pin low (output mode)
    ///
    /// The pin must be configured as an output first.
    pub fn set_low(&self, pin: u8) {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);

        let ctrl = self.reg_ctrl(pin);
        // Set output override to drive low (value 2 = low)
        ctrl.modify(|v| (v & !(3 << ctrl::OUTOVER_SHIFT)) | (2 << ctrl::OUTOVER_SHIFT));
    }

    /// Toggle a GPIO pin
    pub fn toggle(&self, pin: u8) {
        if self.read(pin) {
            self.set_low(pin);
        } else {
            self.set_high(pin);
        }
    }

    /// Read the current level of a GPIO pin
    ///
    /// Returns `true` if the pin is high, `false` if low.
    pub fn read(&self, pin: u8) -> bool {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);

        let status = self.reg_status(pin);
        (status.read() & (1 << status::LEVEL_BIT)) != 0
    }

    /// Configure a GPIO pin as output and set initial level
    pub fn configure_output(&self, pin: u8, initial_high: bool) {
        self.set_function(pin, GpioFunction::Output);
        if initial_high {
            self.set_high(pin);
        } else {
            self.set_low(pin);
        }
    }

    /// Configure a GPIO pin as input
    pub fn configure_input(&self, pin: u8) {
        self.set_function(pin, GpioFunction::Input);
    }

    /// Configure GPIO pins 14 and 15 for UART
    ///
    /// This sets them to Alt0 function (UART TXD/RXD).
    /// Note: With `enable_rp1_uart=1`, firmware already does this.
    pub fn setup_uart(&self) {
        self.set_function(14, GpioFunction::Alt0); // TXD0
        self.set_function(15, GpioFunction::Alt0); // RXD0
    }

    // Register accessors
    fn reg_status(&self, pin: u8) -> MmioReg<u32> {
        let offset = (pin as usize) * GPIO_REG_STRIDE + reg::STATUS;
        // SAFETY: The base address is valid (checked at creation) and the offset is within bounds for the pin.
        unsafe { MmioReg::new(self.base + offset) }
    }

    fn reg_ctrl(&self, pin: u8) -> MmioReg<u32> {
        let offset = (pin as usize) * GPIO_REG_STRIDE + reg::CTRL;
        // SAFETY: The base address is valid (checked at creation) and the offset is within bounds for the pin.
        unsafe { MmioReg::new(self.base + offset) }
    }

    /// Enable interrupt for a specific pin
    ///
    /// Configures the GPIO control register to generate interrupts on
    /// the specified edge transitions.
    pub fn enable_interrupt(&self, pin: u8, rising: bool, falling: bool) {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);
        let ctrl = self.reg_ctrl(pin);
        let mut mask = 0;
        if rising {
            mask |= irq_ctrl::IRQEN_RISING;
        }
        if falling {
            mask |= irq_ctrl::IRQEN_FALLING;
        }
        ctrl.modify(|v| v | mask);
    }

    /// Disable interrupt for a specific pin
    pub fn disable_interrupt(&self, pin: u8) {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);
        let ctrl = self.reg_ctrl(pin);
        let mask = irq_ctrl::IRQEN_RISING
            | irq_ctrl::IRQEN_FALLING
            | irq_ctrl::IRQEN_LOW
            | irq_ctrl::IRQEN_HIGH;
        ctrl.modify(|v| v & !mask);
    }

    /// Clear interrupt for a specific pin
    ///
    /// Writes to the IRQRESET bit in the control register to acknowledge
    /// and clear the pending interrupt.
    pub fn clear_interrupt(&self, pin: u8) {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);
        let ctrl = self.reg_ctrl(pin);
        // Set IRQRESET bit to clear the interrupt
        ctrl.modify(|v| v | irq_ctrl::IRQRESET);
    }

    /// Check if a pin has a pending interrupt event
    ///
    /// Returns the raw event status bits (falling, rising, low, high).
    pub fn get_pending_events(&self, pin: u8) -> u32 {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);
        let status = self.reg_status(pin).read();
        status & status::EVENT_MASK
    }

    /// Check if a rising edge event is pending
    pub fn has_rising_event(&self, pin: u8) -> bool {
        (self.get_pending_events(pin) & status::EVENT_RISING) != 0
    }

    /// Check if a falling edge event is pending
    pub fn has_falling_event(&self, pin: u8) -> bool {
        (self.get_pending_events(pin) & status::EVENT_FALLING) != 0
    }
}

/// Read the ARM generic timer counter for high-precision timestamps
#[inline]
fn read_timer_counter() -> u64 {
    let cntvct: u64;
    // SAFETY: Reading the virtual counter register is safe in EL1/EL0.
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) cntvct);
    }
    cntvct
}

/// Get the timer frequency for converting counter to nanoseconds
#[inline]
fn get_timer_frequency() -> u64 {
    let cntfrq: u64;
    // SAFETY: Reading the counter frequency register is safe in EL1/EL0.
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) cntfrq);
    }
    cntfrq
}

/// Convert timer counter value to nanoseconds
#[inline]
fn counter_to_ns(counter: u64) -> u64 {
    let freq = get_timer_frequency();
    if freq == 0 {
        return 0;
    }
    // Avoid overflow: (counter * 1_000_000_000) / freq
    // Use: counter / freq * 1_000_000_000 + (counter % freq) * 1_000_000_000 / freq
    let secs = counter / freq;
    let remainder = counter % freq;
    secs * 1_000_000_000 + (remainder * 1_000_000_000) / freq
}

/// Handle GPIO interrupt
///
/// Called from the main IRQ handler when an RP1 GPIO interrupt fires.
/// Scans all pins for pending events and invokes attached BPF programs.
pub fn handle_interrupt() {
    // SAFETY: We are in an interrupt handler, so we can access the GPIO hardware.
    // The base address is correct for RPi5.
    let gpio = unsafe { Rp1Gpio::new() };

    // Get timestamp at interrupt entry for accurate timing
    let timestamp = counter_to_ns(read_timer_counter());
    // Bench (Task 11): stamp the cycle counter at IRQ entry so the actuation
    // seam can report edge->actuate latency (M-C).
    #[cfg(feature = "bench")]
    crate::bench::mark_gpio_irq_entry();

    // Scan all pins for events
    for pin in 0..Rp1Gpio::NUM_PINS {
        let events = gpio.get_pending_events(pin);

        // Check if any event is pending on this pin
        if events != 0 {
            // Determine edge type from event status
            let is_rising = (events & status::EVENT_RISING) != 0;
            let is_falling = (events & status::EVENT_FALLING) != 0;

            // Determine the edge type for BPF context
            // 1 = rising, 2 = falling, 3 = both (shouldn't normally happen)
            let edge = match (is_rising, is_falling) {
                (true, false) => 1, // Rising
                (false, true) => 2, // Falling
                (true, true) => 3,  // Both (edge case)
                (false, false) => {
                    // Level interrupt or spurious - skip
                    gpio.clear_interrupt(pin);
                    continue;
                }
            };

            // Bench (Task 11): the e-stop button is not a BPF attach — route its
            // edge straight to the kernel-owned e-stop instead of dispatching.
            #[cfg(feature = "bench")]
            if pin == crate::bench::ESTOP_BUTTON_PIN {
                // Resolve press vs release. With the external pull-up, pressed =
                // pin low (falling edge). Edge 3 (both edges / bounce) is
                // ambiguous, so fall back to the current pin level — a real press
                // must never be dropped just because a release edge was coalesced.
                let pressed = match edge {
                    2 => true,            // falling: pressed
                    1 => false,           // rising: released
                    _ => !gpio.read(pin), // ambiguous: low level == pressed
                };
                gpio.clear_interrupt(pin);
                crate::bench::handle_estop_button(pressed);
                continue;
            }

            // Read current pin value
            let value = if gpio.read(pin) { 1 } else { 0 };

            // 1. Clear interrupt FIRST to avoid missing edges
            gpio.clear_interrupt(pin);

            // 2. Prepare BPF Context
            let event = kernel_bpf::attach::GpioEvent {
                timestamp,
                chip_id: 0, // gpiochip0 (RP1 IO Bank 0)
                line: pin as u32,
                edge,
                value,
            };

            // SAFETY: Transmuting struct to slice for read-only access
            let slice = unsafe {
                core::slice::from_raw_parts(
                    &event as *const _ as *const u8,
                    core::mem::size_of::<kernel_bpf::attach::GpioEvent>(),
                )
            };

            let ctx = kernel_bpf::execution::BpfContext::from_slice(slice);

            // 3. Invoke only the BPF programs routed to this (chip, pin, edge).
            //
            // Clone programs and release the lock BEFORE execution so BPF
            // helpers (e.g. bpf_gpio_write, bpf_ringbuf_output) can re-acquire
            // the manager lock without deadlocking.
            if let Some(manager) = crate::BPF_MANAGER.get() {
                // Resolve into a stack buffer so the IRQ handler never touches
                // the spin-locked global heap on the edge path (#65, ~200k/s).
                // 8 programs/pin is far above any real wiring; excess routes are
                // dropped by gpio_programs_into (bounded per-edge work).
                // ponytail: cap is a local const; if attach ever allows >8 routes
                // per pin, enforce the same cap at register_gpio_route (fail-closed
                // load-time reject) so a 9th route can't silently never fire.
                let fired = kernel_bpf::attach::GpioEdge::from_flags(edge);
                let mut buf: [crate::bpf::GpioProgramSlot; 8] =
                    core::array::from_fn(|_| None);
                let n = manager.lock().gpio_programs_into(0, pin, fired, &mut buf);
                // Manager lock dropped above; helpers may re-acquire it.
                for (prog_id, program) in buf[..n].iter().flatten() {
                    {
                        // No per-edge success log: at 200k edges/s the logger
                        // lock alone would drop edges. Errors are rare; kept.
                        if let Err(e) = crate::bpf::BpfManager::execute_program(program, &ctx) {
                            log::error!("GPIO BPF Hook [id={}] failed: {:?}", prog_id, e);
                        }
                    }
                }
            }
        }
    }

    // Bench (Task 11): bound the IRQ-entry stamp strictly to this interrupt. If no
    // actuation consumed it (e.g. an edge on a pin with no attached program), drop
    // it so it can never produce a bogus M-C line on a later, unrelated actuation.
    #[cfg(feature = "bench")]
    crate::bench::take_gpio_irq_entry();
}
