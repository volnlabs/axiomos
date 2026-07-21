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

use super::memory_map::{RP1_GPIO_BASE, RP1_PADS_BANK0_BASE};
use super::mmio::MmioReg;

/// GPIO function select values
///
/// Each GPIO pin can be configured to one of several functions.
/// The available alternate functions depend on the specific pin.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpioFunction {
    /// Alternate function 0 (varies by pin)
    Alt0 = 0,
    /// Alternate function 1
    Alt1 = 1,
    /// Alternate function 2
    Alt2 = 2,
    /// Alternate function 3
    Alt3 = 3,
    /// Alternate function 4
    Alt4 = 4,
    /// General-purpose I/O. RP1 uses output-enable state, not a different
    /// function number, to distinguish input from output.
    Gpio = 5,
    /// Alternate function 6
    Alt6 = 6,
    /// Alternate function 7
    Alt7 = 7,
    /// Alternate function 8
    Alt8 = 8,
    /// No function selected.
    Null = 31,
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
    /// Interrupt enable for the PCIe-facing IO_BANK0 output.
    pub const PCIE_INTE: usize = 0x11C;
    /// Interrupt status after masking for the PCIe-facing IO_BANK0 output.
    pub const PCIE_INTS: usize = 0x124;
}

/// Register stride per GPIO pin (8 bytes per pin)
const GPIO_REG_STRIDE: usize = 0x08;
/// PADS_BANK0 GPIO0 starts after the voltage-select register.
const PADS_GPIO0_OFFSET: usize = 0x04;
const PADS_GPIO_STRIDE: usize = 0x04;
/// RP1 APB atomic register aliases for set and clear operations.
const ATOMIC_SET_OFFSET: usize = 0x2000;
const ATOMIC_CLEAR_OFFSET: usize = 0x3000;

/// Control register bit fields
mod ctrl {
    /// Function select mask (bits 4:0)
    pub const FUNCSEL_MASK: u32 = 0x1F;
    /// Output override (bits 13:12)
    pub const OUTOVER_SHIFT: u32 = 12;
    pub const OUTOVER_MASK: u32 = 0b11 << OUTOVER_SHIFT;
    /// Output enable override (bits 15:14)
    pub const OEOVER_SHIFT: u32 = 14;
    pub const OEOVER_MASK: u32 = 0b11 << OEOVER_SHIFT;
    /// Force output low/high.
    pub const OUTOVER_LOW: u32 = 0b10;
    pub const OUTOVER_HIGH: u32 = 0b11;
    /// Force output disabled/enabled.
    pub const OEOVER_DISABLE: u32 = 0b10;
    pub const OEOVER_ENABLE: u32 = 0b11;
}

/// Pad-control register bit fields.
mod pads {
    /// Schmitt-trigger (hysteresis) enable (bit 1).
    pub const SCHMITT: u32 = 1 << 1;
    /// Pull-down and pull-up select (bits 3:2).
    pub const PULL_SHIFT: u32 = 2;
    pub const PULL_MASK: u32 = 0b11 << PULL_SHIFT;
    /// Input buffer enable (bit 6).
    pub const IN_ENABLE: u32 = 1 << 6;
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
        ctrl.modify(|v| (v & !ctrl::OUTOVER_MASK) | (ctrl::OUTOVER_HIGH << ctrl::OUTOVER_SHIFT));
    }

    /// Set a GPIO pin low (output mode)
    ///
    /// The pin must be configured as an output first.
    pub fn set_low(&self, pin: u8) {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);

        let ctrl = self.reg_ctrl(pin);
        ctrl.modify(|v| (v & !ctrl::OUTOVER_MASK) | (ctrl::OUTOVER_LOW << ctrl::OUTOVER_SHIFT));
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
        self.set_function(pin, GpioFunction::Gpio);
        if initial_high {
            self.set_high(pin);
        } else {
            self.set_low(pin);
        }
        self.reg_ctrl(pin)
            .modify(|v| (v & !ctrl::OEOVER_MASK) | (ctrl::OEOVER_ENABLE << ctrl::OEOVER_SHIFT));
    }

    /// Configure a GPIO pin as input
    pub fn configure_input(&self, pin: u8) {
        self.set_function(pin, GpioFunction::Gpio);
        self.reg_ctrl(pin)
            .modify(|v| (v & !ctrl::OEOVER_MASK) | (ctrl::OEOVER_DISABLE << ctrl::OEOVER_SHIFT));
        // Enable the pad input buffer. RP1 leaves IE clear on pins the firmware
        // never claims, and a pad with its input buffer disabled reads a
        // constant low and raises no edge event however the external signal
        // moves. Schmitt hysteresis stops one slow external edge from being
        // detected as several.
        self.reg_pad(pin)
            .modify(|v| v | pads::IN_ENABLE | pads::SCHMITT);
    }

    /// Raw PADS_BANK0 control word for a pin. Bring-up diagnostics only.
    pub fn pad_state(&self, pin: u8) -> u32 {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);
        self.reg_pad(pin).read()
    }

    /// Raw IO_BANK0 status word for a pin. Bring-up diagnostics only.
    pub fn status_state(&self, pin: u8) -> u32 {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);
        self.reg_status(pin).read()
    }

    /// Configure the pad's internal pull resistor.
    pub fn set_pull(&self, pin: u8, pull: GpioPull) {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);
        let pad = self.reg_pad(pin);
        pad.modify(|v| (v & !pads::PULL_MASK) | ((pull as u32) << pads::PULL_SHIFT));
    }

    /// Configure GPIO pins 14 and 15 for UART
    ///
    /// This sets them to Alt4 function (UART0 TXD/RXD on RP1 GPIO14/15).
    /// Note: With `enable_rp1_uart=1`, firmware already does this.
    pub fn setup_uart(&self) {
        self.set_function(14, GpioFunction::Alt4); // TXD0
        self.set_function(15, GpioFunction::Alt4); // RXD0
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

    fn reg_pad(&self, pin: u8) -> MmioReg<u32> {
        let offset = PADS_GPIO0_OFFSET + (pin as usize) * PADS_GPIO_STRIDE;
        // SAFETY: PADS_BANK0 contains one 32-bit pad-control register for every
        // user GPIO after its voltage-select register.
        unsafe { MmioReg::new(RP1_PADS_BANK0_BASE + offset) }
    }

    fn reg_ctrl_atomic_set(&self, pin: u8) -> MmioReg<u32> {
        let offset = (pin as usize) * GPIO_REG_STRIDE + reg::CTRL;
        // SAFETY: RP1 exposes an atomic set alias for every IO_BANK0 register.
        unsafe { MmioReg::new(self.base + ATOMIC_SET_OFFSET + offset) }
    }

    fn reg_pcie_inte_atomic_set(&self) -> MmioReg<u32> {
        // SAFETY: PCIE_INTE is inside IO_BANK0 and supports the atomic aliases.
        unsafe { MmioReg::new(self.base + ATOMIC_SET_OFFSET + reg::PCIE_INTE) }
    }

    fn reg_pcie_inte_atomic_clear(&self) -> MmioReg<u32> {
        // SAFETY: PCIE_INTE is inside IO_BANK0 and supports the atomic aliases.
        unsafe { MmioReg::new(self.base + ATOMIC_CLEAR_OFFSET + reg::PCIE_INTE) }
    }

    /// Complete and validate the RP1 IO_BANK0 MSI-X route.
    pub fn init_pcie_interrupt_route(
        &self,
    ) -> Result<super::rp1_irq::Rp1InterruptRoute, super::rp1_irq::Rp1InterruptRouteError> {
        super::rp1_irq::initialize_gpio_route()
    }

    /// Acknowledge RP1 MSI-X vector 0 after all observed GPIO sources have
    /// been cleared. If a level remains asserted, RP1 emits a fresh MSI.
    pub fn acknowledge_pcie_interrupt(&self) {
        super::rp1_irq::acknowledge_gpio_vector();
    }

    /// Return the PCIe-facing pending-pin bitmap for IO_BANK0.
    pub fn pending_pcie_interrupts(&self) -> u32 {
        // SAFETY: PCIE_INTS is a read-only IO_BANK0 register.
        let ints = unsafe { MmioReg::<u32>::new(self.base + reg::PCIE_INTS) };
        ints.read() & ((1u32 << Self::NUM_PINS) - 1)
    }

    /// Enable interrupt for a specific pin
    ///
    /// Configures the GPIO control register to generate interrupts on
    /// the specified edge transitions.
    pub fn enable_interrupt(&self, pin: u8, rising: bool, falling: bool) {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);
        self.reg_pcie_inte_atomic_clear().write(1u32 << pin);
        let ctrl = self.reg_ctrl(pin);
        let all_events = irq_ctrl::IRQEN_RISING
            | irq_ctrl::IRQEN_FALLING
            | irq_ctrl::IRQEN_LOW
            | irq_ctrl::IRQEN_HIGH;
        let mut mask = 0;
        if rising {
            mask |= irq_ctrl::IRQEN_RISING;
        }
        if falling {
            mask |= irq_ctrl::IRQEN_FALLING;
        }
        ctrl.modify(|v| (v & !all_events) | mask);
        self.clear_interrupt(pin);
        self.reg_pcie_inte_atomic_set().write(1u32 << pin);
    }

    /// Disable interrupt for a specific pin
    pub fn disable_interrupt(&self, pin: u8) {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);
        self.reg_pcie_inte_atomic_clear().write(1u32 << pin);
        let ctrl = self.reg_ctrl(pin);
        let mask = irq_ctrl::IRQEN_RISING
            | irq_ctrl::IRQEN_FALLING
            | irq_ctrl::IRQEN_LOW
            | irq_ctrl::IRQEN_HIGH;
        ctrl.modify(|v| v & !mask);
        self.clear_interrupt(pin);
    }

    /// Clear interrupt for a specific pin
    ///
    /// Writes to the IRQRESET bit in the control register to acknowledge
    /// and clear the pending interrupt.
    pub fn clear_interrupt(&self, pin: u8) {
        assert!(pin < Self::NUM_PINS, "Invalid GPIO pin: {}", pin);
        self.reg_ctrl_atomic_set(pin).write(irq_ctrl::IRQRESET);
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
    let pending_before = gpio.pending_pcie_interrupts();

    // Get timestamp at interrupt entry for accurate timing
    let timestamp = counter_to_ns(read_timer_counter());
    // Bench (Task 11): stamp the cycle counter at IRQ entry so the actuation
    // seam can report edge->actuate latency (M-C).
    #[cfg(feature = "bench")]
    crate::bench::mark_gpio_irq_entry();

    let mut handled_events = 0u32;

    // Scan only pins asserted in IO_BANK0's PCIe interrupt status.
    for pin in 0..Rp1Gpio::NUM_PINS {
        if pending_before & (1u32 << pin) == 0 {
            continue;
        }
        let events = gpio.get_pending_events(pin);

        // Check if any event is pending on this pin
        if events != 0 {
            handled_events += 1;
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
                // Resolve press vs release. The fail-safe external circuit holds
                // the pin high through a closed NC contact and pulls it low when
                // the contact opens, its cable breaks, or it is disconnected.
                // Edge 3 (both edges / bounce) is ambiguous, so fall back to the
                // current pin level — a real stop must never be dropped merely
                // because a release edge was coalesced.
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

            // 3. Execute the immutable route snapshot. Readers take no manager,
            // allocator, logger, or refcount path in this IRQ context.
            let fired = kernel_bpf::attach::GpioEdge::from_flags(edge);
            let _ = crate::bpf::BpfManager::run_gpio_programs(0, pin, fired, &ctx);
        }
    }

    let pending_after = gpio.pending_pcie_interrupts();
    gpio.acknowledge_pcie_interrupt();

    #[cfg(feature = "bench")]
    crate::bench::report_gpio_irq_probe(pending_before, pending_after, handled_events);

    // Bench (Task 11): bound the IRQ-entry stamp strictly to this interrupt. If no
    // actuation consumed it (e.g. an edge on a pin with no attached program), drop
    // it so it can never produce a bogus M-C line on a later, unrelated actuation.
    #[cfg(feature = "bench")]
    crate::bench::take_gpio_irq_entry();
}
