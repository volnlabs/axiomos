use crate::time::get_kernel_time_ns;

const GPIO_PIN_COUNT: u32 = 28;

fn valid_gpio_pin(pin: u32) -> bool {
    pin < GPIO_PIN_COUNT
}

fn valid_pwm_id(pwm_id: u32) -> bool {
    pwm_id <= 1
}

fn valid_pwm_channel(channel: u32) -> bool {
    (1..=2).contains(&channel)
}

/// BPF helper: Get current time in nanoseconds
///
/// # Safety
///
/// This function is an entry point for BPF programs. It is safe to call from
/// any context as it only reads the kernel time.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_ktime_get_ns() -> u64 {
    get_kernel_time_ns()
}

/// BPF helper: Get interrupt latency in nanoseconds.
///
/// This returns the time elapsed from the hardware interrupt entry to the
/// current BPF execution point.
///
/// # Safety
///
/// This function expects the BPF context to be passed in R1 by the executor.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn bpf_get_interrupt_latency_ns(
    ctx: *const kernel_bpf::execution::BpfContext<'_>,
) -> u64 {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: The executor guarantees that R1 points to a valid BpfContext.
    unsafe { (*ctx).interrupt_latency_ns() }
}

/// BPF helper: Get boot time in milliseconds.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn bpf_get_boot_time_ms(ctx: *const kernel_bpf::execution::BpfContext<'_>) -> u64 {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: The executor guarantees that R1 points to a live BpfContext.
    unsafe { (*ctx).boot_time_ms() }
}

/// BPF helper: Get kernel heap usage in KB.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn bpf_get_kernel_heap_kb(ctx: *const kernel_bpf::execution::BpfContext<'_>) -> u64 {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: The executor guarantees that R1 points to a live BpfContext.
    unsafe { (*ctx).kernel_heap_kb() }
}

/// BPF helper: Get kernel image size in MB.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn bpf_get_kernel_image_mb(
    ctx: *const kernel_bpf::execution::BpfContext<'_>,
) -> u64 {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: The executor guarantees that R1 points to a live BpfContext.
    unsafe { (*ctx).kernel_image_mb() }
}

/// BPF helper: Read GPIO pin value
///
/// Returns 1 if pin is high, 0 if low, -1 on error (invalid pin).
///
/// # Safety
///
/// This function is an entry point for BPF programs. It accesses hardware registers
/// but validates inputs (pin numbers) to prevent invalid access.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_gpio_read(pin: u32) -> i64 {
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    {
        if !valid_gpio_pin(pin) {
            return -1;
        }
        // SAFETY: Creating a temporary GPIO interface to access hardware registers.
        // Safe because we are on RPi5 (checked by feature) and access is stateless/exclusive.
        let gpio = unsafe { crate::arch::aarch64::platform::rpi5::gpio::Rp1Gpio::new() };
        if gpio.read(pin as u8) {
            1
        } else {
            0
        }
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    {
        let _ = pin;
        -1
    }
}

/// BPF helper: Write GPIO pin value
///
/// Sets output pin high (value != 0) or low (value == 0).
/// Returns 0 on success, -1 on error (invalid pin).
///
/// Note: Pin must be configured as output first via syscall.
///
/// # Safety
///
/// This function is an entry point for BPF programs. It accesses hardware registers
/// but validates inputs (pin numbers) to prevent invalid access.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_gpio_write(pin: u32, value: u32) -> i64 {
    if !valid_gpio_pin(pin) {
        return -1;
    }

    crate::actuation::guard_gpio(pin as u8, value)
}

/// BPF helper: Toggle GPIO pin
///
/// Toggles output pin state (high -> low or low -> high).
/// Returns new value (0 or 1) on success, -1 on error.
///
/// # Safety
///
/// This function is an entry point for BPF programs. It accesses hardware registers
/// but validates inputs (pin numbers) to prevent invalid access.
///
/// NOTE: not exposed to the BPF helper ABI (no `HelperId`, not in the relocation
/// table or interpreter/JIT dispatch). It therefore bypasses the ARM-A actuation
/// monitor. If ever exposed to BPF, route its output through
/// `crate::actuation::guard_gpio` first so it cannot escape the safety envelope.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_gpio_toggle(pin: u32) -> i64 {
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    {
        if !valid_gpio_pin(pin) {
            return -1;
        }
        // SAFETY: Creating a temporary GPIO interface to access hardware registers.
        // Safe because we are on RPi5 (checked by feature) and access is stateless/exclusive.
        let gpio = unsafe { crate::arch::aarch64::platform::rpi5::gpio::Rp1Gpio::new() };
        gpio.toggle(pin as u8);
        // Return new value
        if gpio.read(pin as u8) {
            1
        } else {
            0
        }
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    {
        let _ = pin;
        -1
    }
}

/// BPF helper: Configure GPIO pin as output
///
/// Configures pin as output with specified initial value.
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// This function is an entry point for BPF programs. It accesses hardware registers
/// but validates inputs (pin numbers) to prevent invalid access.
///
/// NOTE: not exposed to the BPF helper ABI (no `HelperId`, not in the relocation
/// table or interpreter/JIT dispatch). It therefore bypasses the ARM-A actuation
/// monitor. If ever exposed to BPF, route its level write through
/// `crate::actuation::guard_gpio` first so it cannot escape the safety envelope.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_gpio_set_output(pin: u32, initial_high: u32) -> i64 {
    #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
    {
        if !valid_gpio_pin(pin) {
            return -1;
        }
        // SAFETY: Creating a temporary GPIO interface to access hardware registers.
        // Safe because we are on RPi5 (checked by feature) and access is stateless/exclusive.
        let gpio = unsafe { crate::arch::aarch64::platform::rpi5::gpio::Rp1Gpio::new() };
        gpio.configure_output(pin as u8, initial_high != 0);
        0
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "rpi5")))]
    {
        let _ = (pin, initial_high);
        -1
    }
}

/// BPF helper: Write to PWM channel
///
/// Arguments:
/// - pwm_id: 0 or 1
/// - channel: 1 or 2
/// - duty_percent: 0-100
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// This function is an entry point for BPF programs. It accesses hardware registers
/// but validates inputs (pwm_id, channel) to prevent invalid access.
/// BPF helper: Emergency motor stop
#[no_mangle]
pub extern "C" fn bpf_pwm_write(pwm_id: u32, channel: u32, duty_percent: u32) -> i64 {
    if !valid_pwm_id(pwm_id) || !valid_pwm_channel(channel) {
        return -1;
    }

    crate::actuation::guard_pwm(pwm_id as u8, channel as u8, duty_percent)
}

/// # Safety
///
/// This function is an entry point for BPF programs. The verifier ensures that the
/// string pointer is valid and points to a null-terminated string in read-only memory.
#[unsafe(no_mangle)]
pub extern "C" fn bpf_trace_printk(fmt: *const u8, _size: u32) -> i32 {
    // SAFETY: The verifier guarantees that the string is in valid memory.
    unsafe {
        let s = core::ffi::CStr::from_ptr(fmt as *const core::ffi::c_char);
        if let Ok(msg) = s.to_str() {
            log::info!("[BPF] {}", msg);
            return 0;
        }
    }
    -1
}

/// BPF helper: look up a map element by key.
///
/// # Safety
/// Called from verified BPF programs. The verifier ensures key_ptr is valid.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn bpf_map_lookup_elem(map_id: u32, key_ptr: *const u8) -> *mut u8 {
    use crate::BPF_MANAGER;
    if let Some(manager) = BPF_MANAGER.get() {
        let manager = manager.lock();
        if let Some(def) = manager.get_map_def(map_id) {
            let key_size = def.key_size as usize;
            // SAFETY: Verifier ensures valid memory access for key_ptr
            let key = unsafe { core::slice::from_raw_parts(key_ptr, key_size) };
            // SAFETY: Manager lock ensures map stability
            if let Some(ptr) = unsafe { manager.map_lookup_ptr(map_id, key) } {
                return ptr;
            }
        }
    }
    core::ptr::null_mut()
}

/// BPF helper: update a map element.
///
/// # Safety
/// Called from verified BPF programs. The verifier ensures pointers are valid.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn bpf_map_update_elem(
    map_id: u32,
    key_ptr: *const u8,
    value_ptr: *const u8,
    flags: u64,
) -> i32 {
    use crate::BPF_MANAGER;
    if let Some(manager) = BPF_MANAGER.get() {
        let manager = manager.lock();
        if let Some(def) = manager.get_map_def(map_id) {
            let key_size = def.key_size as usize;
            let value_size = def.value_size as usize;

            // SAFETY: Verifier ensures valid memory access for key_ptr
            let key = unsafe { core::slice::from_raw_parts(key_ptr, key_size) };
            // SAFETY: Verifier ensures valid memory access for value_ptr
            let value = unsafe { core::slice::from_raw_parts(value_ptr, value_size) };

            if manager.map_update(map_id, key, value, flags).is_ok() {
                return 0;
            }
        }
    }
    -1
}

/// BPF helper: delete a map element.
///
/// # Safety
/// Called from verified BPF programs. The verifier ensures key_ptr is valid.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn bpf_map_delete_elem(map_id: u32, key_ptr: *const u8) -> i32 {
    use crate::BPF_MANAGER;
    if let Some(manager) = BPF_MANAGER.get() {
        let manager = manager.lock();
        if let Some(def) = manager.get_map_def(map_id) {
            let key_size = def.key_size as usize;
            // SAFETY: Verifier ensures valid memory access for key_ptr
            let key = unsafe { core::slice::from_raw_parts(key_ptr, key_size) };
            if manager.map_delete(map_id, key).is_ok() {
                return 0;
            }
        }
    }
    -1
}

/// BPF helper: output data to a ring buffer map.
///
/// Writes event data to a ring buffer map for consumption by userspace.
///
/// # Arguments
/// * `map_id` - The ring buffer map ID
/// * `data_ptr` - Pointer to the event data
/// * `data_size` - Size of the event data in bytes
/// * `flags` - Reserved for future use (pass 0)
///
/// # Returns
/// 0 on success, negative error code on failure.
///
/// # Safety
/// Called from verified BPF programs. The verifier ensures data_ptr is valid.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn bpf_ringbuf_output(
    map_id: u32,
    data_ptr: *const u8,
    data_size: u64,
    flags: u64,
) -> i64 {
    use crate::BPF_MANAGER;

    if data_ptr.is_null() {
        return -1;
    }

    if let Some(manager) = BPF_MANAGER.get() {
        let manager = manager.lock();
        // SAFETY: Verifier ensures valid memory access for data_ptr
        let data = unsafe { core::slice::from_raw_parts(data_ptr, data_size as usize) };

        if manager.ringbuf_output(map_id, data, flags).is_ok() {
            return 0;
        }
    }
    -1
}

/// BPF helper: Push data to a time-series map.
///
/// # Arguments
/// * `map_id` - The time-series map ID
/// * `key_ptr` - Pointer to the timestamp (u64)
/// * `value_ptr` - Pointer to the value
///
/// # Returns
/// 0 on success, negative error code on failure.
///
/// # Safety
/// Called from verified BPF programs. The verifier ensures pointers are valid.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn bpf_timeseries_push(
    map_id: u32,
    key_ptr: *const u8,
    value_ptr: *const u8,
) -> i64 {
    use crate::BPF_MANAGER;

    if key_ptr.is_null() || value_ptr.is_null() {
        return -1;
    }

    if let Some(manager) = BPF_MANAGER.get() {
        let manager = manager.lock();
        if let Some(def) = manager.get_map_def(map_id) {
            let key_size = def.key_size as usize;
            let value_size = def.value_size as usize;

            // SAFETY: Verifier ensures valid memory access for key_ptr
            let key = unsafe { core::slice::from_raw_parts(key_ptr, key_size) };
            // SAFETY: Verifier ensures valid memory access for value_ptr
            let value = unsafe { core::slice::from_raw_parts(value_ptr, value_size) };

            // TimeSeriesMap uses update() to handle push (key treated as timestamp)
            if manager.map_update(map_id, key, value, 0).is_ok() {
                return 0;
            }
        }
    }
    -1
}
