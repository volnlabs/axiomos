//! Industrial I/O (IIO) Driver
//!
//! This module provides the interface for IIO sensors (accelerometers, gyroscopes, etc.)
//! and integrates them with the BPF subsystem.
//!
//! In the future, this will interface with actual I2C/SPI drivers.
//! For now, it provides the mechanism to inject sensor events and trigger BPF hooks.

#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", not(feature = "rpi5"))
))]
use alloc::boxed::Box;
use alloc::vec::Vec;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", not(feature = "rpi5"))
))]
use core::ffi::c_void;

use conquer_once::spin::OnceCell;
use kernel_bpf::attach::{IioChannel, IioEvent};
use kernel_bpf::execution::BpfContext;
use spin::Mutex;

#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", not(feature = "rpi5"))
))]
use crate::mcore::mtask::process::Process;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", not(feature = "rpi5"))
))]
use crate::mcore::mtask::scheduler::run_queue::RunQueues;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", not(feature = "rpi5"))
))]
use crate::mcore::mtask::task::Task;

/// Global IIO manager instance
pub static IIO_MANAGER: OnceCell<Mutex<IioManager>> = OnceCell::uninit();

/// Initialize the IIO subsystem
pub fn init() {
    IIO_MANAGER.init_once(|| Mutex::new(IioManager::new()));
}

/// Manages IIO devices and event dispatch
pub struct IioManager {
    /// Simulated devices for now
    devices: Vec<IioDevice>,
}

impl Default for IioManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IioManager {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    pub fn register_device(&mut self, device: IioDevice) {
        self.devices.push(device);
    }

    /// Dispatch an IIO event to BPF hooks
    ///
    /// This is called by hardware drivers (or simulation) when new data is available.
    pub fn dispatch_event(&self, event: IioEvent) {
        let ctx = BpfContext::from_struct(&event);

        let _ = crate::bpf::BpfManager::run_hook_programs(crate::bpf::ATTACH_TYPE_IIO, &ctx, "iio");
    }
}

/// Represents a physical IIO device
#[derive(Debug, Clone)]
pub struct IioDevice {
    pub id: u32,
    pub name: alloc::string::String,
    pub channels: Vec<IioChannel>,
}

impl IioDevice {
    pub fn new(id: u32, name: &str) -> Self {
        Self {
            id,
            name: name.into(),
            channels: Vec::new(),
        }
    }

    pub fn add_channel(&mut self, channel: IioChannel) {
        self.channels.push(channel);
    }
}

/// Simulation task entry point
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", not(feature = "rpi5"))
))]
extern "C" fn iio_simulation_task(_arg: *mut c_void) {
    let mut counter = 0;
    loop {
        // Generate simulated accelerometer data
        let event = IioEvent {
            timestamp: 0, // In a real system, we'd use a timer
            device_id: 0,
            channel: 0, // AccelX
            value: counter,
            scale: 1_000_000,
            offset: 0,
            reserved: 0,
        };

        if let Some(manager_lock) = IIO_MANAGER.get() {
            let manager = manager_lock.lock();
            manager.dispatch_event(event);
        }

        counter = (counter + 1) % 1000;

        // Simple delay - wait for a few interrupts
        for _ in 0..100 {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::asm!("hlt")
            };
            #[cfg(target_arch = "aarch64")]
            unsafe {
                core::arch::asm!("wfi")
            };
        }
    }
}

/// Initialize a simulated accelerometer for testing
pub fn init_simulated_device() {
    if let Some(manager_lock) = IIO_MANAGER.get() {
        let mut manager = manager_lock.lock();

        let mut accel = IioDevice::new(0, "simulated-accel");
        accel.add_channel(IioChannel::AccelX);
        accel.add_channel(IioChannel::AccelY);
        accel.add_channel(IioChannel::AccelZ);

        manager.register_device(accel);

        ::log::info!("Initialized simulated IIO accelerometer (id=0)");

        // Spawn simulation task.
        // On Pi 5 bring-up we skip this so it doesn't preempt init/benchmark startup.
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", not(feature = "rpi5"))
        ))]
        {
            let task =
                Task::create_new(Process::root(), iio_simulation_task, core::ptr::null_mut())
                    .expect("failed to create IIO simulation task");
            RunQueues::enqueue(Box::pin(task));

            ::log::info!("Started IIO simulation background task");
        }
    }
}
