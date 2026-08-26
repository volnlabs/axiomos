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
use core::sync::atomic::{AtomicU64, Ordering};

use conquer_once::spin::OnceCell;
use kernel_bpf::attach::{IioChannel, IioEvent};
use kernel_bpf::execution::BpfContext;
use spin::Mutex;
use thiserror::Error;

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
use crate::mcore::mtask::task::StackAllocationError;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", not(feature = "rpi5"))
))]
use crate::mcore::mtask::task::Task;

#[derive(Debug, Error)]
pub enum IioInitError {
    #[cfg(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", not(feature = "rpi5"))
    ))]
    #[error("simulation task allocation failed: {0}")]
    SimulationTask(#[from] StackAllocationError),
}

/// Global IIO manager instance
pub static IIO_MANAGER: OnceCell<Mutex<IioManager>> = OnceCell::uninit();

const V04_CONTEXT_CPUS: usize = 4;
// A hook executes synchronously on one CPU. The dispatch masks local IRQs;
// other CPUs use separate slots, so an unrelated motor write cannot consume it.
static V04_ACTIVE_SAMPLE_IDS: [AtomicU64; V04_CONTEXT_CPUS] =
    [const { AtomicU64::new(0) }; V04_CONTEXT_CPUS];

fn v04_cpu_id() -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    {
        (crate::arch::aarch64::cpu::cpu_id() < V04_CONTEXT_CPUS)
            .then(|| crate::arch::aarch64::cpu::cpu_id())
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        Some(0)
    }
}

/// Consume the one benchmark motor marker allowed for the active IIO dispatch.
pub fn take_v04_motor_sample_id() -> Option<u64> {
    let slot = V04_ACTIVE_SAMPLE_IDS.get(v04_cpu_id()?)?;
    let sample_id = slot.load(Ordering::Acquire);
    (sample_id != 0
        && slot
            .compare_exchange(sample_id, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    .then_some(sample_id)
}

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

    pub fn dispatch_v04_event(&self, event: IioEvent, sample_id: u64) -> bool {
        #[cfg(target_arch = "aarch64")]
        let interrupts_enabled = {
            use crate::arch::aarch64::Aarch64;
            use crate::arch::traits::Architecture;
            let enabled = Aarch64::are_interrupts_enabled();
            if enabled {
                Aarch64::disable_interrupts();
            }
            enabled
        };
        let result = (|| {
            let Some(cpu) = v04_cpu_id() else {
                return false;
            };
            let Some(slot) = V04_ACTIVE_SAMPLE_IDS.get(cpu) else {
                return false;
            };
            // IRQ masking makes the per-core context a synchronous scope;
            // compare_exchange still rejects direct/re-entrant dispatch.
            if slot
                .compare_exchange(0, sample_id, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return false;
            }
            crate::serial_println!(
                "V04_HOOK_ENTRY sample_id={} ts_ns={}",
                sample_id,
                event.timestamp
            );
            self.dispatch_event(event);
            slot.store(0, Ordering::Release);
            true
        })();
        #[cfg(target_arch = "aarch64")]
        if interrupts_enabled {
            use crate::arch::aarch64::Aarch64;
            use crate::arch::traits::Architecture;
            Aarch64::enable_interrupts();
        }
        result
    }
}

#[cfg(test)]
mod v04_tests {
    use super::*;

    #[test]
    fn v04_context_rejects_reentry_and_consumes_one_motor_marker() {
        let slot = &V04_ACTIVE_SAMPLE_IDS[0];
        slot.store(0, Ordering::Release);
        assert!(slot
            .compare_exchange(0, 7, Ordering::AcqRel, Ordering::Acquire)
            .is_ok());
        assert!(slot
            .compare_exchange(0, 8, Ordering::AcqRel, Ordering::Acquire)
            .is_err());
        assert_eq!(take_v04_motor_sample_id(), Some(7));
        assert_eq!(take_v04_motor_sample_id(), None);
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
pub fn init_simulated_device() -> Result<(), IioInitError> {
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
                Task::create_new(Process::root(), iio_simulation_task, core::ptr::null_mut())?;
            RunQueues::enqueue(Box::pin(task));

            ::log::info!("Started IIO simulation background task");
        }
    }

    Ok(())
}
