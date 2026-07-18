use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use core::error::Error;

use kernel_pci::config::{ConfigKey, ConfigurationAccess, PortCam, ReadConfig, WriteConfig};
use kernel_pci::PciAddress;
use linkme::distributed_slice;
use log::{debug, error, log_enabled, trace, Level};
use virtio_drivers::transport::pci::bus::DeviceFunction;

#[distributed_slice]
pub static PCI_DRIVERS: [PciDriverDescriptor] = [..];

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PciDriverType {
    Generic,
    Specific,
}

#[allow(clippy::type_complexity)] // refactoring the `init` fn type doesn't provide benefits here
pub struct PciDriverDescriptor {
    pub name: &'static str,
    pub typ: PciDriverType,
    pub probe: fn(PciAddress, &dyn ConfigurationAccess) -> bool,
    pub init: fn(PciAddress, Box<dyn ConfigurationAccess>) -> Result<(), Box<dyn Error>>,
}

pub fn init() {
    if log_enabled!(Level::Trace) {
        PCI_DRIVERS
            .iter()
            .for_each(|driver| trace!("have pci driver: {}", driver.name));
    }

    // SAFETY: PortCam::new() creates a new Port I/O based configuration access mechanism.
    // This is safe in the kernel as we have privileges to access I/O ports.
    let cam = unsafe { PortCam::new() };

    // SAFETY: iterate_all probes the PCI bus. It is safe to do this during initialization.
    unsafe { iterate_all(&cam) }.for_each(|addr| {
        let mut driver: Option<&PciDriverDescriptor> = None;
        let mut conflict = None;
        for candidate in PCI_DRIVERS
            .iter()
            .filter(|driver| (driver.probe)(addr, &cam))
        {
            let Some(selected) = driver else {
                driver = Some(candidate);
                continue;
            };
            match (selected.typ, candidate.typ) {
                (PciDriverType::Generic, PciDriverType::Specific) => driver = Some(candidate),
                (PciDriverType::Specific, PciDriverType::Generic) => {}
                _ => {
                    conflict = Some((selected.name, candidate.name));
                    break;
                }
            }
        }
        if let Some((first, second)) = conflict {
            error!(
                "ambiguous PCI driver match for device {}: {} and {}; skipping device",
                addr, first, second
            );
            return;
        }
        if let Some(driver) = driver {
            debug!("found driver {} for device {}", driver.name, addr);
            let device_string = addr.to_string();
            if let Err(e) = (driver.init)(addr, Box::new(cam.clone())) {
                error!(
                    "failed to init driver {} for device {}: {}",
                    driver.name, device_string, e
                );
            }
        }
    });
}

/// Iterate over all PCI devices
///
/// # Safety
///
/// This function probes the PCI bus which involves reading from hardware registers.
/// The caller must ensure that it is safe to access the PCI configuration space.
unsafe fn iterate_all<C: ConfigurationAccess>(cam: &C) -> impl Iterator<Item = PciAddress> + '_ {
    (0..=u8::MAX)
        .flat_map(|bus| (0_u8..32).map(move |slot| (bus, slot)))
        .flat_map(|(bus, slot)| {
            let addr = PciAddress::new(bus, slot, 0);

            if addr.vendor_id(cam) == 0xFFFF {
                0_u8..0
            } else if addr.is_multifunction(cam) {
                0_u8..8
            } else {
                0_u8..1
            }
            .map(move |function| PciAddress::new(bus, slot, function))
        })
}

pub struct VirtIoCam(Arc<Box<dyn ConfigurationAccess>>);

impl VirtIoCam {
    pub fn new(cam: Box<dyn ConfigurationAccess>) -> Self {
        Self(Arc::new(cam))
    }
}

impl virtio_drivers::transport::pci::bus::ConfigurationAccess for VirtIoCam {
    fn read_word(&self, device_function: DeviceFunction, register_offset: u8) -> u32 {
        let Ok(key) = ConfigKey::<u32>::try_from(register_offset as usize) else {
            return u32::MAX;
        };
        self.0.read_config(
            PciAddress::new(
                device_function.bus,
                device_function.device,
                device_function.function,
            ),
            key,
        )
    }

    fn write_word(&mut self, device_function: DeviceFunction, register_offset: u8, data: u32) {
        let Ok(key) = ConfigKey::<u32>::try_from(register_offset as usize) else {
            return;
        };
        self.0.write_config(
            PciAddress::new(
                device_function.bus,
                device_function.device,
                device_function.function,
            ),
            key,
            data,
        )
    }

    // SAFETY: Cloning the VirtIoCam is safe because it wraps the inner ConfigurationAccess in an Arc,
    // so it just increments the reference count.
    unsafe fn unsafe_clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
