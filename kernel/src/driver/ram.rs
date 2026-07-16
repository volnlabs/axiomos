use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt::{Debug, Formatter};

use kernel_device::block::{BlockBuf, BlockDevice};
use kernel_device::Device;
use spin::Mutex;
use thiserror::Error;

#[cfg(feature = "rpi5")]
use crate::driver::block::RegisterBlockDeviceError;
use crate::driver::KernelDeviceId;

#[cfg(feature = "rpi5")]
static EMBEDDED_DISK: &[u8] = include_bytes!(env!("EMBEDDED_DISK_PATH"));

pub struct RamBlockDevice {
    id: KernelDeviceId,
    data: Arc<Mutex<Vec<u8>>>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum RamBlockDeviceError {
    #[error("block access is outside the ramdisk")]
    OutOfBounds,
}

impl RamBlockDevice {
    pub fn new(data: &[u8]) -> Self {
        Self {
            id: KernelDeviceId::new(),
            data: Arc::new(Mutex::new(data.to_vec())),
        }
    }
}

impl Debug for RamBlockDevice {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RamBlockDevice")
            .field("id", &self.id)
            .field("size", &self.data.lock().len())
            .finish()
    }
}

impl Device<KernelDeviceId> for RamBlockDevice {
    fn id(&self) -> KernelDeviceId {
        self.id
    }
}

impl BlockDevice<KernelDeviceId, 512> for RamBlockDevice {
    fn block_count(&self) -> usize {
        self.data.lock().len() / 512
    }

    fn read_block(
        &mut self,
        block_num: usize,
        buf: &mut BlockBuf<512>,
    ) -> Result<(), Box<dyn Error>> {
        let data = self.data.lock();
        let offset = block_num
            .checked_mul(512)
            .ok_or(RamBlockDeviceError::OutOfBounds)?;
        let end = offset
            .checked_add(512)
            .ok_or(RamBlockDeviceError::OutOfBounds)?;
        let source = data
            .get(offset..end)
            .ok_or(RamBlockDeviceError::OutOfBounds)?;
        buf[..].copy_from_slice(source);
        Ok(())
    }

    fn write_block(&mut self, block_num: usize, buf: &BlockBuf<512>) -> Result<(), Box<dyn Error>> {
        let mut data = self.data.lock();
        let offset = block_num
            .checked_mul(512)
            .ok_or(RamBlockDeviceError::OutOfBounds)?;
        let end = offset
            .checked_add(512)
            .ok_or(RamBlockDeviceError::OutOfBounds)?;
        let destination = data
            .get_mut(offset..end)
            .ok_or(RamBlockDeviceError::OutOfBounds)?;
        destination.copy_from_slice(&buf[..]);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

impl filesystem::BlockDevice for RamBlockDevice {
    type Error = RamBlockDeviceError;

    fn sector_size(&self) -> usize {
        512
    }

    fn sector_count(&self) -> usize {
        self.data.lock().len() / 512
    }

    fn read_sector(&self, sector_index: usize, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let data = self.data.lock();
        let offset = sector_index
            .checked_mul(512)
            .ok_or(RamBlockDeviceError::OutOfBounds)?;
        let len = buf.len().min(512);
        let end = offset
            .checked_add(len)
            .ok_or(RamBlockDeviceError::OutOfBounds)?;
        let source = data
            .get(offset..end)
            .ok_or(RamBlockDeviceError::OutOfBounds)?;
        buf[..len].copy_from_slice(source);
        Ok(len)
    }

    fn write_sector(&mut self, sector_index: usize, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut data = self.data.lock();
        let offset = sector_index
            .checked_mul(512)
            .ok_or(RamBlockDeviceError::OutOfBounds)?;
        let len = buf.len().min(512);
        let end = offset
            .checked_add(len)
            .ok_or(RamBlockDeviceError::OutOfBounds)?;
        let destination = data
            .get_mut(offset..end)
            .ok_or(RamBlockDeviceError::OutOfBounds)?;
        destination.copy_from_slice(&buf[..len]);
        Ok(len)
    }
}

#[cfg(feature = "rpi5")]
pub fn init_embedded() -> Result<(), RegisterBlockDeviceError> {
    use log::info;
    use spin::RwLock;

    use crate::driver::block::BlockDevices;

    info!(
        "Copying embedded disk image ({} bytes) to heap...",
        EMBEDDED_DISK.len()
    );
    let device = RamBlockDevice::new(EMBEDDED_DISK);
    info!("RamBlockDevice created: {:?}", device);

    let device = Arc::new(RwLock::new(device));
    BlockDevices::register_block_device(device)?;
    info!("Embedded ramdisk registered as block device");
    Ok(())
}
