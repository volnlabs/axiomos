use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering::Relaxed;

use kernel_devfs::{BlockDeviceFile, RegisterError as DevFsRegisterError};
use kernel_device::block::BlockDevice;
use kernel_vfs::path::{AbsoluteOwnedPath, PathNotAbsoluteError};
use spin::RwLock;
use thiserror::Error;

use crate::driver::KernelDeviceId;
use crate::file::devfs::devfs;

#[allow(clippy::type_complexity)] // refactoring into types doesn't provide benefits here
static BLOCK_DEVICES: RwLock<
    BTreeMap<u64, Arc<RwLock<dyn BlockDevice<KernelDeviceId, 512> + Send + Sync>>>,
> = RwLock::new(BTreeMap::new());
static BLOCK_DEVICE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct BlockDevices;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum RegisterBlockDeviceError {
    #[error("generated block-device path is not absolute")]
    InvalidGeneratedPath(#[from] PathNotAbsoluteError),
    #[error("failed to publish block device in devfs: {0}")]
    DevFs(#[from] DevFsRegisterError),
}

impl BlockDevices {
    /// Registers a block device and publishes its `/dev/blkN` node.
    ///
    /// # Errors
    /// Returns a typed error if the generated path is invalid or devfs cannot
    /// publish the node. The global registry is not modified on either error.
    pub fn register_block_device<D>(device: Arc<RwLock<D>>) -> Result<(), RegisterBlockDeviceError>
    where
        D: BlockDevice<KernelDeviceId, 512> + Send + Sync + 'static,
    {
        let id = BLOCK_DEVICE_COUNTER.fetch_add(1, Relaxed);
        let path = AbsoluteOwnedPath::try_from(format!("/blk{id}").as_ref())?;
        let open_device = device.clone();
        let mut devices = BLOCK_DEVICES.write();
        let mut devfs = devfs().write();
        devfs.register_file(path.as_ref(), {
            move || Ok(BlockDeviceFile::new(open_device.clone()))
        })?;

        // The devfs write guard prevents the node becoming observable before
        // the registry entry is published.
        let _ = devices.insert(id, device);

        Ok(())
    }

    pub fn by_id(
        id: u64,
    ) -> Option<Arc<RwLock<dyn BlockDevice<KernelDeviceId, 512> + Send + Sync>>> {
        BLOCK_DEVICES.read().get(&id).cloned()
    }
}
