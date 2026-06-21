use alloc::boxed::Box;
use alloc::sync::Arc;
use core::error::Error;
use core::fmt::{Debug, Formatter};
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering::Relaxed;

use kernel_device::block::{BlockBuf, BlockDevice};
use kernel_device::Device;
#[cfg(target_arch = "x86_64")]
use kernel_pci::config::ConfigurationAccess;
#[cfg(target_arch = "x86_64")]
use kernel_pci::PciAddress;
#[cfg(target_arch = "x86_64")]
use linkme::distributed_slice;
use spin::rwlock::RwLock;
use spin::Mutex;
use virtio_drivers::device::blk::VirtIOBlk;
#[cfg(target_arch = "aarch64")]
use virtio_drivers::transport::mmio::MmioTransport;
#[cfg(target_arch = "x86_64")]
use virtio_drivers::transport::pci::PciTransport;

use crate::driver::block::BlockDevices;
#[cfg(target_arch = "x86_64")]
use crate::driver::pci::{PciDriverDescriptor, PciDriverType, PCI_DRIVERS};
#[cfg(target_arch = "x86_64")]
use crate::driver::virtio::hal::transport;
use crate::driver::virtio::hal::HalImpl;
use crate::driver::KernelDeviceId;
use crate::U64Ext;

#[allow(dead_code)]
static VIRTIO_READ_SECTOR_PROBE_SEQ: AtomicU64 = AtomicU64::new(0);

#[allow(dead_code)]
fn should_log_virtio_read_probe(seq: u64) -> bool {
    seq < 8 || seq.is_multiple_of(256)
}

#[cfg(target_arch = "x86_64")]
#[distributed_slice(PCI_DRIVERS)]
static VIRTIO_BLK: PciDriverDescriptor = PciDriverDescriptor {
    name: "virtio-blk",
    typ: PciDriverType::Specific,
    probe: virtio_probe,
    init: virtio_init,
};

#[cfg(target_arch = "x86_64")]
fn virtio_probe(addr: PciAddress, cam: &dyn ConfigurationAccess) -> bool {
    addr.vendor_id(cam) == 0x1af4
        && (0x1000..=0x103f).contains(&addr.device_id(cam))
        && addr.subsystem_id(cam) == 0x02
}

#[cfg(target_arch = "x86_64")]
#[allow(clippy::needless_pass_by_value)] // signature is required like this
fn virtio_init(addr: PciAddress, cam: Box<dyn ConfigurationAccess>) -> Result<(), Box<dyn Error>> {
    let transport = transport(addr, cam);

    let blk = VirtIOBlk::<HalImpl, _>::new(transport)?;

    let id = KernelDeviceId::new();
    let device = VirtioBlockDevice {
        id,
        inner: Arc::new(Mutex::new(VirtioBlkInner::Pci(blk))),
    };
    let device = Arc::new(RwLock::new(device));
    BlockDevices::register_block_device(device.clone())?;

    Ok(())
}

#[cfg(target_arch = "aarch64")]
#[allow(unused)]
pub fn init_mmio(transport: MmioTransport) -> Result<(), Box<dyn Error>> {
    // SAFETY: MMIO transport is backed by kernel-mapped memory that lives for the entire kernel lifetime.
    let transport: MmioTransport<'static> = unsafe { core::mem::transmute(transport) };
    let blk = VirtIOBlk::<HalImpl, _>::new(transport)?;

    let id = KernelDeviceId::new();
    let device = VirtioBlockDevice {
        id,
        inner: Arc::new(Mutex::new(VirtioBlkInner::Mmio(blk))),
    };
    let device = Arc::new(RwLock::new(device));
    BlockDevices::register_block_device(device.clone())?;

    Ok(())
}

#[allow(unused)]
pub enum VirtioBlkInner {
    #[cfg(target_arch = "x86_64")]
    Pci(VirtIOBlk<HalImpl, PciTransport>),
    #[cfg(target_arch = "aarch64")]
    Mmio(VirtIOBlk<HalImpl, MmioTransport<'static>>),
}

#[allow(unused)]
impl VirtioBlkInner {
    fn capacity(&self) -> u64 {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::Pci(blk) => blk.capacity(),
            #[cfg(target_arch = "aarch64")]
            Self::Mmio(blk) => blk.capacity(),
        }
    }

    fn read_blocks(&mut self, block_num: usize, buf: &mut [u8]) -> virtio_drivers::Result {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::Pci(blk) => blk.read_blocks(block_num, buf),
            #[cfg(target_arch = "aarch64")]
            Self::Mmio(blk) => blk.read_blocks(block_num, buf),
        }
    }

    fn write_blocks(&mut self, block_num: usize, buf: &[u8]) -> virtio_drivers::Result {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::Pci(blk) => blk.write_blocks(block_num, buf),
            #[cfg(target_arch = "aarch64")]
            Self::Mmio(blk) => blk.write_blocks(block_num, buf),
        }
    }
}

#[derive(Clone)]
#[allow(unused)]
pub struct VirtioBlockDevice {
    id: KernelDeviceId,
    inner: Arc<Mutex<VirtioBlkInner>>,
}

impl Debug for VirtioBlockDevice {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioBlockDevice")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Device<KernelDeviceId> for VirtioBlockDevice {
    fn id(&self) -> KernelDeviceId {
        self.id
    }
}

impl BlockDevice<KernelDeviceId, 512> for VirtioBlockDevice {
    fn block_count(&self) -> usize {
        self.inner.lock().capacity().into_usize()
    }

    fn read_block(
        &mut self,
        block_num: usize,
        buf: &mut BlockBuf<512>,
    ) -> Result<(), Box<dyn Error>> {
        self.inner.lock().read_blocks(block_num, &mut buf[..])?;
        Ok(())
    }

    fn write_block(&mut self, block_num: usize, buf: &BlockBuf<512>) -> Result<(), Box<dyn Error>> {
        self.inner.lock().write_blocks(block_num, &buf[..])?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        todo!()
    }
}

impl filesystem::BlockDevice for VirtioBlockDevice {
    type Error = ();

    fn sector_size(&self) -> usize {
        512
    }

    fn sector_count(&self) -> usize {
        self.inner.lock().capacity().into_usize()
    }

    fn read_sector(&self, sector_index: usize, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let seq = VIRTIO_READ_SECTOR_PROBE_SEQ.fetch_add(1, Relaxed);
        let log_probe = should_log_virtio_read_probe(seq);
        if log_probe {
            log::info!(
                "virtio-blk read_sector enter seq={} sector={} len={}",
                seq,
                sector_index,
                buf.len()
            );
        }

        let result = self
            .inner
            .lock()
            .read_blocks(sector_index, buf)
            .map(|()| buf.len())
            .map_err(|_| ());

        if log_probe {
            match &result {
                Ok(read) => log::info!("virtio-blk read_sector exit seq={} read={}", seq, read),
                Err(()) => log::warn!("virtio-blk read_sector error seq={}", seq),
            }
        }

        result
    }

    fn write_sector(&mut self, sector_index: usize, buf: &[u8]) -> Result<usize, Self::Error> {
        self.inner
            .lock()
            .write_blocks(sector_index, buf)
            .map(|()| buf.len())
            .map_err(|_| ())
    }
}
