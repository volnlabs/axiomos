use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use kernel_device::block::{BlockBuf, BlockDevice};
use kernel_device::raw::{RawDevice, RawDeviceRegistry};
use kernel_device::{Device, DeviceId, RegisterDeviceError};
use kernel_physical_memory::{PhysAddr, PhysFrame, PhysFrameRangeInclusive, Size4KiB};
use spin::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TestId(u8);

impl DeviceId for TestId {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutOfRange;

impl Display for OutOfRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("block is out of range")
    }
}

impl Error for OutOfRange {}

struct MemoryBlockDevice<const N: usize> {
    id: TestId,
    data: Vec<u8>,
    flushes: Arc<AtomicUsize>,
}

impl<const N: usize> MemoryBlockDevice<N> {
    fn new(id: TestId, blocks: usize, flushes: Arc<AtomicUsize>) -> Self {
        Self {
            id,
            data: (0..blocks * N).map(|index| index as u8).collect(),
            flushes,
        }
    }
}

impl<const N: usize> Device<TestId> for MemoryBlockDevice<N> {
    fn id(&self) -> TestId {
        self.id
    }
}

impl<const N: usize> BlockDevice<TestId, N> for MemoryBlockDevice<N> {
    fn block_count(&self) -> usize {
        self.data.len() / N
    }

    fn read_block(
        &mut self,
        block_num: usize,
        buf: &mut BlockBuf<N>,
    ) -> Result<(), Box<dyn Error>> {
        let start = block_num
            .checked_mul(N)
            .ok_or_else(|| Box::new(OutOfRange) as Box<dyn Error>)?;
        let end = start
            .checked_add(N)
            .ok_or_else(|| Box::new(OutOfRange) as Box<dyn Error>)?;
        let source = self
            .data
            .get(start..end)
            .ok_or_else(|| Box::new(OutOfRange) as Box<dyn Error>)?;
        buf.copy_from_slice(source);
        Ok(())
    }

    fn write_block(&mut self, block_num: usize, buf: &BlockBuf<N>) -> Result<(), Box<dyn Error>> {
        let start = block_num
            .checked_mul(N)
            .ok_or_else(|| Box::new(OutOfRange) as Box<dyn Error>)?;
        let end = start
            .checked_add(N)
            .ok_or_else(|| Box::new(OutOfRange) as Box<dyn Error>)?;
        let destination = self
            .data
            .get_mut(start..end)
            .ok_or_else(|| Box::new(OutOfRange) as Box<dyn Error>)?;
        destination.copy_from_slice(&buf[..]);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct RawFixture {
    id: TestId,
    start: u64,
    end: u64,
}

impl Device<TestId> for RawFixture {
    fn id(&self) -> TestId {
        self.id
    }
}

impl RawDevice<TestId> for RawFixture {
    fn physical_memory(&self) -> PhysFrameRangeInclusive {
        PhysFrameRangeInclusive {
            start: PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(self.start)),
            end: PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(self.end)),
        }
    }
}

#[test]
fn block_buffer_starts_zeroed_and_dereferences_mutably() {
    let mut buf = BlockBuf::<8>::default();
    assert_eq!(&*buf, &[0; 8]);

    buf[2..6].copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(&*buf, &[0, 0, 1, 2, 3, 4, 0, 0]);
}

#[test]
fn boxed_block_device_forwards_complete_contract_and_errors() {
    let flushes = Arc::new(AtomicUsize::new(0));
    let mut device: Box<dyn BlockDevice<TestId, 8>> =
        Box::new(MemoryBlockDevice::new(TestId(7), 2, Arc::clone(&flushes)));

    assert_eq!(device.id(), TestId(7));
    assert_eq!(device.block_count(), 2);

    let mut read = BlockBuf::new();
    device.read_block(1, &mut read).unwrap();
    assert_eq!(&*read, &[8, 9, 10, 11, 12, 13, 14, 15]);

    let mut write = BlockBuf::new();
    write.copy_from_slice(&[42; 8]);
    device.write_block(0, &write).unwrap();
    device.read_block(0, &mut read).unwrap();
    assert_eq!(&*read, &[42; 8]);

    assert_eq!(
        device.read_block(2, &mut read).unwrap_err().to_string(),
        "block is out of range"
    );
    device.flush().unwrap();
    assert_eq!(flushes.load(Ordering::Relaxed), 1);
}

#[test]
fn locked_block_device_forwards_flush_instead_of_panicking() {
    let flushes = Arc::new(AtomicUsize::new(0));
    let mut device = Arc::new(RwLock::new(MemoryBlockDevice::<512>::new(
        TestId(9),
        2,
        Arc::clone(&flushes),
    )));

    assert_eq!(device.id(), TestId(9));
    assert_eq!(device.block_count(), 2);

    let mut write = BlockBuf::new();
    write.fill(0xa5);
    device.write_block(1, &write).unwrap();

    let mut read = BlockBuf::new();
    device.read_block(1, &mut read).unwrap();
    assert!(read.iter().all(|byte| *byte == 0xa5));

    device.flush().unwrap();
    assert_eq!(flushes.load(Ordering::Relaxed), 1);
}

#[test]
fn raw_registry_rejects_duplicate_ids_and_preserves_sorted_devices() {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RawDeviceRegistry<TestId>>();

    let mut registry = RawDeviceRegistry::default();
    for (id, start) in [(TestId(2), 0x4000), (TestId(1), 0x1000)] {
        registry
            .register_device(Arc::new(RwLock::new(RawFixture {
                id,
                start,
                end: start + 0x1000,
            })))
            .unwrap();
    }

    let duplicate = registry.register_device(Arc::new(RwLock::new(RawFixture {
        id: TestId(1),
        start: 0x8000,
        end: 0x9000,
    })));
    assert_eq!(duplicate, Err(RegisterDeviceError::AlreadyRegistered));
    assert_eq!(
        RegisterDeviceError::AlreadyRegistered.to_string(),
        "device id is already registered"
    );

    let devices: Vec<_> = registry
        .all_devices()
        .map(|device| {
            let device = device.read();
            (device.id(), device.physical_memory().start.start_address())
        })
        .collect();
    assert_eq!(
        devices,
        vec![
            (TestId(1), PhysAddr::new(0x1000)),
            (TestId(2), PhysAddr::new(0x4000))
        ]
    );
}

#[test]
fn boxed_device_forwards_identity() {
    struct Identity(TestId);

    impl Device<TestId> for Identity {
        fn id(&self) -> TestId {
            self.0
        }
    }

    let device: Box<dyn Device<TestId>> = Box::new(Identity(TestId(3)));
    assert_eq!(device.id(), TestId(3));
}
