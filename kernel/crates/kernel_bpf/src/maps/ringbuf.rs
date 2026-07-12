//! Ring Buffer Map Implementation
//!
//! A BPF ring buffer map provides efficient, lock-free, single-producer multi-consumer
//! event streaming from kernel to userspace. This is the preferred method for
//! high-volume event streaming in rkBPF.
//!
//! # Memory Layout
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                       Ring Buffer                             │
//! ├──────────┬───────────────────────────────────────────────────┤
//! │ Control  │                  Data Ring                         │
//! │ ┌──────┐ │ ┌────┬────┬────┬────┬────┬────┬────┬────┬────┐   │
//! │ │head  │ │ │    │    │    │    │    │    │    │    │    │   │
//! │ │tail  │ │ │    │    │ ▓▓ │ ▓▓ │ ▓▓ │    │    │    │    │   │
//! │ │      │ │ │    │    │    │    │    │    │    │    │    │   │
//! │ └──────┘ │ └────┴────┴────┴────┴────┴────┴────┴────┴────┘   │
//! │ 16 bytes │              ▲           ▲                        │
//! │          │              │           │                        │
//! │          │            tail        head                       │
//! │          │         (consumer)   (producer)                   │
//! └──────────┴───────────────────────────────────────────────────┘
//! ```
//!
//! # Event Format
//!
//! Each event in the ring buffer has a header:
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │ Header (8 bytes)                            │
//! │ ┌───────────────────┬─────────────────────┐ │
//! │ │ length (4 bytes)  │ flags (4 bytes)     │ │
//! │ └───────────────────┴─────────────────────┘ │
//! ├─────────────────────────────────────────────┤
//! │ Data (length bytes, 8-byte aligned)         │
//! │ ┌─────────────────────────────────────────┐ │
//! │ │ user data...                            │ │
//! │ └─────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Profile Differences
//!
//! | Feature       | Cloud          | Embedded       |
//! |---------------|----------------|----------------|
//! | Buffer size   | Up to 256 MB   | Up to 64 KB    |
//! | Allocation    | Dynamic        | Static pool    |
//! | Resize        | Supported      | **Erased**     |
//! | Overflow      | Drop oldest    | Drop newest    |

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;

use super::{BpfMap, MapDef, MapError, MapResult, MapType};
use crate::profile::{ActiveProfile, PhysicalProfile};

/// Event header in the ring buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct EventHeader {
    /// Length of data (not including header)
    length: u32,
    /// Event flags
    flags: u32,
}

impl EventHeader {
    const SIZE: usize = 8;

    /// Flag indicating event is busy (being written)
    const FLAG_BUSY: u32 = 1 << 31;
    /// Flag indicating event is discarded
    const FLAG_DISCARD: u32 = 1 << 30;

    fn new(length: u32) -> Self {
        Self { length, flags: 0 }
    }

    fn as_bytes(self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&self.length.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.flags.to_ne_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let length = u32::from_ne_bytes(bytes[0..4].try_into().ok()?);
        let flags = u32::from_ne_bytes(bytes[4..8].try_into().ok()?);
        Some(Self { length, flags })
    }

    fn is_busy(&self) -> bool {
        self.flags & Self::FLAG_BUSY != 0
    }

    fn is_discarded(&self) -> bool {
        self.flags & Self::FLAG_DISCARD != 0
    }

    /// Total size of this event including header, 8-byte aligned
    fn total_size(&self) -> usize {
        let data_size = self.length as usize;
        let total = EventHeader::SIZE + data_size;
        // Round up to 8-byte alignment
        (total + 7) & !7
    }
}

/// Ring buffer control structure.
struct RingControl {
    /// Producer position (next write position)
    head: AtomicU64,
    /// Consumer position (next read position)
    tail: AtomicU64,
    /// Buffer capacity
    capacity: usize,
    /// Mask for wrapping (capacity - 1, requires power of 2)
    mask: usize,
}

impl RingControl {
    fn new(capacity: usize) -> Self {
        // Capacity must be power of 2
        debug_assert!(capacity.is_power_of_two());
        Self {
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            capacity,
            mask: capacity - 1,
        }
    }

    /// Get available space for writing.
    fn available_space(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        self.capacity - (head.wrapping_sub(tail) as usize)
    }

    /// Get used space (data available for reading).
    fn used_space(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail) as usize
    }

    /// Wrap position to buffer index.
    fn wrap(&self, pos: u64) -> usize {
        (pos as usize) & self.mask
    }
}

/// Ring buffer map implementation.
///
/// Provides efficient single-producer event streaming suitable for
/// kernel-to-userspace communication.
pub struct RingBufMap<P: PhysicalProfile = ActiveProfile> {
    /// Map definition
    def: MapDef,
    /// Ring control structure
    control: RingControl,
    /// Data buffer
    data: Mutex<Vec<u8>>,
    /// Number of events dropped due to buffer full
    dropped_events: AtomicU64,
    /// Profile marker
    _profile: PhantomData<fn() -> P>,
}

impl<P: PhysicalProfile> RingBufMap<P> {
    /// Maximum buffer size for embedded profile.
    #[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
    const MAX_BUFFER_SIZE: usize = 64 * 1024; // 64 KB

    /// Maximum buffer size for cloud profile.
    #[cfg(feature = "cloud-profile")]
    const MAX_BUFFER_SIZE: usize = 256 * 1024 * 1024; // 256 MB

    /// Create a new ring buffer map.
    ///
    /// # Arguments
    ///
    /// * `size` - Buffer size in bytes (must be power of 2)
    ///
    /// # Errors
    ///
    /// Returns an error if size is not a power of 2 or exceeds limits.
    pub fn new(size: usize) -> MapResult<Self> {
        if !size.is_power_of_two() {
            return Err(MapError::InvalidValue);
        }

        if size == 0 {
            return Err(MapError::InvalidValue);
        }

        if size > Self::MAX_BUFFER_SIZE {
            return Err(MapError::OutOfMemory);
        }

        // Check memory budget for embedded profile
        #[cfg(feature = "embedded-profile")]
        {
            use crate::profile::MemoryStrategy;
            let budget = <P::MemoryStrategy as MemoryStrategy>::MEMORY_BUDGET;
            if budget > 0 && size > budget {
                return Err(MapError::OutOfMemory);
            }
        }

        let def = MapDef {
            map_type: MapType::RingBuf,
            key_size: 0,   // Ring buffers don't use keys
            value_size: 0, // Variable-size events
            max_entries: size as u32,
            flags: 0,
        };

        let mut data = Vec::new();
        data.try_reserve_exact(size)
            .map_err(|_| MapError::OutOfMemory)?;
        data.resize(size, 0);
        let control = RingControl::new(size);

        Ok(Self {
            def,
            control,
            data: Mutex::new(data),
            dropped_events: AtomicU64::new(0),
            _profile: PhantomData,
        })
    }

    /// Create a ring buffer with default size for the profile.
    pub fn with_default_size() -> MapResult<Self> {
        #[cfg(feature = "embedded-profile")]
        let size = 4 * 1024; // 4 KB default for embedded

        #[cfg(feature = "cloud-profile")]
        let size = 64 * 1024; // 64 KB default for cloud

        Self::new(size)
    }

    /// Reserve space for writing an event.
    ///
    /// Returns a reservation that must be submitted or discarded.
    pub fn reserve(&self, size: usize) -> Option<RingBufReservation> {
        let total_size = EventHeader::SIZE.checked_add(size)?;
        let aligned_size = total_size.checked_add(7)? & !7;

        // Check if there's enough space
        if self.control.available_space() < aligned_size {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);

            // In embedded profile, drop newest (this reservation)
            #[cfg(feature = "embedded-profile")]
            return None;

            // In cloud profile, we could drop oldest events to make room
            // For simplicity, we also drop newest here
            #[cfg(feature = "cloud-profile")]
            return None;
        }

        // Allocate space
        let head = self
            .control
            .head
            .fetch_add(aligned_size as u64, Ordering::AcqRel);
        let offset = self.control.wrap(head);

        Some(RingBufReservation {
            offset,
            data_size: size,
            total_size: aligned_size,
        })
    }

    /// Submit data to a reservation.
    ///
    /// This makes the event visible to consumers.
    pub fn submit(&self, reservation: &RingBufReservation, data: &[u8]) -> MapResult<()> {
        if data.len() > reservation.data_size {
            return Err(MapError::InvalidValue);
        }

        let mut buffer = self.data.lock();

        // Write header
        let header = EventHeader::new(data.len() as u32);
        let header_bytes = header.as_bytes();
        self.write_wrapped(&mut buffer, reservation.offset, &header_bytes);

        // Write data
        let data_offset = (reservation.offset + EventHeader::SIZE) & self.control.mask;
        self.write_wrapped(&mut buffer, data_offset, data);

        Ok(())
    }

    /// Output data directly to the ring buffer.
    ///
    /// This is a convenience method combining reserve + submit.
    pub fn output(&self, data: &[u8], flags: u64) -> MapResult<()> {
        let _ = flags; // Reserved for future use

        let reservation = self.reserve(data.len()).ok_or(MapError::MapFull)?;
        self.submit(&reservation, data)
    }

    /// Poll for available events.
    ///
    /// Returns the next event's data if available.
    pub fn poll(&self) -> Option<Vec<u8>> {
        if self.control.used_space() < EventHeader::SIZE {
            return None;
        }

        let buffer = self.data.lock();
        let tail = self.control.tail.load(Ordering::Acquire);
        let offset = self.control.wrap(tail);

        // Read header
        let mut header_bytes = [0u8; 8];
        self.read_wrapped(&buffer, offset, &mut header_bytes);
        let header = EventHeader::from_bytes(&header_bytes)?;

        if header.is_busy() {
            return None; // Event still being written
        }

        if header.is_discarded() {
            // Skip discarded event
            self.control
                .tail
                .fetch_add(header.total_size() as u64, Ordering::Release);
            drop(buffer);
            return self.poll(); // Try next event
        }

        // Read data
        let data_offset = (offset + EventHeader::SIZE) & self.control.mask;
        let mut data = vec![0u8; header.length as usize];
        self.read_wrapped(&buffer, data_offset, &mut data);

        // Advance tail
        self.control
            .tail
            .fetch_add(header.total_size() as u64, Ordering::Release);

        Some(data)
    }

    /// Write data with wrapping at buffer boundary.
    fn write_wrapped(&self, buffer: &mut [u8], offset: usize, data: &[u8]) {
        let capacity = self.control.capacity;
        let first_part = capacity - offset;

        if first_part >= data.len() {
            // No wrap needed
            buffer[offset..offset + data.len()].copy_from_slice(data);
        } else {
            // Wrap around
            buffer[offset..].copy_from_slice(&data[..first_part]);
            buffer[..data.len() - first_part].copy_from_slice(&data[first_part..]);
        }
    }

    /// Read data with wrapping at buffer boundary.
    fn read_wrapped(&self, buffer: &[u8], offset: usize, data: &mut [u8]) {
        let capacity = self.control.capacity;
        let first_part = capacity - offset;

        if first_part >= data.len() {
            // No wrap needed
            data.copy_from_slice(&buffer[offset..offset + data.len()]);
        } else {
            // Wrap around
            let second_part = data.len() - first_part;
            data[..first_part].copy_from_slice(&buffer[offset..]);
            data[first_part..].copy_from_slice(&buffer[..second_part]);
        }
    }

    /// Get number of dropped events.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// Get current buffer usage in bytes.
    pub fn used_bytes(&self) -> usize {
        self.control.used_space()
    }

    /// Get buffer capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.control.capacity
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.control.used_space() == 0
    }
}

/// Reservation for writing to ring buffer.
#[derive(Debug)]
pub struct RingBufReservation {
    /// Offset in the buffer
    offset: usize,
    /// Size of data (not including header)
    data_size: usize,
    /// Total size including header and alignment
    #[allow(dead_code)]
    total_size: usize,
}

impl RingBufReservation {
    /// Get the maximum data size that can be written.
    pub fn data_size(&self) -> usize {
        self.data_size
    }
}

impl<P: PhysicalProfile> BpfMap<P> for RingBufMap<P> {
    fn lookup(&self, _key: &[u8]) -> Option<Vec<u8>> {
        // Ring buffers don't support lookup by key
        // Instead, use poll() to read events
        self.poll()
    }

    fn update(&self, _key: &[u8], value: &[u8], flags: u64) -> MapResult<()> {
        // Ring buffers use output() for writing
        self.output(value, flags)
    }

    fn delete(&self, _key: &[u8]) -> MapResult<()> {
        // Ring buffers don't support delete
        Err(MapError::NotSupported)
    }

    fn def(&self) -> &MapDef {
        &self.def
    }

    #[cfg(feature = "cloud-profile")]
    fn resize(&mut self, new_max_entries: u32) -> MapResult<()> {
        let new_size = new_max_entries as usize;

        if !new_size.is_power_of_two() {
            return Err(MapError::InvalidValue);
        }

        if new_size > Self::MAX_BUFFER_SIZE {
            return Err(MapError::OutOfMemory);
        }

        // Resize requires draining existing data
        let mut buffer = self.data.lock();
        if new_size > buffer.len() {
            let additional = new_size - buffer.len();
            buffer
                .try_reserve_exact(additional)
                .map_err(|_| MapError::OutOfMemory)?;
        }
        buffer.resize(new_size, 0);

        // Reset control
        self.control = RingControl::new(new_size);
        self.def.max_entries = new_max_entries;

        Ok(())
    }
}

// SAFETY: RingBufMap uses atomic operations and mutex for thread safety.
unsafe impl<P: PhysicalProfile> Send for RingBufMap<P> {}
// SAFETY: RingBufMap uses atomic operations and mutex for thread safety.
unsafe impl<P: PhysicalProfile> Sync for RingBufMap<P> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_ringbuf() {
        let ringbuf = RingBufMap::<ActiveProfile>::new(4096).expect("create ringbuf");
        assert_eq!(ringbuf.capacity(), 4096);
        assert!(ringbuf.is_empty());
    }

    #[test]
    fn ringbuf_output_poll() {
        let ringbuf = RingBufMap::<ActiveProfile>::new(4096).expect("create ringbuf");

        // Write some data
        let data = b"hello world";
        ringbuf.output(data, 0).expect("output");

        // Read it back
        let result = ringbuf.poll().expect("poll");
        assert_eq!(result, data);

        // Buffer should be empty now
        assert!(ringbuf.poll().is_none());
    }

    #[test]
    fn ringbuf_multiple_events() {
        let ringbuf = RingBufMap::<ActiveProfile>::new(4096).expect("create ringbuf");

        // Write multiple events
        for i in 0u32..10 {
            let data = i.to_ne_bytes();
            ringbuf.output(&data, 0).expect("output");
        }

        // Read them back in order
        for i in 0u32..10 {
            let result = ringbuf.poll().expect("poll");
            let value = u32::from_ne_bytes(result.try_into().unwrap());
            assert_eq!(value, i);
        }

        assert!(ringbuf.poll().is_none());
    }

    #[test]
    fn ringbuf_wrap_around() {
        // Small buffer to force wrap-around
        let ringbuf = RingBufMap::<ActiveProfile>::new(256).expect("create ringbuf");

        // Write and read many events to cause wrap-around
        for round in 0..5 {
            for i in 0u32..10 {
                let value = round * 10 + i;
                let data = value.to_ne_bytes();
                ringbuf.output(&data, 0).expect("output");

                let result = ringbuf.poll().expect("poll");
                let read_value = u32::from_ne_bytes(result.try_into().unwrap());
                assert_eq!(read_value, value);
            }
        }
    }

    #[test]
    fn ringbuf_reservation() {
        let ringbuf = RingBufMap::<ActiveProfile>::new(4096).expect("create ringbuf");

        // Reserve space
        let reservation = ringbuf.reserve(32).expect("reserve");
        assert_eq!(reservation.data_size(), 32);

        // Submit data
        let data = [0xABu8; 32];
        ringbuf.submit(&reservation, &data).expect("submit");

        // Read it back
        let result = ringbuf.poll().expect("poll");
        assert_eq!(result, data);
    }

    #[test]
    fn ringbuf_buffer_full() {
        // Very small buffer
        let ringbuf = RingBufMap::<ActiveProfile>::new(64).expect("create ringbuf");

        // Fill the buffer
        let data = [0u8; 32];
        ringbuf.output(&data, 0).expect("first output");

        // Second output should fail (buffer full)
        let result = ringbuf.output(&data, 0);
        assert!(matches!(result, Err(MapError::MapFull)));

        // Check dropped count
        assert_eq!(ringbuf.dropped_count(), 1);
    }

    #[test]
    fn ringbuf_non_power_of_two_fails() {
        let result = RingBufMap::<ActiveProfile>::new(1000);
        assert!(matches!(result, Err(MapError::InvalidValue)));
    }

    #[test]
    fn ringbuf_zero_size_fails() {
        let result = RingBufMap::<ActiveProfile>::new(0);
        assert!(matches!(result, Err(MapError::InvalidValue)));
    }
}
