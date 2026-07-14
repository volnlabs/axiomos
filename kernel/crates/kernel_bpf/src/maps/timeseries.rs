//! Time-Series Map Implementation
//!
//! A BPF time-series map stores timestamped values for temporal data analysis.
//! This is designed for robotics sensor data where you need to track values
//! over time and query by time windows.
//!
//! # Memory Layout
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────────┐
//! │                       Time-Series Map                                  │
//! ├───────────────────────────────────────────────────────────────────────┤
//! │ Metadata                                                               │
//! │ ┌─────────────┬─────────────┬─────────────┬─────────────────────────┐ │
//! │ │ head_idx    │ count       │ value_size  │ capacity                │ │
//! │ └─────────────┴─────────────┴─────────────┴─────────────────────────┘ │
//! ├───────────────────────────────────────────────────────────────────────┤
//! │ Circular Buffer of Entries                                            │
//! │ ┌─────────────────────────────────────────────────────────────────┐   │
//! │ │ Entry 0: [timestamp_ns (8B)] [value (value_size B)]             │   │
//! │ ├─────────────────────────────────────────────────────────────────┤   │
//! │ │ Entry 1: [timestamp_ns (8B)] [value (value_size B)]             │   │
//! │ ├─────────────────────────────────────────────────────────────────┤   │
//! │ │ ...                                                              │   │
//! │ ├─────────────────────────────────────────────────────────────────┤   │
//! │ │ Entry N-1: [timestamp_ns (8B)] [value (value_size B)]           │   │
//! │ └─────────────────────────────────────────────────────────────────┘   │
//! └───────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```c
//! // Push a new timestamped value
//! bpf_timeseries_push(&ts_map, key, &value);
//!
//! // Query last N entries
//! bpf_timeseries_query(&ts_map, key, &output, count);
//! ```
//!
//! # Profile Differences
//!
//! | Feature       | Cloud          | Embedded       |
//! |---------------|----------------|----------------|
//! | Max entries   | Up to 1M       | Up to 4K       |
//! | Allocation    | Quota-bounded heap | Profile-bounded heap |
//! | Resize        | Supported      | **Erased**     |

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use spin::RwLock;

use super::{BpfMap, MapDef, MapError, MapResult, MapType};
use crate::profile::{ActiveProfile, PhysicalProfile};

/// Time-series entry header containing timestamp.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TimeSeriesEntry {
    /// Timestamp in nanoseconds (from bpf_ktime_get_ns)
    pub timestamp_ns: u64,
}

impl TimeSeriesEntry {
    const SIZE: usize = 8;

    fn to_bytes(self) -> [u8; 8] {
        self.timestamp_ns.to_ne_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let timestamp_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
        Some(Self { timestamp_ns })
    }
}

/// Internal storage for time-series data.
struct TimeSeriesStorage {
    /// Circular buffer of entries (header + value)
    buffer: Vec<u8>,
    /// Size of each entry (header + value)
    entry_size: usize,
    /// Value size (without header)
    value_size: usize,
    /// Maximum number of entries (capacity)
    capacity: usize,
    /// Current number of entries
    count: usize,
    /// Index of the oldest entry (head of circular buffer)
    head_idx: usize,
}

impl TimeSeriesStorage {
    fn new(value_size: usize, capacity: usize) -> MapResult<Self> {
        let entry_size = TimeSeriesEntry::SIZE
            .checked_add(value_size)
            .ok_or(MapError::OutOfMemory)?;
        let len = entry_size
            .checked_mul(capacity)
            .ok_or(MapError::OutOfMemory)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(len)
            .map_err(|_| MapError::OutOfMemory)?;
        buffer.resize(len, 0);
        Ok(Self {
            buffer,
            entry_size,
            value_size,
            capacity,
            count: 0,
            head_idx: 0,
        })
    }

    /// Push a new entry, overwriting oldest if full.
    fn push(&mut self, timestamp_ns: u64, value: &[u8]) -> bool {
        if value.len() != self.value_size {
            return false;
        }

        // Calculate write index (next position after newest)
        let write_idx = if self.count < self.capacity {
            self.count
        } else {
            // Buffer is full, overwrite oldest
            let idx = self.head_idx;
            self.head_idx = (self.head_idx + 1) % self.capacity;
            idx
        };

        let offset = write_idx * self.entry_size;

        // Write timestamp
        let entry = TimeSeriesEntry { timestamp_ns };
        self.buffer[offset..offset + TimeSeriesEntry::SIZE].copy_from_slice(&entry.to_bytes());

        // Write value
        let value_offset = offset + TimeSeriesEntry::SIZE;
        self.buffer[value_offset..value_offset + self.value_size].copy_from_slice(value);

        if self.count < self.capacity {
            self.count += 1;
        }

        true
    }

    /// Get entry at logical index (0 = oldest, count-1 = newest).
    fn get(&self, logical_idx: usize) -> Option<(u64, &[u8])> {
        if logical_idx >= self.count {
            return None;
        }

        // Map logical index to physical index
        let physical_idx = (self.head_idx + logical_idx) % self.capacity;
        let offset = physical_idx * self.entry_size;

        let entry = TimeSeriesEntry::from_bytes(&self.buffer[offset..])?;
        let value_offset = offset + TimeSeriesEntry::SIZE;
        let value = &self.buffer[value_offset..value_offset + self.value_size];

        Some((entry.timestamp_ns, value))
    }

    /// Get the last N entries (newest first).
    fn get_last_n(&self, n: usize) -> Vec<(u64, Vec<u8>)> {
        let take_count = n.min(self.count);
        let mut result = Vec::with_capacity(take_count);

        for i in 0..take_count {
            // Start from newest (count - 1) and go backwards
            let logical_idx = self.count - 1 - i;
            if let Some((ts, value)) = self.get(logical_idx) {
                result.push((ts, value.to_vec()));
            }
        }

        result
    }

    /// Get entries within a time window [start_ns, end_ns].
    fn get_in_window(&self, start_ns: u64, end_ns: u64) -> Vec<(u64, Vec<u8>)> {
        let mut result = Vec::new();

        for i in 0..self.count {
            if let Some((ts, value)) = self.get(i)
                && ts >= start_ns
                && ts <= end_ns
            {
                result.push((ts, value.to_vec()));
            }
        }

        result
    }

    /// Get the newest entry.
    fn newest(&self) -> Option<(u64, &[u8])> {
        if self.count == 0 {
            return None;
        }
        self.get(self.count - 1)
    }

    /// Get the oldest entry.
    fn oldest(&self) -> Option<(u64, &[u8])> {
        if self.count == 0 {
            return None;
        }
        self.get(0)
    }

    /// Clear all entries.
    fn clear(&mut self) {
        self.count = 0;
        self.head_idx = 0;
    }

    /// Resize storage (cloud profile only).
    #[cfg(feature = "cloud-profile")]
    fn resize(&mut self, new_capacity: usize) -> MapResult<()> {
        if new_capacity == 0 {
            return Err(MapError::InvalidValue);
        }
        if new_capacity == self.capacity {
            return Ok(());
        }

        let new_entry_size = self.entry_size;
        let new_len = new_entry_size
            .checked_mul(new_capacity)
            .ok_or(MapError::OutOfMemory)?;
        let mut new_buffer = Vec::new();
        new_buffer
            .try_reserve_exact(new_len)
            .map_err(|_| MapError::OutOfMemory)?;
        new_buffer.resize(new_len, 0);

        // Copy existing entries in order (oldest to newest)
        let copy_count = self.count.min(new_capacity);
        for i in 0..copy_count {
            if let Some((ts, value)) = self.get(i) {
                let offset = i * new_entry_size;
                let entry = TimeSeriesEntry { timestamp_ns: ts };
                new_buffer[offset..offset + TimeSeriesEntry::SIZE]
                    .copy_from_slice(&entry.to_bytes());
                let value_offset = offset + TimeSeriesEntry::SIZE;
                new_buffer[value_offset..value_offset + self.value_size].copy_from_slice(value);
            }
        }

        self.buffer = new_buffer;
        self.capacity = new_capacity;
        self.count = copy_count;
        self.head_idx = 0;
        Ok(())
    }
}

/// Time-series map implementation.
///
/// Stores timestamped values in a circular buffer for temporal analysis.
/// Ideal for robotics sensor data (IMU, encoders, etc.) where you need
/// to track values over time.
///
/// # Profile Differences
///
/// - **Cloud**: Dynamically allocated, can be resized, up to 1M entries
/// - **Embedded**: Statically allocated, fixed size, up to 4K entries
pub struct TimeSeriesMap<P: PhysicalProfile = ActiveProfile> {
    /// Map definition
    def: MapDef,
    /// Time-series storage
    storage: RwLock<TimeSeriesStorage>,
    /// Profile marker
    _profile: PhantomData<fn() -> P>,
}

impl<P: PhysicalProfile> TimeSeriesMap<P> {
    /// Maximum entries for embedded profile.
    #[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
    const MAX_ENTRIES: usize = 4 * 1024; // 4K entries

    /// Maximum entries for cloud profile.
    #[cfg(feature = "cloud-profile")]
    const MAX_ENTRIES: usize = 1024 * 1024; // 1M entries

    /// Heap bytes reserved by the circular entry buffer.
    pub const fn allocation_size(value_size: u32, max_entries: u32) -> Option<usize> {
        let entry_size = match TimeSeriesEntry::SIZE.checked_add(value_size as usize) {
            Some(size) => size,
            None => return None,
        };
        entry_size.checked_mul(max_entries as usize)
    }

    /// Create a new time-series map.
    ///
    /// # Arguments
    ///
    /// * `value_size` - Size of each value in bytes
    /// * `max_entries` - Maximum number of entries (circular buffer size)
    ///
    /// # Errors
    ///
    /// Returns an error if parameters are invalid or exceed limits.
    pub fn new(value_size: u32, max_entries: u32) -> MapResult<Self> {
        if value_size == 0 {
            return Err(MapError::InvalidValue);
        }

        if max_entries == 0 {
            return Err(MapError::InvalidValue);
        }

        if max_entries as usize > Self::MAX_ENTRIES {
            return Err(MapError::OutOfMemory);
        }

        // Check memory budget for embedded profile
        #[cfg(feature = "embedded-profile")]
        {
            let total_size =
                Self::allocation_size(value_size, max_entries).ok_or(MapError::OutOfMemory)?;
            let budget = P::MEMORY_BUDGET;
            if budget > 0 && total_size > budget {
                return Err(MapError::OutOfMemory);
            }
        }

        let def = MapDef {
            map_type: MapType::TimeSeries,
            key_size: 8, // Timestamp as key for lookups
            value_size,
            max_entries,
            flags: 0,
        };

        let storage = TimeSeriesStorage::new(value_size as usize, max_entries as usize)?;

        Ok(Self {
            def,
            storage: RwLock::new(storage),
            _profile: PhantomData,
        })
    }

    /// Push a new value with the current timestamp.
    ///
    /// This is the primary method for adding data to the time-series.
    pub fn push(&self, timestamp_ns: u64, value: &[u8]) -> MapResult<()> {
        let mut storage = self.storage.write();
        if storage.push(timestamp_ns, value) {
            Ok(())
        } else {
            Err(MapError::InvalidValue)
        }
    }

    /// Get the last N entries (newest first).
    ///
    /// Returns a vector of (timestamp, value) pairs.
    pub fn get_last_n(&self, n: usize) -> Vec<(u64, Vec<u8>)> {
        let storage = self.storage.read();
        storage.get_last_n(n)
    }

    /// Get entries within a time window.
    ///
    /// # Arguments
    ///
    /// * `start_ns` - Start timestamp (inclusive)
    /// * `end_ns` - End timestamp (inclusive)
    pub fn get_in_window(&self, start_ns: u64, end_ns: u64) -> Vec<(u64, Vec<u8>)> {
        let storage = self.storage.read();
        storage.get_in_window(start_ns, end_ns)
    }

    /// Get the newest entry.
    pub fn newest(&self) -> Option<(u64, Vec<u8>)> {
        let storage = self.storage.read();
        storage.newest().map(|(ts, v)| (ts, v.to_vec()))
    }

    /// Get the oldest entry.
    pub fn oldest(&self) -> Option<(u64, Vec<u8>)> {
        let storage = self.storage.read();
        storage.oldest().map(|(ts, v)| (ts, v.to_vec()))
    }

    /// Get the current number of entries.
    pub fn len(&self) -> usize {
        self.storage.read().count
    }

    /// Check if the time-series is empty.
    pub fn is_empty(&self) -> bool {
        self.storage.read().count == 0
    }

    /// Get the capacity (maximum entries).
    pub fn capacity(&self) -> usize {
        self.storage.read().capacity
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.storage.write().clear();
    }

    /// Compute basic statistics over the last N entries.
    ///
    /// Returns (min, max, sum, count) for numeric values interpreted as i64.
    pub fn stats_last_n(&self, n: usize) -> Option<TimeSeriesStats> {
        let entries = self.get_last_n(n);
        if entries.is_empty() {
            return None;
        }

        let mut min_ts = u64::MAX;
        let mut max_ts = 0u64;
        let mut min_val = i64::MAX;
        let mut max_val = i64::MIN;
        let mut sum: i64 = 0;

        for (ts, value) in &entries {
            min_ts = min_ts.min(*ts);
            max_ts = max_ts.max(*ts);

            // Interpret first 8 bytes as i64 for statistics
            if value.len() >= 8 {
                let val = i64::from_ne_bytes(value[0..8].try_into().unwrap());
                min_val = min_val.min(val);
                max_val = max_val.max(val);
                sum = sum.saturating_add(val);
            }
        }

        Some(TimeSeriesStats {
            count: entries.len(),
            min_timestamp_ns: min_ts,
            max_timestamp_ns: max_ts,
            min_value: min_val,
            max_value: max_val,
            sum,
        })
    }
}

/// Statistics computed over time-series entries.
#[derive(Debug, Clone, Copy)]
pub struct TimeSeriesStats {
    /// Number of entries
    pub count: usize,
    /// Minimum timestamp
    pub min_timestamp_ns: u64,
    /// Maximum timestamp
    pub max_timestamp_ns: u64,
    /// Minimum value (first 8 bytes as i64)
    pub min_value: i64,
    /// Maximum value (first 8 bytes as i64)
    pub max_value: i64,
    /// Sum of values
    pub sum: i64,
}

impl TimeSeriesStats {
    /// Compute average value.
    pub fn average(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum as f64 / self.count as f64
        }
    }

    /// Get time span in nanoseconds.
    pub fn time_span_ns(&self) -> u64 {
        self.max_timestamp_ns.saturating_sub(self.min_timestamp_ns)
    }
}

impl<P: PhysicalProfile> BpfMap<P> for TimeSeriesMap<P> {
    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        // Key is interpreted as the number of last entries to return
        // For simplicity, we return the newest entry
        if key.len() >= 4 {
            let n = u32::from_ne_bytes(key[0..4].try_into().ok()?) as usize;
            let entries = self.get_last_n(n.max(1));
            if let Some((ts, value)) = entries.first() {
                // Return timestamp + value
                let mut result = Vec::with_capacity(8 + value.len());
                result.extend_from_slice(&ts.to_ne_bytes());
                result.extend_from_slice(value);
                return Some(result);
            }
        }
        None
    }

    fn update(&self, key: &[u8], value: &[u8], _flags: u64) -> MapResult<()> {
        // Key is the timestamp
        let timestamp_ns = if key.len() >= 8 {
            u64::from_ne_bytes(key[0..8].try_into().map_err(|_| MapError::InvalidKey)?)
        } else {
            // Use 0 as default timestamp (caller should provide real timestamp)
            0
        };
        self.push(timestamp_ns, value)
    }

    fn delete(&self, _key: &[u8]) -> MapResult<()> {
        // Delete not supported - use clear() instead
        Err(MapError::NotSupported)
    }

    fn def(&self) -> &MapDef {
        &self.def
    }

    #[cfg(feature = "cloud-profile")]
    fn resize(&mut self, new_max_entries: u32) -> MapResult<()> {
        if new_max_entries as usize > Self::MAX_ENTRIES {
            return Err(MapError::OutOfMemory);
        }
        self.storage.write().resize(new_max_entries as usize)?;
        self.def.max_entries = new_max_entries;
        Ok(())
    }
}

// SAFETY: TimeSeriesMap uses RwLock for thread safety.
unsafe impl<P: PhysicalProfile> Send for TimeSeriesMap<P> {}
// SAFETY: TimeSeriesMap uses RwLock for thread safety.
unsafe impl<P: PhysicalProfile> Sync for TimeSeriesMap<P> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_timeseries_map() {
        let map = TimeSeriesMap::<ActiveProfile>::new(8, 100).expect("create map");
        assert_eq!(map.capacity(), 100);
        assert!(map.is_empty());
    }

    #[test]
    fn timeseries_push_and_get() {
        let map = TimeSeriesMap::<ActiveProfile>::new(8, 100).expect("create map");

        // Push some values
        let value1 = 100i64.to_ne_bytes();
        let value2 = 200i64.to_ne_bytes();
        let value3 = 300i64.to_ne_bytes();

        map.push(1000, &value1).expect("push 1");
        map.push(2000, &value2).expect("push 2");
        map.push(3000, &value3).expect("push 3");

        assert_eq!(map.len(), 3);

        // Get newest
        let (ts, val) = map.newest().expect("newest");
        assert_eq!(ts, 3000);
        assert_eq!(val, value3);

        // Get oldest
        let (ts, val) = map.oldest().expect("oldest");
        assert_eq!(ts, 1000);
        assert_eq!(val, value1);
    }

    #[test]
    fn timeseries_circular_buffer() {
        // Small capacity to test wrap-around
        let map = TimeSeriesMap::<ActiveProfile>::new(4, 3).expect("create map");

        // Push 5 values into capacity of 3
        for i in 0u32..5 {
            let value = i.to_ne_bytes();
            map.push(i as u64 * 1000, &value).expect("push");
        }

        // Should have 3 entries (oldest were overwritten)
        assert_eq!(map.len(), 3);

        // Oldest should be value 2 (0 and 1 were overwritten)
        let (ts, val) = map.oldest().expect("oldest");
        assert_eq!(ts, 2000);
        assert_eq!(u32::from_ne_bytes(val.try_into().unwrap()), 2);

        // Newest should be value 4
        let (ts, val) = map.newest().expect("newest");
        assert_eq!(ts, 4000);
        assert_eq!(u32::from_ne_bytes(val.try_into().unwrap()), 4);
    }

    #[test]
    fn timeseries_get_last_n() {
        let map = TimeSeriesMap::<ActiveProfile>::new(4, 100).expect("create map");

        for i in 0u32..10 {
            let value = i.to_ne_bytes();
            map.push(i as u64 * 1000, &value).expect("push");
        }

        // Get last 3
        let entries = map.get_last_n(3);
        assert_eq!(entries.len(), 3);

        // Should be newest first: 9, 8, 7
        assert_eq!(entries[0].0, 9000);
        assert_eq!(entries[1].0, 8000);
        assert_eq!(entries[2].0, 7000);
    }

    #[test]
    fn timeseries_get_in_window() {
        let map = TimeSeriesMap::<ActiveProfile>::new(4, 100).expect("create map");

        for i in 0u32..10 {
            let value = i.to_ne_bytes();
            map.push(i as u64 * 1000, &value).expect("push");
        }

        // Get entries in window [3000, 6000]
        let entries = map.get_in_window(3000, 6000);
        assert_eq!(entries.len(), 4); // 3, 4, 5, 6

        for (ts, _) in &entries {
            assert!(*ts >= 3000 && *ts <= 6000);
        }
    }

    #[test]
    fn timeseries_stats() {
        let map = TimeSeriesMap::<ActiveProfile>::new(8, 100).expect("create map");

        for i in 1i64..=5 {
            let value = (i * 10).to_ne_bytes();
            map.push(i as u64 * 1000, &value).expect("push");
        }

        let stats = map.stats_last_n(5).expect("stats");
        assert_eq!(stats.count, 5);
        assert_eq!(stats.min_value, 10);
        assert_eq!(stats.max_value, 50);
        assert_eq!(stats.sum, 10 + 20 + 30 + 40 + 50);
        assert_eq!(stats.average(), 30.0);
        assert_eq!(stats.time_span_ns(), 4000);
    }

    #[test]
    fn timeseries_clear() {
        let map = TimeSeriesMap::<ActiveProfile>::new(4, 100).expect("create map");

        for i in 0u32..5 {
            map.push(i as u64, &i.to_ne_bytes()).expect("push");
        }

        assert_eq!(map.len(), 5);
        map.clear();
        assert!(map.is_empty());
    }

    #[test]
    fn timeseries_bpf_map_interface() {
        let map = TimeSeriesMap::<ActiveProfile>::new(8, 100).expect("create map");

        // Update via BpfMap trait
        let timestamp_key = 5000u64.to_ne_bytes();
        let value = 42i64.to_ne_bytes();
        map.update(&timestamp_key, &value, 0).expect("update");

        // Lookup via BpfMap trait (returns newest)
        let lookup_key = 1u32.to_ne_bytes();
        let result = map.lookup(&lookup_key).expect("lookup");

        // Result should be timestamp + value
        assert_eq!(result.len(), 16);
        let ts = u64::from_ne_bytes(result[0..8].try_into().unwrap());
        let val = i64::from_ne_bytes(result[8..16].try_into().unwrap());
        assert_eq!(ts, 5000);
        assert_eq!(val, 42);
    }

    #[cfg(feature = "cloud-profile")]
    #[test]
    fn timeseries_resize() {
        let mut map = TimeSeriesMap::<ActiveProfile>::new(4, 5).expect("create map");

        // Fill the map
        for i in 0u32..5 {
            map.push(i as u64 * 1000, &i.to_ne_bytes()).expect("push");
        }

        // Resize to larger
        map.resize(10).expect("resize");
        assert_eq!(map.capacity(), 10);
        assert_eq!(map.len(), 5); // Data preserved

        // Can now add more
        for i in 5u32..10 {
            map.push(i as u64 * 1000, &i.to_ne_bytes()).expect("push");
        }
        assert_eq!(map.len(), 10);

        // Resize to smaller (truncates oldest)
        map.resize(3).expect("resize smaller");
        assert_eq!(map.capacity(), 3);
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn timeseries_invalid_params() {
        // Zero value size
        assert!(TimeSeriesMap::<ActiveProfile>::new(0, 100).is_err());

        // Zero entries
        assert!(TimeSeriesMap::<ActiveProfile>::new(8, 0).is_err());
    }
}
