//! BPF Maps
//!
//! BPF maps provide shared data storage between BPF programs and userspace.
//! This module provides profile-aware map implementations with compile-time
//! erasure of profile-inappropriate operations.
//!
//! # Profile Differences
//!
//! | Feature       | Cloud          | Embedded       |
//! |---------------|----------------|----------------|
//! | Allocation    | Quota-bounded heap | 64 KiB profile-bounded heap |
//! | Resize        | Supported      | **Erased**     |
//! | Max entries   | Configurable   | Fixed at init  |
//! | Memory        | Heap           | Heap           |
//!
//! # Compile-Time Erasure
//!
//! The `resize()` method only exists in cloud profile builds.
//! Embedded builds physically cannot call resize operations.

extern crate alloc;

mod array;
mod hash;
mod ringbuf;
mod timeseries;

use alloc::sync::Arc;

pub use array::ArrayMap;
pub use hash::HashMap;
pub use ringbuf::{RingBufMap, RingBufReservation};
use spin::RwLock;
pub use timeseries::{TimeSeriesMap, TimeSeriesStats};

use crate::profile::{ActiveProfile, PhysicalProfile};

/// BPF map types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum MapType {
    /// Unspecified
    Unspec = 0,
    /// Hash table
    Hash = 1,
    /// Array
    Array = 2,
    /// Program array
    ProgArray = 3,
    /// Perf event array
    PerfEventArray = 4,
    /// Per-CPU hash
    PerCpuHash = 5,
    /// Per-CPU array
    PerCpuArray = 6,
    /// Stack trace
    StackTrace = 7,
    /// Cgroup array
    CgroupArray = 8,
    /// LRU hash (cloud only)
    #[cfg(feature = "cloud-profile")]
    LruHash = 9,
    /// LRU per-CPU hash (cloud only)
    #[cfg(feature = "cloud-profile")]
    LruPerCpuHash = 10,
    /// LPM trie (cloud only)
    #[cfg(feature = "cloud-profile")]
    LpmTrie = 11,
    /// Ring buffer
    RingBuf = 27,
    /// Time-series map (rkBPF extension for robotics)
    TimeSeries = 100,
}

/// Map definition structure.
#[derive(Debug, Clone)]
pub struct MapDef {
    /// Map type
    pub map_type: MapType,
    /// Key size in bytes
    pub key_size: u32,
    /// Value size in bytes
    pub value_size: u32,
    /// Maximum number of entries
    pub max_entries: u32,
    /// Map flags
    pub flags: u32,
}

impl MapDef {
    /// Create a new map definition.
    pub const fn new(map_type: MapType, key_size: u32, value_size: u32, max_entries: u32) -> Self {
        Self {
            map_type,
            key_size,
            value_size,
            max_entries,
            flags: 0,
        }
    }

    /// Checked payload size for key/value maps.
    ///
    /// Callers must not use wrapping arithmetic for allocation decisions: all
    /// three fields can originate in an untrusted `BPF_MAP_CREATE` request.
    pub const fn checked_total_size(&self) -> Option<usize> {
        let entry_size = match (self.key_size as usize).checked_add(self.value_size as usize) {
            Some(size) => size,
            None => return None,
        };
        entry_size.checked_mul(self.max_entries as usize)
    }
}

/// Map operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// Key not found
    KeyNotFound,
    /// Key already exists
    KeyExists,
    /// Map is full
    MapFull,
    /// Invalid key
    InvalidKey,
    /// Invalid value
    InvalidValue,
    /// Out of memory
    OutOfMemory,
    /// Invalid map type
    InvalidMapType,
    /// Operation not supported
    NotSupported,
    /// Resize not allowed (embedded profile)
    #[cfg(feature = "embedded-profile")]
    ResizeNotAllowed,
}

impl core::fmt::Display for MapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyNotFound => write!(f, "key not found"),
            Self::KeyExists => write!(f, "key already exists"),
            Self::MapFull => write!(f, "map is full"),
            Self::InvalidKey => write!(f, "invalid key"),
            Self::InvalidValue => write!(f, "invalid value"),
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::InvalidMapType => write!(f, "invalid map type"),
            Self::NotSupported => write!(f, "operation not supported"),
            #[cfg(feature = "embedded-profile")]
            Self::ResizeNotAllowed => write!(f, "resize not allowed in embedded profile"),
        }
    }
}

/// Result type for map operations.
pub type MapResult<T> = Result<T, MapError>;

/// Trait for BPF map operations.
///
/// This trait defines the interface for BPF maps. Different map types
/// provide different lookup and storage characteristics.
///
/// # Profile-Specific Methods
///
/// The `resize()` method is only available in cloud profile builds.
/// It is completely erased from embedded builds.
pub trait BpfMap<P: PhysicalProfile = ActiveProfile>: Send + Sync {
    /// Look up a value by key.
    ///
    /// Returns `None` if the key is not found.
    fn lookup(&self, key: &[u8]) -> Option<alloc::vec::Vec<u8>>;

    /// Update a value for a key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to update
    /// * `value` - The new value
    /// * `flags` - Update flags (0 = any, 1 = no exist, 2 = exist)
    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> MapResult<()>;

    /// Delete a key from the map.
    fn delete(&self, key: &[u8]) -> MapResult<()>;

    /// Get the map definition.
    fn def(&self) -> &MapDef;

    /// Look up a value by key and return a raw pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the map is not resized or deleted while the pointer is in use.
    unsafe fn lookup_ptr(&self, _key: &[u8]) -> Option<*mut u8> {
        None
    }

    /// Resize the map (cloud profile only).
    ///
    /// This method is completely erased from embedded builds.
    ///
    /// # Arguments
    ///
    /// * `new_max_entries` - New maximum number of entries
    #[cfg(feature = "cloud-profile")]
    fn resize(&mut self, new_max_entries: u32) -> MapResult<()>;
}

/// Unique map ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MapId(pub u32);

/// Map handle for sharing maps between programs.
pub struct MapHandle<P: PhysicalProfile = ActiveProfile> {
    id: MapId,
    inner: Arc<RwLock<dyn BpfMap<P>>>,
}

impl<P: PhysicalProfile> MapHandle<P> {
    /// Create a new map handle.
    pub fn new(id: MapId, map: impl BpfMap<P> + 'static) -> Self {
        Self {
            id,
            inner: Arc::new(RwLock::new(map)),
        }
    }

    /// Get the map ID.
    pub fn id(&self) -> MapId {
        self.id
    }

    /// Look up a value.
    pub fn lookup(&self, key: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        self.inner.read().lookup(key)
    }

    /// Update a value.
    pub fn update(&self, key: &[u8], value: &[u8], flags: u64) -> MapResult<()> {
        self.inner.read().update(key, value, flags)
    }

    /// Delete a key.
    pub fn delete(&self, key: &[u8]) -> MapResult<()> {
        self.inner.read().delete(key)
    }
}

impl<P: PhysicalProfile> Clone for MapHandle<P> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_def_checked_total_size() {
        let def = MapDef::new(MapType::Array, 4, 8, 100);
        assert_eq!(def.checked_total_size(), Some((4 + 8) * 100));
    }

    #[test]
    fn map_def_size_never_wraps() {
        let def = MapDef::new(MapType::Hash, u32::MAX, u32::MAX, u32::MAX);
        let expected = (u32::MAX as usize)
            .checked_add(u32::MAX as usize)
            .and_then(|size| size.checked_mul(u32::MAX as usize));
        assert_eq!(def.checked_total_size(), expected);
    }
}
