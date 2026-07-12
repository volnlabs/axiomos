//! Array Map Implementation
//!
//! A BPF array map is a simple lookup table indexed by integer keys.
//! This implementation provides profile-aware storage:
//!
//! - Cloud: Uses dynamic Vec allocation, supports resize
//! - Embedded: Uses static pool allocation, resize is erased

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use spin::RwLock;

use super::{BpfMap, MapDef, MapError, MapResult, MapType};
use crate::profile::{ActiveProfile, PhysicalProfile};

/// Array map implementation.
///
/// Array maps provide O(1) lookup by integer index. The key is
/// interpreted as a u32 index into the array.
///
/// # Profile Differences
///
/// - **Cloud**: Dynamically allocated, can be resized
/// - **Embedded**: Statically allocated from pool, fixed size
pub struct ArrayMap<P: PhysicalProfile = ActiveProfile> {
    /// Map definition
    def: MapDef,
    /// Data storage (value_size * max_entries bytes)
    data: RwLock<ArrayStorage>,
    /// Profile marker (using fn pointer for Send + Sync)
    _profile: PhantomData<fn() -> P>,
}

/// Internal storage for array data.
struct ArrayStorage {
    /// Raw data buffer
    buffer: Vec<u8>,
    /// Value size
    value_size: usize,
    /// Maximum entries
    max_entries: usize,
}

impl ArrayStorage {
    /// Create new storage.
    fn new(value_size: usize, max_entries: usize) -> MapResult<Self> {
        let len = value_size
            .checked_mul(max_entries)
            .ok_or(MapError::OutOfMemory)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(len)
            .map_err(|_| MapError::OutOfMemory)?;
        buffer.resize(len, 0);
        Ok(Self {
            buffer,
            value_size,
            max_entries,
        })
    }

    /// Get a value at index.
    fn get(&self, index: usize) -> Option<&[u8]> {
        if index >= self.max_entries {
            return None;
        }
        let start = index * self.value_size;
        let end = start + self.value_size;
        Some(&self.buffer[start..end])
    }

    /// Set a value at index.
    fn set(&mut self, index: usize, value: &[u8]) -> bool {
        if index >= self.max_entries || value.len() != self.value_size {
            return false;
        }
        let start = index * self.value_size;
        let end = start + self.value_size;
        self.buffer[start..end].copy_from_slice(value);
        true
    }

    /// Resize storage (cloud profile only).
    #[cfg(feature = "cloud-profile")]
    fn resize(&mut self, new_max_entries: usize) -> MapResult<()> {
        let new_size = self
            .value_size
            .checked_mul(new_max_entries)
            .ok_or(MapError::OutOfMemory)?;
        if new_size > self.buffer.len() {
            self.buffer
                .try_reserve_exact(new_size - self.buffer.len())
                .map_err(|_| MapError::OutOfMemory)?;
        }
        self.buffer.resize(new_size, 0);
        self.max_entries = new_max_entries;
        Ok(())
    }
}

impl<P: PhysicalProfile> ArrayMap<P> {
    /// Heap bytes reserved by an array map's value storage.
    pub const fn allocation_size(value_size: u32, max_entries: u32) -> Option<usize> {
        (value_size as usize).checked_mul(max_entries as usize)
    }

    /// Create a new array map.
    ///
    /// # Arguments
    ///
    /// * `def` - Map definition specifying value size and max entries
    ///
    /// # Errors
    ///
    /// Returns an error if the map definition is invalid.
    pub fn new(def: MapDef) -> MapResult<Self> {
        if def.map_type != MapType::Array {
            return Err(MapError::InvalidMapType);
        }

        if def.key_size != 4 {
            // Array maps use u32 keys
            return Err(MapError::InvalidKey);
        }

        if def.value_size == 0 {
            return Err(MapError::InvalidValue);
        }

        if def.max_entries == 0 {
            return Err(MapError::InvalidValue);
        }

        // Check memory budget for embedded profile
        #[cfg(feature = "embedded-profile")]
        {
            use crate::profile::MemoryStrategy;
            let budget = <P::MemoryStrategy as MemoryStrategy>::MEMORY_BUDGET;
            let allocation_size = Self::allocation_size(def.value_size, def.max_entries)
                .ok_or(MapError::OutOfMemory)?;
            if budget > 0 && allocation_size > budget {
                return Err(MapError::OutOfMemory);
            }
        }

        let storage = ArrayStorage::new(def.value_size as usize, def.max_entries as usize)?;

        Ok(Self {
            def,
            data: RwLock::new(storage),
            _profile: PhantomData,
        })
    }

    /// Create an array map with default parameters.
    pub fn with_entries(value_size: u32, max_entries: u32) -> MapResult<Self> {
        let def = MapDef::new(MapType::Array, 4, value_size, max_entries);
        Self::new(def)
    }

    /// Parse key bytes as u32 index.
    fn parse_key(key: &[u8]) -> Option<u32> {
        if key.len() != 4 {
            return None;
        }
        Some(u32::from_ne_bytes(key.try_into().ok()?))
    }
}

impl<P: PhysicalProfile> BpfMap<P> for ArrayMap<P> {
    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        let index = Self::parse_key(key)? as usize;
        let guard = self.data.read();
        guard.get(index).map(|v| v.to_vec())
    }

    fn update(&self, key: &[u8], value: &[u8], _flags: u64) -> MapResult<()> {
        let index = Self::parse_key(key).ok_or(MapError::InvalidKey)? as usize;

        if value.len() != self.def.value_size as usize {
            return Err(MapError::InvalidValue);
        }

        let mut guard = self.data.write();
        if guard.set(index, value) {
            Ok(())
        } else {
            Err(MapError::InvalidKey)
        }
    }

    fn delete(&self, _key: &[u8]) -> MapResult<()> {
        // Array maps don't support delete (values persist until overwritten)
        Err(MapError::NotSupported)
    }

    fn def(&self) -> &MapDef {
        &self.def
    }

    // SAFETY: This method returns a raw pointer to the map value.
    // The caller must ensure that the pointer is not used after the map is modified or dropped.
    // We rely on the caller to maintain the safety invariants required by the BpfMap trait.
    unsafe fn lookup_ptr(&self, key: &[u8]) -> Option<*mut u8> {
        let index = Self::parse_key(key)? as usize;
        let guard = self.data.read();
        let slice = guard.get(index)?;
        // SAFETY: The caller guarantees they hold the lock or ensure validity.
        // We are just returning a raw pointer to the slice content.
        Some(slice.as_ptr() as *mut u8)
    }

    #[cfg(feature = "cloud-profile")]
    fn resize(&mut self, new_max_entries: u32) -> MapResult<()> {
        let mut guard = self.data.write();
        guard.resize(new_max_entries as usize)?;
        self.def.max_entries = new_max_entries;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_array_map() {
        let map = ArrayMap::<ActiveProfile>::with_entries(8, 100).expect("create map");
        assert_eq!(map.def().max_entries, 100);
        assert_eq!(map.def().value_size, 8);
    }

    #[test]
    fn array_map_operations() {
        let map = ArrayMap::<ActiveProfile>::with_entries(4, 10).expect("create map");

        // Write to index 5
        let key = 5u32.to_ne_bytes();
        let value = 42u32.to_ne_bytes();
        map.update(&key, &value, 0).expect("update");

        // Read back
        let result = map.lookup(&key).expect("lookup");
        assert_eq!(result, value);

        // Read non-existent index returns zeros
        let key2 = 7u32.to_ne_bytes();
        let result2 = map.lookup(&key2).expect("lookup");
        assert_eq!(result2, [0u8; 4]);

        // Out of bounds
        let bad_key = 100u32.to_ne_bytes();
        assert!(map.lookup(&bad_key).is_none());
    }

    #[test]
    fn array_map_invalid_key() {
        let map = ArrayMap::<ActiveProfile>::with_entries(4, 10).expect("create map");

        // Wrong key size
        let bad_key = [1u8, 2, 3]; // 3 bytes instead of 4
        assert!(map.lookup(&bad_key).is_none());

        let value = [0u8; 4];
        assert!(matches!(
            map.update(&bad_key, &value, 0),
            Err(MapError::InvalidKey)
        ));
    }

    #[test]
    fn array_map_invalid_value() {
        let map = ArrayMap::<ActiveProfile>::with_entries(4, 10).expect("create map");

        let key = 0u32.to_ne_bytes();
        let bad_value = [1u8, 2, 3]; // 3 bytes instead of 4

        assert!(matches!(
            map.update(&key, &bad_value, 0),
            Err(MapError::InvalidValue)
        ));
    }

    #[test]
    fn array_map_uses_checked_allocation_size() {
        assert_eq!(
            ArrayMap::<ActiveProfile>::allocation_size(u32::MAX, u32::MAX),
            (u32::MAX as usize).checked_mul(u32::MAX as usize)
        );
    }

    #[cfg(feature = "cloud-profile")]
    #[test]
    fn array_map_resize() {
        let mut map = ArrayMap::<ActiveProfile>::with_entries(4, 10).expect("create map");

        // Write to index 5
        let key = 5u32.to_ne_bytes();
        let value = 42u32.to_ne_bytes();
        map.update(&key, &value, 0).expect("update");

        // Resize to 20
        map.resize(20).expect("resize");
        assert_eq!(map.def().max_entries, 20);

        // Original value should still exist
        let result = map.lookup(&key).expect("lookup");
        assert_eq!(result, value);

        // Can now write to index 15
        let key2 = 15u32.to_ne_bytes();
        map.update(&key2, &value, 0).expect("update after resize");
    }
}
