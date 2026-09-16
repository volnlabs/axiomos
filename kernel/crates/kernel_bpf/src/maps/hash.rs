//! Hash Map Implementation
//!
//! A BPF hash map provides O(1) average-case key-value lookups.
//! This implementation uses linear probing for collision resolution,
//! which is cache-friendly and suitable for embedded systems.
//!
//! # Memory Layout
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         Hash Map                                 │
//! ├──────────┬──────────────────────────────────────────────────────┤
//! │ Metadata │                     Buckets                          │
//! │ ┌──────┐ │ ┌─────────┬─────────┬─────────┬─────────┬─────────┐ │
//! │ │count │ │ │ Bucket  │ Bucket  │ Bucket  │ Bucket  │ Bucket  │ │
//! │ │      │ │ │ ┌─────┐ │ ┌─────┐ │ ┌─────┐ │ ┌─────┐ │ ┌─────┐ │ │
//! │ └──────┘ │ │ │state│ │ │state│ │ │state│ │ │state│ │ │state│ │ │
//! │          │ │ │key  │ │ │key  │ │ │key  │ │ │key  │ │ │key  │ │ │
//! │          │ │ │value│ │ │value│ │ │value│ │ │value│ │ │value│ │ │
//! │          │ │ └─────┘ │ └─────┘ │ └─────┘ │ └─────┘ │ └─────┘ │ │
//! │          │ └─────────┴─────────┴─────────┴─────────┴─────────┘ │
//! └──────────┴──────────────────────────────────────────────────────┘
//! ```
//!
//! # Profile Differences
//!
//! | Feature       | Cloud          | Embedded         |
//! |---------------|----------------|------------------|
//! | Allocation    | Quota-bounded heap | Profile-bounded heap |
//! | Resize        | Supported      | **Erased**       |
//! | Max entries   | Configurable   | Fixed at init    |
//! | Memory        | Heap           | Heap             |

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use spin::RwLock;

use super::{BpfMap, MapDef, MapError, MapResult, MapType};
use crate::profile::{ActiveProfile, PhysicalProfile};

/// State of a hash bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum BucketState {
    /// Bucket is empty
    Empty = 0,
    /// Bucket contains valid data
    Occupied = 1,
    /// Bucket was deleted (tombstone)
    Deleted = 2,
}

impl BucketState {
    fn from_byte(value: u8) -> Self {
        match value {
            value if value == Self::Occupied as u8 => Self::Occupied,
            value if value == Self::Deleted as u8 => Self::Deleted,
            _ => Self::Empty,
        }
    }
}

/// Internal storage for hash map.
struct HashStorage {
    /// Flat `[state | key | value]` bucket records.
    storage: Vec<u8>,
    /// Key size in bytes
    key_size: usize,
    /// Value size in bytes
    value_size: usize,
    /// Bytes in one bucket record.
    entry_size: usize,
    /// Number of occupied entries
    count: usize,
    /// Maximum entries (capacity)
    capacity: usize,
}

impl HashStorage {
    fn new(key_size: usize, value_size: usize, capacity: usize) -> MapResult<Self> {
        Self::new_with_reservation(key_size, value_size, capacity, |storage, len| {
            storage
                .try_reserve_exact(len)
                .map_err(|_| MapError::OutOfMemory)
        })
    }

    fn new_with_reservation(
        key_size: usize,
        value_size: usize,
        capacity: usize,
        reserve: impl FnOnce(&mut Vec<u8>, usize) -> MapResult<()>,
    ) -> MapResult<Self> {
        let entry_size = 1usize
            .checked_add(key_size)
            .and_then(|size| size.checked_add(value_size))
            .ok_or(MapError::OutOfMemory)?;
        let storage_size = entry_size
            .checked_mul(capacity)
            .ok_or(MapError::OutOfMemory)?;
        let mut storage = Vec::new();
        reserve(&mut storage, storage_size)?;
        storage.resize(storage_size, BucketState::Empty as u8);

        Ok(Self {
            storage,
            key_size,
            value_size,
            entry_size,
            count: 0,
            capacity,
        })
    }

    fn bucket_offset(&self, index: usize) -> usize {
        index * self.entry_size
    }

    fn state(&self, index: usize) -> BucketState {
        BucketState::from_byte(self.storage[self.bucket_offset(index)])
    }

    fn set_state(&mut self, index: usize, state: BucketState) {
        let offset = self.bucket_offset(index);
        // SAFETY: callers select an in-bounds bucket. Avoid materializing a
        // mutable buffer slice. Deletion changes only
        // this state byte and leaves the fixed value storage initialized,
        // although the lookup-pointer contract ends for the deleted entry.
        unsafe { self.storage.as_mut_ptr().add(offset).write(state as u8) };
    }

    fn key(&self, index: usize) -> &[u8] {
        let start = self.bucket_offset(index) + 1;
        &self.storage[start..start + self.key_size]
    }

    fn value(&self, index: usize) -> &[u8] {
        let start = self.bucket_offset(index) + 1 + self.key_size;
        &self.storage[start..start + self.value_size]
    }

    /// Compute hash of a key.
    fn hash(&self, key: &[u8]) -> usize {
        // FNV-1a hash - good distribution for typical BPF workloads
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in key {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash as usize
    }

    /// Find bucket for a key.
    ///
    /// Returns (bucket_index, found) where:
    /// - If found is true, bucket_index is the bucket containing the key
    /// - If found is false, bucket_index is where the key should be inserted
    fn find_bucket(&self, key: &[u8]) -> (usize, bool) {
        let start = self.hash(key) % self.capacity;
        let mut idx = start;
        let mut first_deleted: Option<usize> = None;

        loop {
            match self.state(idx) {
                BucketState::Empty => {
                    return (first_deleted.unwrap_or(idx), false);
                }
                BucketState::Deleted => {
                    if first_deleted.is_none() {
                        first_deleted = Some(idx);
                    }
                }
                BucketState::Occupied if self.key(idx) == key => {
                    return (idx, true);
                }
                BucketState::Occupied => {}
            }

            // Linear probing
            idx = (idx + 1) % self.capacity;

            if idx == start {
                // Wrapped around - table is full of non-empty slots
                let insert_idx = first_deleted.unwrap_or(idx);
                return (insert_idx, false);
            }
        }
    }

    fn lookup(&self, key: &[u8]) -> Option<&[u8]> {
        if key.len() != self.key_size {
            return None;
        }

        let (idx, found) = self.find_bucket(key);
        if found { Some(self.value(idx)) } else { None }
    }

    fn update(&mut self, key: &[u8], value: &[u8], flags: u64) -> MapResult<()> {
        if key.len() != self.key_size {
            return Err(MapError::InvalidKey);
        }
        if value.len() != self.value_size {
            return Err(MapError::InvalidValue);
        }

        // SAFETY: the slices provide the exact readable extents checked above.
        // Safe Rust also guarantees that neither input aliases the mutable
        // storage borrowed for this update.
        unsafe { self.update_ptr(key.as_ptr(), value.as_ptr(), flags) }
    }

    /// Update from exact-size raw inputs which may point into this storage.
    ///
    /// # Safety
    /// `key` and `value` must remain readable for `key_size` and `value_size`
    /// bytes respectively. They may point within value regions of `storage`,
    /// but no Rust references may alias bytes written by this operation.
    unsafe fn update_ptr(&mut self, key: *const u8, value: *const u8, flags: u64) -> MapResult<()> {
        // Keep the temporary key reference inside the read-only lookup phase.
        // It may itself refer to a map value which this update will overwrite.
        let (idx, found) = {
            // SAFETY: guaranteed by this method's contract.
            let key = unsafe { core::slice::from_raw_parts(key, self.key_size) };
            self.find_bucket(key)
        };

        // BPF_NOEXIST (1): fail if key exists
        if flags == 1 && found {
            return Err(MapError::KeyExists);
        }

        // BPF_EXIST (2): fail if key doesn't exist
        if flags == 2 && !found {
            return Err(MapError::KeyNotFound);
        }

        if !found {
            // Check capacity
            if self.count >= self.capacity {
                return Err(MapError::MapFull);
            }
            self.count += 1;
        }

        let key_start = self.bucket_offset(idx) + 1;
        let value_start = key_start + self.key_size;
        let state = key_start - 1;
        let storage = self.storage.as_mut_ptr();
        // SAFETY: the destination ranges are within the selected bucket. The
        // caller provides readable source extents. `copy` deliberately permits
        // self-update and other overlap within the same backing allocation.
        unsafe {
            core::ptr::copy(key, storage.add(key_start), self.key_size);
            core::ptr::copy(value, storage.add(value_start), self.value_size);
            storage.add(state).write(BucketState::Occupied as u8);
        }

        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> MapResult<()> {
        if key.len() != self.key_size {
            return Err(MapError::InvalidKey);
        }

        let (idx, found) = self.find_bucket(key);

        if !found {
            return Err(MapError::KeyNotFound);
        }

        self.set_state(idx, BucketState::Deleted);
        self.count -= 1;

        Ok(())
    }

    /// Build and populate a replacement table after a caller-provided
    /// reservation succeeds. The live table is published only at the end.
    #[cfg(feature = "cloud-profile")]
    fn resize_with_reservation(
        &mut self,
        new_capacity: usize,
        reserve: impl FnOnce(&mut Vec<u8>, usize) -> MapResult<()>,
    ) -> MapResult<()> {
        if new_capacity == 0 {
            return Err(MapError::InvalidValue);
        }
        let mut replacement =
            Self::new_with_reservation(self.key_size, self.value_size, new_capacity, reserve)?;

        // Populate the replacement fully before publishing it. Any allocation
        // or rehash failure leaves the live table unchanged.
        for index in 0..self.capacity {
            if self.state(index) == BucketState::Occupied {
                replacement.update(self.key(index), self.value(index), 0)?;
            }
        }

        *self = replacement;
        Ok(())
    }
}

/// Hash map implementation.
///
/// Provides O(1) average-case key-value lookups using linear probing.
pub struct HashMap<P: PhysicalProfile = ActiveProfile> {
    /// Map definition
    def: MapDef,
    /// Storage
    storage: RwLock<HashStorage>,
    /// Profile marker
    _profile: PhantomData<fn() -> P>,
}

impl<P: PhysicalProfile> HashMap<P> {
    /// Heap bytes reserved by the flat bucket table.
    pub const fn allocation_size(
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Option<usize> {
        let payload = match 1usize.checked_add(key_size as usize) {
            Some(size) => size,
            None => return None,
        };
        let per_bucket = match payload.checked_add(value_size as usize) {
            Some(size) => size,
            None => return None,
        };
        per_bucket.checked_mul(max_entries as usize)
    }

    /// Create a new hash map.
    ///
    /// # Arguments
    ///
    /// * `def` - Map definition specifying key/value sizes and max entries
    ///
    /// # Errors
    ///
    /// Returns an error if the map definition is invalid.
    pub fn new(def: MapDef) -> MapResult<Self> {
        if def.map_type != MapType::Hash {
            return Err(MapError::InvalidMapType);
        }

        if def.key_size == 0 {
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
            let budget = P::MEMORY_BUDGET;
            let allocation_size =
                Self::allocation_size(def.key_size, def.value_size, def.max_entries)
                    .ok_or(MapError::OutOfMemory)?;
            if budget > 0 && allocation_size > budget {
                return Err(MapError::OutOfMemory);
            }
        }

        let storage = HashStorage::new(
            def.key_size as usize,
            def.value_size as usize,
            def.max_entries as usize,
        )?;

        Ok(Self {
            def,
            storage: RwLock::new(storage),
            _profile: PhantomData,
        })
    }

    /// Create a hash map with specified sizes.
    pub fn with_sizes(key_size: u32, value_size: u32, max_entries: u32) -> MapResult<Self> {
        let def = MapDef::new(MapType::Hash, key_size, value_size, max_entries);
        Self::new(def)
    }

    /// Get the number of entries in the map.
    pub fn len(&self) -> usize {
        self.storage.read().count
    }

    /// Check if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the capacity of the map.
    pub fn capacity(&self) -> usize {
        self.storage.read().capacity
    }

    /// Resize after reserving the unpublished replacement table.
    ///
    /// The map definition is updated only after the replacement has been fully
    /// allocated and rehashed, so every failure leaves both data and metadata
    /// unchanged.
    #[cfg(feature = "cloud-profile")]
    fn resize_with_reservation(
        &mut self,
        new_max_entries: u32,
        reserve: impl FnOnce(&mut Vec<u8>, usize) -> MapResult<()>,
    ) -> MapResult<()> {
        let storage = self.storage.get_mut();

        if (new_max_entries as usize) < storage.count {
            return Err(MapError::InvalidValue);
        }

        storage.resize_with_reservation(new_max_entries as usize, reserve)?;
        self.def.max_entries = new_max_entries;
        Ok(())
    }
}

impl<P: PhysicalProfile> BpfMap<P> for HashMap<P> {
    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        let guard = self.storage.read();
        guard.lookup(key).map(|v| v.to_vec())
    }

    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> MapResult<()> {
        // Reject mismatched generic-helper calls before taking a mutable guard:
        // their value slice may have originated in this map's lookup storage.
        if key.len() != self.def.key_size as usize {
            return Err(MapError::InvalidKey);
        }
        if value.len() != self.def.value_size as usize {
            return Err(MapError::InvalidValue);
        }
        let mut guard = self.storage.write();
        guard.update(key, value, flags)
    }

    unsafe fn update_ptr(&self, key: *const u8, value: *const u8, flags: u64) -> MapResult<()> {
        let mut guard = self.storage.write();
        // SAFETY: forwarded from the BpfMap raw-update contract; the write
        // guard excludes concurrent access without materializing input slices.
        unsafe { guard.update_ptr(key, value, flags) }
    }

    fn delete(&self, key: &[u8]) -> MapResult<()> {
        let mut guard = self.storage.write();
        guard.delete(key)
    }

    fn def(&self) -> &MapDef {
        &self.def
    }

    /// # Safety
    /// This method returns a raw pointer to the map value. The caller must keep
    /// the allocation exclusively leased and prevent resize/drop/deletion of
    /// the selected entry. Fixed-storage updates do not reallocate. Deletion
    /// leaves initialized bytes behind but ends the entry's pointer contract.
    unsafe fn lookup_ptr(&self, key: &[u8]) -> Option<*mut u8> {
        let mut guard = self.storage.write();
        if key.len() != guard.key_size {
            return None;
        }
        let (idx, found) = guard.find_bucket(key);
        if !found {
            return None;
        }
        let value_start = guard.bucket_offset(idx) + 1 + guard.key_size;
        // SAFETY: find_bucket selected an occupied, in-bounds bucket.
        // `as_mut_ptr` preserves writable provenance without first creating a
        // shared reference to the value bytes. The caller keeps the allocation
        // stable and exclusively leased while this pointer remains in use.
        Some(unsafe { guard.storage.as_mut_ptr().add(value_start) })
    }

    #[cfg(feature = "cloud-profile")]
    fn resize(&mut self, new_max_entries: u32) -> MapResult<()> {
        self.resize_with_reservation(new_max_entries, |storage, len| {
            storage
                .try_reserve_exact(len)
                .map_err(|_| MapError::OutOfMemory)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_hash_map() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 8, 100).expect("create map");
        assert_eq!(map.def().max_entries, 100);
        assert_eq!(map.def().key_size, 4);
        assert_eq!(map.def().value_size, 8);
        assert!(map.is_empty());
    }

    #[test]
    fn hash_map_operations() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 8, 100).expect("create map");

        // Insert
        let key = 42u32.to_ne_bytes();
        let value = 123u64.to_ne_bytes();
        map.update(&key, &value, 0).expect("insert");
        assert_eq!(map.len(), 1);

        // Lookup
        let result = map.lookup(&key).expect("lookup");
        assert_eq!(result, value);

        // Update existing
        let new_value = 456u64.to_ne_bytes();
        map.update(&key, &new_value, 0).expect("update");
        let result = map.lookup(&key).expect("lookup after update");
        assert_eq!(result, new_value);
        assert_eq!(map.len(), 1);

        // Delete
        map.delete(&key).expect("delete");
        assert!(map.lookup(&key).is_none());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn hash_map_allocation_size_includes_bucket_storage() {
        let payload = (1 + 4 + 8) * 100;
        assert_eq!(
            HashMap::<ActiveProfile>::allocation_size(4, 8, 100),
            Some(payload)
        );

        let storage = HashStorage::new(4, 8, 100).expect("flat storage");
        assert_eq!(storage.entry_size, 13);
        assert_eq!(storage.storage.len(), payload);
        assert_eq!(storage.bucket_offset(99) + storage.entry_size, payload);
    }

    #[test]
    fn hash_map_noexist_flag() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 8, 100).expect("create map");

        let key = 1u32.to_ne_bytes();
        let value = [0u8; 8];

        // First insert should succeed
        map.update(&key, &value, 1).expect("first insert");

        // Second insert with NOEXIST should fail
        let result = map.update(&key, &value, 1);
        assert!(matches!(result, Err(MapError::KeyExists)));
    }

    #[test]
    fn hash_raw_update_preserves_map_backed_inputs_and_lookup_pointer() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 8, 8).expect("create map");
        let source_key = 1u32.to_ne_bytes();
        let copied_key = 2u32.to_ne_bytes();
        let map_backed_key = 3u32.to_ne_bytes();
        let mut source_value = [0x5a; 8];
        source_value[..4].copy_from_slice(&map_backed_key);
        map.update(&source_key, &source_value, 0)
            .expect("seed source value");

        // SAFETY: this test exclusively owns a fixed-capacity map. Every raw
        // input covers a live value extent or an exact-size local key, and no
        // Rust reference aliases bytes while the raw operations execute.
        unsafe {
            let source = map.lookup_ptr(&source_key).expect("source pointer");

            // Exact self-update and a same-map copy to another entry must both
            // use overlap-aware raw copies.
            map.update_ptr(source_key.as_ptr(), source, 0)
                .expect("self-update");
            map.update_ptr(copied_key.as_ptr(), source, 0)
                .expect("copy to another entry");

            // The key itself may be read from a map value. It is consumed
            // before writes, then copied with raw operations.
            map.update_ptr(source, source, 0)
                .expect("map-backed key and value");
            assert_eq!(
                map.update_ptr(source, source, 1),
                Err(MapError::KeyExists),
                "NOEXIST must fail before mutating either aliased input"
            );

            // Fixed-storage updates do not reallocate. A retained lookup
            // pointer remains writable while its entry is live and the
            // execution lease is exclusive.
            source.add(4).write(0x7b);
            let destination = map.lookup_ptr(&map_backed_key).unwrap();
            map.update_ptr(destination, source, 2)
                .expect("key in destination consumed before overwrite");

            // End pointer use before deletion: the bytes remain initialized,
            // but a deleted entry no longer satisfies the pointer contract.
            let retained = map.lookup_ptr(&copied_key).unwrap();
            map.delete(&source_key).expect("delete source entry");
            retained.add(5).write(0x6c);
        }

        let mut changed_source = source_value;
        changed_source[4] = 0x7b;
        assert!(map.lookup(&source_key).is_none());
        source_value[5] = 0x6c;
        assert_eq!(map.lookup(&copied_key), Some(source_value.to_vec()));
        assert_eq!(map.lookup(&map_backed_key), Some(changed_source.to_vec()));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn hash_map_exist_flag() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 8, 100).expect("create map");

        let key = 1u32.to_ne_bytes();
        let value = [0u8; 8];

        // Update with EXIST flag on non-existent key should fail
        let result = map.update(&key, &value, 2);
        assert!(matches!(result, Err(MapError::KeyNotFound)));

        // Insert first
        map.update(&key, &value, 0).expect("insert");

        // Now update with EXIST should succeed
        map.update(&key, &value, 2).expect("update existing");
    }

    #[test]
    fn hash_map_many_entries() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 4, 1000).expect("create map");

        // Insert many entries
        for i in 0u32..500 {
            let key = i.to_ne_bytes();
            let value = (i * 2).to_ne_bytes();
            map.update(&key, &value, 0).expect("insert");
        }

        assert_eq!(map.len(), 500);

        // Verify all entries
        for i in 0u32..500 {
            let key = i.to_ne_bytes();
            let result = map.lookup(&key).expect("lookup");
            let expected = (i * 2).to_ne_bytes();
            assert_eq!(result, expected);
        }

        // Delete half
        for i in 0u32..250 {
            let key = i.to_ne_bytes();
            map.delete(&key).expect("delete");
        }

        assert_eq!(map.len(), 250);

        // Verify deleted entries are gone
        for i in 0u32..250 {
            let key = i.to_ne_bytes();
            assert!(map.lookup(&key).is_none());
        }

        // Verify remaining entries
        for i in 250u32..500 {
            let key = i.to_ne_bytes();
            assert!(map.lookup(&key).is_some());
        }
    }

    #[test]
    fn hash_map_full() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 4, 10).expect("create map");

        // Fill the map
        for i in 0u32..10 {
            let key = i.to_ne_bytes();
            let value = i.to_ne_bytes();
            map.update(&key, &value, 0).expect("insert");
        }

        // Next insert should fail
        let key = 100u32.to_ne_bytes();
        let value = 100u32.to_ne_bytes();
        let result = map.update(&key, &value, 0);
        assert!(matches!(result, Err(MapError::MapFull)));
    }

    #[test]
    fn hash_map_reuse_deleted() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 4, 10).expect("create map");

        // Fill the map
        for i in 0u32..10 {
            let key = i.to_ne_bytes();
            let value = i.to_ne_bytes();
            map.update(&key, &value, 0).expect("insert");
        }

        // Delete one entry
        let key = 5u32.to_ne_bytes();
        map.delete(&key).expect("delete");

        // Should be able to insert a new entry
        let new_key = 100u32.to_ne_bytes();
        let new_value = 100u32.to_ne_bytes();
        map.update(&new_key, &new_value, 0)
            .expect("insert into deleted slot");
    }

    #[test]
    fn hash_map_invalid_sizes() {
        // Zero key size
        let result = HashMap::<ActiveProfile>::with_sizes(0, 8, 100);
        assert!(matches!(result, Err(MapError::InvalidKey)));

        // Zero value size
        let result = HashMap::<ActiveProfile>::with_sizes(4, 0, 100);
        assert!(matches!(result, Err(MapError::InvalidValue)));

        // Zero entries
        let result = HashMap::<ActiveProfile>::with_sizes(4, 8, 0);
        assert!(matches!(result, Err(MapError::InvalidValue)));
    }

    #[test]
    fn hash_map_wrong_key_size() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 8, 100).expect("create map");

        // Wrong key size on lookup
        let bad_key = [1u8, 2, 3]; // 3 bytes instead of 4
        assert!(map.lookup(&bad_key).is_none());

        // Wrong key size on update
        let value = [0u8; 8];
        assert!(matches!(
            map.update(&bad_key, &value, 0),
            Err(MapError::InvalidKey)
        ));
    }

    #[test]
    fn hash_map_wrong_value_size() {
        let map = HashMap::<ActiveProfile>::with_sizes(4, 8, 100).expect("create map");

        let key = 1u32.to_ne_bytes();
        let bad_value = [1u8, 2, 3]; // 3 bytes instead of 8

        assert!(matches!(
            map.update(&key, &bad_value, 0),
            Err(MapError::InvalidValue)
        ));
    }

    #[cfg(feature = "cloud-profile")]
    #[test]
    fn hash_map_resize() {
        let mut map = HashMap::<ActiveProfile>::with_sizes(4, 4, 10).expect("create map");

        // Insert some entries
        for i in 0u32..5 {
            let key = i.to_ne_bytes();
            let value = (i * 10).to_ne_bytes();
            map.update(&key, &value, 0).expect("insert");
        }

        // Resize to larger
        map.resize(20).expect("resize");
        assert_eq!(map.capacity(), 20);

        // Verify entries still exist
        for i in 0u32..5 {
            let key = i.to_ne_bytes();
            let result = map.lookup(&key).expect("lookup after resize");
            let expected = (i * 10).to_ne_bytes();
            assert_eq!(result, expected);
        }

        // Can now insert more entries
        for i in 10u32..20 {
            let key = i.to_ne_bytes();
            let value = i.to_ne_bytes();
            map.update(&key, &value, 0).expect("insert after resize");
        }
    }

    #[cfg(feature = "cloud-profile")]
    #[test]
    fn hash_map_resize_fail_after_n_preserves_live_storage() {
        let mut map = HashMap::<ActiveProfile>::with_sizes(4, 4, 8).expect("create map");
        let live = [
            (1u32.to_ne_bytes(), 10u32.to_ne_bytes()),
            (2u32.to_ne_bytes(), 20u32.to_ne_bytes()),
            (3u32.to_ne_bytes(), 30u32.to_ne_bytes()),
        ];
        for (key, value) in &live {
            map.update(key, value, 0).expect("seed live entry");
        }
        map.delete(&live[1].0).expect("create tombstone");

        let before_def_max_entries = map.def.max_entries;
        let storage = map.storage.get_mut();
        let before_storage = storage.storage.clone();
        let before_metadata = (
            storage.key_size,
            storage.value_size,
            storage.entry_size,
            storage.count,
            storage.capacity,
        );

        for fail_at in 1..=1 {
            let mut checkpoint = 0;
            let error = map
                .resize_with_reservation(16, |_replacement, len| {
                    checkpoint += 1;
                    assert_eq!(len, 9 * 16);
                    if checkpoint == fail_at {
                        Err(MapError::OutOfMemory)
                    } else {
                        Ok(())
                    }
                })
                .expect_err("injected replacement reservation must fail");

            assert_eq!(error, MapError::OutOfMemory);
            assert_eq!(checkpoint, fail_at);
            let storage = map.storage.get_mut();
            assert_eq!(storage.storage, before_storage);
            assert_eq!(
                (
                    storage.key_size,
                    storage.value_size,
                    storage.entry_size,
                    storage.count,
                    storage.capacity,
                ),
                before_metadata
            );
            assert_eq!(map.def.max_entries, before_def_max_entries);
            assert_eq!(
                map.lookup(&live[0].0).as_deref(),
                Some(live[0].1.as_slice())
            );
            assert!(map.lookup(&live[1].0).is_none());
            assert_eq!(
                map.lookup(&live[2].0).as_deref(),
                Some(live[2].1.as_slice())
            );
        }

        let replacement_value = 200u32.to_ne_bytes();
        map.update(&live[1].0, &replacement_value, 0)
            .expect("reuse live table after failed resize");
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.lookup(&live[1].0).as_deref(),
            Some(replacement_value.as_slice())
        );

        map.resize(16).expect("later production resize succeeds");
        assert_eq!(map.capacity(), 16);
        assert_eq!(map.def.max_entries, 16);
        for key in 4u32..=10 {
            map.update(&key.to_ne_bytes(), &(key * 10).to_ne_bytes(), 0)
                .expect("insert beyond original live count");
        }
        assert_eq!(map.len(), 10);
        assert_eq!(
            map.lookup(&live[0].0).as_deref(),
            Some(live[0].1.as_slice())
        );
        assert_eq!(
            map.lookup(&live[1].0).as_deref(),
            Some(replacement_value.as_slice())
        );
        assert_eq!(
            map.lookup(&live[2].0).as_deref(),
            Some(live[2].1.as_slice())
        );
    }
}
