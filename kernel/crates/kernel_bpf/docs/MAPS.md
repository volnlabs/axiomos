# BPF Maps Guide

This document describes BPF maps and how to use them for data storage and sharing.

## Overview

BPF maps are key-value stores that allow:
- Data sharing between BPF programs
- Communication between BPF and userspace
- Persistent storage across program invocations
- Efficient O(1) or O(log n) lookups

## Map Types

### ArrayMap

Fixed-size array with O(1) access by index.

```rust
use kernel_bpf::maps::{ArrayMap, BpfMap};
use kernel_bpf::profile::ActiveProfile;

// Create array map: 4-byte values, 100 entries
let map = ArrayMap::<ActiveProfile>::with_entries(4, 100)?;

// Keys are indices (0..max_entries)
let key = 5u32.to_ne_bytes();
let value = 42u32.to_ne_bytes();

// Write
map.update(&key, &value, 0)?;

// Read
let result = map.lookup(&key);
assert_eq!(result, Some(value.to_vec()));
```

**Characteristics:**
- O(1) lookup, update, delete
- Pre-allocated storage
- Cannot resize (embedded) or can resize (cloud)
- Keys must be valid indices

### HashMap

Hash table with O(1) average access and arbitrary keys (`maps/hash.rs`).

```rust
use kernel_bpf::maps::{HashMap, MapDef};

// Create from a MapDef (key size, value size, max entries)
let map = HashMap::<ActiveProfile>::new(def)?;

// Arbitrary keys
let key = b"some-unique-key!";
let value = [0u8; 64];
map.update(key, &value, 0)?;
```

### RingBufMap

Single-producer ring buffer for streaming events from BPF programs to
userspace (`maps/ringbuf.rs`). Programs write via the `ringbuf_output` helper
or the reserve/submit/discard helper triple; userspace drains records in
order.

```rust
use kernel_bpf::maps::RingBufMap;

let rb = RingBufMap::<ActiveProfile>::new(size_bytes)?;
```

### TimeSeriesMap

Ring of timestamped samples (`maps/timeseries.rs`). Programs push via the
`timeseries_push` helper; userspace reads the newest sample or drains the
window. Backs the sensor/telemetry export path.

```rust
use kernel_bpf::maps::TimeSeriesMap;

let ts = TimeSeriesMap::<ActiveProfile>::new(value_size, max_entries)?;
let newest: Option<(u64, Vec<u8>)> = ts.newest();
```

## Map Operations

### BpfMap Trait

All maps implement the `BpfMap` trait:

```rust
pub trait BpfMap<P: PhysicalProfile> {
    /// Look up a value by key
    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Update or insert a value
    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> MapResult<()>;

    /// Delete an entry
    fn delete(&self, key: &[u8]) -> MapResult<()>;

    /// Get map definition
    fn def(&self) -> &MapDef;

    /// Resize map (cloud-only)
    #[cfg(feature = "cloud-profile")]
    fn resize(&mut self, new_max_entries: u32) -> MapResult<()>;
}
```

### Lookup

```rust
// Returns Some(value) if found, None if not found
match map.lookup(&key) {
    Some(value) => {
        // Process value
        let num = u32::from_ne_bytes(value.try_into().unwrap());
    }
    None => {
        // Key not found
    }
}
```

### Update

```rust
// Update flags
const BPF_ANY: u64 = 0;      // Create or update
const BPF_NOEXIST: u64 = 1;  // Create only (fail if exists)
const BPF_EXIST: u64 = 2;    // Update only (fail if not exists)

// Create or update
map.update(&key, &value, BPF_ANY)?;

// Create only
match map.update(&key, &value, BPF_NOEXIST) {
    Ok(()) => println!("Created"),
    Err(MapError::KeyExists) => println!("Already exists"),
    Err(e) => return Err(e),
}

// Update only
match map.update(&key, &value, BPF_EXIST) {
    Ok(()) => println!("Updated"),
    Err(MapError::KeyNotFound) => println!("Not found"),
    Err(e) => return Err(e),
}
```

### Delete

```rust
match map.delete(&key) {
    Ok(()) => println!("Deleted"),
    Err(MapError::KeyNotFound) => println!("Not found"),
    Err(e) => return Err(e),
}
```

### Resize (Cloud Only)

```rust
#[cfg(feature = "cloud-profile")]
{
    let mut map = ArrayMap::with_entries(4, 100)?;

    // Grow the map
    map.resize(200)?;
    assert_eq!(map.def().max_entries, 200);

    // Shrink the map (existing entries may be lost)
    map.resize(50)?;
}
```

## Map Definition

```rust
pub struct MapDef {
    /// Type of map
    pub map_type: MapType,
    /// Size of keys in bytes
    pub key_size: u32,
    /// Size of values in bytes
    pub value_size: u32,
    /// Maximum number of entries
    pub max_entries: u32,
    /// Map flags
    pub map_flags: u32,
}

// Get map definition
let def = map.def();
println!("Key size: {}", def.key_size);
println!("Value size: {}", def.value_size);
println!("Max entries: {}", def.max_entries);
```

## Profile Differences

### Cloud Profile

- Maps use heap allocation
- `resize()` method available
- No strict memory limits

```rust
#[cfg(feature = "cloud-profile")]
fn cloud_map_example() {
    let mut map = ArrayMap::with_entries(8, 1000)?;

    // Can grow dynamically
    map.resize(10000)?;
}
```

### Embedded Profile

- Maps use static pool allocation
- No `resize()` method (compile-time erased)
- Strict memory limits from static pool

```rust
#[cfg(feature = "embedded-profile")]
fn embedded_map_example() {
    // Must fit in static pool
    let map = ArrayMap::with_entries(8, 100)?;

    // resize() doesn't exist - compile error if called
    // map.resize(200)?;  // Error: method not found
}
```

## Static Pool (Embedded Only)

The embedded profile uses a static memory pool:

```rust
#[cfg(feature = "embedded-profile")]
{
    use kernel_bpf::maps::StaticPool;

    // Check available memory
    let available = StaticPool::remaining();
    println!("Pool has {} bytes available", available);

    // Allocate from pool (internal use)
    if let Some(ptr) = StaticPool::allocate(1024) {
        // Got 1024 bytes from pool
    } else {
        // Pool exhausted
    }

    // Reset pool (testing only)
    StaticPool::reset();
}
```

**Pool Characteristics:**
- 64KB total size
- Bump allocator (fast, no fragmentation)
- Cannot free individual allocations
- Reset clears entire pool

## Thread Safety

Maps are designed to be thread-safe:

```rust
use std::sync::Arc;
use std::thread;

let map = Arc::new(ArrayMap::with_entries(4, 100)?);

let handles: Vec<_> = (0..4).map(|i| {
    let map = Arc::clone(&map);
    thread::spawn(move || {
        let key = (i as u32).to_ne_bytes();
        let value = (i as u32 * 10).to_ne_bytes();
        map.update(&key, &value, 0).unwrap();
    })
}).collect();

for handle in handles {
    handle.join().unwrap();
}
```

**Implementation:**
- `ArrayMap` uses `RwLock<ArrayStorage>`
- Multiple readers allowed
- Single writer with exclusive access

## Error Handling

```rust
pub enum MapError {
    /// Key was not found
    KeyNotFound,
    /// Key already exists (BPF_NOEXIST)
    KeyExists,
    /// Map is full
    OutOfMemory,
    /// Key size mismatch
    InvalidKeySize,
    /// Value size mismatch
    InvalidValueSize,
    /// Invalid flags
    InvalidFlags,
}

// Handle errors
match map.update(&key, &value, 0) {
    Ok(()) => {}
    Err(MapError::OutOfMemory) => {
        println!("Map is full!");
        // Maybe resize (cloud) or delete old entries
    }
    Err(e) => {
        println!("Update failed: {}", e);
    }
}
```

## Best Practices

### Choosing Map Type

| Use Case | Recommended Map |
|----------|-----------------|
| Fixed index access | ArrayMap |
| Arbitrary keys | HashMap |
| Timestamped samples / telemetry | TimeSeriesMap |
| Kernel→userspace event stream | RingBufMap |

### Memory Planning (Embedded)

```rust
#[cfg(feature = "embedded-profile")]
fn plan_memory() {
    // Calculate memory needed
    let map1_size = key_size * max_entries + value_size * max_entries;
    let map2_size = /* ... */;

    // Check against pool
    let total = map1_size + map2_size;
    if total > StaticPool::total_size() {
        panic!("Maps exceed static pool!");
    }
}
```

### Avoid Hot Keys

```rust
// BAD: All threads hit same key
map.update(b"counter", &value, 0)?;

// GOOD: Use per-thread/per-CPU keys
let key = format!("counter_{}", thread_id);
map.update(key.as_bytes(), &value, 0)?;
```

### Batch Operations

```rust
// BAD: Many individual updates
for i in 0..1000 {
    map.update(&i.to_ne_bytes(), &value, 0)?;
}

// GOOD: Batch if possible (reduce lock contention)
map.batch_update(&keys, &values)?;
```

## Examples

### Counter Map

```rust
// Create counter map
let counters = ArrayMap::<ActiveProfile>::with_entries(8, 10)?;

// Increment counter atomically
fn increment(map: &ArrayMap, index: u32) -> MapResult<u64> {
    let key = index.to_ne_bytes();

    loop {
        let old = match map.lookup(&key) {
            Some(v) => u64::from_ne_bytes(v.try_into().unwrap()),
            None => 0,
        };

        let new = (old + 1).to_ne_bytes();
        match map.update(&key, &new, 0) {
            Ok(()) => return Ok(old + 1),
            Err(MapError::KeyExists) => continue, // Retry
            Err(e) => return Err(e),
        }
    }
}
```

### Configuration Map

```rust
#[repr(C)]
struct Config {
    enabled: u32,
    threshold: u32,
    timeout_ms: u32,
}

let config_map = ArrayMap::with_entries(
    std::mem::size_of::<Config>() as u32,
    1  // Single config entry
)?;

// Write config
let config = Config {
    enabled: 1,
    threshold: 100,
    timeout_ms: 5000,
};
let bytes = unsafe {
    std::slice::from_raw_parts(
        &config as *const _ as *const u8,
        std::mem::size_of::<Config>()
    )
};
config_map.update(&0u32.to_ne_bytes(), bytes, 0)?;
```

### Statistics Map

```rust
#[repr(C)]
struct Stats {
    packets: u64,
    bytes: u64,
    errors: u64,
}

let stats_map = ArrayMap::with_entries(
    std::mem::size_of::<Stats>() as u32,
    256  // One per interface
)?;

// Read stats for interface 5
let key = 5u32.to_ne_bytes();
if let Some(data) = stats_map.lookup(&key) {
    let stats: Stats = unsafe {
        std::ptr::read(data.as_ptr() as *const Stats)
    };
    println!("Packets: {}, Bytes: {}", stats.packets, stats.bytes);
}
```
