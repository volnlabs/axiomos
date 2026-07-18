// Stateful model oracle for the safe ring-buffer API. Successful writes must
// be observed exactly once and in FIFO order across wraparound and full-buffer
// rejection.

#![no_main]

use std::collections::VecDeque;

use kernel_bpf::maps::RingBufMap;
use kernel_bpf::profile::CloudProfile;
use libfuzzer_sys::fuzz_target;

const CAPACITY: usize = 256;
const MAX_EVENT: usize = 96;

fuzz_target!(|data: &[u8]| {
    let ring = RingBufMap::<CloudProfile>::new(CAPACITY).expect("fixed capacity is valid");
    let mut expected = VecDeque::<Vec<u8>>::new();
    let mut cursor = 0;

    while cursor < data.len() {
        let control = data[cursor];
        cursor += 1;
        if control & 0x03 == 0 {
            assert_eq!(ring.poll(), expected.pop_front());
            continue;
        }

        let requested = usize::from(control >> 2).min(MAX_EVENT);
        let available = requested.min(data.len() - cursor);
        let payload = &data[cursor..cursor + available];
        cursor += available;
        if ring.output(payload, u64::from(control)).is_ok() {
            expected.push_back(payload.to_vec());
        }
    }

    while let Some(event) = expected.pop_front() {
        assert_eq!(ring.poll().as_deref(), Some(event.as_slice()));
    }
    assert!(ring.poll().is_none());
    assert!(ring.is_empty());
});
