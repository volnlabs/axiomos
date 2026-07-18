// The protocol bridge accepts raw ring-buffer events and line-oriented JSON
// streams from hardware forwarders. Neither untrusted boundary may panic.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use rk_bridge::{RkEvent, StreamSource};

fuzz_target!(|data: &[u8]| {
    let _ = RkEvent::from_bytes(data);

    let mut stream = StreamSource::new(Cursor::new(data));
    for _ in 0..64 {
        match stream.next_event() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
});
