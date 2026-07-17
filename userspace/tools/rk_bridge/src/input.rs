//! Stream-based event ingestion for hosts that don't have access to the axiomos
//! BPF FS — for example, a Linux box that runs ROS2 and reads forwarded events
//! from `rk_uart_forwarder` over a UART/serial pipe.
//!
//! The wire format is one JSON object per line. The first object on the stream
//! is a `meta` record describing the protocol version; the consumer should
//! tolerate `meta` and `ready` records (and any unknown record types) without
//! treating them as events.
//!
//! See `docs/architecture/protocols/rk-bridge.md` for the full spec.

use std::io::{self, BufRead, BufReader, Read};

use serde::Deserialize;

use crate::event::{RkEvent, SchedSwitchEvent};

/// Errors returned by stream-based input sources.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("input I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("malformed JSON line: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("unsupported protocol version {got}, expected {expected}")]
    ProtocolVersion { got: u32, expected: u32 },
}

/// Protocol version this build understands. Bumped when the wire format
/// changes in a way that older consumers cannot ignore.
pub const SUPPORTED_PROTOCOL_VERSION: u32 = 1;

/// One decoded record from the stream. Most are events; a few are control
/// messages emitted by the forwarder.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireRecord {
    Meta {
        protocol: u32,
        #[serde(default)]
        source: String,
    },
    Ready {
        #[serde(default)]
        map_fd: i64,
    },
    SchedSwitch {
        // Sequence number from the forwarder. Useful for detecting drops on a
        // future reliability layer; not exposed yet.
        #[allow(dead_code)]
        #[serde(default)]
        seq: u64,
        cpu: u64,
        prev_pid: u64,
        prev_tid: u64,
        next_pid: u64,
        next_tid: u64,
    },
}

/// Outcome of parsing one line. Lines that aren't valid JSON or are
/// recognised control records (`meta`, `ready`) yield `None`; the caller
/// should skip those and keep reading. The protocol version is verified the
/// first time a `meta` record is observed.
fn handle_line(line: &str, protocol_seen: &mut bool) -> Result<Option<RkEvent>, InputError> {
    let trimmed = line.trim();
    if trimmed.is_empty() || !trimmed.starts_with('{') {
        return Ok(None);
    }

    let record: WireRecord = serde_json::from_str(trimmed)?;

    match record {
        WireRecord::Meta { protocol, source } => {
            if protocol != SUPPORTED_PROTOCOL_VERSION {
                return Err(InputError::ProtocolVersion {
                    got: protocol,
                    expected: SUPPORTED_PROTOCOL_VERSION,
                });
            }
            *protocol_seen = true;
            log::info!(
                "rk_bridge stream meta: protocol={}, source={}",
                protocol,
                source
            );
            Ok(None)
        }
        WireRecord::Ready { map_fd } => {
            log::info!("rk_bridge stream ready: map_fd={}", map_fd);
            Ok(None)
        }
        WireRecord::SchedSwitch {
            seq: _,
            cpu,
            prev_pid,
            prev_tid,
            next_pid,
            next_tid,
        } => Ok(Some(RkEvent::SchedSwitch(SchedSwitchEvent {
            cpu_id: cpu,
            prev_pid,
            prev_tid,
            next_pid,
            next_tid,
        }))),
    }
}

/// Iterator-style event source over any byte stream that emits the rk_bridge
/// JSON protocol. The reader is buffered internally; pass an unbuffered
/// `Read` (e.g. `io::stdin().lock()` or a serial port handle).
pub struct StreamSource<R: Read> {
    reader: BufReader<R>,
    protocol_seen: bool,
    line: String,
}

impl<R: Read> StreamSource<R> {
    pub fn new(inner: R) -> Self {
        Self {
            reader: BufReader::new(inner),
            protocol_seen: false,
            line: String::with_capacity(256),
        }
    }

    /// Pull the next event. Returns `Ok(None)` at end-of-stream. Skips any
    /// number of control / unknown / blank lines before each event.
    pub fn next_event(&mut self) -> Result<Option<RkEvent>, InputError> {
        loop {
            self.line.clear();
            let read = self.reader.read_line(&mut self.line)?;
            if read == 0 {
                return Ok(None);
            }
            if let Some(event) = handle_line(&self.line, &mut self.protocol_seen)? {
                return Ok(Some(event));
            }
        }
    }

    pub fn protocol_seen(&self) -> bool {
        self.protocol_seen
    }
}

/// Convenience constructor for the common case: read from stdin.
pub fn from_stdin() -> StreamSource<io::Stdin> {
    StreamSource::new(io::stdin())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_line(line: &str) -> Result<Option<RkEvent>, InputError> {
        let mut seen = false;
        handle_line(line, &mut seen)
    }

    #[test]
    fn meta_v1_accepted() {
        parse_line(r#"{"type":"meta","protocol":1,"source":"sched_switch"}"#).unwrap();
    }

    #[test]
    fn meta_wrong_version_rejected() {
        let err = parse_line(r#"{"type":"meta","protocol":99}"#).unwrap_err();
        assert!(matches!(
            err,
            InputError::ProtocolVersion {
                got: 99,
                expected: 1
            }
        ));
    }

    #[test]
    fn ready_returns_none() {
        let result = parse_line(r#"{"type":"ready","map_fd":3}"#).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn sched_switch_decodes() {
        let line = r#"{"type":"sched_switch","seq":1,"cpu":2,"prev_pid":10,"prev_tid":11,"next_pid":20,"next_tid":21}"#;
        let event = parse_line(line).unwrap().expect("event");
        match event {
            RkEvent::SchedSwitch(e) => {
                assert_eq!(e.cpu_id, 2);
                assert_eq!(e.prev_pid, 10);
                assert_eq!(e.next_tid, 21);
            }
            _ => panic!("expected SchedSwitch"),
        }
    }

    #[test]
    fn blank_lines_skipped() {
        assert!(parse_line("").unwrap().is_none());
        assert!(parse_line("--- rk_uart_forwarder begin ---")
            .unwrap()
            .is_none());
    }

    #[test]
    fn stream_drains_to_end() {
        let stream = b"\
--- rk_uart_forwarder begin ---
{\"type\":\"meta\",\"protocol\":1,\"source\":\"sched_switch\"}
{\"type\":\"ready\",\"map_fd\":3}
{\"type\":\"sched_switch\",\"seq\":1,\"cpu\":0,\"prev_pid\":1,\"prev_tid\":1,\"next_pid\":2,\"next_tid\":2}
{\"type\":\"sched_switch\",\"seq\":2,\"cpu\":0,\"prev_pid\":2,\"prev_tid\":2,\"next_pid\":3,\"next_tid\":3}
";
        let mut src = StreamSource::new(&stream[..]);
        assert!(matches!(
            src.next_event().unwrap(),
            Some(RkEvent::SchedSwitch(_))
        ));
        assert!(matches!(
            src.next_event().unwrap(),
            Some(RkEvent::SchedSwitch(_))
        ));
        assert!(src.next_event().unwrap().is_none());
        assert!(src.protocol_seen());
    }
}
