//! Fixed storage for the bench-only deferred console; caller synchronizes.
use core::fmt::{self, Write};

use shrike_link::ring::RingBuf;

const RECORD_BYTES: usize = 1024;
struct Record {
    bytes: [u8; RECORD_BYTES],
    len: usize,
}
impl Record {
    fn new() -> Self {
        Self {
            bytes: [0; RECORD_BYTES],
            len: 0,
        }
    }
}
impl Write for Record {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if text.len() > RECORD_BYTES - self.len {
            return Err(fmt::Error);
        }
        for byte in text.bytes() {
            let needed = if byte == b'\n' { 2 } else { 1 };
            if needed > RECORD_BYTES - self.len {
                return Err(fmt::Error);
            }
            if byte == b'\n' {
                self.bytes[self.len] = b'\r';
                self.len += 1;
            }
            self.bytes[self.len] = byte;
            self.len += 1;
        }
        Ok(())
    }
}

/// N queued bytes plus at most one byte pending a busy UART. Records are
/// formatted into fixed stack storage and either queued whole or dropped.
pub struct BenchBuffer<const N: usize> {
    bytes: RingBuf<N>,
    pending: Option<u8>,
    dropped: u64,
    reported: u64,
    full: u64,
    format: u64,
    contended: u64,
    high_water: usize,
    drains: u64,
    sent: u64,
    fifo_full: u64,
}
impl<const N: usize> BenchBuffer<N> {
    pub const fn new() -> Self {
        Self {
            bytes: RingBuf::new(),
            pending: None,
            dropped: 0,
            reported: 0,
            full: 0,
            format: 0,
            contended: 0,
            high_water: 0,
            drains: 0,
            sent: 0,
            fifo_full: 0,
        }
    }
    fn push_record(&mut self, record: &Record) -> bool {
        if record.len > N - self.bytes.len() {
            return false;
        }
        for &byte in &record.bytes[..record.len] {
            self.bytes.push(byte);
        }
        self.high_water = self.high_water.max(self.bytes.len());
        true
    }
    fn report_loss(&mut self) {
        if self.dropped == self.reported {
            return;
        }
        let mut record = Record::new();
        // Queue diagnostics before the existing fatal-to-the-capture marker:
        // the host may stop its UART reader as soon as it sees LOG_LOSS.
        let _ = writeln!(
            record,
            "PI5_BENCH_LOG_STATE full={} format={} contended={} high_water={} drains={} sent={} fifo_full={}\nPI5_BENCH_LOG_LOSS dropped_records={}",
            self.full, self.format, self.contended, self.high_water,
            self.drains, self.sent, self.fifo_full, self.dropped
        );
        if self.push_record(&record) {
            self.reported = self.dropped;
        }
    }
    pub fn record(&mut self, args: fmt::Arguments<'_>) {
        self.report_loss();
        let mut record = Record::new();
        if record.write_fmt(args).is_err() {
            self.format = self.format.saturating_add(1);
            self.dropped = self.dropped.saturating_add(1);
        } else if !self.push_record(&record) {
            self.full = self.full.saturating_add(1);
            self.dropped = self.dropped.saturating_add(1);
        }
    }
    /// A full FIFO costs one failed send attempt, never a wait. A failed byte
    /// stays pending so neither loss nor reordering can occur on retry.
    pub fn drain(&mut self, budget: usize, mut send: impl FnMut(u8) -> bool) {
        self.drains = self.drains.saturating_add(1);
        let mut sent = 0;
        for _ in 0..budget {
            let Some(byte) = self.pending.take().or_else(|| self.bytes.pop()) else {
                break;
            };
            if !send(byte) {
                self.pending = Some(byte);
                self.fifo_full = self.fifo_full.saturating_add(1);
                break;
            }
            sent += 1;
        }
        self.sent = self.sent.saturating_add(sent);
        self.report_loss();
    }
    pub fn note_dropped(&mut self, count: u64) {
        self.contended = self.contended.saturating_add(count);
        self.dropped = self.dropped.saturating_add(count);
    }
    #[cfg(test)]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn stalled_uart_preserves_fifo_and_drain_budget() {
        let mut buffer = BenchBuffer::<2048>::new();
        buffer.record(format_args!("first\n"));
        let mut calls = 0;
        buffer.drain(64, |_| {
            calls += 1;
            false
        });
        assert_eq!(
            calls, 1,
            "full FIFO must stop after one nonblocking attempt"
        );
        buffer.record(format_args!("second\n"));
        let mut bytes = Vec::new();
        buffer.drain(3, |b| {
            bytes.push(b);
            true
        });
        assert_eq!(bytes, b"fir");
        buffer.drain(64, |b| {
            bytes.push(b);
            true
        });
        assert_eq!(bytes, b"first\r\nsecond\r\n");
        assert_eq!(buffer.dropped(), 0);
        buffer.note_dropped(1); // A rejected recursive/contended producer.
        buffer.drain(0, |_| panic!("zero budget must never touch the UART"));
        buffer.drain(256, |b| {
            bytes.push(b);
            true
        });
        let text = alloc::string::String::from_utf8(bytes).unwrap();
        assert!(text.ends_with("PI5_BENCH_LOG_LOSS dropped_records=1\r\n"));
        assert!(text.contains("PI5_BENCH_LOG_STATE full=0 format=0 contended=1"));
        assert!(text.contains("drains=4 sent=15 fifo_full=1"));
    }

    #[test]
    fn drops_whole_records_and_reports_loss_after_space_returns() {
        let mut buffer = BenchBuffer::<512>::new();
        let full = "x".repeat(504);
        buffer.record(format_args!("{full}\n"));
        buffer.record(format_args!("must-not-appear\n"));
        assert_eq!(buffer.dropped(), 1);
        let mut bytes = Vec::new();
        for _ in 0..16 {
            buffer.drain(64, |b| {
                bytes.push(b);
                true
            });
        }
        let text = alloc::string::String::from_utf8(bytes).unwrap();
        assert!(text.starts_with(&full));
        assert!(!text.contains("must-not"));
        assert!(text.contains("PI5_BENCH_LOG_LOSS dropped_records=1"));
    }

    #[test]
    fn oversized_format_never_leaks_a_partial_record() {
        let mut buffer = BenchBuffer::<2048>::new();
        let exact = "x".repeat(1024);
        buffer.record(format_args!("{exact}"));
        assert_eq!(buffer.dropped(), 0);
        let oversized = "z".repeat(1025);
        buffer.record(format_args!("{oversized}"));
        buffer.record(format_args!("ok\n"));
        let mut bytes = Vec::new();
        for _ in 0..32 {
            buffer.drain(64, |b| {
                bytes.push(b);
                true
            });
        }
        assert_eq!(buffer.dropped(), 1);
        assert!(!bytes.contains(&b'z'));
        assert!(bytes.windows(4).any(|w| w == b"ok\r\n"));
    }

    #[test]
    fn loss_marker_distinguishes_capacity_format_and_contention() {
        let mut buffer = BenchBuffer::<2048>::new();
        let full = "x".repeat(1024);
        buffer.record(format_args!("{full}"));
        buffer.record(format_args!("{full}"));
        buffer.record(format_args!("capacity loss\n"));
        let oversized = "z".repeat(1025);
        buffer.record(format_args!("{oversized}"));
        buffer.note_dropped(2);
        buffer.drain(64, |_| false);
        let mut bytes = Vec::new();
        for _ in 0..64 {
            buffer.drain(64, |b| {
                bytes.push(b);
                true
            });
        }
        let text = alloc::string::String::from_utf8(bytes).unwrap();
        let marker = text
            .lines()
            .find(|line| line.contains("PI5_BENCH_LOG_STATE"))
            .unwrap();
        assert!(marker.contains("full=1 format=1 contended=2"), "{marker}");
        assert!(marker.contains("high_water=2048"), "{marker}");
        assert!(marker.contains("fifo_full=1"), "{marker}");
        assert!(marker.contains("drains="), "{marker}");
        assert!(marker.contains("sent="), "{marker}");
        assert!(text.ends_with("PI5_BENCH_LOG_LOSS dropped_records=4\r\n"));
        assert!(!text.contains("capacity loss"));
        assert!(!text.contains('z'));
    }
}
