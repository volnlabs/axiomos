//! Bounded runtime audit storage. The kernel owner must serialize append/read;
//! this core neither masks IRQs nor performs I/O. Wire payload schemas and event
//! producers are separate from retention, and are not inferred from these bytes.

pub use kernel_abi::{
    MANAGED_AUDIT_ARTIFACT as ARTIFACT, MANAGED_AUDIT_CYCLE as CYCLE, MANAGED_AUDIT_LINK as LINK,
    MANAGED_AUDIT_OPERATION as OPERATION, MANAGED_AUDIT_READ_RECORDS as READ_RECORDS,
    MANAGED_AUDIT_RECORDS as RECORD_CAPACITY, MANAGED_AUDIT_STOP as STOP,
    ManagedAuditRecordV1 as Record,
};

const _: () = assert!(core::mem::size_of::<Record>() == 96);
const _: () = assert!(core::mem::size_of::<[Record; RECORD_CAPACITY]>() == 192 * 1024);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRecord,
    CorruptRecord,
    SequenceExhausted,
    FutureCursor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// Inclusive oldest retained sequence and exclusive next sequence.
    pub oldest: u64,
    pub next: u64,
    pub overwritten: u64,
    /// Rejected append attempts, separate from deliberately suppressed repeats.
    pub dropped: u64,
    pub suppressed: u64,
    pub counters_saturated: bool,
    pub sequence_exhausted: bool,
    /// Survives ring overwrite. Its sequence is None if it could not be recorded.
    pub latest_stop: Option<(Record, Option<u64>)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadBatch {
    pub records: [Record; READ_RECORDS],
    pub count: usize,
    pub next_cursor: u64,
    /// Exact missing sequence count before this batch, including interrupted export.
    pub gap: u64,
}

/// One fixed array plus bounded scalar metadata and an independent stop summary.
/// Const capacity follows the existing AuditRing convention. Kernel integration
/// must select RECORD_CAPACITY and initialize storage before managed execution.
pub struct Recorder<const N: usize> {
    records: [Record; N],
    status: Status,
    stopped: bool,
}

// Latest-stop custody and all counters are bounded separately from the 192 KiB window.
const _: () = assert!(core::mem::size_of::<Recorder<RECORD_CAPACITY>>() <= 192 * 1024 + 256);

impl<const N: usize> Recorder<N> {
    pub const fn new() -> Self {
        assert!(N != 0);
        Self {
            records: [Record::EMPTY; N],
            stopped: false,
            status: Status {
                oldest: 0,
                next: 0,
                overwritten: 0,
                dropped: 0,
                suppressed: 0,
                counters_saturated: false,
                sequence_exhausted: false,
                latest_stop: None,
            },
        }
    }

    pub fn status(&self) -> Status {
        self.status
    }

    /// Called when trusted execution leaves the stopped state. Does not erase
    /// the latest-stop summary or grant execution/rearm permission.
    pub fn leave_stopped_state(&mut self) {
        self.stopped = false;
    }

    /// Account for an unchanged inhibited cycle without overwriting the audit
    /// window or replacing the authoritative stop cause with passive state.
    pub fn suppress_unchanged(&mut self) {
        count(
            &mut self.status.suppressed,
            &mut self.status.counters_saturated,
        );
    }

    /// None denotes a repeated, unchanged stop. Callers must not make control
    /// or activation success depend on this result.
    pub fn append(&mut self, mut record: Record) -> Result<Option<u64>, Error> {
        if !valid(&record) {
            count(
                &mut self.status.dropped,
                &mut self.status.counters_saturated,
            );
            return Err(Error::InvalidRecord);
        }
        if record.kind == STOP {
            if self.stopped
                && self.status.latest_stop.is_some_and(|(previous, _)| {
                    previous.correlation == record.correlation && previous.payload == record.payload
                })
            {
                self.suppress_unchanged();
                return Ok(None);
            }
            // Authoritative even if sequence exhaustion prevents ring insertion.
            record.sequence = 0;
            self.status.latest_stop = Some((record, None));
            self.stopped = true;
        }
        let Some(next) = self.status.next.checked_add(1) else {
            self.status.sequence_exhausted = true;
            count(
                &mut self.status.dropped,
                &mut self.status.counters_saturated,
            );
            return Err(Error::SequenceExhausted);
        };
        let sequence = self.status.next;
        record.sequence = sequence;
        self.records[(sequence % N as u64) as usize] = record;
        self.status.next = next;
        self.status.oldest = next.saturating_sub(N as u64);
        self.status.overwritten = self.status.oldest;
        // The exclusive end cannot represent one more record after MAX - 1.
        self.status.sequence_exhausted = next == u64::MAX;
        if record.kind == STOP {
            self.status.latest_stop = Some((record, Some(sequence)));
        }
        Ok(Some(sequence))
    }

    /// At most two copies; a cursor denotes the next unread sequence, including
    /// cursor zero. Overwrite never silently advances the caller's cursor.
    pub fn read(&self, cursor: u64) -> Result<ReadBatch, Error> {
        self.read_until(cursor, self.status.next)
    }

    /// Read a frozen export interval even while new records arrive. If that
    /// entire interval was overwritten, return its exact gap and no newer data.
    pub fn read_until(&self, cursor: u64, end: u64) -> Result<ReadBatch, Error> {
        if cursor > end || end > self.status.next {
            return Err(Error::FutureCursor);
        }
        let start = cursor.max(self.status.oldest).min(end);
        let count = (end - start).min(READ_RECORDS as u64) as usize;
        let mut batch = ReadBatch {
            records: [Record::EMPTY; READ_RECORDS],
            count,
            next_cursor: start + count as u64,
            gap: start - cursor,
        };
        for (offset, output) in batch.records[..count].iter_mut().enumerate() {
            let sequence = start + offset as u64;
            let record = self.records[(sequence % N as u64) as usize];
            if record.sequence != sequence || !valid(&record) {
                return Err(Error::CorruptRecord);
            }
            *output = record;
        }
        Ok(batch)
    }
}

fn valid(record: &Record) -> bool {
    (ARTIFACT..=LINK).contains(&record.kind) && record.reserved == 0
}

fn count(value: &mut u64, saturated: &mut bool) {
    if let Some(next) = value.checked_add(1) {
        *value = next;
    } else {
        *saturated = true;
    }
}

impl<const N: usize> Default for Recorder<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: u32, ticks: u64, correlation: u64) -> Record {
        Record {
            kind,
            ticks,
            correlation,
            ..Record::EMPTY
        }
    }

    #[test]
    fn overwrite_and_interrupted_export_report_exact_cursor_gaps() {
        let mut recorder = Recorder::<3>::new();
        assert_eq!(recorder.read(0).unwrap().count, 0);
        for i in 0..3 {
            assert_eq!(recorder.append(event(CYCLE, 100 + i, i)), Ok(Some(i)));
        }
        let first = recorder.read(0).unwrap();
        assert_eq!(first.count, 2);
        assert_eq!(first.next_cursor, 2);
        assert_eq!(first.gap, 0);
        assert_eq!(first.records[0].correlation, 0);
        for i in 3..7 {
            recorder.append(event(CYCLE, 100 + i, i)).unwrap();
        }
        let resumed = recorder.read(first.next_cursor).unwrap();
        assert_eq!((resumed.gap, resumed.count, resumed.next_cursor), (2, 2, 6));
        assert_eq!(resumed.records[0].sequence, 4);
        assert_eq!(resumed.records[1].sequence, 5);
        let final_batch = recorder.read(6).unwrap();
        assert_eq!(
            (final_batch.count, final_batch.next_cursor, final_batch.gap),
            (1, 7, 0)
        );
        assert_eq!(final_batch.records[1], Record::EMPTY);
        assert_eq!(recorder.read(8), Err(Error::FutureCursor));
        assert_eq!(
            (
                recorder.status().oldest,
                recorder.status().next,
                recorder.status().overwritten
            ),
            (4, 7, 4)
        );
    }

    #[test]
    fn frozen_export_never_reads_beyond_its_original_end() {
        let mut recorder = Recorder::<3>::new();
        for i in 0..3 {
            recorder.append(event(CYCLE, i, i)).unwrap();
        }
        let end = recorder.status().next;
        recorder.append(event(CYCLE, 3, 3)).unwrap();
        let page = recorder.read_until(2, end).unwrap();
        assert_eq!((page.count, page.next_cursor, page.gap), (1, 3, 0));
        assert_eq!(page.records[0].sequence, 2);
        for i in 4..8 {
            recorder.append(event(CYCLE, i, i)).unwrap();
        }
        let lost = recorder.read_until(1, end).unwrap();
        assert_eq!((lost.count, lost.next_cursor, lost.gap), (0, 3, 2));
        assert_eq!(lost.records, [Record::EMPTY; 2]);
        assert_eq!(recorder.read_until(4, 3), Err(Error::FutureCursor));
        assert_eq!(recorder.read_until(0, 9), Err(Error::FutureCursor));
    }

    #[test]
    fn latest_stop_survives_wrap_and_repeats_do_not_consume_records() {
        let mut recorder = Recorder::<2>::new();
        let stop = event(STOP, 10, 42);
        assert_eq!(recorder.append(stop), Ok(Some(0)));
        assert_eq!(recorder.append(event(STOP, 11, 42)), Ok(None));
        recorder.append(event(CYCLE, 12, 42)).unwrap();
        recorder.append(event(CYCLE, 13, 42)).unwrap();
        let (latest, sequence) = recorder.status().latest_stop.unwrap();
        assert_eq!((latest.ticks, sequence), (10, Some(0)));
        assert_eq!(recorder.status().suppressed, 1);
        assert_eq!(recorder.status().dropped, 0);
        let mut changed = event(STOP, 14, 42);
        changed.payload[0] = 1;
        assert_eq!(recorder.append(changed), Ok(Some(3)));
        assert_eq!(recorder.status().latest_stop.unwrap().0.payload[0], 1);
        recorder.leave_stopped_state();
        assert_eq!(recorder.append(changed), Ok(Some(4)));
    }

    #[test]
    fn malformed_input_and_exhaustion_preserve_retained_data_and_latest_stop() {
        let mut recorder = Recorder::<2>::new();
        recorder.append(event(CYCLE, 1, 1)).unwrap();
        let retained = recorder.read(0).unwrap();
        for bad in [
            Record::EMPTY,
            Record {
                reserved: 1,
                ..event(STOP, 2, 1)
            },
        ] {
            assert_eq!(recorder.append(bad), Err(Error::InvalidRecord));
        }
        assert_eq!(recorder.read(0).unwrap(), retained);
        assert_eq!(recorder.status().dropped, 2);
        assert!(recorder.status().latest_stop.is_none());

        // Force the same valid final two-record state as a long-running recorder.
        recorder.status.next = u64::MAX - 1;
        recorder.status.oldest = u64::MAX - 3;
        recorder.status.overwritten = recorder.status.oldest;
        for offset in 0..2 {
            let sequence = recorder.status.oldest + offset;
            recorder.records[(sequence % 2) as usize] = Record {
                sequence,
                ..event(CYCLE, 1, 1)
            };
        }
        assert_eq!(recorder.append(event(CYCLE, 3, 1)), Ok(Some(u64::MAX - 1)));
        let final_records = recorder.read(u64::MAX - 2).unwrap();
        assert_eq!(
            (final_records.count, final_records.next_cursor),
            (2, u64::MAX)
        );
        let before = recorder.status();
        assert_eq!(
            recorder.append(event(STOP, 4, 2)),
            Err(Error::SequenceExhausted)
        );
        assert_eq!(recorder.status().next, u64::MAX);
        assert_eq!(recorder.status().oldest, before.oldest);
        assert_eq!(recorder.read(before.oldest).unwrap(), final_records);
        assert!(recorder.status().sequence_exhausted);
        let (latest, sequence) = recorder.status().latest_stop.unwrap();
        assert_eq!((latest.ticks, latest.correlation, sequence), (4, 2, None));
        recorder.status.dropped = u64::MAX;
        assert_eq!(
            recorder.append(event(CYCLE, 5, 2)),
            Err(Error::SequenceExhausted)
        );
        assert_eq!(recorder.status().dropped, u64::MAX);
        assert!(recorder.status().counters_saturated);
        let mut suppressed = Recorder::<1>::new();
        suppressed.status.suppressed = u64::MAX;
        suppressed.suppress_unchanged();
        assert_eq!(suppressed.status().suppressed, u64::MAX);
        assert!(suppressed.status().counters_saturated);
        assert_eq!(suppressed.status().next, 0);
    }

    #[test]
    fn corrupt_or_reordered_slots_never_export_as_valid_records() {
        let mut recorder = Recorder::<2>::new();
        recorder.append(event(CYCLE, 1, 1)).unwrap();
        recorder.append(event(CYCLE, 2, 2)).unwrap();
        recorder.records.swap(0, 1);
        assert_eq!(recorder.read(0), Err(Error::CorruptRecord));
        recorder.records.swap(0, 1);
        recorder.records[1].reserved = 1;
        assert_eq!(recorder.read(0), Err(Error::CorruptRecord));
    }
}
