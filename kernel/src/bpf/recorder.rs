//! One kernel-owned audit window. Queries never take the program manager lock.
pub(crate) mod events;
use core::mem::size_of;

use kernel_abi::*;
use kernel_bpf::actuation::recorder::{Error, Record, Recorder, LINK, RECORD_CAPACITY};

struct State {
    window: Recorder<RECORD_CAPACITY>,
    frequency: u64,
    // Most recently committed negotiated audit context. Stops retain it; fresh
    // requalification clears it. Never a persistent boot ID or motion authority.
    session: u64,
    // Preserve a specific link cause through repeated generic managed stops.
    // Cleared by another stop cause or by actual controller execution.
    link_stop: Option<(u64, u32, u32)>,
}

impl State {
    const fn new() -> Self {
        Self {
            window: Recorder::new(),
            frequency: 0,
            session: 0,
            link_stop: None,
        }
    }

    fn init_clock(&mut self, frequency: u64, ticks: u64) {
        if frequency == 0 || self.frequency != 0 {
            return;
        }
        self.frequency = frequency;
        let mut record = Record {
            ticks,
            kind: LINK,
            ..Record::EMPTY
        };
        // Link payload subtype 1: physical counter initialized. This is not
        // session establishment, rearm, FPGA readiness or a sink acknowledgement.
        record.payload[..4].copy_from_slice(&1u32.to_le_bytes());
        record.payload[8..16].copy_from_slice(&frequency.to_le_bytes());
        let _ = self.window.append(record);
    }

    fn status(&self, request: ManagedAuditStatusV1) -> Result<ManagedAuditStatusV1, Errno> {
        header(
            request.version,
            request.size,
            size_of::<ManagedAuditStatusV1>(),
        )?;
        if request
            != (ManagedAuditStatusV1 {
                version: MANAGED_ADMIN_VERSION,
                size: size_of::<ManagedAuditStatusV1>() as u32,
                ..Default::default()
            })
        {
            return Err(EINVAL);
        }
        let status = self.window.status();
        let mut flags = 0;
        if self.frequency != 0 {
            flags |= MANAGED_AUDIT_CLOCK_READY;
        }
        if self.session != 0 {
            flags |= MANAGED_AUDIT_SESSION_ESTABLISHED;
        }
        if status.counters_saturated {
            flags |= MANAGED_AUDIT_COUNTERS_SATURATED;
        }
        if status.sequence_exhausted {
            flags |= MANAGED_AUDIT_SEQUENCE_EXHAUSTED;
        }
        let latest_stop = match status.latest_stop {
            Some((record, sequence)) => {
                flags |= MANAGED_AUDIT_HAS_STOP;
                if sequence.is_some() {
                    flags |= MANAGED_AUDIT_STOP_RECORDED;
                }
                record
            }
            None => Record::EMPTY,
        };
        Ok(ManagedAuditStatusV1 {
            clock_frequency: self.frequency,
            session: self.session,
            oldest: status.oldest,
            next: status.next,
            overwritten: status.overwritten,
            dropped: status.dropped,
            suppressed: status.suppressed,
            flags,
            capacity: RECORD_CAPACITY as u32,
            record_bytes: size_of::<Record>() as u32,
            latest_stop,
            ..request
        })
    }

    fn read(&self, request: ManagedAuditReadV1) -> Result<ManagedAuditReadV1, Errno> {
        header(
            request.version,
            request.size,
            size_of::<ManagedAuditReadV1>(),
        )?;
        if request
            != (ManagedAuditReadV1 {
                version: MANAGED_ADMIN_VERSION,
                size: size_of::<ManagedAuditReadV1>() as u32,
                cursor: request.cursor,
                end: request.end,
                expected_session: request.expected_session,
                ..Default::default()
            })
            || request.cursor > request.end
        {
            return Err(EINVAL);
        }
        if request.expected_session != self.session {
            return Err(ESTALE);
        }
        let batch = self
            .window
            .read_until(request.cursor, request.end)
            .map_err(|error| match error {
                Error::FutureCursor => ESTALE,
                _ => EIO,
            })?;
        Ok(ManagedAuditReadV1 {
            next_cursor: batch.next_cursor,
            gap: batch.gap,
            count: batch.count as u32,
            flags: if batch.gap != 0 {
                MANAGED_AUDIT_READ_GAP
            } else {
                0
            },
            records: batch.records,
            ..request
        })
    }
}

fn header(version: u32, size: u32, expected: usize) -> Result<(), Errno> {
    if version != MANAGED_ADMIN_VERSION {
        return Err(ENOTSUP);
    }
    if size as usize != expected {
        return Err(EINVAL);
    }
    Ok(())
}

// The array is initialized in static storage, never copied onto a kernel stack.
#[cfg(feature = "managed-runtime")]
static RECORDER: spin::Mutex<State> = spin::Mutex::new(State::new());
const _: () = assert!(size_of::<State>() <= 192 * 1024 + 256);

#[cfg(feature = "managed-runtime")]
fn with_owner<T>(f: impl FnOnce(&mut State) -> Result<T, Errno>) -> Result<T, Errno> {
    crate::mcore::context::with_interrupts_masked(|| {
        if !super::installation::qualified_topology() {
            return Err(ENOTSUP);
        }
        // Same CPU, IRQ-masked readers and writers; never wait if that invariant
        // is violated. Each query copies at most two records.
        let mut state = RECORDER.try_lock().ok_or(EBUSY)?;
        f(&mut state)
    })
}

#[cfg(all(feature = "managed-runtime", target_arch = "aarch64", feature = "rpi5"))]
pub(crate) fn init_clock(frequency: u64, ticks: u64) {
    let _ = with_owner(|state| {
        state.init_clock(frequency, ticks);
        Ok(())
    });
}

pub(crate) fn status(request: ManagedAuditStatusV1) -> Result<ManagedAuditStatusV1, Errno> {
    #[cfg(feature = "managed-runtime")]
    {
        with_owner(|state| state.status(request))
    }
    #[cfg(not(feature = "managed-runtime"))]
    {
        let _ = request;
        Err(ENOTSUP)
    }
}

pub(crate) fn read(request: ManagedAuditReadV1) -> Result<ManagedAuditReadV1, Errno> {
    #[cfg(feature = "managed-runtime")]
    {
        with_owner(|state| state.read(request))
    }
    #[cfg(not(feature = "managed-runtime"))]
    {
        let _ = request;
        Err(ENOTSUP)
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::{FromBytes, IntoBytes};

    use super::*;

    fn status_request() -> ManagedAuditStatusV1 {
        ManagedAuditStatusV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedAuditStatusV1>() as u32,
            ..Default::default()
        }
    }
    fn read_request(end: u64) -> ManagedAuditReadV1 {
        ManagedAuditReadV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedAuditReadV1>() as u32,
            end,
            ..Default::default()
        }
    }

    #[test]
    fn recorder_queries_preserve_clock_and_bound_lost_frozen_intervals() {
        let mut state = State::new();
        assert_eq!(state.status(status_request()).unwrap().flags, 0);
        state.init_clock(54_000_000, 800);
        state.init_clock(1, 900); // Never rebase a recorded time domain.
        let status = state.status(status_request()).unwrap();
        assert_eq!(
            (
                status.clock_frequency,
                status.flags,
                status.session,
                status.next
            ),
            (54_000_000, MANAGED_AUDIT_CLOCK_READY, 0, 1)
        );
        let batch = state.read(read_request(status.next)).unwrap();
        assert_eq!((batch.count, batch.next_cursor, batch.gap), (1, 1, 0));
        assert_eq!(batch.records[0].ticks, 800);
        for _ in 0..RECORD_CAPACITY {
            state
                .window
                .append(Record {
                    kind: LINK,
                    ticks: 1000,
                    ..Record::EMPTY
                })
                .unwrap();
        }
        let lost = state.read(read_request(status.next)).unwrap();
        assert_eq!(
            (lost.count, lost.next_cursor, lost.gap, lost.flags),
            (0, 1, 1, MANAGED_AUDIT_READ_GAP)
        );
        assert_eq!(lost.records, [Record::EMPTY; 2]);
        let mut stale = read_request(1);
        stale.expected_session = 1;
        assert_eq!(state.read(stale), Err(ESTALE));
    }

    #[test]
    fn recorder_requests_reject_nonzero_outputs_versions_and_lengths() {
        let state = State::new();
        let status = status_request();
        for offset in 8..size_of::<ManagedAuditStatusV1>() {
            let mut bytes = status.as_bytes().to_vec();
            bytes[offset] = 1;
            assert_eq!(
                state.status(ManagedAuditStatusV1::read_from_bytes(&bytes).unwrap()),
                Err(EINVAL)
            );
        }
        let read = read_request(0);
        for offset in 32..size_of::<ManagedAuditReadV1>() {
            let mut bytes = read.as_bytes().to_vec();
            bytes[offset] = 1;
            assert_eq!(
                state.read(ManagedAuditReadV1::read_from_bytes(&bytes).unwrap()),
                Err(EINVAL)
            );
        }
        let mut bad = status;
        bad.version += 1;
        assert_eq!(state.status(bad), Err(ENOTSUP));
        bad = status;
        bad.size -= 1;
        assert_eq!(state.status(bad), Err(EINVAL));
        assert_eq!(state.read(read_request(1)), Err(ESTALE));
    }
}
