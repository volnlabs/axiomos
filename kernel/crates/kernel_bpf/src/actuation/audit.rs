use core::sync::atomic::{AtomicU64, Ordering};

use super::{ActuationKind, Authority, ChannelId, RejectReason};

/// Trusted source attribution stamped by kernel call-sites for audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditSource {
    Operator,
    Watchdog,
    GpioHook,
    LearnedBehavior,
    Mission,
    SyscallPwm,
}

/// Audit reason code shape shared by governance and ARM-A decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    None,
    UnknownChannel,
    Governance,
}

impl From<RejectReason> for ReasonCode {
    fn from(reason: RejectReason) -> Self {
        match reason {
            RejectReason::UnknownChannel => ReasonCode::UnknownChannel,
        }
    }
}

/// Compact decision tag for fixed-size audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionTag {
    Allow,
    Clamp,
    Safe,
    Reject,
    EstopTrigger,
    EstopRelease,
    ReleaseDenied,
}

pub(super) const EMPTY_CHANNEL: ChannelId = ChannelId {
    kind: ActuationKind::PwmDuty,
    chip: 0,
    channel: 0,
};

/// Fixed-size audit record emitted by the actuation monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub t_ns: u64,
    pub source: AuditSource,
    pub channel: ChannelId,
    pub authority: Authority,
    pub req_value: u32,
    pub decision: DecisionTag,
    pub reason: ReasonCode,
}

impl AuditRecord {
    pub const EMPTY: Self = Self {
        seq: 0,
        t_ns: 0,
        source: AuditSource::LearnedBehavior,
        channel: EMPTY_CHANNEL,
        authority: Authority::Learned,
        req_value: 0,
        decision: DecisionTag::Allow,
        reason: ReasonCode::None,
    };
}

pub struct AuditSlot {
    seq: AtomicU64,
    body: AuditRecord,
}

impl AuditSlot {
    pub const fn new() -> Self {
        Self {
            seq: AtomicU64::new(u64::MAX),
            body: AuditRecord::EMPTY,
        }
    }
}

impl Default for AuditSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Single-writer, overwrite-oldest audit ring.
pub struct AuditRing<const N: usize> {
    buf: [AuditSlot; N],
    head: AtomicU64,
}

impl<const N: usize> AuditRing<N> {
    pub const fn new() -> Self {
        Self {
            buf: [const { AuditSlot::new() }; N],
            head: AtomicU64::new(0),
        }
    }

    pub fn emit(&mut self, mut record: AuditRecord) {
        let seq = self.head.load(Ordering::Relaxed);
        record.seq = seq;
        if N > 0 {
            let idx = (seq as usize) % N;
            self.buf[idx].body = record;
            self.buf[idx].seq.store(seq, Ordering::Release);
        }
        self.head.store(seq.wrapping_add(1), Ordering::Release);
    }

    pub fn snapshot(&self, out: &mut [AuditRecord]) -> usize {
        if N == 0 || out.is_empty() {
            return 0;
        }

        let head = self.head.load(Ordering::Acquire);
        let start = head.saturating_sub(N as u64);
        let mut copied = 0;

        for seq in start..head {
            if copied == out.len() {
                break;
            }
            let idx = (seq as usize) % N;
            let slot = &self.buf[idx];
            let before = slot.seq.load(Ordering::Acquire);
            if before != seq {
                continue;
            }
            let body = slot.body;
            let after = slot.seq.load(Ordering::Acquire);
            if before == after && body.seq == seq {
                out[copied] = body;
                copied += 1;
            }
        }

        copied
    }

    pub fn dropped_since(&self, last_seq: u64) -> u64 {
        let head = self.head.load(Ordering::Acquire);
        let oldest_live = head.saturating_sub(N as u64);
        oldest_live.saturating_sub(last_seq)
    }
}

impl<const N: usize> Default for AuditRing<N> {
    fn default() -> Self {
        Self::new()
    }
}
