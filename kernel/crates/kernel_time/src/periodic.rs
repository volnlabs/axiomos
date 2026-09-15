//! Absolute periodic releases in a caller-supplied monotonic tick domain.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseError {
    InvalidPeriod,
    ClockReversed,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReleaseStats {
    pub serviced: u64,
    pub missed: u64,
    pub late: u64,
    /// Delay from the first outstanding deadline, including skipped releases.
    pub max_wake_lateness: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeriodicRelease {
    pub sequence: u64,
    pub scheduled: u64,
    pub deadline: u64,
    pub actual: u64,
    pub missed_before: u64,
    pub wake_lateness: u64,
}

impl PeriodicRelease {
    pub const fn completed_in_time(self, now: u64) -> bool {
        now >= self.actual && now < self.deadline
    }
}

/// Advances on a fixed grid, returning at most the latest due release per poll.
/// Counter exhaustion and reversed clocks reject without changing the schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeriodicSchedule {
    period: u64,
    next_deadline: u64,
    next_sequence: u64,
    last_seen: u64,
    stats: ReleaseStats,
}

impl PeriodicSchedule {
    pub fn new(start: u64, period: u64) -> Result<Self, ReleaseError> {
        if period == 0 {
            return Err(ReleaseError::InvalidPeriod);
        }
        Ok(Self {
            period,
            next_deadline: start.checked_add(period).ok_or(ReleaseError::Exhausted)?,
            next_sequence: 1,
            last_seen: start,
            stats: ReleaseStats::default(),
        })
    }

    pub const fn next_deadline(&self) -> u64 {
        self.next_deadline
    }

    pub const fn stats(&self) -> ReleaseStats {
        self.stats
    }

    pub fn release(&mut self, now: u64) -> Result<Option<PeriodicRelease>, ReleaseError> {
        if now < self.last_seen {
            return Err(ReleaseError::ClockReversed);
        }
        if now < self.next_deadline {
            self.last_seen = now;
            return Ok(None);
        }
        let wake_lateness = now - self.next_deadline;
        let missed_before = wake_lateness / self.period;
        // Subtraction avoids multiplying the missed count and preserves the grid.
        let scheduled = now - wake_lateness % self.period;
        let deadline = scheduled
            .checked_add(self.period)
            .ok_or(ReleaseError::Exhausted)?;
        let sequence = self
            .next_sequence
            .checked_add(missed_before)
            .ok_or(ReleaseError::Exhausted)?;
        let next_sequence = sequence.checked_add(1).ok_or(ReleaseError::Exhausted)?;
        let stats = ReleaseStats {
            serviced: self
                .stats
                .serviced
                .checked_add(1)
                .ok_or(ReleaseError::Exhausted)?,
            missed: self
                .stats
                .missed
                .checked_add(missed_before)
                .ok_or(ReleaseError::Exhausted)?,
            late: self
                .stats
                .late
                .checked_add(u64::from(wake_lateness != 0))
                .ok_or(ReleaseError::Exhausted)?,
            max_wake_lateness: self.stats.max_wake_lateness.max(wake_lateness),
        };
        self.next_deadline = deadline;
        self.next_sequence = next_sequence;
        self.last_seen = now;
        self.stats = stats;
        Ok(Some(PeriodicRelease {
            sequence,
            scheduled,
            deadline,
            actual: now,
            missed_before,
            wake_lateness,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_releases_account_for_gaps_without_catch_up() {
        let mut clock = PeriodicSchedule::new(100, 10).unwrap();
        assert_eq!(clock.release(109).unwrap(), None);
        let first = clock.release(115).unwrap().unwrap();
        assert_eq!(
            (first.sequence, first.scheduled, first.deadline),
            (1, 110, 120)
        );
        assert_eq!(
            (first.actual, first.missed_before, first.wake_lateness),
            (115, 0, 5)
        );
        assert!(first.completed_in_time(119));
        assert!(!first.completed_in_time(120));
        assert!(!first.completed_in_time(114));
        assert_eq!(clock.next_deadline(), 120);

        let late = clock.release(145).unwrap().unwrap();
        assert_eq!(
            (late.sequence, late.scheduled, late.deadline),
            (4, 140, 150)
        );
        assert_eq!((late.missed_before, late.wake_lateness), (2, 25));
        assert_eq!(clock.release(145).unwrap(), None);
        assert_eq!(clock.release(149).unwrap(), None);
        assert_eq!(clock.release(150).unwrap().unwrap().sequence, 5);
        assert_eq!(
            clock.stats(),
            ReleaseStats {
                serviced: 3,
                missed: 2,
                late: 2,
                max_wake_lateness: 25,
            }
        );
    }

    #[test]
    fn long_masked_interval_cannot_look_like_a_passing_schedule() {
        let mut clock = PeriodicSchedule::new(0, 10_000_000).unwrap();
        let first = clock.release(10_000_000).unwrap().unwrap();
        assert!(!first.completed_in_time(20_000_000));
        let resumed = clock.release(1_000_000_000).unwrap().unwrap();
        assert_eq!((resumed.sequence, resumed.missed_before), (100, 98));
        assert_eq!(clock.stats().serviced + clock.stats().missed, 100);
        assert_eq!(clock.next_deadline(), 1_010_000_000);
        assert_eq!(clock.release(1_000_000_000).unwrap(), None);
    }

    #[test]
    fn invalid_clock_and_counter_exhaustion_reject_before_mutation() {
        assert_eq!(
            PeriodicSchedule::new(0, 0),
            Err(ReleaseError::InvalidPeriod)
        );
        assert_eq!(
            PeriodicSchedule::new(u64::MAX, 1),
            Err(ReleaseError::Exhausted)
        );
        let mut clock = PeriodicSchedule::new(100, 10).unwrap();
        let original = clock;
        assert_eq!(clock.release(99), Err(ReleaseError::ClockReversed));
        assert_eq!(clock, original);
        clock.next_sequence = u64::MAX;
        let original = clock;
        assert_eq!(clock.release(110), Err(ReleaseError::Exhausted));
        assert_eq!(clock, original);
        let mut end = PeriodicSchedule::new(u64::MAX - 1, 1).unwrap();
        let original = end;
        assert_eq!(end.release(u64::MAX), Err(ReleaseError::Exhausted));
        assert_eq!(end, original);
    }
}
