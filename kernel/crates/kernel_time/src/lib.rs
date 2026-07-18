//! Architecture-independent clock conversion helpers.

#![no_std]

/// Number of femtoseconds in one nanosecond.
pub const FEMTOSECONDS_PER_NANOSECOND: u128 = 1_000_000;

/// Number of nanoseconds in one second.
pub const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// One item in an ordered deadline queue.
#[derive(Debug, Eq, PartialEq)]
pub struct DeadlineEntry<T> {
    deadline_ns: u64,
    sequence: u64,
    value: T,
}

impl<T> DeadlineEntry<T> {
    #[must_use]
    pub const fn deadline_ns(&self) -> u64 {
        self.deadline_ns
    }

    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }

    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }
}

/// Fixed-capacity queue ordered by monotonic deadline.
///
/// Storage is reserved inside the queue, so insertion, expiry, and cancellation
/// never allocate. Items with the same deadline retain insertion order.
#[derive(Debug)]
pub struct DeadlineQueue<T, const N: usize> {
    entries: [Option<DeadlineEntry<T>>; N],
    len: usize,
    next_sequence: u64,
}

impl<T, const N: usize> DeadlineQueue<T, N> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            len: 0,
            next_sequence: 0,
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn next_deadline_ns(&self) -> Option<u64> {
        self.entries
            .first()
            .and_then(Option::as_ref)
            .map(DeadlineEntry::deadline_ns)
    }

    /// Insert an item by deadline, returning the item unchanged when full.
    pub fn push(&mut self, deadline_ns: u64, value: T) -> Result<(), T> {
        if self.len == N {
            return Err(value);
        }

        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.entries[self.len] = Some(DeadlineEntry {
            deadline_ns,
            sequence,
            value,
        });
        self.len += 1;
        self.sift_up(self.len - 1);
        Ok(())
    }

    /// Remove the earliest item when its deadline has elapsed.
    pub fn pop_expired(&mut self, now_ns: u64) -> Option<DeadlineEntry<T>> {
        if self
            .next_deadline_ns()
            .is_some_and(|deadline| deadline <= now_ns)
        {
            self.remove_at(0)
        } else {
            None
        }
    }

    /// Remove the first item matching `predicate`.
    pub fn cancel(
        &mut self,
        mut predicate: impl FnMut(&DeadlineEntry<T>) -> bool,
    ) -> Option<DeadlineEntry<T>> {
        let index = (0..self.len).find(|index| {
            predicate(
                self.entries[*index]
                    .as_ref()
                    .expect("occupied deadline queue prefix"),
            )
        })?;
        self.remove_at(index)
    }

    fn remove_at(&mut self, index: usize) -> Option<DeadlineEntry<T>> {
        if index >= self.len {
            return None;
        }

        let removed = self.entries[index].take();
        self.len -= 1;
        if index != self.len {
            self.entries[index] = self.entries[self.len].take();
            let parent = index.saturating_sub(1) / 2;
            if index > 0 && self.entry_precedes(index, parent) {
                self.sift_up(index);
            } else {
                self.sift_down(index);
            }
        } else {
            self.entries[self.len] = None;
        }
        removed
    }

    fn entry_precedes(&self, left: usize, right: usize) -> bool {
        let left = self.entries[left]
            .as_ref()
            .expect("occupied deadline heap prefix");
        let right = self.entries[right]
            .as_ref()
            .expect("occupied deadline heap prefix");
        (left.deadline_ns, left.sequence) < (right.deadline_ns, right.sequence)
    }

    fn sift_up(&mut self, mut index: usize) {
        while index > 0 {
            let parent = (index - 1) / 2;
            if !self.entry_precedes(index, parent) {
                break;
            }
            self.entries.swap(index, parent);
            index = parent;
        }
    }

    fn sift_down(&mut self, mut index: usize) {
        loop {
            let left = index * 2 + 1;
            if left >= self.len {
                break;
            }
            let right = left + 1;
            let child = if right < self.len && self.entry_precedes(right, left) {
                right
            } else {
                left
            };
            if !self.entry_precedes(child, index) {
                break;
            }
            self.entries.swap(index, child);
            index = child;
        }
    }
}

impl<T, const N: usize> Default for DeadlineQueue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a hardware counter with a period expressed in femtoseconds to
/// nanoseconds, saturating only when the result cannot fit in `u64`.
#[must_use]
pub const fn femtosecond_ticks_to_nanoseconds(ticks: u64, period_femtoseconds: u32) -> u64 {
    saturating_u128_to_u64(
        (ticks as u128 * period_femtoseconds as u128) / FEMTOSECONDS_PER_NANOSECOND,
    )
}

/// Convert a fixed-frequency counter to nanoseconds without overflowing the
/// intermediate multiplication.
#[must_use]
pub const fn frequency_ticks_to_nanoseconds(ticks: u64, frequency_hz: u64) -> Option<u64> {
    if frequency_hz == 0 {
        return None;
    }

    Some(saturating_u128_to_u64(
        (ticks as u128 * NANOSECONDS_PER_SECOND as u128) / frequency_hz as u128,
    ))
}

/// Validate a POSIX-style `(seconds, nanoseconds)` pair and convert it to a
/// duration. Negative values, non-normalized nanoseconds, and overflow are
/// rejected.
#[must_use]
pub const fn timespec_to_duration_nanoseconds(seconds: i64, nanoseconds: i64) -> Option<u64> {
    if seconds < 0 || nanoseconds < 0 || nanoseconds >= NANOSECONDS_PER_SECOND as i64 {
        return None;
    }

    let seconds = seconds as u64;
    let nanoseconds = nanoseconds as u64;
    match seconds.checked_mul(NANOSECONDS_PER_SECOND) {
        Some(value) => value.checked_add(nanoseconds),
        None => None,
    }
}

const fn saturating_u128_to_u64(value: u128) -> u64 {
    if value > u64::MAX as u128 {
        u64::MAX
    } else {
        value as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpet_period_conversion_has_correct_units() {
        // A 100 ns HPET period is reported as 100,000,000 femtoseconds.
        assert_eq!(femtosecond_ticks_to_nanoseconds(10, 100_000_000), 1_000);
    }

    #[test]
    fn frequency_conversion_handles_fractional_seconds() {
        assert_eq!(
            frequency_ticks_to_nanoseconds(37_500_000, 50_000_000),
            Some(750_000_000)
        );
    }

    #[test]
    fn frequency_conversion_rejects_zero_frequency() {
        assert_eq!(frequency_ticks_to_nanoseconds(1, 0), None);
    }

    #[test]
    fn conversions_do_not_overflow_intermediate_values() {
        assert_eq!(
            femtosecond_ticks_to_nanoseconds(u64::MAX, u32::MAX),
            u64::MAX
        );
        assert_eq!(frequency_ticks_to_nanoseconds(u64::MAX, 1), Some(u64::MAX));
    }

    #[test]
    fn conversions_are_monotonic() {
        let period = 100_000_000;
        for ticks in 0..10_000 {
            assert!(
                femtosecond_ticks_to_nanoseconds(ticks, period)
                    <= femtosecond_ticks_to_nanoseconds(ticks + 1, period)
            );
        }
    }

    #[test]
    fn timespec_validation_rejects_negative_and_non_normalized_values() {
        assert_eq!(timespec_to_duration_nanoseconds(-1, 0), None);
        assert_eq!(timespec_to_duration_nanoseconds(0, -1), None);
        assert_eq!(
            timespec_to_duration_nanoseconds(0, NANOSECONDS_PER_SECOND as i64),
            None
        );
    }

    #[test]
    fn timespec_conversion_checks_overflow() {
        assert_eq!(
            timespec_to_duration_nanoseconds(2, 500_000_000),
            Some(2_500_000_000)
        );
        assert_eq!(timespec_to_duration_nanoseconds(i64::MAX, 0), None);
    }

    #[test]
    fn deadline_queue_orders_concurrent_sleepers_and_preserves_ties() {
        let mut queue = DeadlineQueue::<u8, 5>::new();
        queue.push(30, 3).unwrap();
        queue.push(10, 1).unwrap();
        queue.push(20, 2).unwrap();
        queue.push(20, 4).unwrap();

        assert_eq!(queue.next_deadline_ns(), Some(10));
        assert_eq!(queue.pop_expired(9), None);
        assert_eq!(
            queue.pop_expired(10).map(DeadlineEntry::into_value),
            Some(1)
        );
        assert_eq!(
            queue.pop_expired(20).map(DeadlineEntry::into_value),
            Some(2)
        );
        assert_eq!(
            queue.pop_expired(20).map(DeadlineEntry::into_value),
            Some(4)
        );
        assert_eq!(
            queue.pop_expired(30).map(DeadlineEntry::into_value),
            Some(3)
        );
        assert!(queue.is_empty());
    }

    #[test]
    fn deadline_queue_cancellation_removes_only_the_requested_sleeper() {
        let mut queue = DeadlineQueue::<u8, 4>::new();
        queue.push(10, 1).unwrap();
        queue.push(20, 2).unwrap();
        queue.push(30, 3).unwrap();

        let cancelled = queue.cancel(|entry| *entry.value() == 2).unwrap();
        assert_eq!(cancelled.deadline_ns(), 20);
        assert_eq!(cancelled.into_value(), 2);
        assert_eq!(queue.len(), 2);
        assert_eq!(
            queue.pop_expired(30).map(DeadlineEntry::into_value),
            Some(1)
        );
        assert_eq!(
            queue.pop_expired(30).map(DeadlineEntry::into_value),
            Some(3)
        );
    }

    #[test]
    fn deadline_queue_capacity_failure_returns_ownership() {
        let mut queue = DeadlineQueue::<u8, 1>::new();
        queue.push(10, 1).unwrap();

        assert_eq!(queue.push(20, 2), Err(2));
        assert_eq!(queue.len(), 1);
    }
}
