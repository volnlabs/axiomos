//! Allocation-free policy for bounded page-range transactions.

pub(crate) const TRANSACTION_CAPACITY: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MapRangePlan {
    page_count: usize,
}

impl MapRangePlan {
    pub(crate) const fn new(page_count: usize) -> Self {
        assert!(
            page_count <= TRANSACTION_CAPACITY,
            "map range exceeds stack-backed transaction capacity"
        );
        Self { page_count }
    }

    /// Frames after the frame whose map operation failed. An owned mapping
    /// releases at most one frame for each page that the transaction could
    /// still have mapped; it never drains an oversized or infinite iterator.
    pub(crate) const fn frames_after_failed_mapping(self, mapped_count: usize) -> usize {
        assert!(mapped_count < self.page_count);
        self.page_count - mapped_count - 1
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::cell::Cell;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::rc::Rc;

    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct Outcome {
        consumed_frames: usize,
        mapped_pages: usize,
        unmapped_pages: usize,
        released_frames: usize,
        failed: bool,
    }

    fn drive<I>(
        page_count: usize,
        mut frames: I,
        fail_at_page: Option<usize>,
        owned: bool,
    ) -> Outcome
    where
        I: Iterator<Item = usize>,
    {
        let plan = MapRangePlan::new(page_count);
        let mut consumed_frames = 0;
        let mut mapped_pages = 0;

        for page_index in 0..page_count {
            if frames.next().is_none() {
                return Outcome {
                    consumed_frames,
                    mapped_pages,
                    unmapped_pages: mapped_pages,
                    released_frames: usize::from(owned) * mapped_pages,
                    failed: true,
                };
            }
            consumed_frames += 1;

            if fail_at_page == Some(page_index) {
                let pending = if owned {
                    let remaining = plan.frames_after_failed_mapping(mapped_pages);
                    let drained = frames.by_ref().take(remaining).count();
                    consumed_frames += drained;
                    1 + drained
                } else {
                    0
                };
                return Outcome {
                    consumed_frames,
                    mapped_pages,
                    unmapped_pages: mapped_pages,
                    released_frames: usize::from(owned) * mapped_pages + pending,
                    failed: true,
                };
            }

            mapped_pages += 1;
        }

        Outcome {
            consumed_frames,
            mapped_pages,
            unmapped_pages: 0,
            released_frames: 0,
            failed: false,
        }
    }

    #[test]
    fn short_iterator_rolls_back_only_frames_that_were_mapped() {
        assert_eq!(
            drive(4, 0..2, None, true),
            Outcome {
                consumed_frames: 2,
                mapped_pages: 2,
                unmapped_pages: 2,
                released_frames: 2,
                failed: true,
            }
        );
    }

    #[test]
    fn oversized_iterator_is_not_drained_after_success() {
        assert_eq!(
            drive(3, 0..10, None, true),
            Outcome {
                consumed_frames: 3,
                mapped_pages: 3,
                unmapped_pages: 0,
                released_frames: 0,
                failed: false,
            }
        );
    }

    #[test]
    fn owned_failure_consumes_at_most_one_frame_per_page() {
        for fail_at_page in [0, 1, 255, 511] {
            let outcome = drive(
                TRANSACTION_CAPACITY,
                core::iter::repeat(0usize),
                Some(fail_at_page),
                true,
            );
            assert_eq!(outcome.consumed_frames, TRANSACTION_CAPACITY);
            assert_eq!(outcome.mapped_pages, fail_at_page);
            assert_eq!(outcome.unmapped_pages, fail_at_page);
            assert_eq!(outcome.released_frames, TRANSACTION_CAPACITY);
            assert!(outcome.failed);
        }
    }

    #[test]
    fn non_owned_failure_does_not_drain_or_release_frames() {
        let outcome = drive(
            TRANSACTION_CAPACITY,
            core::iter::repeat(0usize),
            Some(255),
            false,
        );
        assert_eq!(outcome.consumed_frames, 256);
        assert_eq!(outcome.mapped_pages, 255);
        assert_eq!(outcome.unmapped_pages, 255);
        assert_eq!(outcome.released_frames, 0);
        assert!(outcome.failed);
    }

    #[test]
    fn oversized_range_panics_before_consuming_a_frame() {
        let consumed = Rc::new(Cell::new(0));
        let observed = consumed.clone();
        let mut frames = core::iter::from_fn(move || {
            observed.set(observed.get() + 1);
            Some(0usize)
        });

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _plan = MapRangePlan::new(TRANSACTION_CAPACITY + 1);
            let _ = frames.next();
        }));
        assert!(result.is_err());
        assert_eq!(consumed.get(), 0);
    }
}
