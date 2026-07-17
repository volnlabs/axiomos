//! Pure boot-heap sizing and mapping policy.
//!
//! This module deliberately has no kernel dependencies so its 1/2/4 GiB
//! contracts can be exercised on the host without constructing page tables or
//! allocating the represented memory.

const MIB_2: usize = 2 * 1024 * 1024;
const INITIAL_HEAP_MAX: usize = 128 * 1024 * 1024;
const TOTAL_HEAP_MIN: usize = 8 * 1024 * 1024;
const TOTAL_HEAP_MAX: usize = 512 * 1024 * 1024;
const FRAME_SIZE: usize = 4 * 1024;

/// Stage 2 creates one `FrameState` byte and one `u32` refcount per 4 KiB
/// frame. Three additional bytes per frame leave bounded headroom for the
/// region vectors and allocator bookkeeping while those tables are built.
pub(crate) const EXPECTED_FRAME_METADATA_BYTES: usize = 5;
const BOOTSTRAP_HEAP_BYTES_PER_FRAME: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeapSizes {
    initial: usize,
    total: usize,
}

impl HeapSizes {
    /// Calculate heap sizes from the usable physical-memory inventory.
    pub(crate) fn from_physical_memory(usable_ram_bytes: usize) -> Self {
        let frame_count = usable_ram_bytes.div_ceil(FRAME_SIZE);
        let metadata_budget = frame_count.saturating_mul(BOOTSTRAP_HEAP_BYTES_PER_FRAME);
        let initial = metadata_budget
            .clamp(MIB_2, INITIAL_HEAP_MAX)
            .div_ceil(MIB_2)
            * MIB_2;

        // Four-CPU boot consumes just under 4 MiB before userspace begins and
        // then performs additional 512 KiB-class allocations. Preserve an
        // explicit 8 MiB floor instead of letting a 1 GiB guest run at the
        // former, already-exhausted 4 MiB total.
        let minimum_total = (initial + MIB_2).max(TOTAL_HEAP_MIN);
        let total = (usable_ram_bytes / 256)
            .clamp(minimum_total, TOTAL_HEAP_MAX)
            .div_ceil(MIB_2)
            * MIB_2;

        Self { initial, total }
    }

    pub(crate) const fn initial(self) -> usize {
        self.initial
    }

    pub(crate) const fn total(self) -> usize {
        self.total
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PageChunk {
    pub(crate) start_page: usize,
    pub(crate) page_count: usize,
}

/// Iterator that partitions a page count into bounded mapping transactions.
pub(crate) struct PageChunks {
    next_page: usize,
    remaining_pages: usize,
    max_pages: usize,
}

impl PageChunks {
    pub(crate) fn new(total_pages: usize, max_pages: usize) -> Self {
        assert!(max_pages > 0, "mapping chunk capacity must be non-zero");
        Self {
            next_page: 0,
            remaining_pages: total_pages,
            max_pages,
        }
    }
}

impl Iterator for PageChunks {
    type Item = PageChunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_pages == 0 {
            return None;
        }

        let page_count = self.remaining_pages.min(self.max_pages);
        let chunk = PageChunk {
            start_page: self.next_page,
            page_count,
        };
        self.next_page += page_count;
        self.remaining_pages -= page_count;
        Some(chunk)
    }
}

pub(crate) const fn inclusive_end_offset(byte_len: usize) -> u64 {
    assert!(byte_len > 0, "mapped byte range must be non-empty");
    byte_len as u64 - 1
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    const GIB: usize = 1024 * 1024 * 1024;
    const TRANSACTION_CAP: usize = 512;

    fn chunks_for_initial_heap(ram: usize) -> Vec<PageChunk> {
        let sizes = HeapSizes::from_physical_memory(ram);
        PageChunks::new(sizes.initial() / FRAME_SIZE, TRANSACTION_CAP).collect()
    }

    #[test]
    fn one_two_four_gib_heap_sizes_cover_frame_metadata() {
        let cases = [
            (1 * GIB, MIB_2, 4 * MIB_2),
            (2 * GIB, 2 * MIB_2, 4 * MIB_2),
            (4 * GIB, 4 * MIB_2, 8 * MIB_2),
        ];

        for (ram, expected_initial, expected_total) in cases {
            let sizes = HeapSizes::from_physical_memory(ram);
            assert_eq!(sizes.initial(), expected_initial, "ram={ram}");
            assert_eq!(sizes.total(), expected_total, "ram={ram}");

            let frames = ram / FRAME_SIZE;
            let metadata_bytes = frames * EXPECTED_FRAME_METADATA_BYTES;
            assert!(
                sizes.initial() >= metadata_bytes,
                "ram={ram}: initial heap must hold stage-2 frame metadata"
            );
        }
    }

    #[test]
    fn one_gib_total_heap_keeps_measured_smp4_headroom() {
        let sizes = HeapSizes::from_physical_memory(GIB);
        let measured_pre_userspace_working_set = 4_025 * 1024;
        let observed_follow_up_allocation = 512 * 1024;
        assert!(
            sizes.total() >= measured_pre_userspace_working_set + observed_follow_up_allocation,
            "the 1 GiB policy must not restore the exhausted 4 MiB total"
        );
        assert_eq!(sizes.total(), TOTAL_HEAP_MIN);
    }

    #[test]
    fn one_two_four_gib_bootstrap_maps_stay_within_transaction_capacity() {
        let expected_chunk_counts = [(1 * GIB, 1), (2 * GIB, 2), (4 * GIB, 4)];

        for (ram, expected_chunks) in expected_chunk_counts {
            let chunks = chunks_for_initial_heap(ram);
            assert_eq!(chunks.len(), expected_chunks, "ram={ram}");
            assert!(chunks
                .iter()
                .all(|chunk| chunk.page_count <= TRANSACTION_CAP));
            assert_eq!(chunks.first().unwrap().start_page, 0);
            for pair in chunks.windows(2) {
                assert_eq!(
                    pair[0].start_page + pair[0].page_count,
                    pair[1].start_page,
                    "chunks must cover adjacent pages without gaps"
                );
            }

            let mapped_pages: usize = chunks.iter().map(|chunk| chunk.page_count).sum();
            let sizes = HeapSizes::from_physical_memory(ram);
            assert_eq!(mapped_pages, sizes.initial() / FRAME_SIZE);
        }
    }

    #[test]
    fn stage_two_range_end_is_inclusive_without_an_extra_huge_page() {
        for ram in [1 * GIB, 2 * GIB, 4 * GIB] {
            let sizes = HeapSizes::from_physical_memory(ram);
            let extension = sizes.total() - sizes.initial();
            let mapped_huge_pages = inclusive_end_offset(extension) as usize / MIB_2 + 1;
            assert_eq!(mapped_huge_pages, extension / MIB_2, "ram={ram}");
        }
    }

    #[test]
    fn aarch64_stage_two_four_kib_maps_are_bounded_for_one_two_four_gib() {
        let expected_chunk_counts = [(1 * GIB, 3), (2 * GIB, 2), (4 * GIB, 4)];

        for (ram, expected_chunks) in expected_chunk_counts {
            let sizes = HeapSizes::from_physical_memory(ram);
            let extension_pages = (sizes.total() - sizes.initial()) / FRAME_SIZE;
            let chunks: Vec<_> = PageChunks::new(extension_pages, TRANSACTION_CAP).collect();
            assert_eq!(chunks.len(), expected_chunks, "ram={ram}");
            assert!(chunks
                .iter()
                .all(|chunk| chunk.page_count <= TRANSACTION_CAP));
            assert_eq!(
                chunks.iter().map(|chunk| chunk.page_count).sum::<usize>(),
                extension_pages,
                "ram={ram}: chunks must cover the full stage-two extension"
            );
        }
    }

    #[test]
    fn chunk_plan_handles_a_short_final_transaction() {
        let chunks: Vec<_> = PageChunks::new(513, TRANSACTION_CAP).collect();
        assert_eq!(
            chunks,
            vec![
                PageChunk {
                    start_page: 0,
                    page_count: 512,
                },
                PageChunk {
                    start_page: 512,
                    page_count: 1,
                },
            ]
        );
    }
}
