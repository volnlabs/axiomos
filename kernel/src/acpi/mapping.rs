const PAGE_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MappingPlan {
    pub physical_base: usize,
    pub offset: usize,
    pub page_count: usize,
    pub mapped_len: usize,
}

pub(crate) fn plan_mapping(
    physical_address: usize,
    requested_len: usize,
    type_len: usize,
) -> Option<MappingPlan> {
    let required_len = requested_len.max(type_len);
    if required_len == 0 {
        return None;
    }

    let offset = physical_address & (PAGE_SIZE - 1);
    let covered_len = offset.checked_add(required_len)?;
    let page_count = covered_len.checked_add(PAGE_SIZE - 1)? / PAGE_SIZE;
    let mapped_len = page_count.checked_mul(PAGE_SIZE)?;
    let physical_base = physical_address.checked_sub(offset)?;
    physical_base.checked_add(mapped_len)?;

    Some(MappingPlan {
        physical_base,
        offset,
        page_count,
        mapped_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_region_uses_one_page() {
        assert_eq!(
            plan_mapping(0x2000, 64, 16),
            Some(MappingPlan {
                physical_base: 0x2000,
                offset: 0,
                page_count: 1,
                mapped_len: PAGE_SIZE,
            })
        );
    }

    #[test]
    fn unaligned_region_returns_offset_and_covers_crossing_page() {
        assert_eq!(
            plan_mapping(0x2ff0, 32, 16),
            Some(MappingPlan {
                physical_base: 0x2000,
                offset: 0xff0,
                page_count: 2,
                mapped_len: 2 * PAGE_SIZE,
            })
        );
    }

    #[test]
    fn type_size_is_covered_when_larger_than_requested_length() {
        assert_eq!(plan_mapping(0x3ff8, 4, 16).unwrap().page_count, 2);
    }

    #[test]
    fn zero_length_and_overflow_are_rejected() {
        assert_eq!(plan_mapping(0x1000, 0, 0), None);
        assert_eq!(plan_mapping(usize::MAX - 3, 8, 1), None);
    }
}
