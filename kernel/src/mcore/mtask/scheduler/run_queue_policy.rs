pub const MAX_STEAL_ATTEMPTS: usize = 4;

/// Select an online victim by ordinal, excluding the local CPU.
///
/// The ordinal wraps across eligible CPUs so each dequeue probes at most
/// `MAX_STEAL_ATTEMPTS` actual queues rather than scanning empty CPU slots.
#[must_use]
pub fn victim_at(online_mask: u64, local_cpu: usize, ordinal: usize) -> Option<usize> {
    let local_bit = 1u64.checked_shl(u32::try_from(local_cpu).ok()?)?;
    let candidates = online_mask & !local_bit;
    let count = candidates.count_ones() as usize;
    if count == 0 {
        return None;
    }

    let mut remaining = ordinal % count;
    for cpu_id in 0..u64::BITS as usize {
        if candidates & (1u64 << cpu_id) == 0 {
            continue;
        }
        if remaining == 0 {
            return Some(cpu_id);
        }
        remaining -= 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_local_cpu_and_wraps_online_victims() {
        let online = (1 << 0) | (1 << 2) | (1 << 7);
        assert_eq!(victim_at(online, 2, 0), Some(0));
        assert_eq!(victim_at(online, 2, 1), Some(7));
        assert_eq!(victim_at(online, 2, 2), Some(0));
    }

    #[test]
    fn sparse_masks_probe_real_queues() {
        let online = (1 << 1) | (1 << 63);
        assert_eq!(victim_at(online, 1, 0), Some(63));
        assert_eq!(victim_at(online, 1, 99), Some(63));
    }

    #[test]
    fn returns_none_without_an_online_victim() {
        assert_eq!(victim_at(1 << 4, 4, 0), None);
        assert_eq!(victim_at(0, 4, 0), None);
        assert_eq!(victim_at(u64::MAX, 64, 0), None);
    }
}
