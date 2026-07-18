use alloc::vec::Vec;

use kernel_bpf::execution::BpfError;

pub(super) const SLOT_BITS: u32 = 10;
pub(super) const SLOT_MASK: u32 = (1 << SLOT_BITS) - 1;
// Keep the top bit clear because userspace transports handles through c_int.
const MAX_GENERATION: u32 = (i32::MAX as u32) >> SLOT_BITS;

pub(super) const fn slot(handle: u32) -> usize {
    (handle & SLOT_MASK) as usize
}

pub(super) const fn generation(handle: u32) -> u32 {
    handle >> SLOT_BITS
}

pub(super) const fn can_reuse(generation: u32) -> bool {
    generation < MAX_GENERATION
}

pub(super) fn encode(slot: usize, generation: u32) -> u32 {
    debug_assert!(slot <= SLOT_MASK as usize);
    debug_assert!(generation <= MAX_GENERATION);
    let handle = (generation << SLOT_BITS) | slot as u32;
    debug_assert!(i32::try_from(handle).is_ok());
    handle
}

pub(super) fn decode(generations: &[u32], handle: u32) -> Option<usize> {
    let slot = slot(handle);
    (generations.get(slot).copied() == Some(generation(handle))).then_some(slot)
}

pub(super) fn insert<T>(
    slots: &mut Vec<Option<T>>,
    generations: &mut Vec<u32>,
    max_slots: usize,
    value: T,
) -> Result<u32, BpfError> {
    insert_with_reservations(
        slots,
        generations,
        max_slots,
        value,
        |slots| slots.try_reserve(1).map_err(|_| BpfError::OutOfMemory),
        |generations| {
            generations
                .try_reserve(1)
                .map_err(|_| BpfError::OutOfMemory)
        },
    )
}

fn insert_with_reservations<T>(
    slots: &mut Vec<Option<T>>,
    generations: &mut Vec<u32>,
    max_slots: usize,
    value: T,
    mut reserve_slot: impl FnMut(&mut Vec<Option<T>>) -> Result<(), BpfError>,
    mut reserve_generation: impl FnMut(&mut Vec<u32>) -> Result<(), BpfError>,
) -> Result<u32, BpfError> {
    if let Some(slot) = slots
        .iter()
        .enumerate()
        .find(|(slot, entry)| entry.is_none() && can_reuse(generations[*slot]))
        .map(|(slot, _)| slot)
    {
        let generation = generations[slot] + 1;
        generations[slot] = generation;
        slots[slot] = Some(value);
        return Ok(encode(slot, generation));
    }
    if slots.len() >= max_slots || slots.len() > SLOT_MASK as usize {
        return Err(BpfError::ResourceLimit);
    }
    // Reserve both backing vectors before publishing either half of the
    // handle-table record. A failure may grow capacity, but it cannot expose a
    // slot without a matching generation or consume `value` into the table.
    reserve_slot(slots)?;
    reserve_generation(generations)?;
    let slot = slots.len();
    slots.push(Some(value));
    generations.push(0);
    Ok(encode(slot, 0))
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::*;

    struct DropTracked<'a> {
        drops: &'a Cell<usize>,
    }

    impl Drop for DropTracked<'_> {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    #[test]
    fn stale_generation_does_not_decode_after_slot_reuse() {
        let mut slots = Vec::new();
        let mut generations = Vec::new();
        let old = insert(&mut slots, &mut generations, 1, 10).unwrap();
        slots[slot(old)] = None;
        let new = insert(&mut slots, &mut generations, 1, 20).unwrap();

        assert_ne!(old, new);
        assert_eq!(decode(&generations, old), None);
        assert_eq!(decode(&generations, new), Some(0));
    }

    #[test]
    fn slot_limit_is_enforced_before_publication() {
        let mut slots = Vec::new();
        let mut generations = Vec::new();
        insert(&mut slots, &mut generations, 1, 10).unwrap();

        assert_eq!(
            insert(&mut slots, &mut generations, 1, 20),
            Err(BpfError::ResourceLimit)
        );
        assert_eq!(slots, [Some(10)]);
        assert_eq!(generations, [0]);
    }

    #[test]
    fn append_reservation_failure_sweep_preserves_state_and_value_ownership() {
        for fail_at in 1..=2 {
            let drops = Cell::new(0usize);
            let calls = Cell::new(0usize);
            let mut slots = Vec::new();
            let mut generations = Vec::new();

            let result = insert_with_reservations(
                &mut slots,
                &mut generations,
                4,
                DropTracked { drops: &drops },
                |_| {
                    let call = calls.get() + 1;
                    calls.set(call);
                    (call != fail_at).then_some(()).ok_or(BpfError::OutOfMemory)
                },
                |_| {
                    let call = calls.get() + 1;
                    calls.set(call);
                    (call != fail_at).then_some(()).ok_or(BpfError::OutOfMemory)
                },
            );

            assert_eq!(result, Err(BpfError::OutOfMemory));
            assert!(slots.is_empty(), "failure {fail_at} published a slot");
            assert!(
                generations.is_empty(),
                "failure {fail_at} published a generation"
            );
            assert_eq!(calls.get(), fail_at);
            assert_eq!(drops.get(), 1);

            let handle = insert(
                &mut slots,
                &mut generations,
                4,
                DropTracked { drops: &drops },
            )
            .unwrap();
            assert_eq!(decode(&generations, handle), Some(0));
            drop(slots);
            assert_eq!(drops.get(), 2);
        }
    }
}
