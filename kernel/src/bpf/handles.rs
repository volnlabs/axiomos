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
    slots.try_reserve(1).map_err(|_| BpfError::OutOfMemory)?;
    generations
        .try_reserve(1)
        .map_err(|_| BpfError::OutOfMemory)?;
    let slot = slots.len();
    slots.push(Some(value));
    generations.push(0);
    Ok(encode(slot, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
