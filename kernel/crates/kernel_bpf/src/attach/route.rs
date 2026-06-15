//! GPIO attachment routing: maps a fired `(chip, pin, edge)` to the programs
//! attached for it, so each GPIO program runs only for its own pin and edge
//! (rising and falling attach independently; distinct pins never cross-fire).
//!
//! Pure (no MMIO) so the selection logic is host-tested.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::GpioEdge;

/// A table of GPIO attachments keyed by `(chip, pin)`, each holding the
/// `(edge, prog_id)` pairs attached there.
#[derive(Debug, Default)]
pub struct GpioRouteTable {
    routes: BTreeMap<(u8, u8), Vec<(GpioEdge, u32)>>,
}

impl GpioRouteTable {
    pub const fn new() -> Self {
        Self { routes: BTreeMap::new() }
    }

    /// Record that `prog_id` is attached to `(chip, pin)` for `edge`.
    pub fn insert(&mut self, chip: u8, pin: u8, edge: GpioEdge, prog_id: u32) {
        self.routes.entry((chip, pin)).or_default().push((edge, prog_id));
    }

    /// Program ids whose attached edge matches `fired`. `Both` matches either
    /// direction (on the attached side and the fired side).
    pub fn programs_for(&self, chip: u8, pin: u8, fired: GpioEdge) -> Vec<u32> {
        let mut out = Vec::new();
        if let Some(list) = self.routes.get(&(chip, pin)) {
            for &(edge, id) in list {
                if edge == fired || edge == GpioEdge::Both || fired == GpioEdge::Both {
                    out.push(id);
                }
            }
        }
        out
    }

    /// Remove all routes for a program (used on detach).
    pub fn remove(&mut self, prog_id: u32) {
        for list in self.routes.values_mut() {
            list.retain(|&(_, id)| id != prog_id);
        }
        self.routes.retain(|_, list| !list.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rising_and_falling_attach_independently() {
        let mut t = GpioRouteTable::new();
        t.insert(0, 17, GpioEdge::Rising, 1);
        t.insert(0, 17, GpioEdge::Falling, 2);
        assert_eq!(t.programs_for(0, 17, GpioEdge::Rising), alloc::vec![1]);
        assert_eq!(t.programs_for(0, 17, GpioEdge::Falling), alloc::vec![2]);
    }

    #[test]
    fn distinct_pins_do_not_cross_fire() {
        let mut t = GpioRouteTable::new();
        t.insert(0, 17, GpioEdge::Rising, 1);
        t.insert(0, 22, GpioEdge::Rising, 2);
        assert_eq!(t.programs_for(0, 22, GpioEdge::Rising), alloc::vec![2]);
        assert!(t.programs_for(0, 5, GpioEdge::Rising).is_empty());
    }

    #[test]
    fn both_matches_either_direction() {
        let mut t = GpioRouteTable::new();
        t.insert(0, 17, GpioEdge::Both, 1);
        assert_eq!(t.programs_for(0, 17, GpioEdge::Rising), alloc::vec![1]);
        assert_eq!(t.programs_for(0, 17, GpioEdge::Falling), alloc::vec![1]);
    }

    #[test]
    fn remove_drops_program_routes() {
        let mut t = GpioRouteTable::new();
        t.insert(0, 17, GpioEdge::Rising, 1);
        t.remove(1);
        assert!(t.programs_for(0, 17, GpioEdge::Rising).is_empty());
    }
}
