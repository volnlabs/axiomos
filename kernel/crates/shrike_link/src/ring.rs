//! Fixed-capacity byte ring buffer for the UART transport (TX/RX staging).
//!
//! Single-producer / single-consumer in intent (IRQ fills RX, the transport
//! task drains it; the task fills TX, the IRQ/poller drains it) but NOT
//! lock-free — the caller provides synchronization (a spinlock in the kernel).
//! Pure no_std, host-tested.

/// A byte FIFO of fixed capacity `N`.
pub struct RingBuf<const N: usize> {
    buf: [u8; N],
    head: usize,
    tail: usize,
    len: usize,
}

impl<const N: usize> Default for RingBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RingBuf<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len == N
    }

    /// Push one byte. Returns `false` (and drops the byte) if full.
    pub fn push(&mut self, b: u8) -> bool {
        if self.len == N {
            return false;
        }
        self.buf[self.tail] = b;
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        true
    }

    /// Pop the oldest byte, or `None` if empty.
    pub fn pop(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        let b = self.buf[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pops_none() {
        let mut r = RingBuf::<4>::new();
        assert!(r.is_empty());
        assert_eq!(r.pop(), None);
    }

    #[test]
    fn fifo_order() {
        let mut r = RingBuf::<4>::new();
        assert!(r.push(1));
        assert!(r.push(2));
        assert!(r.push(3));
        assert_eq!(r.len(), 3);
        assert_eq!(r.pop(), Some(1));
        assert_eq!(r.pop(), Some(2));
        assert_eq!(r.pop(), Some(3));
        assert_eq!(r.pop(), None);
    }

    #[test]
    fn full_rejects_and_uses_all_n_slots() {
        let mut r = RingBuf::<3>::new();
        assert!(r.push(10));
        assert!(r.push(11));
        assert!(r.push(12)); // 3rd slot usable (no reserved slot)
        assert!(r.is_full());
        assert!(!r.push(13)); // full -> dropped
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn wraps_around() {
        let mut r = RingBuf::<3>::new();
        r.push(1);
        r.push(2);
        assert_eq!(r.pop(), Some(1)); // head advances
        r.push(3);
        r.push(4); // tail wraps past the buffer end
        assert!(!r.push(5)); // now full (2,3,4)
        assert_eq!(r.pop(), Some(2));
        assert_eq!(r.pop(), Some(3));
        assert_eq!(r.pop(), Some(4));
        assert!(r.is_empty());
    }

    #[test]
    fn stress_wrap_many_cycles() {
        let mut r = RingBuf::<8>::new();
        let mut expect = 0u8;
        let mut next = 0u8;
        for _ in 0..1000 {
            // keep it ~half full, pushing 3 popping 2 each round
            for _ in 0..3 {
                if r.push(next) {
                    next = next.wrapping_add(1);
                }
            }
            for _ in 0..2 {
                if let Some(b) = r.pop() {
                    assert_eq!(b, expect);
                    expect = expect.wrapping_add(1);
                }
            }
        }
        while let Some(b) = r.pop() {
            assert_eq!(b, expect);
            expect = expect.wrapping_add(1);
        }
        assert_eq!(expect, next); // every pushed byte popped exactly once, in order
    }
}
