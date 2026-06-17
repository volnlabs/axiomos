//! Verifier State Tracking
//!
//! This module defines the state tracked during BPF program verification,
//! including register types, stack slots, and the overall verifier state
//! at each program point.

extern crate alloc;

use core::fmt;

use crate::bytecode::registers::Register;

/// Type of value held in a register.
///
/// The verifier tracks what type of value each register holds to ensure
/// type-safe operations and memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegType {
    /// Register has not been initialized
    #[default]
    NotInit,

    /// Scalar value (integer)
    Scalar,

    /// Pointer to stack frame (with offset from FP)
    PtrToStack,

    /// Pointer to map value
    PtrToMapValue,

    /// Pointer to map key
    PtrToMapKey,

    /// Pointer to context
    PtrToCtx,

    /// Pointer to packet data
    PtrToPacket,

    /// Pointer to packet end
    PtrToPacketEnd,

    /// Pointer to packet metadata
    PtrToPacketMeta,

    /// Constant pointer to map
    ConstPtrToMap,

    /// Frame pointer (R10, read-only)
    PtrToFp,

    /// Null pointer
    NullPtr,
}

impl RegType {
    /// Check if this is a pointer type.
    #[inline]
    pub const fn is_pointer(&self) -> bool {
        !matches!(self, Self::NotInit | Self::Scalar)
    }

    /// Check if this type can be dereferenced for read.
    #[inline]
    pub const fn can_read(&self) -> bool {
        matches!(
            self,
            Self::PtrToStack
                | Self::PtrToMapValue
                | Self::PtrToCtx
                | Self::PtrToPacket
                | Self::PtrToPacketMeta
        )
    }

    /// Check if this type can be dereferenced for write.
    #[inline]
    pub const fn can_write(&self) -> bool {
        matches!(
            self,
            Self::PtrToStack | Self::PtrToMapValue | Self::PtrToPacket
        )
    }
}

/// Verifier proof that a map-value pointer may be written.
///
/// `ReadWrite(None)` is the legacy/all-RW case: no `map_perms` table was
/// supplied, so every reachable map is writable by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapWritability {
    ReadWrite(Option<u32>),
    ReadOnly(u32),
    Unprovable,
}

impl MapWritability {
    #[inline]
    pub const fn is_read_write(self) -> bool {
        matches!(self, Self::ReadWrite(_))
    }

    #[inline]
    pub const fn map_id(self) -> Option<u32> {
        match self {
            Self::ReadWrite(id) => id,
            Self::ReadOnly(id) => Some(id),
            Self::Unprovable => None,
        }
    }
}

/// State of a single register during verification.
#[derive(Debug, Clone)]
pub struct RegState {
    /// Type of value in the register
    pub reg_type: RegType,

    /// For scalar values: known value if constant, None otherwise
    pub scalar_value: Option<ScalarValue>,

    /// For pointer types: offset from base
    pub ptr_offset: i64,

    /// For map pointers: map ID
    pub map_id: Option<u32>,

    /// For dereferenceable pointer types (map value, ctx, packet): the size in
    /// bytes of the region the pointer's base addresses. A load/store is valid
    /// only when `ptr_offset + insn.offset + access_size <= mem_range`. `None`
    /// means the size is unknown — `verify_memory` rejects dereferences through
    /// a non-stack pointer with no known range (sound: no blind deref).
    pub mem_range: Option<u32>,

    /// True if this pointer may be null (e.g. a `bpf_map_lookup_elem` result).
    /// Dereferencing a maybe-null pointer is rejected until a null check
    /// (`if r != 0`) proves it non-null on that branch.
    pub maybe_null: bool,

    /// For `PtrToMapValue`: proof that stores through this pointer are allowed.
    pub map_writability: MapWritability,
}

impl RegState {
    /// Create an uninitialized register state.
    pub const fn uninit() -> Self {
        Self {
            reg_type: RegType::NotInit,
            scalar_value: None,
            ptr_offset: 0,
            map_id: None,
            mem_range: None,
            maybe_null: false,
            map_writability: MapWritability::Unprovable,
        }
    }

    /// Create a scalar register state.
    pub fn scalar(value: Option<ScalarValue>) -> Self {
        Self {
            reg_type: RegType::Scalar,
            scalar_value: value,
            ptr_offset: 0,
            map_id: None,
            mem_range: None,
            maybe_null: false,
            map_writability: MapWritability::Unprovable,
        }
    }

    /// Create a stack pointer state.
    pub fn stack_ptr(offset: i64) -> Self {
        Self {
            reg_type: RegType::PtrToStack,
            scalar_value: None,
            ptr_offset: offset,
            map_id: None,
            mem_range: None,
            maybe_null: false,
            map_writability: MapWritability::Unprovable,
        }
    }

    /// Create a frame pointer state (R10).
    pub const fn frame_ptr() -> Self {
        Self {
            reg_type: RegType::PtrToFp,
            scalar_value: None,
            ptr_offset: 0,
            map_id: None,
            mem_range: None,
            maybe_null: false,
            map_writability: MapWritability::Unprovable,
        }
    }

    /// Create a context pointer state (R1 at entry).
    ///
    /// `mem_range` is left `None` here; the verifier sets it from the
    /// program's context size (`VerifyConfig::ctx_size`) at entry.
    pub const fn ctx_ptr() -> Self {
        Self {
            reg_type: RegType::PtrToCtx,
            scalar_value: None,
            ptr_offset: 0,
            map_id: None,
            mem_range: None,
            maybe_null: false,
            map_writability: MapWritability::Unprovable,
        }
    }

    /// Create a read-only pointer to the bytes behind `BpfContext::data`.
    ///
    /// This intentionally uses `PtrToCtx`, not `PtrToPacket`: hook payloads are
    /// kernel-owned event structs and must be readable/passable to helpers, but
    /// stores through them are not allowed.
    pub fn ctx_data_ptr(size: u32) -> Self {
        Self {
            reg_type: RegType::PtrToCtx,
            scalar_value: None,
            ptr_offset: 0,
            map_id: None,
            mem_range: Some(size),
            maybe_null: false,
            map_writability: MapWritability::Unprovable,
        }
    }

    /// Create a map-value pointer state with a known accessible size.
    ///
    /// `maybe_null` reflects that `bpf_map_lookup_elem` can return NULL; the
    /// verifier rejects dereferences until a null check clears it.
    pub fn map_value(size: u32, maybe_null: bool) -> Self {
        Self::map_value_with_writability(size, maybe_null, MapWritability::ReadWrite(None))
    }

    /// Create a map-value pointer state with an explicit writability proof.
    pub fn map_value_with_writability(
        size: u32,
        maybe_null: bool,
        map_writability: MapWritability,
    ) -> Self {
        Self {
            reg_type: RegType::PtrToMapValue,
            scalar_value: None,
            ptr_offset: 0,
            map_id: map_writability.map_id(),
            mem_range: Some(size),
            maybe_null,
            map_writability,
        }
    }

    /// Check if the register is initialized.
    #[inline]
    pub fn is_init(&self) -> bool {
        !matches!(self.reg_type, RegType::NotInit)
    }
}

impl Default for RegState {
    fn default() -> Self {
        Self::uninit()
    }
}

/// Tracked scalar value with range information.
#[derive(Debug, Clone, Copy)]
pub struct ScalarValue {
    /// Known exact value (if constant)
    pub value: Option<u64>,

    /// Minimum possible value
    pub min: u64,

    /// Maximum possible value
    pub max: u64,

    /// Tracked number representation
    pub tnum: TnumValue,
}

impl ScalarValue {
    /// Create a constant scalar value.
    pub const fn constant(value: u64) -> Self {
        Self {
            value: Some(value),
            min: value,
            max: value,
            tnum: TnumValue::constant(value),
        }
    }

    /// Create an unknown scalar value.
    pub const fn unknown() -> Self {
        Self {
            value: None,
            min: 0,
            max: u64::MAX,
            tnum: TnumValue::unknown(),
        }
    }

    /// Check if this is a known constant.
    #[inline]
    pub const fn is_constant(&self) -> bool {
        self.value.is_some()
    }

    /// Check if the value is known to be zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.value == Some(0)
    }

    /// Check if the value could be zero.
    #[inline]
    pub fn could_be_zero(&self) -> bool {
        self.min == 0 || self.value == Some(0)
    }
}

impl Default for ScalarValue {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Tnum (tracked number) for partial value tracking.
///
/// A tnum represents partial knowledge about a value:
/// - `value`: bits that are known to be set
/// - `mask`: bits that are unknown (1 = unknown, 0 = known)
///
/// For a known constant, mask = 0 and value = the constant.
/// For completely unknown, mask = u64::MAX and value = 0.
#[derive(Debug, Clone, Copy)]
pub struct TnumValue {
    /// Known bit values (only valid where mask is 0)
    pub value: u64,
    /// Unknown bit mask (1 = unknown)
    pub mask: u64,
}

impl TnumValue {
    /// Create a tnum for a known constant.
    pub const fn constant(value: u64) -> Self {
        Self { value, mask: 0 }
    }

    /// Create a tnum for a completely unknown value.
    pub const fn unknown() -> Self {
        Self {
            value: 0,
            mask: u64::MAX,
        }
    }

    /// Check if this is a known constant.
    #[inline]
    pub const fn is_constant(&self) -> bool {
        self.mask == 0
    }

    /// Get the known constant value if fully known.
    #[inline]
    pub const fn as_constant(&self) -> Option<u64> {
        if self.mask == 0 {
            Some(self.value)
        } else {
            None
        }
    }

    /// Does this tnum contain `n` as a possible concrete value?
    ///
    /// A concrete `n` is contained iff every known bit of the tnum matches
    /// the corresponding bit of `n`. Unknown bits don't constrain.
    #[inline]
    pub const fn contains(&self, n: u64) -> bool {
        (self.value & !self.mask) == (n & !self.mask)
    }

    /// Tnum-aware addition. Result contains every `a + b` where `a` is
    /// contained in `self` and `b` is contained in `other`.
    ///
    /// Reference: Linux `kernel/bpf/tnum.c` `tnum_add` — propagates carries
    /// through the known bits and widens the mask wherever a carry chain
    /// crosses an unknown bit.
    pub const fn add(self, other: Self) -> Self {
        let sm = self.mask.wrapping_add(other.mask);
        let sv = self.value.wrapping_add(other.value);
        let sigma = sm.wrapping_add(sv);
        // chi: bit set iff a carry would propagate through an unknown
        let chi = sigma ^ sv;
        let mu = chi | self.mask | other.mask;
        Self {
            value: sv & !mu,
            mask: mu,
        }
    }

    /// Tnum-aware subtraction. Same shape as `add` with the analogous
    /// borrow logic.
    pub const fn sub(self, other: Self) -> Self {
        let dv = self.value.wrapping_sub(other.value);
        let alpha = dv.wrapping_add(self.mask);
        let beta = dv.wrapping_sub(other.mask);
        let chi = alpha ^ beta;
        let mu = chi | self.mask | other.mask;
        Self {
            value: dv & !mu,
            mask: mu,
        }
    }

    /// Bitwise AND. A bit is known-1 iff both operands know it's 1; a bit
    /// is known-0 iff either operand knows it's 0; otherwise unknown.
    pub const fn and(self, other: Self) -> Self {
        let alpha = self.value | self.mask;
        let beta = other.value | other.mask;
        let v = self.value & other.value;
        Self {
            value: v,
            mask: alpha & beta & !v,
        }
    }

    /// Bitwise OR. A bit is known-1 iff either operand knows it's 1; a bit
    /// is known-0 iff both operands know it's 0; otherwise unknown.
    pub const fn or(self, other: Self) -> Self {
        let v = self.value | other.value;
        let mu = (self.mask | other.mask) & !v;
        Self { value: v, mask: mu }
    }

    /// Bitwise XOR. A bit is unknown iff either operand has it unknown.
    pub const fn xor(self, other: Self) -> Self {
        let v = self.value ^ other.value;
        let mu = self.mask | other.mask;
        Self {
            value: v & !mu,
            mask: mu,
        }
    }

    /// Logical left shift by a constant. Known bits shift; new low bits
    /// are known zero.
    pub const fn lshift(self, shift: u8) -> Self {
        if shift >= 64 {
            return Self { value: 0, mask: 0 };
        }
        Self {
            value: self.value << shift,
            mask: self.mask << shift,
        }
    }

    /// Logical right shift by a constant. Known bits shift; new high bits
    /// are known zero.
    pub const fn rshift(self, shift: u8) -> Self {
        if shift >= 64 {
            return Self { value: 0, mask: 0 };
        }
        Self {
            value: self.value >> shift,
            mask: self.mask >> shift,
        }
    }

    /// Arithmetic right shift by a constant. The sign bit is replicated,
    /// but only the known portion is replicated — if the sign bit is
    /// unknown, the new high bits stay unknown.
    pub const fn arshift(self, shift: u8) -> Self {
        if shift >= 64 {
            // The result is either all-1s or all-0s depending on the sign
            // bit, which we may or may not know. Conservative: collapse to
            // fully unknown when we don't know the sign.
            return if (self.mask >> 63) & 1 == 1 {
                Self::unknown()
            } else {
                let bit = (self.value >> 63) & 1;
                Self::constant(if bit == 1 { u64::MAX } else { 0 })
            };
        }
        let v = (self.value as i64 >> shift) as u64;
        let m = (self.mask as i64 >> shift) as u64;
        Self { value: v, mask: m }
    }

    /// Tnum-aware multiplication. Conservative: builds the result by
    /// iterating the known bits of one operand and adding shifted copies
    /// of the other. Linux's `tnum_mul` is the spec.
    pub fn mul(self, other: Self) -> Self {
        let mut acc = Self::constant(0);
        let mut a = self;
        let mut b = other;
        // Walk 64 bit positions; for each bit position in `b`, if known-1
        // add a shifted `a`, if unknown add an unknown-shifted `a` (i.e.
        // contribute uncertainty).
        for _ in 0..64 {
            // Low bit of b
            let b_known_one = b.value & 1 == 1 && b.mask & 1 == 0;
            let b_unknown = b.mask & 1 == 1;
            if b_known_one {
                acc = acc.add(a);
            } else if b_unknown {
                // Unknown bit: contributes a value-or-zero — model as
                // tnum_add with a tnum that's "0 or a".
                let maybe_a = Self {
                    value: 0,
                    mask: a.value | a.mask,
                };
                acc = acc.add(maybe_a);
            }
            a = a.lshift(1);
            b = b.rshift(1);
        }
        acc
    }

    /// Intersect two tnums describing the same value (e.g. on a control
    /// flow merge where both predecessors describe the same variable).
    /// The result is the most precise tnum that is contained in both.
    /// Returns `None` if the two are inconsistent — they disagree on a
    /// known bit.
    pub const fn intersect(self, other: Self) -> Option<Self> {
        // Both know bit i and disagree → inconsistent.
        let known_both = !self.mask & !other.mask;
        if (self.value ^ other.value) & known_both != 0 {
            return None;
        }
        let v = self.value | other.value;
        let mu = self.mask & other.mask;
        Some(Self { value: v, mask: mu })
    }

    /// True iff every concrete value contained in `other` is also contained
    /// in `self`. Used by the verifier state-pruning subsumption check —
    /// `a.subsumes(b)` means "we've already explored a state at least as
    /// general as the current `b`, so we can prune."
    #[inline]
    pub const fn subsumes(&self, other: &Self) -> bool {
        // self's known bits must agree with other's known bits, and self's
        // mask must be a superset of other's mask (self is at least as
        // permissive).
        let bits_disagree = (self.value ^ other.value) & !self.mask & !other.mask;
        bits_disagree == 0 && (self.mask | other.mask) == self.mask
    }
}

impl Default for TnumValue {
    fn default() -> Self {
        Self::unknown()
    }
}

impl PartialEq for TnumValue {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.mask == other.mask
    }
}

impl Eq for TnumValue {}

/// State of a stack slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StackSlot {
    /// Slot is invalid/uninitialized
    #[default]
    Invalid,

    /// Slot contains spilled register
    Spill(Register),

    /// Slot contains scalar data
    Scalar,

    /// Slot contains zero
    Zero,
}

/// Stack state during verification.
///
/// **Sparse**: only the slots a program actually touches are stored, keyed by
/// `idx = -offset - 1` (idx 0 = FP-1); an absent slot reads as
/// [`StackSlot::Invalid`]. The previous dense representation allocated a
/// `Vec<StackSlot>` of the *full* profile stack size — 512 KiB slots (~1 MiB)
/// on the cloud profile — for **every** cloned verifier state, which dominated
/// the verifier's memory and was the root of the loop-driven OOM bounded in
/// #116. Real programs touch a tiny fraction of the stack, so the sparse map
/// is orders of magnitude smaller and makes per-state cloning cheap, which is
/// what lets the recorded-state budget be raised.
#[derive(Clone)]
pub struct StackState {
    /// Non-`Invalid` slots, keyed by `idx = -offset - 1`.
    slots: alloc::collections::BTreeMap<usize, StackSlot>,

    /// Number of addressable slots (the profile stack size). Bounds checks use
    /// this; it does not allocate.
    capacity: usize,

    /// Maximum stack depth used (positive value).
    max_depth: usize,
}

impl StackState {
    /// Create a new stack state with given capacity.
    pub fn new(max_size: usize) -> Self {
        Self {
            slots: alloc::collections::BTreeMap::new(),
            capacity: max_size,
            max_depth: 0,
        }
    }

    /// Get the slot at the given offset from FP.
    ///
    /// Offset should be negative (stack grows down). An in-bounds slot that was
    /// never written reads as [`StackSlot::Invalid`].
    pub fn get(&self, offset: i64) -> Option<StackSlot> {
        if offset >= 0 || offset < -(self.capacity as i64) {
            return None;
        }
        let idx = (-offset - 1) as usize;
        Some(self.slots.get(&idx).copied().unwrap_or(StackSlot::Invalid))
    }

    /// Set the slot at the given offset from FP.
    pub fn set(&mut self, offset: i64, slot: StackSlot) -> bool {
        if offset >= 0 || offset < -(self.capacity as i64) {
            return false;
        }
        let idx = (-offset - 1) as usize;
        // Keep the map sparse: an `Invalid` slot is the default, so store it as
        // absence rather than an entry.
        if matches!(slot, StackSlot::Invalid) {
            self.slots.remove(&idx);
        } else {
            self.slots.insert(idx, slot);
        }

        // Update max depth
        let depth = idx + 1;
        if depth > self.max_depth {
            self.max_depth = depth;
        }

        true
    }

    /// Get the maximum stack depth used.
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Check if access at offset with size is valid.
    pub fn is_valid_access(&self, offset: i64, size: usize) -> bool {
        // Stack access must be negative offset from FP
        if offset >= 0 {
            return false;
        }

        // Check bounds
        let end_offset = offset - (size as i64) + 1;
        if end_offset < -(self.capacity as i64) {
            return false;
        }

        true
    }
}

impl Default for StackState {
    fn default() -> Self {
        Self::new(512) // Default 512 bytes
    }
}

impl fmt::Debug for StackState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StackState")
            .field("max_depth", &self.max_depth)
            .field("capacity", &self.capacity)
            .field("live_slots", &self.slots.len())
            .finish()
    }
}

/// Complete verifier state at a program point.
#[derive(Clone)]
pub struct VerifierState {
    /// Register states
    pub regs: [RegState; Register::COUNT],

    /// Stack state
    pub stack: StackState,

    /// Current instruction pointer
    pub insn_idx: usize,

    /// Number of instructions processed (for bounds checking)
    pub insn_processed: usize,
}

impl VerifierState {
    /// Create initial verifier state for program entry.
    pub fn new_entry(stack_size: usize) -> Self {
        let mut regs = core::array::from_fn(|_| RegState::uninit());

        // R1 = context pointer at entry
        regs[Register::R1 as usize] = RegState::ctx_ptr();

        // R10 = frame pointer (always valid)
        regs[Register::R10 as usize] = RegState::frame_ptr();

        Self {
            regs,
            stack: StackState::new(stack_size),
            insn_idx: 0,
            insn_processed: 0,
        }
    }

    /// Get register state.
    pub fn reg(&self, reg: Register) -> &RegState {
        &self.regs[reg as usize]
    }

    /// Get mutable register state.
    pub fn reg_mut(&mut self, reg: Register) -> &mut RegState {
        &mut self.regs[reg as usize]
    }

    /// Check if a register is initialized.
    pub fn is_reg_init(&self, reg: Register) -> bool {
        self.regs[reg as usize].is_init()
    }

    /// Mark a register as containing a scalar value.
    pub fn set_scalar(&mut self, reg: Register, value: Option<ScalarValue>) {
        self.regs[reg as usize] = RegState::scalar(value);
    }

    /// Advance to next instruction.
    pub fn advance(&mut self) {
        self.insn_idx += 1;
        self.insn_processed += 1;
    }

    /// Jump to a specific instruction.
    pub fn jump_to(&mut self, idx: usize) {
        self.insn_idx = idx;
        self.insn_processed += 1;
    }
}

impl fmt::Debug for VerifierState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifierState")
            .field("insn_idx", &self.insn_idx)
            .field("insn_processed", &self.insn_processed)
            .field("stack_depth", &self.stack.max_depth())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_type_properties() {
        assert!(!RegType::NotInit.is_pointer());
        assert!(!RegType::Scalar.is_pointer());
        assert!(RegType::PtrToStack.is_pointer());
        assert!(RegType::PtrToCtx.is_pointer());

        assert!(RegType::PtrToStack.can_read());
        assert!(RegType::PtrToStack.can_write());
        assert!(RegType::PtrToCtx.can_read());
        assert!(!RegType::PtrToCtx.can_write());
    }

    #[test]
    fn scalar_value_tracking() {
        let constant = ScalarValue::constant(42);
        assert!(constant.is_constant());
        assert_eq!(constant.value, Some(42));

        let unknown = ScalarValue::unknown();
        assert!(!unknown.is_constant());
        assert!(unknown.could_be_zero());
    }

    #[test]
    fn stack_state_operations() {
        let mut stack = StackState::new(256);

        // Valid negative offsets
        assert!(stack.set(-1, StackSlot::Scalar));
        assert!(stack.set(-8, StackSlot::Zero));

        assert_eq!(stack.get(-1), Some(StackSlot::Scalar));
        assert_eq!(stack.get(-8), Some(StackSlot::Zero));
        assert_eq!(stack.max_depth(), 8);

        // Invalid positive offset
        assert!(!stack.set(0, StackSlot::Scalar));
        assert!(!stack.set(1, StackSlot::Scalar));
    }

    #[test]
    fn verifier_state_entry() {
        let state = VerifierState::new_entry(512);

        // R1 should be context pointer
        assert!(state.is_reg_init(Register::R1));
        assert_eq!(state.reg(Register::R1).reg_type, RegType::PtrToCtx);

        // R10 should be frame pointer
        assert!(state.is_reg_init(Register::R10));
        assert_eq!(state.reg(Register::R10).reg_type, RegType::PtrToFp);

        // Other registers should be uninitialized
        assert!(!state.is_reg_init(Register::R0));
        assert!(!state.is_reg_init(Register::R2));
    }

    // --- tnum operations ---
    //
    // For each op we (1) check it on known constants, (2) check that the
    // result contains every concrete value reachable from contained
    // operands. The second check is the soundness invariant we'll lean on
    // when threading tnum through `verify_alu`.

    #[test]
    fn tnum_constant_roundtrip() {
        let t = TnumValue::constant(42);
        assert!(t.is_constant());
        assert_eq!(t.as_constant(), Some(42));
        assert!(t.contains(42));
        assert!(!t.contains(43));
    }

    #[test]
    fn tnum_unknown_contains_everything() {
        let t = TnumValue::unknown();
        assert!(t.contains(0));
        assert!(t.contains(u64::MAX));
        assert!(t.contains(0xdeadbeef));
        assert!(!t.is_constant());
    }

    #[test]
    fn tnum_add_constants() {
        let a = TnumValue::constant(3);
        let b = TnumValue::constant(5);
        assert_eq!(a.add(b), TnumValue::constant(8));
    }

    #[test]
    fn tnum_add_widens_through_unknown() {
        // r = (something & 0xff)  →  low 8 bits unknown, high 56 known zero
        let masked = TnumValue {
            value: 0,
            mask: 0xff,
        };
        let one = TnumValue::constant(1);
        let r = masked.add(one);
        // Result must contain (k + 1) for every k in 0..=255
        for k in 0..=255u64 {
            assert!(r.contains(k + 1), "missing {} from sum tnum", k + 1);
        }
    }

    #[test]
    fn tnum_sub_constants() {
        let a = TnumValue::constant(10);
        let b = TnumValue::constant(3);
        assert_eq!(a.sub(b), TnumValue::constant(7));
    }

    #[test]
    fn tnum_and_masks_low_bits() {
        // unknown & 0xff = low 8 bits unknown, rest known zero
        let any = TnumValue::unknown();
        let mask = TnumValue::constant(0xff);
        let r = any.and(mask);
        assert_eq!(
            r,
            TnumValue {
                value: 0,
                mask: 0xff
            }
        );
        for k in 0..=255u64 {
            assert!(r.contains(k));
        }
        assert!(!r.contains(0x100));
    }

    #[test]
    fn tnum_or_sets_known_high_bits() {
        let zero = TnumValue::constant(0);
        let high = TnumValue::constant(0xff00);
        let r = zero.or(high);
        assert_eq!(r, TnumValue::constant(0xff00));
    }

    #[test]
    fn tnum_xor_propagates_unknown() {
        let any = TnumValue::unknown();
        let zero = TnumValue::constant(0);
        let r = any.xor(zero);
        // Anything XOR 0 = anything → still fully unknown
        assert_eq!(r, TnumValue::unknown());
    }

    #[test]
    fn tnum_lshift_clears_low_bits() {
        let masked = TnumValue {
            value: 0,
            mask: 0xff,
        };
        let r = masked.lshift(8);
        assert_eq!(
            r,
            TnumValue {
                value: 0,
                mask: 0xff00
            }
        );
        // After shifting low byte left by 8, low byte is known zero.
        assert!(r.contains(0));
        assert!(r.contains(0xff00));
        assert!(!r.contains(0x01));
    }

    #[test]
    fn tnum_rshift_clears_high_bits() {
        let r = TnumValue::unknown().rshift(56);
        // Top 56 bits now known zero; low 8 bits unknown.
        assert_eq!(
            r,
            TnumValue {
                value: 0,
                mask: 0xff
            }
        );
    }

    #[test]
    fn tnum_arshift_extends_known_sign() {
        let neg_one = TnumValue::constant(u64::MAX);
        let r = neg_one.arshift(8);
        assert_eq!(r, TnumValue::constant(u64::MAX));
    }

    #[test]
    fn tnum_arshift_with_unknown_sign_stays_uncertain() {
        let any = TnumValue::unknown();
        let r = any.arshift(1);
        // High bit was unknown, so after arithmetic right shift the new
        // top bit is still unknown. The result must still contain both
        // the positive and negative concrete values reachable from `any`.
        assert!(r.contains(0));
        assert!(r.contains(u64::MAX >> 1));
        // arshift of i64::MIN by 1 = -1 >> 1 in signed, which is still
        // negative. Result must still cover the very-negative case.
        assert!(r.contains((i64::MIN >> 1) as u64));
    }

    #[test]
    fn tnum_mul_constants() {
        let a = TnumValue::constant(6);
        let b = TnumValue::constant(7);
        assert_eq!(a.mul(b), TnumValue::constant(42));
    }

    #[test]
    fn tnum_mul_by_known_zero_is_zero() {
        let any = TnumValue::unknown();
        let zero = TnumValue::constant(0);
        assert_eq!(any.mul(zero), TnumValue::constant(0));
    }

    #[test]
    fn tnum_intersect_consistent() {
        // (anything with low byte == 0x42)  ∩  (anything with high byte == 0xff)
        let a = TnumValue {
            value: 0x42,
            mask: !0xffu64,
        };
        let b = TnumValue {
            value: 0xff << 56,
            mask: !(0xffu64 << 56),
        };
        let r = a.intersect(b).expect("consistent");
        // Result fixes both bytes, leaves middle 6 bytes unknown.
        assert_eq!(r.value, 0x42 | (0xff << 56));
        assert_eq!(r.mask, !(0xffu64 | (0xffu64 << 56)));
    }

    #[test]
    fn tnum_intersect_inconsistent_returns_none() {
        let a = TnumValue::constant(1);
        let b = TnumValue::constant(2);
        assert!(a.intersect(b).is_none());
    }

    #[test]
    fn tnum_subsumes_self() {
        let t = TnumValue::constant(7);
        assert!(t.subsumes(&t));
    }

    #[test]
    fn tnum_unknown_subsumes_constant() {
        assert!(TnumValue::unknown().subsumes(&TnumValue::constant(42)));
    }

    #[test]
    fn tnum_constant_does_not_subsume_unknown() {
        assert!(!TnumValue::constant(42).subsumes(&TnumValue::unknown()));
    }

    #[test]
    fn tnum_disagreeing_constants_do_not_subsume() {
        assert!(!TnumValue::constant(1).subsumes(&TnumValue::constant(2)));
    }
}
