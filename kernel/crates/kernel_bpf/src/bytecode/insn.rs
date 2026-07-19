//! BPF Instruction Format
//!
//! eBPF instructions are 64 bits (8 bytes) with the following format:
//!
//! ```text
//! +--------+----+----+--------+------------+
//! | opcode | dst| src| offset |  immediate |
//! | 8 bits | 4b | 4b | 16 bits|   32 bits  |
//! +--------+----+----+--------+------------+
//! ```
//!
//! The dst and src fields are packed into a single byte:
//! - Low 4 bits: destination register
//! - High 4 bits: source register
//!
//! Wide instructions (for 64-bit immediates) use two consecutive
//! instruction slots, with the upper 32 bits in the second slot's
//! immediate field.

use core::fmt;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::opcode::{AluOp, DecodedOpcode, JmpOp, MemMode, MemSize, OpcodeClass, SourceType};
use super::registers::Register;

/// Single BPF instruction (8 bytes).
///
/// This is the fundamental unit of BPF bytecode. Each instruction
/// contains an opcode, two register fields, an offset, and an
/// immediate value.
#[derive(Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct BpfInsn {
    /// Opcode specifying operation type
    pub opcode: u8,
    /// Register fields: dst (low 4 bits) | src (high 4 bits)
    pub regs: u8,
    /// Offset for memory operations and jumps
    pub offset: i16,
    /// Immediate value for operations
    pub imm: i32,
}

impl BpfInsn {
    /// Size of a BPF instruction in bytes
    pub const SIZE: usize = 8;

    /// Create a new instruction.
    #[inline]
    pub const fn new(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Self {
        Self {
            opcode,
            regs: (src << 4) | (dst & 0x0f),
            offset,
            imm,
        }
    }

    /// Get the destination register field.
    #[inline]
    pub const fn dst_reg(&self) -> u8 {
        self.regs & 0x0f
    }

    /// Get the source register field.
    #[inline]
    pub const fn src_reg(&self) -> u8 {
        (self.regs >> 4) & 0x0f
    }

    /// Get the destination register.
    #[inline]
    pub fn dst(&self) -> Option<Register> {
        Register::from_raw(self.dst_reg())
    }

    /// Get the source register.
    #[inline]
    pub fn src(&self) -> Option<Register> {
        Register::from_raw(self.src_reg())
    }

    /// Get the instruction class.
    #[inline]
    pub const fn class(&self) -> Option<OpcodeClass> {
        OpcodeClass::from_opcode(self.opcode)
    }

    /// Get the source type (immediate or register).
    #[inline]
    pub const fn source_type(&self) -> SourceType {
        SourceType::from_opcode(self.opcode)
    }

    /// Check if this is a wide instruction (uses next slot for 64-bit immediate).
    ///
    /// Wide instructions are used for loading 64-bit immediate values
    /// and use two instruction slots.
    #[inline]
    pub const fn is_wide(&self) -> bool {
        // LD_DW_IMM: opcode 0x18
        self.opcode == 0x18
    }

    /// Check if this is an ALU instruction.
    #[inline]
    pub const fn is_alu(&self) -> bool {
        matches!(self.class(), Some(OpcodeClass::Alu32 | OpcodeClass::Alu64))
    }

    /// Check if this is a 64-bit ALU instruction.
    #[inline]
    pub const fn is_alu64(&self) -> bool {
        matches!(self.class(), Some(OpcodeClass::Alu64))
    }

    /// Check if this is a jump instruction.
    #[inline]
    pub const fn is_jump(&self) -> bool {
        matches!(self.class(), Some(OpcodeClass::Jmp | OpcodeClass::Jmp32))
    }

    /// Check if this is a memory instruction.
    #[inline]
    pub const fn is_memory(&self) -> bool {
        matches!(
            self.class(),
            Some(OpcodeClass::Ld | OpcodeClass::Ldx | OpcodeClass::St | OpcodeClass::Stx)
        )
    }

    /// Check if this is an exit instruction.
    #[inline]
    pub const fn is_exit(&self) -> bool {
        // EXIT: opcode 0x95
        self.opcode == 0x95
    }

    /// Check if this is a call instruction.
    #[inline]
    pub const fn is_call(&self) -> bool {
        // CALL: opcode 0x85
        self.opcode == 0x85
    }

    /// Get the ALU operation if this is an ALU instruction.
    #[inline]
    pub const fn alu_op(&self) -> Option<AluOp> {
        if self.is_alu() {
            AluOp::from_opcode(self.opcode)
        } else {
            None
        }
    }

    /// Get the jump operation if this is a jump instruction.
    #[inline]
    pub const fn jmp_op(&self) -> Option<JmpOp> {
        if self.is_jump() {
            JmpOp::from_opcode(self.opcode)
        } else {
            None
        }
    }

    /// Get the memory size for memory instructions.
    #[inline]
    pub const fn mem_size(&self) -> Option<MemSize> {
        if self.is_memory() {
            MemSize::from_opcode(self.opcode)
        } else {
            None
        }
    }

    /// Get the memory mode for memory instructions.
    #[inline]
    pub const fn mem_mode(&self) -> Option<MemMode> {
        if self.is_memory() {
            MemMode::from_opcode(self.opcode)
        } else {
            None
        }
    }

    /// Decode the opcode into its components.
    #[inline]
    pub const fn decode(&self) -> Option<DecodedOpcode> {
        DecodedOpcode::decode(self.opcode)
    }

    /// Create a NOP instruction (mov r0, r0).
    #[inline]
    pub const fn nop() -> Self {
        Self::new(0xbf, 0, 0, 0, 0) // mov64 r0, r0
    }

    /// Create an exit instruction.
    #[inline]
    pub const fn exit() -> Self {
        Self::new(0x95, 0, 0, 0, 0)
    }

    /// Create a 64-bit move immediate instruction.
    #[inline]
    pub const fn mov64_imm(dst: u8, imm: i32) -> Self {
        Self::new(0xb7, dst, 0, 0, imm)
    }

    /// Create a 64-bit move register instruction.
    #[inline]
    pub const fn mov64_reg(dst: u8, src: u8) -> Self {
        Self::new(0xbf, dst, src, 0, 0)
    }

    /// Create a 64-bit add immediate instruction.
    #[inline]
    pub const fn add64_imm(dst: u8, imm: i32) -> Self {
        Self::new(0x07, dst, 0, 0, imm)
    }

    /// Create a 64-bit add register instruction.
    #[inline]
    pub const fn add64_reg(dst: u8, src: u8) -> Self {
        Self::new(0x0f, dst, src, 0, 0)
    }

    /// Create a call instruction.
    #[inline]
    pub const fn call(helper_id: i32) -> Self {
        Self::new(0x85, 0, 0, 0, helper_id)
    }

    /// Create a conditional jump (jeq imm).
    #[inline]
    pub const fn jeq_imm(dst: u8, imm: i32, offset: i16) -> Self {
        Self::new(0x15, dst, 0, offset, imm)
    }

    /// Create a conditional jump (jeq reg).
    #[inline]
    pub const fn jeq_reg(dst: u8, src: u8, offset: i16) -> Self {
        Self::new(0x1d, dst, src, offset, 0)
    }

    /// Create a conditional jump (jne imm).
    #[inline]
    pub const fn jne_imm(dst: u8, imm: i32, offset: i16) -> Self {
        Self::new(0x55, dst, 0, offset, imm)
    }

    /// Create an unconditional jump.
    #[inline]
    pub const fn ja(offset: i16) -> Self {
        Self::new(0x05, 0, 0, offset, 0)
    }

    /// Create a 64-bit subtract immediate instruction.
    #[inline]
    pub const fn sub64_imm(dst: u8, imm: i32) -> Self {
        Self::new(0x17, dst, 0, 0, imm)
    }

    /// Create a 64-bit multiply immediate instruction.
    #[inline]
    pub const fn mul64_imm(dst: u8, imm: i32) -> Self {
        Self::new(0x27, dst, 0, 0, imm)
    }

    /// Create a 64-bit divide immediate instruction.
    #[inline]
    pub const fn div64_imm(dst: u8, imm: i32) -> Self {
        Self::new(0x37, dst, 0, 0, imm)
    }

    /// Create a 64-bit modulo immediate instruction.
    #[inline]
    pub const fn mod64_imm(dst: u8, imm: i32) -> Self {
        Self::new(0x97, dst, 0, 0, imm)
    }

    /// Create a 64-bit AND immediate instruction.
    #[inline]
    pub const fn and64_imm(dst: u8, imm: i32) -> Self {
        Self::new(0x57, dst, 0, 0, imm)
    }

    /// Create a 64-bit OR immediate instruction.
    #[inline]
    pub const fn or64_imm(dst: u8, imm: i32) -> Self {
        Self::new(0x47, dst, 0, 0, imm)
    }

    /// Create a 64-bit XOR immediate instruction.
    #[inline]
    pub const fn xor64_imm(dst: u8, imm: i32) -> Self {
        Self::new(0xa7, dst, 0, 0, imm)
    }

    /// Create a 64-bit left shift immediate instruction.
    #[inline]
    pub const fn lsh64_imm(dst: u8, imm: i32) -> Self {
        Self::new(0x67, dst, 0, 0, imm)
    }

    /// Create a 64-bit right shift immediate instruction.
    #[inline]
    pub const fn rsh64_imm(dst: u8, imm: i32) -> Self {
        Self::new(0x77, dst, 0, 0, imm)
    }

    /// Create a 64-bit negate instruction.
    #[inline]
    pub const fn neg64(dst: u8) -> Self {
        Self::new(0x87, dst, 0, 0, 0)
    }
}

impl fmt::Debug for BpfInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BpfInsn")
            .field("opcode", &format_args!("{:#04x}", self.opcode))
            .field("dst", &self.dst_reg())
            .field("src", &self.src_reg())
            .field("offset", &self.offset)
            .field("imm", &self.imm)
            .finish()
    }
}

impl fmt::Display for BpfInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Try to format as a human-readable instruction
        if self.is_exit() {
            return write!(f, "exit");
        }

        if self.is_call() {
            return write!(f, "call {}", self.imm);
        }

        if let Some(alu_op) = self.alu_op() {
            let width = if self.is_alu64() { "" } else { "32" };
            if matches!(self.source_type(), SourceType::Imm) {
                return write!(f, "{}{} r{}, {}", alu_op, width, self.dst_reg(), self.imm);
            } else {
                return write!(
                    f,
                    "{}{} r{}, r{}",
                    alu_op,
                    width,
                    self.dst_reg(),
                    self.src_reg()
                );
            }
        }

        if let Some(jmp_op) = self.jmp_op() {
            if jmp_op.is_unconditional() {
                return write!(f, "ja {:+}", self.offset);
            }
            if matches!(self.source_type(), SourceType::Imm) {
                return write!(
                    f,
                    "{} r{}, {}, {:+}",
                    jmp_op,
                    self.dst_reg(),
                    self.imm,
                    self.offset
                );
            } else {
                return write!(
                    f,
                    "{} r{}, r{}, {:+}",
                    jmp_op,
                    self.dst_reg(),
                    self.src_reg(),
                    self.offset
                );
            }
        }

        // Fallback to raw format
        write!(
            f,
            "op={:#04x} dst=r{} src=r{} off={} imm={}",
            self.opcode,
            self.dst_reg(),
            self.src_reg(),
            self.offset,
            self.imm
        )
    }
}

/// Wide instruction for 64-bit immediates.
///
/// BPF uses two instruction slots to encode 64-bit immediate values.
/// This struct represents the combined instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WideInsn {
    /// First instruction slot
    pub insn: BpfInsn,
    /// Second instruction slot (only imm field is used)
    pub next: BpfInsn,
}

impl WideInsn {
    /// Get the full 64-bit immediate value.
    #[inline]
    pub const fn imm64(&self) -> u64 {
        let low = self.insn.imm as u32 as u64;
        let high = self.next.imm as u32 as u64;
        (high << 32) | low
    }

    /// Create a wide instruction for loading a 64-bit immediate.
    #[inline]
    pub const fn ld_dw_imm(dst: u8, imm64: u64) -> Self {
        Self {
            insn: BpfInsn::new(0x18, dst, 0, 0, imm64 as i32),
            next: BpfInsn::new(0x00, 0, 0, 0, (imm64 >> 32) as i32),
        }
    }
}

/// Parsed instruction with extracted fields.
#[derive(Debug, Clone)]
pub enum ParsedInsn {
    /// ALU operation
    Alu {
        op: AluOp,
        is_64bit: bool,
        dst: Register,
        src: AluSrc,
    },
    /// Jump operation
    Jmp {
        op: JmpOp,
        is_64bit: bool,
        dst: Register,
        src: JmpSrc,
        offset: i16,
    },
    /// Memory load
    Load {
        size: MemSize,
        dst: Register,
        src: Register,
        offset: i16,
    },
    /// Memory store
    Store {
        size: MemSize,
        dst: Register,
        src: StoreSrc,
        offset: i16,
    },
    /// Wide load (64-bit immediate)
    LoadImm64 { dst: Register, imm: u64 },
    /// Function call
    Call { helper_id: i32 },
    /// Program exit
    Exit,
}

/// Source operand for ALU operations.
#[derive(Debug, Clone, Copy)]
pub enum AluSrc {
    Imm(i32),
    Reg(Register),
}

/// Source operand for jump comparisons.
#[derive(Debug, Clone, Copy)]
pub enum JmpSrc {
    Imm(i32),
    Reg(Register),
}

/// Source operand for store operations.
#[derive(Debug, Clone, Copy)]
pub enum StoreSrc {
    Imm(i32),
    Reg(Register),
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn instruction_size() {
        assert_eq!(core::mem::size_of::<BpfInsn>(), 8);
    }

    #[test]
    fn register_extraction() {
        let insn = BpfInsn::new(0x07, 5, 3, 0, 0);
        assert_eq!(insn.dst_reg(), 5);
        assert_eq!(insn.src_reg(), 3);
    }

    #[test]
    fn exit_instruction() {
        let insn = BpfInsn::exit();
        assert!(insn.is_exit());
        assert!(!insn.is_call());
        assert_eq!(format!("{}", insn), "exit");
    }

    #[test]
    fn call_instruction() {
        let insn = BpfInsn::call(42);
        assert!(insn.is_call());
        assert!(!insn.is_exit());
        assert_eq!(format!("{}", insn), "call 42");
    }

    #[test]
    fn alu_instruction() {
        let insn = BpfInsn::add64_imm(1, 100);
        assert!(insn.is_alu());
        assert!(insn.is_alu64());
        assert_eq!(insn.alu_op(), Some(AluOp::Add));
    }

    #[test]
    fn wide_instruction() {
        let wide = WideInsn::ld_dw_imm(0, 0x123456789abcdef0);
        assert!(wide.insn.is_wide());
        assert_eq!(wide.imm64(), 0x123456789abcdef0);
    }
}
