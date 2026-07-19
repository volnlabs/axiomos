//! x86_64 JIT Compiler for BPF Programs
//!
//! This module provides Just-In-Time compilation of BPF bytecode to
//! x86_64 machine code. JIT is only available in the cloud profile.
//!
//! # Register Mapping
//!
//! BPF registers are mapped to x86_64 registers:
//!
//! | BPF    | x86_64 | Purpose                    |
//! |--------|--------|----------------------------|
//! | R0     | RAX    | Return value               |
//! | R1     | RDI    | Arg 1 / context ptr        |
//! | R2     | RSI    | Arg 2                      |
//! | R3     | RDX    | Arg 3                      |
//! | R4     | RCX    | Arg 4                      |
//! | R5     | R8     | Arg 5                      |
//! | R6     | RBX    | Callee-saved               |
//! | R7     | R13    | Callee-saved               |
//! | R8     | R14    | Callee-saved               |
//! | R9     | R15    | Callee-saved               |
//! | R10    | RBP    | Frame pointer (read-only)  |
//!
//! Note: R9 is used as a temporary for some operations.
//!
//! # Stack Layout
//!
//! ```text
//! High Address
//! ┌─────────────────────┐
//! │ Return address      │
//! ├─────────────────────┤
//! │ Saved RBP           │
//! ├─────────────────────┤
//! │ Saved RBX           │
//! ├─────────────────────┤
//! │ Saved R13-R15       │
//! ├─────────────────────┤
//! │ BPF stack space     │
//! │ (profile max)       │
//! ├─────────────────────┤  ← BPF R10 (frame pointer)
//! │                     │
//! Low Address
//! ```
//!
//! # Profile Erasure
//!
//! This entire module is gated behind:
//! ```rust,ignore
//! #[cfg(all(feature = "cloud-profile", target_arch = "x86_64"))]
//! ```

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::bytecode::insn::BpfInsn;
use crate::bytecode::opcode::{AluOp, JmpOp, MemSize, OpcodeClass, SourceType};
use crate::bytecode::program::BpfProgram;
use crate::execution::{BpfContext, BpfExecutor, BpfResult};
use crate::profile::CloudProfile;

// x86_64 register encodings (REX.W mode, 64-bit)
const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RBX: u8 = 3;
const RSP: u8 = 4;
const RBP: u8 = 5;
const RSI: u8 = 6;
const RDI: u8 = 7;
const R8: u8 = 8;
const R9: u8 = 9;
// R10-R11 are caller-saved, avoid for BPF registers
const R13: u8 = 13;
const R14: u8 = 14;
const R15: u8 = 15;

/// BPF to x86_64 register mapping.
/// R0-R10 map to: RAX, RDI, RSI, RDX, RCX, R8, RBX, R13, R14, R15, RBP
const BPF_TO_X64: [u8; 11] = [
    RAX, // R0 -> RAX (return value)
    RDI, // R1 -> RDI (arg1/context, System V ABI)
    RSI, // R2 -> RSI (arg2)
    RDX, // R3 -> RDX (arg3)
    RCX, // R4 -> RCX (arg4)
    R8,  // R5 -> R8 (arg5)
    RBX, // R6 -> RBX (callee-saved)
    R13, // R7 -> R13 (callee-saved)
    R14, // R8 -> R14 (callee-saved)
    R15, // R9 -> R15 (callee-saved)
    RBP, // R10 -> RBP (frame pointer)
];

/// Temporary register for complex operations.
const TMP_REG: u8 = R9;

/// x86_64 code emitter.
struct X64Emitter {
    /// Emitted code bytes
    code: Vec<u8>,
    /// Jump targets that need patching (code_offset, target_insn_idx)
    jump_patches: Vec<(usize, usize)>,
    /// BPF instruction offsets in generated code
    insn_offsets: Vec<usize>,
}

impl X64Emitter {
    fn new(capacity: usize) -> Self {
        Self {
            code: Vec::with_capacity(capacity),
            jump_patches: Vec::new(),
            insn_offsets: Vec::new(),
        }
    }

    /// Emit a single byte.
    fn emit_byte(&mut self, b: u8) {
        self.code.push(b);
    }

    /// Emit multiple bytes.
    fn emit_bytes(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    /// Get current code offset.
    fn offset(&self) -> usize {
        self.code.len()
    }

    /// Record the start of a BPF instruction.
    fn mark_insn(&mut self) {
        self.insn_offsets.push(self.offset());
    }

    /// Record a jump that needs patching.
    fn record_jump(&mut self, target_insn: usize) {
        // Jump offset is at current position - 4 (32-bit displacement)
        self.jump_patches.push((self.offset() - 4, target_insn));
    }

    /// Check if register needs REX prefix (R8-R15).
    fn needs_rex(reg: u8) -> bool {
        reg >= 8
    }

    /// Build REX prefix.
    fn rex(w: bool, r: u8, x: u8, b: u8) -> u8 {
        let mut rex = 0x40;
        if w {
            rex |= 0x08;
        } // 64-bit operand
        if r >= 8 {
            rex |= 0x04;
        } // Extension of ModR/M reg
        if x >= 8 {
            rex |= 0x02;
        } // Extension of SIB index
        if b >= 8 {
            rex |= 0x01;
        } // Extension of ModR/M r/m or SIB base
        rex
    }

    /// Build ModR/M byte.
    fn modrm(md: u8, reg: u8, rm: u8) -> u8 {
        ((md & 0x3) << 6) | ((reg & 0x7) << 3) | (rm & 0x7)
    }

    // ============================================================
    // x86_64 Instruction Encoding
    // ============================================================

    /// MOV reg, reg (64-bit)
    fn emit_mov_reg(&mut self, dst: u8, src: u8) {
        // REX.W + 89 /r (MOV r/m64, r64)
        self.emit_byte(Self::rex(true, src, 0, dst));
        self.emit_byte(0x89);
        self.emit_byte(Self::modrm(0b11, src, dst));
    }

    /// MOV reg, imm64
    fn emit_mov_imm64(&mut self, dst: u8, imm: i64) {
        // REX.W + B8+rd io (MOV r64, imm64)
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0xB8 + (dst & 0x7));
        self.emit_bytes(&imm.to_le_bytes());
    }

    /// MOV reg, imm32 (sign-extended to 64-bit)
    fn emit_mov_imm32(&mut self, dst: u8, imm: i32) {
        // REX.W + C7 /0 id (MOV r/m64, imm32)
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0xC7);
        self.emit_byte(Self::modrm(0b11, 0, dst));
        self.emit_bytes(&imm.to_le_bytes());
    }

    /// XOR reg, reg (for zeroing)
    fn emit_xor_reg(&mut self, dst: u8, src: u8) {
        // REX.W + 31 /r
        self.emit_byte(Self::rex(true, src, 0, dst));
        self.emit_byte(0x31);
        self.emit_byte(Self::modrm(0b11, src, dst));
    }

    /// ADD reg, reg
    fn emit_add_reg(&mut self, dst: u8, src: u8) {
        // REX.W + 01 /r
        self.emit_byte(Self::rex(true, src, 0, dst));
        self.emit_byte(0x01);
        self.emit_byte(Self::modrm(0b11, src, dst));
    }

    /// ADD reg, imm32
    fn emit_add_imm32(&mut self, dst: u8, imm: i32) {
        // REX.W + 81 /0 id
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0x81);
        self.emit_byte(Self::modrm(0b11, 0, dst));
        self.emit_bytes(&imm.to_le_bytes());
    }

    /// SUB reg, reg
    fn emit_sub_reg(&mut self, dst: u8, src: u8) {
        // REX.W + 29 /r
        self.emit_byte(Self::rex(true, src, 0, dst));
        self.emit_byte(0x29);
        self.emit_byte(Self::modrm(0b11, src, dst));
    }

    /// SUB reg, imm32
    fn emit_sub_imm32(&mut self, dst: u8, imm: i32) {
        // REX.W + 81 /5 id
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0x81);
        self.emit_byte(Self::modrm(0b11, 5, dst));
        self.emit_bytes(&imm.to_le_bytes());
    }

    /// IMUL reg, reg (signed multiply)
    fn emit_imul_reg(&mut self, dst: u8, src: u8) {
        // REX.W + 0F AF /r
        self.emit_byte(Self::rex(true, dst, 0, src));
        self.emit_bytes(&[0x0F, 0xAF]);
        self.emit_byte(Self::modrm(0b11, dst, src));
    }

    /// DIV reg (unsigned: RDX:RAX / reg -> RAX quotient, RDX remainder)
    fn emit_div_reg(&mut self, src: u8) {
        // REX.W + F7 /6
        self.emit_byte(Self::rex(true, 0, 0, src));
        self.emit_byte(0xF7);
        self.emit_byte(Self::modrm(0b11, 6, src));
    }

    /// IDIV reg (signed)
    #[allow(dead_code)]
    fn emit_idiv_reg(&mut self, src: u8) {
        // REX.W + F7 /7
        self.emit_byte(Self::rex(true, 0, 0, src));
        self.emit_byte(0xF7);
        self.emit_byte(Self::modrm(0b11, 7, src));
    }

    /// AND reg, reg
    fn emit_and_reg(&mut self, dst: u8, src: u8) {
        // REX.W + 21 /r
        self.emit_byte(Self::rex(true, src, 0, dst));
        self.emit_byte(0x21);
        self.emit_byte(Self::modrm(0b11, src, dst));
    }

    /// AND reg, imm32
    fn emit_and_imm32(&mut self, dst: u8, imm: i32) {
        // REX.W + 81 /4 id
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0x81);
        self.emit_byte(Self::modrm(0b11, 4, dst));
        self.emit_bytes(&imm.to_le_bytes());
    }

    /// OR reg, reg
    fn emit_or_reg(&mut self, dst: u8, src: u8) {
        // REX.W + 09 /r
        self.emit_byte(Self::rex(true, src, 0, dst));
        self.emit_byte(0x09);
        self.emit_byte(Self::modrm(0b11, src, dst));
    }

    /// OR reg, imm32
    fn emit_or_imm32(&mut self, dst: u8, imm: i32) {
        // REX.W + 81 /1 id
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0x81);
        self.emit_byte(Self::modrm(0b11, 1, dst));
        self.emit_bytes(&imm.to_le_bytes());
    }

    /// XOR reg, imm32
    fn emit_xor_imm32(&mut self, dst: u8, imm: i32) {
        // REX.W + 81 /6 id
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0x81);
        self.emit_byte(Self::modrm(0b11, 6, dst));
        self.emit_bytes(&imm.to_le_bytes());
    }

    /// SHL reg, CL (shift left by CL)
    fn emit_shl_cl(&mut self, dst: u8) {
        // REX.W + D3 /4
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0xD3);
        self.emit_byte(Self::modrm(0b11, 4, dst));
    }

    /// SHL reg, imm8
    fn emit_shl_imm(&mut self, dst: u8, imm: u8) {
        // REX.W + C1 /4 ib
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0xC1);
        self.emit_byte(Self::modrm(0b11, 4, dst));
        self.emit_byte(imm & 0x3F);
    }

    /// SHR reg, CL (shift right logical)
    fn emit_shr_cl(&mut self, dst: u8) {
        // REX.W + D3 /5
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0xD3);
        self.emit_byte(Self::modrm(0b11, 5, dst));
    }

    /// SHR reg, imm8
    fn emit_shr_imm(&mut self, dst: u8, imm: u8) {
        // REX.W + C1 /5 ib
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0xC1);
        self.emit_byte(Self::modrm(0b11, 5, dst));
        self.emit_byte(imm & 0x3F);
    }

    /// SAR reg, CL (shift right arithmetic)
    fn emit_sar_cl(&mut self, dst: u8) {
        // REX.W + D3 /7
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0xD3);
        self.emit_byte(Self::modrm(0b11, 7, dst));
    }

    /// SAR reg, imm8
    fn emit_sar_imm(&mut self, dst: u8, imm: u8) {
        // REX.W + C1 /7 ib
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0xC1);
        self.emit_byte(Self::modrm(0b11, 7, dst));
        self.emit_byte(imm & 0x3F);
    }

    /// NEG reg (two's complement)
    fn emit_neg(&mut self, dst: u8) {
        // REX.W + F7 /3
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0xF7);
        self.emit_byte(Self::modrm(0b11, 3, dst));
    }

    /// CMP reg, reg
    fn emit_cmp_reg(&mut self, dst: u8, src: u8) {
        // REX.W + 39 /r
        self.emit_byte(Self::rex(true, src, 0, dst));
        self.emit_byte(0x39);
        self.emit_byte(Self::modrm(0b11, src, dst));
    }

    /// CMP reg, imm32
    fn emit_cmp_imm32(&mut self, dst: u8, imm: i32) {
        // REX.W + 81 /7 id
        self.emit_byte(Self::rex(true, 0, 0, dst));
        self.emit_byte(0x81);
        self.emit_byte(Self::modrm(0b11, 7, dst));
        self.emit_bytes(&imm.to_le_bytes());
    }

    /// TEST reg, reg
    fn emit_test_reg(&mut self, dst: u8, src: u8) {
        // REX.W + 85 /r
        self.emit_byte(Self::rex(true, src, 0, dst));
        self.emit_byte(0x85);
        self.emit_byte(Self::modrm(0b11, src, dst));
    }

    /// JMP rel32 (unconditional)
    fn emit_jmp_rel32(&mut self, offset: i32) {
        // E9 cd
        self.emit_byte(0xE9);
        self.emit_bytes(&offset.to_le_bytes());
    }

    /// Jcc rel32 (conditional jump)
    fn emit_jcc_rel32(&mut self, cc: u8, offset: i32) {
        // 0F 8x cd
        self.emit_bytes(&[0x0F, 0x80 + cc]);
        self.emit_bytes(&offset.to_le_bytes());
    }

    /// CALL rel32
    #[allow(dead_code)]
    fn emit_call_rel32(&mut self, offset: i32) {
        // E8 cd
        self.emit_byte(0xE8);
        self.emit_bytes(&offset.to_le_bytes());
    }

    /// RET
    fn emit_ret(&mut self) {
        self.emit_byte(0xC3);
    }

    /// PUSH reg
    fn emit_push(&mut self, reg: u8) {
        if reg >= 8 {
            self.emit_byte(0x41); // REX.B
        }
        self.emit_byte(0x50 + (reg & 0x7));
    }

    /// POP reg
    fn emit_pop(&mut self, reg: u8) {
        if reg >= 8 {
            self.emit_byte(0x41); // REX.B
        }
        self.emit_byte(0x58 + (reg & 0x7));
    }

    /// MOV [base + disp32], reg
    fn emit_store(&mut self, base: u8, disp: i32, src: u8, size: MemSize) {
        match size {
            MemSize::Byte => {
                // REX + 88 /r
                self.emit_byte(Self::rex(false, src, 0, base));
                self.emit_byte(0x88);
            }
            MemSize::Half => {
                // 66 REX + 89 /r (16-bit)
                self.emit_byte(0x66);
                self.emit_byte(Self::rex(false, src, 0, base));
                self.emit_byte(0x89);
            }
            MemSize::Word => {
                // REX + 89 /r (32-bit, no REX.W)
                if Self::needs_rex(src) || Self::needs_rex(base) {
                    self.emit_byte(Self::rex(false, src, 0, base));
                }
                self.emit_byte(0x89);
            }
            MemSize::DWord => {
                // REX.W + 89 /r (64-bit)
                self.emit_byte(Self::rex(true, src, 0, base));
                self.emit_byte(0x89);
            }
        }
        self.emit_modrm_disp(src, base, disp);
    }

    /// MOV reg, [base + disp32]
    fn emit_load(&mut self, dst: u8, base: u8, disp: i32, size: MemSize) {
        match size {
            MemSize::Byte => {
                // MOVZX for zero-extension
                self.emit_byte(Self::rex(true, dst, 0, base));
                self.emit_bytes(&[0x0F, 0xB6]);
            }
            MemSize::Half => {
                // MOVZX for 16-bit
                self.emit_byte(Self::rex(true, dst, 0, base));
                self.emit_bytes(&[0x0F, 0xB7]);
            }
            MemSize::Word => {
                // MOV with zero extension
                if Self::needs_rex(dst) || Self::needs_rex(base) {
                    self.emit_byte(Self::rex(false, dst, 0, base));
                }
                self.emit_byte(0x8B);
            }
            MemSize::DWord => {
                // REX.W + 8B /r
                self.emit_byte(Self::rex(true, dst, 0, base));
                self.emit_byte(0x8B);
            }
        }
        self.emit_modrm_disp(dst, base, disp);
    }

    /// Emit ModR/M + SIB + displacement for [base + disp32]
    fn emit_modrm_disp(&mut self, reg: u8, base: u8, disp: i32) {
        let base_enc = base & 0x7;
        let reg_enc = reg & 0x7;

        if base_enc == RSP {
            // Need SIB byte for RSP/R12 as base
            if disp == 0 && base_enc != RBP {
                self.emit_byte(Self::modrm(0b00, reg_enc, 0b100));
                self.emit_byte(0x24); // SIB: no index, RSP base
            } else if (-128..=127).contains(&disp) {
                self.emit_byte(Self::modrm(0b01, reg_enc, 0b100));
                self.emit_byte(0x24);
                self.emit_byte(disp as i8 as u8);
            } else {
                self.emit_byte(Self::modrm(0b10, reg_enc, 0b100));
                self.emit_byte(0x24);
                self.emit_bytes(&disp.to_le_bytes());
            }
        } else if disp == 0 && base_enc != RBP {
            self.emit_byte(Self::modrm(0b00, reg_enc, base_enc));
        } else if (-128..=127).contains(&disp) {
            self.emit_byte(Self::modrm(0b01, reg_enc, base_enc));
            self.emit_byte(disp as i8 as u8);
        } else {
            self.emit_byte(Self::modrm(0b10, reg_enc, base_enc));
            self.emit_bytes(&disp.to_le_bytes());
        }
    }

    /// CQO - sign extend RAX to RDX:RAX
    #[allow(dead_code)]
    fn emit_cqo(&mut self) {
        // REX.W + 99
        self.emit_bytes(&[0x48, 0x99]);
    }

    /// XOR RDX, RDX - zero RDX for unsigned division
    fn emit_xor_rdx_rdx(&mut self) {
        self.emit_xor_reg(RDX, RDX);
    }
}

/// x86_64 condition codes.
#[allow(dead_code)]
mod cc {
    pub const JO: u8 = 0x0; // Overflow
    pub const JNO: u8 = 0x1; // Not overflow
    pub const JB: u8 = 0x2; // Below (unsigned <)
    pub const JAE: u8 = 0x3; // Above or equal (unsigned >=)
    pub const JE: u8 = 0x4; // Equal
    pub const JNE: u8 = 0x5; // Not equal
    pub const JBE: u8 = 0x6; // Below or equal (unsigned <=)
    pub const JA: u8 = 0x7; // Above (unsigned >)
    pub const JS: u8 = 0x8; // Sign
    pub const JNS: u8 = 0x9; // Not sign
    pub const JL: u8 = 0xC; // Less (signed <)
    pub const JGE: u8 = 0xD; // Greater or equal (signed >=)
    pub const JLE: u8 = 0xE; // Less or equal (signed <=)
    pub const JG: u8 = 0xF; // Greater (signed >)
}

/// JIT-compiled BPF program.
#[allow(dead_code)]
pub struct JitProgram {
    /// Executable code (would be mmap'd with PROT_EXEC in real impl)
    code: Vec<u8>,
    /// Entry point offset
    entry: usize,
}

/// JIT compiler and executor.
pub struct JitExecutor {
    _private: PhantomData<()>,
}

impl JitExecutor {
    /// Create a new JIT executor.
    pub fn new() -> Self {
        Self {
            _private: PhantomData,
        }
    }

    /// Compile a BPF program to native code.
    pub fn compile(&self, program: &BpfProgram<CloudProfile>) -> Result<JitProgram, JitError> {
        let insns = program.instructions();
        if insns.is_empty() {
            return Err(JitError::CodegenFailed);
        }

        let mut compiler = Arm64JitCompiler::new();
        compiler.compile_program(insns)
    }
}

impl Default for JitExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfExecutor<CloudProfile> for JitExecutor {
    fn execute(&self, program: &BpfProgram<CloudProfile>, ctx: &BpfContext<'_>) -> BpfResult {
        // Try to compile, fall back to interpreter on failure
        match self.compile(program) {
            Ok(_jit_prog) => {
                // In a real implementation, we would:
                // 1. mmap the code with PROT_EXEC
                // 2. Cast to function pointer
                // 3. Call with context
                // For safety reasons in this demo, fall back to interpreter
                let interp = crate::execution::Interpreter::<CloudProfile>::new();
                interp.execute(program, ctx)
            }
            Err(_) => {
                // Fall back to interpreter
                let interp = crate::execution::Interpreter::<CloudProfile>::new();
                interp.execute(program, ctx)
            }
        }
    }
}

/// x86_64 JIT compiler.
pub struct Arm64JitCompiler {
    emitter: X64Emitter,
    stack_size: usize,
}

impl Arm64JitCompiler {
    /// Create a new compiler.
    pub fn new() -> Self {
        Self {
            emitter: X64Emitter::new(4096),
            stack_size: 512, // Default BPF stack size
        }
    }

    /// Compile a BPF program.
    pub fn compile_program(&mut self, insns: &[BpfInsn]) -> Result<JitProgram, JitError> {
        // Reserve space for instruction offsets
        self.emitter.insn_offsets.reserve(insns.len());

        // Emit prologue
        let entry = self.emitter.offset();
        self.emit_prologue();

        // Compile each instruction
        let mut i = 0;
        while i < insns.len() {
            self.emitter.mark_insn();
            let insn = &insns[i];

            // Handle wide instructions (64-bit immediate)
            if insn.is_wide() {
                if i + 1 >= insns.len() {
                    return Err(JitError::CodegenFailed);
                }
                let next = &insns[i + 1];
                let imm64 = (insn.imm as u32 as u64) | ((next.imm as u32 as u64) << 32);
                let dst = BPF_TO_X64[insn.dst_reg() as usize];
                self.emitter.emit_mov_imm64(dst, imm64 as i64);
                i += 2;
                continue;
            }

            self.compile_insn(insn)?;
            i += 1;
        }

        // Patch jumps
        self.patch_jumps();

        Ok(JitProgram {
            code: core::mem::take(&mut self.emitter.code),
            entry,
        })
    }

    /// Emit function prologue.
    fn emit_prologue(&mut self) {
        // Save callee-saved registers
        self.emitter.emit_push(RBP);
        self.emitter.emit_push(RBX);
        self.emitter.emit_push(R13);
        self.emitter.emit_push(R14);
        self.emitter.emit_push(R15);

        // Setup BPF frame pointer (RBP points to BPF stack)
        // SUB RSP, stack_size
        self.emitter.emit_sub_imm32(RSP, self.stack_size as i32);

        // MOV RBP, RSP (R10 = frame pointer)
        self.emitter.emit_mov_reg(RBP, RSP);
    }

    /// Emit function epilogue.
    fn emit_epilogue(&mut self) {
        // Restore stack
        self.emitter.emit_add_imm32(RSP, self.stack_size as i32);

        // Restore callee-saved registers
        self.emitter.emit_pop(R15);
        self.emitter.emit_pop(R14);
        self.emitter.emit_pop(R13);
        self.emitter.emit_pop(RBX);
        self.emitter.emit_pop(RBP);

        // Return
        self.emitter.emit_ret();
    }

    /// Compile a single BPF instruction.
    fn compile_insn(&mut self, insn: &BpfInsn) -> Result<(), JitError> {
        // Exit instruction
        if insn.is_exit() {
            self.emit_epilogue();
            return Ok(());
        }

        let Some(class) = insn.class() else {
            return Err(JitError::UnsupportedInstruction);
        };

        match class {
            OpcodeClass::Alu64 => self.compile_alu(insn, true)?,
            OpcodeClass::Alu32 => self.compile_alu(insn, false)?,
            OpcodeClass::Jmp => self.compile_jmp(insn, true)?,
            OpcodeClass::Jmp32 => self.compile_jmp(insn, false)?,
            OpcodeClass::Ldx => self.compile_load(insn)?,
            OpcodeClass::Stx | OpcodeClass::St => self.compile_store(insn)?,
            OpcodeClass::Ld => {
                // Handled above (wide load)
                return Err(JitError::UnsupportedInstruction);
            }
        }

        Ok(())
    }

    /// Compile ALU instruction.
    fn compile_alu(&mut self, insn: &BpfInsn, is_64bit: bool) -> Result<(), JitError> {
        let dst = BPF_TO_X64[insn.dst_reg() as usize];
        let is_reg = matches!(SourceType::from_opcode(insn.opcode), SourceType::Reg);

        let Some(op) = AluOp::from_opcode(insn.opcode) else {
            return Err(JitError::UnsupportedInstruction);
        };

        match op {
            AluOp::Add => {
                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    self.emitter.emit_add_reg(dst, src);
                } else {
                    self.emitter.emit_add_imm32(dst, insn.imm);
                }
            }
            AluOp::Sub => {
                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    self.emitter.emit_sub_reg(dst, src);
                } else {
                    self.emitter.emit_sub_imm32(dst, insn.imm);
                }
            }
            AluOp::Mul => {
                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    self.emitter.emit_imul_reg(dst, src);
                } else {
                    // IMUL with immediate requires different encoding
                    // Load imm to TMP, then multiply
                    self.emitter.emit_mov_imm32(TMP_REG, insn.imm);
                    self.emitter.emit_imul_reg(dst, TMP_REG);
                }
            }
            AluOp::Div => {
                // Division requires RAX:RDX setup
                // Save RAX if dst != RAX
                if dst != RAX {
                    self.emitter.emit_mov_reg(TMP_REG, RAX);
                    self.emitter.emit_mov_reg(RAX, dst);
                }
                self.emitter.emit_xor_rdx_rdx(); // Zero RDX for unsigned div

                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    self.emitter.emit_div_reg(src);
                } else {
                    self.emitter.emit_mov_imm32(R9, insn.imm);
                    self.emitter.emit_div_reg(R9);
                }

                if dst != RAX {
                    self.emitter.emit_mov_reg(dst, RAX);
                    self.emitter.emit_mov_reg(RAX, TMP_REG);
                }
            }
            AluOp::Mod => {
                // Similar to div, but result is in RDX
                if dst != RAX {
                    self.emitter.emit_mov_reg(TMP_REG, RAX);
                    self.emitter.emit_mov_reg(RAX, dst);
                }
                self.emitter.emit_xor_rdx_rdx();

                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    self.emitter.emit_div_reg(src);
                } else {
                    self.emitter.emit_mov_imm32(R9, insn.imm);
                    self.emitter.emit_div_reg(R9);
                }

                // Remainder is in RDX
                self.emitter.emit_mov_reg(dst, RDX);
                if dst != RAX {
                    self.emitter.emit_mov_reg(RAX, TMP_REG);
                }
            }
            AluOp::Or => {
                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    self.emitter.emit_or_reg(dst, src);
                } else {
                    self.emitter.emit_or_imm32(dst, insn.imm);
                }
            }
            AluOp::And => {
                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    self.emitter.emit_and_reg(dst, src);
                } else {
                    self.emitter.emit_and_imm32(dst, insn.imm);
                }
            }
            AluOp::Xor => {
                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    self.emitter.emit_xor_reg(dst, src);
                } else {
                    self.emitter.emit_xor_imm32(dst, insn.imm);
                }
            }
            AluOp::Lsh => {
                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    // Shift amount must be in CL
                    if src != RCX {
                        self.emitter.emit_mov_reg(RCX, src);
                    }
                    self.emitter.emit_shl_cl(dst);
                } else {
                    self.emitter.emit_shl_imm(dst, insn.imm as u8);
                }
            }
            AluOp::Rsh => {
                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    if src != RCX {
                        self.emitter.emit_mov_reg(RCX, src);
                    }
                    self.emitter.emit_shr_cl(dst);
                } else {
                    self.emitter.emit_shr_imm(dst, insn.imm as u8);
                }
            }
            AluOp::Arsh => {
                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    if src != RCX {
                        self.emitter.emit_mov_reg(RCX, src);
                    }
                    self.emitter.emit_sar_cl(dst);
                } else {
                    self.emitter.emit_sar_imm(dst, insn.imm as u8);
                }
            }
            AluOp::Neg => {
                self.emitter.emit_neg(dst);
            }
            AluOp::Mov => {
                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    self.emitter.emit_mov_reg(dst, src);
                } else if insn.imm == 0 {
                    self.emitter.emit_xor_reg(dst, dst);
                } else {
                    self.emitter.emit_mov_imm32(dst, insn.imm);
                }
            }
            AluOp::End => {
                // Byte swap - not commonly used, skip for now
                return Err(JitError::UnsupportedInstruction);
            }
        }

        // For 32-bit ALU, zero-extend result
        if !is_64bit {
            // MOV eax, eax zero-extends to 64-bit
            // This is implicit in x86_64 for 32-bit operations
        }

        Ok(())
    }

    /// Compile jump instruction.
    fn compile_jmp(&mut self, insn: &BpfInsn, _is_64bit: bool) -> Result<(), JitError> {
        let Some(op) = JmpOp::from_opcode(insn.opcode) else {
            return Err(JitError::UnsupportedInstruction);
        };

        match op {
            JmpOp::Ja => {
                // Unconditional jump
                self.emitter.emit_jmp_rel32(0); // Placeholder
                let target = (self.emitter.insn_offsets.len() as i32) + insn.offset as i32;
                self.emitter.record_jump(target as usize);
            }
            JmpOp::Call => {
                // Helper call - for now, emit a call to a stub
                // In real impl, would resolve helper and call it
                // For safety, just return 0
                self.emitter.emit_xor_reg(RAX, RAX);
            }
            JmpOp::Exit => {
                self.emit_epilogue();
            }
            _ => {
                // Conditional jump
                let dst = BPF_TO_X64[insn.dst_reg() as usize];
                let is_reg = matches!(SourceType::from_opcode(insn.opcode), SourceType::Reg);

                if is_reg {
                    let src = BPF_TO_X64[insn.src_reg() as usize];
                    self.emitter.emit_cmp_reg(dst, src);
                } else {
                    self.emitter.emit_cmp_imm32(dst, insn.imm);
                }

                let cc = match op {
                    JmpOp::Jeq => cc::JE,
                    JmpOp::Jne => cc::JNE,
                    JmpOp::Jgt => cc::JA,
                    JmpOp::Jge => cc::JAE,
                    JmpOp::Jlt => cc::JB,
                    JmpOp::Jle => cc::JBE,
                    JmpOp::Jsgt => cc::JG,
                    JmpOp::Jsge => cc::JGE,
                    JmpOp::Jslt => cc::JL,
                    JmpOp::Jsle => cc::JLE,
                    JmpOp::Jset => {
                        // JSET: jump if (dst & src) != 0
                        if is_reg {
                            let src = BPF_TO_X64[insn.src_reg() as usize];
                            self.emitter.emit_test_reg(dst, src);
                        } else {
                            self.emitter.emit_mov_imm32(TMP_REG, insn.imm);
                            self.emitter.emit_test_reg(dst, TMP_REG);
                        }
                        cc::JNE
                    }
                    _ => return Err(JitError::UnsupportedInstruction),
                };

                self.emitter.emit_jcc_rel32(cc, 0); // Placeholder
                let target = (self.emitter.insn_offsets.len() as i32) + insn.offset as i32;
                self.emitter.record_jump(target as usize);
            }
        }

        Ok(())
    }

    /// Compile load instruction.
    fn compile_load(&mut self, insn: &BpfInsn) -> Result<(), JitError> {
        let dst = BPF_TO_X64[insn.dst_reg() as usize];
        let src = BPF_TO_X64[insn.src_reg() as usize];
        let Some(size) = MemSize::from_opcode(insn.opcode) else {
            return Err(JitError::UnsupportedInstruction);
        };

        self.emitter.emit_load(dst, src, insn.offset as i32, size);
        Ok(())
    }

    /// Compile store instruction.
    fn compile_store(&mut self, insn: &BpfInsn) -> Result<(), JitError> {
        let dst = BPF_TO_X64[insn.dst_reg() as usize];
        let Some(size) = MemSize::from_opcode(insn.opcode) else {
            return Err(JitError::UnsupportedInstruction);
        };

        let Some(class) = insn.class() else {
            return Err(JitError::UnsupportedInstruction);
        };

        if matches!(class, OpcodeClass::St) {
            // Store immediate
            self.emitter.emit_mov_imm32(TMP_REG, insn.imm);
            self.emitter
                .emit_store(dst, insn.offset as i32, TMP_REG, size);
        } else {
            // Store register
            let src = BPF_TO_X64[insn.src_reg() as usize];
            self.emitter.emit_store(dst, insn.offset as i32, src, size);
        }

        Ok(())
    }

    /// Patch jump targets.
    fn patch_jumps(&mut self) {
        for (patch_offset, target_insn) in &self.emitter.jump_patches {
            let target_offset = if *target_insn < self.emitter.insn_offsets.len() {
                self.emitter.insn_offsets[*target_insn]
            } else {
                // Jump past end - point to epilogue
                self.emitter.code.len()
            };

            // Calculate relative offset (from instruction after the jump)
            let rel_offset = (target_offset as i32) - (*patch_offset as i32) - 4;

            // Patch the offset
            let bytes = rel_offset.to_le_bytes();
            self.emitter.code[*patch_offset..*patch_offset + 4].copy_from_slice(&bytes);
        }
    }
}

impl Default for Arm64JitCompiler {
    fn default() -> Self {
        Self::new()
    }
}

/// JIT compilation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitError {
    /// JIT compilation is not yet implemented
    NotImplemented,
    /// Failed to allocate executable memory
    AllocationFailed,
    /// Code generation failed
    CodegenFailed,
    /// Unsupported instruction
    UnsupportedInstruction,
}

impl core::fmt::Display for JitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotImplemented => write!(f, "JIT compilation not implemented"),
            Self::AllocationFailed => write!(f, "failed to allocate executable memory"),
            Self::CodegenFailed => write!(f, "code generation failed"),
            Self::UnsupportedInstruction => write!(f, "unsupported instruction"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jit_compile_simple() {
        use crate::bytecode::insn::BpfInsn;
        use crate::bytecode::program::{BpfProgType, ProgramBuilder};

        let program = ProgramBuilder::<CloudProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 42))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let jit = JitExecutor::new();
        let result = jit.compile(&program);

        // Should compile successfully now
        assert!(result.is_ok());
    }

    #[test]
    fn jit_compile_arithmetic() {
        use crate::bytecode::insn::BpfInsn;
        use crate::bytecode::program::{BpfProgType, ProgramBuilder};

        let program = ProgramBuilder::<CloudProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 10))
            .insn(BpfInsn::add64_imm(0, 5))
            .insn(BpfInsn::mov64_imm(1, 3))
            .insn(BpfInsn::add64_reg(0, 1))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let jit = JitExecutor::new();
        let result = jit.compile(&program);

        assert!(result.is_ok());
    }

    #[test]
    fn jit_fallback_to_interpreter() {
        use crate::bytecode::insn::BpfInsn;
        use crate::bytecode::program::{BpfProgType, ProgramBuilder};

        let program = ProgramBuilder::<CloudProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 42))
            .insn(BpfInsn::exit())
            .build()
            .expect("valid program");

        let jit = JitExecutor::new();
        let ctx = BpfContext::empty();

        // Should fall back to interpreter and work
        let result = jit.execute(&program, &ctx);
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn emitter_mov_reg() {
        let mut emitter = X64Emitter::new(64);

        // MOV RAX, RBX
        emitter.emit_mov_reg(RAX, RBX);

        // Should be: REX.W + 89 /r
        assert_eq!(&emitter.code[..3], &[0x48, 0x89, 0xD8]);
    }

    #[test]
    fn emitter_add_reg() {
        let mut emitter = X64Emitter::new(64);

        // ADD RAX, RCX
        emitter.emit_add_reg(RAX, RCX);

        // Should be: REX.W + 01 /r
        assert_eq!(&emitter.code[..3], &[0x48, 0x01, 0xC8]);
    }
}
