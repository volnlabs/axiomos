//! BPF Bytecode Interpreter
//!
//! This module provides a pure interpreter for BPF bytecode.
//! The interpreter is available in both cloud and embedded profiles,
//! serving as the primary execution mode for embedded and fallback
//! for cloud (when JIT is unavailable).
//!
//! # Profile Constraints
//!
//! The interpreter enforces profile-specific limits:
//! - Instruction count bounded by `P::MAX_INSN_COUNT`
//! - Stack size bounded by `P::MAX_STACK_SIZE`

extern crate alloc;

use alloc::vec;
use core::marker::PhantomData;

use super::{BpfContext, BpfError, BpfExecutor, BpfResult};
use crate::bytecode::insn::BpfInsn;
use crate::bytecode::opcode::{AluOp, JmpOp, MemSize, OpcodeClass, SourceType};
use crate::bytecode::program::BpfProgram;
use crate::bytecode::registers::{Register, RegisterFile};
use crate::profile::{ActiveProfile, PhysicalProfile};
use crate::verifier::HelperId;
use crate::verifier::helpers::{RuntimeHelper, get_helper_descriptor};

// SAFETY: These functions are defined in the kernel and linked into the final binary.
// They follow the C calling convention which matches the interpreter's expectations.
// In host-based tests, these symbols are provided by the `helpers_stub` module in `mod.rs`.
unsafe extern "C" {
    fn bpf_ktime_get_ns() -> u64;
    fn bpf_get_interrupt_latency_ns(ctx: *const BpfContext<'_>) -> u64;
    fn bpf_get_boot_time_ms(ctx: *const BpfContext<'_>) -> u64;
    fn bpf_get_kernel_heap_kb(ctx: *const BpfContext<'_>) -> u64;
    fn bpf_get_kernel_image_mb(ctx: *const BpfContext<'_>) -> u64;
    fn bpf_trace_printk(fmt: *const u8, size: u32) -> i32;
    fn bpf_map_lookup_elem(map_id: u32, key: *const u8) -> *mut u8;
    fn bpf_map_update_elem(map_id: u32, key: *const u8, value: *const u8, flags: u64) -> i32;
    fn bpf_map_delete_elem(map_id: u32, key: *const u8) -> i32;
    fn bpf_ringbuf_output(map_id: u32, data: *const u8, size: u64, flags: u64) -> i64;
    fn bpf_timeseries_push(map_id: u32, key: *const u8, value: *const u8) -> i64;
    // Robotics helpers
    fn bpf_gpio_read(pin: u32) -> i64;
    fn bpf_gpio_write(pin: u32, value: u32) -> i64;
    fn bpf_pwm_write(pwm_id: u32, channel: u32, duty: u32) -> i64;
    fn bpf_motor_pair_v1(left_permille: i32, right_permille: i32) -> i64;
}

/// BPF bytecode interpreter.
///
/// The interpreter executes BPF programs instruction by instruction.
/// It is the simplest and most portable execution mode.
pub struct Interpreter<P: PhysicalProfile = ActiveProfile> {
    _profile: PhantomData<P>,
}

impl<P: PhysicalProfile> Interpreter<P> {
    /// Create a new interpreter.
    pub fn new() -> Self {
        Self {
            _profile: PhantomData,
        }
    }

    /// Execute a single instruction.
    fn execute_insn(
        &self,
        insn: &BpfInsn,
        regs: &mut RegisterFile,
        stack: &mut [u8],
        ctx: &BpfContext<'_>,
    ) -> Result<InsnResult, BpfError> {
        // Exit instruction
        if insn.is_exit() {
            return Ok(InsnResult::Exit);
        }

        // Get opcode class
        let class = insn.class().ok_or(BpfError::InvalidInstruction)?;

        match class {
            OpcodeClass::Alu64 | OpcodeClass::Alu32 => {
                self.execute_alu(insn, regs, class == OpcodeClass::Alu64)?;
            }

            OpcodeClass::Jmp | OpcodeClass::Jmp32 => {
                return self.execute_jmp(insn, regs, class == OpcodeClass::Jmp, ctx, stack);
            }

            OpcodeClass::Ldx => {
                self.execute_load(insn, regs, stack, ctx)?;
            }

            OpcodeClass::Stx | OpcodeClass::St => {
                self.execute_store(insn, regs, stack)?;
            }

            OpcodeClass::Ld => {
                // Wide load (64-bit immediate)
                return Ok(InsnResult::WideLoad);
            }
        }

        Ok(InsnResult::Continue)
    }

    /// Execute an ALU instruction.
    fn execute_alu(
        &self,
        insn: &BpfInsn,
        regs: &mut RegisterFile,
        is_64bit: bool,
    ) -> Result<(), BpfError> {
        let dst = Register::from_raw(insn.dst_reg()).ok_or(BpfError::InvalidInstruction)?;

        let src_val = if matches!(SourceType::from_opcode(insn.opcode), SourceType::Reg) {
            let src = Register::from_raw(insn.src_reg()).ok_or(BpfError::InvalidInstruction)?;
            regs.get(src)
        } else {
            insn.imm as i64 as u64
        };

        let dst_val = regs.get(dst);

        let alu_op = AluOp::from_opcode(insn.opcode).ok_or(BpfError::InvalidInstruction)?;

        let result = match alu_op {
            AluOp::Add => dst_val.wrapping_add(src_val),
            AluOp::Sub => dst_val.wrapping_sub(src_val),
            AluOp::Mul => dst_val.wrapping_mul(src_val),
            AluOp::Div => {
                if src_val == 0 {
                    return Err(BpfError::DivisionByZero);
                }
                dst_val / src_val
            }
            AluOp::Or => dst_val | src_val,
            AluOp::And => dst_val & src_val,
            AluOp::Lsh => dst_val << (src_val & 0x3f),
            AluOp::Rsh => dst_val >> (src_val & 0x3f),
            AluOp::Neg => (-(dst_val as i64)) as u64,
            AluOp::Mod => {
                if src_val == 0 {
                    return Err(BpfError::DivisionByZero);
                }
                dst_val % src_val
            }
            AluOp::Xor => dst_val ^ src_val,
            AluOp::Mov => src_val,
            AluOp::Arsh => ((dst_val as i64) >> (src_val & 0x3f)) as u64,
            AluOp::End => {
                // Byte swap
                match insn.imm {
                    16 => (dst_val as u16).swap_bytes() as u64,
                    32 => (dst_val as u32).swap_bytes() as u64,
                    64 => dst_val.swap_bytes(),
                    _ => return Err(BpfError::InvalidInstruction),
                }
            }
        };

        // Truncate to 32 bits for 32-bit ALU
        let result = if is_64bit {
            result
        } else {
            (result as u32) as u64
        };

        regs.set(dst, result);
        Ok(())
    }

    /// Execute a jump instruction.
    fn execute_jmp(
        &self,
        insn: &BpfInsn,
        regs: &mut RegisterFile,
        is_64bit: bool,
        ctx: &BpfContext<'_>,
        stack: &[u8],
    ) -> Result<InsnResult, BpfError> {
        let jmp_op = JmpOp::from_opcode(insn.opcode).ok_or(BpfError::InvalidInstruction)?;

        // Handle call and exit
        if matches!(jmp_op, JmpOp::Call) {
            return self.execute_call(insn, regs, ctx, stack);
        }

        if matches!(jmp_op, JmpOp::Exit) {
            return Ok(InsnResult::Exit);
        }

        // Unconditional jump
        if matches!(jmp_op, JmpOp::Ja) {
            return Ok(InsnResult::Jump(insn.offset));
        }

        // Conditional jump
        let dst = Register::from_raw(insn.dst_reg()).ok_or(BpfError::InvalidInstruction)?;
        let dst_val = regs.get(dst);

        let src_val = if matches!(SourceType::from_opcode(insn.opcode), SourceType::Reg) {
            let src = Register::from_raw(insn.src_reg()).ok_or(BpfError::InvalidInstruction)?;
            regs.get(src)
        } else {
            insn.imm as i64 as u64
        };

        // Truncate to 32 bits for 32-bit jumps
        let (dst_val, src_val) = if is_64bit {
            (dst_val, src_val)
        } else {
            ((dst_val as u32) as u64, (src_val as u32) as u64)
        };

        let condition = match jmp_op {
            JmpOp::Jeq => dst_val == src_val,
            JmpOp::Jgt => dst_val > src_val,
            JmpOp::Jge => dst_val >= src_val,
            JmpOp::Jlt => dst_val < src_val,
            JmpOp::Jle => dst_val <= src_val,
            JmpOp::Jset => (dst_val & src_val) != 0,
            JmpOp::Jne => dst_val != src_val,
            JmpOp::Jsgt => (dst_val as i64) > (src_val as i64),
            JmpOp::Jsge => (dst_val as i64) >= (src_val as i64),
            JmpOp::Jslt => (dst_val as i64) < (src_val as i64),
            JmpOp::Jsle => (dst_val as i64) <= (src_val as i64),
            _ => return Err(BpfError::InvalidInstruction),
        };

        if condition {
            Ok(InsnResult::Jump(insn.offset))
        } else {
            Ok(InsnResult::Continue)
        }
    }

    /// Execute a call instruction.
    fn execute_call(
        &self,
        insn: &BpfInsn,
        regs: &mut RegisterFile,
        ctx: &BpfContext<'_>,
        stack: &[u8],
    ) -> Result<InsnResult, BpfError> {
        let helper_id = insn.imm;

        // Get arguments from R1-R5
        let args = [
            regs.get(Register::R1),
            regs.get(Register::R2),
            regs.get(Register::R3),
            regs.get(Register::R4),
            regs.get(Register::R5),
        ];

        // Execute helper
        let result = self.call_helper(helper_id, args, ctx, stack)?;

        // Store result in R0
        regs.set(Register::R0, result);

        Ok(InsnResult::Continue)
    }

    /// Call a helper function.
    fn call_helper(
        &self,
        helper_id: i32,
        args: [u64; 5],
        ctx: &BpfContext<'_>,
        stack: &[u8],
    ) -> Result<u64, BpfError> {
        let Some(id) = HelperId::from_raw(helper_id) else {
            return Err(BpfError::InvalidHelper(helper_id));
        };
        let Some(runtime) = get_helper_descriptor(id).runtime() else {
            return Err(BpfError::InvalidHelper(helper_id));
        };

        // Integer registers retain addresses, not the live stack borrow's
        // provenance. Reconstruct stack-backed input pointers from this borrow
        // for the duration of the helper call. Other pointers retain the
        // existing verifier/map/context lifetime contract.
        let input_ptr = |addr: u64| {
            let start = stack.as_ptr().addr() as u64;
            match addr.checked_sub(start) {
                Some(offset) if offset <= stack.len() as u64 => {
                    stack.as_ptr().wrapping_add(offset as usize)
                }
                _ => addr as *const u8,
            }
        };

        // SAFETY: The helper contract requires live, in-bounds input buffers.
        // The reconstruction above restores stack provenance, not bounds or
        // initialization proofs for implicit map-key/value lengths; those remain
        // a separate verifier/helper obligation. Helpers consume input pointers
        // synchronously and must not retain them after returning.
        unsafe {
            match runtime {
                RuntimeHelper::KtimeGetNs => Ok(bpf_ktime_get_ns()),

                RuntimeHelper::GetInterruptLatencyNs => {
                    Ok(bpf_get_interrupt_latency_ns(ctx as *const BpfContext<'_>))
                }

                RuntimeHelper::GetBootTimeMs => {
                    Ok(bpf_get_boot_time_ms(ctx as *const BpfContext<'_>))
                }

                RuntimeHelper::GetKernelHeapKb => {
                    Ok(bpf_get_kernel_heap_kb(ctx as *const BpfContext<'_>))
                }

                RuntimeHelper::GetKernelImageMb => {
                    Ok(bpf_get_kernel_image_mb(ctx as *const BpfContext<'_>))
                }

                RuntimeHelper::TracePrintk => {
                    Ok(bpf_trace_printk(input_ptr(args[0]), args[1] as u32) as u64)
                }

                RuntimeHelper::MapLookupElem => {
                    Ok(bpf_map_lookup_elem(args[0] as u32, input_ptr(args[1])) as u64)
                }

                RuntimeHelper::MapUpdateElem => Ok(bpf_map_update_elem(
                    args[0] as u32,
                    input_ptr(args[1]),
                    input_ptr(args[2]),
                    args[3],
                ) as u64),

                RuntimeHelper::MapDeleteElem => {
                    Ok(bpf_map_delete_elem(args[0] as u32, input_ptr(args[1])) as u64)
                }

                RuntimeHelper::RingbufOutput => {
                    Ok(
                        bpf_ringbuf_output(args[0] as u32, input_ptr(args[1]), args[2], args[3])
                            as u64,
                    )
                }

                RuntimeHelper::TimeseriesPush => Ok(bpf_timeseries_push(
                    args[0] as u32,
                    input_ptr(args[1]),
                    input_ptr(args[2]),
                ) as u64),

                // Robotics Helpers
                // bpf_gpio_set (1003) -> bpf_gpio_write
                RuntimeHelper::GpioSet => Ok(bpf_gpio_write(args[0] as u32, args[1] as u32) as u64),

                // bpf_gpio_get (1004) -> bpf_gpio_read
                RuntimeHelper::GpioGet => Ok(bpf_gpio_read(args[0] as u32) as u64),

                RuntimeHelper::PwmWrite => {
                    Ok(bpf_pwm_write(args[0] as u32, args[1] as u32, args[2] as u32) as u64)
                }
                RuntimeHelper::MotorPairV1 => {
                    Ok(bpf_motor_pair_v1(args[0] as i32, args[1] as i32) as u64)
                }
            }
        }
    }

    /// Execute a load instruction.
    fn execute_load(
        &self,
        insn: &BpfInsn,
        regs: &mut RegisterFile,
        stack: &[u8],
        ctx: &BpfContext<'_>,
    ) -> Result<(), BpfError> {
        let dst = Register::from_raw(insn.dst_reg()).ok_or(BpfError::InvalidInstruction)?;
        let src = Register::from_raw(insn.src_reg()).ok_or(BpfError::InvalidInstruction)?;

        let size = MemSize::from_opcode(insn.opcode).ok_or(BpfError::InvalidInstruction)?;

        let base = regs.get(src);
        let addr = base
            .checked_add_signed(i64::from(insn.offset))
            .ok_or(BpfError::OutOfBounds)?;

        // Frame-pointer copies are stack accesses too. Access through the live
        // slice instead of an integer-derived pointer invalidated by reborrows.
        if let Some(stack_idx) = stack_access_offset(stack, base, addr, size.size_bytes())? {
            let value = match size {
                MemSize::Byte => stack[stack_idx] as u64,
                MemSize::Half => {
                    let bytes: [u8; 2] = stack[stack_idx..stack_idx + 2]
                        .try_into()
                        .map_err(|_| BpfError::OutOfBounds)?;
                    u16::from_ne_bytes(bytes) as u64
                }
                MemSize::Word => {
                    let bytes: [u8; 4] = stack[stack_idx..stack_idx + 4]
                        .try_into()
                        .map_err(|_| BpfError::OutOfBounds)?;
                    u32::from_ne_bytes(bytes) as u64
                }
                MemSize::DWord => {
                    let bytes: [u8; 8] = stack[stack_idx..stack_idx + 8]
                        .try_into()
                        .map_err(|_| BpfError::OutOfBounds)?;
                    u64::from_ne_bytes(bytes)
                }
            };

            regs.set(dst, value);
            return Ok(());
        }

        // 2. Context access
        // Check if address is within the BpfContext struct
        let ctx_addr = ctx as *const _ as u64;
        let ctx_size = core::mem::size_of::<BpfContext<'_>>() as u64;

        if addr >= ctx_addr && addr + size.size_bytes() as u64 <= ctx_addr + ctx_size {
            // SAFETY: We verified the address and size are within the bounds of the context struct.
            // read_unaligned is used because BPF allows unaligned accesses.
            let value = unsafe {
                match size {
                    MemSize::Byte => core::ptr::read_unaligned(addr as *const u8) as u64,
                    MemSize::Half => core::ptr::read_unaligned(addr as *const u16) as u64,
                    MemSize::Word => core::ptr::read_unaligned(addr as *const u32) as u64,
                    MemSize::DWord => core::ptr::read_unaligned(addr as *const u64),
                }
            };
            regs.set(dst, value);
            return Ok(());
        }

        // 3. Data access
        // Check if address is within [ctx.data, ctx.data_end)
        let data_start = ctx.data_ptr() as u64;
        let data_end = ctx.data_end_ptr() as u64;

        if !ctx.data_ptr().is_null()
            && addr >= data_start
            && addr + size.size_bytes() as u64 <= data_end
        {
            // SAFETY: We verified the address and size are within the valid data range [data, data_end).
            // read_unaligned is used because packet data may be unaligned.
            let value = unsafe {
                match size {
                    MemSize::Byte => core::ptr::read_unaligned(addr as *const u8) as u64,
                    MemSize::Half => core::ptr::read_unaligned(addr as *const u16) as u64,
                    MemSize::Word => core::ptr::read_unaligned(addr as *const u32) as u64,
                    MemSize::DWord => core::ptr::read_unaligned(addr as *const u64),
                }
            };
            regs.set(dst, value);
            return Ok(());
        }

        // 4. Generic pointer dereference (e.g., map value pointers from bpf_map_lookup_elem)
        //
        // BPF helpers like bpf_map_lookup_elem return raw pointers to map values.
        // After verification, these pointers are trusted. We allow reads through any
        // non-null pointer that didn't match the above categories.
        if addr != 0 {
            // SAFETY: Verification bounds map-value accesses; the execution's
            // captured map bindings and leases keep their storage live and
            // exclusively available until execution returns.
            let value = unsafe {
                match size {
                    MemSize::Byte => core::ptr::read_unaligned(addr as *const u8) as u64,
                    MemSize::Half => core::ptr::read_unaligned(addr as *const u16) as u64,
                    MemSize::Word => core::ptr::read_unaligned(addr as *const u32) as u64,
                    MemSize::DWord => core::ptr::read_unaligned(addr as *const u64),
                }
            };
            regs.set(dst, value);
            return Ok(());
        }

        Err(BpfError::OutOfBounds)
    }

    /// Execute a store instruction.
    fn execute_store(
        &self,
        insn: &BpfInsn,
        regs: &RegisterFile,
        stack: &mut [u8],
    ) -> Result<(), BpfError> {
        let dst = Register::from_raw(insn.dst_reg()).ok_or(BpfError::InvalidInstruction)?;
        let class = insn.class().ok_or(BpfError::InvalidInstruction)?;

        let value = if matches!(class, OpcodeClass::St) {
            // Store immediate
            insn.imm as i64 as u64
        } else {
            // Store register
            let src = Register::from_raw(insn.src_reg()).ok_or(BpfError::InvalidInstruction)?;
            regs.get(src)
        };

        let size = MemSize::from_opcode(insn.opcode).ok_or(BpfError::InvalidInstruction)?;

        let base = regs.get(dst);
        let addr = base
            .checked_add_signed(i64::from(insn.offset))
            .ok_or(BpfError::OutOfBounds)?;

        if let Some(stack_idx) = stack_access_offset(stack, base, addr, size.size_bytes())? {
            match size {
                MemSize::Byte => {
                    stack[stack_idx] = value as u8;
                }
                MemSize::Half => {
                    let bytes = (value as u16).to_ne_bytes();
                    stack[stack_idx..stack_idx + 2].copy_from_slice(&bytes);
                }
                MemSize::Word => {
                    let bytes = (value as u32).to_ne_bytes();
                    stack[stack_idx..stack_idx + 4].copy_from_slice(&bytes);
                }
                MemSize::DWord => {
                    let bytes = value.to_ne_bytes();
                    stack[stack_idx..stack_idx + 8].copy_from_slice(&bytes);
                }
            }
            return Ok(());
        }

        // Generic pointer store (e.g., map value pointers from bpf_map_lookup_elem)
        //
        // BPF helpers return raw pointers to map values that programs can write through.
        // After verification, these pointers are trusted.
        if addr != 0 {
            // SAFETY: The BPF verifier (or program construction) ensures the pointer
            // is valid. Map value pointers are stable for the duration of BPF execution.
            unsafe {
                match size {
                    MemSize::Byte => core::ptr::write_unaligned(addr as *mut u8, value as u8),
                    MemSize::Half => core::ptr::write_unaligned(addr as *mut u16, value as u16),
                    MemSize::Word => core::ptr::write_unaligned(addr as *mut u32, value as u32),
                    MemSize::DWord => core::ptr::write_unaligned(addr as *mut u64, value),
                }
            }
            return Ok(());
        }

        Err(BpfError::OutOfBounds)
    }
}

/// Identify stack addresses, including R10's one-past-end value. If either
/// the base or effective address belongs to the stack, an invalid range must
/// fail here rather than falling through to a generic raw-pointer access.
fn stack_access_offset(
    stack: &[u8],
    base: u64,
    addr: u64,
    size: usize,
) -> Result<Option<usize>, BpfError> {
    let start = stack.as_ptr().addr() as u64;
    let end = start + stack.len() as u64;
    if !(start..=end).contains(&base) && !(start..=end).contains(&addr) {
        return Ok(None);
    }
    let offset = addr.checked_sub(start).ok_or(BpfError::OutOfBounds)?;
    if offset > stack.len() as u64 || size as u64 > stack.len() as u64 - offset {
        return Err(BpfError::OutOfBounds);
    }
    Ok(Some(offset as usize))
}

impl<P: PhysicalProfile> Default for Interpreter<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: PhysicalProfile> Interpreter<P> {
    /// Execute a program using a caller-provided stack buffer, allocating
    /// nothing on the hot path.
    ///
    /// `stack` must be at least `P::MAX_STACK_SIZE` bytes; the leading
    /// `MAX_STACK_SIZE` bytes are zeroed and used as the BPF stack frame. This
    /// is the form the kernel's per-hook execution path calls so that no heap
    /// allocation lands on an interrupt/real-time path — a heap allocation
    /// there is both WCET-unsound (the admitted cycle bound does not model
    /// allocator latency) and, in IRQ context, a deadlock hazard against the
    /// global heap lock. See issue #181.
    pub fn execute_with_stack(
        &self,
        program: &BpfProgram<P>,
        ctx: &BpfContext<'_>,
        stack: &mut [u8],
    ) -> BpfResult {
        let insns = program.instructions();

        if insns.is_empty() {
            return Err(BpfError::NotLoaded);
        }

        if stack.len() < P::MAX_STACK_SIZE {
            return Err(BpfError::OutOfBounds);
        }
        let stack = &mut stack[..P::MAX_STACK_SIZE];
        let used_stack_start = P::MAX_STACK_SIZE - program.stack_size();
        stack[used_stack_start..].fill(0);

        // Initialize register file
        let mut regs = RegisterFile::new();

        // R1 = context pointer
        regs.set(Register::R1, ctx as *const _ as u64);

        // R10 = frame pointer (top of stack)
        let fp = stack.as_ptr() as u64 + P::MAX_STACK_SIZE as u64;
        // SAFETY: We are initializing the frame pointer R10 with a valid stack address.
        // The stack slice is live for the duration of this call.
        unsafe {
            regs.set_unchecked(Register::R10, fp);
        }

        // Execute
        let mut pc = 0usize;
        let mut insn_count = 0usize;
        let insn_limit = P::MAX_INSN_COUNT;

        loop {
            // Check bounds
            if pc >= insns.len() {
                return Err(BpfError::OutOfBounds);
            }

            // Check instruction limit
            insn_count += 1;
            if insn_count > insn_limit {
                return Err(BpfError::Timeout);
            }

            let insn = &insns[pc];

            // Handle wide instruction
            if insn.is_wide() {
                if pc + 1 >= insns.len() {
                    return Err(BpfError::InvalidInstruction);
                }
                let next_insn = &insns[pc + 1];
                let imm64 = (insn.imm as u32 as u64) | ((next_insn.imm as u32 as u64) << 32);

                let dst = Register::from_raw(insn.dst_reg()).ok_or(BpfError::InvalidInstruction)?;
                regs.set(dst, imm64);

                pc += 2;
                continue;
            }

            // Execute instruction
            match self.execute_insn(insn, &mut regs, stack, ctx)? {
                InsnResult::Continue => {
                    pc += 1;
                }
                InsnResult::Jump(offset) => {
                    pc = ((pc as i64) + 1 + (offset as i64)) as usize;
                }
                InsnResult::Exit => {
                    return Ok(regs.return_value());
                }
                InsnResult::WideLoad => {
                    // Handled above, shouldn't reach here
                    return Err(BpfError::InvalidInstruction);
                }
            }
        }
    }
}

impl<P: PhysicalProfile> BpfExecutor<P> for Interpreter<P> {
    /// Convenience entry point that allocates a fresh stack per call.
    ///
    /// Suitable for tests, benchmarks, and any cold path. The kernel's hot
    /// execution path calls [`Interpreter::execute_with_stack`] with a reused
    /// buffer instead — see #181.
    fn execute(&self, program: &BpfProgram<P>, ctx: &BpfContext<'_>) -> BpfResult {
        let mut stack = vec![0u8; P::MAX_STACK_SIZE];
        self.execute_with_stack(program, ctx, &mut stack)
    }
}

/// Result of executing a single instruction.
enum InsnResult {
    /// Continue to next instruction
    Continue,
    /// Jump by offset
    Jump(i16),
    /// Program exit
    Exit,
    /// Wide load (64-bit immediate)
    WideLoad,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::program::{BpfProgType, ProgramBuilder};
    use crate::execution::helpers_stub;

    #[test]
    fn ensure_stubs_linked() {
        // Explicitly reference a stub to ensure the module and its no_mangle symbols
        // are not optimized away by the linker during host tests.
        assert_eq!(helpers_stub::bpf_ktime_get_ns(), 0);
    }

    #[test]
    fn execute_simple_program() {
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 42)) // r0 = 42
            .exit()
            .build()
            .expect("valid program");

        let interpreter = Interpreter::<ActiveProfile>::new();
        let ctx = BpfContext::empty();

        let result = interpreter.execute(&program, &ctx);
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn execute_with_stack_matches_execute_and_rejects_small_buffer() {
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 42))
            .exit()
            .build()
            .expect("valid program");
        let interpreter = Interpreter::<ActiveProfile>::new();
        let ctx = BpfContext::empty();

        // A caller-provided, reusable buffer gives the same result as the
        // allocating path — and a reused buffer stays correct across fires (#181).
        let mut stack = vec![0u8; ActiveProfile::MAX_STACK_SIZE];
        assert_eq!(
            interpreter.execute_with_stack(&program, &ctx, &mut stack),
            Ok(42)
        );
        assert_eq!(
            interpreter.execute_with_stack(&program, &ctx, &mut stack),
            Ok(42)
        );
        assert_eq!(interpreter.execute(&program, &ctx), Ok(42));

        // A stack-free verified program must not clear unrelated scratch bytes.
        let mut untouched = vec![0xa5; ActiveProfile::MAX_STACK_SIZE];
        assert_eq!(
            interpreter.execute_with_stack(&program, &ctx, &mut untouched),
            Ok(42)
        );
        assert!(untouched.iter().all(|byte| *byte == 0xa5));

        // Clearing is limited to the verifier-recorded suffix while preserving
        // the fixed top-of-stack address used by R10.
        let stack_program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::new(0x7a, 10, 0, -16, 42))
            .insn(BpfInsn::mov64_imm(0, 0))
            .exit()
            .build()
            .expect("valid stack program");
        assert_eq!(stack_program.stack_size(), 16);
        let mut reused = vec![0xa5; ActiveProfile::MAX_STACK_SIZE];
        let cleared_from = ActiveProfile::MAX_STACK_SIZE - stack_program.stack_size();
        assert_eq!(
            interpreter.execute_with_stack(&stack_program, &ctx, &mut reused),
            Ok(0)
        );
        assert!(reused[..cleared_from].iter().all(|byte| *byte == 0xa5));
        assert_eq!(
            &reused[cleared_from..cleared_from + 8],
            &42i64.to_ne_bytes()
        );
        assert!(reused[cleared_from + 8..].iter().all(|byte| *byte == 0));

        // An undersized buffer is refused, not a UB write past the end.
        let mut small = vec![0u8; ActiveProfile::MAX_STACK_SIZE - 1];
        assert_eq!(
            interpreter.execute_with_stack(&program, &ctx, &mut small),
            Err(BpfError::OutOfBounds)
        );
    }

    #[test]
    fn copied_stack_pointer_rejects_out_of_bounds_access() {
        let interpreter = Interpreter::<ActiveProfile>::new();
        let mut stack = [0u8; 16];
        let start = stack.as_ptr().addr() as u64;
        let end = start + stack.len() as u64;
        let ctx = BpfContext::empty();
        let mut regs = RegisterFile::new();
        regs.set(Register::R7, 42);
        for (base, offset) in [(start, -1), (end, 0), (end, -7), (end, 1)] {
            regs.set(Register::R6, base);
            assert_eq!(
                interpreter.execute_load(
                    &BpfInsn::new(0x79, 0, 6, offset, 0),
                    &mut regs,
                    &stack,
                    &ctx
                ),
                Err(BpfError::OutOfBounds)
            );
            assert_eq!(
                interpreter.execute_store(&BpfInsn::new(0x7b, 6, 7, offset, 0), &regs, &mut stack),
                Err(BpfError::OutOfBounds)
            );
            assert_eq!(stack, [0; 16]);
        }
        for base in [0, u64::MAX] {
            regs.set(Register::R6, base);
            let offset = if base == 0 { -1 } else { 1 };
            assert_eq!(
                interpreter.execute_load(
                    &BpfInsn::new(0x79, 0, 6, offset, 0),
                    &mut regs,
                    &stack,
                    &ctx
                ),
                Err(BpfError::OutOfBounds)
            );
            assert_eq!(
                interpreter.execute_store(&BpfInsn::new(0x7b, 6, 7, offset, 0), &regs, &mut stack),
                Err(BpfError::OutOfBounds)
            );
        }
        for (base, offset) in [(start, 0), (end, -8)] {
            regs.set(Register::R6, base);
            interpreter
                .execute_store(&BpfInsn::new(0x7b, 6, 7, offset, 0), &regs, &mut stack)
                .unwrap();
            interpreter
                .execute_load(
                    &BpfInsn::new(0x79, 0, 6, offset, 0),
                    &mut regs,
                    &stack,
                    &ctx,
                )
                .unwrap();
            assert_eq!(regs.get(Register::R0), 42);
        }
    }

    #[test]
    fn copied_stack_pointer_roundtrip_all_widths() {
        for (store, load, store_reg, expected) in [
            (0x72, 0x71, 0x73, 43),
            (0x6a, 0x69, 0x6b, 43),
            (0x62, 0x61, 0x63, 43),
            (0x7a, 0x79, 0x7b, 43),
        ] {
            let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
                .insn(BpfInsn::new(store, 10, 0, -15, 42))
                .insn(BpfInsn::mov64_reg(6, 10))
                .insn(BpfInsn::add64_imm(6, -15))
                .insn(BpfInsn::new(load, 7, 6, 0, 0))
                .insn(BpfInsn::add64_imm(7, 1))
                .insn(BpfInsn::new(store_reg, 6, 7, 0, 0))
                .insn(BpfInsn::new(load, 0, 10, -15, 0))
                .exit()
                .build()
                .expect("verified unaligned stack access through a copied frame pointer");
            let mut stack = vec![0; ActiveProfile::MAX_STACK_SIZE];
            for _ in 0..2 {
                assert_eq!(
                    Interpreter::<ActiveProfile>::new().execute_with_stack(
                        &program,
                        &BpfContext::empty(),
                        &mut stack
                    ),
                    Ok(expected)
                );
            }
        }
    }

    #[test]
    fn execute_arithmetic() {
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 10)) // r0 = 10
            .insn(BpfInsn::add64_imm(0, 5)) // r0 += 5
            .insn(BpfInsn::mov64_imm(1, 3)) // r1 = 3
            .insn(BpfInsn::add64_reg(0, 1)) // r0 += r1
            .exit()
            .build()
            .expect("valid program");

        let interpreter = Interpreter::<ActiveProfile>::new();
        let ctx = BpfContext::empty();

        let result = interpreter.execute(&program, &ctx);
        assert_eq!(result, Ok(18)); // 10 + 5 + 3 = 18
    }

    #[test]
    fn execute_conditional_jump() {
        // if r0 == 0, return 1, else return 2
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 0)) // r0 = 0
            .insn(BpfInsn::jeq_imm(0, 0, 2)) // if r0 == 0, skip 2
            .insn(BpfInsn::mov64_imm(0, 2)) // r0 = 2 (skipped)
            .insn(BpfInsn::ja(1)) // skip next
            .insn(BpfInsn::mov64_imm(0, 1)) // r0 = 1
            .exit()
            .build()
            .expect("valid program");

        let interpreter = Interpreter::<ActiveProfile>::new();
        let ctx = BpfContext::empty();

        let result = interpreter.execute(&program, &ctx);
        assert_eq!(result, Ok(1));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Too slow under Miri - tests instruction limit timeout
    fn execute_timeout() {
        // Infinite loop (would timeout)
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 0)) // r0 = 0
            .insn(BpfInsn::ja(-1)) // infinite loop
            .exit()
            .build();

        #[cfg(feature = "embedded-profile")]
        {
            assert!(program.is_err());
            return;
        }

        #[cfg(feature = "cloud-profile")]
        let program = program.expect("cloud profile permits loops with a runtime limit");

        #[cfg(feature = "cloud-profile")]
        let interpreter = Interpreter::<ActiveProfile>::new();
        #[cfg(feature = "cloud-profile")]
        let ctx = BpfContext::empty();

        #[cfg(feature = "cloud-profile")]
        let result = interpreter.execute(&program, &ctx);
        #[cfg(feature = "cloud-profile")]
        assert_eq!(result, Err(BpfError::Timeout));
    }

    #[test]
    fn verifier_rejects_division_by_zero_before_execution() {
        let result = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(0, 10)) // r0 = 10
            .insn(BpfInsn::mov64_imm(1, 0)) // r1 = 0
            .insn(BpfInsn::new(0x3f, 0, 1, 0, 0)) // r0 /= r1
            .exit()
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn execute_map_lookup_helper() {
        // Test that calling bpf_map_lookup_elem helper works
        // Helper 3 = bpf_map_lookup_elem(map_id, key_ptr) -> value_ptr
        helpers_stub::reset_test_map();

        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::new(0x7a, 10, 0, -8, 0)) // *(u64 *)(r10 - 8) = key
            .insn(BpfInsn::mov64_imm(1, 0)) // r1 = map_id (0)
            .insn(BpfInsn::mov64_reg(2, 10))
            .insn(BpfInsn::add64_imm(2, -8)) // r2 = &key
            .insn(BpfInsn::call(5)) // r0 = bpf_map_lookup_elem(r1, r2)
            .exit()
            .build()
            .expect("valid program");

        let interpreter = Interpreter::<ActiveProfile>::new();
        let ctx = BpfContext::empty();

        let result = interpreter.execute(&program, &ctx);
        // Result should be a non-null pointer (the address of TEST_MAP_VALUE)
        assert!(result.is_ok());
        assert_ne!(result.unwrap(), 0);
    }

    /// # Miri safety contract
    ///
    /// The helper must read the actual stack payload, with a pointer valid
    /// through its call. A stub that stores the pointer's numeric address
    /// instead of reading it would hide interpreter aliasing failures.
    #[test]
    fn execute_map_update_helper() {
        // Test that calling bpf_map_update_elem helper works
        // Helper 4 = bpf_map_update_elem(map_id, key_ptr, value_ptr, flags) -> result
        helpers_stub::reset_test_map();
        assert_eq!(helpers_stub::get_test_map_value(), 0);

        // We need to put a value on the stack and pass its pointer
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::new(0x7a, 10, 0, -8, 0)) // key
            .insn(BpfInsn::new(0x7a, 10, 0, -16, 42)) // value
            .insn(BpfInsn::mov64_imm(1, 0)) // r1 = map_id (0)
            .insn(BpfInsn::mov64_reg(2, 10))
            .insn(BpfInsn::add64_imm(2, -8)) // r2 = &key
            .insn(BpfInsn::mov64_reg(3, 10))
            .insn(BpfInsn::add64_imm(3, -16)) // r3 = &value
            .insn(BpfInsn::mov64_imm(4, 0)) // r4 = flags (0)
            .insn(BpfInsn::call(6)) // r0 = bpf_map_update_elem(r1, r2, r3, r4)
            .exit()
            .build()
            .expect("valid program");

        let interpreter = Interpreter::<ActiveProfile>::new();
        let ctx = BpfContext::empty();

        let result = interpreter.execute(&program, &ctx);
        // Helper should return 0 on success
        assert_eq!(result, Ok(0));
        assert_eq!(helpers_stub::get_test_map_value(), 42);
    }

    #[test]
    fn execute_map_delete_helper() {
        // Test that calling bpf_map_delete_elem helper works
        // Helper 5 = bpf_map_delete_elem(map_id, key_ptr) -> result
        helpers_stub::reset_test_map();

        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::new(0x7a, 10, 0, -8, 0)) // key
            .insn(BpfInsn::mov64_imm(1, 0)) // r1 = map_id (0)
            .insn(BpfInsn::mov64_reg(2, 10))
            .insn(BpfInsn::add64_imm(2, -8)) // r2 = &key
            .insn(BpfInsn::call(7)) // r0 = bpf_map_delete_elem(r1, r2)
            .exit()
            .build()
            .expect("valid program");

        let interpreter = Interpreter::<ActiveProfile>::new();
        let ctx = BpfContext::empty();

        let result = interpreter.execute(&program, &ctx);
        // Helper should return 0 on success
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn execute_gpio_helper() {
        // Test that calling bpf_gpio_write helper works
        // Helper 1003 = bpf_gpio_write(pin, value) -> result

        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::mov64_imm(1, 17)) // r1 = pin 17
            .insn(BpfInsn::mov64_imm(2, 1)) // r2 = value 1
            .insn(BpfInsn::call(1003)) // r0 = bpf_gpio_write(r1, r2)
            .exit()
            .build_raw()
            .verify_with_config(crate::verifier::VerifyConfig {
                allow_actuation: true,
                ..crate::verifier::VerifyConfig::default()
            })
            .expect("valid program");

        let interpreter = Interpreter::<ActiveProfile>::new();
        let ctx = BpfContext::empty();

        let result = interpreter.execute(&program, &ctx);
        // Helper stub returns 0
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn execute_latency_helper() {
        let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
            .insn(BpfInsn::call(13)) // r0 = bpf_get_interrupt_latency_ns(r1)
            .exit()
            .build()
            .expect("valid program");

        let interpreter = Interpreter::<ActiveProfile>::new();
        let mut ctx = BpfContext::empty();
        ctx.set_interrupt_latency_ns(12345);

        let result = interpreter.execute(&program, &ctx);
        assert_eq!(result, Ok(12345));
    }
}
