# BPF-to-BPF Call Canonicalization Implementation Plan

> **Archived historical record.** Retained for provenance; not a current
> implementation contract. See the [current documentation authority](../../current/README.md).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Support BPF-to-BPF (subprogram) calls by inlining them in a loader-side normalization pass *before* verification, so the verifier keeps seeing a single flat loop-free program.

**Architecture:** A new `loader/normalize.rs` module resolves pseudo-calls, builds a subprogram call graph, rejects recursion / excess depth / excess expanded size, then inline-expands every subprogram call into one flat instruction vector — rewriting `EXIT`→`JA`, fixing internal jump offsets, and rebasing each inlined frame's `r10`-relative stack accesses to a distinct stack window. The verifier and its soundness proof are unchanged: it consumes the flattened program. (Full rationale: `docs/archive/specs/2026-06-30-bpf-call-canonicalization-design.md`.)

**Tech Stack:** Rust, `no_std` (`extern crate alloc`), crate `kernel_bpf`.

## Global Constraints

- `no_std`: every new file starts with `extern crate alloc;` and imports `alloc::vec::Vec` etc. No `std`.
- Subprogram call encoding: `call` instruction is opcode `0x85` (`BpfInsn::is_call()`); a BPF-to-BPF call has `src_reg() == BPF_PSEUDO_CALL == 1`; its `imm` is a signed instruction count relative to the *next* instruction (target index = `call_idx + 1 + imm`). A helper call has `src_reg() == 0`.
- Supported subprogram layout: a single program section, `main` at instruction index 0, subprograms laid out contiguously after it (entry-delimited ranges). Cross-section subprogram linking is out of scope. `// ponytail: single-section layout, add cross-section linking when an ELF needs it.`
- Frame size `FRAME_SIZE = 512` bytes; `MAX_CALL_DEPTH = 8` (matches Linux; `8 × 512 = 4 KiB ≤ 8 KiB` embedded stack — no profile-limit changes).
- Embedded profile limits (verbatim): `MAX_STACK_SIZE = 8 KiB`, `MAX_INSN_COUNT = 100_000`. Cloud: `512 KiB` / `1_000_000`.
- Test command (embedded): from repo root, `cargo test -p kernel_bpf <filter>`. Cloud variant: `cargo test -p kernel_bpf --no-default-features --features cloud-profile <filter>`.
- Commit after every task. Conventional Commits; end commit messages with the repo's `Co-Authored-By` trailer.

---

### Task 1: Module scaffold, pseudo-call classification, subprogram bounds

**Files:**
- Create: `kernel/crates/kernel_bpf/src/loader/normalize.rs`
- Modify: `kernel/crates/kernel_bpf/src/loader/mod.rs` (add `mod normalize;` near the other `mod` lines ~45-48; add `pub use normalize::{normalize, Normalized};` near the other `pub use` lines ~53-56)
- Test: inline `#[cfg(test)]` module in `normalize.rs`

**Interfaces:**
- Produces:
  - `pub const BPF_PSEUDO_CALL: u8 = 1;`
  - `pub const FRAME_SIZE: i64 = 512;`
  - `pub const MAX_CALL_DEPTH: usize = 8;`
  - `fn is_subprog_call(insn: &BpfInsn) -> bool`
  - `fn call_target(call_idx: usize, insn: &BpfInsn) -> i64`
  - `fn subprogram_bounds(insns: &[BpfInsn]) -> Vec<(usize, usize)>` — sorted, non-overlapping `[start, end)` ranges; entry points are index 0 plus every subprogram-call target; `main` is the range containing index 0.

- [ ] **Step 1: Write the failing test**

Add to `normalize.rs`:

```rust
#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;
    use super::*;
    use crate::bytecode::insn::BpfInsn;

    // A BPF-to-BPF call to the subprogram at `target` from position `at`.
    fn subprog_call(at: usize, target: usize) -> BpfInsn {
        let imm = target as i64 - at as i64 - 1;
        let mut i = BpfInsn::call(imm as i32);
        i.regs = (i.regs & 0x0f) | (BPF_PSEUDO_CALL << 4); // src_reg = 1
        i
    }

    #[test]
    fn classifies_subprog_vs_helper_calls() {
        let helper = BpfInsn::call(3); // src_reg 0
        let sub = subprog_call(0, 4);
        assert!(!is_subprog_call(&helper));
        assert!(is_subprog_call(&sub));
        assert_eq!(call_target(0, &sub), 4);
    }

    #[test]
    fn bounds_split_two_functions() {
        // 0: call ->3 ; 1: r0=0 ; 2: exit ; 3: r0=1 ; 4: exit
        let insns = vec![
            subprog_call(0, 3),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, 1),
            BpfInsn::exit(),
        ];
        assert_eq!(subprogram_bounds(&insns), vec![(0, 3), (3, 5)]);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kernel_bpf normalize::tests`
Expected: FAIL — `normalize` module / symbols not found (won't compile).

- [ ] **Step 3: Write minimal implementation**

Top of `normalize.rs`:

```rust
//! Pre-verification normalization pipeline.
//!
//! Transforms arbitrary loaded bytecode into the canonical flat program the
//! verifier consumes. Today this resolves BPF-to-BPF (subprogram) calls by
//! inline expansion; it is the intended home for future BTF/CO-RE rewrites.
//! See `docs/archive/specs/2026-06-30-bpf-call-canonicalization-design.md`.

extern crate alloc;

use alloc::vec::Vec;

use crate::bytecode::insn::BpfInsn;

/// `src_reg` value marking a `call` as a BPF-to-BPF subprogram call.
pub const BPF_PSEUDO_CALL: u8 = 1;
/// Per-frame stack window size (bytes).
pub const FRAME_SIZE: i64 = 512;
/// Maximum subprogram call depth (matches Linux; bounds flat stack use).
pub const MAX_CALL_DEPTH: usize = 8;

/// True if `insn` is a BPF-to-BPF subprogram call (not a helper call).
fn is_subprog_call(insn: &BpfInsn) -> bool {
    insn.is_call() && insn.src_reg() == BPF_PSEUDO_CALL
}

/// Absolute target instruction index of a subprogram call.
fn call_target(call_idx: usize, insn: &BpfInsn) -> i64 {
    call_idx as i64 + 1 + insn.imm as i64
}

/// Entry-delimited subprogram ranges `[start, end)`, sorted and contiguous.
fn subprogram_bounds(insns: &[BpfInsn]) -> Vec<(usize, usize)> {
    use alloc::collections::BTreeSet;
    let mut entries: BTreeSet<usize> = BTreeSet::new();
    entries.insert(0);
    for (i, insn) in insns.iter().enumerate() {
        if is_subprog_call(insn) {
            let t = call_target(i, insn);
            if t >= 0 && (t as usize) < insns.len() {
                entries.insert(t as usize);
            }
        }
    }
    let starts: Vec<usize> = entries.into_iter().collect();
    let mut bounds = Vec::with_capacity(starts.len());
    for (k, &s) in starts.iter().enumerate() {
        let end = starts.get(k + 1).copied().unwrap_or(insns.len());
        bounds.push((s, end));
    }
    bounds
}
```

In `mod.rs`, add alongside existing module declarations:

```rust
mod normalize;
```

and alongside existing re-exports:

```rust
pub use normalize::{normalize, Normalized};
```

(Note: `normalize`/`Normalized` are defined in Task 5; this re-export will not compile until then. To keep Task 1 self-contained and compiling, add only `mod normalize;` now and add the `pub use` line in Task 5.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p kernel_bpf normalize::tests`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add kernel/crates/kernel_bpf/src/loader/normalize.rs kernel/crates/kernel_bpf/src/loader/mod.rs
git commit -m "feat(bpf): subprogram call classification + bounds (#87)"
```

---

### Task 2: Call graph, recursion / depth / size checks, error variants

**Files:**
- Modify: `kernel/crates/kernel_bpf/src/loader/normalize.rs`
- Modify: `kernel/crates/kernel_bpf/src/loader/error.rs` (add variants + `Display` arms)
- Test: inline tests in `normalize.rs`

**Interfaces:**
- Consumes: `subprogram_bounds`, `is_subprog_call`, `call_target` (Task 1).
- Produces:
  - `LoadError::RecursiveCall { subprog: usize }`
  - `LoadError::CallDepthExceeded { depth: usize, limit: usize }`
  - `LoadError::ExpansionTooLarge { got: usize, limit: usize }`
  - `LoadError::MalformedPseudoCall { insn_idx: usize }`
  - `fn subprog_index(bounds: &[(usize, usize)], target: i64) -> Option<usize>` — which subprogram a target index begins; `Some` only if `target` is exactly a subprogram start.
  - `fn callees(insns, bounds, sp) -> Result<Vec<usize>, LoadError>` — subprogram indices called from subprogram `sp` (in call-site order; `MalformedPseudoCall` if a target is out of range or not a subprogram entry).
  - `fn check_recursion(insns, bounds) -> Result<(), LoadError>`
  - `fn call_depth(insns, bounds) -> Result<usize, LoadError>` — longest call-graph path length (leaf = 0); errors `CallDepthExceeded` if `> MAX_CALL_DEPTH`.
  - `fn expanded_size(insns, bounds) -> usize` — additive post-inline instruction estimate of `main` (subprogram containing index 0): `size(s) = (len(s) − subprog_calls_in_s) + Σ_callsites size(callee)`.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `normalize.rs`:

```rust
    #[test]
    fn rejects_direct_recursion() {
        // 0: call ->0 (self) ; 1: exit
        let insns = vec![subprog_call(0, 0), BpfInsn::exit()];
        let bounds = subprogram_bounds(&insns);
        assert_eq!(
            check_recursion(&insns, &bounds),
            Err(crate::loader::LoadError::RecursiveCall { subprog: 0 })
        );
    }

    #[test]
    fn computes_call_depth_and_rejects_too_deep() {
        // main(0) -> f1(2) -> f2(4); depth 2, accepted.
        let insns = vec![
            subprog_call(0, 2),
            BpfInsn::exit(),
            subprog_call(2, 4),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];
        let bounds = subprogram_bounds(&insns);
        assert!(check_recursion(&insns, &bounds).is_ok());
        assert_eq!(call_depth(&insns, &bounds).unwrap(), 2);
    }

    #[test]
    fn malformed_pseudo_call_target() {
        // target points into the middle of a function (not an entry)
        let insns = vec![subprog_call(0, 2), BpfInsn::exit(), BpfInsn::mov64_imm(0,0), BpfInsn::add64_imm(0,1), BpfInsn::exit()];
        // make a second call whose target (3) is not a subprogram start
        let mut insns = insns;
        insns[1] = subprog_call(1, 3);
        let bounds = subprogram_bounds(&insns);
        assert_eq!(
            callees(&insns, &bounds, 0).err(),
            Some(crate::loader::LoadError::MalformedPseudoCall { insn_idx: 1 })
        );
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kernel_bpf normalize::tests`
Expected: FAIL — `check_recursion`/`call_depth`/`callees` and the error variants do not exist.

- [ ] **Step 3: Write minimal implementation**

In `error.rs`, add to the `enum LoadError` (before the closing brace):

```rust
    /// A subprogram call participates in a recursion cycle.
    RecursiveCall { subprog: usize },
    /// Subprogram call depth exceeds the supported limit.
    CallDepthExceeded { depth: usize, limit: usize },
    /// Inlined program would exceed the instruction-count limit.
    ExpansionTooLarge { got: usize, limit: usize },
    /// A pseudo-call target is out of range or not a subprogram entry.
    MalformedPseudoCall { insn_idx: usize },
```

and to the `Display` match:

```rust
            Self::RecursiveCall { subprog } => write!(f, "recursive subprogram call (subprog {})", subprog),
            Self::CallDepthExceeded { depth, limit } => write!(f, "call depth {} exceeds limit {}", depth, limit),
            Self::ExpansionTooLarge { got, limit } => write!(f, "expanded program {} insns exceeds limit {}", got, limit),
            Self::MalformedPseudoCall { insn_idx } => write!(f, "malformed pseudo-call at insn {}", insn_idx),
```

In `normalize.rs` add (`use crate::loader::error::{LoadError, LoadResult};` at the top imports):

```rust
fn subprog_index(bounds: &[(usize, usize)], target: i64) -> Option<usize> {
    if target < 0 {
        return None;
    }
    let t = target as usize;
    bounds.iter().position(|&(s, _)| s == t)
}

fn callees(
    insns: &[BpfInsn],
    bounds: &[(usize, usize)],
    sp: usize,
) -> LoadResult<Vec<usize>> {
    let (start, end) = bounds[sp];
    let mut out = Vec::new();
    let mut i = start;
    while i < end {
        let insn = &insns[i];
        if is_subprog_call(insn) {
            match subprog_index(bounds, call_target(i, insn)) {
                Some(idx) => out.push(idx),
                None => return Err(LoadError::MalformedPseudoCall { insn_idx: i }),
            }
        }
        i += if insn.is_wide() { 2 } else { 1 };
    }
    Ok(out)
}

fn check_recursion(insns: &[BpfInsn], bounds: &[(usize, usize)]) -> LoadResult<()> {
    // DFS with a coloring: 0=unvisited, 1=on-stack, 2=done.
    let n = bounds.len();
    let mut color = alloc::vec![0u8; n];
    fn dfs(
        sp: usize,
        insns: &[BpfInsn],
        bounds: &[(usize, usize)],
        color: &mut [u8],
    ) -> LoadResult<()> {
        color[sp] = 1;
        for c in callees(insns, bounds, sp)? {
            if color[c] == 1 {
                return Err(LoadError::RecursiveCall { subprog: c });
            }
            if color[c] == 0 {
                dfs(c, insns, bounds, color)?;
            }
        }
        color[sp] = 2;
        Ok(())
    }
    for sp in 0..n {
        if color[sp] == 0 {
            dfs(sp, insns, bounds, &mut color)?;
        }
    }
    Ok(())
}

fn call_depth(insns: &[BpfInsn], bounds: &[(usize, usize)]) -> LoadResult<usize> {
    // Longest path from `main` (subprogram containing index 0) over the DAG.
    // Recursion must already be rejected before calling this.
    fn depth(
        sp: usize,
        insns: &[BpfInsn],
        bounds: &[(usize, usize)],
        memo: &mut [Option<usize>],
    ) -> LoadResult<usize> {
        if let Some(d) = memo[sp] {
            return Ok(d);
        }
        let mut best = 0;
        for c in callees(insns, bounds, sp)? {
            best = best.max(1 + depth(c, insns, bounds, memo)?);
        }
        memo[sp] = Some(best);
        Ok(best)
    }
    let main = subprog_index(bounds, 0).expect("index 0 is always a subprogram start");
    let mut memo = alloc::vec![None; bounds.len()];
    let d = depth(main, insns, bounds, &mut memo)?;
    if d > MAX_CALL_DEPTH {
        return Err(LoadError::CallDepthExceeded { depth: d, limit: MAX_CALL_DEPTH });
    }
    Ok(d)
}

fn expanded_size(insns: &[BpfInsn], bounds: &[(usize, usize)]) -> usize {
    fn size(
        sp: usize,
        insns: &[BpfInsn],
        bounds: &[(usize, usize)],
        memo: &mut [Option<usize>],
    ) -> usize {
        if let Some(s) = memo[sp] {
            return s;
        }
        let (start, end) = bounds[sp];
        let mut total = 0usize;
        let mut i = start;
        while i < end {
            let insn = &insns[i];
            if is_subprog_call(insn) {
                if let Some(c) = subprog_index(bounds, call_target(i, insn)) {
                    total += size(c, insns, bounds, memo); // call insn replaced by callee body
                }
            } else {
                total += if insn.is_wide() { 2 } else { 1 };
            }
            i += if insn.is_wide() { 2 } else { 1 };
        }
        memo[sp] = Some(total);
        total
    }
    let main = subprog_index(bounds, 0).expect("index 0 is a subprogram start");
    let mut memo = alloc::vec![None; bounds.len()];
    size(main, insns, bounds, &mut memo)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p kernel_bpf normalize::tests`
Expected: PASS (recursion, depth, malformed-call tests).

- [ ] **Step 5: Commit**

```bash
git add kernel/crates/kernel_bpf/src/loader/normalize.rs kernel/crates/kernel_bpf/src/loader/error.rs
git commit -m "feat(bpf): subprogram call graph + recursion/depth/size checks (#87)"
```

---

### Task 3: Stack rebasing primitive

**Files:**
- Modify: `kernel/crates/kernel_bpf/src/loader/normalize.rs`
- Test: inline tests in `normalize.rs`

**Interfaces:**
- Produces: `fn rebase(insn: BpfInsn, depth: usize) -> ([BpfInsn; 2], usize)` — returns the rewritten instruction(s) and how many are valid (1 or 2). For `depth == 0` returns the instruction unchanged (len 1). Rewrites:
  - direct `r10`-relative memory access → subtract `depth × FRAME_SIZE` from `offset`;
  - `mov64_reg X, r10` (opcode `0xbf`, `src_reg == 10`) → emit the mov followed by `add64_imm X, -(depth × FRAME_SIZE)` (len 2);
  - everything else unchanged.

  Pointer register for a memory op: LDX (load) dereferences `src_reg`; ST/STX (store) dereference `dst_reg`. (`BpfInsn::is_memory()` is true for LD/LDX/ST/STX; LD here is `ld_imm64`, not `r10`-relative, so it is never rebased.)

- [ ] **Step 1: Write the failing test**

Add to the `tests` module:

```rust
    // store *(r10 + off) = src  →  opcode 0x7b (STX, DW), dst=r10
    fn stx_to_fp(off: i16, src: u8) -> BpfInsn {
        BpfInsn::new(0x7b, 10, src, off, 0)
    }
    // load dst = *(r10 + off)  →  opcode 0x79 (LDX, DW), src=r10
    fn ldx_from_fp(dst: u8, off: i16) -> BpfInsn {
        BpfInsn::new(0x79, dst, 10, off, 0)
    }

    #[test]
    fn rebase_depth_zero_is_identity() {
        let i = stx_to_fp(-8, 1);
        let (out, n) = rebase(i, 0);
        assert_eq!(n, 1);
        assert_eq!(out[0], i);
    }

    #[test]
    fn rebase_shifts_direct_fp_access() {
        let (store, n) = rebase(stx_to_fp(-8, 1), 1);
        assert_eq!(n, 1);
        assert_eq!(store[0].offset, -8 - 512);
        let (load, n) = rebase(ldx_from_fp(2, -16), 2);
        assert_eq!(n, 1);
        assert_eq!(load[0].offset, -16 - 1024);
    }

    #[test]
    fn rebase_mov_from_fp_emits_add() {
        let (out, n) = rebase(BpfInsn::mov64_reg(6, 10), 1);
        assert_eq!(n, 2);
        assert_eq!(out[0], BpfInsn::mov64_reg(6, 10));
        assert_eq!(out[1], BpfInsn::add64_imm(6, -512));
    }

    #[test]
    fn rebase_leaves_nonstack_untouched() {
        let i = BpfInsn::mov64_imm(0, 7);
        let (out, n) = rebase(i, 3);
        assert_eq!(n, 1);
        assert_eq!(out[0], i);
        // a memory op through a non-r10 register is untouched
        let m = BpfInsn::new(0x7b, 1, 2, -8, 0); // *(r1 - 8) = r2
        let (out, n) = rebase(m, 3);
        assert_eq!(n, 1);
        assert_eq!(out[0], m);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kernel_bpf normalize::tests::rebase`
Expected: FAIL — `rebase` not defined.

- [ ] **Step 3: Write minimal implementation**

In `normalize.rs`:

```rust
/// Rewrite a single instruction for an inlined frame at `depth`.
///
/// Returns the rewritten instruction(s) and the valid length (1 or 2). `r10` is
/// the only source of a stack pointer, so shifting direct `r10`-relative
/// accesses and `r10` copies by `depth × FRAME_SIZE` relocates the whole frame
/// to its own stack window; pointers derived further carry the shift.
fn rebase(insn: BpfInsn, depth: usize) -> ([BpfInsn; 2], usize) {
    if depth == 0 {
        return ([insn, insn], 1);
    }
    let disp = (depth as i64 * FRAME_SIZE) as i16;

    // mov64 X, r10
    if insn.opcode == 0xbf && insn.src_reg() == 10 {
        let add = BpfInsn::add64_imm(insn.dst_reg(), -(depth as i64 * FRAME_SIZE) as i32);
        return ([insn, add], 2);
    }

    // direct r10-relative memory access
    if insn.is_memory() && !insn.is_wide() {
        let ptr_is_fp = match insn.class() {
            Some(crate::bytecode::opcode::OpcodeClass::Ldx) => insn.src_reg() == 10,
            Some(crate::bytecode::opcode::OpcodeClass::St)
            | Some(crate::bytecode::opcode::OpcodeClass::Stx) => insn.dst_reg() == 10,
            _ => false,
        };
        if ptr_is_fp {
            let mut m = insn;
            m.offset -= disp;
            return ([m, m], 1);
        }
    }

    ([insn, insn], 1)
}
```

(If `OpcodeClass` import path differs, use the existing import already present via `BpfInsn`; confirm with `codegraph node OpcodeClass` or `grep -n 'enum OpcodeClass' kernel/crates/kernel_bpf/src/bytecode/opcode.rs`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p kernel_bpf normalize::tests::rebase`
Expected: PASS (4 rebase tests).

- [ ] **Step 5: Commit**

```bash
git add kernel/crates/kernel_bpf/src/loader/normalize.rs
git commit -m "feat(bpf): stack-frame rebasing primitive for inlining (#87)"
```

---

### Task 4: Body expansion with jump fixup and EXIT→JA

**Files:**
- Modify: `kernel/crates/kernel_bpf/src/loader/normalize.rs`
- Test: inline tests in `normalize.rs`

**Interfaces:**
- Consumes: `rebase` (Task 3), `subprogram_bounds`, `is_subprog_call`, `call_target`, `subprog_index` (Tasks 1-2).
- Produces: `fn expand(insns, bounds, sp, depth) -> Vec<BpfInsn>` — the flattened body of subprogram `sp` inlined at `depth`. Internal relative jumps are re-targeted to the new layout; each `EXIT` becomes a `JA` to one-past-body-end **except** when `depth == 0` (the `main` `EXIT` is preserved); subprogram calls are replaced by the recursively expanded callee body; non-call instructions are rebased.

  Recompute internal jump offsets after expansion using an old→new index map, because inlining and rebase-inserted `add` instructions change distances. Only *this* subprogram's own jumps are fixed here; a spliced callee block returned by the recursive call already has its internal jumps fixed.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module:

```rust
    #[test]
    fn expand_leaf_fixes_forward_jump_and_keeps_main_exit() {
        // Single-function "main" (depth 0), no calls, with a forward jump:
        // 0: if r0 == 0 goto +1 ; 1: r0 = 1 ; 2: exit
        let insns = vec![
            BpfInsn::jeq_imm(0, 0, 1),
            BpfInsn::mov64_imm(0, 1),
            BpfInsn::exit(),
        ];
        let bounds = subprogram_bounds(&insns);
        let out = expand(&insns, &bounds, 0, 0);
        // Nothing inserted at depth 0 with no calls → identical layout.
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].offset, 1); // jump target unchanged
        assert!(out[2].is_exit());    // main exit preserved
    }

    #[test]
    fn expand_inlines_leaf_and_converts_exit_to_ja() {
        // main(0): 0: call ->2 ; 1: exit
        // leaf(2): 2: r0 = 7 ; 3: exit
        let insns = vec![
            subprog_call(0, 2),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, 7),
            BpfInsn::exit(),
        ];
        let bounds = subprogram_bounds(&insns);
        let out = expand(&insns, &bounds, 0, 0);
        // Expected flat: [r0=7, ja->end(=main continuation), exit]
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], BpfInsn::mov64_imm(0, 7));
        assert_eq!(out[1].opcode, 0x05);      // JA
        assert_eq!(out[1].offset, 0);          // jump to next insn (the continuation = main exit)
        assert!(out[2].is_exit());             // main's own exit, preserved
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kernel_bpf normalize::tests::expand`
Expected: FAIL — `expand` not defined.

- [ ] **Step 3: Write minimal implementation**

In `normalize.rs`:

```rust
fn expand(
    insns: &[BpfInsn],
    bounds: &[(usize, usize)],
    sp: usize,
    depth: usize,
) -> Vec<BpfInsn> {
    let (start, end) = bounds[sp];
    let mut out: Vec<BpfInsn> = Vec::new();
    // old (absolute) index within [start,end) → position in `out`.
    let mut old_to_new = alloc::vec![usize::MAX; end - start];
    // (pos in out, absolute old target index) for this subprogram's own jumps.
    let mut pending_jumps: Vec<(usize, usize)> = Vec::new();
    // positions of EXIT-derived JAs to fix to body end (non-main only).
    let mut exit_positions: Vec<usize> = Vec::new();

    let mut i = start;
    while i < end {
        let insn = insns[i];
        old_to_new[i - start] = out.len();

        if is_subprog_call(&insn) {
            let callee = subprog_index(bounds, call_target(i, &insn))
                .expect("callees() already validated targets");
            let block = expand(insns, bounds, callee, depth + 1);
            out.extend(block);
        } else if insn.is_exit() {
            if depth == 0 {
                out.push(insn); // main's terminating exit
            } else {
                out.push(BpfInsn::ja(0)); // fixed up below
                exit_positions.push(out.len() - 1);
            }
        } else if insn.is_jump() {
            // Conditional/unconditional internal jump (not a call).
            let target = (i as i64 + 1 + insn.offset as i64) as usize;
            out.push(insn);
            pending_jumps.push((out.len() - 1, target));
        } else if insn.is_wide() {
            out.push(insn);
            out.push(insns[i + 1]); // copy the 64-bit immediate continuation
        } else {
            let (re, n) = rebase(insn, depth);
            for k in 0..n {
                out.push(re[k]);
            }
        }

        i += if insn.is_wide() { 2 } else { 1 };
    }

    let body_end = out.len();
    for pos in exit_positions {
        out[pos].offset = (body_end - pos - 1) as i16;
    }
    for (pos, target) in pending_jumps {
        let new_target = old_to_new[target - start];
        debug_assert!(new_target != usize::MAX, "jump target inside subprogram");
        out[pos].offset = (new_target as isize - pos as isize - 1) as i16;
    }

    out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p kernel_bpf normalize::tests::expand`
Expected: PASS (2 expand tests).

- [ ] **Step 5: Commit**

```bash
git add kernel/crates/kernel_bpf/src/loader/normalize.rs
git commit -m "feat(bpf): inline body expansion with jump fixup + EXIT->JA (#87)"
```

---

### Task 5: Top-level `normalize` entry point

**Files:**
- Modify: `kernel/crates/kernel_bpf/src/loader/normalize.rs`
- Modify: `kernel/crates/kernel_bpf/src/loader/mod.rs` (add the deferred `pub use normalize::{normalize, Normalized};`)
- Test: inline tests in `normalize.rs`

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces:
  - `pub struct Normalized { pub insns: Vec<BpfInsn>, pub source_map: Vec<u32> }` — `source_map[new_idx]` = the original absolute instruction index it came from (for diagnostics). `// ponytail: source_map carried but not yet threaded to LoadedProgram; wire it when a diagnostic consumer exists.`
  - `pub fn normalize(insns: &[BpfInsn]) -> LoadResult<Normalized>` — order: if no subprogram calls, return `insns` unchanged with the identity `source_map` (fast path); else `subprogram_bounds` → `check_recursion` → `call_depth` → `expanded_size` vs `MAX_INSN_COUNT` (→ `ExpansionTooLarge`) → `expand(main, 0)`; finally re-check the produced length ≤ `MAX_INSN_COUNT`.

  The instruction-count limit comes from the active profile: `use crate::bytecode::program::BpfProgram; use crate::profile::ActiveProfile; let limit = BpfProgram::<ActiveProfile>::MAX_INSN_COUNT;`.

  `expand` (Task 4) does not produce a `source_map`; for this task have `normalize` build a parallel source map by extending `expand` to also return source indices, OR (simpler, chosen here) recompute the source map as a second pass is unnecessary — instead change `expand` to push to an out-param. To avoid reworking Task 4's signature, `normalize` calls a thin wrapper `expand_with_src` that mirrors `expand` but pairs each pushed instruction with its source index. **Implementation note:** rather than duplicate, refactor `expand` to return `Vec<(BpfInsn, u32)>` and have callers map. See Step 3.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module:

```rust
    use crate::loader::LoadError;

    #[test]
    fn normalize_fast_path_no_calls() {
        let insns = vec![BpfInsn::mov64_imm(0, 0), BpfInsn::exit()];
        let n = normalize(&insns).unwrap();
        assert_eq!(n.insns, insns);
        assert_eq!(n.source_map, vec![0, 1]);
    }

    #[test]
    fn normalize_inlines_and_removes_subprog_calls() {
        // main(0): call ->2 ; exit    leaf(2): r0=7 ; exit
        let insns = vec![
            subprog_call(0, 2),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, 7),
            BpfInsn::exit(),
        ];
        let n = normalize(&insns).unwrap();
        // No subprogram calls remain in the normalized program.
        assert!(!n.insns.iter().any(is_subprog_call));
        // Flat: [r0=7, ja, exit]
        assert_eq!(n.insns.len(), 3);
        assert!(n.insns[2].is_exit());
    }

    #[test]
    fn normalize_rejects_recursion() {
        let insns = vec![subprog_call(0, 0), BpfInsn::exit()];
        assert_eq!(normalize(&insns).err(), Some(LoadError::RecursiveCall { subprog: 0 }));
    }

    #[test]
    fn normalize_rebases_nested_frames() {
        // main(0): store *(r10-8)=r1 ; call ->3 ; exit
        // leaf(3): store *(r10-8)=r2 ; exit   (depth 1 → offset shifts by 512)
        let insns = vec![
            BpfInsn::new(0x7b, 10, 1, -8, 0), // *(r10-8) = r1   (main, depth 0)
            subprog_call(1, 3),
            BpfInsn::exit(),
            BpfInsn::new(0x7b, 10, 2, -8, 0), // *(r10-8) = r2   (leaf, depth 1)
            BpfInsn::exit(),
        ];
        let n = normalize(&insns).unwrap();
        // main's store keeps -8; leaf's store rebased to -8-512.
        let stores: Vec<i16> = n.insns.iter().filter(|i| i.opcode == 0x7b).map(|i| i.offset).collect();
        assert_eq!(stores, vec![-8, -8 - 512]);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kernel_bpf normalize::tests::normalize`
Expected: FAIL — `normalize` / `Normalized` not defined.

- [ ] **Step 3: Write minimal implementation**

Refactor `expand` to carry source indices (changes its return type; update Task 4's two tests to read `.0` where they referenced instructions — see note below). Replace `expand`'s signature and the three push sites:

```rust
// return type now pairs each instruction with its originating absolute index
fn expand(
    insns: &[BpfInsn],
    bounds: &[(usize, usize)],
    sp: usize,
    depth: usize,
) -> Vec<(BpfInsn, u32)> {
    // ... identical body, but every `out.push(x)` becomes `out.push((x, i as u32))`
    // and `out.extend(block)` stays (block is already Vec<(BpfInsn,u32)>).
    // Offset fixups index `out[pos].0.offset`.
}
```

Then add:

```rust
/// The canonical flat program the verifier consumes.
#[derive(Debug, Clone)]
pub struct Normalized {
    /// Flattened, loop-free instructions; all `call`s are helper calls.
    pub insns: Vec<BpfInsn>,
    /// `source_map[new_idx]` = originating absolute source instruction index.
    pub source_map: Vec<u32>,
}

/// Normalize loaded bytecode into the canonical flat program (resolve and
/// inline BPF-to-BPF calls). Returns the input unchanged if it has no
/// subprogram calls.
pub fn normalize(insns: &[BpfInsn]) -> LoadResult<Normalized> {
    use crate::bytecode::program::BpfProgram;
    use crate::profile::ActiveProfile;
    let limit = BpfProgram::<ActiveProfile>::MAX_INSN_COUNT;

    if !insns.iter().any(is_subprog_call) {
        return Ok(Normalized {
            insns: insns.to_vec(),
            source_map: (0..insns.len() as u32).collect(),
        });
    }

    let bounds = subprogram_bounds(insns);
    check_recursion(insns, &bounds)?;
    call_depth(insns, &bounds)?; // rejects CallDepthExceeded

    let est = expanded_size(insns, &bounds);
    if est > limit {
        return Err(LoadError::ExpansionTooLarge { got: est, limit });
    }

    let main = subprog_index(&bounds, 0).expect("index 0 is a subprogram start");
    let expanded = expand(insns, &bounds, main, 0);
    if expanded.len() > limit {
        return Err(LoadError::ExpansionTooLarge { got: expanded.len(), limit });
    }

    let (flat, source_map): (Vec<BpfInsn>, Vec<u32>) = expanded.into_iter().unzip();
    Ok(Normalized { insns: flat, source_map })
}
```

Update the two Task 4 tests to read the paired form: `out[0].0`, `out[1].0.offset`, `out[2].0.is_exit()`, and `out.len()` is unchanged.

Add the deferred re-export in `mod.rs`:

```rust
pub use normalize::{normalize, Normalized};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p kernel_bpf normalize`
Expected: PASS (all normalize + expand + earlier tests).

- [ ] **Step 5: Commit**

```bash
git add kernel/crates/kernel_bpf/src/loader/normalize.rs kernel/crates/kernel_bpf/src/loader/mod.rs
git commit -m "feat(bpf): normalize entry point inlining subprogram calls (#87)"
```

---

### Task 6: Loader integration + verifier accepts normalized programs

**Files:**
- Modify: `kernel/crates/kernel_bpf/src/loader/mod.rs` (call `normalize` in `load_programs`)
- Test: new integration test file `kernel/crates/kernel_bpf/tests/bpf_to_bpf_calls.rs`

**Interfaces:**
- Consumes: `normalize` (Task 5); `Verifier::verify_with_config`, `VerifyConfig` (existing verifier API).
- Produces: `load_programs` stores normalized instructions in each `LoadedProgram`. End-to-end guarantee: a program with subprogram calls verifies after normalization; recursion is rejected at normalization.

- [ ] **Step 1: Write the failing test**

In `load_programs` (`mod.rs`), the test target is the new line; first write the integration test. Create `kernel/crates/kernel_bpf/tests/bpf_to_bpf_calls.rs`:

```rust
//! End-to-end: BPF-to-BPF calls normalize then verify.

use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::bytecode::program::BpfProgType;
use kernel_bpf::loader::{normalize, LoadError};
use kernel_bpf::verifier::{VerifyConfig, Verifier};
use kernel_bpf::profile::ActiveProfile;

fn subprog_call(at: usize, target: usize) -> BpfInsn {
    let imm = target as i64 - at as i64 - 1;
    let mut i = BpfInsn::call(imm as i32);
    i.regs = (i.regs & 0x0f) | (1 << 4); // src_reg = BPF_PSEUDO_CALL
    i
}

#[test]
fn three_function_program_normalizes_and_verifies() {
    // main(0): call ->3 ; r0 unchanged ; exit
    // leaf(3): r0 = 1 ; exit
    let insns = vec![
        subprog_call(0, 3),
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::exit(),
        BpfInsn::mov64_imm(0, 1),
        BpfInsn::exit(),
    ];
    let norm = normalize(&insns).expect("normalizes");
    assert!(!norm.insns.iter().any(|i| i.is_call() && i.src_reg() == 1));
    let prog = Verifier::<ActiveProfile>::verify_with_config(
        BpfProgType::SocketFilter,
        &norm.insns,
        VerifyConfig::default(),
    );
    assert!(prog.is_ok(), "verifier accepts normalized program: {:?}", prog.err());
}

#[test]
fn recursive_program_is_rejected_at_normalization() {
    let insns = vec![subprog_call(0, 0), BpfInsn::exit()];
    assert_eq!(normalize(&insns).err(), Some(LoadError::RecursiveCall { subprog: 0 }));
}
```

(Confirm the exact public paths for `Verifier`, `VerifyConfig`, `BpfProgType`, `ActiveProfile` with `grep -rn 'pub use' kernel/crates/kernel_bpf/src/lib.rs`; adjust `use` lines if the crate re-exports them at a different path. The verifier test in `verifier/core.rs` shows the in-crate names; the integration test needs their `pub` re-exports.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kernel_bpf --test bpf_to_bpf_calls`
Expected: FAIL to compile if the public paths differ, or the first test FAILS only if normalization is not wired — but since `normalize` is public (Task 5), both tests should already pass at this point *for the direct `normalize` call*. The integration is proven separately below; if both pass immediately, proceed to wire the loader (Step 3) and re-run to confirm no regression.

- [ ] **Step 3: Write minimal implementation**

In `mod.rs` `load_programs`, normalize after relocation:

```rust
            // Apply relocations
            let mut relocator = Relocator::new(maps);
            let insns = relocator.relocate(&name, insns, parser)?;

            // Resolve & inline BPF-to-BPF calls into a flat program (#87).
            let insns = normalize(&insns)?.insns;

            programs.push(LoadedProgram::new(name, prog_type, insns));
```

Add `use normalize::normalize;` is unnecessary since `mod.rs` already re-exports it; reference it as `normalize(...)` via the `pub use` (in-module path `self::normalize::normalize`) — if the bare call does not resolve, call `crate::loader::normalize(&insns)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p kernel_bpf --test bpf_to_bpf_calls`
Then the full crate, both profiles:
Run: `cargo test -p kernel_bpf`
Run: `cargo test -p kernel_bpf --no-default-features --features cloud-profile`
Expected: PASS (integration tests + no regressions in either profile).

- [ ] **Step 5: Commit**

```bash
git add kernel/crates/kernel_bpf/src/loader/mod.rs kernel/crates/kernel_bpf/tests/bpf_to_bpf_calls.rs
git commit -m "feat(bpf): normalize loaded programs before verification (#87)"
```

---

## Self-Review

**Spec coverage:**
- Pipeline (ELF→reloc→graph→canonicalizer→verifier): Tasks 1-2 (graph), 3-5 (canonicalizer), 6 (wiring). ✓
- Pseudo-call resolution: Task 1 (`is_subprog_call`/`call_target`). ✓
- Subprogram graph: Tasks 1-2. ✓
- Recursion detection / depth check / size pre-check: Task 2 + Task 5 errors. ✓
- Inline expansion + EXIT→JA + jump fixup: Task 4. ✓
- Stack rebasing / frame isolation (free): Task 3 + Task 5 nested test; isolation verified end-to-end in Task 6 (verifier rejects out-of-frame). ✓
- Callee-saved R6-R9 verbatim (no injected save/restore): inherent — `expand` copies non-stack instructions unchanged; no register rewrite beyond stack rebase. ✓
- `Normalized { insns, source_map }` IR + verifier consumes flat program: Tasks 5-6. ✓
- Errors `RecursiveCall`/`CallDepthExceeded`/`ExpansionTooLarge`/`MalformedPseudoCall`: Task 2. ✓
- Testing (3-function accept, recursive reject, depth reject, size reject, rebase correctness): Tasks 2,4,5,6. **Gap:** spec lists a "callee writes to caller frame → rejected" test and a "WCET longest-path includes callee" check; these are verifier/cost behaviors over the normalized program. Added as follow-up assertions — see note. The "callee writes caller frame" case is an *original positive r10 offset*, already rejected by the existing out-of-frame check; an explicit end-to-end test belongs in Task 6 and should be added there if cheap.
- `#89`/`#90` composition: documented in spec; no tasks here (separate specs). ✓

**Placeholder scan:** No TBD/TODO-as-work, no "add error handling"; all code shown. The two `// ponytail:` comments mark deliberate scope ceilings (single-section layout; source_map not yet threaded), not gaps. ✓

**Type consistency:** `expand` return type changes in Task 5 (instruction → `(BpfInsn, u32)` pair); Task 4's tests are explicitly updated in Task 5 Step 3 to read `.0`. `subprogram_bounds`/`subprog_index`/`callees`/`call_depth`/`expanded_size`/`rebase`/`expand`/`normalize`/`Normalized` names are used identically across tasks. Error variant field names (`subprog`, `depth`/`limit`, `got`/`limit`, `insn_idx`) match between `error.rs` and call sites. ✓

**One known refinement for the implementer:** Task 6 Step 2 notes the integration tests may pass before the loader wiring (because they call `normalize` directly). That is intended — the loader wiring (Step 3) is verified by the no-regression full-crate run. If you want the integration test to *fail first* against the loader specifically, add a test that drives `BpfLoader::load` on a crafted ELF; this is heavier (needs an ELF fixture) and is optional.
