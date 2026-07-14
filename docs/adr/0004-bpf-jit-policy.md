# ADR-0004: BPF JIT policy

- Status: Accepted
- Date: 2026-07-14

## Decision

axiomos v1.0 is interpreter-only. No shipped profile enables a BPF JIT, and JIT
support is not on the release critical path. Experimental JIT code must not
provide kernel allocator symbols, executable mappings, or production call sites.

The existing AArch64 per-execution compiler/allocator path will be removed from
the shipped `kernel_bpf` surface or relocated to an experiment. Retaining it
behind an undocumented feature is not sufficient because dead unsafe code still
adds audit and maintenance surface.

A future JIT requires a new superseding ADR and all of the following:

1. Compilation occurs exactly once after verification and before publication.
2. The verified program owns an immutable executable code image until epoch-safe
   unload completes.
3. Code is emitted into writable, non-executable pages and transitioned once to
   read-only executable pages. No mapping is writable and executable together.
4. Compilation, allocation, protection changes, and cache maintenance are fully
   fallible and transactional.
5. Hook dispatch performs no compilation, allocation, mapping, or protection
   changes.
6. Differential tests compare every supported instruction/helper with the
   interpreter, including malformed and resource-failure cases.
