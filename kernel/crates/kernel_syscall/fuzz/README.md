# Syscall argument fuzz harness

`mmap_arguments` feeds arbitrary syscall-shaped argument words through the
real `kernel_syscall::mman::sys_mmap` validation path. Its mock
`MemoryRegionAccess` never maps host memory, so an accepted request proves
only that the syscall contract reached a transaction boundary safely.

Run locally from `kernel/crates/kernel_syscall`:

```bash
cargo fuzz run mmap_arguments -- -max_total_time=600
```
