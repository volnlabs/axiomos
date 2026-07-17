# Boot And Run

Use the typed command surface so target selection and exit status remain
consistent:

```sh
cargo xtask run x86_64
cargo xtask run virt
cargo xtask deploy rpi5
```

The x86_64 runner assembles the kernel, root filesystem, and Limine image before
launching QEMU. Raspberry Pi deployment is a physical operation; inspect it
first with `cargo xtask deploy rpi5 --dry-run`.
