# Static-state declaration inventory

Baseline: `4f5aa90`. This lexical inventory includes tests, boot-only declarations and architecture alternatives; it is not a count of concurrently live production globals. Struct-owned and MMIO state are covered in the main report. Dependency and macro-generated globals are outside this inventory.

| File:line | Declaration | Type | Classification |
|---|---|---|---|
| `firmware/shrike/rp2040/src/main.rs:27` | `BOOT2_FIRMWARE` | `[u8` | immutable or externally initialized; inspect type |
| `kernel/crates/kernel_bpf/src/execution/mod.rs:29` | `TEST_MAP_VALUE` | `AtomicU64` | interior/initialization mutability |
| `kernel/crates/kernel_bpf/src/execution/mod.rs:34` | `REC_LOCK` | `AtomicBool` | interior/initialization mutability |
| `kernel/crates/kernel_bpf/src/execution/mod.rs:35` | `RECORDING` | `AtomicBool` | interior/initialization mutability |
| `kernel/crates/kernel_bpf/src/execution/mod.rs:36` | `PWM_CH1` | `AtomicI64` | interior/initialization mutability |
| `kernel/crates/kernel_bpf/src/execution/mod.rs:37` | `PWM_CH2` | `AtomicI64` | interior/initialization mutability |
| `kernel/crates/kernel_devfs/src/fs.rs:135` | `FS_COUNTER` | `AtomicU64` | interior/initialization mutability |
| `kernel/crates/kernel_devfs/src/fs.rs:281` | `ID_COUNTER` | `AtomicUsize` | interior/initialization mutability |
| `kernel/crates/kernel_physical_memory/src/fault.rs:41` | `BUDGET` | `AtomicU32` | interior/initialization mutability |
| `kernel/crates/kernel_physical_memory/src/fault.rs:42` | `DISARMED` | `AtomicBool` | interior/initialization mutability |
| `kernel/crates/kernel_physical_memory/src/fault.rs:43` | `SERIAL` | `Mutex<()>` | interior/initialization mutability |
| `kernel/crates/kernel_physical_memory/src/fault.rs:47` | `ARMED_ON_THIS_THREAD` | `Cell<bool>` | interior/initialization mutability |
| `kernel/src/acpi.rs:17` | `ACPI_TABLES` | `OnceCell<Mutex<AcpiTables<AcpiHandlerImpl>>>` | interior/initialization mutability |
| `kernel/src/actuation.rs:17` | `ACTUATION_MONITOR` | `Mutex<Monitor<ActiveProfile>>` | interior/initialization mutability |
| `kernel/src/actuation.rs:18` | `APPLY_LOCK` | `Mutex<()>` | interior/initialization mutability |
| `kernel/src/actuation.rs:19` | `NEXT_V04_ESTOP_EVENT` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/apic.rs:14` | `IO_APIC` | `OnceCell<Mutex<IoApic>>` | interior/initialization mutability |
| `kernel/src/arch/aarch64/boot.rs:6` | `BOOT_INFO` | `BootInfo` | explicit static mut |
| `kernel/src/arch/aarch64/boot.rs:65` | `__bss_start` | `u8` | immutable or externally initialized; inspect type |
| `kernel/src/arch/aarch64/boot.rs:66` | `__bss_end` | `u8` | immutable or externally initialized; inspect type |
| `kernel/src/arch/aarch64/dtb.rs:55` | `DTB_INFO` | `DeviceTreeInfo` | explicit static mut |
| `kernel/src/arch/aarch64/exceptions.rs:10` | `PREEMPT_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/arch/aarch64/exceptions.rs:12` | `SYNC_ENTRY_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/arch/aarch64/exceptions.rs:14` | `SYNC_DECODE_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/arch/aarch64/exceptions.rs:16` | `SVC_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/arch/aarch64/exceptions.rs:18` | `SVC_ENTER_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/arch/aarch64/exceptions.rs:20` | `SVC_RETURN_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/arch/aarch64/exceptions.rs:22` | `DATA_ABORT_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/arch/aarch64/exceptions.rs:24` | `INSTR_ABORT_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/arch/aarch64/gic.rs:85` | `GICD` | `usize` | immutable or externally initialized; inspect type |
| `kernel/src/arch/aarch64/gic.rs:89` | `GICC` | `usize` | immutable or externally initialized; inspect type |
| `kernel/src/arch/aarch64/interrupts.rs:27` | `TIMER_IRQ_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/arch/aarch64/interrupts.rs:29` | `FIRST_IRQ_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/arch/aarch64/mm.rs:21` | `BOOT_TABLES` | `BootPageTables` | explicit static mut |
| `kernel/src/arch/aarch64/phys.rs:12` | `BOOT_REGIONS` | `[crate::mem::phys::MemoryRegion` | explicit static mut |
| `kernel/src/arch/aarch64/phys.rs:39` | `__text_start` | `u8` | immutable or externally initialized; inspect type |
| `kernel/src/arch/aarch64/phys.rs:40` | `__bss_end` | `u8` | immutable or externally initialized; inspect type |
| `kernel/src/arch/aarch64/platform/rpi5/control_link.rs:58` | `CONTROL_LINK` | `OnceCell<Mutex<ControlLink>>` | interior/initialization mutability |
| `kernel/src/arch/aarch64/platform/rpi5/control_link.rs:59` | `NEXT_SENSOR_SAMPLE_ID` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/arch/aarch64/platform/rpi5/control_link.rs:60` | `NEXT_LINK_LOSS_EVENT_ID` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/arch/aarch64/platform/rpi5/control_link.rs:61` | `NEXT_CHUNK_ID` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/arch/aarch64/platform/rpi5/control_link.rs:62` | `LINK_UNINITIALIZED_REPORTED` | `core::sync::atomic::AtomicBool` | interior/initialization mutability |
| `kernel/src/arch/aarch64/platform/rpi5/mod.rs:28` | `UART` | `Lazy<Mutex<Rp1Uart>>` | interior/initialization mutability |
| `kernel/src/arch/aarch64/platform/rpi5/mod.rs:37` | `PWM0` | `Lazy<Mutex<Rp1Pwm>>` | interior/initialization mutability |
| `kernel/src/arch/aarch64/platform/rpi5/mod.rs:46` | `PWM1` | `Lazy<Mutex<Rp1Pwm>>` | interior/initialization mutability |
| `kernel/src/arch/aarch64/platform/rpi5/pwm.rs:101` | `PWM0` | `Mutex<Rp1Pwm>` | interior/initialization mutability |
| `kernel/src/arch/aarch64/platform/rpi5/pwm.rs:105` | `PWM1` | `Mutex<Rp1Pwm>` | interior/initialization mutability |
| `kernel/src/arch/aarch64/platform/virt/mod.rs:11` | `SERIAL_CONSOLE` | `Lazy<Mutex<PL011Uart>>` | interior/initialization mutability |
| `kernel/src/arch/x86_64.rs:13` | `TLB_SHOOTDOWN_EPOCH` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/arch/x86_64.rs:15` | `TLB_SHOOTDOWN_REPORTED` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/arch/x86_64.rs:16` | `TLB_SHOOTDOWN_ACKS` | `[AtomicU64` | interior/initialization mutability |
| `kernel/src/backtrace.rs:16` | `BACKTRACE_CONTEXT` | `OnceCell<BacktraceContext>` | interior/initialization mutability |
| `kernel/src/bench.rs:78` | `GPIO_IRQ_ENTRY` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/bench.rs:80` | `NEXT_SAMPLE_ID` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/bench.rs:82` | `GPIO_IRQ_SAMPLE_ID` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/bench.rs:84` | `ESTOP_SAMPLE_ID` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/bench.rs:86` | `REFLEX_SAMPLE_ID` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/bench.rs:88` | `GPIO_IRQ_PROVEN` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/bench.rs:90` | `GPIO_IRQ_DIAG_COUNT` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/bpf/mod.rs:209` | `HOOK_SNAPSHOTS` | `EpochSnapshot<HookSnapshot>` | interior/initialization mutability |
| `kernel/src/bpf/trust.rs:12` | `PRODUCTION_BPF_TRUSTED_KEY` | `&[u8` | immutable or externally initialized; inspect type |
| `kernel/src/driver/block.rs:17` | `BLOCK_DEVICES` | `RwLock< BTreeMap<u64, Arc<RwLock<dyn BlockDevice<KernelDeviceId, 512> + Send + Sync>>>, >` | interior/initialization mutability |
| `kernel/src/driver/block.rs:20` | `BLOCK_DEVICE_COUNTER` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/driver/iio.rs:60` | `IIO_MANAGER` | `OnceCell<Mutex<IioManager>>` | interior/initialization mutability |
| `kernel/src/driver/iio.rs:65` | `V04_ACTIVE_SAMPLE_IDS` | `[AtomicU64` | interior/initialization mutability |
| `kernel/src/driver/mod.rs:33` | `COUNTER` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/driver/pci.rs:13` | `PCI_DRIVERS` | `[PciDriverDescriptor]` | immutable or externally initialized; inspect type |
| `kernel/src/driver/ram.rs:17` | `EMBEDDED_DISK` | `&[u8]` | immutable or externally initialized; inspect type |
| `kernel/src/driver/raw.rs:9` | `RAW_DEVICES` | `RwLock<RawDeviceRegistry<KernelDeviceId>>` | interior/initialization mutability |
| `kernel/src/driver/virtio/block.rs:34` | `VIRTIO_READ_SECTOR_PROBE_SEQ` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/driver/virtio/block.rs:43` | `VIRTIO_BLK` | `PciDriverDescriptor` | immutable or externally initialized; inspect type |
| `kernel/src/driver/virtio/gpu.rs:25` | `VIRTIO_GPU` | `PciDriverDescriptor` | immutable or externally initialized; inspect type |
| `kernel/src/driver/virtio/hal.rs:76` | `MMIO_ALLOC_OFFSET` | `AtomicUsize` | interior/initialization mutability |
| `kernel/src/file/devfs.rs:10` | `DEVFS` | `OnceCell<ArcLockedDevFs>` | interior/initialization mutability |
| `kernel/src/file/ext2.rs:51` | `FS_COUNTER` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/file/mod.rs:18` | `VFS` | `RwLock<Vfs>` | interior/initialization mutability |
| `kernel/src/hpet.rs:17` | `HPET` | `OnceCell<RwLock<Hpet>>` | interior/initialization mutability |
| `kernel/src/lib.rs:49` | `BOOT_TIME_SECONDS` | `OnceCell<u64>` | interior/initialization mutability |
| `kernel/src/lib.rs:59` | `BOOT_METRICS` | `OnceCell<KernelBootMetrics>` | interior/initialization mutability |
| `kernel/src/lib.rs:60` | `BPF_MANAGER` | `OnceCell<Mutex<bpf::BpfManager>>` | interior/initialization mutability |
| `kernel/src/lib.rs:217` | `__text_start` | `u8` | immutable or externally initialized; inspect type |
| `kernel/src/lib.rs:218` | `__kernel_end` | `u8` | immutable or externally initialized; inspect type |
| `kernel/src/limine.rs:11` | `_START_MARKER` | `RequestsStartMarker` | interior/initialization mutability |
| `kernel/src/limine.rs:16` | `_END_MARKER` | `RequestsEndMarker` | interior/initialization mutability |
| `kernel/src/limine.rs:21` | `BASE_REVISION` | `BaseRevision` | interior/initialization mutability |
| `kernel/src/limine.rs:26` | `BOOT_TIME` | `DateAtBootRequest` | interior/initialization mutability |
| `kernel/src/limine.rs:31` | `KERNEL_FILE_REQUEST` | `ExecutableFileRequest` | interior/initialization mutability |
| `kernel/src/limine.rs:36` | `KERNEL_ADDRESS_REQUEST` | `ExecutableAddressRequest` | interior/initialization mutability |
| `kernel/src/limine.rs:41` | `MEMORY_MAP_REQUEST` | `MemoryMapRequest` | interior/initialization mutability |
| `kernel/src/limine.rs:46` | `HHDM_REQUEST` | `HhdmRequest` | interior/initialization mutability |
| `kernel/src/limine.rs:51` | `RSDP_REQUEST` | `RsdpRequest` | interior/initialization mutability |
| `kernel/src/limine.rs:56` | `STACK_SIZE_REQUEST` | `StackSizeRequest` | interior/initialization mutability |
| `kernel/src/limine.rs:61` | `MODULE_REQUEST` | `ModuleRequest` | interior/initialization mutability |
| `kernel/src/limine.rs:66` | `MP_REQUEST` | `MpRequest` | explicit static mut |
| `kernel/src/mcore/context.rs:29` | `ONLINE_CPU_MASK` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/mcore/context.rs:31` | `ONLINE_LAPIC_IDS` | `[AtomicU32` | interior/initialization mutability |
| `kernel/src/mcore/mtask/process/construction.rs:27` | `ROOT_PROCESS` | `OnceCell<Arc<Process>>` | interior/initialization mutability |
| `kernel/src/mcore/mtask/process/id.rs:27` | `COUNTER` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/mcore/mtask/process/trampoline.rs:41` | `TRAMPOLINE_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/mcore/mtask/process/trampoline.rs:47` | `TRAMPOLINE_OPEN_STAGE_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/mcore/mtask/process/trampoline.rs:53` | `TRAMPOLINE_READ_STAGE_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/mcore/mtask/process/trampoline.rs:59` | `TRAMPOLINE_ELF_STAGE_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/mcore/mtask/process/trampoline.rs:65` | `TRAMPOLINE_ENTER_USER_STAGE_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/mcore/mtask/process/trampoline.rs:71` | `TRAMPOLINE_TTBR0_STAGE_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/mcore/mtask/process/tree.rs:9` | `PROCESS_TREE` | `OnceCell<RwLock<ProcessTree>>` | interior/initialization mutability |
| `kernel/src/mcore/mtask/scheduler/cleanup.rs:19` | `CLEANUP_QUEUE` | `OnceCell<TaskQueue>` | interior/initialization mutability |
| `kernel/src/mcore/mtask/scheduler/cleanup.rs:20` | `CLEANUP_WORKER_SCHEDULED` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/mcore/mtask/scheduler/cleanup.rs:27` | `CLEANUP_RUN_MARKER_SENT` | `Rpi5AtomicBool` | interior/initialization mutability |
| `kernel/src/mcore/mtask/scheduler/mod.rs:50` | `SCHED_SWITCH_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/mcore/mtask/scheduler/mod.rs:56` | `SCHED_SWITCH_TARGET_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/mcore/mtask/scheduler/run_queue.rs:12` | `RUN_QUEUES` | `OnceCell<RunQueueSet<Task>>` | interior/initialization mutability |
| `kernel/src/mcore/mtask/scheduler/sleep.rs:13` | `SLEEP_QUEUE` | `OnceCell<Mutex<DeadlineQueue<Pin<Box<Task>>, MAX_SLEEPING_TASKS>>>` | interior/initialization mutability |
| `kernel/src/mcore/mtask/task/id.rs:27` | `COUNTER` | `AtomicU64` | interior/initialization mutability |
| `kernel/src/mem/address_space/mod.rs:58` | `KERNEL_ADDRESS_SPACE` | `OnceCell<AddressSpace>` | interior/initialization mutability |
| `kernel/src/mem/address_space/mod.rs:60` | `RECURSIVE_INDEX` | `OnceCell<usize>` | interior/initialization mutability |
| `kernel/src/mem/heap.rs:31` | `HEAP_INITIALIZED` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/mem/heap.rs:34` | `HEAP_START` | `VirtAddr` | immutable or externally initialized; inspect type |
| `kernel/src/mem/heap.rs:37` | `HEAP_START` | `VirtAddr` | immutable or externally initialized; inspect type |
| `kernel/src/mem/heap.rs:40` | `HEAP_SIZES` | `OnceCell<HeapSizes>` | interior/initialization mutability |
| `kernel/src/mem/heap.rs:43` | `ALLOCATOR` | `linked_list_allocator::LockedHeap` | interior/initialization mutability |
| `kernel/src/mem/phys.rs:16` | `PHYS_ALLOC` | `Option<Mutex<MultiStageAllocator>>` | explicit static mut |
| `kernel/src/mem/phys.rs:17` | `FRAME_REFS` | `Option<Mutex<FrameRefCounts>>` | explicit static mut |
| `kernel/src/mem/phys.rs:53` | `RESERVED_REGIONS` | `ReservedRegions` | explicit static mut |
| `kernel/src/mem/phys.rs:322` | `BOOT_REGIONS` | `[MemoryRegion` | explicit static mut |
| `kernel/src/mem/virt.rs:21` | `VMM` | `OnceCell<RwLock<VirtualMemoryManager>>` | interior/initialization mutability |
| `kernel/src/serial.rs:8` | `SERIAL1` | `Lazy<Mutex<SerialPort>>` | interior/initialization mutability |
| `kernel/src/syscall/mod.rs:61` | `WRITE_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/syscall/mod.rs:63` | `BPF_MARKER_SENT` | `AtomicBool` | interior/initialization mutability |
| `kernel/src/syscall/mod.rs:64` | `EXPORTED_RINGBUF_MAP_ID` | `AtomicU32` | interior/initialization mutability |
| `userspace/core/init/src/main.rs:1214` | `EXEC_PATH` | `&[u8]` | immutable or externally initialized; inspect type |
| `userspace/core/init/src/main.rs:1230` | `MISSING_PATH` | `&[u8]` | immutable or externally initialized; inspect type |
| `userspace/core/init/src/main.rs:1542` | `PATH` | `&[u8]` | immutable or externally initialized; inspect type |
