/// Architecture-independent trait for platform-specific operations
pub trait Architecture {
    /// Perform early architecture initialization (before memory management)
    fn early_init();

    /// Perform full architecture initialization
    fn init();

    /// Enable interrupts
    fn enable_interrupts();

    /// Disable interrupts
    fn disable_interrupts();

    /// Check if interrupts are enabled
    fn are_interrupts_enabled() -> bool;

    /// Wait for an interrupt (halt until interrupt)
    fn wait_for_interrupt();

    /// Shutdown the system
    fn shutdown() -> !;

    /// Reboot the system
    fn reboot() -> !;
}

/// Architecture-specific context for task switching
#[derive(Debug, Clone, Default)]
pub struct TaskContext {
    /// Stack pointer
    pub stack_pointer: usize,
    /// Instruction pointer / program counter
    pub instruction_pointer: usize,
    /// Architecture-specific register state
    pub arch_state: ArchState,
}

/// Architecture-specific register state
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone)]
pub struct ArchState {
    pub rflags: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

#[cfg(all(target_arch = "aarch64", feature = "aarch64_arch"))]
#[derive(Debug, Clone)]
pub struct ArchState {
    pub x19: u64, // callee-saved registers
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,   // frame pointer
    pub x30: u64,   // link register
    pub ttbr0: u64, // page table base (user)
    pub ttbr1: u64, // page table base (kernel)
}

// Stub for aarch64 without aarch64_arch feature
#[cfg(all(target_arch = "aarch64", not(feature = "aarch64_arch")))]
#[derive(Debug, Clone)]
pub struct ArchState;

#[cfg(all(target_arch = "aarch64", not(feature = "aarch64_arch")))]
impl Default for ArchState {
    fn default() -> Self {
        Self
    }
}

#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", feature = "aarch64_arch")
))]
#[allow(clippy::derivable_impls)]
impl Default for ArchState {
    fn default() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self {
                rflags: 0x202, // IF flag set
                rbp: 0,
                rbx: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
            }
        }

        #[cfg(all(target_arch = "aarch64", feature = "aarch64_arch"))]
        {
            Self {
                x19: 0,
                x20: 0,
                x21: 0,
                x22: 0,
                x23: 0,
                x24: 0,
                x25: 0,
                x26: 0,
                x27: 0,
                x28: 0,
                x29: 0,
                x30: 0,
                ttbr0: 0,
                ttbr1: 0,
            }
        }
    }
}
