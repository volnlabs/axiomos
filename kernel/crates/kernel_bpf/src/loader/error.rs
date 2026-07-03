//! Loader Error Types

use core::fmt;

/// Errors that can occur during BPF object loading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// ELF data is too small
    ElfTooSmall,
    /// Invalid ELF magic number
    InvalidMagic,
    /// Unsupported ELF class (not 64-bit)
    UnsupportedClass,
    /// Unsupported endianness
    UnsupportedEndian,
    /// Unsupported ELF machine type
    UnsupportedMachine,
    /// Invalid ELF header
    InvalidHeader,
    /// Section index out of bounds
    SectionOutOfBounds,
    /// Invalid section header
    InvalidSectionHeader,
    /// Section data out of bounds
    SectionDataOutOfBounds,
    /// String table error
    InvalidStringTable,
    /// Too many programs in object file
    TooManyPrograms,
    /// Too many maps in object file
    TooManyMaps,
    /// Invalid map definition data
    InvalidMapData,
    /// Unsupported map type
    UnsupportedMapType(u32),
    /// Invalid instruction data
    InvalidInstructionData,
    /// Invalid relocation
    InvalidRelocation,
    /// Undefined symbol in relocation
    UndefinedSymbol,
    /// Symbol table not found
    NoSymbolTable,
    /// License not found
    LicenseNotFound,
    /// Invalid license string
    InvalidLicense,
    /// BTF parsing error
    BtfError,
    /// A subprogram call participates in a recursion cycle.
    RecursiveCall { subprog: usize },
    /// Subprogram call depth exceeds the supported limit.
    CallDepthExceeded { depth: usize, limit: usize },
    /// Inlined program would exceed the instruction-count limit.
    ExpansionTooLarge { got: usize, limit: usize },
    /// A pseudo-call target is out of range or not a subprogram entry.
    MalformedPseudoCall { insn_idx: usize },
    /// A jump offset computed during inlining exceeds the i16 range.
    JumpOffsetOverflow { insn_idx: usize },
    /// A jump target computed during inlining is outside the subprogram's [start, end) range.
    JumpTargetOutOfRange { insn_idx: usize },
    /// A direct r10-relative memory access is outside the callee's own frame `[-FRAME_SIZE, 0)`.
    StackOffsetOutOfFrame { insn_idx: usize },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ElfTooSmall => write!(f, "ELF data too small"),
            Self::InvalidMagic => write!(f, "invalid ELF magic number"),
            Self::UnsupportedClass => write!(f, "unsupported ELF class (not 64-bit)"),
            Self::UnsupportedEndian => write!(f, "unsupported endianness"),
            Self::UnsupportedMachine => write!(f, "unsupported ELF machine type"),
            Self::InvalidHeader => write!(f, "invalid ELF header"),
            Self::SectionOutOfBounds => write!(f, "section index out of bounds"),
            Self::InvalidSectionHeader => write!(f, "invalid section header"),
            Self::SectionDataOutOfBounds => write!(f, "section data out of bounds"),
            Self::InvalidStringTable => write!(f, "invalid string table"),
            Self::TooManyPrograms => write!(f, "too many programs in object file"),
            Self::TooManyMaps => write!(f, "too many maps in object file"),
            Self::InvalidMapData => write!(f, "invalid map definition data"),
            Self::UnsupportedMapType(t) => write!(f, "unsupported map type: {}", t),
            Self::InvalidInstructionData => write!(f, "invalid instruction data"),
            Self::InvalidRelocation => write!(f, "invalid relocation"),
            Self::UndefinedSymbol => write!(f, "undefined symbol in relocation"),
            Self::NoSymbolTable => write!(f, "symbol table not found"),
            Self::LicenseNotFound => write!(f, "license not found"),
            Self::InvalidLicense => write!(f, "invalid license string"),
            Self::BtfError => write!(f, "BTF parsing error"),
            Self::RecursiveCall { subprog } => {
                write!(f, "recursive subprogram call (subprog {})", subprog)
            }
            Self::CallDepthExceeded { depth, limit } => {
                write!(f, "call depth {} exceeds limit {}", depth, limit)
            }
            Self::ExpansionTooLarge { got, limit } => {
                write!(f, "expanded program {} insns exceeds limit {}", got, limit)
            }
            Self::MalformedPseudoCall { insn_idx } => {
                write!(f, "malformed pseudo-call at insn {}", insn_idx)
            }
            Self::JumpOffsetOverflow { insn_idx } => {
                write!(f, "jump offset overflow at insn {}", insn_idx)
            }
            Self::JumpTargetOutOfRange { insn_idx } => write!(
                f,
                "jump target out of subprogram range at insn {}",
                insn_idx
            ),
            Self::StackOffsetOutOfFrame { insn_idx } => write!(
                f,
                "direct r10-relative access out of callee frame at insn {}",
                insn_idx
            ),
        }
    }
}

/// Result type for loading operations.
pub type LoadResult<T> = Result<T, LoadError>;
