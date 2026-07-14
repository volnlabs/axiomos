use thiserror::Error;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum MountError {
    #[error("the mount point is already used by another mount")]
    AlreadyMounted,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum UnmountError {
    #[error("not mounted")]
    NotMounted,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum ExistsError {}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum OpenError {
    #[error("not found")]
    NotFound,
    #[error("path is a directory")]
    IsDirectory,
    #[error("file type is not supported")]
    UnsupportedFileType,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum CloseError {
    #[error("not open")]
    NotOpen,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum FsError {
    #[error("filesystem is not open")]
    FileSystemNotOpen,
    #[error("invalid handle")]
    InvalidHandle,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum ReadError {
    #[error("{0}")]
    FsError(
        #[from]
        #[source]
        FsError,
    ),
    #[error("end of file")]
    EndOfFile,
    #[error("read failed")]
    ReadFailed,
    #[error("file is not readable")]
    NotReadable,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum WriteError {
    #[error("{0}")]
    FsError(
        #[from]
        #[source]
        FsError,
    ),
    #[error("write failed")]
    WriteFailed,
    #[error("file is not writable")]
    NotWritable,
    #[error("pipe has no reader")]
    BrokenPipe,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum StatError {
    #[error("{0}")]
    FsError(
        #[from]
        #[source]
        FsError,
    ),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum MkdirError {
    #[error("{0}")]
    FsError(
        #[from]
        #[source]
        FsError,
    ),
    #[error("already exists")]
    AlreadyExists,
    #[error("parent not found")]
    NotFound,
    #[error("parent is not a directory")]
    NotADirectory,
    #[error("directory creation is not supported")]
    Unsupported,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum RmdirError {
    #[error("{0}")]
    FsError(
        #[from]
        #[source]
        FsError,
    ),
    #[error("not found")]
    NotFound,
    #[error("not a directory")]
    NotADirectory,
    #[error("directory not empty")]
    NotEmpty,
    #[error("directory removal is not supported")]
    Unsupported,
}
