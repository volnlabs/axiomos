use core::fmt::Write;

use conquer_once::spin::OnceCell;
use kernel_devfs::{ArcLockedDevFs, Null, Serial};
use kernel_vfs::path::{AbsolutePath, PathNotAbsoluteError};
use thiserror::Error;

use crate::serial_print;

static DEVFS: OnceCell<ArcLockedDevFs> = OnceCell::uninit();

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum DevFsInitError {
    #[error("default devfs path is invalid: {0}")]
    InvalidPath(#[from] PathNotAbsoluteError),
    #[error("default devfs node registration failed: {0}")]
    Registration(#[from] kernel_devfs::RegisterError),
}

#[must_use]
pub fn devfs() -> &'static ArcLockedDevFs {
    match DEVFS.get() {
        Some(devfs) => devfs,
        None => crate::fatal::halt("devfs-uninitialized"),
    }
}

pub fn init() -> Result<(), DevFsInitError> {
    let devfs = ArcLockedDevFs::new();
    {
        let mut guard = devfs.write();
        guard.register_file(AbsolutePath::try_new("/serial")?, || {
            Ok(Serial::<SerialWrite>::default())
        })?;

        // TODO: implement proper STDIO
        guard.register_file(AbsolutePath::try_new("/stdin")?, || Ok(Null))?;
        guard.register_file(AbsolutePath::try_new("/stdout")?, || {
            Ok(Serial::<SerialWrite>::default())
        })?;
        guard.register_file(AbsolutePath::try_new("/stderr")?, || {
            Ok(Serial::<SerialWrite>::default())
        })?;
    }
    DEVFS.init_once(|| devfs);
    Ok(())
}

#[derive(Default)]
struct SerialWrite;

impl Write for SerialWrite {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial_print!("{s}");
        Ok(())
    }
}
