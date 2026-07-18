use kernel_abi::{EINVAL, ENAMETOOLONG, ERANGE, Errno, PATH_MAX, UIO_MAXIOV};
use kernel_vfs::path::{AbsolutePath, Path};

use crate::access::{CwdAccess, FileAccess};

/// Whence values for lseek
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

pub fn sys_getcwd<Cx: CwdAccess>(cx: &Cx, buf: &mut [u8]) -> Result<usize, Errno> {
    if buf.is_empty() {
        return Err(EINVAL);
    }

    let cwd = cx.current_working_directory();
    let guard = cwd.read();
    let bytelen = guard.len();
    if buf.len() <= bytelen {
        return Err(ERANGE);
    }
    buf.iter_mut().zip(guard.bytes()).for_each(|(s, b)| {
        *s = b;
    });
    buf[bytelen] = 0; // Null-terminate the string

    Ok(bytelen + 1)
}

pub fn sys_read<Cx: FileAccess>(cx: &Cx, fildes: Cx::Fd, buf: &mut [u8]) -> Result<usize, Errno> {
    cx.read(fildes, buf).map_err(|error| error.errno())
}

pub fn sys_write<Cx: FileAccess>(cx: &Cx, fildes: Cx::Fd, buf: &[u8]) -> Result<usize, Errno> {
    cx.write(fildes, buf).map_err(|error| error.errno())
}

pub fn sys_writev<Cx: FileAccess>(
    cx: &Cx,
    fildes: Cx::Fd,
    buffers: &[&[u8]],
) -> Result<usize, Errno> {
    if buffers.len() > UIO_MAXIOV {
        return Err(EINVAL);
    }

    let mut total_written = 0usize;
    let fd_int: core::ffi::c_int = fildes.into();

    for buffer in buffers {
        if buffer.is_empty() {
            continue;
        }

        let current_fd = Cx::Fd::from(fd_int);
        let written = cx
            .write(current_fd, buffer)
            .map_err(|error| error.errno())?;
        total_written = total_written.checked_add(written).ok_or(EINVAL)?;

        if written < buffer.len() {
            break;
        }
    }

    Ok(total_written)
}

/// Close a file descriptor.
pub fn sys_close<Cx: FileAccess>(cx: &Cx, fildes: Cx::Fd) -> Result<usize, Errno> {
    cx.close(fildes).map_err(|error| error.errno())?;
    Ok(0)
}

/// Reposition read/write file offset.
pub fn sys_lseek<Cx: FileAccess>(
    cx: &Cx,
    fildes: Cx::Fd,
    offset: i64,
    whence: i32,
) -> Result<usize, Errno> {
    cx.lseek(fildes, offset, whence)
        .map_err(|error| error.errno())
}

/// Create a pipe and return its read and write descriptors.
pub fn sys_pipe<Cx: FileAccess>(cx: &Cx) -> Result<(Cx::Fd, Cx::Fd), Errno> {
    let (read_fd, write_fd) = cx.pipe().map_err(|error| error.errno())?;
    Ok((read_fd, write_fd))
}

/// Duplicate a file descriptor.
pub fn sys_dup<Cx: FileAccess>(cx: &Cx, oldfd: Cx::Fd) -> Result<usize, Errno> {
    let newfd = cx.dup(oldfd).map_err(|error| error.errno())?;
    Ok(newfd.into() as usize)
}

/// Duplicate a file descriptor to a specific value.
pub fn sys_dup2<Cx: FileAccess>(cx: &Cx, oldfd: Cx::Fd, newfd: Cx::Fd) -> Result<usize, Errno> {
    let res = cx.dup2(oldfd, newfd).map_err(|error| error.errno())?;
    Ok(res.into() as usize)
}

fn resolve_path<Cx: CwdAccess>(
    cx: &Cx,
    path_bytes: &[u8],
) -> Result<alloc::borrow::Cow<'static, AbsolutePath>, Errno> {
    use alloc::borrow::{Cow, ToOwned};

    if path_bytes.len() > PATH_MAX {
        return Err(ENAMETOOLONG);
    }

    let path_str = core::str::from_utf8(path_bytes).map_err(|_| EINVAL)?;
    let path = Path::new(path_str);

    if let Ok(p) = AbsolutePath::try_new(path) {
        Ok(Cow::Owned(p.to_owned()))
    } else {
        let mut p = cx.current_working_directory().read().clone();
        p.push(path);
        Ok(Cow::Owned(p))
    }
}

pub fn sys_chdir<Cx: CwdAccess>(cx: &Cx, path_bytes: &[u8]) -> Result<usize, Errno> {
    let path = resolve_path(cx, path_bytes)?;
    cx.chdir(&path)?;
    Ok(0)
}

pub fn sys_mkdir<Cx: CwdAccess + FileAccess>(
    cx: &Cx,
    path_bytes: &[u8],
    _mode: usize,
) -> Result<usize, Errno> {
    let path = resolve_path(cx, path_bytes)?;
    cx.mkdir(&path).map_err(|error| error.errno())?;
    Ok(0)
}

pub fn sys_rmdir<Cx: CwdAccess + FileAccess>(cx: &Cx, path_bytes: &[u8]) -> Result<usize, Errno> {
    let path = resolve_path(cx, path_bytes)?;
    cx.rmdir(&path).map_err(|error| error.errno())?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;
    use alloc::vec;

    use kernel_abi::{EINVAL, ERANGE, Errno};
    use kernel_vfs::path::{AbsoluteOwnedPath, AbsolutePath};
    use spin::rwlock::RwLock;

    use crate::access::CwdAccess;
    use crate::unistd::sys_getcwd;

    #[test]
    fn test_getcwd() {
        struct Cwd<'a>(&'a RwLock<AbsoluteOwnedPath>);
        impl CwdAccess for Cwd<'_> {
            fn current_working_directory(&self) -> &RwLock<AbsoluteOwnedPath> {
                self.0
            }

            fn chdir(&self, path: &AbsolutePath) -> Result<(), Errno> {
                *self.0.write() = path.to_owned();
                Ok(())
            }
        }

        for args in [
            (("/test/path", 0), Err(EINVAL)),
            (("/test/path", 10), Err(ERANGE)),
            (("/test/path", 11), Ok(11)),
        ] {
            let ((path, size), expected) = args;
            let cwd = AbsoluteOwnedPath::try_from(path).unwrap().into();
            let access = Cwd(&cwd);
            let mut buf = vec![0u8; size];
            let res = sys_getcwd(&access, &mut buf);
            match expected {
                Ok(expected_len) => match res {
                    Ok(written) => {
                        assert_eq!(written, expected_len);
                        assert_eq!(path.as_bytes(), &buf[..path.len()]);
                        assert_eq!(0, buf[path.len()]);
                    }
                    Err(e) => panic!("failed with {e} but expected success"),
                },
                Err(e) => {
                    assert_eq!(res, Err(e));
                }
            }
        }
    }
}
