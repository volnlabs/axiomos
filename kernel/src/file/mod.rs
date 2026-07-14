use core::sync::atomic::{AtomicU64, Ordering};

use kernel_vfs::node::VfsNode;
use kernel_vfs::path::AbsolutePath;
use kernel_vfs::Vfs;
use spin::RwLock;

use crate::file::devfs::devfs;

pub mod devfs;
pub mod ext2;
pub mod pipe;
mod pipe_state;

use pipe::PipeEndpoint;

static VFS: RwLock<Vfs> = RwLock::new(Vfs::new());

#[must_use]
pub fn vfs() -> &'static RwLock<Vfs> {
    &VFS
}

pub fn init() {
    devfs::init();

    VFS.write()
        .mount(AbsolutePath::try_new("/dev").unwrap(), devfs().clone())
        .expect("should be able to mount devfs");
}

#[derive(Debug)]
pub struct OpenFileDescription {
    position: AtomicU64,
    object: FileObject,
}

#[derive(Debug)]
enum FileObject {
    Node(VfsNode),
    Pipe(PipeEndpoint),
}

impl From<VfsNode> for OpenFileDescription {
    fn from(node: VfsNode) -> Self {
        Self {
            position: AtomicU64::new(0),
            object: FileObject::Node(node),
        }
    }
}

impl OpenFileDescription {
    #[must_use]
    pub fn from_pipe(endpoint: PipeEndpoint) -> Self {
        Self {
            position: AtomicU64::new(0),
            object: FileObject::Pipe(endpoint),
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, kernel_vfs::ReadError> {
        match &self.object {
            FileObject::Node(node) => {
                let len = buf.len() as u64;
                let offset = self.position.fetch_add(len, Ordering::Relaxed);
                match node.read(buf, offset as usize) {
                    Ok(read) => {
                        self.position
                            .fetch_sub(len.saturating_sub(read as u64), Ordering::Relaxed);
                        Ok(read)
                    }
                    Err(error) => {
                        self.position.fetch_sub(len, Ordering::Relaxed);
                        Err(error)
                    }
                }
            }
            FileObject::Pipe(endpoint) => endpoint.read(buf),
        }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, kernel_vfs::WriteError> {
        match &self.object {
            FileObject::Node(node) => {
                let len = buf.len() as u64;
                let offset = self.position.fetch_add(len, Ordering::Relaxed);
                match node.write(buf, offset as usize) {
                    Ok(written) => {
                        self.position
                            .fetch_sub(len.saturating_sub(written as u64), Ordering::Relaxed);
                        Ok(written)
                    }
                    Err(error) => {
                        self.position.fetch_sub(len, Ordering::Relaxed);
                        Err(error)
                    }
                }
            }
            FileObject::Pipe(endpoint) => endpoint.write(buf),
        }
    }

    pub fn stat(&self, stat: &mut kernel_vfs::Stat) -> Result<(), kernel_vfs::StatError> {
        match &self.object {
            FileObject::Node(node) => node.stat(stat),
            FileObject::Pipe(endpoint) => endpoint.stat(stat),
        }
    }

    #[must_use]
    pub fn is_seekable(&self) -> bool {
        matches!(self.object, FileObject::Node(_))
    }

    pub fn position(&self) -> &AtomicU64 {
        &self.position
    }
}
