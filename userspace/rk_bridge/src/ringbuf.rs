//! Ring buffer consumer for reading rkBPF events through the Axiom BPF syscall path.
//!
//! The current kernel exposes pinned map lookup plus `BPF_RINGBUF_POLL`, not a
//! file-backed `mmap` interface. This consumer opens a pinned object path,
//! queries the map metadata, and drains events by polling the kernel.

use kernel_abi::{
    BpfAttr, BpfObjectInfo, BpfMapTags, SYS_BPF, BPF_OBJECT_KIND_MAP, BPF_OBJ_GET,
    BPF_OBJ_GET_INFO_BY_FD, BPF_RINGBUF_POLL,
};
use std::ffi::CString;
use std::io;
use std::path::Path;

const DEFAULT_EVENT_BUF_SIZE: usize = 4096;

/// Errors that can occur when working with ring buffers.
#[derive(Debug, thiserror::Error)]
pub enum RingBufError {
    /// Failed to resolve the pinned ring buffer object.
    #[error("failed to open pinned ring buffer {path}: {source}")]
    Open { path: String, source: io::Error },

    /// Failed to query ring buffer metadata from the kernel.
    #[error("failed to query ring buffer info for map fd {map_fd}: {source}")]
    Info { map_fd: u32, source: io::Error },

    /// The object returned by the kernel is not a ring buffer map.
    #[error("object at {path} is not a ring buffer map")]
    NotRingBuf { path: String },

    /// Ring buffer path is invalid for syscall use.
    #[error("invalid pinned object path {0}")]
    InvalidPath(String),

    /// Polling the ring buffer failed.
    #[error("ring buffer poll failed for map fd {map_fd}: {source}")]
    Poll { map_fd: u32, source: io::Error },
}

/// Consumer for reading events from a pinned BPF ring buffer.
pub struct RingBufConsumer {
    map_fd: u32,
    event_buf: Vec<u8>,
    info: BpfObjectInfo,
}

impl RingBufConsumer {
    /// Open a ring buffer from a pinned BPF object path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, RingBufError> {
        let path = path.as_ref();
        let path_string = path.display().to_string();
        let c_path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| RingBufError::InvalidPath(path_string.clone()))?;

        let map_fd = bpf_obj_get(&c_path).map_err(|source| RingBufError::Open {
            path: path_string.clone(),
            source,
        })?;

        let info = bpf_obj_get_info_by_fd(map_fd).map_err(|source| RingBufError::Info {
            map_fd,
            source,
        })?;

        if info.object_kind != BPF_OBJECT_KIND_MAP
            || info.map_type != BpfMapTags::RINGBUF.bits()
        {
            return Err(RingBufError::NotRingBuf { path: path_string });
        }

        let event_buf_size = usize::try_from(info.max_entries)
            .ok()
            .filter(|size| *size > 0)
            .unwrap_or(DEFAULT_EVENT_BUF_SIZE);

        Ok(Self {
            map_fd,
            event_buf: vec![0u8; event_buf_size],
            info,
        })
    }

    /// Drain all currently available events without blocking.
    pub fn poll(&mut self) -> Result<Vec<Vec<u8>>, RingBufError> {
        let mut events = Vec::new();

        while let Some(event) = self.read_event()? {
            events.push(event);
        }

        Ok(events)
    }

    /// Read the next event from the ring buffer.
    pub fn read_event(&mut self) -> Result<Option<Vec<u8>>, RingBufError> {
        loop {
            let attr = BpfAttr {
                map_fd: self.map_fd,
                key: self.event_buf.as_mut_ptr() as u64,
                value: self.event_buf.len() as u64,
                ..Default::default()
            };

            let result = sys_bpf(BPF_RINGBUF_POLL, &attr);
            if result == 0 {
                return Ok(None);
            }
            if result > 0 {
                let size = result as usize;
                return Ok(Some(self.event_buf[..size].to_vec()));
            }

            let err = io::Error::from_raw_os_error((-result) as i32);
            if err.raw_os_error() == Some(libc::ENOSPC) {
                let next_len = self.event_buf.len().saturating_mul(2).max(DEFAULT_EVENT_BUF_SIZE);
                self.event_buf.resize(next_len, 0);
                continue;
            }

            return Err(RingBufError::Poll {
                map_fd: self.map_fd,
                source: err,
            });
        }
    }

    /// Return the pinned map identifier exposed by the kernel.
    pub fn map_fd(&self) -> u32 {
        self.map_fd
    }

    /// Return kernel metadata for the opened map.
    pub fn info(&self) -> &BpfObjectInfo {
        &self.info
    }
}

fn bpf_obj_get(path: &CString) -> io::Result<u32> {
    let attr = BpfAttr {
        pathname: path.as_ptr() as u64,
        path_len: path.as_bytes_with_nul().len() as u32,
        ..Default::default()
    };

    let result = sys_bpf(BPF_OBJ_GET, &attr);
    if result < 0 {
        Err(io::Error::from_raw_os_error((-result) as i32))
    } else {
        Ok(result as u32)
    }
}

fn bpf_obj_get_info_by_fd(map_fd: u32) -> io::Result<BpfObjectInfo> {
    let mut info = BpfObjectInfo::default();
    let attr = BpfAttr {
        map_fd,
        info: (&mut info as *mut BpfObjectInfo) as u64,
        info_len: core::mem::size_of::<BpfObjectInfo>() as u32,
        ..Default::default()
    };

    let result = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr);
    if result < 0 {
        Err(io::Error::from_raw_os_error((-result) as i32))
    } else {
        Ok(info)
    }
}

fn sys_bpf(cmd: u32, attr: &BpfAttr) -> i32 {
    unsafe {
        libc::syscall(
            SYS_BPF as libc::c_long,
            cmd as libc::c_long,
            attr as *const BpfAttr,
            core::mem::size_of::<BpfAttr>() as libc::c_long,
        ) as i32
    }
}

/// Mock ring buffer for testing without kernel interaction.
pub struct MockRingBuf {
    events: Vec<Vec<u8>>,
    position: usize,
}

impl MockRingBuf {
    /// Create a new mock ring buffer with pre-loaded events.
    pub fn new(events: Vec<Vec<u8>>) -> Self {
        Self { events, position: 0 }
    }

    /// Read the next event.
    pub fn read_event(&mut self) -> Option<Vec<u8>> {
        if self.position < self.events.len() {
            let event = self.events[self.position].clone();
            self.position += 1;
            Some(event)
        } else {
            None
        }
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.position >= self.events.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_ringbuf() {
        let events = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        let mut mock = MockRingBuf::new(events);
        assert!(!mock.is_empty());

        assert_eq!(mock.read_event(), Some(vec![1, 2, 3]));
        assert_eq!(mock.read_event(), Some(vec![4, 5, 6]));
        assert_eq!(mock.read_event(), Some(vec![7, 8, 9]));
        assert_eq!(mock.read_event(), None);
        assert!(mock.is_empty());
    }
}
