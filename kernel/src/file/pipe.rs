use alloc::sync::Arc;

use kernel_vfs::{FileType, ReadError, Stat, StatError, WriteError};
use spin::Mutex;

use crate::file::pipe_state::{PipeRead, PipeState, PipeWrite};
use crate::mcore::mtask::scheduler::wait::{TaskWait, WaitChannel};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum PipeDirection {
    Read,
    Write,
}

#[derive(Debug)]
struct Pipe {
    state: Mutex<PipeState>,
    readable: Arc<WaitChannel>,
    writable: Arc<WaitChannel>,
}

impl Pipe {
    fn new() -> Self {
        Self {
            state: Mutex::new(PipeState::new()),
            readable: Arc::new(WaitChannel::new()),
            writable: Arc::new(WaitChannel::new()),
        }
    }
}

#[derive(Debug)]
pub struct PipeEndpoint {
    pipe: Arc<Pipe>,
    direction: PipeDirection,
}

impl PipeEndpoint {
    #[must_use]
    pub fn pair() -> (Self, Self) {
        let pipe = Arc::new(Pipe::new());
        (
            Self {
                pipe: pipe.clone(),
                direction: PipeDirection::Read,
            },
            Self {
                pipe,
                direction: PipeDirection::Write,
            },
        )
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, ReadError> {
        if self.direction != PipeDirection::Read {
            return Err(ReadError::NotReadable);
        }

        loop {
            let mut state = self.pipe.state.lock();
            match state.read(buf) {
                PipeRead::Read(bytes) => {
                    self.pipe.writable.wake_all();
                    return Ok(bytes);
                }
                PipeRead::EndOfFile => return Ok(0),
                PipeRead::Block => {
                    TaskWait::block_current(&self.pipe.readable, move || drop(state));
                }
            }
        }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, WriteError> {
        if self.direction != PipeDirection::Write {
            return Err(WriteError::NotWritable);
        }

        loop {
            let mut state = self.pipe.state.lock();
            match state.write(buf) {
                PipeWrite::Written(bytes) => {
                    self.pipe.readable.wake_all();
                    return Ok(bytes);
                }
                PipeWrite::Broken => return Err(WriteError::BrokenPipe),
                PipeWrite::Block => {
                    TaskWait::block_current(&self.pipe.writable, move || drop(state));
                }
            }
        }
    }

    pub fn stat(&self, stat: &mut Stat) -> Result<(), StatError> {
        stat.size = self.pipe.state.lock().buffered_len();
        stat.file_type = FileType::Pipe;
        Ok(())
    }
}

impl Drop for PipeEndpoint {
    fn drop(&mut self) {
        let mut state = self.pipe.state.lock();
        match self.direction {
            PipeDirection::Read => {
                state.close_reader();
                self.pipe.writable.wake_all();
            }
            PipeDirection::Write => {
                state.close_writer();
                self.pipe.readable.wake_all();
            }
        }
    }
}
