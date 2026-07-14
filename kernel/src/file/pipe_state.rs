extern crate alloc;

use alloc::collections::VecDeque;

pub const PIPE_CAPACITY: usize = 64 * 1024;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PipeRead {
    Read(usize),
    EndOfFile,
    Block,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PipeWrite {
    Written(usize),
    Broken,
    Block,
}

#[derive(Debug)]
pub struct PipeState {
    buffer: VecDeque<u8>,
    readers: usize,
    writers: usize,
}

impl PipeState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: VecDeque::new(),
            readers: 1,
            writers: 1,
        }
    }

    pub fn read(&mut self, output: &mut [u8]) -> PipeRead {
        if output.is_empty() {
            return PipeRead::Read(0);
        }
        if self.buffer.is_empty() {
            return if self.writers == 0 {
                PipeRead::EndOfFile
            } else {
                PipeRead::Block
            };
        }

        let count = output.len().min(self.buffer.len());
        for byte in &mut output[..count] {
            *byte = self.buffer.pop_front().expect("pipe length was checked");
        }
        PipeRead::Read(count)
    }

    pub fn write(&mut self, input: &[u8]) -> PipeWrite {
        if self.readers == 0 {
            return PipeWrite::Broken;
        }
        if input.is_empty() {
            return PipeWrite::Written(0);
        }
        let available = PIPE_CAPACITY - self.buffer.len();
        if available == 0 {
            return PipeWrite::Block;
        }

        let count = input.len().min(available);
        self.buffer.extend(&input[..count]);
        PipeWrite::Written(count)
    }

    pub fn close_reader(&mut self) {
        self.readers = self.readers.saturating_sub(1);
    }

    pub fn close_writer(&mut self) {
        self.writers = self.writers.saturating_sub(1);
    }

    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for PipeState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_live_pipe_blocks_then_transfers_data() {
        let mut pipe = PipeState::new();
        let mut output = [0; 3];
        assert_eq!(pipe.read(&mut output), PipeRead::Block);
        assert_eq!(pipe.write(b"abc"), PipeWrite::Written(3));
        assert_eq!(pipe.read(&mut output), PipeRead::Read(3));
        assert_eq!(&output, b"abc");
    }

    #[test]
    fn writer_close_turns_empty_read_into_eof() {
        let mut pipe = PipeState::new();
        pipe.close_writer();
        assert_eq!(pipe.read(&mut [0; 1]), PipeRead::EndOfFile);
    }

    #[test]
    fn reader_close_breaks_writes() {
        let mut pipe = PipeState::new();
        pipe.close_reader();
        assert_eq!(pipe.write(b"x"), PipeWrite::Broken);
    }

    #[test]
    fn capacity_bounds_buffer_and_allows_partial_write() {
        let mut pipe = PipeState::new();
        let input = alloc::vec![1; PIPE_CAPACITY + 1];
        assert_eq!(pipe.write(&input), PipeWrite::Written(PIPE_CAPACITY));
        assert_eq!(pipe.write(b"x"), PipeWrite::Block);
        assert_eq!(pipe.buffered_len(), PIPE_CAPACITY);
    }
}
