use kernel_vfs::{FileType, ReadError, Stat, StatError, WriteError};

use crate::DevFile;

#[derive(Debug, Copy, Clone)]
pub struct Zero;

impl DevFile for Zero {
    fn read(&mut self, buf: &mut [u8], _: usize) -> Result<usize, ReadError> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&mut self, buf: &[u8], _: usize) -> Result<usize, WriteError> {
        Ok(buf.len())
    }

    fn stat(&mut self, stat: &mut Stat) -> Result<(), StatError> {
        stat.size = 0;
        stat.file_type = FileType::CharacterDevice;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fill_the_entire_buffer_with_zeroes_at_any_offset() {
        let mut device = Zero;
        let mut buf = [0xa5; 5];

        assert_eq!(device.read(&mut buf, 37), Ok(buf.len()));
        assert_eq!(buf, [0; 5]);

        let mut empty = [];
        assert_eq!(device.read(&mut empty, usize::MAX), Ok(0));
    }

    #[test]
    fn writes_discard_every_byte_at_any_offset() {
        let mut device = Zero;

        assert_eq!(device.write(b"discarded", 91), Ok(9));
        assert_eq!(device.write(&[], usize::MAX), Ok(0));
    }

    #[test]
    fn stat_reports_an_empty_character_device() {
        let mut device = Zero;
        let mut stat = Stat {
            size: 99,
            file_type: FileType::Regular,
        };

        assert_eq!(device.stat(&mut stat), Ok(()));
        assert_eq!(stat.size, 0);
        assert_eq!(stat.file_type, FileType::CharacterDevice);
    }
}
