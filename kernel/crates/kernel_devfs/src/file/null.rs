use kernel_vfs::{FileType, ReadError, Stat, StatError, WriteError};

use crate::DevFile;

#[derive(Debug, Copy, Clone)]
pub struct Null;

impl DevFile for Null {
    fn read(&mut self, _: &mut [u8], _: usize) -> Result<usize, ReadError> {
        Err(ReadError::EndOfFile)
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
    fn reads_report_end_of_file_without_modifying_the_buffer() {
        let mut device = Null;
        let mut buf = [0xa5; 4];

        assert_eq!(device.read(&mut buf, 37), Err(ReadError::EndOfFile));
        assert_eq!(buf, [0xa5; 4]);
    }

    #[test]
    fn writes_discard_every_byte_at_any_offset() {
        let mut device = Null;

        assert_eq!(device.write(b"discarded", 91), Ok(9));
        assert_eq!(device.write(&[], usize::MAX), Ok(0));
    }

    #[test]
    fn stat_reports_an_empty_character_device() {
        let mut device = Null;
        let mut stat = Stat {
            size: 99,
            file_type: FileType::Regular,
        };

        assert_eq!(device.stat(&mut stat), Ok(()));
        assert_eq!(stat.size, 0);
        assert_eq!(stat.file_type, FileType::CharacterDevice);
    }
}
