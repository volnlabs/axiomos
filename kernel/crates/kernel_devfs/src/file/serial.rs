use core::fmt::Write;
use core::str::from_utf8;

use kernel_vfs::{FileType, ReadError, Stat, StatError, WriteError};

use crate::DevFile;

pub struct Serial<T> {
    out: T,
}

impl<T> Default for Serial<T>
where
    T: Default,
{
    fn default() -> Self {
        Self { out: T::default() }
    }
}

impl<T> DevFile for Serial<T>
where
    T: Write + Send + Sync,
{
    fn read(&mut self, _: &mut [u8], _: usize) -> Result<usize, ReadError> {
        Err(ReadError::EndOfFile)
    }

    fn write(&mut self, buf: &[u8], _: usize) -> Result<usize, WriteError> {
        let s = from_utf8(buf).map_err(|_| WriteError::WriteFailed)?;
        self.out.write_str(s).map_err(|_| WriteError::WriteFailed)?;
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
    use alloc::string::String;
    use core::fmt::{self, Write};

    use super::*;

    #[derive(Default)]
    struct RecordingWriter {
        output: String,
        fail: bool,
    }

    impl Write for RecordingWriter {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            if self.fail {
                return Err(fmt::Error);
            }
            self.output.push_str(value);
            Ok(())
        }
    }

    #[test]
    fn default_constructs_the_underlying_writer() {
        let device = Serial::<RecordingWriter>::default();

        assert!(device.out.output.is_empty());
        assert!(!device.out.fail);
    }

    #[test]
    fn reads_report_end_of_file_without_modifying_the_buffer() {
        let mut device = Serial::<RecordingWriter>::default();
        let mut buf = [0xa5; 4];

        assert_eq!(device.read(&mut buf, 37), Err(ReadError::EndOfFile));
        assert_eq!(buf, [0xa5; 4]);
    }

    #[test]
    fn writes_valid_utf8_to_the_underlying_writer() {
        let mut device = Serial::<RecordingWriter>::default();

        assert_eq!(device.write(b"hello", 91), Ok(5));
        assert_eq!(device.write(" world".as_bytes(), usize::MAX), Ok(6));
        assert_eq!(device.out.output, "hello world");
    }

    #[test]
    fn writes_reject_invalid_utf8_without_touching_the_writer() {
        let mut device = Serial::<RecordingWriter>::default();

        assert_eq!(device.write(&[0xff], 0), Err(WriteError::WriteFailed));
        assert!(device.out.output.is_empty());
    }

    #[test]
    fn writes_propagate_underlying_formatter_failures() {
        let mut device = Serial {
            out: RecordingWriter {
                output: String::new(),
                fail: true,
            },
        };

        assert_eq!(device.write(b"hello", 0), Err(WriteError::WriteFailed));
        assert!(device.out.output.is_empty());
    }

    #[test]
    fn stat_reports_an_empty_character_device() {
        let mut device = Serial::<RecordingWriter>::default();
        let mut stat = Stat {
            size: 99,
            file_type: FileType::Regular,
        };

        assert_eq!(device.stat(&mut stat), Ok(()));
        assert_eq!(stat.size, 0);
        assert_eq!(stat.file_type, FileType::CharacterDevice);
    }
}
