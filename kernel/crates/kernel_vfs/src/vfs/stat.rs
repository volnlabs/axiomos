#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    #[default]
    Regular,
    Directory,
    CharacterDevice,
    BlockDevice,
    Pipe,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stat {
    pub size: usize,
    pub file_type: FileType,
}
