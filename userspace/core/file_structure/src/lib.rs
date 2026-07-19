#![no_std]

pub const STRUCTURE: Dir<'static> = Dir::new(
    "",
    &[
        Dir::new(
            "bin",
            &[],
            &[
                File::new("init", Kind::Executable),
                File::new("gpio_demo", Kind::Executable),
                File::new("pwm_demo", Kind::Executable),
                File::new("timeseries_demo", Kind::Executable),
                File::new("iio_demo", Kind::Executable),
                File::new("syscall_demo", Kind::Executable),
                File::new("sys_exit_demo", Kind::Executable),
                File::new("sched_switch_demo", Kind::Executable),
                File::new("sched_switch_export_demo", Kind::Executable),
                File::new("sched_switch_bridge_demo", Kind::Executable),
                File::new("rk_uart_forwarder", Kind::Executable),
                File::new("file_io_demo", Kind::Executable),
                File::new("fork_test", Kind::Executable),
                File::new("bpf_loader", Kind::Executable),
                File::new("signed_bpf_loader", Kind::Executable),
                File::new("benchmark", Kind::Executable),
                File::new("verifier_bench", Kind::Executable),
            ],
        ),
        Dir::new("dev", &[Dir::new("fd", &[], &[])], &[]),
        Dir::new(
            "var",
            &[
                Dir::new("tmp", &[], &[]),
                Dir::new(
                    "lib",
                    &[Dir::new("rkbpf", &[Dir::new("programs", &[], &[])], &[])],
                    &[],
                ),
            ],
            &[],
        ),
    ],
    &[],
);

pub struct Dir<'a> {
    pub name: &'a str,
    pub subdirs: &'a [Dir<'a>],
    pub files: &'a [File<'a>],
}

impl<'a> Dir<'a> {
    #[must_use]
    pub const fn new(name: &'a str, subdirs: &'a [Dir<'a>], files: &'a [File<'a>]) -> Self {
        Self {
            name,
            subdirs,
            files,
        }
    }

    /// Validate that this directory tree can be materialized below a root path.
    ///
    /// The root directory must have an empty name. Every descendant name must
    /// be a single, non-empty path component, and directory/file names must be
    /// unique within their parent. These constraints prevent a manifest entry
    /// from escaping or ambiguously replacing another rootfs entry.
    ///
    /// # Errors
    ///
    /// Returns the first invalid or duplicate entry encountered while walking
    /// the tree.
    pub fn validate(&self) -> Result<(), ValidationError<'a>> {
        if !self.name.is_empty() {
            return Err(ValidationError::RootName(self.name));
        }

        self.validate_descendants()
    }

    fn validate_descendants(&self) -> Result<(), ValidationError<'a>> {
        for (index, subdir) in self.subdirs.iter().enumerate() {
            validate_component(subdir.name)?;

            if self.subdirs[index + 1..]
                .iter()
                .any(|candidate| candidate.name == subdir.name)
                || self.files.iter().any(|file| file.name == subdir.name)
            {
                return Err(ValidationError::DuplicateName(subdir.name));
            }

            subdir.validate_descendants()?;
        }

        for (index, file) in self.files.iter().enumerate() {
            validate_component(file.name)?;
            if self.files[index + 1..]
                .iter()
                .any(|candidate| candidate.name == file.name)
            {
                return Err(ValidationError::DuplicateName(file.name));
            }
        }

        Ok(())
    }
}

pub struct File<'a> {
    pub name: &'a str,
    pub kind: Kind,
}

impl<'a> File<'a> {
    #[must_use]
    pub const fn new(name: &'a str, kind: Kind) -> Self {
        Self { name, kind }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Executable,
    Resource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError<'a> {
    RootName(&'a str),
    InvalidName(&'a str),
    DuplicateName(&'a str),
}

fn validate_component(name: &str) -> Result<(), ValidationError<'_>> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.as_bytes().iter().any(|byte| matches!(byte, b'/' | 0))
    {
        Err(ValidationError::InvalidName(name))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_dir<'a>(dir: &'a Dir<'a>, name: &str) -> Option<&'a Dir<'a>> {
        if dir.name == name {
            return Some(dir);
        }
        dir.subdirs.iter().find_map(|subdir| find_dir(subdir, name))
    }

    fn child_dir<'a>(dir: &'a Dir<'a>, name: &str) -> &'a Dir<'a> {
        dir.subdirs
            .iter()
            .find(|subdir| subdir.name == name)
            .expect("required child directory exists")
    }

    #[test]
    fn legacy_bpf_reflex_demo_is_not_shipped() {
        let bin = find_dir(&STRUCTURE, "bin").expect("/bin directory exists");
        let legacy_demo = concat!("safety", "_", "demo");

        assert!(
            !bin.files.iter().any(|file| file.name == legacy_demo),
            "v0.3 hard e-stop is kernel-owned; do not ship the legacy BPF safety demo"
        );
    }

    #[test]
    fn shipped_rootfs_manifest_is_safe_and_has_required_topology() {
        STRUCTURE
            .validate()
            .expect("shipped rootfs manifest is valid");

        let bin = child_dir(&STRUCTURE, "bin");
        let dev_fd = child_dir(child_dir(&STRUCTURE, "dev"), "fd");
        let programs = child_dir(child_dir(child_dir(&STRUCTURE, "var"), "lib"), "rkbpf");
        let programs = child_dir(programs, "programs");

        assert!(
            !bin.files.is_empty(),
            "the shipped image needs an init binary"
        );
        assert!(
            bin.files
                .iter()
                .any(|file| file.name == "init" && file.kind == Kind::Executable)
        );
        assert!(dev_fd.subdirs.is_empty() && dev_fd.files.is_empty());
        assert!(programs.subdirs.is_empty() && programs.files.is_empty());
        assert!(
            bin.files.iter().all(|file| file.kind == Kind::Executable),
            "/bin may only contain executable build artifacts"
        );
    }

    #[test]
    fn root_name_must_be_empty() {
        let root = Dir::new("root", &[], &[]);
        assert_eq!(root.validate(), Err(ValidationError::RootName("root")));
    }

    #[test]
    fn descendant_names_must_be_safe_path_components() {
        for invalid in ["", ".", "..", "nested/name", "nul\0name"] {
            let subdirs = [Dir::new(invalid, &[], &[])];
            let root = Dir::new("", &subdirs, &[]);
            assert_eq!(root.validate(), Err(ValidationError::InvalidName(invalid)));

            let files = [File::new(invalid, Kind::Resource)];
            let root = Dir::new("", &[], &files);
            assert_eq!(root.validate(), Err(ValidationError::InvalidName(invalid)));
        }
    }

    #[test]
    fn names_are_unique_across_sibling_directories_and_files() {
        let duplicate_dirs = [Dir::new("same", &[], &[]), Dir::new("same", &[], &[])];
        let root = Dir::new("", &duplicate_dirs, &[]);
        assert_eq!(root.validate(), Err(ValidationError::DuplicateName("same")));

        let duplicate_files = [
            File::new("same", Kind::Executable),
            File::new("same", Kind::Resource),
        ];
        let root = Dir::new("", &[], &duplicate_files);
        assert_eq!(root.validate(), Err(ValidationError::DuplicateName("same")));

        let dirs = [Dir::new("same", &[], &[])];
        let files = [File::new("same", Kind::Resource)];
        let root = Dir::new("", &dirs, &files);
        assert_eq!(root.validate(), Err(ValidationError::DuplicateName("same")));
    }

    #[test]
    fn nested_manifest_entries_are_validated_recursively() {
        let invalid_files = [File::new("../escape", Kind::Resource)];
        let nested = [Dir::new("nested", &[], &invalid_files)];
        let root = Dir::new("", &nested, &[]);

        assert_eq!(
            root.validate(),
            Err(ValidationError::InvalidName("../escape"))
        );
    }
}
