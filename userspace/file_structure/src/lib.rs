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

pub enum Kind {
    Executable,
    Resource,
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

    #[test]
    fn legacy_bpf_reflex_demo_is_not_shipped() {
        let bin = find_dir(&STRUCTURE, "bin").expect("/bin directory exists");
        let legacy_demo = concat!("safety", "_", "demo");

        assert!(
            !bin.files.iter().any(|file| file.name == legacy_demo),
            "v0.3 hard e-stop is kernel-owned; do not ship the legacy BPF safety demo"
        );
    }
}
