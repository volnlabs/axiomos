use std::fs;
use std::fs::{copy, create_dir, create_dir_all, exists, remove_dir_all, remove_file};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use file_structure::{Dir, Kind};
use ovmf_prebuilt::{Arch, FileType, Prebuilt, Source};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=limine.conf");

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let kernel_env = if target_arch == "x86_64" {
        "CARGO_BIN_FILE_KERNEL_X86_kernel"
    } else if target_arch == "aarch64" {
        "CARGO_BIN_FILE_KERNEL_AARCH64_kernel"
    } else {
        panic!("Unsupported architecture: {}", target_arch);
    };

    let kernel = PathBuf::from(
        std::env::var_os(kernel_env)
            .unwrap_or_else(|| panic!("{} environment variable should be set", kernel_env)),
    );
    println!("cargo:rustc-env=KERNEL_BINARY={}", kernel.display());

    if target_arch == "x86_64" {
        let limine_dir = limine();
        let iso = build_iso(&limine_dir, &kernel);
        println!("cargo:rustc-env=BOOTABLE_ISO={}", iso.display());

        let ovmf = ovmf();
        println!(
            "cargo:rustc-env=OVMF_X86_64_CODE={}",
            ovmf.get_file(Arch::X64, FileType::Code).display()
        );
        println!(
            "cargo:rustc-env=OVMF_X86_64_VARS={}",
            ovmf.get_file(Arch::X64, FileType::Vars).display()
        );
    } else {
        // Provide dummy values for other architectures to satisfy env!() in main.rs if it's compiled
        // though in our case we cfg-ed it out in main.rs.
        // However, it's safer to just not break the build if possible.
        println!("cargo:rustc-env=BOOTABLE_ISO=unused");
        println!("cargo:rustc-env=OVMF_X86_64_CODE=unused");
        println!("cargo:rustc-env=OVMF_X86_64_VARS=unused");
    }

    let disk_image = build_os_disk_image(&target_arch);
    println!("cargo:rustc-env=DISK_IMAGE={}", disk_image.display());
}

fn build_os_disk_image(target_arch: &str) -> PathBuf {
    let disk_dir = build_os_disk_dir(target_arch);
    let disk_image = disk_dir.with_extension("img");

    let _ = remove_file(&disk_image); // if this fails, doesn't matter

    // works on my machine. TODO: use the mkfs-ext2 crate once it's ready
    let mut cmd = Command::new("mke2fs");
    cmd.arg("-d").arg(
        disk_dir
            .to_str()
            .expect("disk_dir path should be valid UTF-8"),
    );
    cmd.arg("-m").arg("5");
    cmd.arg("-t").arg("ext2");
    cmd.arg(
        disk_image
            .to_str()
            .expect("disk_image path should be valid UTF-8"),
    );
    // The embedded ext2 image now carries multiple demo/bridge binaries.
    // Keep some headroom so incremental demo work does not immediately exhaust
    // the rootfs during image population.
    cmd.arg("20M");

    let rc = cmd.status().expect("mke2fs command should execute");
    assert_eq!(
        0,
        rc.code().expect("mke2fs should have an exit code"),
        "process should exit successfully"
    );

    disk_image
}

fn build_os_disk_dir(target_arch: &str) -> PathBuf {
    let disk = out_dir().join("disk");
    let _ = remove_dir_all(&disk);
    create_dir(&disk).expect("should be able to create disk directory");

    build_dir(&disk, &file_structure::STRUCTURE, target_arch);

    fs::write(disk.join("var/hello.txt"), "Hello, axiom-ebpf!\n")
        .expect("should be able to write hello.txt");

    disk
}

fn build_dir(current_path: &Path, current_dir: &Dir<'_>, target_arch: &str) {
    for file in current_dir.files {
        let file_path = current_path.join(file.name);
        match file.kind {
            Kind::Executable => {
                let suffix = if target_arch == "x86_64" {
                    "x86"
                } else {
                    target_arch
                };
                let dep_name = format!("{}_{}", file.name, suffix);
                let env_var = format!("CARGO_BIN_FILE_{}_{}", dep_name.to_uppercase(), file.name);
                let bindep = std::env::var_os(&env_var).unwrap_or_else(|| {
                    panic!("could not find the bindep {env_var} in the environment variables")
                });
                copy(&bindep, &file_path).expect("should be able to copy executable to disk");
            }
            Kind::Resource => {
                todo!("copy resource into the disk image");
            }
        }
    }

    for subdir in current_dir.subdirs {
        let subdir_path = current_path.join(subdir.name);
        create_dir(&subdir_path).expect("should be able to create subdirectory");

        build_dir(&subdir_path, subdir, target_arch);
    }
}

fn ovmf() -> Prebuilt {
    Prebuilt::fetch(Source::LATEST, PathBuf::from("target/ovmf"))
        .expect("should be able to fetch OVMF prebuilt firmware")
}

fn build_iso(limine_checkout: impl AsRef<Path>, kernel_binary: impl AsRef<Path>) -> PathBuf {
    let limine_checkout = limine_checkout.as_ref();
    let kernel_binary = kernel_binary.as_ref();

    let out_dir = out_dir();

    let iso_dir = out_dir.join("iso_root");
    let boot_dir = iso_dir.join("boot");
    let limine_dir = boot_dir.join("limine");
    create_dir_all(&limine_dir).expect("should be able to create limine directory");
    let efi_boot_dir = iso_dir.join("EFI/BOOT");
    create_dir_all(&efi_boot_dir).expect("should be able to create EFI boot directory");

    let project_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR environment variable should be set"),
    );

    let limine_conf_name = "limine.conf";
    let limine_conf = project_dir.join(limine_conf_name);

    copy(limine_conf, limine_dir.join(limine_conf_name))
        .expect("should be able to copy limine.conf");

    // copy the kernel binary to the location that is specified in limine.conf
    copy(kernel_binary, boot_dir.join("kernel")).expect("should be able to copy kernel binary");

    // the following is x86_64 specific

    for path in [
        "limine-bios.sys",
        "limine-bios-cd.bin",
        "limine-uefi-cd.bin",
    ] {
        let from = limine_checkout.join(path);
        let to = limine_dir.join(path);
        copy(&from, &to).unwrap_or_else(|_| {
            panic!(
                "should be able to copy {} to {}",
                from.display(),
                to.display()
            )
        });
    }

    for path in ["BOOTX64.EFI", "BOOTIA32.EFI"] {
        let from = limine_checkout.join(path);
        let to = efi_boot_dir.join(path);
        copy(from, to).expect("should be able to copy EFI boot files");
    }

    let output_iso = out_dir.join("muffin.iso");

    let status = std::process::Command::new("xorriso")
        .arg("-as")
        .arg("mkisofs")
        .arg("-b")
        .arg(
            limine_dir
                .join("limine-bios-cd.bin")
                .strip_prefix(&iso_dir)
                .expect("limine-bios-cd.bin path should be within iso_dir"),
        )
        .arg("-no-emul-boot")
        .arg("-boot-load-size")
        .arg("4")
        .arg("-boot-info-table")
        .arg("--efi-boot")
        .arg(
            limine_dir
                .join("limine-uefi-cd.bin")
                .strip_prefix(&iso_dir)
                .expect("limine-uefi-cd.bin path should be within iso_dir"),
        )
        .arg("-efi-boot-part")
        .arg("--efi-boot-image")
        .arg("--protective-msdos-label")
        .arg(iso_dir)
        .arg("-o")
        .arg(&output_iso)
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .status()
        .expect("xorriso command should execute");
    assert!(status.success());

    let status = std::process::Command::new(limine_checkout.join("limine"))
        .arg("bios-install")
        .arg(&output_iso)
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .status()
        .expect("limine bios-install command should execute");
    assert!(status.success());

    output_iso
}

fn limine() -> PathBuf {
    let limine_dir = PathBuf::from("target/limine");

    // check whether we've already checked it out
    if exists(&limine_dir).expect("should be able to check if limine directory exists") {
        return limine_dir;
    }

    // check out
    let status = std::process::Command::new("git")
        .arg("clone")
        .arg("https://github.com/limine-bootloader/limine.git")
        .arg("--branch=v9.x-binary")
        .arg("--depth=1")
        .arg(&limine_dir)
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .status()
        .expect("git clone command should execute");
    assert!(status.success());

    // build
    let status = std::process::Command::new("make")
        .current_dir(&limine_dir)
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .status()
        .expect("make command should execute");
    assert!(status.success());

    limine_dir
}

fn out_dir() -> PathBuf {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR environment variable should be set");
    PathBuf::from(out_dir)
}
