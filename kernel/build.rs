fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    // Handle embedded disk image for rpi5
    if std::env::var("CARGO_FEATURE_RPI5").is_ok() {
        let out_dir = std::env::var("OUT_DIR").unwrap();

        if let Ok(disk_path) = std::env::var("AXIOM_DISK_IMAGE") {
            // Use pre-built disk image
            let dest = format!("{}/disk.img", out_dir);
            std::fs::copy(&disk_path, &dest)
                .unwrap_or_else(|e| panic!("failed to copy disk image from {}: {}", disk_path, e));
            println!("cargo:rustc-env=EMBEDDED_DISK_PATH={}", dest);
            println!("cargo:rerun-if-changed={}", disk_path);
        } else {
            // Generate a minimal empty ext2 disk image as fallback
            let dest = format!("{}/disk.img", out_dir);
            let status = std::process::Command::new("mke2fs")
                .arg("-t")
                .arg("ext2")
                .arg(&dest)
                .arg("10M")
                .status()
                .expect("mke2fs command should execute (install e2fsprogs)");
            assert!(status.success(), "mke2fs should succeed");
            println!("cargo:rustc-env=EMBEDDED_DISK_PATH={}", dest);
        }
    }

    // Set linker script
    let linker_script = if std::env::var("CARGO_FEATURE_VIRT").is_ok() && arch == "aarch64" {
        "linker-virt.ld"
    } else {
        match arch.as_str() {
            "aarch64" => "linker-aarch64.ld",
            "x86_64" => "linker-x86_64.ld",
            _ => panic!("unsupported main-kernel target architecture: {arch}"),
        }
    };

    println!("cargo:rustc-link-arg=-T{dir}/{linker_script}");
    println!("cargo:rerun-if-changed={dir}/{linker_script}");

    // Compile architecture-specific assembly files
    match arch.as_str() {
        "aarch64" => {
            println!("cargo:rerun-if-changed=src/arch/aarch64/boot.S");
            println!("cargo:rerun-if-changed=src/arch/aarch64/exception_vectors.S");

            cc::Build::new()
                .compiler("aarch64-linux-gnu-gcc")
                .file("src/arch/aarch64/boot.S")
                .file("src/arch/aarch64/exception_vectors.S")
                .compile("aarch64_boot");
        }
        "x86_64" => {
            // x86_64 doesn't need assembly compilation (uses Limine)
        }
        _ => unreachable!("unsupported architecture was rejected while selecting the linker"),
    }
}
