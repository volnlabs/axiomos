fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    // Host unit tests link through the platform test harness. Applying the
    // bare-metal linker script there suppresses its TLS segment and makes the
    // kernel's otherwise host-runnable unit tests fail at link time.
    if target_os != "none" {
        return;
    }

    // Handle embedded disk image for rpi5
    if std::env::var("CARGO_FEATURE_RPI5").is_ok() {
        println!("cargo:rerun-if-env-changed=AXIOM_DISK_IMAGE");
        let out_dir = std::env::var("OUT_DIR").unwrap();

        if let Ok(disk_path) = std::env::var("AXIOM_DISK_IMAGE") {
            // Use pre-built disk image
            let dest = format!("{}/disk.img", out_dir);
            std::fs::copy(&disk_path, &dest)
                .unwrap_or_else(|e| panic!("failed to copy disk image from {}: {}", disk_path, e));
            println!("cargo:rustc-env=EMBEDDED_DISK_PATH={}", dest);
            println!("cargo:rerun-if-changed={}", disk_path);
        } else {
            // Generate a minimal empty ext2 disk image as fallback.
            //
            // This must be byte-reproducible: the image is embedded in the
            // kernel, so any variation changes kernel8.img and breaks artifact
            // provenance for HIL benchmark campaigns. mke2fs otherwise stamps a
            // random filesystem UUID, a random directory hash seed, and the
            // current time into the superblock. Pin all three. The hash seed
            // UUID must be non-zero — mke2fs treats the all-zero UUID as unset
            // and falls back to a random seed.
            // Ubuntu 24.04's e2fsprogs 1.47.0 needs E2FSPROGS_FAKE_TIME;
            // SOURCE_DATE_EPOCH is supported only by newer versions. Use the
            // same non-zero epoch for both: zero means wall clock in 1.47.0.
            const DISK_UUID: &str = "a5106f0e-9d4f-4b7a-8c21-3f6d0e5b1c94";
            let dest = format!("{}/disk.img", out_dir);
            // mke2fs on an existing file can behave differently; start clean.
            let _ = std::fs::remove_file(&dest);
            let status = std::process::Command::new("mke2fs")
                .env("SOURCE_DATE_EPOCH", "1")
                .env("E2FSPROGS_FAKE_TIME", "1")
                .arg("-q")
                .arg("-t")
                .arg("ext2")
                .arg("-U")
                .arg(DISK_UUID)
                .arg("-E")
                .arg(format!("hash_seed={DISK_UUID}"))
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
