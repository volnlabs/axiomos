fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=src/boot.S");
    println!("cargo:rustc-link-arg=-Tlinker.ld");

    // Compile boot assembly
    cc::Build::new()
        .file("src/boot.S")
        .flag("-march=rv64gc")
        .flag("-mabi=lp64d")
        .compile("boot");
}
