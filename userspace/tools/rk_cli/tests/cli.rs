use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use kernel_bpf::signing::{SignatureVerifier, TrustedKey};
use tempfile::TempDir;

fn rk(args: &[&str], home: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rk"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .output()
        .expect("run rk CLI")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn path(path: &Path) -> &str {
    path.to_str().expect("temporary path is UTF-8")
}

fn bpf_elf() -> Vec<u8> {
    let mut elf = vec![0u8; 64];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[18..20].copy_from_slice(&247u16.to_le_bytes());
    elf[40..48].copy_from_slice(&64u64.to_le_bytes());
    elf[60..62].copy_from_slice(&1u16.to_le_bytes());
    elf.extend_from_slice(b"rk-cli-production-container");
    elf
}

fn generate_keypair(temp: &TempDir, name: &str) -> (PathBuf, PathBuf) {
    let prefix = temp.path().join(name);
    let output = rk(&["key", "generate", "--output", path(&prefix)], temp.path());
    assert!(
        output.status.success(),
        "key generation failed: {}",
        text(&output.stderr)
    );
    (prefix.with_extension("key"), prefix.with_extension("pub"))
}

fn sign(temp: &TempDir, private_key: &Path, output_name: &str) -> (PathBuf, Vec<u8>) {
    let input = temp.path().join("program.o");
    let signed = temp.path().join(output_name);
    let elf = bpf_elf();
    fs::write(&input, &elf).expect("write ELF fixture");

    let output = rk(
        &[
            "sign",
            "--input",
            path(&input),
            "--output",
            path(&signed),
            "--key",
            path(private_key),
        ],
        temp.path(),
    );
    assert!(
        output.status.success(),
        "signing failed: {}",
        text(&output.stderr)
    );
    (signed, elf)
}

#[test]
fn cli_sign_verify_round_trip_matches_kernel_authentication() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (private_key, public_key) = generate_keypair(&temp, "release");
    let (signed_path, elf) = sign(&temp, &private_key, "program.rbpf");

    let verify = rk(
        &[
            "verify",
            "--input",
            path(&signed_path),
            "--key",
            path(&public_key),
        ],
        temp.path(),
    );
    assert!(
        verify.status.success(),
        "verification failed: {}",
        text(&verify.stderr)
    );
    assert!(text(&verify.stdout).contains("Program verification successful"));

    let public = fs::read(public_key).expect("read public key");
    let trusted = TrustedKey::from_bytes(&public).expect("valid public key");
    let verifier = SignatureVerifier::from_trusted_keys(&[trusted]).expect("trust key");
    let signed = fs::read(signed_path).expect("read signed program");
    assert_eq!(verifier.authenticate(&signed, false), Ok(elf.as_slice()));
}

#[test]
fn cli_trust_store_resolves_signer_and_rejects_tampering() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (private_key, public_key) = generate_keypair(&temp, "operator");
    let (signed_path, _) = sign(&temp, &private_key, "trusted.rbpf");

    let import = rk(
        &[
            "key",
            "import",
            "--key",
            path(&public_key),
            "--alias",
            "operator",
        ],
        temp.path(),
    );
    assert!(
        import.status.success(),
        "import failed: {}",
        text(&import.stderr)
    );

    let verify = rk(&["verify", "--input", path(&signed_path)], temp.path());
    assert!(
        verify.status.success(),
        "trusted verification failed: {}",
        text(&verify.stderr)
    );

    let list = rk(&["key", "list"], temp.path());
    assert!(list.status.success());
    assert!(text(&list.stdout).contains("operator"));

    let mut tampered = fs::read(&signed_path).expect("read signed program");
    *tampered.last_mut().expect("payload byte") ^= 0x5a;
    fs::write(&signed_path, tampered).expect("write tampered program");
    let rejected = rk(&["verify", "--input", path(&signed_path)], temp.path());
    assert!(!rejected.status.success());
    assert!(text(&rejected.stderr).contains("Hash verification failed"));
}

#[test]
fn cli_rejects_wrong_key_signature_and_malformed_containers() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (private_key, _) = generate_keypair(&temp, "signer");
    let (_, wrong_public_key) = generate_keypair(&temp, "other");
    let (signed_path, _) = sign(&temp, &private_key, "program.rbpf");

    let wrong_key = rk(
        &[
            "verify",
            "--input",
            path(&signed_path),
            "--key",
            path(&wrong_public_key),
        ],
        temp.path(),
    );
    assert!(!wrong_key.status.success());
    assert!(text(&wrong_key.stderr).contains("Signature verification failed"));

    let short = temp.path().join("short.rbpf");
    fs::write(&short, b"RBPF").expect("write short container");
    let short_result = rk(
        &[
            "verify",
            "--input",
            path(&short),
            "--key",
            path(&wrong_public_key),
        ],
        temp.path(),
    );
    assert!(!short_result.status.success());
    assert!(text(&short_result.stderr).contains("File too small"));

    let original = fs::read(&signed_path).expect("read signed container");
    let invalid_magic = temp.path().join("invalid-magic.rbpf");
    let mut bytes = original.clone();
    bytes[0] = b'X';
    fs::write(&invalid_magic, bytes).expect("write invalid-magic container");
    let magic_result = rk(
        &[
            "verify",
            "--input",
            path(&invalid_magic),
            "--key",
            path(&wrong_public_key),
        ],
        temp.path(),
    );
    assert!(!magic_result.status.success());
    assert!(text(&magic_result.stderr).contains("Invalid magic bytes"));

    let unsupported = temp.path().join("unsupported.rbpf");
    let mut bytes = original;
    bytes[4] = 2;
    fs::write(&unsupported, bytes).expect("write unsupported container");
    let version_result = rk(
        &[
            "verify",
            "--input",
            path(&unsupported),
            "--key",
            path(&wrong_public_key),
        ],
        temp.path(),
    );
    assert!(!version_result.status.success());
    assert!(text(&version_result.stderr).contains("Unsupported version: 2"));

    let invalid_elf = temp.path().join("invalid.o");
    fs::write(&invalid_elf, b"not an ELF").expect("write invalid ELF");
    let sign_result = rk(
        &[
            "sign",
            "--input",
            path(&invalid_elf),
            "--output",
            path(&temp.path().join("invalid.rbpf")),
            "--key",
            path(&private_key),
        ],
        temp.path(),
    );
    assert!(!sign_result.status.success());
    assert!(text(&sign_result.stderr).contains("does not appear to be an ELF"));

    let invalid_key = temp.path().join("invalid.key");
    fs::write(&invalid_key, b"not PKCS#8").expect("write invalid key");
    let valid_elf = temp.path().join("valid.o");
    fs::write(&valid_elf, bpf_elf()).expect("write valid ELF");
    let invalid_key_result = rk(
        &[
            "sign",
            "--input",
            path(&valid_elf),
            "--output",
            path(&temp.path().join("bad-key.rbpf")),
            "--key",
            path(&invalid_key),
        ],
        temp.path(),
    );
    assert!(!invalid_key_result.status.success());
    assert!(text(&invalid_key_result.stderr).contains("Failed to parse private key"));
}

#[test]
fn cli_reports_signed_and_unsigned_program_metadata() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (private_key, _) = generate_keypair(&temp, "metadata");
    let (signed_path, elf) = sign(&temp, &private_key, "metadata.rbpf");
    let unsigned_path = temp.path().join("metadata.o");
    fs::write(&unsigned_path, elf).expect("write unsigned ELF");

    let signed_info = rk(&["info", "--input", path(&signed_path)], temp.path());
    assert!(signed_info.status.success());
    let signed_stdout = text(&signed_info.stdout);
    assert!(signed_stdout.contains("Signed Program"));
    assert!(signed_stdout.contains("Hash verified"));
    assert!(signed_stdout.contains("Machine: BPF (247)"));

    let unsigned_info = rk(&["info", "--input", path(&unsigned_path)], temp.path());
    assert!(unsigned_info.status.success());
    let unsigned_stdout = text(&unsigned_info.stdout);
    assert!(unsigned_stdout.contains("ELF Object (Unsigned)"));
    assert!(unsigned_stdout.contains("Use 'rk sign'"));
}

#[test]
fn cli_key_exports_preserve_public_key_and_reject_unknown_format() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let (private_key, public_key) = generate_keypair(&temp, "export");
    let original = fs::read(&public_key).expect("read public key");

    let raw = rk(
        &[
            "key",
            "export",
            "--key",
            path(&public_key),
            "--format",
            "raw",
        ],
        temp.path(),
    );
    assert!(raw.status.success());
    assert_eq!(
        fs::read(format!("{}.raw", path(&public_key))).expect("read raw export"),
        original
    );

    let private_raw = rk(
        &[
            "key",
            "export",
            "--key",
            path(&private_key),
            "--format",
            "raw",
        ],
        temp.path(),
    );
    assert!(private_raw.status.success());
    assert_eq!(
        fs::read(format!("{}.raw", path(&private_key))).expect("read private-key export"),
        original
    );

    let pem = rk(
        &[
            "key",
            "export",
            "--key",
            path(&public_key),
            "--format",
            "pem",
        ],
        temp.path(),
    );
    assert!(pem.status.success());
    let pem_data =
        fs::read_to_string(format!("{}.pem", path(&public_key))).expect("read PEM export");
    assert!(pem_data.starts_with("-----BEGIN RKBPF PUBLIC KEY-----\n"));
    assert!(pem_data.ends_with("-----END RKBPF PUBLIC KEY-----\n"));

    let unknown = rk(
        &[
            "key",
            "export",
            "--key",
            path(&public_key),
            "--format",
            "der",
        ],
        temp.path(),
    );
    assert!(!unknown.status.success());
    assert!(text(&unknown.stderr).contains("Unknown format"));
}

#[test]
fn cli_rejects_missing_local_inputs_before_external_tooling() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let missing = temp.path().join("missing.c");
    let build = rk(
        &["build", "--source", path(&missing), "--profile", "embedded"],
        temp.path(),
    );
    assert!(!build.status.success());
    assert!(text(&build.stderr).contains("Source path does not exist"));

    let deploy = rk(&["deploy"], temp.path());
    assert!(!deploy.status.success());
    assert!(text(&deploy.stderr).contains("No programs specified"));
}

#[test]
fn cli_init_writes_selected_profile_and_refuses_overwrite() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let project = temp.path().join("motor-guard");

    let init = rk(&["init", "motor-guard", "--profile", "cloud"], temp.path());
    assert!(init.status.success(), "init failed: {}", text(&init.stderr));
    let config = fs::read_to_string(project.join("rkbpf.toml")).expect("read project config");
    assert!(config.contains("name = \"motor-guard\""));
    assert!(config.contains("profile = \"cloud\""));
    assert!(project.join("include/rkbpf/helpers.h").is_file());
    assert!(project.join("src/main.bpf.c").is_file());

    let repeated = rk(&["init", "motor-guard", "--profile", "cloud"], temp.path());
    assert!(!repeated.status.success());
    assert!(text(&repeated.stderr).contains("already exists"));
}
