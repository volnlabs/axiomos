use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use kernel_bpf::profile::CloudProfile;
use kernel_bpf::signing::managed::{
    BundleError, PrivateArray, EFFECT_MOTOR_PAIR, HEADER_SIZE, MAX_BUNDLE_BYTES,
};
use kernel_bpf::signing::{SignatureVerifier, SigningError, TrustedKey};
use kernel_bpf::verifier::{BehaviorArtifact, VerificationBudget};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tempfile::TempDir;

const BEHAVIOR_ID: &str = "00112233445566778899aabbccddeeff";
const PROGRAM: [u8; 16] = [
    0xb7, 0, 0, 0, 0, 0, 0, 0, // r0 = 0
    0x95, 0, 0, 0, 0, 0, 0, 0, // exit
];

fn rk(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rk"))
        .args(args)
        .current_dir(cwd)
        .env("HOME", cwd)
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

fn key(temp: &TempDir, name: &str) -> (PathBuf, [u8; 32]) {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse generated key");
    let private = temp.path().join(format!("{name}.key"));
    fs::write(&private, pkcs8.as_ref()).expect("write private key");
    (private, key_pair.public_key().as_ref().try_into().unwrap())
}

fn make_bundle(temp: &TempDir, name: &str, key: &Path, extra: &[&str]) -> (PathBuf, Output) {
    let input = temp.path().join(format!("{name}.bin"));
    let output = temp.path().join(format!("{name}.axmb"));
    fs::write(&input, PROGRAM).expect("write raw BPF program");
    let mut args = vec![
        "bundle",
        "--input",
        path(&input),
        "--output",
        path(&output),
        "--key",
        path(key),
        "--behavior-id",
        BEHAVIOR_ID,
        "--revision",
        "42",
    ];
    args.extend_from_slice(extra);
    let result = rk(&args, temp.path());
    (output, result)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn cli_bundle_authenticates_and_prepares_with_the_kernel() {
    let temp = tempfile::tempdir().unwrap();
    let (private, public) = key(&temp, "operator");
    let (output, result) = make_bundle(
        &temp,
        "controller",
        &private,
        &[
            "--motor-pair",
            "--envelope",
            "--array-value-size",
            "16",
            "--array-entries",
            "1024",
        ],
    );
    assert!(result.status.success(), "{}", text(&result.stderr));

    let bytes = fs::read(output).unwrap();
    let trusted = TrustedKey::from_bytes(&public).unwrap();
    let verifier = SignatureVerifier::from_trusted_keys(&[trusted]).unwrap();
    let authenticated = verifier.authenticate_managed(&bytes).unwrap();
    let manifest = authenticated.manifest();
    assert_eq!(manifest.behavior_id, hex_id(BEHAVIOR_ID));
    assert_eq!(manifest.revision, 42);
    assert!(manifest.envelope);
    assert_eq!(manifest.effects, EFFECT_MOTOR_PAIR);
    assert_eq!(
        manifest.private_array,
        Some(PrivateArray {
            value_size: 16,
            max_entries: 1024,
        })
    );

    let mut budget = VerificationBudget::new(512 * 1024);
    let artifact = BehaviorArtifact::<CloudProfile>::prepare(
        &authenticated,
        EFFECT_MOTOR_PAIR,
        EFFECT_MOTOR_PAIR,
        &mut budget,
    )
    .unwrap();
    assert_eq!(artifact.identity(), authenticated.identity());
    let output_charge = artifact.output_charge();
    drop(artifact);
    budget.release_output(output_charge).unwrap();
    assert_eq!(budget.used(), 0);

    let stdout = text(&result.stdout);
    let identity = authenticated.identity();
    assert!(stdout.contains(&format!("Signer public key: {}", hex(&public))));
    assert!(stdout.contains(&format!(
        "Signer fingerprint: {}",
        hex(identity.signer_fingerprint.as_bytes())
    )));
    assert!(stdout.contains(&format!(
        "Payload digest: {}",
        hex(identity.payload_digest.as_bytes())
    )));
    assert!(stdout.contains(&format!(
        "Bundle digest: {}",
        hex(identity.bundle_digest.as_bytes())
    )));
    assert!(stdout.contains(
        "Signed only; kernel authentication, verification, admission, and activation have not run."
    ));
}

#[test]
fn kernel_rejects_wrong_key_and_tampered_manifest_or_payload() {
    let temp = tempfile::tempdir().unwrap();
    let (private, public) = key(&temp, "operator");
    let (_, other_public) = key(&temp, "other");
    let (output, result) = make_bundle(&temp, "signed", &private, &[]);
    assert!(result.status.success(), "{}", text(&result.stderr));
    let bytes = fs::read(output).unwrap();

    let wrong =
        SignatureVerifier::from_trusted_keys(&[TrustedKey::from_bytes(&other_public).unwrap()])
            .unwrap();
    assert_eq!(
        wrong.authenticate_managed(&bytes).unwrap_err(),
        BundleError::Authentication(SigningError::UntrustedSigner)
    );

    let verifier =
        SignatureVerifier::from_trusted_keys(&[TrustedKey::from_bytes(&public).unwrap()]).unwrap();
    let mut manifest_tamper = bytes.clone();
    manifest_tamper[32] ^= 1;
    assert_eq!(
        verifier.authenticate_managed(&manifest_tamper).unwrap_err(),
        BundleError::Authentication(SigningError::InvalidSignature)
    );
    let mut payload_tamper = bytes;
    *payload_tamper.last_mut().unwrap() ^= 1;
    assert_eq!(
        verifier.authenticate_managed(&payload_tamper).unwrap_err(),
        BundleError::Authentication(SigningError::HashMismatch)
    );
}

#[test]
fn kernel_rejects_malformed_bundle_lengths() {
    let temp = tempfile::tempdir().unwrap();
    let (private, public) = key(&temp, "operator");
    let (output, result) = make_bundle(&temp, "lengths", &private, &[]);
    assert!(result.status.success(), "{}", text(&result.stderr));
    let bytes = fs::read(output).unwrap();
    let verifier =
        SignatureVerifier::from_trusted_keys(&[TrustedKey::from_bytes(&public).unwrap()]).unwrap();

    let mut wrong_total = bytes.clone();
    wrong_total[8] ^= 1;
    assert_eq!(
        verifier.authenticate_managed(&wrong_total).unwrap_err(),
        BundleError::Malformed
    );
    let mut wrong_slots = bytes.clone();
    wrong_slots[12] ^= 1;
    assert_eq!(
        verifier.authenticate_managed(&wrong_slots).unwrap_err(),
        BundleError::Malformed
    );
    assert_eq!(
        verifier
            .authenticate_managed(&bytes[..bytes.len() - 1])
            .unwrap_err(),
        BundleError::Malformed
    );
}

#[test]
fn cli_rejects_invalid_inputs_array_shapes_and_existing_output() {
    let temp = tempfile::tempdir().unwrap();
    let (private, _) = key(&temp, "operator");
    let private_bytes = fs::read(&private).unwrap();

    for (name, bytes, expected) in [
        ("empty", Vec::new(), "input payload must be nonempty"),
        (
            "short",
            vec![0; 7],
            "input payload length must be a multiple of 8 bytes",
        ),
        ("elf", b"\x7fELFbad!".to_vec(), "ELF input is not supported"),
        (
            "large",
            vec![0; MAX_BUNDLE_BYTES - HEADER_SIZE + 1],
            "input exceeds the maximum raw payload",
        ),
    ] {
        let input = temp.path().join(format!("{name}.bin"));
        let output = temp.path().join(format!("{name}.axmb"));
        fs::write(&input, bytes).unwrap();
        let result = rk(
            &[
                "bundle",
                "--input",
                path(&input),
                "--output",
                path(&output),
                "--key",
                path(&private),
                "--behavior-id",
                BEHAVIOR_ID,
                "--revision",
                "1",
            ],
            temp.path(),
        );
        assert!(!result.status.success());
        assert!(text(&result.stderr).contains(expected), "{name}");
        assert!(!output.exists());
    }

    let (_, one_array_field) =
        make_bundle(&temp, "unpaired", &private, &["--array-value-size", "4"]);
    assert!(!one_array_field.status.success());
    assert!(text(&one_array_field.stderr).contains("--array-entries"));

    let (oversized_output, oversized_array) = make_bundle(
        &temp,
        "oversized-array",
        &private,
        &["--array-value-size", "16385", "--array-entries", "1"],
    );
    assert!(!oversized_array.status.success());
    assert!(text(&oversized_array.stderr).contains("exceeds the 16 KiB limit"));
    assert!(!oversized_output.exists());

    let (overflow_output, overflow_array) = make_bundle(
        &temp,
        "overflow-array",
        &private,
        &[
            "--array-value-size",
            "4294967295",
            "--array-entries",
            "4294967295",
        ],
    );
    assert!(!overflow_array.status.success());
    assert!(text(&overflow_array.stderr).contains("exceeds the 16 KiB limit"));
    assert!(!overflow_output.exists());

    let bad_id_input = temp.path().join("bad-id.bin");
    let bad_id_output = temp.path().join("bad-id.axmb");
    fs::write(&bad_id_input, PROGRAM).unwrap();
    let bad_id = rk(
        &[
            "bundle",
            "--input",
            path(&bad_id_input),
            "--output",
            path(&bad_id_output),
            "--key",
            path(&private),
            "--behavior-id",
            "not-hex",
            "--revision",
            "1",
        ],
        temp.path(),
    );
    assert!(!bad_id.status.success());
    assert!(text(&bad_id.stderr).contains("exactly 32 hexadecimal characters"));

    let (output, first) = make_bundle(&temp, "existing", &private, &[]);
    assert!(first.status.success(), "{}", text(&first.stderr));
    let original = fs::read(&output).unwrap();
    let (_, repeated) = make_bundle(&temp, "existing", &private, &[]);
    assert!(!repeated.status.success());
    assert!(text(&repeated.stderr).contains("existing files are not overwritten"));
    assert_eq!(fs::read(output).unwrap(), original);

    let key_output_input = temp.path().join("key-output.bin");
    fs::write(&key_output_input, PROGRAM).unwrap();
    let key_output = rk(
        &[
            "bundle",
            "--input",
            path(&key_output_input),
            "--output",
            path(&private),
            "--key",
            path(&private),
            "--behavior-id",
            BEHAVIOR_ID,
            "--revision",
            "1",
        ],
        temp.path(),
    );
    assert!(!key_output.status.success());
    assert!(text(&key_output.stderr).contains("existing files are not overwritten"));
    assert_eq!(fs::read(private).unwrap(), private_bytes);
}

fn hex_id(value: &str) -> [u8; 16] {
    let mut id = [0; 16];
    for (byte, digits) in id.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(digits).unwrap(), 16).unwrap();
    }
    id
}
