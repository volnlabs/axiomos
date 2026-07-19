// Parsing and integrity oracle for attacker-controlled signed BPF containers.
// The raw path exercises malformed headers; the structured path guarantees
// coverage of successful parsing and hash verification.

#![no_main]

use kernel_bpf::signing::{
    ProgramHash, Signature, SignatureFlags, SignedProgram, SignedProgramHeader, SIGNATURE_LEN,
    SIGNING_VERSION,
};
use libfuzzer_sys::fuzz_target;

const MAX_PAYLOAD: usize = 64 * 1024;

fn exercise_parsed_container(data: &[u8]) {
    let Ok(signed) = SignedProgram::from_bytes(data) else {
        return;
    };

    let encoded = signed.header().to_bytes();
    let reparsed = SignedProgramHeader::from_bytes(&encoded)
        .expect("serializing a parsed header must produce a valid header");
    assert_eq!(reparsed.version, signed.header().version);
    assert_eq!(reparsed.flags, signed.header().flags);
    assert!(reparsed.program_hash.matches(&signed.header().program_hash));
    assert_eq!(reparsed.signature.as_bytes(), signed.signature().as_bytes());
    assert_eq!(reparsed.signer_id, *signed.signer_id());
    assert_eq!(reparsed.timestamp, signed.timestamp());
    let _ = signed.verify_hash();
}

fn exercise_structured_container(data: &[u8]) {
    let control = data.first().copied().unwrap_or(0);
    let payload = data.get(1..).unwrap_or_default();
    let payload = &payload[..payload.len().min(MAX_PAYLOAD)];
    let program_hash = ProgramHash::compute(payload);

    let mut signature = [0u8; SIGNATURE_LEN];
    for (index, byte) in signature.iter_mut().enumerate() {
        *byte = data.get(index + 1).copied().unwrap_or(index as u8);
    }
    let mut signer_id = [0u8; 8];
    for (index, byte) in signer_id.iter_mut().enumerate() {
        *byte = data.get(index + 1 + SIGNATURE_LEN).copied().unwrap_or(0);
    }

    let header = SignedProgramHeader {
        version: SIGNING_VERSION,
        flags: SignatureFlags::from_byte(control),
        program_hash,
        signature: Signature::from_bytes(signature),
        signer_id,
        timestamp: u64::from_le_bytes(signer_id),
    };
    let mut container = header.to_bytes().to_vec();
    container.extend_from_slice(payload);

    let corrupt_payload = control & 1 != 0 && !payload.is_empty();
    if corrupt_payload {
        *container.last_mut().expect("payload is non-empty") ^= 1;
    }

    let signed = SignedProgram::from_bytes(&container)
        .expect("a serialized signed-program header must parse");
    assert_eq!(signed.program_data().len(), payload.len());
    assert_eq!(signed.verify_hash().is_err(), corrupt_payload);
}

fuzz_target!(|data: &[u8]| {
    exercise_parsed_container(data);
    exercise_structured_container(data);
});
