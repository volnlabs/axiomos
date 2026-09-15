//! Fixed-size administration dispatch; expensive work runs in the root worker.
use core::mem::size_of;

use kernel_abi::*;
use zerocopy::{FromBytes, IntoBytes};

use crate::bpf::preparation::LifecycleTarget;
use crate::bpf::{installation, BpfManager};

pub(super) fn is_command(cmd: u32) -> bool {
    (BPF_MANAGED_UPLOAD_BEGIN..=BPF_MANAGED_REARM).contains(&cmd)
}

fn request_size(cmd: u32) -> Result<usize, Errno> {
    match cmd {
        BPF_MANAGED_UPLOAD_BEGIN => Ok(size_of::<ManagedUploadBeginV1>()),
        BPF_MANAGED_UPLOAD_CHUNK => Ok(size_of::<ManagedUploadChunkV1>()),
        BPF_MANAGED_UPLOAD_FINALIZE | BPF_MANAGED_CANCEL => {
            Ok(size_of::<ManagedOperationRequestV1>())
        }
        BPF_MANAGED_OPERATION_QUERY => Ok(size_of::<ManagedOperationV1>()),
        BPF_MANAGED_ACTIVATE
        | BPF_MANAGED_ROLLBACK
        | BPF_MANAGED_DEACTIVATE
        | BPF_MANAGED_RETIRE => Ok(size_of::<ManagedInstallationRequestV1>()),
        BPF_MANAGED_SLOT_QUERY => Ok(size_of::<ManagedSlotV1>()),
        BPF_MANAGED_INSTALLATION_CANCEL => Ok(size_of::<ManagedInstallationCancelV1>()),
        BPF_MANAGED_RECORDER_STATUS => Ok(size_of::<ManagedAuditStatusV1>()),
        BPF_MANAGED_RECORDER_READ => Ok(size_of::<ManagedAuditReadV1>()),
        BPF_MANAGED_REARM => Ok(size_of::<ManagedRearmRequestV1>()),
        _ => Err(ENOTSUP),
    }
}

fn request_version(cmd: u32, size: usize) -> Result<u32, Errno> {
    if request_size(cmd)? == size {
        Ok(MANAGED_ADMIN_VERSION)
    } else if cmd == BPF_MANAGED_SLOT_QUERY && size == size_of::<ManagedSlotArtifactV2>() {
        Ok(MANAGED_SLOT_ARTIFACT_VERSION)
    } else {
        Err(EINVAL)
    }
}

fn validate_header(cmd: u32, bytes: &[u8]) -> Result<(), Errno> {
    let expected_version = request_version(cmd, bytes.len())?;
    let version = u32::from_ne_bytes(bytes[..4].try_into().map_err(|_| EINVAL)?);
    let size = u32::from_ne_bytes(bytes[4..8].try_into().map_err(|_| EINVAL)?);
    if version != expected_version {
        return Err(ENOTSUP);
    }
    if size as usize != bytes.len() {
        return Err(EINVAL);
    }
    Ok(())
}

/// Decode the exact lifecycle identity before calling a slot-locking wrapper.
fn lifecycle_request(cmd: u32, bytes: &[u8]) -> Result<(u64, u64, LifecycleTarget), Errno> {
    validate_header(cmd, bytes)?;
    match cmd {
        BPF_MANAGED_ACTIVATE
        | BPF_MANAGED_ROLLBACK
        | BPF_MANAGED_DEACTIVATE
        | BPF_MANAGED_RETIRE => {
            let request =
                ManagedInstallationRequestV1::read_from_bytes(bytes).map_err(|_| EINVAL)?;
            if request.reserved != 0 {
                return Err(EINVAL);
            }
            let target = match cmd {
                BPF_MANAGED_ACTIVATE => LifecycleTarget::Candidate(request.artifact_handle),
                BPF_MANAGED_ROLLBACK => LifecycleTarget::Previous(request.artifact_handle),
                BPF_MANAGED_DEACTIVATE => LifecycleTarget::Deactivate(request.artifact_handle),
                BPF_MANAGED_RETIRE => LifecycleTarget::Retire(request.artifact_handle),
                _ => return Err(ENOTSUP),
            };
            Ok((
                request.expected_last_id,
                request.expected_generation,
                target,
            ))
        }
        BPF_MANAGED_INSTALLATION_CANCEL => {
            let request =
                ManagedInstallationCancelV1::read_from_bytes(bytes).map_err(|_| EINVAL)?;
            if request.reserved != 0 || request.id == 0 {
                return Err(EINVAL);
            }
            let target = match request.target_kind {
                MANAGED_TARGET_CANDIDATE => LifecycleTarget::Candidate(request.artifact_handle),
                MANAGED_TARGET_PREVIOUS => LifecycleTarget::Previous(request.artifact_handle),
                MANAGED_TARGET_DEACTIVATE => LifecycleTarget::Deactivate(request.artifact_handle),
                MANAGED_TARGET_RETIRE => LifecycleTarget::Retire(request.artifact_handle),
                _ => return Err(EINVAL),
            };
            Ok((request.id, request.expected_generation, target))
        }
        _ => Err(ENOTSUP),
    }
}

fn operation_query_id(bytes: &[u8]) -> Result<u64, Errno> {
    validate_header(BPF_MANAGED_OPERATION_QUERY, bytes)?;
    let request = ManagedOperationV1::read_from_bytes(bytes).map_err(|_| EINVAL)?;
    let expected = ManagedOperationV1 {
        version: MANAGED_ADMIN_VERSION,
        size: size_of::<ManagedOperationV1>() as u32,
        id: request.id,
        ..Default::default()
    };
    if request != expected {
        return Err(EINVAL);
    }
    Ok(request.id)
}

fn rearm_request(bytes: &[u8]) -> Result<ManagedRearmRequestV1, Errno> {
    validate_header(BPF_MANAGED_REARM, bytes)?;
    let request = ManagedRearmRequestV1::read_from_bytes(bytes).map_err(|_| EINVAL)?;
    if request.reserved != 0 {
        return Err(EINVAL);
    }
    Ok(request)
}

fn validate_slot_query(bytes: &[u8]) -> Result<(), Errno> {
    validate_header(BPF_MANAGED_SLOT_QUERY, bytes)?;
    let request = ManagedSlotV1::read_from_bytes(bytes).map_err(|_| EINVAL)?;
    if request
        != (ManagedSlotV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedSlotV1>() as u32,
            ..Default::default()
        })
    {
        return Err(EINVAL);
    }
    Ok(())
}

fn slot_artifact_request(bytes: &[u8]) -> Result<ManagedSlotArtifactV2, Errno> {
    validate_header(BPF_MANAGED_SLOT_QUERY, bytes)?;
    let request = ManagedSlotArtifactV2::read_from_bytes(bytes).map_err(|_| EINVAL)?;
    if request
        != (ManagedSlotArtifactV2 {
            version: MANAGED_SLOT_ARTIFACT_VERSION,
            size: size_of::<ManagedSlotArtifactV2>() as u32,
            expected_generation: request.expected_generation,
            expected_last_id: request.expected_last_id,
            artifact_handle: request.artifact_handle,
            expected_roles: request.expected_roles,
            ..Default::default()
        })
        || request.expected_roles == 0
        || request.expected_roles
            & !(MANAGED_SLOT_HAS_ACTIVE | MANAGED_SLOT_HAS_PREVIOUS | MANAGED_SLOT_HAS_CANDIDATE)
            != 0
    {
        return Err(EINVAL);
    }
    Ok(request)
}

fn handle(
    manager: &mut BpfManager,
    owner: u64,
    cmd: u32,
    bytes: &[u8],
) -> Result<(usize, Option<ManagedOperationV1>), Errno> {
    validate_header(cmd, bytes)?;
    let value = match cmd {
        BPF_MANAGED_UPLOAD_BEGIN => {
            let request = ManagedUploadBeginV1::read_from_bytes(bytes).map_err(|_| EINVAL)?;
            if request.reserved != 0 {
                return Err(EINVAL);
            }
            manager.managed_upload_begin(owner, request.expected_last_id, request.total_bytes)?
                as usize
        }
        BPF_MANAGED_UPLOAD_CHUNK => {
            let request = ManagedUploadChunkV1::read_from_bytes(bytes).map_err(|_| EINVAL)?;
            if request.reserved != 0 || request.length as usize > request.bytes.len() {
                return Err(EINVAL);
            }
            let (payload, reserved) = request.bytes.split_at(request.length as usize);
            if reserved.iter().any(|byte| *byte != 0) {
                return Err(EINVAL);
            }
            manager.managed_upload_chunk(owner, request.id, request.offset, payload)? as usize
        }
        BPF_MANAGED_UPLOAD_FINALIZE | BPF_MANAGED_CANCEL => {
            let request = ManagedOperationRequestV1::read_from_bytes(bytes).map_err(|_| EINVAL)?;
            if request.reserved != 0 {
                return Err(EINVAL);
            }
            if cmd == BPF_MANAGED_UPLOAD_FINALIZE {
                manager.managed_upload_finalize(owner, request.id)? as usize
            } else {
                manager.managed_operation_cancel(owner, request.id)?;
                0
            }
        }
        BPF_MANAGED_OPERATION_QUERY => {
            return Ok((
                0,
                Some(manager.managed_operation_query(operation_query_id(bytes)?)?),
            ));
        }
        _ => return Err(ENOTSUP),
    };
    Ok((value, None))
}

pub(super) fn dispatch(owner: u64, cmd: u32, ptr: usize, size: usize) -> isize {
    let result = (|| {
        if !cfg!(feature = "managed-runtime") {
            return Err(ENOTSUP);
        }
        request_version(cmd, size)?;
        let mut bytes = [0u8; size_of::<ManagedUploadChunkV1>()];
        super::validation::copy_from_userspace_into(ptr, &mut bytes[..size])?;
        let bytes = &bytes[..size];
        // Recorder queries own only the recorder. Lifecycle wrappers take slot
        // then manager with IRQs masked; keep both outside the upload lock below.
        match cmd {
            BPF_MANAGED_CANCEL => {
                validate_header(cmd, bytes)?;
                let request =
                    ManagedOperationRequestV1::read_from_bytes(bytes).map_err(|_| EINVAL)?;
                if request.reserved != 0 {
                    return Err(EINVAL);
                }
                installation::cancel_operation(owner, request.id)?;
                return Ok(0);
            }
            BPF_MANAGED_REARM => {
                let request = rearm_request(bytes)?;
                return installation::request_rearm(
                    request.expected_last_id,
                    request.expected_generation,
                )
                .map(|id| id as usize);
            }
            BPF_MANAGED_RECORDER_STATUS => {
                validate_header(cmd, bytes)?;
                let request = ManagedAuditStatusV1::read_from_bytes(bytes).map_err(|_| EINVAL)?;
                let reply = crate::bpf::recorder::status(request)?;
                super::validation::copy_to_userspace_bounded(ptr, reply.as_bytes())?;
                return Ok(0);
            }
            BPF_MANAGED_RECORDER_READ => {
                validate_header(cmd, bytes)?;
                let request = ManagedAuditReadV1::read_from_bytes(bytes).map_err(|_| EINVAL)?;
                let reply = crate::bpf::recorder::read(request)?;
                super::validation::copy_to_userspace_bounded(ptr, reply.as_bytes())?;
                return Ok(0);
            }
            BPF_MANAGED_ACTIVATE
            | BPF_MANAGED_ROLLBACK
            | BPF_MANAGED_DEACTIVATE
            | BPF_MANAGED_RETIRE => {
                let (last_id, generation, target) = lifecycle_request(cmd, bytes)?;
                return installation::request_installation(last_id, generation, target)
                    .map(|id| id as usize);
            }
            BPF_MANAGED_INSTALLATION_CANCEL => {
                let (id, generation, target) = lifecycle_request(cmd, bytes)?;
                installation::cancel_installation(id, generation, target)?;
                return Ok(0);
            }
            BPF_MANAGED_SLOT_QUERY => {
                if bytes.len() == size_of::<ManagedSlotArtifactV2>() {
                    let reply = installation::query_slot_artifact(slot_artifact_request(bytes)?)?;
                    super::validation::copy_to_userspace_bounded(ptr, reply.as_bytes())?;
                    return Ok(0);
                }
                validate_slot_query(bytes)?;
                let reply = installation::query_slot()?;
                super::validation::copy_to_userspace_bounded(ptr, reply.as_bytes())?;
                return Ok(0);
            }
            BPF_MANAGED_OPERATION_QUERY => {
                let reply = installation::query_installation(operation_query_id(bytes)?)?;
                super::validation::copy_to_userspace_bounded(ptr, reply.as_bytes())?;
                return Ok(0);
            }
            _ => {}
        }
        let (value, reply) = {
            let manager = crate::BPF_MANAGER.get().ok_or(ENODEV)?;
            handle(&mut manager.lock(), owner, cmd, bytes)?
        };
        // Wake after releasing the producer's condition lock. A finalize with
        // a lost reply remains committed and discoverable by its original ID.
        if matches!(cmd, BPF_MANAGED_UPLOAD_FINALIZE | BPF_MANAGED_CANCEL) {
            crate::bpf::preparation::wake();
        }
        if let Some(reply) = reply {
            super::validation::copy_to_userspace_bounded(ptr, reply.as_bytes())?;
        }
        Ok(value)
    })();
    match result {
        Ok(value) => value as isize,
        Err(error) => -isize::from(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rearm_has_its_own_bounded_admin_command() {
        assert!(is_command(269));
        assert_eq!(request_size(269), Ok(32));
        let request = ManagedRearmRequestV1 {
            version: 1,
            size: 32,
            expected_last_id: 1 << 40,
            expected_generation: 1 << 41,
            reserved: 0,
        };
        assert_eq!(rearm_request(request.as_bytes()), Ok(request));
        for length in 0..32 {
            assert!(rearm_request(&request.as_bytes()[..length]).is_err());
        }
        let mut oversized = request.as_bytes().to_vec();
        oversized.push(0);
        assert_eq!(rearm_request(&oversized), Err(EINVAL));
        for byte in 24..32 {
            let mut bad = request.as_bytes().to_vec();
            bad[byte] = 1;
            assert_eq!(rearm_request(&bad), Err(EINVAL));
        }
        let mut bad = request;
        bad.version = 2;
        assert_eq!(rearm_request(bad.as_bytes()), Err(ENOTSUP));
        bad = request;
        bad.size = 31;
        assert_eq!(rearm_request(bad.as_bytes()), Err(EINVAL));
    }

    #[test]
    fn artifact_query_keeps_v1_and_rejects_every_nonzero_output_byte() {
        let request = ManagedSlotArtifactV2 {
            version: MANAGED_SLOT_ARTIFACT_VERSION,
            size: size_of::<ManagedSlotArtifactV2>() as u32,
            expected_generation: 1 << 40,
            expected_last_id: 1 << 41,
            expected_roles: MANAGED_SLOT_HAS_ACTIVE,
            ..Default::default()
        };
        assert_eq!(slot_artifact_request(request.as_bytes()), Ok(request));
        let v1 = ManagedSlotV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedSlotV1>() as u32,
            ..Default::default()
        };
        assert_eq!(validate_slot_query(v1.as_bytes()), Ok(()));
        for offset in 32..size_of::<ManagedSlotArtifactV2>() {
            let mut bytes = request.as_bytes().to_vec();
            bytes[offset] = 1;
            assert_eq!(slot_artifact_request(&bytes), Err(EINVAL));
        }
        for len in 0..size_of::<ManagedSlotArtifactV2>() {
            assert!(slot_artifact_request(&request.as_bytes()[..len]).is_err());
        }
        let mut oversized = request.as_bytes().to_vec();
        oversized.push(0);
        assert_eq!(slot_artifact_request(&oversized), Err(EINVAL));
        for version in [0, MANAGED_ADMIN_VERSION, MANAGED_SLOT_ARTIFACT_VERSION + 1] {
            let mut bad = request;
            bad.version = version;
            assert_eq!(slot_artifact_request(bad.as_bytes()), Err(ENOTSUP));
        }
        for roles in [0, MANAGED_SLOT_INHIBITED, u32::MAX] {
            let mut bad = request;
            bad.expected_roles = roles;
            assert_eq!(slot_artifact_request(bad.as_bytes()), Err(EINVAL));
        }
    }

    #[test]
    fn recorder_headers_reject_inexact_lengths_and_unknown_versions() {
        for cmd in [BPF_MANAGED_RECORDER_STATUS, BPF_MANAGED_RECORDER_READ] {
            assert!(is_command(cmd));
            let size = request_size(cmd).unwrap();
            assert!(size <= size_of::<ManagedUploadChunkV1>());
            let mut bytes = alloc::vec![0; size];
            bytes[..4].copy_from_slice(&MANAGED_ADMIN_VERSION.to_ne_bytes());
            bytes[4..8].copy_from_slice(&(size as u32).to_ne_bytes());
            assert_eq!(validate_header(cmd, &bytes), Ok(()));
            for len in 0..size {
                assert_eq!(validate_header(cmd, &bytes[..len]), Err(EINVAL));
            }
            bytes.push(0);
            assert_eq!(validate_header(cmd, &bytes), Err(EINVAL));
            bytes.pop();
            bytes[..4].copy_from_slice(&(MANAGED_ADMIN_VERSION + 1).to_ne_bytes());
            assert_eq!(validate_header(cmd, &bytes), Err(ENOTSUP));
            bytes[..4].copy_from_slice(&MANAGED_ADMIN_VERSION.to_ne_bytes());
            bytes[4..8].fill(0);
            assert_eq!(validate_header(cmd, &bytes), Err(EINVAL));
        }
        assert!(!is_command(BPF_MANAGED_REARM + 1));
    }

    #[test]
    fn lifecycle_layouts_validate_before_resolving_exact_targets() {
        let install = ManagedInstallationRequestV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedInstallationRequestV1>() as u32,
            expected_last_id: 1 << 40,
            expected_generation: 1 << 41,
            artifact_handle: 0,
            reserved: 0,
        };
        let mut cancel = ManagedInstallationCancelV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedInstallationCancelV1>() as u32,
            id: 1 << 40,
            expected_generation: 1 << 41,
            artifact_handle: 0,
            target_kind: MANAGED_TARGET_CANDIDATE,
            reserved: 0,
        };
        for (cmd, bytes, reserved, target) in [
            (
                BPF_MANAGED_ACTIVATE,
                install.as_bytes(),
                28,
                LifecycleTarget::Candidate(0),
            ),
            (
                BPF_MANAGED_ROLLBACK,
                install.as_bytes(),
                28,
                LifecycleTarget::Previous(0),
            ),
            (
                BPF_MANAGED_DEACTIVATE,
                install.as_bytes(),
                28,
                LifecycleTarget::Deactivate(0),
            ),
            (
                BPF_MANAGED_RETIRE,
                install.as_bytes(),
                28,
                LifecycleTarget::Retire(0),
            ),
            (
                BPF_MANAGED_INSTALLATION_CANCEL,
                cancel.as_bytes(),
                32,
                LifecycleTarget::Candidate(0),
            ),
        ] {
            assert_eq!(
                lifecycle_request(cmd, bytes),
                Ok((1 << 40, 1 << 41, target))
            );
            assert!(request_size(cmd).unwrap() <= size_of::<ManagedUploadChunkV1>());
            for len in 0..bytes.len() {
                assert_eq!(lifecycle_request(cmd, &bytes[..len]), Err(EINVAL));
            }
            let mut invalid = bytes.to_vec();
            invalid.push(0);
            assert_eq!(lifecycle_request(cmd, &invalid), Err(EINVAL));
            invalid = bytes.to_vec();
            invalid[..4].copy_from_slice(&(MANAGED_ADMIN_VERSION + 1).to_ne_bytes());
            assert_eq!(lifecycle_request(cmd, &invalid), Err(ENOTSUP));
            invalid = bytes.to_vec();
            invalid[4..8].copy_from_slice(&0u32.to_ne_bytes());
            assert_eq!(lifecycle_request(cmd, &invalid), Err(EINVAL));
            for byte in reserved..bytes.len() {
                invalid = bytes.to_vec();
                invalid[byte] = 1;
                assert_eq!(lifecycle_request(cmd, &invalid), Err(EINVAL));
            }
        }
        cancel.target_kind = MANAGED_TARGET_PREVIOUS;
        assert_eq!(
            lifecycle_request(BPF_MANAGED_INSTALLATION_CANCEL, cancel.as_bytes()),
            Ok((1 << 40, 1 << 41, LifecycleTarget::Previous(0)))
        );
        cancel.target_kind = MANAGED_TARGET_DEACTIVATE;
        assert_eq!(
            lifecycle_request(BPF_MANAGED_INSTALLATION_CANCEL, cancel.as_bytes()),
            Ok((1 << 40, 1 << 41, LifecycleTarget::Deactivate(0)))
        );
        cancel.target_kind = MANAGED_TARGET_RETIRE;
        assert_eq!(
            lifecycle_request(BPF_MANAGED_INSTALLATION_CANCEL, cancel.as_bytes()),
            Ok((1 << 40, 1 << 41, LifecycleTarget::Retire(0)))
        );
        for kind in [0, MANAGED_TARGET_RETIRE + 1, u32::MAX] {
            cancel.target_kind = kind;
            assert_eq!(
                lifecycle_request(BPF_MANAGED_INSTALLATION_CANCEL, cancel.as_bytes()),
                Err(EINVAL)
            );
        }
        cancel.id = 0;
        for kind in MANAGED_TARGET_CANDIDATE..=MANAGED_TARGET_RETIRE {
            cancel.target_kind = kind;
            assert_eq!(
                lifecycle_request(BPF_MANAGED_INSTALLATION_CANCEL, cancel.as_bytes()),
                Err(EINVAL)
            );
        }
        assert_eq!(request_size(BPF_MANAGED_CANCEL), Ok(24));
        assert_eq!(request_size(BPF_MANAGED_DEACTIVATE), Ok(32));
        assert_eq!(request_size(BPF_MANAGED_RETIRE), Ok(32));
        assert_eq!(request_size(BPF_MANAGED_INSTALLATION_CANCEL), Ok(40));
        // A lifecycle cancellation cannot be smuggled into the old upload shape.
        assert_eq!(
            validate_header(BPF_MANAGED_CANCEL, cancel.as_bytes()),
            Err(EINVAL)
        );
    }

    #[test]
    fn query_inputs_reject_every_nonzero_output_byte() {
        let slot = ManagedSlotV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedSlotV1>() as u32,
            ..Default::default()
        };
        assert_eq!(validate_slot_query(slot.as_bytes()), Ok(()));
        for byte in 8..size_of::<ManagedSlotV1>() {
            let mut invalid = slot.as_bytes().to_vec();
            invalid[byte] = 1;
            assert_eq!(validate_slot_query(&invalid), Err(EINVAL));
        }
        for len in 0..size_of::<ManagedSlotV1>() {
            assert_eq!(validate_slot_query(&slot.as_bytes()[..len]), Err(EINVAL));
        }
        let mut invalid_slot = slot;
        invalid_slot.version += 1;
        assert_eq!(validate_slot_query(invalid_slot.as_bytes()), Err(ENOTSUP));
        invalid_slot = slot;
        invalid_slot.size -= 1;
        assert_eq!(validate_slot_query(invalid_slot.as_bytes()), Err(EINVAL));
        let mut oversized = slot.as_bytes().to_vec();
        oversized.push(0);
        assert_eq!(validate_slot_query(&oversized), Err(EINVAL));

        let mut operation = ManagedOperationV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedOperationV1>() as u32,
            ..Default::default()
        };
        assert_eq!(operation_query_id(operation.as_bytes()), Ok(0));
        operation.id = 1 << 40;
        assert_eq!(operation_query_id(operation.as_bytes()), Ok(1 << 40));
        for byte in 16..size_of::<ManagedOperationV1>() {
            let mut invalid = operation.as_bytes().to_vec();
            invalid[byte] = 1;
            assert_eq!(operation_query_id(&invalid), Err(EINVAL));
        }
    }

    #[test]
    fn managed_commands_reject_wrong_syscall_size_before_user_copy() {
        for cmd in BPF_MANAGED_UPLOAD_BEGIN..=BPF_MANAGED_REARM {
            assert!(is_command(cmd));
            for size in [0, request_size(cmd).unwrap() - 1, usize::MAX] {
                let error = if cfg!(feature = "managed-runtime") {
                    EINVAL
                } else {
                    ENOTSUP
                };
                assert_eq!(dispatch(7, cmd, usize::MAX, size), -isize::from(error));
            }
        }
        assert!(!is_command(BPF_MANAGED_UPLOAD_BEGIN - 1));
        assert!(!is_command(BPF_MANAGED_REARM + 1));
    }

    #[test]
    fn managed_abi_validates_its_own_shape_before_mutation() {
        let mut manager = BpfManager::new();
        manager.enable_managed_preparation().unwrap();
        let mut request = ManagedUploadBeginV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedUploadBeginV1>() as u32,
            total_bytes: 16,
            ..Default::default()
        };
        assert!(size_of::<ManagedUploadBeginV1>() < size_of::<BpfAttr>());
        request.version += 1;
        assert_eq!(
            handle(
                &mut manager,
                7,
                BPF_MANAGED_UPLOAD_BEGIN,
                request.as_bytes()
            ),
            Err(ENOTSUP)
        );
        request.version -= 1;
        request.reserved = 1;
        assert_eq!(
            handle(
                &mut manager,
                7,
                BPF_MANAGED_UPLOAD_BEGIN,
                request.as_bytes()
            ),
            Err(EINVAL)
        );
        request.reserved = 0;
        assert_eq!(
            handle(
                &mut manager,
                7,
                BPF_MANAGED_UPLOAD_BEGIN,
                &request.as_bytes()[..23]
            ),
            Err(EINVAL)
        );
        assert_eq!(manager.managed_operation_query(0).unwrap().id, 0);
        assert_eq!(
            handle(
                &mut manager,
                7,
                BPF_MANAGED_UPLOAD_BEGIN,
                request.as_bytes()
            ),
            Ok((1, None))
        );
        let query = ManagedOperationV1 {
            version: 1,
            size: size_of::<ManagedOperationV1>() as u32,
            ..Default::default()
        };
        let reply = handle(
            &mut manager,
            7,
            BPF_MANAGED_OPERATION_QUERY,
            query.as_bytes(),
        )
        .unwrap()
        .1
        .unwrap();
        assert_eq!(reply.id, 1);
        assert_eq!(reply.phase, MANAGED_OPERATION_UPLOADING);

        let unchanged = |manager: &BpfManager| {
            (
                manager.resource_usage(),
                manager.managed_operation_query(1).unwrap(),
            )
        };
        let uploading = unchanged(&manager);
        let mut chunk = ManagedUploadChunkV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedUploadChunkV1>() as u32,
            id: 1,
            offset: 0,
            length: 16,
            reserved: 0,
            bytes: [0; MANAGED_UPLOAD_CHUNK_BYTES],
        };
        chunk.reserved = 1;
        assert_eq!(
            handle(&mut manager, 7, BPF_MANAGED_UPLOAD_CHUNK, chunk.as_bytes()),
            Err(EINVAL)
        );
        assert_eq!(unchanged(&manager), uploading);
        chunk.reserved = 0;
        chunk.length = MANAGED_UPLOAD_CHUNK_BYTES as u32 + 1;
        assert_eq!(
            handle(&mut manager, 7, BPF_MANAGED_UPLOAD_CHUNK, chunk.as_bytes()),
            Err(EINVAL)
        );
        assert_eq!(unchanged(&manager), uploading);
        chunk.length = 16;
        chunk.bytes[16] = 1;
        assert_eq!(
            handle(&mut manager, 7, BPF_MANAGED_UPLOAD_CHUNK, chunk.as_bytes()),
            Err(EINVAL)
        );
        assert_eq!(unchanged(&manager), uploading);
        chunk.bytes[16] = 0;

        let mut operation = ManagedOperationRequestV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedOperationRequestV1>() as u32,
            id: 1,
            reserved: 1,
        };
        for command in [BPF_MANAGED_UPLOAD_FINALIZE, BPF_MANAGED_CANCEL] {
            assert_eq!(
                handle(&mut manager, 7, command, operation.as_bytes()),
                Err(EINVAL)
            );
            assert_eq!(unchanged(&manager), uploading);
        }

        let mut malformed_query = query;
        malformed_query.reserved = 1;
        assert_eq!(
            handle(
                &mut manager,
                7,
                BPF_MANAGED_OPERATION_QUERY,
                malformed_query.as_bytes(),
            ),
            Err(EINVAL)
        );
        assert_eq!(unchanged(&manager), uploading);

        assert_eq!(
            handle(&mut manager, 7, BPF_MANAGED_UPLOAD_CHUNK, chunk.as_bytes()),
            Ok((16, None))
        );
        operation.reserved = 0;
        let before_finalize_usage = manager.resource_usage();
        assert_eq!(
            handle(
                &mut manager,
                7,
                BPF_MANAGED_UPLOAD_FINALIZE,
                operation.as_bytes(),
            ),
            Ok((1, None))
        );
        let queued_usage = manager.resource_usage();
        assert_ne!(queued_usage, before_finalize_usage);
        let queued = handle(
            &mut manager,
            7,
            BPF_MANAGED_OPERATION_QUERY,
            query.as_bytes(),
        )
        .unwrap()
        .1
        .unwrap();
        assert_eq!(queued.id, 1);
        assert_eq!(queued.phase, MANAGED_OPERATION_QUEUED);
        assert_eq!(queued.received_bytes, 16);
        assert_eq!(manager.resource_usage(), queued_usage);

        // A lost finalize reply is recovered by an exact retry of the same ID.
        assert_eq!(
            handle(
                &mut manager,
                7,
                BPF_MANAGED_UPLOAD_FINALIZE,
                operation.as_bytes(),
            ),
            Ok((1, None))
        );
        assert_eq!(manager.resource_usage(), queued_usage);
        assert_eq!(manager.managed_operation_query(1).unwrap(), queued);
    }
}
