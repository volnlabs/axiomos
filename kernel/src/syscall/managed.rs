//! Fixed-size administration dispatch; expensive work runs in the root worker.
use core::mem::size_of;

use kernel_abi::*;
use zerocopy::{FromBytes, IntoBytes};

use crate::bpf::BpfManager;

pub(super) fn is_command(cmd: u32) -> bool {
    (BPF_MANAGED_UPLOAD_BEGIN..=BPF_MANAGED_CANCEL).contains(&cmd)
}

fn request_size(cmd: u32) -> Result<usize, Errno> {
    match cmd {
        BPF_MANAGED_UPLOAD_BEGIN => Ok(size_of::<ManagedUploadBeginV1>()),
        BPF_MANAGED_UPLOAD_CHUNK => Ok(size_of::<ManagedUploadChunkV1>()),
        BPF_MANAGED_UPLOAD_FINALIZE | BPF_MANAGED_CANCEL => {
            Ok(size_of::<ManagedOperationRequestV1>())
        }
        BPF_MANAGED_OPERATION_QUERY => Ok(size_of::<ManagedOperationV1>()),
        _ => Err(ENOTSUP),
    }
}

fn handle(
    manager: &mut BpfManager,
    owner: u64,
    cmd: u32,
    bytes: &[u8],
) -> Result<(usize, Option<ManagedOperationV1>), Errno> {
    if bytes.len() != request_size(cmd)? {
        return Err(EINVAL);
    }
    let version = u32::from_ne_bytes(bytes[..4].try_into().map_err(|_| EINVAL)?);
    let size = u32::from_ne_bytes(bytes[4..8].try_into().map_err(|_| EINVAL)?);
    if version != MANAGED_ADMIN_VERSION {
        return Err(ENOTSUP);
    }
    if size as usize != bytes.len() {
        return Err(EINVAL);
    }
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
            let request = ManagedOperationV1::read_from_bytes(bytes).map_err(|_| EINVAL)?;
            let expected = ManagedOperationV1 {
                version,
                size,
                id: request.id,
                ..Default::default()
            };
            if request != expected {
                return Err(EINVAL);
            }
            return Ok((0, Some(manager.managed_operation_query(request.id)?)));
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
        if size != request_size(cmd)? {
            return Err(EINVAL);
        }
        let mut bytes = [0u8; size_of::<ManagedUploadChunkV1>()];
        super::validation::copy_from_userspace_into(ptr, &mut bytes[..size])?;
        let (value, reply) = {
            let manager = crate::BPF_MANAGER.get().ok_or(ENODEV)?;
            handle(&mut manager.lock(), owner, cmd, &bytes[..size])?
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
