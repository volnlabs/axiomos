#![no_std]

#[cfg(feature = "managed-runtime")]
mod managed {
    use kernel_abi::*;
    use shrike_link::installer::{Decoder, Endpoint, FRAME_BYTES, MAX_MESSAGE_BYTES};
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

    pub const STOP_COMMAND: u16 = 0xffff;

    #[must_use]
    pub fn retryable_read(result: i32) -> bool {
        result == -i32::from(EAGAIN) || result == -i32::from(EINTR)
    }

    pub struct Transport {
        endpoint: Endpoint,
        decoder: Decoder,
        reply: [u8; FRAME_BYTES],
        sent: usize,
        pending: bool,
    }

    impl Transport {
        #[must_use]
        pub const fn new() -> Self {
            Self {
                endpoint: Endpoint::new(),
                decoder: Decoder::new(),
                reply: [0; FRAME_BYTES],
                sent: 0,
                pending: false,
            }
        }

        #[must_use]
        pub fn pending_reply(&self) -> Option<&[u8]> {
            self.pending.then_some(&self.reply[self.sent..])
        }

        pub fn written(&mut self, count: usize) {
            if !self.pending {
                return;
            }
            self.sent += count.min(FRAME_BYTES - self.sent);
            if self.sent == FRAME_BYTES {
                self.sent = 0;
                self.pending = false;
            }
        }

        pub fn receive(
            &mut self,
            bytes: &[u8],
            dispatch: impl FnOnce(&[u8], &mut [u8; MAX_MESSAGE_BYTES]) -> usize,
        ) {
            if self.pending {
                return;
            }
            let mut dispatch = Some(dispatch);
            for byte in bytes.iter().take(FRAME_BYTES) {
                if let Some(request) = self.decoder.push(*byte) {
                    let reply = self
                        .endpoint
                        .exchange(request, dispatch.take().expect("one decoded frame"));
                    self.reply = reply.encode();
                    self.sent = 0;
                    self.pending = true;
                    break;
                }
            }
        }

        pub fn rx_fault(&mut self) {
            self.endpoint = Endpoint::new();
            self.decoder = Decoder::new();
        }

        pub fn read_error(&mut self, result: i32) {
            if !retryable_read(result) {
                self.rx_fault();
            }
        }
    }

    impl Default for Transport {
        fn default() -> Self {
            Self::new()
        }
    }

    pub fn dispatch(
        request: &[u8],
        response: &mut [u8; shrike_link::installer::MAX_MESSAGE_BYTES],
        mut bpf: impl FnMut(u32, &mut [u8]) -> isize,
        stop: impl FnOnce() -> isize,
    ) -> usize {
        let Some(command) = request
            .get(..2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .map(u16::from_le_bytes)
        else {
            return result_only(response, -isize::from(EINVAL));
        };
        let body = &request[2..];
        if command == STOP_COMMAND {
            return if body.is_empty() {
                result_only(response, stop())
            } else {
                result_only(response, -isize::from(EINVAL))
            };
        }

        let command = u32::from(command);
        match command {
            BPF_MANAGED_UPLOAD_BEGIN => {
                forward::<ManagedUploadBeginV1>(command, body, response, false, &mut bpf)
            }
            BPF_MANAGED_UPLOAD_CHUNK => {
                forward::<ManagedUploadChunkV1>(command, body, response, false, &mut bpf)
            }
            BPF_MANAGED_UPLOAD_FINALIZE | BPF_MANAGED_CANCEL => {
                forward::<ManagedOperationRequestV1>(command, body, response, false, &mut bpf)
            }
            BPF_MANAGED_REARM => {
                forward::<ManagedRearmRequestV1>(command, body, response, false, &mut bpf)
            }
            BPF_MANAGED_OPERATION_QUERY => {
                forward::<ManagedOperationV1>(command, body, response, true, &mut bpf)
            }
            BPF_MANAGED_ACTIVATE
            | BPF_MANAGED_ROLLBACK
            | BPF_MANAGED_DEACTIVATE
            | BPF_MANAGED_RETIRE => {
                forward::<ManagedInstallationRequestV1>(command, body, response, false, &mut bpf)
            }
            BPF_MANAGED_SLOT_QUERY => {
                if body.len() == core::mem::size_of::<ManagedSlotArtifactV2>() {
                    return forward::<ManagedSlotArtifactV2>(
                        command, body, response, true, &mut bpf,
                    );
                }
                forward::<ManagedSlotV1>(command, body, response, true, &mut bpf)
            }
            BPF_MANAGED_INSTALLATION_CANCEL => {
                forward::<ManagedInstallationCancelV1>(command, body, response, false, &mut bpf)
            }
            BPF_MANAGED_RECORDER_STATUS => {
                if body.len() == core::mem::size_of::<ManagedAuditStatusV2>() {
                    return forward::<ManagedAuditStatusV2>(
                        command, body, response, true, &mut bpf,
                    );
                }
                forward::<ManagedAuditStatusV1>(command, body, response, true, &mut bpf)
            }
            BPF_MANAGED_RECORDER_READ => {
                forward::<ManagedAuditReadV1>(command, body, response, true, &mut bpf)
            }
            _ => result_only(response, -isize::from(ENOTSUP)),
        }
    }

    fn forward<T>(
        command: u32,
        body: &[u8],
        response: &mut [u8; shrike_link::installer::MAX_MESSAGE_BYTES],
        include_body: bool,
        bpf: &mut impl FnMut(u32, &mut [u8]) -> isize,
    ) -> usize
    where
        T: FromBytes + IntoBytes + KnownLayout + Immutable,
    {
        if body.len() != core::mem::size_of::<T>() {
            return result_only(response, -isize::from(EINVAL));
        }
        let Ok(mut typed) = T::read_from_bytes(body) else {
            return result_only(response, -isize::from(EINVAL));
        };
        let result = bpf(command, typed.as_mut_bytes());
        let len = result_only(response, result);
        if result >= 0 && include_body {
            response[len..len + body.len()].copy_from_slice(typed.as_bytes());
            len + body.len()
        } else {
            len
        }
    }

    fn result_only(
        response: &mut [u8; shrike_link::installer::MAX_MESSAGE_BYTES],
        result: isize,
    ) -> usize {
        response[..8].copy_from_slice(&(result as i64).to_le_bytes());
        8
    }

    #[cfg(test)]
    mod tests {
        use core::cell::Cell;

        use zerocopy::IntoBytes;

        use super::*;

        fn message(command: u16, body: &[u8]) -> [u8; shrike_link::installer::MAX_MESSAGE_BYTES] {
            let mut request = [0; shrike_link::installer::MAX_MESSAGE_BYTES];
            request[..2].copy_from_slice(&command.to_le_bytes());
            request[2..2 + body.len()].copy_from_slice(body);
            request
        }

        fn result(response: &[u8]) -> i64 {
            i64::from_le_bytes(response[..8].try_into().unwrap())
        }

        #[test]
        fn transport_preserves_partial_reply_and_does_not_receive_until_written() {
            use shrike_link::installer::{Frame, FrameKind};

            let reset = Frame::new(FrameKind::Reset, 1, b"12345678")
                .unwrap()
                .encode();
            let expected = Frame::new(FrameKind::Ack, 1, b"12345678").unwrap().encode();
            let mut transport = Transport::new();
            transport.receive(&[0, 1, 2, 3, 4, 0xff], |_, _| {
                panic!("arbitrary bytes dispatched")
            });
            assert!(transport.pending_reply().is_none());
            transport.receive(&reset[..5], |_, _| panic!("partial reset dispatched"));
            assert!(transport.pending_reply().is_none());
            transport.receive(&reset[5..], |_, _| panic!("reset dispatched"));
            assert_eq!(transport.pending_reply(), Some(&expected[..]));

            transport.written(3);
            assert_eq!(transport.pending_reply(), Some(&expected[3..]));
            transport.receive(&reset, |_, _| panic!("read while replying"));
            assert_eq!(transport.pending_reply(), Some(&expected[3..]));
            transport.written(usize::MAX);
            assert!(transport.pending_reply().is_none());
        }

        #[test]
        fn only_idle_and_interrupted_reads_preserve_transport_state() {
            assert!(retryable_read(-i32::from(EAGAIN)));
            assert!(retryable_read(-i32::from(EINTR)));
            assert!(!retryable_read(-i32::from(EIO)));
            assert!(!retryable_read(0));
            assert!(!retryable_read(1));
        }

        #[test]
        fn transport_applies_retryable_read_classification_to_partial_input() {
            use shrike_link::installer::{FRAME_BYTES, Frame, FrameKind};

            let reset = Frame::new(FrameKind::Reset, 1, b"12345678")
                .unwrap()
                .encode();
            let mut transport = Transport::new();
            transport.receive(&reset[..7], |_, _| panic!("partial reset dispatched"));
            transport.read_error(-i32::from(EAGAIN));
            transport.receive(&reset[7..], |_, _| panic!("reset dispatched"));
            assert!(transport.pending_reply().is_some());
            transport.written(FRAME_BYTES);

            let request = Frame::new(FrameKind::RequestLast, 2, b"x")
                .unwrap()
                .encode();
            transport.receive(&request[..7], |_, _| panic!("partial request dispatched"));
            transport.read_error(-i32::from(EIO));
            transport.receive(&request[7..], |_, _| {
                panic!("suffix dispatched after fault")
            });
            assert!(transport.pending_reply().is_none());
            transport.receive(&request, |_, _| {
                panic!("request dispatched without fresh reset")
            });
            assert!(transport.pending_reply().is_some());
        }

        #[test]
        fn receive_fault_requires_a_fresh_reset_without_dispatching_requests() {
            use shrike_link::installer::{FRAME_BYTES, Frame, FrameKind};

            let mut transport = Transport::new();
            let reset = Frame::new(FrameKind::Reset, 7, b"abcdefgh")
                .unwrap()
                .encode();
            transport.receive(&reset, |_, _| 0);
            transport.written(FRAME_BYTES);
            transport.rx_fault();

            let request = Frame::new(FrameKind::RequestLast, 8, b"x")
                .unwrap()
                .encode();
            transport.receive(&request, |_, _| panic!("request dispatched after RX fault"));
            let error = Frame::new(FrameKind::Error, 8, &[]).unwrap().encode();
            assert_eq!(transport.pending_reply(), Some(&error[..]));
        }

        #[test]
        fn every_managed_command_forwards_only_its_exact_body_size() {
            let cases = [
                (
                    BPF_MANAGED_UPLOAD_BEGIN,
                    core::mem::size_of::<ManagedUploadBeginV1>(),
                ),
                (
                    BPF_MANAGED_UPLOAD_CHUNK,
                    core::mem::size_of::<ManagedUploadChunkV1>(),
                ),
                (
                    BPF_MANAGED_UPLOAD_FINALIZE,
                    core::mem::size_of::<ManagedOperationRequestV1>(),
                ),
                (
                    BPF_MANAGED_OPERATION_QUERY,
                    core::mem::size_of::<ManagedOperationV1>(),
                ),
                (
                    BPF_MANAGED_CANCEL,
                    core::mem::size_of::<ManagedOperationRequestV1>(),
                ),
                (
                    BPF_MANAGED_ACTIVATE,
                    core::mem::size_of::<ManagedInstallationRequestV1>(),
                ),
                (
                    BPF_MANAGED_ROLLBACK,
                    core::mem::size_of::<ManagedInstallationRequestV1>(),
                ),
                (
                    BPF_MANAGED_SLOT_QUERY,
                    core::mem::size_of::<ManagedSlotV1>(),
                ),
                (
                    BPF_MANAGED_SLOT_QUERY,
                    core::mem::size_of::<ManagedSlotArtifactV2>(),
                ),
                (
                    BPF_MANAGED_INSTALLATION_CANCEL,
                    core::mem::size_of::<ManagedInstallationCancelV1>(),
                ),
                (
                    BPF_MANAGED_DEACTIVATE,
                    core::mem::size_of::<ManagedInstallationRequestV1>(),
                ),
                (
                    BPF_MANAGED_RETIRE,
                    core::mem::size_of::<ManagedInstallationRequestV1>(),
                ),
                (
                    BPF_MANAGED_REARM,
                    core::mem::size_of::<ManagedRearmRequestV1>(),
                ),
                (
                    BPF_MANAGED_RECORDER_STATUS,
                    core::mem::size_of::<ManagedAuditStatusV1>(),
                ),
                (
                    BPF_MANAGED_RECORDER_STATUS,
                    core::mem::size_of::<ManagedAuditStatusV2>(),
                ),
                (
                    BPF_MANAGED_RECORDER_READ,
                    core::mem::size_of::<ManagedAuditReadV1>(),
                ),
            ];
            for (command, body_len) in cases {
                let request = message(command as u16, &[0; 288]);
                let mut response = [0; shrike_link::installer::MAX_MESSAGE_BYTES];
                let calls = Cell::new(0);
                let len = dispatch(
                    &request[..2 + body_len],
                    &mut response,
                    |got_command, body| {
                        calls.set(calls.get() + 1);
                        assert_eq!(got_command, command);
                        assert_eq!(body.len(), body_len);
                        0x1_0000_0001
                    },
                    || panic!("managed command called stop"),
                );
                assert_eq!(calls.get(), 1);
                assert_eq!(result(&response), 0x1_0000_0001);
                assert_eq!(
                    len,
                    if matches!(
                        command,
                        BPF_MANAGED_OPERATION_QUERY
                            | BPF_MANAGED_SLOT_QUERY
                            | BPF_MANAGED_RECORDER_STATUS
                            | BPF_MANAGED_RECORDER_READ
                    ) {
                        8 + body_len
                    } else {
                        8
                    }
                );
            }
        }

        #[test]
        fn rearm_rejects_every_inexact_body_length_without_a_syscall() {
            let mut response = [0; shrike_link::installer::MAX_MESSAGE_BYTES];
            let request = message(BPF_MANAGED_REARM as u16, &[0; 288]);
            for body_len in 0..=288 {
                if body_len == core::mem::size_of::<ManagedRearmRequestV1>() {
                    continue;
                }
                let len = dispatch(
                    &request[..2 + body_len],
                    &mut response,
                    |_, _| panic!("malformed rearm dispatched"),
                    || panic!("rearm called stop"),
                );
                assert_eq!(len, 8);
                assert_eq!(result(&response), -(isize::from(EINVAL) as i64));
            }
        }

        #[test]
        fn successful_queries_return_the_full_updated_struct() {
            let operation = ManagedOperationV1 {
                version: MANAGED_ADMIN_VERSION,
                size: core::mem::size_of::<ManagedOperationV1>() as u32,
                id: 9,
                ..Default::default()
            };
            let request = message(BPF_MANAGED_OPERATION_QUERY as u16, operation.as_bytes());
            let mut response = [0; shrike_link::installer::MAX_MESSAGE_BYTES];
            let len = dispatch(
                &request[..2 + operation.as_bytes().len()],
                &mut response,
                |_, body| {
                    body[16..20].copy_from_slice(&MANAGED_OPERATION_COMMITTED.to_ne_bytes());
                    0
                },
                || 0,
            );

            assert_eq!(len, 8 + operation.as_bytes().len());
            assert_eq!(result(&response), 0);
            assert_eq!(
                u32::from_ne_bytes(response[24..28].try_into().unwrap()),
                MANAGED_OPERATION_COMMITTED
            );
        }

        #[test]
        fn failed_query_and_malformed_or_unknown_requests_return_only_an_error_word() {
            let calls = Cell::new(0);
            for request in [&[][..], &[1][..], &[0, 1, 0][..], &[0xff, 0x7f][..]] {
                let mut response = [0; shrike_link::installer::MAX_MESSAGE_BYTES];
                let len = dispatch(
                    request,
                    &mut response,
                    |_, _| {
                        calls.set(calls.get() + 1);
                        0
                    },
                    || panic!("malformed request called stop"),
                );
                assert_eq!(len, 8);
                assert!(result(&response) < 0);
            }
            assert_eq!(calls.get(), 0);

            let oversized = message(BPF_MANAGED_UPLOAD_BEGIN as u16, &[0; 25]);
            let mut response = [0; shrike_link::installer::MAX_MESSAGE_BYTES];
            assert_eq!(
                dispatch(
                    &oversized[..27],
                    &mut response,
                    |_, _| panic!("oversized request forwarded"),
                    || 0,
                ),
                8
            );
            assert_eq!(result(&response), -i64::from(i32::from(EINVAL)));

            let query = ManagedSlotV1::default();
            let request = message(BPF_MANAGED_SLOT_QUERY as u16, query.as_bytes());
            let mut response = [0; shrike_link::installer::MAX_MESSAGE_BYTES];
            let len = dispatch(
                &request[..2 + query.as_bytes().len()],
                &mut response,
                |_, _| -isize::from(EINVAL),
                || 0,
            );
            assert_eq!(len, 8);
            assert_eq!(result(&response), -i64::from(i32::from(EINVAL)));
        }

        #[test]
        fn stop_is_exact_and_never_forwards_to_bpf() {
            let request = STOP_COMMAND.to_le_bytes();
            let mut response = [0; shrike_link::installer::MAX_MESSAGE_BYTES];
            let stops = Cell::new(0);
            let len = dispatch(
                &request,
                &mut response,
                |_, _| panic!("stop forwarded to BPF"),
                || {
                    stops.set(stops.get() + 1);
                    -7
                },
            );
            assert_eq!(len, 8);
            assert_eq!(result(&response), -7);
            assert_eq!(stops.get(), 1);

            let malformed = [request[0], request[1], 0];
            assert_eq!(dispatch(&malformed, &mut response, |_, _| 0, || 0), 8);
            assert_eq!(result(&response), -i64::from(i32::from(EINVAL)));
        }
    }
}

#[cfg(feature = "managed-runtime")]
pub use managed::{STOP_COMMAND, Transport, dispatch, retryable_read};
