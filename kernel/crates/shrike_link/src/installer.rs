//! Fixed-size installer transport, separate from the actuator message namespace.

use crate::crc16;

pub const FRAME_BYTES: usize = 16;
pub const DATA_BYTES: usize = 8;
pub const MAX_MESSAGE_BYTES: usize = 320;

const MAGIC: u8 = 0xA5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Request = 0,
    RequestLast = 1,
    Poll = 2,
    Reset = 3,
    Ack = 8,
    Response = 9,
    ResponseLast = 10,
    Error = 11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    BadLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub sequence: u32,
    pub len: u8,
    pub data: [u8; DATA_BYTES],
}

impl Frame {
    pub fn new(kind: FrameKind, sequence: u32, payload: &[u8]) -> Result<Self, WireError> {
        if payload.len() > DATA_BYTES || !valid_len(kind, payload.len()) {
            return Err(WireError::BadLength);
        }
        let mut data = [0; DATA_BYTES];
        data[..payload.len()].copy_from_slice(payload);
        Ok(Self {
            kind,
            sequence,
            len: payload.len() as u8,
            data,
        })
    }

    #[must_use]
    pub fn encode(&self) -> [u8; FRAME_BYTES] {
        let mut bytes = [0; FRAME_BYTES];
        bytes[0] = MAGIC;
        bytes[1] = (self.kind as u8) << 4 | self.len;
        bytes[2..6].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[6..14].copy_from_slice(&self.data);
        let crc = crc16(&bytes[..14]).to_le_bytes();
        bytes[14..16].copy_from_slice(&crc);
        bytes
    }

    fn is_canonical(&self) -> bool {
        let len = self.len as usize;
        len <= DATA_BYTES
            && valid_len(self.kind, len)
            && self.data[len..].iter().all(|byte| *byte == 0)
    }
}

const fn valid_len(kind: FrameKind, len: usize) -> bool {
    match kind {
        FrameKind::Poll | FrameKind::Error => len == 0,
        FrameKind::Reset => len == DATA_BYTES,
        FrameKind::Ack => len == 0 || len == DATA_BYTES,
        FrameKind::Request
        | FrameKind::RequestLast
        | FrameKind::Response
        | FrameKind::ResponseLast => len <= DATA_BYTES,
    }
}

fn decode_candidate(bytes: &[u8; FRAME_BYTES]) -> Option<Frame> {
    if bytes[0] != MAGIC || crc16(&bytes[..14]).to_le_bytes() != bytes[14..16] {
        return None;
    }
    let kind = match bytes[1] >> 4 {
        0 => FrameKind::Request,
        1 => FrameKind::RequestLast,
        2 => FrameKind::Poll,
        3 => FrameKind::Reset,
        8 => FrameKind::Ack,
        9 => FrameKind::Response,
        10 => FrameKind::ResponseLast,
        11 => FrameKind::Error,
        _ => return None,
    };
    let len = (bytes[1] & 0x0f) as usize;
    if len > DATA_BYTES || !valid_len(kind, len) || bytes[6 + len..14].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let mut data = [0; DATA_BYTES];
    data.copy_from_slice(&bytes[6..14]);
    Some(Frame {
        kind,
        sequence: u32::from_le_bytes(bytes[2..6].try_into().ok()?),
        len: len as u8,
        data,
    })
}

pub struct Decoder {
    bytes: [u8; FRAME_BYTES],
    len: usize,
}

impl Decoder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; FRAME_BYTES],
            len: 0,
        }
    }

    pub fn push(&mut self, byte: u8) -> Option<Frame> {
        if self.len == 0 && byte != MAGIC {
            return None;
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        if self.len < FRAME_BYTES {
            return None;
        }
        if let Some(frame) = decode_candidate(&self.bytes) {
            self.len = 0;
            return Some(frame);
        }

        if let Some(next) = self.bytes[1..].iter().position(|byte| *byte == MAGIC) {
            let next = next + 1;
            self.bytes.copy_within(next..FRAME_BYTES, 0);
            self.len = FRAME_BYTES - next;
        } else {
            self.len = 0;
        }
        None
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Endpoint {
    eligible: bool,
    expected_sequence: u32,
    request: [u8; MAX_MESSAGE_BYTES],
    request_len: usize,
    response: [u8; MAX_MESSAGE_BYTES],
    response_len: usize,
    response_cursor: usize,
    response_pending: bool,
    previous_request: Option<Frame>,
    previous_reply: Option<Frame>,
}

impl Endpoint {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            eligible: false,
            expected_sequence: 0,
            request: [0; MAX_MESSAGE_BYTES],
            request_len: 0,
            response: [0; MAX_MESSAGE_BYTES],
            response_len: 0,
            response_cursor: 0,
            response_pending: false,
            previous_request: None,
            previous_reply: None,
        }
    }

    pub fn exchange(
        &mut self,
        request: Frame,
        dispatch: impl FnOnce(&[u8], &mut [u8; MAX_MESSAGE_BYTES]) -> usize,
    ) -> Frame {
        if !request.is_canonical() {
            return error(request.sequence);
        }
        if self.previous_request == Some(request) {
            return self
                .previous_reply
                .unwrap_or_else(|| error(request.sequence));
        }
        if self
            .previous_request
            .is_some_and(|previous| previous.sequence == request.sequence)
        {
            return error(request.sequence);
        }

        if request.kind == FrameKind::Reset {
            if request.sequence == u32::MAX {
                return error(request.sequence);
            }
            self.request_len = 0;
            self.response_len = 0;
            self.response_cursor = 0;
            self.response_pending = false;
            self.previous_request = None;
            self.previous_reply = None;
            self.eligible = true;
            self.expected_sequence = request.sequence + 1;
            let reply = Frame::new(FrameKind::Ack, request.sequence, &request.data).unwrap();
            self.previous_request = Some(request);
            self.previous_reply = Some(reply);
            return reply;
        }

        if !self.eligible
            || request.sequence != self.expected_sequence
            || request.sequence == u32::MAX
        {
            return error(request.sequence);
        }

        let reply = match request.kind {
            FrameKind::Request | FrameKind::RequestLast => {
                let len = request.len as usize;
                if self.response_pending || self.request_len + len > MAX_MESSAGE_BYTES {
                    return error(request.sequence);
                }
                self.request[self.request_len..self.request_len + len]
                    .copy_from_slice(&request.data[..len]);
                self.request_len += len;
                if request.kind == FrameKind::RequestLast {
                    self.response_len =
                        dispatch(&self.request[..self.request_len], &mut self.response)
                            .min(MAX_MESSAGE_BYTES);
                    self.request_len = 0;
                    self.response_cursor = 0;
                    self.response_pending = true;
                }
                Frame::new(FrameKind::Ack, request.sequence, &[]).unwrap()
            }
            FrameKind::Poll => {
                if !self.response_pending {
                    return error(request.sequence);
                }
                let end = (self.response_cursor + DATA_BYTES).min(self.response_len);
                let kind = if end == self.response_len {
                    FrameKind::ResponseLast
                } else {
                    FrameKind::Response
                };
                let reply = Frame::new(
                    kind,
                    request.sequence,
                    &self.response[self.response_cursor..end],
                )
                .unwrap();
                self.response_cursor = end;
                if kind == FrameKind::ResponseLast {
                    self.response_pending = false;
                }
                reply
            }
            FrameKind::Reset
            | FrameKind::Ack
            | FrameKind::Response
            | FrameKind::ResponseLast
            | FrameKind::Error => return error(request.sequence),
        };
        self.expected_sequence = request.sequence + 1;
        self.previous_request = Some(request);
        self.previous_reply = Some(reply);
        reply
    }
}

fn error(sequence: u32) -> Frame {
    Frame {
        kind: FrameKind::Error,
        sequence,
        len: 0,
        data: [0; DATA_BYTES],
    }
}

impl Default for Endpoint {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::*;

    fn decode(bytes: &[u8]) -> Vec<Frame> {
        let mut decoder = Decoder::new();
        bytes
            .iter()
            .filter_map(|byte| decoder.push(*byte))
            .collect()
    }

    fn frame(kind: FrameKind, sequence: u32, payload: &[u8]) -> Frame {
        Frame::new(kind, sequence, payload).unwrap()
    }

    fn reset(endpoint: &mut Endpoint, sequence: u32) -> Frame {
        endpoint.exchange(frame(FrameKind::Reset, sequence, b"12345678"), |_, _| {
            panic!("reset must not dispatch")
        })
    }

    #[test]
    fn canonical_wire_layout_roundtrips_magic_in_every_payload_position() {
        let original = frame(
            FrameKind::RequestLast,
            0x7856_3412,
            &[MAGIC, 1, MAGIC, 3, MAGIC, 5, MAGIC, 7],
        );
        let bytes = original.encode();

        assert_eq!(bytes[0], MAGIC);
        assert_eq!(bytes[1], 0x18);
        assert_eq!(&bytes[2..6], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&bytes[6..14], &original.data);
        assert_eq!(&bytes[14..16], &crc16(&bytes[..14]).to_le_bytes());
        assert_eq!(decode(&bytes), vec![original]);
    }

    #[test]
    fn decoder_rejects_noncanonical_candidates_and_recovers_at_next_magic() {
        let good = frame(FrameKind::Poll, 9, &[]).encode();
        let mut unknown = good;
        unknown[1] = 0x40;
        let unknown_crc = crc16(&unknown[..14]).to_le_bytes();
        unknown[14..].copy_from_slice(&unknown_crc);
        let mut padded = good;
        padded[6] = 1;
        let padded_crc = crc16(&padded[..14]).to_le_bytes();
        padded[14..].copy_from_slice(&padded_crc);
        let mut corrupt = good;
        corrupt[14] ^= 1;

        let mut stream = Vec::new();
        stream.extend_from_slice(&unknown);
        stream.extend_from_slice(&padded);
        stream.extend_from_slice(&corrupt);
        stream.extend_from_slice(&good);
        assert_eq!(decode(&stream), vec![frame(FrameKind::Poll, 9, &[])]);
    }

    #[test]
    fn decoder_recovers_from_inserted_and_dropped_bytes() {
        let first = frame(FrameKind::Request, 1, b"ab").encode();
        let second = frame(FrameKind::RequestLast, 2, b"cd").encode();
        let third = frame(FrameKind::Poll, 3, &[]).encode();
        let mut stream = Vec::new();
        stream.extend_from_slice(&first[..7]);
        stream.extend_from_slice(&first[8..]);
        stream.extend_from_slice(&second[..5]);
        stream.push(0x55);
        stream.extend_from_slice(&second[5..]);
        stream.extend_from_slice(&third);

        assert_eq!(decode(&stream), vec![frame(FrameKind::Poll, 3, &[])]);
    }

    #[test]
    fn frame_constructor_enforces_kind_lengths() {
        assert_eq!(
            Frame::new(FrameKind::Request, 0, &[0; DATA_BYTES + 1]),
            Err(WireError::BadLength)
        );
        assert_eq!(
            Frame::new(FrameKind::Poll, 0, &[1]),
            Err(WireError::BadLength)
        );
        assert_eq!(
            Frame::new(FrameKind::Reset, 0, &[0; 7]),
            Err(WireError::BadLength)
        );
        assert!(Frame::new(FrameKind::Reset, 0, &[0; 8]).is_ok());
    }

    #[test]
    fn cold_endpoint_requires_reset_and_reset_echoes_challenge() {
        let mut endpoint = Endpoint::new();
        let rejected = endpoint.exchange(frame(FrameKind::RequestLast, 1, b"go"), |_, _| 0);
        assert_eq!(rejected.kind, FrameKind::Error);

        let ack = reset(&mut endpoint, 41);
        assert_eq!(ack, frame(FrameKind::Ack, 41, b"12345678"));
    }

    #[test]
    fn fragments_dispatch_once_and_polls_drain_the_bounded_response() {
        let mut endpoint = Endpoint::new();
        reset(&mut endpoint, 10);
        assert_eq!(
            endpoint.exchange(frame(FrameKind::Request, 11, b"abcdefgh"), |_, _| 0),
            frame(FrameKind::Ack, 11, &[])
        );
        let calls = Cell::new(0);
        let final_request = frame(FrameKind::RequestLast, 12, b"ij");
        let ack = endpoint.exchange(final_request, |request, response| {
            calls.set(calls.get() + 1);
            assert_eq!(request, b"abcdefghij");
            response[..10].copy_from_slice(b"0123456789");
            10
        });
        assert_eq!(ack, frame(FrameKind::Ack, 12, &[]));
        assert_eq!(
            endpoint.exchange(final_request, |_, _| panic!("duplicate dispatched")),
            ack
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            endpoint.exchange(frame(FrameKind::Poll, 13, &[]), |_, _| 0),
            frame(FrameKind::Response, 13, b"01234567")
        );
        assert_eq!(
            endpoint.exchange(frame(FrameKind::Poll, 14, &[]), |_, _| 0),
            frame(FrameKind::ResponseLast, 14, b"89")
        );
    }

    #[test]
    fn retransmission_and_rejection_do_not_repeat_dispatch_or_lose_cache() {
        let mut endpoint = Endpoint::new();
        reset(&mut endpoint, 20);
        let calls = Cell::new(0);
        let request = frame(FrameKind::RequestLast, 21, b"x");
        endpoint.exchange(request, |_, response| {
            calls.set(calls.get() + 1);
            response[..1].copy_from_slice(b"y");
            1
        });

        let altered = frame(FrameKind::RequestLast, 21, b"z");
        assert_eq!(
            endpoint.exchange(altered, |_, _| panic!("altered duplicate dispatched")),
            frame(FrameKind::Error, 21, &[])
        );
        assert_eq!(
            endpoint.exchange(request, |_, _| panic!("exact duplicate dispatched")),
            frame(FrameKind::Ack, 21, &[])
        );
        let poll = frame(FrameKind::Poll, 22, &[]);
        let reply = endpoint.exchange(poll, |_, _| 0);
        assert_eq!(reply, frame(FrameKind::ResponseLast, 22, b"y"));
        assert_eq!(endpoint.exchange(poll, |_, _| 0), reply);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn unread_response_rejects_new_request_without_consuming_sequence() {
        let mut endpoint = Endpoint::new();
        reset(&mut endpoint, 30);
        endpoint.exchange(frame(FrameKind::RequestLast, 31, b"a"), |_, response| {
            response[0] = 7;
            1
        });
        assert_eq!(
            endpoint.exchange(frame(FrameKind::Request, 32, b"b"), |_, _| 0),
            frame(FrameKind::Error, 32, &[])
        );
        assert_eq!(
            endpoint.exchange(frame(FrameKind::Poll, 32, &[]), |_, _| 0),
            frame(FrameKind::ResponseLast, 32, &[7])
        );
    }

    #[test]
    fn accumulator_overflow_is_transactional_and_retryable() {
        let mut endpoint = Endpoint::new();
        reset(&mut endpoint, 100);
        for sequence in 101..141 {
            assert_eq!(
                endpoint
                    .exchange(frame(FrameKind::Request, sequence, &[1; 8]), |_, _| 0)
                    .kind,
                FrameKind::Ack
            );
        }
        assert_eq!(
            endpoint
                .exchange(frame(FrameKind::RequestLast, 141, &[2]), |_, _| 0)
                .kind,
            FrameKind::Error
        );
        let mut seen = 0;
        assert_eq!(
            endpoint.exchange(frame(FrameKind::RequestLast, 141, &[]), |request, _| {
                seen = request.len();
                0
            }),
            frame(FrameKind::Ack, 141, &[])
        );
        assert_eq!(seen, MAX_MESSAGE_BYTES);
    }

    #[test]
    fn sequence_exhaustion_requires_a_fresh_nonoverflowing_reset() {
        let mut endpoint = Endpoint::new();
        assert_eq!(reset(&mut endpoint, u32::MAX - 1).kind, FrameKind::Ack);
        assert_eq!(
            endpoint
                .exchange(frame(FrameKind::RequestLast, u32::MAX, &[]), |_, _| 0)
                .kind,
            FrameKind::Error
        );
        assert_eq!(reset(&mut endpoint, u32::MAX).kind, FrameKind::Error);
        assert_eq!(reset(&mut endpoint, 5).kind, FrameKind::Ack);
    }

    #[test]
    fn altered_reset_duplicate_preserves_the_exact_cached_ack() {
        let mut endpoint = Endpoint::new();
        let original = frame(FrameKind::Reset, 9, b"12345678");
        let ack = endpoint.exchange(original, |_, _| 0);
        assert_eq!(
            endpoint.exchange(frame(FrameKind::Reset, 9, b"abcdefgh"), |_, _| 0),
            frame(FrameKind::Error, 9, &[])
        );
        assert_eq!(endpoint.exchange(original, |_, _| 0), ack);
    }
}
