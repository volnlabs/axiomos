//! Pi5 <-> Shrike-lite UART control-link frame codec.
//!
//! Binary, framed, corruption-safe. Spec:
//! `docs/superpowers/specs/2026-06-23-shrike-link-uart-protocol.md`.
//!
//! Wire frame: `SYNC(0x7E) VER(0x01) TYPE LEN PAYLOAD[LEN] CRC_LO CRC_HI`,
//! CRC16-CCITT/FALSE over `VER,TYPE,LEN,PAYLOAD`. The decoder is a byte-fed
//! state machine: only the `Idle` state treats `0x7E` as SYNC; once `LEN` is
//! accepted, payload+CRC are consumed by count, so `0x7E` inside a payload is
//! data, not a frame boundary (no COBS needed).
//!
//! The codec does NOT clamp motor duty — the kernel actuation monitor and the
//! FPGA envelope are the single clamp source of truth.
#![cfg_attr(not(test), no_std)]

pub mod watchdog;

pub const SYNC: u8 = 0x7E;
pub const VERSION: u8 = 0x01;
/// Max payload bytes; bounds the decoder's stack buffer and the wire `LEN`.
pub const MAX_PAYLOAD: usize = 16;
/// Largest frame on the wire: SYNC+VER+TYPE+LEN + payload + CRC(2).
pub const MAX_FRAME: usize = 4 + MAX_PAYLOAD + 2;

// Frozen TYPE table. High bit = direction: 0 = Pi5->Shrike, 1 = Shrike->Pi5.
const T_MOTOR: u8 = 0x01;
const T_ESTOP: u8 = 0x02;
const T_HB_TO_SHRIKE: u8 = 0x03;
const T_SENSOR: u8 = 0x81;
const T_HB_TO_PI: u8 = 0x82;

/// A decoded control-link message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Msg {
    /// Pi5 -> Shrike. Signed per-mille duty (-1000..=1000); not clamped here.
    /// `seq` is a monotonic anti-replay counter (freshness check; the link
    /// watchdog is the hard liveness guarantee).
    MotorSetpoint { seq: u8, left: i16, right: i16 },
    /// Pi5 -> Shrike. Advisory soft e-stop (the hard e-stop is an independent
    /// FPGA line, non-bypassable).
    Estop { assert: bool },
    /// Pi5 -> Shrike. Liveness.
    HeartbeatToShrike { seq: u16 },
    /// Shrike -> Pi5. Sensor frame.
    Sensor { ultrasonic_echo_us: u16, estop_line: bool, flags: u8 },
    /// Shrike -> Pi5. Liveness.
    HeartbeatToPi { seq: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// Encode: caller buffer too small for the frame.
    BufTooSmall,
    /// `LEN` exceeds `MAX_PAYLOAD`, or does not match the TYPE's fixed length.
    BadLen,
    /// CRC mismatch — frame dropped, decoder resynced.
    BadCrc,
    /// Version byte not `VERSION`.
    BadVersion,
    /// CRC/LEN valid but TYPE unknown — consumed by count, stream stays aligned.
    UnknownType,
}

/// CRC16-CCITT/FALSE: poly 0x1021, init 0xFFFF, no reflection, no final xor.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        let mut i = 0;
        while i < 8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
            i += 1;
        }
    }
    crc
}

/// Serialize `msg` into `out`, returning the frame length. `out` should be at
/// least `MAX_FRAME` bytes; `Err(BufTooSmall)` if it is too short.
pub fn encode(msg: &Msg, out: &mut [u8]) -> Result<usize, LinkError> {
    let mut payload = [0u8; MAX_PAYLOAD];
    let (ty, len) = match *msg {
        Msg::MotorSetpoint { seq, left, right } => {
            payload[0] = seq;
            payload[1..3].copy_from_slice(&left.to_le_bytes());
            payload[3..5].copy_from_slice(&right.to_le_bytes());
            (T_MOTOR, 5usize)
        }
        Msg::Estop { assert } => {
            payload[0] = assert as u8;
            (T_ESTOP, 1)
        }
        Msg::HeartbeatToShrike { seq } => {
            payload[0..2].copy_from_slice(&seq.to_le_bytes());
            (T_HB_TO_SHRIKE, 2)
        }
        Msg::Sensor {
            ultrasonic_echo_us,
            estop_line,
            flags,
        } => {
            payload[0..2].copy_from_slice(&ultrasonic_echo_us.to_le_bytes());
            payload[2] = estop_line as u8;
            payload[3] = flags;
            (T_SENSOR, 4)
        }
        Msg::HeartbeatToPi { seq } => {
            payload[0..2].copy_from_slice(&seq.to_le_bytes());
            (T_HB_TO_PI, 2)
        }
    };

    let total = 4 + len + 2;
    if out.len() < total {
        return Err(LinkError::BufTooSmall);
    }
    out[0] = SYNC;
    out[1] = VERSION;
    out[2] = ty;
    out[3] = len as u8;
    out[4..4 + len].copy_from_slice(&payload[..len]);
    // CRC covers VER,TYPE,LEN,PAYLOAD == out[1..4+len].
    let crc = crc16(&out[1..4 + len]);
    out[4 + len] = (crc & 0xFF) as u8;
    out[5 + len] = (crc >> 8) as u8;
    Ok(total)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Ver,
    Type,
    Len,
    Payload,
    CrcLo,
    CrcHi,
}

/// Streaming, byte-fed frame decoder. Feed one byte at a time; returns
/// `Some(result)` when a frame completes (or errors), `None` mid-frame. After
/// any error the decoder returns to `Idle` so the stream re-aligns on the next
/// `SYNC` — a single corrupt candidate costs at most one resync.
pub struct Decoder {
    state: State,
    ty: u8,
    len: usize,
    idx: usize,
    payload: [u8; MAX_PAYLOAD],
    crc_lo: u8,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            state: State::Idle,
            ty: 0,
            len: 0,
            idx: 0,
            payload: [0u8; MAX_PAYLOAD],
            crc_lo: 0,
        }
    }

    fn reset(&mut self) {
        self.state = State::Idle;
        self.idx = 0;
    }

    pub fn push(&mut self, b: u8) -> Option<Result<Msg, LinkError>> {
        match self.state {
            State::Idle => {
                if b == SYNC {
                    self.state = State::Ver;
                }
                None
            }
            State::Ver => {
                if b == VERSION {
                    self.state = State::Type;
                    None
                } else {
                    self.reset();
                    Some(Err(LinkError::BadVersion))
                }
            }
            State::Type => {
                self.ty = b;
                self.state = State::Len;
                None
            }
            State::Len => {
                if b as usize > MAX_PAYLOAD {
                    self.reset();
                    return Some(Err(LinkError::BadLen));
                }
                self.len = b as usize;
                self.idx = 0;
                self.state = if self.len == 0 {
                    State::CrcLo
                } else {
                    State::Payload
                };
                None
            }
            State::Payload => {
                // Consumed by count: 0x7E here is data, never a frame boundary.
                self.payload[self.idx] = b;
                self.idx += 1;
                if self.idx == self.len {
                    self.state = State::CrcLo;
                }
                None
            }
            State::CrcLo => {
                self.crc_lo = b;
                self.state = State::CrcHi;
                None
            }
            State::CrcHi => {
                let got = (self.crc_lo as u16) | ((b as u16) << 8);
                // Recompute over VER,TYPE,LEN,PAYLOAD.
                let hdr = [VERSION, self.ty, self.len as u8];
                let want = crc16_split(&hdr, &self.payload[..self.len]);
                let result = if got != want {
                    Err(LinkError::BadCrc)
                } else {
                    decode_msg(self.ty, self.len, &self.payload[..self.len])
                };
                self.reset();
                Some(result)
            }
        }
    }
}

/// CRC over a header slice followed by a payload slice, without allocating.
fn crc16_split(head: &[u8], tail: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    let step = |b: u8, crc: &mut u16| {
        *crc ^= (b as u16) << 8;
        let mut i = 0;
        while i < 8 {
            *crc = if *crc & 0x8000 != 0 {
                (*crc << 1) ^ 0x1021
            } else {
                *crc << 1
            };
            i += 1;
        }
    };
    for &b in head {
        step(b, &mut crc);
    }
    for &b in tail {
        step(b, &mut crc);
    }
    crc
}

fn decode_msg(ty: u8, len: usize, p: &[u8]) -> Result<Msg, LinkError> {
    // LEN must match the TYPE's fixed payload length exactly.
    let need = |n: usize| -> Result<(), LinkError> {
        if len == n {
            Ok(())
        } else {
            Err(LinkError::BadLen)
        }
    };
    match ty {
        T_MOTOR => {
            need(5)?;
            Ok(Msg::MotorSetpoint {
                seq: p[0],
                left: i16::from_le_bytes([p[1], p[2]]),
                right: i16::from_le_bytes([p[3], p[4]]),
            })
        }
        T_ESTOP => {
            need(1)?;
            Ok(Msg::Estop { assert: p[0] != 0 })
        }
        T_HB_TO_SHRIKE => {
            need(2)?;
            Ok(Msg::HeartbeatToShrike {
                seq: u16::from_le_bytes([p[0], p[1]]),
            })
        }
        T_SENSOR => {
            need(4)?;
            Ok(Msg::Sensor {
                ultrasonic_echo_us: u16::from_le_bytes([p[0], p[1]]),
                estop_line: p[2] != 0,
                flags: p[3],
            })
        }
        T_HB_TO_PI => {
            need(2)?;
            Ok(Msg::HeartbeatToPi {
                seq: u16::from_le_bytes([p[0], p[1]]),
            })
        }
        _ => Err(LinkError::UnknownType),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(dec: &mut Decoder, bytes: &[u8]) -> Vec<Result<Msg, LinkError>> {
        let mut out = Vec::new();
        for &b in bytes {
            if let Some(r) = dec.push(b) {
                out.push(r);
            }
        }
        out
    }

    fn roundtrip(msg: Msg) {
        let mut buf = [0u8; MAX_FRAME];
        let n = encode(&msg, &mut buf).unwrap();
        let mut dec = Decoder::new();
        let got = drain(&mut dec, &buf[..n]);
        assert_eq!(got, vec![Ok(msg)], "roundtrip {:?}", msg);
    }

    #[test]
    fn roundtrip_all_messages() {
        roundtrip(Msg::MotorSetpoint { seq: 7, left: -1000, right: 1000 });
        roundtrip(Msg::Estop { assert: true });
        roundtrip(Msg::Estop { assert: false });
        roundtrip(Msg::HeartbeatToShrike { seq: 0xBEEF });
        roundtrip(Msg::Sensor { ultrasonic_echo_us: 12345, estop_line: true, flags: 0xA5 });
        roundtrip(Msg::HeartbeatToPi { seq: 1 });
    }

    #[test]
    fn in_payload_sync_byte_is_data() {
        // seq and both duty bytes carry 0x7E; must survive consume-by-count.
        let msg = Msg::MotorSetpoint { seq: 0x7E, left: 0x007E, right: 0x7E00u16 as i16 };
        let mut buf = [0u8; MAX_FRAME];
        let n = encode(&msg, &mut buf).unwrap();
        assert!(buf[..n].iter().filter(|&&b| b == 0x7E).count() >= 3);
        let mut dec = Decoder::new();
        assert_eq!(drain(&mut dec, &buf[..n]), vec![Ok(msg)]);
    }

    #[test]
    fn crc_corruption_rejected() {
        let mut buf = [0u8; MAX_FRAME];
        let n = encode(&Msg::MotorSetpoint { seq: 1, left: 5, right: 6 }, &mut buf).unwrap();
        buf[5] ^= 0x01; // flip a payload bit
        let mut dec = Decoder::new();
        assert_eq!(drain(&mut dec, &buf[..n]), vec![Err(LinkError::BadCrc)]);
        // Decoder resynced: a fresh valid frame after the bad one decodes.
        let n2 = encode(&Msg::Estop { assert: true }, &mut buf).unwrap();
        assert_eq!(drain(&mut dec, &buf[..n2]), vec![Ok(Msg::Estop { assert: true })]);
    }

    #[test]
    fn len_over_max_rejected() {
        let frame = [SYNC, VERSION, T_MOTOR, (MAX_PAYLOAD + 1) as u8, 0, 0];
        let mut dec = Decoder::new();
        assert_eq!(drain(&mut dec, &frame), vec![Err(LinkError::BadLen)]);
    }

    #[test]
    fn len_mismatch_for_type_rejected() {
        // TYPE=motor but LEN=2 (motor needs 5). Build a CRC-valid frame by hand.
        let len = 2u8;
        let payload = [0u8, 0u8];
        let crc = crc16_split(&[VERSION, T_MOTOR, len], &payload);
        let frame = [
            SYNC, VERSION, T_MOTOR, len, payload[0], payload[1],
            (crc & 0xFF) as u8, (crc >> 8) as u8,
        ];
        let mut dec = Decoder::new();
        assert_eq!(drain(&mut dec, &frame), vec![Err(LinkError::BadLen)]);
    }

    #[test]
    fn unknown_type_stays_aligned() {
        let ty = 0x40u8; // unknown, valid CRC/LEN
        let len = 1u8;
        let payload = [0x99u8];
        let crc = crc16_split(&[VERSION, ty, len], &payload);
        let frame = [SYNC, VERSION, ty, len, payload[0], (crc & 0xFF) as u8, (crc >> 8) as u8];
        let mut dec = Decoder::new();
        let mut buf = [0u8; MAX_FRAME];
        let n = encode(&Msg::HeartbeatToPi { seq: 9 }, &mut buf).unwrap();
        let mut stream = frame.to_vec();
        stream.extend_from_slice(&buf[..n]);
        assert_eq!(
            drain(&mut dec, &stream),
            vec![Err(LinkError::UnknownType), Ok(Msg::HeartbeatToPi { seq: 9 })]
        );
    }

    #[test]
    fn bad_version_dropped_then_resync() {
        let mut dec = Decoder::new();
        assert_eq!(drain(&mut dec, &[SYNC, 0x02]), vec![Err(LinkError::BadVersion)]);
        let mut buf = [0u8; MAX_FRAME];
        let n = encode(&Msg::Estop { assert: false }, &mut buf).unwrap();
        assert_eq!(drain(&mut dec, &buf[..n]), vec![Ok(Msg::Estop { assert: false })]);
    }

    #[test]
    fn resync_after_garbage_prefix() {
        let mut buf = [0u8; MAX_FRAME];
        let n = encode(&Msg::HeartbeatToShrike { seq: 42 }, &mut buf).unwrap();
        let mut stream = vec![0xAA, 0xBB, 0xCC, 0x00, 0xFF];
        stream.extend_from_slice(&buf[..n]);
        let mut dec = Decoder::new();
        let got = drain(&mut dec, &stream);
        assert_eq!(got.last(), Some(&Ok(Msg::HeartbeatToShrike { seq: 42 })));
    }

    #[test]
    fn truncated_frame_yields_nothing() {
        let mut buf = [0u8; MAX_FRAME];
        let n = encode(&Msg::Sensor { ultrasonic_echo_us: 1, estop_line: false, flags: 0 }, &mut buf).unwrap();
        let mut dec = Decoder::new();
        assert!(drain(&mut dec, &buf[..n - 1]).is_empty());
        // Completing it then decodes.
        assert_eq!(dec.push(buf[n - 1]), Some(Ok(Msg::Sensor { ultrasonic_echo_us: 1, estop_line: false, flags: 0 })));
    }

    #[test]
    fn buf_too_small() {
        let mut tiny = [0u8; 3];
        assert_eq!(encode(&Msg::Estop { assert: true }, &mut tiny), Err(LinkError::BufTooSmall));
    }

    #[test]
    fn crc16_known_vector() {
        // CRC16-CCITT/FALSE("123456789") == 0x29B1.
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    #[test]
    fn crc16_split_matches_crc16() {
        // The decode-path CRC engine must equal the encode-path one for the
        // same logical bytes, or every frame would fail CRC across the wire.
        assert_eq!(crc16_split(b"1234", b"56789"), 0x29B1);
        assert_eq!(crc16_split(b"", b"123456789"), crc16(b"123456789"));
        assert_eq!(crc16_split(&[VERSION, T_MOTOR, 5], &[1, 2, 3, 4, 5]), {
            let mut v = vec![VERSION, T_MOTOR, 5];
            v.extend_from_slice(&[1, 2, 3, 4, 5]);
            crc16(&v)
        });
    }

    #[test]
    fn max_payload_exact_frame_consumes_without_off_by_one() {
        // No defined Msg has a 16-byte payload, so use an unknown TYPE with
        // LEN == MAX_PAYLOAD: exercises the consume-by-count path at the buffer
        // boundary. Must yield UnknownType (CRC/LEN valid) and stay aligned.
        let ty = 0x40u8;
        let payload = [0x7Eu8; MAX_PAYLOAD]; // all-SYNC payload, worst case
        let crc = crc16_split(&[VERSION, ty, MAX_PAYLOAD as u8], &payload);
        let mut frame = vec![SYNC, VERSION, ty, MAX_PAYLOAD as u8];
        frame.extend_from_slice(&payload);
        frame.push((crc & 0xFF) as u8);
        frame.push((crc >> 8) as u8);
        let mut dec = Decoder::new();
        assert_eq!(drain(&mut dec, &frame), vec![Err(LinkError::UnknownType)]);
        // Still aligned: a normal frame after it decodes.
        let mut buf = [0u8; MAX_FRAME];
        let n = encode(&Msg::Estop { assert: true }, &mut buf).unwrap();
        assert_eq!(drain(&mut dec, &buf[..n]), vec![Ok(Msg::Estop { assert: true })]);
    }

    #[test]
    fn decoder_reuse_across_back_to_back_frames() {
        let msgs = [
            Msg::MotorSetpoint { seq: 1, left: -10, right: 10 },
            Msg::HeartbeatToShrike { seq: 2 },
            Msg::Estop { assert: true },
            Msg::Sensor { ultrasonic_echo_us: 999, estop_line: false, flags: 3 },
        ];
        let mut stream = Vec::new();
        for m in &msgs {
            let mut buf = [0u8; MAX_FRAME];
            let n = encode(m, &mut buf).unwrap();
            stream.extend_from_slice(&buf[..n]);
        }
        let mut dec = Decoder::new();
        let got = drain(&mut dec, &stream);
        let want: Vec<Result<Msg, LinkError>> = msgs.iter().map(|m| Ok(*m)).collect();
        assert_eq!(got, want);
    }
}
