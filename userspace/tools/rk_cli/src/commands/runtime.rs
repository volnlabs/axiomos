//! One bounded request at a time over the Pi debug UART.

mod audit;

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::Subcommand;
use kernel_abi::*;
use ring::rand::{SecureRandom, SystemRandom};
use shrike_link::installer::{
    Decoder, Frame, FrameKind, DATA_BYTES, FRAME_BYTES, MAX_MESSAGE_BYTES,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Subcommand)]
pub enum RuntimeCommand {
    /// Query the retained audit interval, clock and explicit loss counters
    AuditStatus,
    /// Export one bounded audit interval as JSON lines, including any gaps
    AuditExport {
        #[arg(long)]
        output: PathBuf,
    },
    /// Upload a canonical signed managed bundle, then enqueue preparation
    Upload { bundle: PathBuf },
    /// Query slot status, a retained operation (0 selects latest), or an artifact
    Query {
        #[arg(long, conflicts_with = "artifact")]
        operation: Option<u64>,
        #[arg(long)]
        artifact: Option<u32>,
    },
    /// Activate an exact staged artifact against the observed slot generation
    Activate {
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        artifact: u32,
    },
    /// Activate the exact retained previous artifact with fresh state
    Rollback {
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        artifact: u32,
    },
    /// Safely deactivate the exact active artifact
    Deactivate {
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        artifact: u32,
    },
    /// Retire an exact inactive artifact
    Retire {
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        artifact: u32,
    },
    /// Cancel an upload/preparation, or an exact lifecycle request
    Cancel {
        id: u64,
        #[arg(long, requires_all = ["artifact", "target_kind"])]
        expected_generation: Option<u64>,
        #[arg(long, requires = "expected_generation")]
        artifact: Option<u32>,
        #[arg(long, requires = "expected_generation", value_parser = clap::value_parser!(u32).range(1..=4))]
        target_kind: Option<u32>,
    },
    /// Trigger trusted stop; this does not unload code or release e-stop
    Stop,
}

struct Client<T> {
    io: T,
    decoder: Decoder,
    sequence: u32,
    timeout: Duration,
}

impl<T: Read + Write> Client<T> {
    fn connect(
        io: T,
        sequence: u32,
        challenge: [u8; DATA_BYTES],
        timeout: Duration,
    ) -> Result<Self> {
        let mut client = Self {
            io,
            decoder: Decoder::new(),
            sequence,
            timeout,
        };
        let reply = client.exchange(FrameKind::Reset, &challenge)?;
        ensure!(
            reply.kind == FrameKind::Ack
                && reply.len as usize == DATA_BYTES
                && reply.data == challenge,
            "installer reset challenge did not match"
        );
        Ok(client)
    }

    fn exchange(&mut self, kind: FrameKind, data: &[u8]) -> Result<Frame> {
        let next = self
            .sequence
            .checked_add(1)
            .context("installer sequence exhausted; reconnect and query")?;
        let frame = Frame::new(kind, self.sequence, data)
            .map_err(|e| anyhow!("invalid installer frame: {e:?}"))?;
        let bytes = frame.encode();
        let deadline = Instant::now() + self.timeout;
        let mut written = 0;
        loop {
            ensure!(Instant::now() < deadline,
                "installer response timed out; outcome may be unknown—query slot/operation before retrying");
            if written < bytes.len() {
                match self.io.write(&bytes[written..]) {
                    Ok(n) => {
                        ensure!(n <= bytes.len() - written, "invalid serial write count");
                        written += n;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => {
                        return Err(e).context("installer write failed; query before retrying")
                    }
                }
            } else {
                let mut input = [0; FRAME_BYTES];
                match self.io.read(&mut input) {
                    Ok(n) => {
                        ensure!(n <= input.len(), "invalid serial read count");
                        for byte in &input[..n] {
                            if let Some(reply) = self.decoder.push(*byte) {
                                if reply.sequence == self.sequence {
                                    ensure!(
                                        reply.kind != FrameKind::Error,
                                        "installer rejected transport frame: {:?}",
                                        &reply.data[..reply.len as usize]
                                    );
                                    self.sequence = next;
                                    return Ok(reply);
                                }
                            }
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => {
                        return Err(e).context("installer read failed; query before retrying")
                    }
                }
            }
            // No retransmission without a credit: an unread original frame can
            // still occupy the complete receive FIFO. Kernel receipts recover
            // an unknown outcome after an explicit reconnect/query.
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn request(&mut self, command: u16, body: &[u8]) -> Result<(i64, Vec<u8>)> {
        ensure!(
            body.len() <= MAX_MESSAGE_BYTES - 2,
            "management request too large"
        );
        let mut message = [0; MAX_MESSAGE_BYTES];
        message[..2].copy_from_slice(&command.to_le_bytes());
        message[2..2 + body.len()].copy_from_slice(body);
        let message = &message[..2 + body.len()];
        let fragments = message.chunks(DATA_BYTES);
        let count = fragments.len();
        for (index, bytes) in fragments.enumerate() {
            let kind = if index + 1 == count {
                FrameKind::RequestLast
            } else {
                FrameKind::Request
            };
            let ack = self.exchange(kind, bytes)?;
            ensure!(
                ack.kind == FrameKind::Ack && ack.len == 0,
                "unexpected installer request acknowledgement"
            );
        }
        let mut response = Vec::with_capacity(MAX_MESSAGE_BYTES);
        loop {
            let frame = self.exchange(FrameKind::Poll, &[])?;
            ensure!(
                matches!(frame.kind, FrameKind::Response | FrameKind::ResponseLast),
                "unexpected installer response"
            );
            let len = frame.len as usize;
            ensure!(
                response.len() + len <= MAX_MESSAGE_BYTES,
                "oversized installer response"
            );
            ensure!(
                len != 0 || frame.kind == FrameKind::ResponseLast,
                "empty continuing response"
            );
            response.extend_from_slice(&frame.data[..len]);
            if frame.kind == FrameKind::ResponseLast {
                break;
            }
        }
        ensure!(response.len() >= 8, "truncated syscall result");
        let result = i64::from_le_bytes(response[..8].try_into().unwrap());
        let output = response[8..].to_vec();
        if result < 0 {
            ensure!(output.is_empty(), "malformed rejected management response");
            bail!("management command {command} rejected: kernel result {result}");
        }
        Ok((result, output))
    }

    fn call(&mut self, command: u32, body: &(impl IntoBytes + Immutable)) -> Result<u64> {
        let (result, output) = self.request(command as u16, body.as_bytes())?;
        ensure!(output.is_empty(), "unexpected output from mutation");
        Ok(result as u64)
    }

    fn slot(&mut self) -> Result<ManagedSlotV1> {
        let request = ManagedSlotV1 {
            version: MANAGED_ADMIN_VERSION,
            size: std::mem::size_of::<ManagedSlotV1>() as u32,
            ..Default::default()
        };
        let (result, output) = self.request(BPF_MANAGED_SLOT_QUERY as u16, request.as_bytes())?;
        ensure!(result == 0, "invalid slot query return");
        let slot = ManagedSlotV1::read_from_bytes(&output)
            .map_err(|_| anyhow!("invalid slot response size"))?;
        ensure!(
            slot.version == request.version
                && slot.size == request.size
                && slot.reserved == 0
                && slot.flags & !63 == 0,
            "invalid slot response header"
        );
        Ok(slot)
    }

    fn operation(&mut self, id: u64) -> Result<ManagedOperationV1> {
        let request = ManagedOperationV1 {
            version: MANAGED_ADMIN_VERSION,
            size: std::mem::size_of::<ManagedOperationV1>() as u32,
            id,
            ..Default::default()
        };
        let (result, output) =
            self.request(BPF_MANAGED_OPERATION_QUERY as u16, request.as_bytes())?;
        ensure!(result == 0, "invalid operation query return");
        let operation = ManagedOperationV1::read_from_bytes(&output)
            .map_err(|_| anyhow!("invalid operation response size"))?;
        ensure!(
            operation.version == request.version
                && operation.size == request.size
                && operation.reserved == 0,
            "invalid operation response header"
        );
        ensure!(
            id == 0 || operation.id == id,
            "operation response identity mismatch"
        );
        Ok(operation)
    }
}

#[cfg(target_os = "linux")]
fn open_port(port: &Path) -> Result<File> {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    ensure!(
        port.metadata()?.file_type().is_char_device(),
        "--port must be a serial character device"
    );
    ensure!(
        std::process::Command::new("stty")
            .arg("-F")
            .arg(port)
            .args([
                "115200", "raw", "-echo", "-ixon", "-ixoff", "-crtscts", "min", "0", "time", "0"
            ])
            .status()?
            .success(),
        "could not configure serial port"
    );
    // Linux asm-generic/fcntl.h: O_NONBLOCK = 1 << 11.
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(1 << 11)
        .open(port)?;
    // Discard prior boot text/replies for a finite interval. Reset's challenge
    // confirms this connection; this is not MCU/FPGA safety qualification.
    let until = Instant::now() + Duration::from_millis(200);
    let mut bytes = [0; 64];
    while Instant::now() < until {
        match file.read(&mut bytes) {
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.into()),
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn open_port(_port: &Path) -> Result<File> {
    bail!("runtime UART currently supports Linux hosts")
}

pub fn run(port: &Path, command: RuntimeCommand) -> Result<()> {
    ensure!(
        cfg!(target_endian = "little"),
        "runtime ABI requires a little-endian host"
    );
    let io = open_port(port)?;
    let mut random = [0; 12];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| anyhow!("could not create transport challenge"))?;
    let sequence = u32::from_le_bytes(random[..4].try_into().unwrap()) & 0x7fff_ffff;
    let mut client = Client::connect(
        io,
        sequence,
        random[4..].try_into().unwrap(),
        Duration::from_secs(2),
    )?;
    match command {
        RuntimeCommand::AuditStatus => {
            println!("{}", audit::status_json(&client.audit_status()?));
        }
        RuntimeCommand::AuditExport { output } => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .with_context(|| format!("create new audit export {}", output.display()))?;
            client.export_audit(&mut file)?;
            println!(
                "Audit interval exported to {}; inspect its gap and loss fields.",
                output.display()
            );
        }
        RuntimeCommand::Query {
            artifact: Some(handle),
            ..
        } => {
            let slot = client.slot()?;
            let artifact = client.slot_artifact(&slot, handle)?;
            println!("{}", audit::artifact_json(&artifact));
        }
        RuntimeCommand::Query {
            operation: Some(id),
            artifact: None,
        } => {
            let op = client.operation(id)?;
            println!(
                "{}",
                serde_json::json!({"id":op.id,"phase":op.phase,"error":op.error,
                "total_bytes":op.total_bytes,"received_bytes":op.received_bytes,"artifact_handle":op.artifact_handle,
                "behavior_id":hex(&op.behavior_id),"revision":op.revision,
                "bundle_digest":hex(&op.bundle_digest),"payload_digest":hex(&op.payload_digest),
                "signer_fingerprint":hex(&op.signer_fingerprint),"signer_public_key":hex(&op.signer_public_key),"workspace_peak":op.workspace_peak})
            );
        }
        RuntimeCommand::Query {
            operation: None,
            artifact: None,
        } => {
            let slot = client.slot()?;
            println!(
                "{}",
                serde_json::json!({"last_id":slot.last_id,"generation":slot.generation,
                "pending_id":slot.pending_id,"flags":slot.flags,"pending_target_kind":slot.pending_target_kind,
                "active_artifact":(slot.flags & MANAGED_SLOT_HAS_ACTIVE != 0).then_some(slot.active_artifact),
                "previous_artifact":(slot.flags & MANAGED_SLOT_HAS_PREVIOUS != 0).then_some(slot.previous_artifact),
                "candidate_artifact":(slot.flags & MANAGED_SLOT_HAS_CANDIDATE != 0).then_some(slot.candidate_artifact),
                "active_charge_ns_per_s":slot.active_charge_ns_per_s})
            );
        }
        RuntimeCommand::Upload { bundle } => {
            let mut file =
                File::open(&bundle).with_context(|| format!("open {}", bundle.display()))?;
            let total = file.metadata()?.len();
            ensure!(
                total != 0 && total <= 256 * 1024,
                "bundle must contain 1..=262144 bytes"
            );
            let begin = ManagedUploadBeginV1 {
                version: MANAGED_ADMIN_VERSION,
                size: std::mem::size_of::<ManagedUploadBeginV1>() as u32,
                expected_last_id: client.slot()?.last_id,
                total_bytes: total as u32,
                reserved: 0,
            };
            let id = client.call(BPF_MANAGED_UPLOAD_BEGIN, &begin)?;
            // Print the stable kernel ID before further transfer: a lost reply
            // must be recovered with query, never by blind re-activation.
            println!("{}", serde_json::json!({"upload_id":id}));
            let mut offset = 0;
            while offset < total as u32 {
                let mut chunk = ManagedUploadChunkV1 {
                    version: MANAGED_ADMIN_VERSION,
                    size: std::mem::size_of::<ManagedUploadChunkV1>() as u32,
                    id,
                    offset,
                    length: (total as u32 - offset).min(MANAGED_UPLOAD_CHUNK_BYTES as u32),
                    reserved: 0,
                    bytes: [0; MANAGED_UPLOAD_CHUNK_BYTES],
                };
                file.read_exact(&mut chunk.bytes[..chunk.length as usize])?;
                let received = client.call(BPF_MANAGED_UPLOAD_CHUNK, &chunk)?;
                offset += chunk.length;
                ensure!(
                    received == u64::from(offset),
                    "upload offset acknowledgement mismatch"
                );
            }
            let mut extra = [0];
            ensure!(
                file.read(&mut extra)? == 0,
                "bundle changed size during upload; query/cancel upload {id}"
            );
            let finalize = ManagedOperationRequestV1 {
                version: MANAGED_ADMIN_VERSION,
                size: std::mem::size_of::<ManagedOperationRequestV1>() as u32,
                id,
                reserved: 0,
            };
            let operation = client.call(BPF_MANAGED_UPLOAD_FINALIZE, &finalize)?;
            println!(
                "{}",
                serde_json::json!({"operation_id":operation,"accepted":true})
            );
        }
        RuntimeCommand::Stop => {
            let (_, bytes) = client.request(u16::MAX, &[])?;
            ensure!(bytes.is_empty(), "invalid stop response");
            println!("{}", serde_json::json!({"stop_requested":true}));
        }
        RuntimeCommand::Cancel {
            id,
            expected_generation,
            artifact,
            target_kind,
        } => {
            if let Some(expected_generation) = expected_generation {
                let request = ManagedInstallationCancelV1 {
                    version: MANAGED_ADMIN_VERSION,
                    size: std::mem::size_of::<ManagedInstallationCancelV1>() as u32,
                    id,
                    expected_generation,
                    artifact_handle: artifact.context("--artifact required")?,
                    target_kind: target_kind.context("--target-kind required")?,
                    reserved: 0,
                };
                client.call(BPF_MANAGED_INSTALLATION_CANCEL, &request)?;
            } else {
                client.call(
                    BPF_MANAGED_CANCEL,
                    &ManagedOperationRequestV1 {
                        version: MANAGED_ADMIN_VERSION,
                        size: std::mem::size_of::<ManagedOperationRequestV1>() as u32,
                        id,
                        reserved: 0,
                    },
                )?;
            }
            println!("{}", serde_json::json!({"cancel_requested":id}));
        }
        other => {
            let (cmd, expected_generation, artifact_handle) = match other {
                RuntimeCommand::Activate {
                    expected_generation,
                    artifact,
                } => (BPF_MANAGED_ACTIVATE, expected_generation, artifact),
                RuntimeCommand::Rollback {
                    expected_generation,
                    artifact,
                } => (BPF_MANAGED_ROLLBACK, expected_generation, artifact),
                RuntimeCommand::Deactivate {
                    expected_generation,
                    artifact,
                } => (BPF_MANAGED_DEACTIVATE, expected_generation, artifact),
                RuntimeCommand::Retire {
                    expected_generation,
                    artifact,
                } => (BPF_MANAGED_RETIRE, expected_generation, artifact),
                _ => unreachable!(),
            };
            let request = ManagedInstallationRequestV1 {
                version: MANAGED_ADMIN_VERSION,
                size: std::mem::size_of::<ManagedInstallationRequestV1>() as u32,
                expected_last_id: client.slot()?.last_id,
                expected_generation,
                artifact_handle,
                reserved: 0,
            };
            let id = client.call(cmd, &request)?;
            println!("{}", serde_json::json!({"operation_id":id,"accepted":true}));
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use signed_bpf_loader::{dispatch, Transport};

    use super::*;

    struct Peer {
        transport: Transport,
        calls: Vec<Vec<u8>>,
        syscall: fn(u32, &mut [u8]) -> isize,
        stops: usize,
        drop_reply: bool,
    }
    impl Peer {
        fn new() -> Self {
            Self {
                transport: Transport::new(),
                calls: Vec::new(),
                syscall: |_, _| 123456789012,
                stops: 0,
                drop_reply: false,
            }
        }
    }
    impl Write for Peer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let n = bytes.len().min(3);
            assert!(
                self.transport.pending_reply().is_none(),
                "host exceeded frame credit"
            );
            let calls = &mut self.calls;
            let stops = &mut self.stops;
            let syscall = self.syscall;
            self.transport.receive(&bytes[..n], |request, out| {
                calls.push(request.to_vec());
                dispatch(request, out, syscall, || {
                    *stops += 1;
                    0
                })
            });
            if self.drop_reply {
                self.transport.written(FRAME_BYTES);
            }
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Read for Peer {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let reply = self
                .transport
                .pending_reply()
                .ok_or(io::ErrorKind::WouldBlock)?;
            let n = bytes.len().min(2).min(reply.len());
            bytes[..n].copy_from_slice(&reply[..n]);
            self.transport.written(n);
            Ok(n)
        }
    }

    #[test]
    fn actual_client_transport_and_dispatcher_preserve_binary_through_partial_io() {
        let mut client =
            Client::connect(Peer::new(), 17, [0xa5; 8], Duration::from_secs(1)).unwrap();
        let request = ManagedUploadChunkV1 {
            version: MANAGED_ADMIN_VERSION,
            size: std::mem::size_of::<ManagedUploadChunkV1>() as u32,
            id: 1 << 40,
            offset: 0,
            length: MANAGED_UPLOAD_CHUNK_BYTES as u32,
            reserved: 0,
            bytes: std::array::from_fn(|i| i as u8),
        };
        let (id, out) = client
            .request(BPF_MANAGED_UPLOAD_CHUNK as u16, request.as_bytes())
            .unwrap();
        assert_eq!(id, 123456789012);
        assert!(out.is_empty());
        assert_eq!(client.io.calls.len(), 1);
        assert_eq!(&client.io.calls[0][2..], request.as_bytes());
        assert_eq!(client.io.stops, 0);
    }

    #[test]
    fn queries_retain_full_identity_and_generation_through_real_dispatcher() {
        let mut peer = Peer::new();
        peer.syscall = |command, body| {
            match command {
                BPF_MANAGED_OPERATION_QUERY => {
                    let mut op = ManagedOperationV1::read_from_bytes(body).unwrap();
                    assert_eq!(op.id, 1 << 40);
                    op.phase = MANAGED_OPERATION_RESIDENT;
                    op.artifact_handle = 0;
                    op.signer_fingerprint = [0xa5; 32];
                    op.payload_digest = [0xff; 32];
                    body.copy_from_slice(op.as_bytes());
                }
                BPF_MANAGED_SLOT_QUERY => {
                    let mut slot = ManagedSlotV1::read_from_bytes(body).unwrap();
                    slot.flags = MANAGED_SLOT_HAS_ACTIVE;
                    slot.active_artifact = 0;
                    slot.generation = 1 << 41;
                    body.copy_from_slice(slot.as_bytes());
                }
                _ => panic!("unexpected management command"),
            }
            0
        };
        let mut client = Client::connect(peer, 17, [0xa5; 8], Duration::from_secs(1)).unwrap();
        let op = client.operation(1 << 40).unwrap();
        assert_eq!(op.signer_fingerprint, [0xa5; 32]);
        assert_eq!(op.payload_digest, [0xff; 32]);
        let slot = client.slot().unwrap();
        assert_eq!(slot.generation, 1 << 41);
        assert_ne!(slot.flags & MANAGED_SLOT_HAS_ACTIVE, 0);
        assert_eq!(slot.active_artifact, 0);
        assert_eq!(client.io.calls.len(), 2);
        assert_eq!(client.io.stops, 0);
    }

    fn audit_reply(command: u32, body: &mut [u8]) -> isize {
        match command {
            BPF_MANAGED_SLOT_QUERY if body.len() == std::mem::size_of::<ManagedSlotV1>() => {
                let mut slot = ManagedSlotV1::read_from_bytes(body).unwrap();
                slot.generation = 1 << 40;
                slot.last_id = 1 << 41;
                slot.flags = MANAGED_SLOT_HAS_ACTIVE | MANAGED_SLOT_HAS_CANDIDATE;
                body.copy_from_slice(slot.as_bytes());
            }
            BPF_MANAGED_SLOT_QUERY => {
                let mut artifact = ManagedSlotArtifactV2::read_from_bytes(body).unwrap();
                assert_eq!(artifact.expected_generation, 1 << 40);
                assert_eq!(artifact.expected_last_id, 1 << 41);
                assert_eq!(
                    artifact.expected_roles,
                    MANAGED_SLOT_HAS_ACTIVE | MANAGED_SLOT_HAS_CANDIDATE
                );
                assert_eq!(artifact.artifact_handle, 0);
                artifact.wcet_cycles = 123;
                artifact.behavior_id = [0xfe; 16];
                artifact.revision = 1 << 42;
                artifact.bundle_digest = [0xfd; 32];
                artifact.payload_digest = [0xff; 32];
                artifact.signer_public_key = [0xa5; 32];
                artifact.signer_fingerprint =
                    *kernel_bpf::signing::ProgramHash::compute(&artifact.signer_public_key)
                        .as_bytes();
                artifact.helper_version = 1;
                artifact.context_version = 1;
                artifact.private_value_size = 8;
                artifact.private_max_entries = 1;
                body.copy_from_slice(artifact.as_bytes());
            }
            BPF_MANAGED_RECORDER_STATUS => {
                let mut status = ManagedAuditStatusV1::read_from_bytes(body).unwrap();
                status.clock_frequency = 54_000_000;
                status.flags = MANAGED_AUDIT_CLOCK_READY;
                status.capacity = MANAGED_AUDIT_RECORDS as u32;
                status.record_bytes = std::mem::size_of::<ManagedAuditRecordV1>() as u32;
                status.next = 2052;
                status.oldest = 4;
                status.overwritten = 4;
                body.copy_from_slice(status.as_bytes());
            }
            BPF_MANAGED_RECORDER_READ => {
                let mut reply = ManagedAuditReadV1::read_from_bytes(body).unwrap();
                assert_eq!(reply.end, 2052);
                assert_eq!(reply.expected_session, 0);
                let start = match reply.cursor {
                    4 => {
                        reply.gap = 2045;
                        reply.flags = MANAGED_AUDIT_READ_GAP;
                        2049
                    }
                    2051 => 2051,
                    _ => panic!("export did not advance within the frozen interval"),
                };
                reply.count = (reply.end - start).min(2) as u32;
                reply.next_cursor = start + u64::from(reply.count);
                for (i, record) in reply.records[..reply.count as usize].iter_mut().enumerate() {
                    *record = ManagedAuditRecordV1 {
                        sequence: start + i as u64,
                        ticks: (start + i as u64) * 540_000,
                        correlation: 1 << 40,
                        kind: MANAGED_AUDIT_CYCLE,
                        payload: [0xa5; 64],
                        ..Default::default()
                    };
                }
                body.copy_from_slice(reply.as_bytes());
            }
            _ => panic!("unexpected audit command"),
        }
        0
    }

    #[test]
    fn audit_export_preserves_binary_records_and_exact_gaps_through_real_dispatcher() {
        let mut peer = Peer::new();
        peer.syscall = audit_reply;
        let mut client = Client::connect(peer, 17, [0xa5; 8], Duration::from_secs(1)).unwrap();
        let mut output = Vec::new();
        client.export_audit(&mut output).unwrap();
        let lines: Vec<serde_json::Value> = std::str::from_utf8(&output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 6);
        assert_eq!(lines[0]["clock_frequency"], 54_000_000);
        assert_eq!(lines[0]["session_established"], false);
        assert_eq!(lines[0]["payloads_decoded"], false);
        let artifacts = lines[0]["artifacts"].as_array().unwrap();
        assert_eq!(artifacts.len(), 1); // Active/candidate alias is queried once.
        assert_eq!(
            artifacts[0]["roles"],
            MANAGED_SLOT_HAS_ACTIVE | MANAGED_SLOT_HAS_CANDIDATE
        );
        assert_eq!(artifacts[0]["revision"], 1u64 << 42);
        assert_eq!(artifacts[0]["signer_public_key"], "a5".repeat(32));
        assert_eq!(artifacts[0]["payload_digest"], "ff".repeat(32));
        assert_eq!(
            lines[1],
            serde_json::json!({"type":"gap", "start":4, "end":2049, "count":2045})
        );
        assert_eq!(lines[2]["correlation"], 1u64 << 40);
        assert_eq!(lines[2]["payload_hex"], "a5".repeat(64));
        assert_eq!(lines[4]["sequence"], 2051);
        assert_eq!(
            lines[5],
            serde_json::json!({"type":"end", "cursor":2052, "records":3, "gaps":2045})
        );
        assert_eq!(client.io.calls.len(), 5);
        assert_eq!(client.io.stops, 0);
    }

    #[test]
    fn interrupted_audit_export_has_no_end_marker_and_malformed_status_rejects() {
        let mut peer = Peer::new();
        peer.syscall = |command, body| {
            if command == BPF_MANAGED_RECORDER_READ {
                -isize::from(EIO)
            } else {
                audit_reply(command, body)
            }
        };
        let mut client = Client::connect(peer, 17, [0xa5; 8], Duration::from_secs(1)).unwrap();
        let mut output = Vec::new();
        assert!(client.export_audit(&mut output).is_err());
        let lines: Vec<_> = std::str::from_utf8(&output).unwrap().lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("header"));
        assert_eq!(client.io.calls.len(), 4);
        assert_eq!(client.io.stops, 0);

        client.io.syscall = |command, body| {
            let result = audit_reply(command, body);
            let mut status = ManagedAuditStatusV1::read_from_bytes(body).unwrap();
            status.flags |= 0x8000_0000;
            body.copy_from_slice(status.as_bytes());
            result
        };
        assert!(client.audit_status().is_err());
    }

    #[test]
    fn stale_artifact_context_cannot_produce_a_complete_export_or_retry() {
        let mut peer = Peer::new();
        peer.syscall = |command, body| {
            if command == BPF_MANAGED_SLOT_QUERY
                && body.len() == std::mem::size_of::<ManagedSlotArtifactV2>()
            {
                -isize::from(ESTALE)
            } else {
                audit_reply(command, body)
            }
        };
        let mut client = Client::connect(peer, 17, [0xa5; 8], Duration::from_secs(1)).unwrap();
        let mut output = Vec::new();
        assert!(client.export_audit(&mut output).is_err());
        assert!(output.is_empty());
        assert_eq!(client.io.calls.len(), 3);
        assert_eq!(client.io.stops, 0);
    }

    #[test]
    fn lost_reply_does_not_blindly_resend_a_mutation_or_exceed_receive_credit() {
        let mut client =
            Client::connect(Peer::new(), 17, [0xa5; 8], Duration::from_secs(1)).unwrap();
        client.io.drop_reply = true;
        client.timeout = Duration::from_millis(40);
        assert!(client
            .request(u16::MAX, &[])
            .unwrap_err()
            .to_string()
            .contains("query"));
        assert_eq!(client.io.calls.len(), 1);
        assert_eq!(client.io.stops, 1);
    }
}
