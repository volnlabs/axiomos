//! Offline interpretation of one retained window, never a qualification verdict.
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{anyhow, bail, ensure, Context, Result};
use kernel_abi::*;
use serde_json::{json, Value};
use zerocopy::FromBytes;

use super::{artifact_json, validate_artifact};

const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

pub fn run(input: &Path, output: &Path) -> Result<()> {
    let decoded = decode(File::open(input).context("open audit input")?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .context("create new decoded audit file")?;
    serde_json::to_writer_pretty(&mut file, &decoded)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn decode(input: impl Read) -> Result<Value> {
    ensure!(
        cfg!(target_endian = "little"),
        "audit ABI requires a little-endian host"
    );
    let mut text = String::new();
    input.take(MAX_FILE_BYTES + 1).read_to_string(&mut text)?;
    ensure!(
        text.len() as u64 <= MAX_FILE_BYTES && text.ends_with('\n'),
        "oversized or truncated audit file"
    );
    let lines: Vec<_> = text.lines().collect();
    ensure!(
        (2..=2 * MANAGED_AUDIT_RECORDS + 2).contains(&lines.len()),
        "invalid audit line count"
    );
    let parse = |line: &str| -> Result<Value> {
        ensure!(line.len() <= 16 * 1024, "oversized audit line");
        let value: Value = serde_json::from_str(line)?;
        // Exports use serde_json's canonical compact representation. This also
        // rejects duplicate keys rather than silently accepting the last value.
        ensure!(
            serde_json::to_vec(&value)?.as_slice() == line.as_bytes(),
            "noncanonical audit line or duplicate keys"
        );
        Ok(value)
    };
    let header = parse(lines[0])?;
    fields(
        &header,
        &[
            "type",
            "format",
            "version",
            "clock_frequency",
            "session",
            "session_established",
            "persistent_boot_identity",
            "oldest",
            "end",
            "overwritten",
            "dropped",
            "suppressed",
            "flags",
            "capacity",
            "record_bytes",
            "latest_stop",
            "payloads_decoded",
            "slot_generation",
            "slot_last_id",
            "artifacts",
        ],
    )?;
    ensure!(
        s(&header, "type")? == "header"
            && s(&header, "format")? == "axiomos-managed-audit"
            && n(&header, "version")? == 1,
        "unsupported audit header"
    );
    let oldest = n(&header, "oldest")?;
    let end = n(&header, "end")?;
    let frequency = n(&header, "clock_frequency")?;
    let flags = n(&header, "flags")?;
    ensure!(
        n(&header, "capacity")? == MANAGED_AUDIT_RECORDS as u64
            && n(&header, "record_bytes")? == 96
            && oldest == end.saturating_sub(MANAGED_AUDIT_RECORDS as u64)
            && n(&header, "overwritten")? == oldest,
        "invalid retained interval"
    );
    ensure!(
        flags & !63 == 0
            && flags & 1 != 0
            && frequency != 0
            && (flags & 2 != 0) == (n(&header, "session")? != 0)
            && b(&header, "session_established")? == (flags & 2 != 0)
            && (flags & 8 != 0) == (end == u64::MAX)
            && !b(&header, "persistent_boot_identity")?
            && !b(&header, "payloads_decoded")?,
        "inconsistent audit header flags"
    );
    n(&header, "dropped")?;
    n(&header, "suppressed")?;
    let mut state = DecodeState {
        missing_mapping_allowed: oldest != 0 || n(&header, "dropped")? != 0,
        ..Default::default()
    };
    let artifacts = header["artifacts"]
        .as_array()
        .ok_or_else(|| anyhow!("missing artifact list"))?;
    ensure!(artifacts.len() <= 3, "too many retained artifacts");
    for artifact in artifacts {
        let a = retained_artifact(artifact)?;
        ensure!(
            a.expected_generation == n(&header, "slot_generation")?
                && a.expected_last_id == n(&header, "slot_last_id")?,
            "artifact snapshot mismatch"
        );
        ensure!(
            state
                .artifacts
                .insert(a.artifact_handle, identity_json(&a))
                .is_none(),
            "duplicate retained artifact"
        );
    }
    n(&header, "slot_generation")?;
    n(&header, "slot_last_id")?;
    let mut cursor = oldest;
    let mut count = 0u64;
    let mut lost = 0u64;
    let mut last_tick = None;
    let mut events = Vec::new();
    // A retained window may start midway through a historical identity group.
    let mut orphan_allowed = oldest != 0 || n(&header, "dropped")? != 0;
    for line in &lines[1..lines.len() - 1] {
        let raw = parse(line)?;
        match s(&raw, "type")? {
            "gap" => {
                fields(&raw, &["type", "start", "end", "count"])?;
                let gap = n(&raw, "count")?;
                let next = cursor
                    .checked_add(gap)
                    .ok_or_else(|| anyhow!("gap overflow"))?;
                ensure!(
                    gap != 0
                        && n(&raw, "start")? == cursor
                        && n(&raw, "end")? == next
                        && next <= end,
                    "invalid transport gap"
                );
                state.break_identity(cursor, "identity interrupted by recorder overwrite");
                state.missing_mapping_allowed = true;
                for trace in state.lifecycles.values_mut() {
                    trace.seen |= 1 << 15;
                }
                cursor = next;
                lost += gap;
                orphan_allowed = true;
                events.push(raw);
            }
            "record" => {
                let record = raw_record(&raw, false)?;
                ensure!(
                    record.sequence == cursor
                        && cursor < end
                        && last_tick.is_none_or(|t| record.ticks >= t),
                    "missing/reordered record or reversed timestamp"
                );
                last_tick = Some(record.ticks);
                let decoded = state
                    .record(&record, frequency, orphan_allowed)
                    .with_context(|| format!("audit sequence {}", record.sequence))?;
                if record.kind != MANAGED_AUDIT_ARTIFACT {
                    orphan_allowed = false;
                }
                let mut event = raw;
                event["decoded"] = decoded;
                events.push(event);
                count += 1;
                cursor += 1;
            }
            _ => bail!("unexpected record type inside audit interval"),
        }
    }
    let terminal = parse(lines[lines.len() - 1])?;
    fields(&terminal, &["type", "cursor", "records", "gaps"])?;
    ensure!(
        s(&terminal, "type")? == "end"
            && n(&terminal, "cursor")? == end
            && cursor == end
            && n(&terminal, "records")? == count
            && n(&terminal, "gaps")? == lost,
        "missing or inconsistent end marker"
    );
    ensure!(
        state.pending.is_none(),
        "truncated authenticated identity group"
    );
    let latest = if flags & 16 != 0 {
        let record = raw_record(&header["latest_stop"], flags & 32 == 0)?;
        ensure!(
            record.kind == MANAGED_AUDIT_STOP && (flags & 32 == 0 || record.sequence < end),
            "invalid latest stop"
        );
        Some(state.record(&record, frequency, false)?)
    } else {
        ensure!(
            header["latest_stop"].is_null() && flags & 32 == 0,
            "unexpected latest stop"
        );
        None
    };
    Ok(
        json!({"format":"axiomos-managed-audit-decoded","version":1,"header":header,
        "events":events,"latest_stop_decoded":latest,"semantic_gaps":state.gaps,
        "payloads_decoded":true,"qualification_evaluated":false,"signature_reverified":false}),
    )
}

fn fields(v: &Value, names: &[&str]) -> Result<()> {
    let object = v
        .as_object()
        .ok_or_else(|| anyhow!("expected JSON object"))?;
    ensure!(
        object.len() == names.len() && names.iter().all(|k| object.contains_key(*k)),
        "missing or unknown audit fields"
    );
    Ok(())
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().ok_or_else(|| anyhow!("invalid integer {k}"))
}
fn n32(v: &Value, k: &str) -> Result<u32> {
    Ok(n(v, k)?.try_into()?)
}
fn b(v: &Value, k: &str) -> Result<bool> {
    v[k].as_bool().ok_or_else(|| anyhow!("invalid boolean {k}"))
}
fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().ok_or_else(|| anyhow!("invalid string {k}"))
}
fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    ensure!(text.len() == N * 2 && text.is_ascii(), "invalid hex length");
    let mut bytes = [0; N];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)?;
    }
    Ok(bytes)
}
fn raw_record(v: &Value, unrecorded: bool) -> Result<ManagedAuditRecordV1> {
    fields(
        v,
        &[
            "type",
            "sequence",
            "ticks",
            "correlation",
            "kind",
            "payload_hex",
        ],
    )?;
    ensure!(s(v, "type")? == "record", "invalid record type");
    let sequence = if unrecorded {
        ensure!(v["sequence"].is_null(), "unrecorded stop has sequence");
        0
    } else {
        n(v, "sequence")?
    };
    let r = ManagedAuditRecordV1 {
        sequence,
        ticks: n(v, "ticks")?,
        correlation: n(v, "correlation")?,
        kind: n32(v, "kind")?,
        payload: unhex(s(v, "payload_hex")?)?,
        ..Default::default()
    };
    super::valid_record(&r)?;
    Ok(r)
}

fn retained_artifact(v: &Value) -> Result<ManagedSlotArtifactV2> {
    fields(
        v,
        &[
            "artifact_handle",
            "roles",
            "slot_generation",
            "slot_last_id",
            "behavior_id",
            "revision",
            "bundle_digest",
            "payload_digest",
            "signer_fingerprint",
            "signer_public_key",
            "helper_version",
            "context_version",
            "effective_effects",
            "envelope",
            "private_array",
            "modeled_wcet_cycles",
        ],
    )?;
    let (value_size, max_entries) = if v["private_array"].is_null() {
        (0, 0)
    } else {
        fields(&v["private_array"], &["value_size", "max_entries"])?;
        (
            n32(&v["private_array"], "value_size")?,
            n32(&v["private_array"], "max_entries")?,
        )
    };
    let a = ManagedSlotArtifactV2 {
        version: MANAGED_SLOT_ARTIFACT_VERSION,
        size: 224,
        expected_generation: n(v, "slot_generation")?,
        expected_last_id: n(v, "slot_last_id")?,
        artifact_handle: n32(v, "artifact_handle")?,
        expected_roles: n32(v, "roles")?,
        wcet_cycles: n(v, "modeled_wcet_cycles")?,
        behavior_id: unhex(s(v, "behavior_id")?)?,
        revision: n(v, "revision")?,
        bundle_digest: unhex(s(v, "bundle_digest")?)?,
        payload_digest: unhex(s(v, "payload_digest")?)?,
        signer_fingerprint: unhex(s(v, "signer_fingerprint")?)?,
        signer_public_key: unhex(s(v, "signer_public_key")?)?,
        helper_version: n32(v, "helper_version")?,
        context_version: n32(v, "context_version")?,
        effective_effects: n32(v, "effective_effects")?,
        envelope: u32::from(b(v, "envelope")?),
        private_value_size: value_size,
        private_max_entries: max_entries,
        reserved: 0,
    };
    ensure!(
        a.expected_roles != 0 && a.expected_roles & !7 == 0,
        "invalid retained roles"
    );
    validate_artifact(&a, &a)?;
    Ok(a)
}
fn identity_json(a: &ManagedSlotArtifactV2) -> Value {
    let mut value = artifact_json(a);
    for k in ["roles", "slot_generation", "slot_last_id"] {
        value.as_object_mut().unwrap().remove(k);
    }
    value
}

struct PendingIdentity {
    operation: u64,
    ticks: u64,
    outcome: ManagedAuditUploadV1,
    next: u32,
    bytes: [u8; 224],
}
struct LifecycleTrace {
    public: u64,
    accepted: ManagedAuditLifecycleV1,
    // Lifecycle events 1..8; barrier begin/frame/complete/ack/receipt 9..13;
    // failed handoff 14; interrupted retained history 15.
    seen: u16,
    barrier: Option<(u32, u64, u32)>,
}
#[derive(Default)]
struct DecodeState {
    artifacts: BTreeMap<u32, Value>,
    lifecycles: BTreeMap<u64, LifecycleTrace>,
    pending: Option<PendingIdentity>,
    gaps: Vec<Value>,
    missing_mapping_allowed: bool,
}
impl DecodeState {
    fn gap(&mut self, sequence: u64, reason: &str) {
        self.gaps.push(json!({"sequence":sequence,"reason":reason}));
    }
    fn break_identity(&mut self, sequence: u64, reason: &str) {
        if self.pending.take().is_some() {
            self.gap(sequence, reason);
        }
    }
    fn identity(&mut self, handle: u32, sequence: u64) -> Value {
        if let Some(identity) = self.artifacts.get(&handle) {
            return identity.clone();
        }
        self.gap(
            sequence,
            "artifact identity is outside the retained context",
        );
        Value::Null
    }
    fn record(
        &mut self,
        r: &ManagedAuditRecordV1,
        frequency: u64,
        orphan_allowed: bool,
    ) -> Result<Value> {
        ensure!(
            self.pending.is_none() || r.kind == MANAGED_AUDIT_ARTIFACT,
            "interleaved or truncated identity group"
        );
        match r.kind {
            MANAGED_AUDIT_ARTIFACT => {
                let p = ManagedAuditIdentityFragmentV1::read_from_bytes(&r.payload).unwrap();
                ensure!(
                    p.index < 4 && r.correlation != 0,
                    "invalid identity fragment"
                );
                let Some(pending) = self.pending.as_mut() else {
                    ensure!(
                        orphan_allowed,
                        "identity fragment has no authenticated outcome"
                    );
                    self.gap(
                        r.sequence,
                        "partial identity group at retained/export gap boundary",
                    );
                    return Ok(json!({"event":"unresolved_identity_fragment","index":p.index}));
                };
                ensure!(
                    p.index == pending.next
                        && r.correlation == pending.operation
                        && r.ticks == pending.ticks
                        && p.artifact_handle == pending.outcome.artifact_handle,
                    "reordered or mismatched identity fragment"
                );
                let offset = p.index as usize * 56;
                pending.bytes[offset..offset + 56].copy_from_slice(&p.data);
                pending.next += 1;
                if pending.next != 4 {
                    return Ok(json!({"event":"identity_fragment","index":p.index}));
                }
                let pending = self.pending.take().unwrap();
                let identity = manifest_identity(&pending.bytes, &pending.outcome)?;
                if pending.outcome.flags & MANAGED_AUDIT_UPLOAD_HAS_ARTIFACT != 0 {
                    if let Some(previous) =
                        self.artifacts.insert(p.artifact_handle, identity.clone())
                    {
                        ensure!(
                            previous == identity,
                            "conflicting immutable artifact identity"
                        );
                    }
                }
                Ok(
                    json!({"event":"authenticated_identity","identity":identity,"registered":pending.outcome.flags & 2 != 0}),
                )
            }
            MANAGED_AUDIT_OPERATION => match u32::from_le_bytes(r.payload[..4].try_into().unwrap())
            {
                MANAGED_AUDIT_UPLOAD => {
                    let p = ManagedAuditUploadV1::read_from_bytes(&r.payload).unwrap();
                    ensure!(
                        r.correlation != 0
                            && (1..=6).contains(&p.phase)
                            && p.flags & !7 == 0
                            && p.reserved == 0
                            && p.reserved_tail == [0; 16]
                            && p.total_bytes != 0
                            && p.total_bytes <= 256 * 1024
                            && p.received_bytes <= p.total_bytes,
                        "invalid upload outcome"
                    );
                    ensure!(
                        (p.phase == 4) == (p.flags & 2 != 0)
                            && (matches!(p.phase, 5 | 6)) == (p.error != 0)
                            && (p.flags & 2 != 0 || p.artifact_handle == 0)
                            && (p.flags & 4 != 0 || p.modeled_wcet_cycles == 0)
                            && (p.flags & 6 == 0 || p.flags & 1 != 0)
                            && (p.flags & 1 == 0 || p.phase >= 4),
                        "inconsistent upload outcome"
                    );
                    if p.flags & 1 != 0 {
                        self.pending = Some(PendingIdentity {
                            operation: r.correlation,
                            ticks: r.ticks,
                            outcome: p,
                            next: 0,
                            bytes: [0; 224],
                        });
                    }
                    Ok(
                        json!({"event":"upload","phase":phase(p.phase)?,"errno":p.error,"artifact_handle":(p.flags&2!=0).then_some(p.artifact_handle),
                        "authenticated_identity_follows":p.flags&1!=0,"modeled_wcet_cycles":(p.flags&4!=0).then_some(p.modeled_wcet_cycles),
                        "workspace_peak":p.workspace_peak,"total_bytes":p.total_bytes,"received_bytes":p.received_bytes}),
                    )
                }
                MANAGED_AUDIT_LIFECYCLE => self.lifecycle(r),
                _ => bail!("unsupported operation payload"),
            },
            MANAGED_AUDIT_CYCLE => {
                let p = ManagedAuditCycleV1::read_from_bytes(&r.payload).unwrap();
                let failure = failure(p.failure, p.failure_detail)?;
                ensure!(
                    p.flags & !31 == 0
                        && p.decision <= 3
                        && p.queue_outcome <= 5
                        && (p.flags & 1 != 0 || p.artifact_handle == 0)
                        && (p.flags & 8 == 0 || p.flags & 16 != 0)
                        && (p.flags & 8 != 0 || (p.requested_left, p.requested_right) == (0, 0))
                        && (p.decision != 0 || (p.decided_left, p.decided_right) == (0, 0))
                        && (p.queue_outcome != 0 || p.decision == 0)
                        && (p.queue_outcome != 1 || p.decision != 0)
                        && (p.flags & 2 == 0 || (p.flags & 24 == 0 && p.queue_outcome == 0)),
                    "inconsistent cycle payload"
                );
                ensure!(
                    (p.flags & 4 == 0 || p.flags & 2 != 0)
                        && (p.flags & 16 == 0 || (p.flags & 1 != 0 && p.flags & 2 == 0))
                        && (p.flags & 1 == 0 || r.correlation != 0)
                        && (p.queue_outcome == 0 || p.flags & 16 != 0)
                        && (p.failure != 0
                            || p.flags & 2 != 0
                            || (p.flags & 16 != 0 && p.queue_outcome == 1))
                        && (p.decision != 3 || (p.decided_left, p.decided_right) == (0, 0)),
                    "invalid cycle execution custody"
                );
                if (1001..=1021).contains(&p.failure) {
                    ensure!(
                        p.flags & 24 == 0 && p.queue_outcome == 0,
                        "failed invocation leaked a request"
                    );
                }
                if p.failure == 6 {
                    ensure!(
                        p.queue_outcome == p.failure_detail,
                        "submission failure mismatch"
                    );
                }
                let identity = if p.flags & 1 != 0 {
                    self.identity(p.artifact_handle, r.sequence)
                } else {
                    Value::Null
                };
                Ok(
                    json!({"event":"cycle","cycle_id":p.cycle_id,"generation":r.correlation,"scheduled_ticks":p.scheduled_ticks,"actual_ticks":p.actual_ticks,
                    "missed_releases":p.missed_releases,"safe_mode":p.flags&2!=0,"handoff":p.flags&4!=0,
                    "request_known":p.flags&16!=0,"requested_pair":(p.flags&8!=0).then_some([p.requested_left,p.requested_right]),
                    "effective_requested_pair":(p.flags&16!=0).then_some([p.requested_left,p.requested_right]),
                    "decided_pair":(p.decision!=0).then_some([p.decided_left,p.decided_right]),"decision":(["absent","allow","clamp","safe"][p.decision as usize]),
                    "local_queue_outcome":(["none","queued","ownership_rejected","deadline_expired","clock_reversed","queue_failed"][p.queue_outcome as usize]),
                    "failure":failure,"failure_detail":p.failure_detail,"identity":identity}),
                )
            }
            MANAGED_AUDIT_STOP => {
                let p = ManagedAuditStopV1::read_from_bytes(&r.payload).unwrap();
                let mut public_operation = None;
                ensure!(
                    p.reserved == [0; 16]
                        && p.flags & !7 == 0
                        && (p.category == 5 || p.flags & 4 == 0)
                        && p.source <= 7
                        && (p.flags & 2 != 0 || p.artifact_handle == 0),
                    "invalid stop payload"
                );
                let event = match p.category {
                    5 => {
                        ensure!(
                            p.source == 7
                                && p.flags & !4 == 0
                                && (p.flags & 4 != 0) == (r.correlation != 0)
                                && p.cycle_id == 0
                                && p.observed_ticks == 0
                                && p.deadline_ticks == 0,
                            "invalid link fault stop fields"
                        );
                        link_fault(p.reason, p.detail)?;
                        if p.flags & 4 != 0 {
                            if let Some(trace) = self.lifecycles.get_mut(&r.correlation) {
                                public_operation = Some(trace.public);
                                trace.seen |= 1 << 14;
                            } else {
                                self.gap(
                                    r.sequence,
                                    "link fault operation mapping is outside the retained context",
                                );
                            }
                        }
                        "link_fault_stop_requested"
                    }
                    1 | 3 => {
                        ensure!(
                            p.flags == 0
                                && r.correlation == 0
                                && p.cycle_id == 0
                                && p.observed_ticks == 0
                                && p.deadline_ticks == 0
                                && p.detail == 0,
                            "invalid global stop fields"
                        );
                        if p.category == 1 {
                            ensure!(p.reason == 0 && p.source != 0, "invalid trusted stop");
                            "trusted_stop"
                        } else {
                            ensure!(
                                (1..=8).contains(&p.reason) && p.source == 7,
                                "invalid timer fault"
                            );
                            "timer_fault"
                        }
                    }
                    2 | 4 => {
                        ensure!(
                            p.flags & 1 != 0 && p.source == 7 && p.reason != 0,
                            "invalid cycle stop"
                        );
                        failure(p.reason, p.detail)?;
                        if p.category == 2 {
                            ensure!(p.observed_ticks == 0, "invalid cycle fault timestamp");
                            "cycle_fault"
                        } else {
                            ensure!(
                                p.reason == 5
                                    && p.detail == 0
                                    && p.observed_ticks >= p.deadline_ticks,
                                "invalid completion miss"
                            );
                            "completion_miss"
                        }
                    }
                    _ => bail!("unsupported stop category"),
                };
                let identity = if p.flags & 2 != 0 {
                    self.identity(p.artifact_handle, r.sequence)
                } else {
                    Value::Null
                };
                let fault = match p.category {
                    5 => Some(link_fault(p.reason, p.detail)?),
                    2 | 4 => Some(failure(p.reason, p.detail)?),
                    3 => Some(
                        [
                            "",
                            "busy",
                            "not_started",
                            "already_started",
                            "invalid_period",
                            "clock_reversed",
                            "exhausted",
                            "stopped",
                            "managed_control",
                        ][p.reason as usize],
                    ),
                    _ => None,
                };
                Ok(
                    json!({"event":event,"source":source(p.source),"source_code":p.source,"reason":p.reason,"failure":fault,"detail":p.detail,"cycle_id":(p.flags&1!=0).then_some(p.cycle_id),
                    "generation":(p.flags&1!=0).then_some(r.correlation),"observed_ticks":p.observed_ticks,"deadline_ticks":p.deadline_ticks,"identity":identity,
                    "instance_id":(p.flags&4!=0).then_some(r.correlation),"public_operation_id":public_operation,"physical_output_observed":false}),
                )
            }
            MANAGED_AUDIT_LINK => {
                let subtype = u32::from_le_bytes(r.payload[..4].try_into().unwrap());
                ensure!(
                    matches!(subtype, MANAGED_AUDIT_MOTOR_TX | MANAGED_AUDIT_HANDOFF_LINK)
                        || r.correlation == 0,
                    "unexpected global link correlation"
                );
                let source = u32::from_le_bytes(r.payload[4..8].try_into().unwrap());
                match subtype {
                    1 => {
                        ensure!(
                            source == 0
                                && u64::from_le_bytes(r.payload[8..16].try_into().unwrap())
                                    == frequency
                                && r.payload[16..] == [0; 48],
                            "invalid clock record"
                        );
                        Ok(json!({"event":"clock_initialized","frequency":frequency}))
                    }
                    2 => {
                        ensure!(
                            (1..=7).contains(&source) && r.payload[8..] == [0; 56],
                            "invalid local release"
                        );
                        Ok(
                            json!({"event":"local_stop_release","source":self::source(source),"source_code":source,"physical_rearm":false}),
                        )
                    }
                    MANAGED_AUDIT_MOTOR_TX => {
                        let p = ManagedAuditMotorTxV1::read_from_bytes(&r.payload).unwrap();
                        let origin = p.flags & MANAGED_AUDIT_MOTOR_HAS_ORIGIN != 0;
                        let intermediate = p.flags & MANAGED_AUDIT_MOTOR_INTERMEDIATE_ZERO != 0;
                        let pending = p.event == MANAGED_AUDIT_MOTOR_PENDING_DISCARDED;
                        let discarded = matches!(
                            p.event,
                            MANAGED_AUDIT_MOTOR_PENDING_DISCARDED
                                | MANAGED_AUDIT_MOTOR_FRAME_DISCARDED
                        );
                        ensure!(
                            matches!(
                                p.event,
                                MANAGED_AUDIT_MOTOR_FRAMED
                                    | MANAGED_AUDIT_MOTOR_LOCAL_COMPLETE
                                    | MANAGED_AUDIT_MOTOR_PENDING_DISCARDED
                                    | MANAGED_AUDIT_MOTOR_FRAME_DISCARDED
                            ) && p.flags
                                & !(MANAGED_AUDIT_MOTOR_HAS_ORIGIN
                                    | MANAGED_AUDIT_MOTOR_INTERMEDIATE_ZERO)
                                == 0
                                && p.command_sequence <= u8::MAX as u32
                                && p.reserved == [0; 20]
                                && if discarded {
                                    (1..=6).contains(&p.reason)
                                } else {
                                    p.reason == 0
                                }
                                && (!pending || (p.command_sequence == 0 && !intermediate))
                                && (p.event != MANAGED_AUDIT_MOTOR_FRAME_DISCARDED
                                    || (2..=5).contains(&p.reason))
                                && (!intermediate || (p.left, p.right) == (0, 0))
                                && if origin {
                                    r.correlation != 0
                                } else {
                                    r.correlation == 0 && p.cycle_id == 0 && p.artifact_handle == 0
                                },
                            "invalid motor TX record"
                        );
                        let identity = if origin {
                            self.identity(p.artifact_handle, r.sequence)
                        } else {
                            Value::Null
                        };
                        Ok(json!({
                            "event": (["motor_frame_created", "motor_frame_local_uart_complete", "motor_pending_discarded", "motor_frame_discarded"][p.event as usize - 1]),
                            "origin_known": origin,
                            "cycle_id": origin.then_some(p.cycle_id),
                            "generation": origin.then_some(r.correlation),
                            "artifact_handle": origin.then_some(p.artifact_handle),
                            "command_sequence": (!pending).then_some(p.command_sequence),
                            "framed_pair": (!pending).then_some([p.left, p.right]),
                            "pending_pair": pending.then_some([p.left, p.right]),
                            "discard_reason": if discarded { Some(["superseded", "safe_pair", "expired", "stop", "handoff", "inhibited"][p.reason as usize - 1]) } else { None },
                            "intermediate_zero": intermediate,
                            "queued_at_ns": p.queued_at_ns,
                            "queued_clock": "pi_cntvct_ns",
                            "identity": identity,
                            "sink_acceptance": null
                        }))
                    }
                    MANAGED_AUDIT_HANDOFF_LINK => self.handoff_link(r),
                    _ => bail!("unsupported link payload"),
                }
            }
            _ => bail!("unsupported record kind"),
        }
    }
    fn handoff_link(&mut self, r: &ManagedAuditRecordV1) -> Result<Value> {
        let p = ManagedAuditHandoffV1::read_from_bytes(&r.payload).unwrap();
        let has_op = p.flags & MANAGED_AUDIT_HANDOFF_HAS_OPERATION != 0;
        let has_generation = p.flags & MANAGED_AUDIT_HANDOFF_HAS_GENERATION != 0;
        let barrier = matches!(p.message_kind, 3 | 4);
        ensure!(
            (1..=7).contains(&p.event)
                && (1..=4).contains(&p.message_kind)
                && p.session != 0
                && p.command_sequence <= 255
                && p.reserved == [0; 12]
                && p.flags & !3 == 0
                && has_op == (r.correlation != 0)
                && has_generation == (p.event == MANAGED_AUDIT_HANDOFF_RECEIPT_COMMITTED)
                && if has_generation {
                    p.generation != 0
                } else {
                    p.generation == 0
                }
                && p.observed_ticks <= r.ticks
                && if barrier {
                    p.wire_correlation != 0
                } else {
                    p.wire_correlation == 0 && p.command_sequence == 0
                },
            "invalid handoff fields"
        );
        let shape = match p.event {
            1 => p.message_kind == 3 && has_op && p.error == 0,
            2 | 3 => {
                matches!(p.message_kind, 1 | 3)
                    && has_op == barrier
                    && (p.error == 0 || (p.event == 3 && (2006..=2008).contains(&p.error)))
            }
            4 => matches!(p.message_kind, 2 | 4) && has_op == barrier && p.error == 0,
            5 => matches!(p.message_kind, 2 | 4) && p.error == 0,
            6 => matches!(p.message_kind, 2 | 4) && matches!(p.error, 2007 | 2008),
            7 => p.message_kind == 4 && has_op && p.error == 0,
            _ => false,
        };
        ensure!(shape, "invalid handoff event custody");
        let mut public = None;
        if has_op {
            if let Some(trace) = self.lifecycles.get_mut(&r.correlation) {
                public = Some(trace.public);
                let progress = match p.event {
                    1 => Some((9, 4)),
                    2 if barrier => Some((10, 9)),
                    3 if barrier => Some((11, 10)),
                    4 if barrier => Some((12, 11)),
                    7 => Some((13, 12)),
                    _ => None,
                };
                if let Some((bit, prerequisite)) = progress {
                    ensure!(
                        trace.seen & (1 << bit) == 0
                            && ((bit + 1)..=13).all(|later| trace.seen & (1 << later) == 0),
                        "repeated or reordered handoff observation"
                    );
                    if p.error == 0 {
                        ensure!(trace.seen & (1 << 14) == 0, "failed handoff cannot advance");
                    }
                    // Slot cancellation precedes link disarm at the next
                    // release. A transport match in that interval is valid
                    // evidence, but cannot begin or commit an installation.
                    if matches!(p.event, 1 | 7) {
                        ensure!(
                            trace.seen & ((1 << 6) | (1 << 8)) == 0,
                            "cancelled or retired operation cannot begin or commit"
                        );
                    }
                    if p.event != 7 && p.error == 0 {
                        ensure!(
                            trace.seen & (1 << 5) == 0,
                            "handoff observation after commit"
                        );
                    }
                    for required in [Some(prerequisite), (p.event == 7).then_some(5)]
                        .into_iter()
                        .flatten()
                    {
                        if trace.seen & (1 << required) == 0 {
                            ensure!(
                                trace.seen & (1 << 15) != 0,
                                "handoff observation missing prerequisite"
                            );
                            self.gaps.push(json!({"sequence":r.sequence,"reason":"handoff prerequisite lost in transport gap"}));
                        }
                    }
                    let identity = (p.session, p.wire_correlation, p.command_sequence);
                    if let Some(expected) = trace.barrier {
                        ensure!(identity == expected, "handoff wire identity mismatch");
                    } else {
                        trace.barrier = Some(identity);
                    }
                    if p.event == 7 {
                        ensure!(
                            p.generation == trace.accepted.target_generation,
                            "receipt generation mismatch"
                        );
                    }
                    trace.seen |= 1 << bit;
                }
                if p.error != 0 {
                    trace.seen |= 1 << 14;
                }
            } else {
                ensure!(
                    self.missing_mapping_allowed,
                    "handoff has no operation acceptance in complete window"
                );
                self.gap(
                    r.sequence,
                    "handoff operation mapping is outside the retained context",
                );
            }
        }
        Ok(json!({
            "event": (["barrier_begin", "handoff_frame_created", "handoff_frame_local_uart_complete", "handoff_reply_accepted", "handoff_reply_ignored", "handoff_reply_rejected", "handoff_receipt_committed"][p.event as usize - 1]),
            "message": (["session_offer", "session_ready", "safe_barrier", "safe_ack"][p.message_kind as usize - 1]),
            "session": p.session, "wire_correlation": barrier.then_some(p.wire_correlation),
            "command_sequence": barrier.then_some(p.command_sequence),
            "instance_id": has_op.then_some(r.correlation), "public_operation_id": public,
            "generation": has_generation.then_some(p.generation), "observed_ticks": p.observed_ticks,
            "failure": failure(p.error, 0)?,
            "peer_reports_safe": (p.event == 4 && p.message_kind == 4 || p.event == 7).then_some(true),
            "physical_output_observed": false
        }))
    }

    fn lifecycle(&mut self, r: &ManagedAuditRecordV1) -> Result<Value> {
        let p = ManagedAuditLifecycleV1::read_from_bytes(&r.payload).unwrap();
        ensure!(
            (1..=8).contains(&p.event)
                && (1..=4).contains(&p.action)
                && p.instance_id != 0
                && p.reserved == 0
                && p.flags & !3 == 0
                && (p.flags & 1 != 0) == (r.correlation != 0),
            "invalid lifecycle fields"
        );
        let phase = phase(p.phase)?;
        ensure!(
            match p.event {
                1 => matches!(p.phase, 2 | 7) && p.error == 0,
                2 => matches!(p.phase, 3 | 10),
                3 => matches!(p.phase, 7 | 10) && (p.phase == 10) == (p.error != 0),
                4 => p.phase == 8 && p.error == 0 && p.action != 4,
                5 => p.phase == 9 && p.error == 0,
                6 => p.phase == 10 && p.error != 0,
                7 => matches!(p.phase, 9 | 10),
                8 => matches!(p.phase, 5 | 6 | 9) && (p.phase != 9) == (p.error != 0),
                _ => false,
            },
            "event does not match lifecycle phase/outcome"
        );
        ensure!(
            p.target_generation
                == p.expected_generation
                    .checked_add(u64::from(p.action != 4))
                    .ok_or_else(|| anyhow!("generation overflow"))?,
            "invalid target generation"
        );
        if p.event == 4 {
            ensure!(
                p.phase == 8 && p.flags & 2 != 0 && p.error == 0,
                "invalid handoff entry"
            );
        }
        if p.event == 5 {
            ensure!(
                p.phase == 9 && p.error == 0 && p.observed_generation == p.target_generation,
                "invalid commit"
            );
        }
        if p.event == 6 {
            ensure!(
                p.phase == 10 && p.error != 0,
                "invalid cancellation custody"
            );
        }
        ensure!(
            p.observed_generation == p.expected_generation
                || (p.event >= 5 && p.observed_generation == p.target_generation),
            "invalid observed generation"
        );
        if p.event == 1 {
            ensure!(
                p.flags & 1 != 0 && p.error == 0 && matches!(p.phase, 2 | 7),
                "invalid lifecycle acceptance"
            );
            ensure!(
                self.lifecycles
                    .insert(
                        p.instance_id,
                        LifecycleTrace {
                            public: r.correlation,
                            accepted: p,
                            seen: 0,
                            barrier: None
                        }
                    )
                    .is_none(),
                "duplicate internal lifecycle identity"
            );
        }
        let public = if let Some(LifecycleTrace {
            public,
            accepted,
            seen,
            ..
        }) = self.lifecycles.get_mut(&p.instance_id)
        {
            ensure!(
                (
                    p.expected_generation,
                    p.target_generation,
                    p.artifact_handle,
                    p.action
                ) == (
                    accepted.expected_generation,
                    accepted.target_generation,
                    accepted.artifact_handle,
                    accepted.action
                ) && (p.flags & 1 == 0 || r.correlation == *public),
                "lifecycle identity mismatch"
            );
            ensure!(
                *seen & (1 << p.event) == 0 && *seen & (1 << 8) == 0,
                "repeated or post-retirement lifecycle event"
            );
            ensure!(
                !matches!(p.event, 4 | 5) || *seen & ((1 << 6) | (1 << 14)) == 0,
                "cancelled or failed operation cannot hand off or commit"
            );
            let prerequisite = match p.event {
                3 => Some(2),
                4 if p.action != 3 => Some(3),
                5 if p.action != 4 => Some(4),
                8 => Some(7),
                _ => None,
            };
            if let Some(required) = prerequisite {
                if *seen & (1 << required) == 0 {
                    ensure!(
                        *seen & (1 << 15) != 0,
                        "lifecycle boundary missing its prerequisite"
                    );
                    self.gaps.push(json!({"sequence":r.sequence,"reason":"lifecycle prerequisite lost in transport gap"}));
                }
            }
            *seen |= 1 << p.event;
            Some(*public)
        } else {
            ensure!(
                self.missing_mapping_allowed,
                "lifecycle identity has no acceptance in a complete window"
            );
            self.gap(
                r.sequence,
                "lifecycle acceptance mapping is outside the retained context",
            );
            (p.flags & 1 != 0).then_some(r.correlation)
        };
        let identity = self.identity(p.artifact_handle, r.sequence);
        Ok(
            json!({"event":(["","accepted","preparing","built","handoff","committed","cancelled_pending_cleanup","cleanup","reclamation_settled"][p.event as usize]),
            "action":(["","activate","rollback","deactivate","retire_inactive"][p.action as usize]),"public_operation_id":public,"instance_id":p.instance_id,
            "expected_generation":p.expected_generation,"target_generation":p.target_generation,"observed_generation":p.observed_generation,
            "phase":phase,"errno":p.error,"inhibited":p.flags&2!=0,"identity":identity}),
        )
    }
}

fn source(code: u32) -> &'static str {
    [
        "unspecified",
        "operator",
        "watchdog",
        "gpio_hook",
        "learned_behavior",
        "mission",
        "pwm_syscall",
        "managed_control",
    ][code as usize]
}

fn phase(code: u32) -> Result<&'static str> {
    [
        "idle",
        "uploading",
        "queued",
        "preparing",
        "resident",
        "failed",
        "cancelled",
        "staged",
        "handoff",
        "committed",
        "cleanup",
    ]
    .get(code as usize)
    .copied()
    .ok_or_else(|| anyhow!("unknown operation phase"))
}
fn failure(code: u32, detail: u32) -> Result<&'static str> {
    ensure!(
        detail == 0 || code == 6 || code == 1004,
        "unexpected fault detail"
    );
    let name = match code {
        0 => "none",
        1 => "invalid_release",
        2 => "missed_release",
        3 => "clock_invalid",
        4 => "clock_reversed",
        5 => "deadline",
        6 => {
            ensure!((2..=5).contains(&detail), "invalid submission failure");
            "submission"
        }
        7 => "policy_stopped",
        1001..=1021 => [
            "division_by_zero",
            "out_of_bounds",
            "stack_overflow",
            "invalid_helper",
            "timeout",
            "invalid_instruction",
            "not_loaded",
            "out_of_memory",
            "resource_limit",
            "object_busy",
            "permission_denied",
            "reentrant_execution",
            "verification_failed",
            "signature_rejected",
            "admission_rejected",
            "gpio_fanout_exceeded",
            "read_only_map",
            "managed_context_invalid",
            "duplicate_request",
            "invalid_request",
            "map_failure",
        ][(code - 1001) as usize],
        2001..=2009 => [
            "link_not_established",
            "handoff_busy",
            "bad_identity",
            "invalid_timeout",
            "counter_exhausted",
            "stale_handoff",
            "handoff_timeout",
            "handoff_clock_reversed",
            "handoff_invalid_release",
        ][(code - 2001) as usize],
        _ => bail!("unknown fault code"),
    };
    Ok(name)
}

fn manifest_identity(bytes: &[u8; 224], outcome: &ManagedAuditUploadV1) -> Result<Value> {
    use kernel_bpf::signing::managed;
    let u16_at = |i| u16::from_le_bytes(bytes[i..i + 2].try_into().unwrap());
    let u32_at = |i| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
    let total = u32_at(8);
    ensure!(
        &bytes[..4] == managed::MAGIC
            && u16_at(4) == managed::VERSION
            && u16_at(6) as usize == managed::HEADER_SIZE
            && u16_at(40) == managed::CONTROL_SLOT
            && u16_at(42) == managed::CONTEXT_VERSION
            && u16_at(44) == managed::HELPER_VERSION
            && u16_at(46) & !1 == 0
            && bytes[60..64] == [0; 4]
            && bytes[128..160] == [0; 32]
            && total == outcome.total_bytes
            && total as usize <= managed::MAX_BUNDLE_BYTES
            && u32_at(12) != 0
            && u32_at(12)
                .checked_mul(8)
                .and_then(|n| n.checked_add(managed::HEADER_SIZE as u32))
                == Some(total),
        "invalid authenticated manifest shape"
    );
    let a = ManagedSlotArtifactV2 {
        version: 2,
        size: 224,
        artifact_handle: outcome.artifact_handle,
        behavior_id: bytes[16..32].try_into().unwrap(),
        revision: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
        bundle_digest: bytes[160..192].try_into().unwrap(),
        payload_digest: bytes[64..96].try_into().unwrap(),
        signer_fingerprint: bytes[192..224].try_into().unwrap(),
        signer_public_key: bytes[96..128].try_into().unwrap(),
        helper_version: u16_at(44) as u32,
        context_version: u16_at(42) as u32,
        envelope: (u16_at(46) & 1) as u32,
        effective_effects: u32_at(48),
        private_value_size: u32_at(52),
        private_max_entries: u32_at(56),
        wcet_cycles: outcome.modeled_wcet_cycles,
        ..Default::default()
    };
    validate_artifact(&a, &a)?;
    let mut identity = identity_json(&a);
    if outcome.flags & 2 == 0 {
        identity["artifact_handle"] = Value::Null;
    }
    if outcome.flags & 4 == 0 {
        identity["modeled_wcet_cycles"] = Value::Null;
    }
    Ok(identity)
}

fn link_fault(reason: u32, detail: u32) -> Result<&'static str> {
    ensure!(
        match reason {
            1 => (1..=15).contains(&detail),
            2 => (1..=6).contains(&detail),
            3 => (1..=64).contains(&detail),
            4 | 5 | 7 => detail == 0,
            6 => (2001..=2009).contains(&detail),
            _ => false,
        },
        "invalid link fault reason/detail"
    );
    Ok([
        "uart_receive",
        "decoder",
        "rx_overflow",
        "peer_estop",
        "pi_inbound_timeout",
        "handoff",
        "link_unavailable",
    ][reason as usize - 1])
}

#[cfg(test)]
mod tests {
    use zerocopy::IntoBytes;

    use super::super::record_json;
    use super::*;

    fn export(records: &[ManagedAuditRecordV1]) -> String {
        let status = ManagedAuditStatusV1 {
            flags: MANAGED_AUDIT_CLOCK_READY,
            clock_frequency: 1000,
            capacity: MANAGED_AUDIT_RECORDS as u32,
            record_bytes: 96,
            next: records.len() as u64,
            ..Default::default()
        };
        let mut header = super::super::status_json(&status);
        header["slot_generation"] = json!(0);
        header["slot_last_id"] = json!(0);
        header["artifacts"] = json!([]);
        let mut lines = vec![header];
        for (i, r) in records.iter().enumerate() {
            let mut r = *r;
            r.sequence = i as u64;
            lines.push(record_json(&r));
        }
        lines.push(json!({"type":"end","cursor":records.len(),"records":records.len(),"gaps":0}));
        lines.into_iter().map(|v| v.to_string() + "\n").collect()
    }

    fn identity_and_lifecycle() -> Vec<ManagedAuditRecordV1> {
        use kernel_bpf::signing::{managed, ProgramHash};
        let program = [kernel_bpf::bytecode::insn::BpfInsn::exit()];
        let manifest = managed::Manifest {
            behavior_id: [7; 16],
            revision: 1 << 40,
            envelope: true,
            effects: 1,
            private_array: Some(managed::PrivateArray {
                value_size: 8,
                max_entries: 1,
            }),
        }
        .unsigned_header(program.as_bytes(), &[41; 32])
        .unwrap();
        let mut identity = [0u8; 224];
        identity[..160].copy_from_slice(&manifest[..160]);
        identity[160..192].fill(9);
        identity[192..].copy_from_slice(ProgramHash::compute(&[41; 32]).as_bytes());
        let upload = ManagedAuditUploadV1 {
            operation_kind: 1,
            phase: 4,
            flags: 7,
            artifact_handle: 17,
            total_bytes: 232,
            received_bytes: 232,
            workspace_peak: 512,
            modeled_wcet_cycles: 123,
            ..Default::default()
        };
        let mut records = vec![ManagedAuditRecordV1 {
            kind: MANAGED_AUDIT_OPERATION,
            correlation: 9,
            payload: upload.as_bytes().try_into().unwrap(),
            ..Default::default()
        }];
        for (index, data) in identity.as_chunks::<56>().0.iter().enumerate() {
            let p = ManagedAuditIdentityFragmentV1 {
                index: index as u32,
                artifact_handle: 17,
                data: *data,
            };
            records.push(ManagedAuditRecordV1 {
                kind: MANAGED_AUDIT_ARTIFACT,
                correlation: 9,
                payload: p.as_bytes().try_into().unwrap(),
                ..Default::default()
            });
        }
        for (event, phase) in [(1, 2), (2, 3), (3, 7), (4, 8), (5, 9), (7, 9), (8, 9)] {
            let public = !matches!(event, 4 | 5);
            let p = ManagedAuditLifecycleV1 {
                operation_kind: 2,
                event,
                instance_id: 7,
                target_generation: 1,
                observed_generation: u64::from(event >= 5),
                artifact_handle: 17,
                action: 1,
                phase,
                flags: u32::from(public) | (u32::from(event < 5) * 2),
                ..Default::default()
            };
            records.push(ManagedAuditRecordV1 {
                kind: MANAGED_AUDIT_OPERATION,
                correlation: if public { 42 } else { 0 },
                payload: p.as_bytes().try_into().unwrap(),
                ..Default::default()
            });
        }
        let p = ManagedAuditCycleV1 {
            cycle_id: 1,
            scheduled_ticks: 10,
            actual_ticks: 10,
            artifact_handle: 17,
            flags: 17,
            decision: 1,
            queue_outcome: 1,
            ..Default::default()
        };
        records.push(ManagedAuditRecordV1 {
            ticks: 10,
            kind: MANAGED_AUDIT_CYCLE,
            correlation: 1,
            payload: p.as_bytes().try_into().unwrap(),
            ..Default::default()
        });
        records
    }

    fn handoff_trace() -> Vec<ManagedAuditRecordV1> {
        let mut records = Vec::new();
        for (i, record) in identity_and_lifecycle().into_iter().enumerate() {
            records.push(record);
            let events: &[u32] = match i {
                8 => &[1, 2, 3, 5, 4, 5],
                9 => &[7],
                _ => &[],
            };
            for &event in events {
                let p = ManagedAuditHandoffV1 {
                    link_kind: MANAGED_AUDIT_HANDOFF_LINK,
                    event,
                    session: 7,
                    command_sequence: 255,
                    wire_correlation: (1 << 40) + 9,
                    generation: u64::from(event == 7),
                    message_kind: if event <= 3 { 3 } else { 4 },
                    flags: if event == 7 { 3 } else { 1 },
                    ..Default::default()
                };
                records.push(ManagedAuditRecordV1 {
                    kind: MANAGED_AUDIT_LINK,
                    correlation: 7,
                    payload: p.as_bytes().try_into().unwrap(),
                    ..Default::default()
                });
            }
        }
        records
    }

    #[test]
    fn handoff_decode_joins_real_wire_identity_and_requires_ordered_receipt() {
        let records = handoff_trace();
        let decoded = decode(export(&records).as_bytes()).unwrap();
        let links: Vec<_> = decoded["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["kind"] == MANAGED_AUDIT_LINK)
            .collect();
        assert_eq!(links.len(), 7);
        assert_eq!(links[0]["decoded"]["public_operation_id"], 42);
        assert_eq!(links[0]["decoded"]["instance_id"], 7);
        assert_eq!(links[0]["decoded"]["session"], 7);
        assert_eq!(links[0]["decoded"]["wire_correlation"], (1u64 << 40) + 9);
        assert_eq!(links[0]["decoded"]["command_sequence"], 255);
        assert_eq!(links[4]["decoded"]["event"], "handoff_reply_accepted");
        assert_eq!(links[4]["decoded"]["peer_reports_safe"], true);
        assert!(links[3]["decoded"]["peer_reports_safe"].is_null());
        assert_eq!(links[6]["decoded"]["event"], "handoff_receipt_committed");
        assert_eq!(links[6]["decoded"]["generation"], 1);
        assert_eq!(links[6]["decoded"]["physical_output_observed"], false);
        assert!(decoded["semantic_gaps"].as_array().unwrap().is_empty());
        assert_eq!(decoded["qualification_evaluated"], false);

        let indices: Vec<_> = records
            .iter()
            .enumerate()
            .filter(|(_, r)| r.kind == MANAGED_AUDIT_LINK)
            .map(|(i, _)| i)
            .collect();
        // Every matched/owned identity must agree with begin; ignored packets
        // retain their own identity and cannot grant eligibility.
        for &slot in &[1, 2, 4, 6] {
            for byte in [8, 12, 16] {
                let mut bad = records.clone();
                bad[indices[slot]].payload[byte] ^= 1;
                assert!(
                    decode(export(&bad).as_bytes()).is_err(),
                    "slot {slot} byte {byte}"
                );
            }
        }
        let mut wrong_ignored = records.clone();
        wrong_ignored[indices[3]].payload[16] ^= 1;
        assert!(decode(export(&wrong_ignored).as_bytes()).is_ok());
        for byte in [24, 32, 40, 44, 48, 52] {
            let mut bad = records.clone();
            bad[indices[6]].payload[byte] ^= 1;
            assert!(
                decode(export(&bad).as_bytes()).is_err(),
                "receipt byte {byte}"
            );
        }
        let mut reordered = records.clone();
        reordered.swap(indices[1], indices[2]);
        assert!(decode(export(&reordered).as_bytes()).is_err());
        let mut repeated = records.clone();
        repeated.insert(indices[4], records[indices[4]]);
        assert!(decode(export(&repeated).as_bytes()).is_err());
        // Missing protocol prerequisites and a missing public/internal mapping
        // are separately visible gaps, never manufactured acceptance proof.
        for (start, end) in [(9, 12), (5, 12)] {
            let mut lines: Vec<Value> = export(&records)
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            lines.splice(
                start + 1..end + 1,
                [json!({"type":"gap", "start":start, "end":end, "count":end-start})],
            );
            let terminal = lines.last_mut().unwrap();
            terminal["records"] = json!(records.len() - (end - start));
            terminal["gaps"] = json!(end - start);
            let raw: String = lines.iter().map(|v| v.to_string() + "\n").collect();
            let decoded = decode(raw.as_bytes()).unwrap();
            assert!(!decoded["semantic_gaps"].as_array().unwrap().is_empty());
            assert_eq!(decoded["qualification_evaluated"], false);
        }
        let mut failed = records.clone();
        let mut p = ManagedAuditHandoffV1::read_from_bytes(&failed[indices[2]].payload).unwrap();
        p.error = 2007;
        failed[indices[2]].payload = p.as_bytes().try_into().unwrap();
        assert!(decode(export(&failed).as_bytes()).is_err());
    }

    #[test]
    fn handoff_reply_can_match_after_admin_cancel_without_authorizing_publication() {
        let original = handoff_trace();
        let mut records = original[..15].to_vec();
        let mut cancelled = ManagedAuditLifecycleV1::read_from_bytes(&records[5].payload).unwrap();
        cancelled.event = MANAGED_AUDIT_CANCELLED;
        cancelled.phase = MANAGED_OPERATION_CLEANUP;
        cancelled.error = i32::from(ECANCELED) as u32;
        cancelled.flags = MANAGED_AUDIT_LIFECYCLE_INHIBITED;
        records.insert(
            13,
            ManagedAuditRecordV1 {
                kind: MANAGED_AUDIT_OPERATION,
                payload: cancelled.as_bytes().try_into().unwrap(),
                ..Default::default()
            },
        );
        // SYS_BPF cancellation updates the slot; the independent link mailbox
        // can still match a peer reply before the next release disarms it.
        let decoded = decode(export(&records).as_bytes()).unwrap();
        assert_eq!(
            decoded["events"][14]["decoded"]["event"],
            "handoff_reply_accepted"
        );
        assert!(decoded["events"][14]["decoded"]["generation"].is_null());
        records.push(original[16]); // A matching wire receipt cannot undo cancel.
        assert!(decode(export(&records).as_bytes()).is_err());
    }

    #[test]
    fn motor_discard_decode_distinguishes_pending_and_framed_custody() {
        let p = ManagedAuditMotorTxV1 {
            link_kind: MANAGED_AUDIT_MOTOR_TX,
            event: MANAGED_AUDIT_MOTOR_PENDING_DISCARDED,
            reason: MANAGED_AUDIT_DISCARD_SUPERSEDED,
            cycle_id: 40,
            artifact_handle: 0,
            flags: MANAGED_AUDIT_MOTOR_HAS_ORIGIN,
            left: 200,
            right: -300,
            ..Default::default()
        };
        let decode_one = |p: ManagedAuditMotorTxV1| {
            decode(
                export(&[ManagedAuditRecordV1 {
                    correlation: 9,
                    kind: MANAGED_AUDIT_LINK,
                    payload: p.as_bytes().try_into().unwrap(),
                    ..Default::default()
                }])
                .as_bytes(),
            )
        };
        let reasons = [
            "superseded",
            "safe_pair",
            "expired",
            "stop",
            "handoff",
            "inhibited",
        ];
        for reason in 1..=6 {
            let result = decode_one(ManagedAuditMotorTxV1 { reason, ..p }).unwrap();
            let d = &result["events"][0]["decoded"];
            assert_eq!(d["event"], "motor_pending_discarded");
            assert_eq!(d["discard_reason"], reasons[reason as usize - 1]);
            assert_eq!(d["pending_pair"], json!([200, -300]));
            assert!(d["framed_pair"].is_null());
            assert!(d["command_sequence"].is_null());
            assert_eq!(d["generation"], 9);
            assert_eq!(d["cycle_id"], 40);
            assert_eq!(d["artifact_handle"], 0);
            assert!(d["sink_acceptance"].is_null());
            assert_eq!(result["semantic_gaps"].as_array().unwrap().len(), 1);
        }
        let frame = ManagedAuditMotorTxV1 {
            event: MANAGED_AUDIT_MOTOR_FRAME_DISCARDED,
            command_sequence: 255,
            reason: 2,
            ..p
        };
        for reason in 2..=5 {
            let result = decode_one(ManagedAuditMotorTxV1 { reason, ..frame }).unwrap();
            let d = &result["events"][0]["decoded"];
            assert_eq!(d["event"], "motor_frame_discarded");
            assert_eq!(d["discard_reason"], reasons[reason as usize - 1]);
            assert_eq!(d["framed_pair"], json!([200, -300]));
            assert!(d["pending_pair"].is_null());
            assert_eq!(d["command_sequence"], 255);
        }
        for bad in [
            ManagedAuditMotorTxV1 { reason: 0, ..p },
            ManagedAuditMotorTxV1 { reason: 7, ..p },
            ManagedAuditMotorTxV1 {
                command_sequence: 1,
                ..p
            },
            ManagedAuditMotorTxV1 {
                flags: 3,
                left: 0,
                right: 0,
                ..p
            },
            ManagedAuditMotorTxV1 { reason: 1, ..frame },
            ManagedAuditMotorTxV1 { reason: 6, ..frame },
            ManagedAuditMotorTxV1 {
                event: MANAGED_AUDIT_MOTOR_FRAMED,
                ..frame
            },
        ] {
            assert!(decode_one(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn motor_tx_decode_preserves_origin_and_never_claims_sink_acceptance() {
        let mut records = identity_and_lifecycle();
        let p = ManagedAuditMotorTxV1 {
            link_kind: MANAGED_AUDIT_MOTOR_TX,
            event: MANAGED_AUDIT_MOTOR_FRAMED,
            cycle_id: 1 << 40,
            queued_at_ns: u64::MAX - 10,
            artifact_handle: 17,
            flags: MANAGED_AUDIT_MOTOR_HAS_ORIGIN | MANAGED_AUDIT_MOTOR_INTERMEDIATE_ZERO,
            command_sequence: 255,
            ..Default::default()
        };
        let record = |p: ManagedAuditMotorTxV1, generation| ManagedAuditRecordV1 {
            ticks: 11,
            correlation: generation,
            kind: MANAGED_AUDIT_LINK,
            payload: p.as_bytes().try_into().unwrap(),
            ..Default::default()
        };
        records.push(record(p, 1 << 41));
        records.push(record(
            ManagedAuditMotorTxV1 {
                event: MANAGED_AUDIT_MOTOR_LOCAL_COMPLETE,
                ..p
            },
            1 << 41,
        ));
        let result = decode(export(&records).as_bytes()).unwrap();
        assert_eq!(
            result["events"][13]["decoded"]["event"],
            "motor_frame_created"
        );
        let complete = &result["events"][14]["decoded"];
        assert_eq!(complete["event"], "motor_frame_local_uart_complete");
        assert_eq!(complete["generation"], 1u64 << 41);
        assert_eq!(complete["cycle_id"], 1u64 << 40);
        assert_eq!(complete["command_sequence"], 255);
        assert_eq!(complete["framed_pair"], json!([0, 0]));
        assert_eq!(complete["intermediate_zero"], true);
        assert_eq!(complete["queued_at_ns"], u64::MAX - 10);
        assert_eq!(complete["identity"]["artifact_handle"], 17);
        assert_eq!(complete["sink_acceptance"], Value::Null);
        assert_eq!(result["qualification_evaluated"], false);
        assert!(result["semantic_gaps"].as_array().unwrap().is_empty());

        // Wire sequence zero is valid. Unknown origin and unknown retained
        // identity remain explicit; neither is inferred from an artifact zero.
        let untagged = ManagedAuditMotorTxV1 {
            cycle_id: 0,
            artifact_handle: 0,
            flags: 0,
            command_sequence: 0,
            ..p
        };
        let decoded = decode(export(&[record(untagged, 0)]).as_bytes()).unwrap();
        assert!(decoded["events"][0]["decoded"]["generation"].is_null());
        assert!(decoded["events"][0]["decoded"]["identity"].is_null());
        assert!(decoded["semantic_gaps"].as_array().unwrap().is_empty());
        let missing = decode(
            export(&[record(
                ManagedAuditMotorTxV1 {
                    artifact_handle: 0,
                    ..p
                },
                1,
            )])
            .as_bytes(),
        )
        .unwrap();
        assert!(missing["events"][0]["decoded"]["identity"].is_null());
        assert_eq!(missing["semantic_gaps"].as_array().unwrap().len(), 1);
        for bad in [
            ManagedAuditMotorTxV1 { event: 0, ..p },
            ManagedAuditMotorTxV1 { event: 3, ..p },
            ManagedAuditMotorTxV1 { flags: 4, ..p },
            ManagedAuditMotorTxV1 { flags: 0, ..p },
            ManagedAuditMotorTxV1 {
                command_sequence: 256,
                ..p
            },
            ManagedAuditMotorTxV1 { left: 1, ..p },
            ManagedAuditMotorTxV1 {
                reserved: [1; 20],
                ..p
            },
        ] {
            assert!(
                decode(export(&[record(bad, 1)]).as_bytes()).is_err(),
                "{bad:?}"
            );
        }
        assert!(decode(export(&[record(p, 0)]).as_bytes()).is_err());
        assert!(decode(export(&[record(untagged, 1)]).as_bytes()).is_err());
    }

    #[test]
    fn offline_identity_and_lifecycle_require_exact_fragments_and_correlated_boundaries() {
        let records = identity_and_lifecycle();
        let decoded = decode(export(&records).as_bytes()).unwrap();
        assert!(decoded["semantic_gaps"].as_array().unwrap().is_empty());
        assert_eq!(
            decoded["events"][4]["decoded"]["identity"]["revision"],
            1u64 << 40
        );
        assert_eq!(decoded["events"][9]["decoded"]["public_operation_id"], 42);
        assert_eq!(decoded["events"][12]["decoded"]["request_known"], true);
        assert_eq!(
            decoded["events"][12]["decoded"]["identity"]["artifact_handle"],
            17
        );
        for (record, byte) in [(2, 0), (4, 63), (1, 52), (9, 8), (9, 48)] {
            let mut bad = records.clone();
            bad[record].payload[byte] ^= 1;
            assert!(
                decode(export(&bad).as_bytes()).is_err(),
                "record {record} byte {byte}"
            );
        }
        assert!(decode(export(&records[..4]).as_bytes()).is_err());
        let mut reordered = records.clone();
        reordered.swap(2, 3);
        assert!(decode(export(&reordered).as_bytes()).is_err());
        let mut missing_handoff = records.clone();
        missing_handoff.remove(8);
        assert!(decode(export(&missing_handoff).as_bytes()).is_err());
        let cycle = *records.last().unwrap();
        let unresolved = decode(export(&[cycle]).as_bytes()).unwrap();
        assert_eq!(unresolved["semantic_gaps"].as_array().unwrap().len(), 1);
        assert!(unresolved["events"][0]["decoded"]["identity"].is_null());
    }

    #[test]
    fn offline_overwrite_gap_does_not_invent_handoff_or_publication_proof() {
        let raw = export(&identity_and_lifecycle());
        let mut lines: Vec<Value> = raw
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        lines[9] = json!({"type":"gap","start":8,"end":9,"count":1});
        let end = lines.last_mut().unwrap();
        end["records"] = json!(12);
        end["gaps"] = json!(1);
        let raw: String = lines.iter().map(|v| v.to_string() + "\n").collect();
        let decoded = decode(raw.as_bytes()).unwrap();
        assert!(!decoded["semantic_gaps"].as_array().unwrap().is_empty());
        assert_eq!(decoded["qualification_evaluated"], false);
    }

    #[test]
    fn offline_link_faults_keep_operation_distinct_from_generation() {
        for (reason, detail, name) in [
            (1, 15, "uart_receive"),
            (2, 3, "decoder"),
            (3, 2, "rx_overflow"),
            (4, 0, "peer_estop"),
            (5, 0, "pi_inbound_timeout"),
            (6, 2007, "handoff"),
            (7, 0, "link_unavailable"),
        ] {
            let p = ManagedAuditStopV1 {
                category: 5,
                source: 7,
                reason,
                detail,
                flags: 4,
                ..Default::default()
            };
            let mut records = identity_and_lifecycle();
            // The fixture's installation uses internal ID 7, public ID 42.
            let r = ManagedAuditRecordV1 {
                ticks: 50,
                kind: MANAGED_AUDIT_STOP,
                correlation: 7,
                payload: p.as_bytes().try_into().unwrap(),
                ..Default::default()
            };
            records.push(r);
            let decoded = decode(export(&records).as_bytes()).unwrap();
            let last = decoded["events"].as_array().unwrap().last().unwrap();
            assert_eq!(last["decoded"]["event"], "link_fault_stop_requested");
            assert_eq!(last["decoded"]["failure"], name);
            assert_eq!(last["decoded"]["instance_id"], 7);
            assert_eq!(last["decoded"]["public_operation_id"], 42);
            assert!(last["decoded"]["generation"].is_null());
            assert_eq!(last["decoded"]["physical_output_observed"], false);
            let mut lines: Vec<Value> = export(&records)
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            lines[0]["flags"] = json!(
                MANAGED_AUDIT_CLOCK_READY | MANAGED_AUDIT_HAS_STOP | MANAGED_AUDIT_STOP_RECORDED
            );
            lines[0]["latest_stop"] = record_json(&ManagedAuditRecordV1 {
                sequence: records.len() as u64 - 1,
                ..r
            });
            let text: String = lines
                .into_iter()
                .map(|line| line.to_string() + "\n")
                .collect();
            let decoded = decode(text.as_bytes()).unwrap();
            assert_eq!(decoded["latest_stop_decoded"]["failure"], name);
            assert_eq!(decoded["latest_stop_decoded"]["instance_id"], 7);
            for (offset, value) in [(28, 1u32), (32, 0), (36, 2), (48, 1)] {
                let mut bad = records.clone();
                bad.last_mut().unwrap().payload[offset..offset + 4]
                    .copy_from_slice(&value.to_le_bytes());
                assert!(decode(export(&bad).as_bytes()).is_err());
            }
            let mut bad = records.clone();
            bad.last_mut().unwrap().payload[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(decode(export(&bad).as_bytes()).is_err());
        }
        let mut records = handoff_trace();
        let ack = records
            .iter()
            .position(|r| {
                r.kind == MANAGED_AUDIT_LINK
                    && u32::from_le_bytes(r.payload[4..8].try_into().unwrap()) == 4
            })
            .unwrap();
        let p = ManagedAuditStopV1 {
            category: 5,
            source: 7,
            reason: 1,
            detail: 8,
            flags: 4,
            ..Default::default()
        };
        let fault = ManagedAuditRecordV1 {
            kind: MANAGED_AUDIT_STOP,
            correlation: 7,
            payload: p.as_bytes().try_into().unwrap(),
            ..Default::default()
        };
        records.insert(ack, fault);
        // A matched ack cannot revive eligibility invalidated by a link fault.
        assert!(decode(export(&records).as_bytes()).is_err());
        records.truncate(ack + 1);
        assert!(decode(export(&records).as_bytes()).is_ok());
        // Even without any handoff LINK observations, the lifecycle commit
        // itself must reject a known fault; a missing receipt cannot hide it.
        let mut lifecycle_only = identity_and_lifecycle();
        lifecycle_only.insert(9, fault);
        assert!(decode(export(&lifecycle_only).as_bytes()).is_err());
        let mut uncorrelated = fault;
        uncorrelated.correlation = 0;
        uncorrelated.payload[28..32].copy_from_slice(&0u32.to_le_bytes());
        let decoded = decode(export(&[uncorrelated]).as_bytes()).unwrap();
        assert!(decoded["events"][0]["decoded"]["instance_id"].is_null());
    }

    #[test]
    fn offline_retained_identity_and_exhausted_latest_stop_are_independent_of_window() {
        let records = identity_and_lifecycle();
        let decoded = decode(export(&records).as_bytes()).unwrap();
        let mut artifact = decoded["events"][4]["decoded"]["identity"].clone();
        artifact["roles"] = json!(1);
        artifact["slot_generation"] = json!(1);
        artifact["slot_last_id"] = json!(42);
        let mut lines: Vec<Value> = export(&records)
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        lines[0]["artifacts"] = json!([artifact]);
        lines[0]["slot_generation"] = json!(1);
        lines[0]["slot_last_id"] = json!(42);
        let encoded =
            |lines: &[Value]| -> String { lines.iter().map(|v| v.to_string() + "\n").collect() };
        assert!(decode(encoded(&lines).as_bytes()).is_ok());
        lines[0]["artifacts"][0]["bundle_digest"] = json!("aa".repeat(32));
        assert!(decode(encoded(&lines).as_bytes()).is_err());
        lines[0]["artifacts"][0]["bundle_digest"] = json!("09".repeat(32));
        let p = ManagedAuditStopV1 {
            cycle_id: 1,
            deadline_ticks: 20,
            artifact_handle: 17,
            flags: 3,
            category: 2,
            source: 7,
            reason: 5,
            ..Default::default()
        };
        let r = ManagedAuditRecordV1 {
            ticks: 20,
            kind: MANAGED_AUDIT_STOP,
            correlation: 1,
            payload: p.as_bytes().try_into().unwrap(),
            ..Default::default()
        };
        let mut latest = record_json(&r);
        latest["sequence"] = Value::Null;
        let mut header = lines[0].clone();
        let oldest = u64::MAX - MANAGED_AUDIT_RECORDS as u64;
        header["flags"] = json!(25);
        header["end"] = json!(u64::MAX);
        header["oldest"] = json!(oldest);
        header["overwritten"] = json!(oldest);
        header["dropped"] = json!(1);
        header["latest_stop"] = latest;
        let raw = encoded(&[
            header,
            json!({"type":"gap","start":oldest,"end":u64::MAX,"count":2048}),
            json!({"type":"end","cursor":u64::MAX,"records":0,"gaps":2048}),
        ]);
        let decoded = decode(raw.as_bytes()).unwrap();
        assert_eq!(
            decoded["latest_stop_decoded"]["identity"]["artifact_handle"],
            17
        );
        assert_eq!(decoded["latest_stop_decoded"]["event"], "cycle_fault");
    }

    #[test]
    fn offline_payload_validation_rejects_unknown_flags_faults_and_link_subtypes() {
        let cycle = *identity_and_lifecycle().last().unwrap();
        for (offset, value) in [(39, 0x80), (48, 4), (52, 6), (56, 255), (60, 1)] {
            let mut bad = cycle;
            bad.payload[offset] = value;
            assert!(decode(export(&[bad]).as_bytes()).is_err());
        }
        let mut clock = ManagedAuditRecordV1 {
            kind: MANAGED_AUDIT_LINK,
            ..Default::default()
        };
        clock.payload[..4].copy_from_slice(&1u32.to_le_bytes());
        clock.payload[8..16].copy_from_slice(&1000u64.to_le_bytes());
        assert!(decode(export(&[clock]).as_bytes()).is_ok());
        for offset in [4, 16, 63] {
            let mut bad = clock;
            bad.payload[offset] = 1;
            assert!(decode(export(&[bad]).as_bytes()).is_err());
        }
        clock.payload[..4].copy_from_slice(&3u32.to_le_bytes());
        assert!(decode(export(&[clock]).as_bytes()).is_err());
    }

    #[test]
    fn offline_decode_rejects_incomplete_reordered_malformed_and_oversized_data() {
        let stop = ManagedAuditStopV1 {
            category: 1,
            source: 1,
            ..Default::default()
        };
        let record = ManagedAuditRecordV1 {
            ticks: 7,
            kind: MANAGED_AUDIT_STOP,
            payload: stop.as_bytes().try_into().unwrap(),
            ..Default::default()
        };
        let raw = export(&[record]);
        let decoded = decode(raw.as_bytes()).unwrap();
        assert_eq!(decoded["events"][0]["decoded"]["event"], "trusted_stop");
        assert_eq!(decoded["qualification_evaluated"], false);
        assert!(decoded["semantic_gaps"].as_array().unwrap().is_empty());
        let lines: Vec<_> = raw.lines().collect();
        for bad in [
            lines[..2].join("\n") + "\n",
            raw.trim_end().to_owned(),
            format!("{}\n{}\n{}\n", lines[0], lines[2], lines[1]),
            raw.replace("\"sequence\":0", "\"sequence\":1"),
            raw.replace("\"version\":1", "\"version\":2"),
            raw.replace("\"gaps\":0", "\"gaps\":1"),
            raw.replace(
                "\"type\":\"header\"",
                "\"type\":\"header\",\"type\":\"header\"",
            ),
        ] {
            assert!(decode(bad.as_bytes()).is_err());
        }
        let mut invalid = record;
        invalid.payload[48] = 1;
        assert!(decode(export(&[invalid]).as_bytes()).is_err());
        assert!(decode(vec![b' '; MAX_FILE_BYTES as usize + 1].as_slice()).is_err());
    }
}
