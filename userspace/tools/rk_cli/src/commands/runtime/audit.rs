//! Bounded audit transport and envelope export. Payload interpretation is separate.
pub(super) mod decode;
use std::io::{Read, Write};
use std::mem::size_of;

use anyhow::{anyhow, ensure, Result};
use kernel_abi::*;
use serde_json::{json, Value};
use zerocopy::{FromBytes, IntoBytes};

use super::{hex, Client};

impl<T: Read + Write> Client<T> {
    pub(super) fn slot_artifact(
        &mut self,
        slot: &ManagedSlotV1,
        handle: u32,
    ) -> Result<ManagedSlotArtifactV2> {
        let roles = slot.artifact_roles(handle);
        ensure!(roles != 0, "artifact is not retained in this slot snapshot");
        let request = ManagedSlotArtifactV2 {
            version: MANAGED_SLOT_ARTIFACT_VERSION,
            size: size_of::<ManagedSlotArtifactV2>() as u32,
            expected_generation: slot.generation,
            expected_last_id: slot.last_id,
            artifact_handle: handle,
            expected_roles: roles,
            ..Default::default()
        };
        let (result, bytes) = self.request(BPF_MANAGED_SLOT_QUERY as u16, request.as_bytes())?;
        ensure!(result == 0, "invalid artifact query return");
        let reply = ManagedSlotArtifactV2::read_from_bytes(&bytes)
            .map_err(|_| anyhow!("invalid artifact query size"))?;
        validate_artifact(&request, &reply)?;
        Ok(reply)
    }

    fn retained_artifacts(&mut self, slot: &ManagedSlotV1) -> Result<Vec<ManagedSlotArtifactV2>> {
        let mut artifacts: Vec<ManagedSlotArtifactV2> = Vec::with_capacity(3);
        for (handle, flag) in [
            (slot.active_artifact, MANAGED_SLOT_HAS_ACTIVE),
            (slot.previous_artifact, MANAGED_SLOT_HAS_PREVIOUS),
            (slot.candidate_artifact, MANAGED_SLOT_HAS_CANDIDATE),
        ] {
            if slot.flags & flag != 0 && !artifacts.iter().any(|a| a.artifact_handle == handle) {
                artifacts.push(self.slot_artifact(slot, handle)?);
            }
        }
        Ok(artifacts)
    }

    pub(super) fn audit_status(&mut self) -> Result<ManagedAuditStatusV1> {
        let request = ManagedAuditStatusV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedAuditStatusV1>() as u32,
            ..Default::default()
        };
        let (result, bytes) =
            self.request(BPF_MANAGED_RECORDER_STATUS as u16, request.as_bytes())?;
        ensure!(result == 0, "invalid recorder status return");
        let status = ManagedAuditStatusV1::read_from_bytes(&bytes)
            .map_err(|_| anyhow!("invalid recorder status size"))?;
        ensure!(
            status.version == request.version
                && status.size == request.size
                && status.reserved == 0
                && status.flags & !63 == 0
                && status.capacity as usize == MANAGED_AUDIT_RECORDS
                && status.record_bytes as usize == size_of::<ManagedAuditRecordV1>(),
            "invalid recorder status header"
        );
        ensure!(
            status.oldest == status.next.saturating_sub(u64::from(status.capacity))
                && status.overwritten == status.oldest,
            "invalid retained audit interval"
        );
        ensure!(
            (status.flags & MANAGED_AUDIT_CLOCK_READY != 0) == (status.clock_frequency != 0)
                && (status.flags & MANAGED_AUDIT_SESSION_ESTABLISHED != 0) == (status.session != 0)
                && (status.flags & MANAGED_AUDIT_SEQUENCE_EXHAUSTED != 0)
                    == (status.next == u64::MAX),
            "inconsistent recorder clock, session or exhaustion status"
        );
        if status.flags & MANAGED_AUDIT_HAS_STOP != 0 {
            valid_record(&status.latest_stop)?;
            ensure!(
                status.latest_stop.kind == MANAGED_AUDIT_STOP,
                "invalid latest-stop kind"
            );
            if status.flags & MANAGED_AUDIT_STOP_RECORDED != 0 {
                ensure!(
                    status.latest_stop.sequence < status.next,
                    "invalid latest-stop sequence"
                );
            } else {
                ensure!(
                    status.latest_stop.sequence == 0,
                    "unrecorded stop has a sequence"
                );
            }
        } else {
            ensure!(
                status.flags & MANAGED_AUDIT_STOP_RECORDED == 0
                    && status.latest_stop == ManagedAuditRecordV1::EMPTY,
                "unexpected latest-stop data"
            );
        }
        Ok(status)
    }

    pub(super) fn audit_read(
        &mut self,
        cursor: u64,
        end: u64,
        session: u64,
    ) -> Result<ManagedAuditReadV1> {
        let request = ManagedAuditReadV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedAuditReadV1>() as u32,
            cursor,
            end,
            expected_session: session,
            ..Default::default()
        };
        let (result, bytes) = self.request(BPF_MANAGED_RECORDER_READ as u16, request.as_bytes())?;
        ensure!(result == 0, "invalid recorder read return");
        let reply = ManagedAuditReadV1::read_from_bytes(&bytes)
            .map_err(|_| anyhow!("invalid recorder read size"))?;
        validate_read(&request, &reply)?;
        Ok(reply)
    }

    pub(super) fn export_audit(&mut self, out: &mut impl Write) -> Result<()> {
        let status = self.audit_status()?;
        ensure!(
            status.flags & MANAGED_AUDIT_CLOCK_READY != 0,
            "recorder clock is not initialized"
        );
        let slot = self.slot()?;
        let artifacts = self.retained_artifacts(&slot)?;
        let mut header = status_json(&status);
        header["slot_generation"] = json!(slot.generation);
        header["slot_last_id"] = json!(slot.last_id);
        header["artifacts"] = Value::Array(artifacts.iter().map(artifact_json).collect());
        line(out, &header)?;
        let mut cursor = status.oldest;
        let mut records = 0u64;
        let mut gaps = 0u64;
        let mut last_tick = None;
        while cursor < status.next {
            let batch = self.audit_read(cursor, status.next, status.session)?;
            if batch.gap != 0 {
                line(
                    out,
                    &json!({"type":"gap", "start":cursor,
                    "end":cursor + batch.gap, "count":batch.gap}),
                )?;
                gaps += batch.gap;
            }
            for record in &batch.records[..batch.count as usize] {
                ensure!(
                    last_tick.is_none_or(|last| record.ticks >= last),
                    "audit timestamp reversed; export is incomplete"
                );
                last_tick = Some(record.ticks);
                line(out, &record_json(record))?;
                records += 1;
            }
            cursor = batch.next_cursor;
        }
        // A truncated file has no end marker; neither skipped records nor an
        // interrupted serial exchange can become a complete-looking export.
        line(
            out,
            &json!({"type":"end", "cursor":cursor, "records":records, "gaps":gaps}),
        )?;
        out.flush()?;
        Ok(())
    }
}

fn validate_artifact(request: &ManagedSlotArtifactV2, reply: &ManagedSlotArtifactV2) -> Result<()> {
    ensure!(
        reply.version == request.version
            && reply.size == request.size
            && reply.expected_generation == request.expected_generation
            && reply.expected_last_id == request.expected_last_id
            && reply.artifact_handle == request.artifact_handle
            && reply.expected_roles == request.expected_roles
            && reply.reserved == 0,
        "artifact query identity mismatch"
    );
    use kernel_bpf::signing::{managed, ProgramHash};
    ensure!(
        reply.helper_version == u32::from(managed::HELPER_VERSION)
            && reply.context_version == u32::from(managed::CONTEXT_VERSION)
            && reply.effective_effects & !managed::EFFECT_MOTOR_PAIR == 0
            && reply.envelope <= 1,
        "unsupported artifact binding contract"
    );
    ensure!(
        (reply.private_value_size == 0 && reply.private_max_entries == 0)
            || (managed::PrivateArray {
                value_size: reply.private_value_size,
                max_entries: reply.private_max_entries
            })
            .payload_bytes()
            .is_ok(),
        "invalid artifact private-array declaration"
    );
    ensure!(
        ProgramHash::compute(&reply.signer_public_key).as_bytes() == &reply.signer_fingerprint,
        "artifact signer fingerprint mismatch"
    );
    Ok(())
}

pub(super) fn artifact_json(artifact: &ManagedSlotArtifactV2) -> Value {
    json!({"artifact_handle":artifact.artifact_handle,"roles":artifact.expected_roles,
        "slot_generation":artifact.expected_generation,"slot_last_id":artifact.expected_last_id,
        "behavior_id":hex(&artifact.behavior_id),"revision":artifact.revision,
        "bundle_digest":hex(&artifact.bundle_digest),"payload_digest":hex(&artifact.payload_digest),
        "signer_fingerprint":hex(&artifact.signer_fingerprint),"signer_public_key":hex(&artifact.signer_public_key),
        "helper_version":artifact.helper_version,"context_version":artifact.context_version,
        "effective_effects":artifact.effective_effects,"envelope":artifact.envelope != 0,
        "private_array":(artifact.private_value_size != 0).then(|| json!({
            "value_size":artifact.private_value_size,"max_entries":artifact.private_max_entries})),
        "modeled_wcet_cycles":artifact.wcet_cycles})
}

fn line(out: &mut impl Write, value: &Value) -> Result<()> {
    serde_json::to_writer(&mut *out, value)?;
    out.write_all(b"\n")?;
    Ok(())
}

fn valid_record(record: &ManagedAuditRecordV1) -> Result<()> {
    ensure!(
        record.reserved == 0
            && (MANAGED_AUDIT_ARTIFACT..=MANAGED_AUDIT_LINK).contains(&record.kind),
        "invalid audit record envelope"
    );
    Ok(())
}

fn validate_read(request: &ManagedAuditReadV1, reply: &ManagedAuditReadV1) -> Result<()> {
    ensure!(
        reply.version == request.version
            && reply.size == request.size
            && reply.cursor == request.cursor
            && reply.end == request.end
            && reply.expected_session == request.expected_session,
        "audit read identity mismatch"
    );
    ensure!(
        reply.count as usize <= MANAGED_AUDIT_READ_RECORDS
            && reply.next_cursor <= request.end
            && reply.flags
                == if reply.gap != 0 {
                    MANAGED_AUDIT_READ_GAP
                } else {
                    0
                },
        "invalid audit read bounds or flags"
    );
    let start = request
        .cursor
        .checked_add(reply.gap)
        .ok_or_else(|| anyhow!("audit gap overflow"))?;
    ensure!(
        start.checked_add(u64::from(reply.count)) == Some(reply.next_cursor),
        "unaccounted audit cursor movement"
    );
    ensure!(
        request.cursor == request.end || reply.next_cursor > request.cursor,
        "audit export made no progress"
    );
    for (index, record) in reply.records[..reply.count as usize].iter().enumerate() {
        valid_record(record)?;
        ensure!(
            record.sequence == start + index as u64,
            "missing or reordered audit record"
        );
    }
    ensure!(
        reply.records[reply.count as usize..]
            .iter()
            .all(|r| *r == ManagedAuditRecordV1::EMPTY),
        "nonzero unused audit records"
    );
    Ok(())
}

fn record_json(record: &ManagedAuditRecordV1) -> Value {
    json!({"type":"record", "sequence":record.sequence, "ticks":record.ticks,
        "correlation":record.correlation, "kind":record.kind,
        "payload_hex":hex(&record.payload)})
}

pub(super) fn status_json(status: &ManagedAuditStatusV1) -> Value {
    let latest = (status.flags & MANAGED_AUDIT_HAS_STOP != 0).then(|| {
        let mut record = record_json(&status.latest_stop);
        record["sequence"] = if status.flags & MANAGED_AUDIT_STOP_RECORDED != 0 {
            json!(status.latest_stop.sequence)
        } else {
            Value::Null
        };
        record
    });
    json!({"type":"header", "format":"axiomos-managed-audit", "version":1,
        "clock_frequency":status.clock_frequency, "session":status.session,
        "session_established":status.flags & MANAGED_AUDIT_SESSION_ESTABLISHED != 0,
        "persistent_boot_identity":false, "oldest":status.oldest, "end":status.next,
        "overwritten":status.overwritten, "dropped":status.dropped,
        "suppressed":status.suppressed, "flags":status.flags,
        "capacity":status.capacity, "record_bytes":status.record_bytes,
        "latest_stop":latest, "payloads_decoded":false})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_context_rejects_stale_identity_bad_bindings_and_fingerprint() {
        let request = ManagedSlotArtifactV2 {
            version: MANAGED_SLOT_ARTIFACT_VERSION,
            size: size_of::<ManagedSlotArtifactV2>() as u32,
            expected_generation: 1 << 40,
            expected_last_id: 1 << 41,
            expected_roles: MANAGED_SLOT_HAS_ACTIVE,
            ..Default::default()
        };
        let reply = ManagedSlotArtifactV2 {
            helper_version: 1,
            context_version: 1,
            signer_fingerprint: *kernel_bpf::signing::ProgramHash::compute(
                &request.signer_public_key,
            )
            .as_bytes(),
            ..request
        };
        validate_artifact(&request, &reply).unwrap();
        for mutate in [
            |a: &mut ManagedSlotArtifactV2| {
                a.expected_generation += 1;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.expected_last_id += 1;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.artifact_handle += 1;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.expected_roles |= MANAGED_SLOT_HAS_PREVIOUS;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.version = 1;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.size -= 1;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.reserved = 1;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.helper_version += 1;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.context_version += 1;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.effective_effects = u32::MAX;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.envelope = 2;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.private_value_size = 8;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.private_max_entries = 1;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.private_value_size = u32::MAX;
                a.private_max_entries = u32::MAX;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.signer_public_key[31] ^= 1;
            },
            |a: &mut ManagedSlotArtifactV2| {
                a.signer_fingerprint[31] ^= 1;
            },
        ] {
            let mut invalid = reply;
            mutate(&mut invalid);
            assert!(validate_artifact(&request, &invalid).is_err());
        }
    }
    #[test]
    fn malformed_pages_cannot_hide_missing_reordered_or_unused_records() {
        let request = ManagedAuditReadV1 {
            version: MANAGED_ADMIN_VERSION,
            size: size_of::<ManagedAuditReadV1>() as u32,
            cursor: 4,
            end: 8,
            ..Default::default()
        };
        let mut reply = ManagedAuditReadV1 {
            next_cursor: 6,
            count: 2,
            ..request
        };
        for (i, r) in reply.records.iter_mut().enumerate() {
            *r = ManagedAuditRecordV1 {
                sequence: 4 + i as u64,
                kind: MANAGED_AUDIT_CYCLE,
                ..Default::default()
            };
        }
        validate_read(&request, &reply).unwrap();
        for mutate in [
            |r: &mut ManagedAuditReadV1| {
                r.count = 3;
            },
            |r: &mut ManagedAuditReadV1| {
                r.next_cursor = 7;
            },
            |r: &mut ManagedAuditReadV1| {
                r.records.swap(0, 1);
            },
            |r: &mut ManagedAuditReadV1| {
                r.records[0].reserved = 1;
            },
            |r: &mut ManagedAuditReadV1| {
                r.records[0].kind = 99;
            },
            |r: &mut ManagedAuditReadV1| {
                r.expected_session = 1;
            },
            |r: &mut ManagedAuditReadV1| {
                r.flags = 2;
            },
            |r: &mut ManagedAuditReadV1| {
                r.gap = u64::MAX;
            },
            |r: &mut ManagedAuditReadV1| {
                r.count = 1;
                r.next_cursor = 5;
            },
        ] {
            let mut invalid = reply;
            mutate(&mut invalid);
            assert!(validate_read(&request, &invalid).is_err());
        }
    }
}
