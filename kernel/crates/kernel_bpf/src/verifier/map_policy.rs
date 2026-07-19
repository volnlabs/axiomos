use super::core::{MapPerm, VerifyConfig};
use super::error::{VerifyError, VerifyResult};
use super::helpers::HelperId;
use super::state::{MapWritability, RegState};
use crate::bytecode::registers::Register;

fn map_handle_slot(id: u64, config: &VerifyConfig) -> Option<usize> {
    if config.map_generations.is_empty() {
        return usize::try_from(id).ok();
    }
    let bits = u32::from(config.map_handle_slot_bits);
    if bits == 0 || bits >= u32::BITS || id > u64::from(u32::MAX) {
        return None;
    }
    let id = id as u32;
    let slot = (id & ((1u32 << bits) - 1)) as usize;
    let generation = id >> bits;
    (config.map_generations.get(slot).copied() == Some(generation)).then_some(slot)
}

/// Resolve the accessible size of a map-value pointer returned by lookup.
pub(super) fn map_lookup_value_size(
    map_id_reg: &RegState,
    config: &VerifyConfig,
) -> Result<u32, u64> {
    let table = config.map_value_sizes;
    if table.is_empty() {
        return Ok(config.map_value_size);
    }
    match map_id_reg.scalar_value.and_then(|scalar| scalar.value) {
        Some(id) => {
            let index = map_handle_slot(id, config).ok_or(id)?;
            if matches!(
                config.map_perms.get(index),
                Some(MapPerm::Unavailable | MapPerm::WriteOnly)
            ) {
                return Err(id);
            }
            table.get(index).copied().ok_or(id)
        }
        None => {
            if !config.map_generations.is_empty()
                || config
                    .map_perms
                    .iter()
                    .any(|perm| matches!(perm, MapPerm::Unavailable | MapPerm::WriteOnly))
            {
                return Err(u64::MAX);
            }
            Ok(table.iter().copied().min().unwrap_or(0))
        }
    }
}

pub(super) fn map_lookup_writability(
    map_id_reg: &RegState,
    config: &VerifyConfig,
) -> MapWritability {
    let known_id = map_id_reg
        .scalar_value
        .and_then(|scalar| scalar.value)
        .and_then(|id| u32::try_from(id).ok());

    if config.map_perms.is_empty() {
        return MapWritability::ReadWrite(known_id);
    }

    let Some(id) = known_id else {
        return MapWritability::Unprovable;
    };
    let Some(perm) =
        map_handle_slot(u64::from(id), config).and_then(|slot| config.map_perms.get(slot))
    else {
        return MapWritability::Unprovable;
    };

    match perm {
        MapPerm::Unavailable => MapWritability::Unprovable,
        MapPerm::ReadOnly => MapWritability::ReadOnly(id),
        MapPerm::WriteOnly | MapPerm::ReadWrite => MapWritability::ReadWrite(Some(id)),
    }
}

pub(super) fn check_map_write_writability(
    writability: MapWritability,
    insn_idx: usize,
) -> VerifyResult<()> {
    match writability {
        MapWritability::ReadWrite(_) => Ok(()),
        MapWritability::ReadOnly(map_id) => {
            Err(VerifyError::WriteToReadOnlyMap { insn_idx, map_id })
        }
        MapWritability::Unprovable => Err(VerifyError::WriteMapNotProvablyWritable { insn_idx }),
    }
}

pub(super) fn mutating_helper_map_arg(helper: HelperId) -> Option<Register> {
    match helper {
        HelperId::MapUpdateElem
        | HelperId::MapDeleteElem
        | HelperId::RingbufOutput
        | HelperId::TimeseriesPush => Some(Register::R1),
        _ => None,
    }
}

pub(super) fn referenced_map_helper_arg(helper: HelperId) -> Option<Register> {
    match helper {
        HelperId::MapLookupElem
        | HelperId::MapUpdateElem
        | HelperId::MapDeleteElem
        | HelperId::RingbufOutput
        | HelperId::TimeseriesPush => Some(Register::R1),
        _ => None,
    }
}
