use alloc::string::String;
use alloc::vec::Vec;

use kernel_bpf::execution::BpfError;
use kernel_bpf::verifier::LoadCaller;

pub(super) const MAX_MAP_GRANTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapAccess(u8);

impl MapAccess {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const READ_WRITE: Self = Self(Self::READ.0 | Self::WRITE.0);

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub(super) const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Immutable authority snapshot captured before entering the BPF manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfLoadAuthorization {
    pub(super) caller: LoadCaller,
    pub(super) allow_actuation: bool,
    pub(super) map_access: MapAccess,
}

impl BpfLoadAuthorization {
    pub const fn new(caller: LoadCaller, allow_actuation: bool, map_access: MapAccess) -> Self {
        Self {
            caller,
            allow_actuation,
            map_access,
        }
    }

    pub(super) const fn kernel() -> Self {
        Self::new(LoadCaller::Trusted, true, MapAccess::READ_WRITE)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MapGrant {
    owner: u64,
    access: MapAccess,
}

pub(super) struct MapGrants {
    entries: Vec<MapGrant>,
}

impl MapGrants {
    pub(super) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(super) fn access_for(&self, owner: u64) -> Option<MapAccess> {
        self.entries
            .iter()
            .find(|grant| grant.owner == owner)
            .map(|grant| grant.access)
    }

    pub(super) fn grant(&mut self, owner: u64, access: MapAccess) -> Result<(), BpfError> {
        if let Some(grant) = self.entries.iter_mut().find(|grant| grant.owner == owner) {
            grant.access = grant.access.union(access);
            return Ok(());
        }
        if self.entries.len() >= MAX_MAP_GRANTS {
            return Err(BpfError::ResourceLimit);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| BpfError::OutOfMemory)?;
        self.entries.push(MapGrant { owner, access });
        Ok(())
    }

    pub(super) fn revoke_owner(&mut self, owner: u64) {
        self.entries.retain(|grant| grant.owner != owner);
    }
}

pub(super) struct PinnedMap {
    pub(super) path: String,
    pub(super) map_id: u32,
    pub(super) owner: u64,
    pub(super) offered: MapAccess,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_accumulate_without_losing_existing_authority() {
        let mut grants = MapGrants::new();
        grants.grant(7, MapAccess::READ).unwrap();
        grants.grant(7, MapAccess::WRITE).unwrap();

        assert_eq!(grants.access_for(7), Some(MapAccess::READ_WRITE));
    }

    #[test]
    fn revocation_only_removes_the_named_owner() {
        let mut grants = MapGrants::new();
        grants.grant(7, MapAccess::READ).unwrap();
        grants.grant(8, MapAccess::WRITE).unwrap();

        grants.revoke_owner(7);

        assert_eq!(grants.access_for(7), None);
        assert_eq!(grants.access_for(8), Some(MapAccess::WRITE));
    }

    #[test]
    fn grant_table_rejects_entries_beyond_the_fixed_bound() {
        let mut grants = MapGrants::new();
        for owner in 0..MAX_MAP_GRANTS as u64 {
            grants.grant(owner, MapAccess::READ).unwrap();
        }

        assert_eq!(
            grants.grant(MAX_MAP_GRANTS as u64, MapAccess::READ),
            Err(BpfError::ResourceLimit)
        );
    }
}
