//! Fixed managed-controller verification contract. Authentication and admission
//! are separate worker responsibilities; this module proves bytecode/bindings.

use super::budget::BudgetVec;
use super::core::{MapPerm, Verifier, VerifyConfig, VerifyStats};
use super::error::{VerifyError, VerifyResult};
use super::{LoadCaller, VerificationBudget};
use crate::actuation::EnvelopeEntry;
use crate::bytecode::{BpfInsn, BpfProgType, BpfProgram};
use crate::profile::{ActiveProfile, PhysicalProfile};
use crate::signing::managed::{
    ArtifactIdentity, AuthenticatedBundle, EFFECT_MOTOR_PAIR, Manifest, PrivateArray,
};

/// Retained declaration used for both verification and every fresh instance.
/// Administration privilege cannot widen the signed/trusted/slot intersection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedContract {
    envelope: bool,
    private_array: Option<PrivateArray>,
    effects: u32,
}

impl ManagedContract {
    pub fn new(manifest: Manifest, signer_effects: u32, slot_effects: u32) -> VerifyResult<Self> {
        if (manifest.effects | signer_effects | slot_effects) & !EFFECT_MOTOR_PAIR != 0
            || manifest
                .private_array
                .is_some_and(|array| array.payload_bytes().is_err())
        {
            return Err(VerifyError::UnsupportedManagedContract);
        }
        Ok(Self {
            envelope: manifest.envelope,
            private_array: manifest.private_array,
            effects: manifest.effects & signer_effects & slot_effects,
        })
    }

    pub const fn envelope(self) -> bool {
        self.envelope
    }
    pub const fn private_array(self) -> Option<PrivateArray> {
        self.private_array
    }
    pub const fn effects(self) -> u32 {
        self.effects
    }

    pub(super) fn value_sizes(self) -> [u32; 2] {
        [
            if self.envelope {
                core::mem::size_of::<EnvelopeEntry>() as u32
            } else {
                0
            },
            self.private_array.map_or(0, |array| array.value_size),
        ]
    }
}

/// Code verified against one exact managed contract. No public conversion to a
/// legacy program exists: ordinary hook execution and JIT cannot accept it,
/// even when the instruction stream contains no managed helper.
///
/// ```compile_fail
/// use kernel_bpf::{execution::{BpfContext, BpfExecutor, Interpreter}, verifier::ManagedProgram};
/// use kernel_bpf::profile::ActiveProfile;
/// fn ordinary(program: &ManagedProgram<ActiveProfile>) {
///     let _ = Interpreter::<ActiveProfile>::new().execute(program, &BpfContext::empty());
/// }
/// ```
#[derive(Debug)]
pub struct ManagedProgram<P: PhysicalProfile = ActiveProfile> {
    program: BpfProgram<P>,
    contract: ManagedContract,
}

impl<P: PhysicalProfile> ManagedProgram<P> {
    pub const fn contract(&self) -> ManagedContract {
        self.contract
    }
    pub(crate) fn program(&self) -> &BpfProgram<P> {
        &self.program
    }
}

/// Immutable authenticated and verified managed behavior.
///
/// Admission, installation, mutable state and actuation are separate manager
/// responsibilities. `code_bytes` is the code Vec's raw retained capacity;
/// `output_charge` is what the originating allocator-aware budget must release
/// after the artifact is dropped or its ownership transfers.
#[derive(Debug)]
pub struct BehaviorArtifact<P: PhysicalProfile = ActiveProfile> {
    identity: ArtifactIdentity,
    program: ManagedProgram<P>,
    wcet_cycles: u64,
    states_explored: usize,
    code_bytes: usize,
    output_charge: usize,
}

impl<P: PhysicalProfile> BehaviorArtifact<P> {
    pub fn prepare(
        bundle: &AuthenticatedBundle<'_>,
        signer_effects: u32,
        slot_effects: u32,
        budget: &mut VerificationBudget,
    ) -> VerifyResult<Self> {
        let baseline = budget.used();
        let contract = ManagedContract::new(bundle.manifest(), signer_effects, slot_effects)?;
        let mut decoded = BudgetVec::new(Some(&*budget));
        let instructions = bundle.instructions();
        decoded.reserve(instructions.len())?;
        for insn in instructions {
            decoded.push(insn)?;
        }
        let (program, stats) =
            Verifier::<P>::verify_managed_with_stats_bounded(&decoded, contract, budget)?;
        drop(decoded);

        let VerifyStats {
            states_explored,
            wcet_cycles,
            referenced_map_handles,
        } = stats;
        let outputs = budget
            .used()
            .checked_sub(baseline)
            .ok_or(VerifyError::ResourceExhausted)?;
        let Some(handle_bytes) = referenced_map_handles
            .capacity()
            .checked_mul(core::mem::size_of::<u32>())
            .and_then(|bytes| budget.allocation_charge(bytes).ok())
            .filter(|bytes| *bytes <= outputs)
        else {
            drop((program, referenced_map_handles));
            budget.release_output(outputs)?;
            return Err(VerifyError::ResourceExhausted);
        };
        drop(referenced_map_handles);
        if budget.release_output(handle_bytes).is_err() {
            drop(program);
            budget.release_output(outputs)?;
            return Err(VerifyError::ResourceExhausted);
        }
        let output_charge = outputs - handle_bytes;
        let Some(code_bytes) = program
            .program()
            .instructions()
            .len()
            .checked_mul(core::mem::size_of::<BpfInsn>())
        else {
            drop(program);
            budget.release_output(output_charge)?;
            return Err(VerifyError::ResourceExhausted);
        };
        if budget.allocation_charge(code_bytes).ok() != Some(output_charge) {
            drop(program);
            budget.release_output(output_charge)?;
            return Err(VerifyError::ResourceExhausted);
        }

        Ok(Self {
            identity: bundle.identity(),
            program,
            wcet_cycles,
            states_explored,
            code_bytes,
            output_charge,
        })
    }

    pub const fn identity(&self) -> ArtifactIdentity {
        self.identity
    }

    pub const fn contract(&self) -> ManagedContract {
        self.program.contract()
    }

    pub const fn program(&self) -> &ManagedProgram<P> {
        &self.program
    }

    pub const fn wcet_cycles(&self) -> u64 {
        self.wcet_cycles
    }

    pub const fn states_explored(&self) -> usize {
        self.states_explored
    }

    pub const fn code_bytes(&self) -> usize {
        self.code_bytes
    }

    /// Retained code allocation charge in the originating verification budget.
    pub const fn output_charge(&self) -> usize {
        self.output_charge
    }
}

impl<P: PhysicalProfile> Verifier<'_, P> {
    /// Bounded preparation only: retains output charges just like the legacy
    /// bounded entry. No installation, map allocation, admission or publication.
    pub fn verify_managed_with_stats_bounded(
        insns: &[BpfInsn],
        contract: ManagedContract,
        budget: &VerificationBudget,
    ) -> VerifyResult<(ManagedProgram<P>, VerifyStats)> {
        let sizes = contract.value_sizes();
        let perms = [
            if contract.envelope {
                MapPerm::ReadOnly
            } else {
                MapPerm::Unavailable
            },
            if contract.private_array.is_some() {
                MapPerm::ReadWrite
            } else {
                MapPerm::Unavailable
            },
        ];
        let config = VerifyConfig {
            ctx_size: core::mem::size_of::<crate::execution::BpfContext<'_>>() as u32,
            ctx_data_size: core::mem::size_of::<kernel_abi::ManagedControlContextV1>() as u32,
            map_value_sizes: &sizes,
            map_perms: &perms,
            map_generations: &[0, 0],
            map_handle_slot_bits: kernel_abi::BPF_HANDLE_SLOT_BITS,
            caller: LoadCaller::Unprivileged,
            forbid_logging_helpers: true,
            ..VerifyConfig::default()
        };
        let (program, stats) = Verifier::<P>::verify_inner(
            BpfProgType::SocketFilter,
            insns,
            config,
            Some(budget),
            Some(contract),
        )?;
        Ok((ManagedProgram { program, contract }, stats))
    }
}

/// Canonical normalized instructions only: no ELF/pseudo bindings, BPF calls,
/// ignored modes/reserved fields, malformed wide tails or branches into tails.
/// This is a shape check; the existing verifier still proves instruction safety.
pub(super) fn check_normalized(insns: &[BpfInsn]) -> VerifyResult<()> {
    use crate::bytecode::opcode::{AluOp, JmpOp, MemMode, OpcodeClass, SourceType};
    let invalid = |idx: usize| VerifyError::InvalidOpcode {
        insn_idx: idx,
        opcode: insns[idx].opcode,
    };
    let mut idx = 0;
    while idx < insns.len() {
        let insn = &insns[idx];
        let reg_source = insn.source_type() == SourceType::Reg;
        let canonical = if insn.is_wide() {
            let Some(tail) = insns.get(idx + 1) else {
                return Err(invalid(idx));
            };
            if insn.src_reg() != 0
                || insn.offset != 0
                || tail.opcode != 0
                || tail.regs != 0
                || tail.offset != 0
            {
                return Err(invalid(idx));
            }
            idx += 2;
            continue;
        } else if insn.is_call() {
            insn.regs == 0 && insn.offset == 0
        } else if insn.is_exit() {
            insn.regs == 0 && insn.offset == 0 && insn.imm == 0
        } else if insn.is_alu() {
            insn.offset == 0
                && match insn.alu_op() {
                    Some(AluOp::End) => {
                        insn.class() == Some(OpcodeClass::Alu32)
                            && insn.src_reg() == 0
                            && matches!(insn.imm, 16 | 32 | 64)
                    }
                    Some(AluOp::Neg) => !reg_source && insn.src_reg() == 0 && insn.imm == 0,
                    Some(_) => {
                        if reg_source {
                            insn.imm == 0
                        } else {
                            insn.src_reg() == 0
                        }
                    }
                    None => false,
                }
        } else if insn.is_jump() {
            match insn.jmp_op() {
                Some(JmpOp::Call | JmpOp::Exit) | None => false,
                Some(JmpOp::Ja) => {
                    insn.class() == Some(OpcodeClass::Jmp)
                        && !reg_source
                        && insn.regs == 0
                        && insn.imm == 0
                }
                Some(_) => {
                    if reg_source {
                        insn.imm == 0
                    } else {
                        insn.src_reg() == 0
                    }
                }
            }
        } else {
            insn.mem_mode() == Some(MemMode::Mem)
                && match insn.class() {
                    Some(OpcodeClass::Ldx | OpcodeClass::Stx) => insn.imm == 0,
                    Some(OpcodeClass::St) => insn.src_reg() == 0,
                    _ => false,
                }
        };
        if !canonical {
            return Err(invalid(idx));
        }
        if insn.is_jump() && !insn.is_call() && !insn.is_exit() {
            let target = idx as i64 + 1 + i64::from(insn.offset);
            if target > 0 && insns.get(target as usize - 1).is_some_and(BpfInsn::is_wide) {
                return Err(VerifyError::InvalidJump {
                    insn_idx: idx,
                    target: target as i32,
                });
            }
        }
        idx += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use ed25519_dalek::{Signer, SigningKey};

    use super::super::HelperId;
    use super::*;
    use crate::actuation::EnvelopeMap;
    use crate::maps::BpfMap;
    use crate::signing::managed::{HEADER_SIZE, MANIFEST_SIZE, signing_hash};
    use crate::signing::{ProgramHash, SignatureVerifier, TrustedKey};

    fn manifest() -> Manifest {
        Manifest {
            behavior_id: [0; 16],
            revision: 1,
            envelope: true,
            effects: EFFECT_MOTOR_PAIR,
            private_array: Some(PrivateArray {
                value_size: 8,
                max_entries: 4,
            }),
        }
    }
    fn contract() -> ManagedContract {
        ManagedContract::new(manifest(), 1, 1).unwrap()
    }

    fn signed_bundle(manifest: Manifest, insns: &[BpfInsn]) -> (Vec<u8>, SignatureVerifier) {
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(insns.len() * BpfInsn::SIZE)
            .unwrap();
        for insn in insns {
            payload.push(insn.opcode);
            payload.push(insn.regs);
            payload.extend_from_slice(&insn.offset.to_le_bytes());
            payload.extend_from_slice(&insn.imm.to_le_bytes());
        }
        let key = SigningKey::from_bytes(&[91; 32]);
        let public_key = key.verifying_key().to_bytes();
        let mut header = manifest.unsigned_header(&payload, &public_key).unwrap();
        let signature = key.sign(signing_hash(&header).as_bytes()).to_bytes();
        header[MANIFEST_SIZE..HEADER_SIZE].copy_from_slice(&signature);
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&payload);
        let verifier =
            SignatureVerifier::from_trusted_keys(&[TrustedKey::from_bytes(&public_key).unwrap()])
                .unwrap();
        (bytes, verifier)
    }
    fn verify(
        insns: &[BpfInsn],
        contract: ManagedContract,
    ) -> VerifyResult<(ManagedProgram, VerifyStats)> {
        let budget = VerificationBudget::new(512 * 1024);
        let result =
            Verifier::<ActiveProfile>::verify_managed_with_stats_bounded(insns, contract, &budget);
        if result.is_err() {
            assert_eq!(budget.used(), 0, "rejection must refund scratch/output");
        }
        result
    }
    fn lookup(handle: i32) -> Vec<BpfInsn> {
        vec![
            BpfInsn::new(0x62, 10, 0, -4, 0),
            BpfInsn::mov64_imm(1, handle),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -4),
            BpfInsn::call(HelperId::MapLookupElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ]
    }
    fn update() -> Vec<BpfInsn> {
        vec![
            BpfInsn::new(0x7a, 10, 0, -16, 0),
            BpfInsn::new(0x7a, 10, 0, -8, 0),
            BpfInsn::mov64_imm(1, 1),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -4),
            BpfInsn::mov64_reg(3, 10),
            BpfInsn::add64_imm(3, -16),
            BpfInsn::mov64_imm(4, 0),
            BpfInsn::call(HelperId::MapUpdateElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ]
    }

    #[test]
    fn managed_contract_matches_real_envelope_and_checks_private_limits() {
        let map = EnvelopeMap::<ActiveProfile>::init_from_profile();
        assert_eq!(contract().value_sizes()[0], map.def().value_size);
        assert_eq!(map.def().key_size, 4);
        for (value_size, max_entries) in [(0, 1), (1, 0), (16_385, 1), (u32::MAX, u32::MAX)] {
            assert_eq!(
                ManagedContract::new(
                    Manifest {
                        private_array: Some(PrivateArray {
                            value_size,
                            max_entries
                        }),
                        ..manifest()
                    },
                    1,
                    1
                ),
                Err(VerifyError::UnsupportedManagedContract)
            );
        }
        assert!(
            ManagedContract::new(
                Manifest {
                    private_array: Some(PrivateArray {
                        value_size: 16,
                        max_entries: 1024
                    }),
                    ..manifest()
                },
                1,
                1
            )
            .is_ok()
        );
        for (declared, signer, slot) in [(2, 1, 1), (1, 2, 1), (1, 1, 2)] {
            assert_eq!(
                ManagedContract::new(
                    Manifest {
                        effects: declared,
                        ..manifest()
                    },
                    signer,
                    slot
                ),
                Err(VerifyError::UnsupportedManagedContract)
            );
        }
    }

    #[test]
    fn behavior_artifact_preserves_authenticated_identity_contract_and_cost() {
        let insns = update();
        let (bytes, verifier) = signed_bundle(manifest(), &insns);
        let bundle = verifier.authenticate_managed(&bytes).unwrap();
        let identity = bundle.identity();
        let mut budget = VerificationBudget::new(512 * 1024);
        let baseline = budget.used();
        let artifact = BehaviorArtifact::<ActiveProfile>::prepare(&bundle, 1, 1, &mut budget)
            .expect("authenticated managed artifact");

        assert_eq!(artifact.identity(), identity);
        assert_eq!(identity.bundle_digest, ProgramHash::compute(&bytes));
        assert_eq!(artifact.contract(), contract());
        assert_eq!(artifact.program().program().instructions(), insns);
        assert!(artifact.wcet_cycles() > 0);
        assert!(artifact.states_explored() > 0);
        assert_eq!(artifact.code_bytes(), insns.len() * BpfInsn::SIZE);
        assert_eq!(artifact.output_charge(), artifact.code_bytes());
        assert_eq!(budget.used() - baseline, artifact.code_bytes());

        let charge = artifact.code_bytes();
        drop(artifact);
        budget.release_output(charge).unwrap();
        assert_eq!(budget.used(), baseline);
    }

    #[test]
    fn behavior_artifact_retains_code_with_originating_allocator_policy() {
        let insns = lookup(0);
        let (bytes, verifier) = signed_bundle(manifest(), &insns);
        let bundle = verifier.authenticate_managed(&bytes).unwrap();
        let mut budget = VerificationBudget::with_allocator_policy(512 * 1024, 64, 8).unwrap();
        let artifact = BehaviorArtifact::<ActiveProfile>::prepare(&bundle, 1, 1, &mut budget)
            .expect("allocator-aware artifact");

        assert_eq!(artifact.code_bytes(), insns.len() * BpfInsn::SIZE);
        assert_eq!(artifact.output_charge(), 64);
        assert_eq!(budget.used(), artifact.output_charge());
        let charge = artifact.output_charge();
        drop(artifact);
        budget.release_output(charge).unwrap();
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn behavior_artifact_failures_refund_without_touching_existing_output() {
        let good = [BpfInsn::mov64_imm(0, 0), BpfInsn::exit()];
        let (good_bytes, verifier) = signed_bundle(manifest(), &good);
        let good_bundle = verifier.authenticate_managed(&good_bytes).unwrap();
        let mut budget = VerificationBudget::new(512 * 1024);
        let retained =
            BehaviorArtifact::<ActiveProfile>::prepare(&good_bundle, 1, 1, &mut budget).unwrap();
        let existing = budget.used();

        let invalid = [BpfInsn::mov64_imm(0, 0)];
        let (invalid_bytes, invalid_verifier) = signed_bundle(manifest(), &invalid);
        let invalid_bundle = invalid_verifier
            .authenticate_managed(&invalid_bytes)
            .unwrap();
        assert!(
            BehaviorArtifact::<ActiveProfile>::prepare(&invalid_bundle, 1, 1, &mut budget).is_err()
        );
        assert_eq!(budget.used(), existing);

        let mut empty_budget = VerificationBudget::new(0);
        assert!(matches!(
            BehaviorArtifact::<ActiveProfile>::prepare(&good_bundle, 1, 1, &mut empty_budget),
            Err(VerifyError::ResourceExhausted)
        ));
        assert_eq!(empty_budget.used(), 0);

        let charge = retained.code_bytes();
        drop(retained);
        budget.release_output(charge).unwrap();
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn managed_effect_is_intersection_and_capture_is_never_legacy() {
        let insns = [
            BpfInsn::mov64_imm(1, 5),
            BpfInsn::mov64_imm(2, -5),
            BpfInsn::call(HelperId::ManagedMotorPairV1 as i32),
            BpfInsn::exit(),
        ];
        for declared in 0..=1 {
            for signer in 0..=1 {
                for slot in 0..=1 {
                    let c = ManagedContract::new(
                        Manifest {
                            effects: declared,
                            ..manifest()
                        },
                        signer,
                        slot,
                    )
                    .unwrap();
                    assert_eq!(c.effects(), declared & signer & slot);
                    assert_eq!(verify(&insns, c).is_ok(), declared & signer & slot == 1);
                }
            }
        }
        for caller in [
            LoadCaller::Unprivileged,
            LoadCaller::Privileged,
            LoadCaller::Trusted,
        ] {
            assert!(matches!(
                Verifier::<ActiveProfile>::verify_with_config(
                    BpfProgType::SocketFilter,
                    &insns,
                    VerifyConfig {
                        caller,
                        allow_actuation: true,
                        ..VerifyConfig::default()
                    }
                ),
                Err(VerifyError::HelperModeMismatch { .. })
            ));
        }
        for id in 0..=kernel_abi::BPF_HELPER_MANAGED_MOTOR_PAIR_V1 {
            let Some(helper) = HelperId::from_raw(id) else {
                continue;
            };
            if matches!(
                helper,
                HelperId::ManagedMotorPairV1 | HelperId::MapLookupElem | HelperId::MapUpdateElem
            ) {
                continue;
            }
            assert!(
                verify(
                    &[BpfInsn::call(id), BpfInsn::mov64_imm(0, 0), BpfInsn::exit()],
                    contract()
                )
                .is_err(),
                "helper {helper:?}"
            );
        }
    }

    #[test]
    fn managed_local_bindings_reject_absent_dynamic_global_and_stale_handles() {
        for id in [0, 1] {
            let (_, stats) = verify(&lookup(id), contract()).unwrap();
            assert_eq!(stats.referenced_map_handles, [id as u32]);
        }
        for id in [2, 1024, 1025, i32::MAX, -1] {
            assert!(matches!(
                verify(&lookup(id), contract()),
                Err(VerifyError::InvalidMapId { .. })
            ));
        }
        let none = ManagedContract::new(
            Manifest {
                envelope: false,
                private_array: None,
                ..manifest()
            },
            1,
            1,
        )
        .unwrap();
        for id in [0, 1] {
            assert!(verify(&lookup(id), none).is_err());
        }
        let mut dynamic = lookup(1);
        // Load a scalar from frozen payload, rather than a proven local handle.
        dynamic.splice(
            1..2,
            [
                BpfInsn::new(0x79, 6, 1, 0, 0),
                BpfInsn::new(0x79, 1, 6, 8, 0),
            ],
        );
        assert!(matches!(
            verify(&dynamic, contract()),
            Err(VerifyError::InvalidMapId { .. })
        ));
        let mut wide = lookup(1);
        wide.splice(
            1..2,
            [BpfInsn::new(0x18, 1, 0, 0, 1), BpfInsn::new(0, 0, 0, 0, 0)],
        );
        verify(&wide, contract()).unwrap();
        wide[2].imm = 1; // a nonzero upper half cannot truncate to local1
        assert!(matches!(
            verify(&wide, contract()),
            Err(VerifyError::InvalidMapId { .. })
        ));
    }

    #[test]
    fn managed_map_buffers_require_exact_bounds_and_initialized_bytes() {
        verify(&update(), contract()).unwrap();
        let mut bad = lookup(1);
        bad[3].imm = -2;
        assert!(matches!(
            verify(&bad, contract()),
            Err(VerifyError::OutOfBoundsAccess { .. })
        ));
        let mut bad = lookup(1);
        bad[0] = BpfInsn::new(0x72, 10, 0, -4, 0); // initialize one key byte only
        assert!(matches!(
            verify(&bad, contract()),
            Err(VerifyError::InvalidMemoryAccess { .. })
        ));
        let mut bad = update();
        bad[0] = BpfInsn::new(0x62, 10, 0, -16, 0); // four of eight value bytes
        assert!(matches!(
            verify(&bad, contract()),
            Err(VerifyError::InvalidMemoryAccess { .. })
        ));
        let mut bad = update();
        bad[6].imm = -4; // value crosses frame boundary
        assert!(matches!(
            verify(&bad, contract()),
            Err(VerifyError::OutOfBoundsAccess { .. })
        ));
        let bigger = ManagedContract::new(
            Manifest {
                private_array: Some(PrivateArray {
                    value_size: 24,
                    max_entries: 1,
                }),
                ..manifest()
            },
            1,
            1,
        )
        .unwrap();
        assert!(matches!(
            verify(&update(), bigger),
            Err(VerifyError::OutOfBoundsAccess { .. })
        ));
    }

    #[test]
    fn managed_envelope_is_read_only_and_nullable_values_need_refinement() {
        let mut write = update();
        write[2].imm = 0;
        assert!(matches!(
            verify(&write, contract()),
            Err(VerifyError::WriteToReadOnlyMap { .. })
        ));
        let mut direct = lookup(0);
        direct.splice(
            5..5,
            [
                BpfInsn::new(0x15, 0, 0, 1, 0),
                BpfInsn::new(0x62, 0, 0, 0, 0),
            ],
        );
        assert!(matches!(
            verify(&direct, contract()),
            Err(VerifyError::WriteToReadOnlyMap { .. })
        ));
        let mut read = lookup(1);
        read[5] = BpfInsn::new(0x79, 0, 0, 0, 0);
        assert!(matches!(
            verify(&read, contract()),
            Err(VerifyError::InvalidMemoryAccess { .. })
        ));
        read.insert(5, BpfInsn::new(0x15, 0, 0, 1, 0));
        read.insert(7, BpfInsn::mov64_imm(0, 0));
        verify(&read, contract()).unwrap();
        let mut input = lookup(1);
        input.truncate(5);
        input.extend([
            BpfInsn::mov64_reg(3, 0),
            BpfInsn::mov64_imm(1, 1),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -4),
            BpfInsn::mov64_imm(4, 0),
            BpfInsn::call(HelperId::MapUpdateElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ]);
        assert!(matches!(
            verify(&input, contract()),
            Err(VerifyError::InvalidMemoryAccess { .. })
        ));
    }

    #[test]
    fn managed_payload_is_exact_and_state_cannot_capture_addresses() {
        // END's source bit selects byte order; it does not read R0, which
        // deliberately holds a payload pointer here.
        verify(
            &[
                BpfInsn::new(0x79, 0, 1, 0, 0),
                BpfInsn::mov64_imm(2, 42),
                BpfInsn::new(0xdc, 2, 0, 0, 64),
                BpfInsn::mov64_reg(0, 2),
                BpfInsn::exit(),
            ],
            contract(),
        )
        .unwrap();
        let ctx_size = core::mem::size_of::<kernel_abi::ManagedControlContextV1>();
        let mut read = [
            BpfInsn::new(0x79, 2, 1, 0, 0),
            BpfInsn::new(0x79, 0, 2, (ctx_size - 8) as i16, 0),
            BpfInsn::exit(),
        ];
        verify(&read, contract()).unwrap();
        read[1].offset += 1;
        assert!(matches!(
            verify(&read, contract()),
            Err(VerifyError::OutOfBoundsAccess { .. })
        ));
        for insns in [
            vec![BpfInsn::new(0x61, 0, 1, 0, 0), BpfInsn::exit()], // partial wrapper address
            vec![
                BpfInsn::mov64_reg(0, 10),
                BpfInsn::and64_imm(0, -1),
                BpfInsn::exit(),
            ],
            vec![
                BpfInsn::new(0x7b, 10, 1, -8, 0),
                BpfInsn::mov64_imm(0, 0),
                BpfInsn::exit(),
            ],
            vec![BpfInsn::new(0x79, 0, 10, -8, 0), BpfInsn::exit()],
        ] {
            assert!(matches!(
                verify(&insns, contract()),
                Err(VerifyError::InvalidMemoryAccess { .. })
            ));
        }
    }

    #[test]
    fn managed_normalized_shape_and_loop_gate_apply_in_both_profiles() {
        for insns in [
            vec![
                BpfInsn::new(0x18, 0, 1, 0, 0),
                BpfInsn::new(0, 0, 0, 0, 0),
                BpfInsn::exit(),
            ],
            vec![
                BpfInsn::new(0x18, 0, 0, 0, 0),
                BpfInsn::mov64_imm(0, 0),
                BpfInsn::exit(),
            ],
            vec![
                BpfInsn::new(0x85, 0, 1, 0, HelperId::ManagedMotorPairV1 as i32),
                BpfInsn::exit(),
            ],
            vec![BpfInsn::new(0xdb, 10, 0, -8, 0), BpfInsn::exit()], // unsupported atomic mode
            vec![
                BpfInsn::new(0x05, 0, 0, 1, 0),
                BpfInsn::new(0x18, 0, 0, 0, 0),
                BpfInsn::new(0, 0, 0, 0, 0),
                BpfInsn::exit(),
            ],
        ] {
            assert!(verify(&insns, contract()).is_err());
        }
        assert!(matches!(
            verify(
                &[
                    BpfInsn::mov64_imm(0, 0),
                    BpfInsn::new(0x55, 0, 0, -1, 0),
                    BpfInsn::exit()
                ],
                contract()
            ),
            Err(VerifyError::UnboundedLoop { .. })
        ));
        let budget = VerificationBudget::new(0);
        assert!(matches!(
            Verifier::<ActiveProfile>::verify_managed_with_stats_bounded(
                &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()],
                contract(),
                &budget
            ),
            Err(VerifyError::ResourceExhausted)
        ));
        assert_eq!(budget.used(), 0);
    }
}
