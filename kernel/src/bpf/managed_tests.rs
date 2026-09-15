extern crate std;

use ed25519_dalek::{Signer, SigningKey};
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::signing::managed::*;
use kernel_bpf::signing::{SignatureVerifier, TrustedKey};
use kernel_bpf::verifier::{BehaviorArtifact, VerificationBudget};
use zerocopy::IntoBytes;

use super::*;
use crate::bpf::{BpfManager, BPF_MAP_TYPE_ARRAY};

pub(in crate::bpf) fn artifact(revision: u64) -> BehaviorArtifact {
    artifact_with_state(
        revision,
        Some(PrivateArray {
            value_size: 8,
            max_entries: 4,
        }),
    )
}

pub(in crate::bpf) fn artifact_with_state(
    revision: u64,
    private_array: Option<PrivateArray>,
) -> BehaviorArtifact {
    artifact_from_program(
        revision,
        true,
        0,
        private_array,
        &[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()],
    )
}

pub(in crate::bpf) fn artifact_from_program(
    revision: u64,
    envelope: bool,
    effects: u32,
    private_array: Option<PrivateArray>,
    program: &[BpfInsn],
) -> BehaviorArtifact {
    artifact_and_budget_from_program(revision, envelope, effects, private_array, program).0
}

fn artifact_and_budget_from_program(
    revision: u64,
    envelope: bool,
    effects: u32,
    private_array: Option<PrivateArray>,
    program: &[BpfInsn],
) -> (BehaviorArtifact, VerificationBudget) {
    let key = SigningKey::from_bytes(&[19; 32]);
    let manifest = Manifest {
        behavior_id: [7; 16],
        revision,
        envelope,
        effects,
        private_array,
    };
    let payload = program.as_bytes();
    let mut header = manifest
        .unsigned_header(&payload, key.verifying_key().as_bytes())
        .unwrap();
    let signature = key.sign(signing_hash(&header).as_bytes());
    header[MANIFEST_SIZE..].copy_from_slice(&signature.to_bytes());
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(payload);
    let trust = SignatureVerifier::from_trusted_keys(&[TrustedKey::from_bytes(
        key.verifying_key().as_bytes(),
    )
    .unwrap()])
    .unwrap();
    let bundle = trust.authenticate_managed(&bytes).unwrap();
    let mut budget = VerificationBudget::new(512 * 1024);
    let artifact = BehaviorArtifact::prepare(&bundle, effects, effects, &mut budget).unwrap();
    (artifact, budget)
}

#[test]
fn managed_maximum_private_array_and_stateless_shapes_have_exact_ownership() {
    for (revision, private_array, expects_map) in [
        (
            1,
            Some(PrivateArray {
                value_size: 16 * 1024,
                max_entries: 1,
            }),
            true,
        ),
        (2, None, false),
    ] {
        let mut manager = BpfManager::new();
        manager.prepare_managed_storage().unwrap();
        let baseline = manager.resource_usage();
        let id = manager
            .register_managed_artifact(artifact_with_state(revision, private_array))
            .unwrap();
        let first = manager.create_managed_instance(id).unwrap();
        let second = manager.create_managed_instance(id).unwrap();
        assert_eq!(first.maps[1].is_some(), expects_map);
        assert_eq!(
            manager.managed_instances[0]
                .as_ref()
                .unwrap()
                .private_map_id
                .is_some(),
            expects_map
        );
        if let Some(map) = &first.maps[1] {
            assert_eq!(map.runtime.map.def().value_size, 16 * 1024);
            assert_eq!(map.runtime.map.def().max_entries, 1);
            assert_eq!(map.runtime.map.def().value_size as usize, 16 * 1024);
        }
        assert_eq!(second.maps[1].is_some(), expects_map);
        drop(first);
        drop(second);
        assert_eq!(manager.reclaim_managed_instances(), 2);
        manager.retire_managed_artifact(id).unwrap();
        assert_eq!(manager.resource_usage(), baseline);
    }
}

#[test]
fn managed_failed_registration_refunds_the_completed_build() {
    let mut manager = BpfManager::new();
    let id = manager.register_managed_artifact(artifact(1)).unwrap();
    let before = manager.resource_usage();
    let prepared = manager.begin_managed_instance(id).unwrap().build();
    let reserved = manager.resource_usage();
    // Model unavailable publication capacity after work was accepted.
    manager.limits.max_map_slots = manager.maps.len();
    let failure = match manager.finish_managed_instance(prepared) {
        Ok(_) => panic!("publication capacity unexpectedly remained available"),
        Err(failure) => failure,
    };
    assert_eq!(failure.error(), BpfError::ResourceLimit);
    assert_eq!(manager.resource_usage(), reserved);
    assert!(manager.managed_instance_preparation.is_some());
    let receipt = failure.release().unwrap();
    assert_eq!(manager.resource_usage(), reserved);
    assert!(manager.managed_instance_preparation.is_some());
    manager.finish_failed_managed_instance(receipt).unwrap();
    assert_eq!(manager.resource_usage(), before);
    assert!(manager.managed_instance_preparation.is_none());
    assert!(manager.managed_instances.iter().all(Option::is_none));
}

#[test]
fn managed_reclamation_drops_outside_lock_before_exact_refund() {
    let mut manager = BpfManager::new();
    manager.prepare_managed_storage().unwrap();
    let baseline = manager.resource_usage();
    let id = manager.register_managed_artifact(artifact(1)).unwrap();
    let instance = manager.create_managed_instance(id).unwrap();
    let retained = manager.resource_usage();
    drop(instance);

    let reclaim = manager.begin_managed_instance_reclamation().unwrap();
    assert_eq!(manager.resource_usage(), retained);
    assert!(manager.managed_reclamation.is_some());
    assert!(matches!(
        manager.begin_managed_instance(id),
        Err(BpfError::ObjectBusy)
    ));
    assert!(matches!(
        manager.create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1),
        Err(BpfError::ObjectBusy)
    ));
    assert!(matches!(
        manager.register_managed_artifact(artifact(2)),
        Err(BpfError::ObjectBusy)
    ));
    let receipt = reclaim.release();
    assert_eq!(manager.resource_usage(), retained);
    manager.finish_managed_reclamation(receipt).unwrap();
    assert!(manager.managed_reclamation.is_none());
    assert_eq!(manager.resource_usage().live_maps, baseline.live_maps);

    let artifact_reclaim = manager.begin_managed_artifact_reclamation(id).unwrap();
    assert_eq!(
        manager.resource_usage().live_programs,
        retained.live_programs
    );
    let receipt = artifact_reclaim.release();
    assert_eq!(
        manager.resource_usage().live_programs,
        retained.live_programs
    );
    manager.finish_managed_reclamation(receipt).unwrap();
    assert_eq!(manager.resource_usage(), baseline);
}

#[test]
fn managed_reclamation_rejects_live_and_weak_readers_without_reserving() {
    let mut manager = BpfManager::new();
    let id = manager.register_managed_artifact(artifact(1)).unwrap();
    let instance = manager.create_managed_instance(id).unwrap();
    let retained = manager.resource_usage();
    assert!(matches!(
        manager.begin_managed_instance_reclamation(),
        Err(BpfError::ObjectBusy)
    ));
    assert!(manager.managed_reclamation.is_none());
    drop(instance);

    let weak = Arc::downgrade(
        &manager
            .managed_instances
            .iter()
            .flatten()
            .next()
            .unwrap()
            .instance,
    );
    assert!(matches!(
        manager.begin_managed_instance_reclamation(),
        Err(BpfError::ObjectBusy)
    ));
    assert_eq!(manager.resource_usage(), retained);
    assert!(weak.upgrade().is_some());
    drop(weak);

    let private = manager.managed_instances[0].as_ref().unwrap().instance.maps[1]
        .as_ref()
        .unwrap()
        .runtime
        .clone();
    let map_weak = Arc::downgrade(&private);
    drop(private);
    assert!(matches!(
        manager.begin_managed_instance_reclamation(),
        Err(BpfError::ObjectBusy)
    ));
    assert!(manager.managed_instances[0].as_ref().unwrap().instance.maps[1].is_some());
    assert!(map_weak.upgrade().is_some());
    drop(map_weak);

    manager.managed_instances[0].as_ref().unwrap().instance.maps[1]
        .as_ref()
        .unwrap()
        .runtime
        .leased
        .store(true, core::sync::atomic::Ordering::Release);
    assert!(matches!(
        manager.begin_managed_instance_reclamation(),
        Err(BpfError::ObjectBusy)
    ));
    manager.managed_instances[0].as_ref().unwrap().instance.maps[1]
        .as_ref()
        .unwrap()
        .runtime
        .leased
        .store(false, core::sync::atomic::Ordering::Release);
    assert_eq!(manager.resource_usage(), retained);
}

#[test]
fn managed_reclamation_counter_exhaustion_preserves_tables_bindings_and_charges() {
    let mut manager = BpfManager::new();
    let id = manager.register_managed_artifact(artifact(1)).unwrap();
    let instance = manager.create_managed_instance(id).unwrap();
    let private_id = manager.managed_instances[0]
        .as_ref()
        .unwrap()
        .private_map_id
        .unwrap();
    let before = manager.resource_usage();
    drop(instance);
    manager.next_managed_reclamation = u64::MAX;

    assert!(matches!(
        manager.begin_managed_instance_reclamation(),
        Err(BpfError::ResourceLimit)
    ));
    assert!(manager.managed_instances[0].as_ref().unwrap().instance.maps[1].is_some());
    assert!(manager.map_entry(private_id).is_some());
    assert_eq!(manager.resource_usage(), before);
    assert!(manager.managed_reclamation.is_none());
    assert!(matches!(
        manager.begin_managed_artifact_reclamation(id),
        Err(BpfError::ResourceLimit | BpfError::ObjectBusy)
    ));
    assert!(manager.managed_artifact(id).is_ok());

    let mut artifact_manager = BpfManager::new();
    let artifact_id = artifact_manager
        .register_managed_artifact(artifact(2))
        .unwrap();
    let artifact_before = artifact_manager.resource_usage();
    artifact_manager.next_managed_reclamation = u64::MAX;
    assert!(matches!(
        artifact_manager.begin_managed_artifact_reclamation(artifact_id),
        Err(BpfError::ResourceLimit)
    ));
    assert!(artifact_manager.managed_artifact(artifact_id).is_ok());
    assert_eq!(artifact_manager.resource_usage(), artifact_before);
    assert!(artifact_manager.managed_reclamation.is_none());
}

#[test]
fn managed_instance_preparation_blocks_unrelated_artifact_reclamation() {
    let mut manager = BpfManager::new();
    let candidate = manager.register_managed_artifact(artifact(1)).unwrap();
    let unused = manager.register_managed_artifact(artifact(2)).unwrap();
    let preparation = manager.begin_managed_instance(candidate).unwrap();
    let reserved = manager.resource_usage();
    let reservation_id = manager.managed_instance_preparation.as_ref().unwrap().id;

    assert!(matches!(
        manager.begin_managed_artifact_reclamation(unused),
        Err(BpfError::ObjectBusy)
    ));
    assert_eq!(manager.resource_usage(), reserved);
    assert_eq!(
        manager.managed_instance_preparation.as_ref().unwrap().id,
        reservation_id
    );
    assert!(manager.managed_artifact(unused).is_ok());
    assert!(manager.managed_reclamation.is_none());

    let instance = manager
        .finish_managed_instance(preparation.build())
        .unwrap();
    assert_eq!(
        instance.artifact().identity(),
        manager.managed_artifact(candidate).unwrap().identity()
    );
}

#[test]
fn managed_registration_transfers_caller_budget_on_every_result() {
    let program = [BpfInsn::mov64_imm(0, 0), BpfInsn::exit()];
    let mut manager = BpfManager::new();

    let (first, mut first_budget) = artifact_and_budget_from_program(1, false, 0, None, &program);
    let first_code = first.code_bytes();
    assert_eq!(first_budget.used(), first_code);
    let before_insert = manager.resource_usage();
    let id = manager.register_managed_artifact(first).unwrap();
    first_budget.release_output(first_code).unwrap();
    assert_eq!(first_budget.used(), 0);
    let inserted = manager.resource_usage();
    assert_eq!(inserted.live_programs, before_insert.live_programs + 1);
    assert!(inserted.program_bytes > before_insert.program_bytes);

    let (duplicate, mut duplicate_budget) =
        artifact_and_budget_from_program(1, false, 0, None, &program);
    let duplicate_code = duplicate.code_bytes();
    assert_eq!(manager.register_managed_artifact(duplicate).unwrap(), id);
    duplicate_budget.release_output(duplicate_code).unwrap();
    assert_eq!(duplicate_budget.used(), 0);
    assert_eq!(manager.resource_usage(), inserted);

    manager
        .register_managed_artifact(artifact_from_program(2, false, 0, None, &program))
        .unwrap();
    manager
        .register_managed_artifact(artifact_from_program(3, false, 0, None, &program))
        .unwrap();
    let full = manager.resource_usage();
    let (rejected, mut rejected_budget) =
        artifact_and_budget_from_program(4, false, 0, None, &program);
    let rejected_code = rejected.code_bytes();
    assert!(matches!(
        manager.register_managed_artifact(rejected),
        Err(BpfError::ResourceLimit)
    ));
    rejected_budget.release_output(rejected_code).unwrap();
    assert_eq!(rejected_budget.used(), 0);
    assert_eq!(manager.resource_usage(), full);
}

#[test]
fn managed_instance_allocation_failures_refund_reservation_without_touching_live_state() {
    for fail_at in 1..=4 {
        let mut manager = BpfManager::new();
        let id = manager.register_managed_artifact(artifact(1)).unwrap();
        let live = manager.create_managed_instance(id).unwrap();
        live.maps[1]
            .as_ref()
            .unwrap()
            .runtime
            .map
            .update(&0u32.to_ne_bytes(), &77u64.to_ne_bytes(), 0)
            .unwrap();
        let identity = live.artifact().identity();
        let before = manager.resource_usage();

        let mut checkpoint = 0;
        let prepared = manager.begin_managed_instance(id).unwrap().build_with(|| {
            checkpoint += 1;
            if checkpoint == fail_at {
                Err(BpfError::OutOfMemory)
            } else {
                Ok(())
            }
        });
        assert!(
            matches!(
                manager.finish_managed_instance(prepared),
                Err(error) if error.error() == BpfError::OutOfMemory
            ),
            "allocation checkpoint {fail_at}"
        );
        assert_eq!(checkpoint, fail_at);
        assert_eq!(manager.resource_usage(), before);
        assert!(manager.managed_instance_preparation.is_none());
        assert_eq!(live.artifact().identity(), identity);
        assert_eq!(
            live.maps[1]
                .as_ref()
                .unwrap()
                .runtime
                .map
                .lookup(&0u32.to_ne_bytes())
                .unwrap(),
            77u64.to_ne_bytes()
        );
        assert_eq!(manager.managed_instances.iter().flatten().count(), 1);
    }
}

#[test]
fn managed_pending_preparation_is_exclusive_and_reserves_legacy_map_capacity() {
    let mut manager = BpfManager::new();
    let id = manager.register_managed_artifact(artifact(1)).unwrap();
    manager.limits.max_live_maps = manager.live_maps + 1;
    manager.limits.max_map_slots = manager.maps.len() + 1;
    let before = manager.resource_usage();

    let pending = manager.begin_managed_instance(id).unwrap();
    assert!(matches!(
        manager.begin_managed_instance(id),
        Err(BpfError::ObjectBusy)
    ));
    assert!(matches!(
        manager.create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1),
        Err(BpfError::ResourceLimit)
    ));
    assert!(matches!(
        manager.finish_managed_instance(pending.cancel()),
        Err(error) if error.error() == BpfError::ObjectBusy
    ));
    assert_eq!(manager.resource_usage(), before);
    assert!(manager.managed_instance_preparation.is_none());
}

#[test]
fn managed_preparation_counter_exhaustion_does_not_reserve_resources() {
    let mut manager = BpfManager::new();
    let id = manager.register_managed_artifact(artifact(1)).unwrap();
    manager.next_managed_preparation = u64::MAX;
    let before = manager.resource_usage();

    assert!(matches!(
        manager.begin_managed_instance(id),
        Err(BpfError::ResourceLimit)
    ));
    assert_eq!(manager.resource_usage(), before);
    assert!(manager.managed_instance_preparation.is_none());
}

#[test]
fn managed_ownership_lifecycle_survives_100_000_fresh_instances() {
    const ITERATIONS: usize = 100_000;

    // Authentication and verification happen once. This soak exercises only
    // kernel ownership, allocation, generation, and reclamation; it is not an
    // activation or timing qualification.
    let verified = artifact(1);
    let mut manager = BpfManager::new();
    manager.prepare_managed_storage().unwrap();
    let table_floor = manager.resource_usage();
    let artifact_id = manager.register_managed_artifact(verified).unwrap();
    let artifact_floor = manager.resource_usage();
    let mut live_high_water = artifact_floor;
    let mut previous_private_id = None;

    for iteration in 0..ITERATIONS {
        let instance = manager.create_managed_instance(artifact_id).unwrap();
        let private_id = manager.managed_instances[0]
            .as_ref()
            .and_then(|entry| entry.private_map_id)
            .unwrap();
        let live = manager.resource_usage();
        live_high_water.live_programs = live_high_water.live_programs.max(live.live_programs);
        live_high_water.program_bytes = live_high_water.program_bytes.max(live.program_bytes);
        live_high_water.live_maps = live_high_water.live_maps.max(live.live_maps);
        live_high_water.map_bytes = live_high_water.map_bytes.max(live.map_bytes);
        if let Some(stale) = previous_private_id {
            assert!(manager.map_entry(stale).is_none());
            assert_ne!(stale, private_id);
        }
        instance.maps[1]
            .as_ref()
            .unwrap()
            .runtime
            .map
            .update(&0u32.to_ne_bytes(), &(iteration as u64).to_ne_bytes(), 0)
            .unwrap();
        drop(instance);
        assert_eq!(manager.reclaim_managed_instances(), 1);
        assert_eq!(manager.resource_usage(), artifact_floor);
        previous_private_id = Some(private_id);
    }

    manager.retire_managed_artifact(artifact_id).unwrap();
    assert_eq!(manager.resource_usage(), table_floor);
    assert!(manager.managed_artifact(artifact_id).is_err());
    assert_eq!(live_high_water.live_programs, artifact_floor.live_programs);
    assert_eq!(live_high_water.live_maps, artifact_floor.live_maps + 1);
    assert!(live_high_water.program_bytes > artifact_floor.program_bytes);
    assert!(live_high_water.map_bytes > artifact_floor.map_bytes);
    std::println!(
        "managed ownership 100k: floor={artifact_floor:?} live_high_water={live_high_water:?} table_floor={table_floor:?}"
    );
}

pub(in crate::bpf) fn stateful_managed_program() -> alloc::vec::Vec<BpfInsn> {
    alloc::vec![
        BpfInsn::new(0x62, 10, 0, -4, 0), // key = 0
        BpfInsn::mov64_imm(1, 1),
        BpfInsn::mov64_reg(2, 10),
        BpfInsn::add64_imm(2, -4),
        BpfInsn::call(kernel_abi::BPF_HELPER_MAP_LOOKUP_ELEM),
        BpfInsn::jne_imm(0, 0, 2),
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::exit(),
        BpfInsn::mov64_reg(6, 0),
        BpfInsn::new(0x79, 7, 6, 0, 0), // previous private value
        BpfInsn::mov64_reg(8, 7),
        BpfInsn::add64_imm(8, 1),
        BpfInsn::new(0x7b, 10, 8, -16, 0),
        BpfInsn::mov64_imm(1, 1),
        BpfInsn::mov64_reg(2, 10),
        BpfInsn::add64_imm(2, -4),
        BpfInsn::mov64_reg(3, 10),
        BpfInsn::add64_imm(3, -16),
        BpfInsn::mov64_imm(4, 0),
        BpfInsn::call(kernel_abi::BPF_HELPER_MAP_UPDATE_ELEM),
        BpfInsn::mov64_imm(1, 0),
        BpfInsn::mov64_reg(2, 10),
        BpfInsn::add64_imm(2, -4),
        BpfInsn::call(kernel_abi::BPF_HELPER_MAP_LOOKUP_ELEM),
        BpfInsn::jne_imm(0, 0, 2),
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::exit(),
        BpfInsn::new(0x79, 9, 0, 0, 0), // prove envelope value is readable
        BpfInsn::mov64_reg(1, 7),
        BpfInsn::mov64_reg(2, 7),
        BpfInsn::call(kernel_abi::BPF_HELPER_MANAGED_MOTOR_PAIR_V1),
        BpfInsn::mov64_reg(0, 9),
        BpfInsn::exit(),
    ]
}

#[test]
fn managed_execution_uses_exact_bindings_and_keeps_instance_state_isolated() {
    let program = stateful_managed_program();
    let artifact = artifact_from_program(
        10,
        true,
        EFFECT_MOTOR_PAIR,
        Some(PrivateArray {
            value_size: 8,
            max_entries: 1,
        }),
        &program,
    );
    let mut manager = BpfManager::new();
    let id = manager.register_managed_artifact(artifact).unwrap();
    let a = manager.create_managed_instance(id).unwrap();
    let b = manager.create_managed_instance(id).unwrap();
    let context = ManagedControlContextV1 {
        version: kernel_abi::MANAGED_CONTROL_CONTEXT_V1_VERSION,
        size: kernel_abi::MANAGED_CONTROL_CONTEXT_V1_SIZE,
        ..Default::default()
    };

    assert_eq!(a.execute(&context).unwrap().motor_pair().left, 0);
    assert_eq!(a.execute(&context).unwrap().motor_pair().left, 1);
    assert_eq!(b.execute(&context).unwrap().motor_pair().left, 0);
    assert!(!a.maps[0]
        .as_ref()
        .unwrap()
        .runtime
        .leased
        .load(core::sync::atomic::Ordering::Acquire));
    assert!(!a.maps[1]
        .as_ref()
        .unwrap()
        .runtime
        .leased
        .load(core::sync::atomic::Ordering::Acquire));
}

#[test]
fn managed_execution_failure_discards_request_and_releases_map_lease() {
    let program = [
        BpfInsn::mov64_imm(1, 7),
        BpfInsn::mov64_imm(2, -7),
        BpfInsn::call(kernel_abi::BPF_HELPER_MANAGED_MOTOR_PAIR_V1),
        BpfInsn::new(0x62, 10, 0, -4, 99),
        BpfInsn::mov64_imm(1, 1),
        BpfInsn::mov64_reg(2, 10),
        BpfInsn::add64_imm(2, -4),
        BpfInsn::call(kernel_abi::BPF_HELPER_MAP_LOOKUP_ELEM),
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::exit(),
    ];
    let artifact = artifact_from_program(
        11,
        false,
        EFFECT_MOTOR_PAIR,
        Some(PrivateArray {
            value_size: 8,
            max_entries: 1,
        }),
        &program,
    );
    let mut manager = BpfManager::new();
    let id = manager.register_managed_artifact(artifact).unwrap();
    let instance = manager.create_managed_instance(id).unwrap();
    let context = ManagedControlContextV1 {
        version: kernel_abi::MANAGED_CONTROL_CONTEXT_V1_VERSION,
        size: kernel_abi::MANAGED_CONTROL_CONTEXT_V1_SIZE,
        ..Default::default()
    };

    assert_eq!(instance.execute(&context), Err(BpfError::ManagedMapFailure));
    assert!(!instance.maps[1]
        .as_ref()
        .unwrap()
        .runtime
        .leased
        .load(core::sync::atomic::Ordering::Acquire));
    // A following invocation reaches the same deliberate failure rather than
    // reentrancy/busy state; no earlier capture escapes an `Err` result.
    assert_eq!(instance.execute(&context), Err(BpfError::ManagedMapFailure));
}

#[test]
fn managed_weak_references_keep_allocation_charges_until_release() {
    let mut manager = BpfManager::new();
    let id = manager.register_managed_artifact(artifact(1)).unwrap();
    let instance = manager.create_managed_instance(id).unwrap();
    let weak = Arc::downgrade(&instance);
    let before = manager.resource_usage();
    drop(instance);
    assert_eq!(manager.reclaim_managed_instances(), 0);
    assert_eq!(manager.resource_usage(), before);
    assert!(weak.upgrade().is_some());
    drop(weak);
    assert_eq!(manager.reclaim_managed_instances(), 1);
    let weak = Arc::downgrade(manager.managed_artifact(id).unwrap());
    let before = manager.resource_usage();
    assert!(matches!(
        manager.retire_managed_artifact(id),
        Err(BpfError::ObjectBusy)
    ));
    assert_eq!(manager.resource_usage(), before);
    drop(weak);
    manager.retire_managed_artifact(id).unwrap();
}

#[test]
fn managed_ownership_retains_shared_code_and_fresh_private_state() {
    let mut manager = BpfManager::new();
    manager.prepare_managed_storage().unwrap();
    let baseline = manager.resource_usage();
    let id = manager.register_managed_artifact(artifact(1)).unwrap();
    let registered = manager.resource_usage();
    assert_eq!(registered.live_programs, baseline.live_programs + 1);
    let a = manager.create_managed_instance(id).unwrap();
    let b = manager.create_managed_instance(id).unwrap();
    let private_a = a.maps[1].as_ref().unwrap();
    private_a
        .runtime
        .map
        .update(&0u32.to_ne_bytes(), &42u64.to_ne_bytes(), 0)
        .unwrap();
    assert_eq!(
        b.maps[1]
            .as_ref()
            .unwrap()
            .runtime
            .map
            .lookup(&0u32.to_ne_bytes())
            .unwrap(),
        [0; 8]
    );
    assert!(matches!(
        manager.create_managed_instance(id),
        Err(BpfError::ObjectBusy)
    ));
    assert!(matches!(
        manager.retire_managed_artifact(id),
        Err(BpfError::ObjectBusy)
    ));
    assert!(manager.reclaim_owner(0));
    assert!(manager.reclaim_owner(u64::MAX));
    assert_eq!(
        manager.resource_usage().live_programs,
        registered.live_programs
    );
    assert_eq!(manager.reclaim_managed_instances(), 0);
    drop(a);
    assert_eq!(manager.reclaim_managed_instances(), 1);
    let fresh = manager.create_managed_instance(id).unwrap();
    assert_eq!(
        fresh.maps[1]
            .as_ref()
            .unwrap()
            .runtime
            .map
            .lookup(&0u32.to_ne_bytes())
            .unwrap(),
        [0; 8]
    );
    drop(b);
    drop(fresh);
    assert_eq!(manager.reclaim_managed_instances(), 2);
    manager.retire_managed_artifact(id).unwrap();
    assert_eq!(manager.resource_usage(), baseline);
}

#[test]
fn managed_objects_reject_legacy_access_and_bound_artifacts() {
    let mut manager = BpfManager::new();
    let id = manager.register_managed_artifact(artifact(1)).unwrap();
    assert!(matches!(
        manager.unload_program(id),
        Err(BpfError::PermissionDenied)
    ));
    assert!(matches!(
        manager.execute(id, &BpfContext::empty()),
        Err(BpfError::PermissionDenied)
    ));
    assert!(matches!(
        manager.attach(crate::bpf::ATTACH_TYPE_TIMER, id),
        Err(BpfError::PermissionDenied)
    ));
    let instance = manager.create_managed_instance(id).unwrap();
    let map_id = manager
        .managed_instances
        .iter()
        .flatten()
        .find_map(|e| e.private_map_id)
        .unwrap();
    for pid in [0, 1, u64::MAX] {
        assert!(matches!(
            manager.map_lookup_for(pid, map_id, &0u32.to_ne_bytes()),
            Err(BpfError::PermissionDenied)
        ));
        assert!(matches!(
            manager.destroy_map_for(pid, map_id),
            Err(BpfError::PermissionDenied)
        ));
        assert!(matches!(
            manager.pin_map_for(pid, "/private".into(), map_id),
            Err(BpfError::PermissionDenied)
        ));
    }
    assert!(manager.map_lookup(map_id, &0u32.to_ne_bytes()).is_none());
    assert!(matches!(
        manager.map_update(map_id, &0u32.to_ne_bytes(), &[1; 8], 0),
        Err(BpfError::PermissionDenied)
    ));
    assert!(manager.get_map_def(map_id).is_none());
    assert_eq!(manager.register_managed_artifact(artifact(1)).unwrap(), id);
    manager.register_managed_artifact(artifact(2)).unwrap();
    manager.register_managed_artifact(artifact(3)).unwrap();
    assert!(matches!(
        manager.register_managed_artifact(artifact(4)),
        Err(BpfError::ResourceLimit)
    ));
    drop(instance);
}
