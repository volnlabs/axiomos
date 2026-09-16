//! Preparation failures with a real stateful installation and retained previous.
use kernel_bpf::signing::managed::EFFECT_MOTOR_PAIR;
use kernel_bpf::verifier::admission::AdmissionLedger;

use super::*;

fn manifest(revision: u64) -> Manifest {
    Manifest {
        behavior_id: [9; 16],
        revision,
        envelope: true,
        effects: EFFECT_MOTOR_PAIR,
        private_array: Some(PrivateArray {
            value_size: 8,
            max_entries: 1,
        }),
    }
}

#[test]
fn preparation_failures_preserve_stateful_active_previous_and_admission() {
    // Signed invalid bytecode, a signed undeclared local binding, and a valid
    // controller whose modeled cost exceeds the fixed active admission budget.
    for failure in 0..7 {
        let (mut worker, slot, manager) = fixture_worker();
        let program = crate::bpf::managed::tests::stateful_managed_program();
        let context = ManagedControlContextV1 {
            version: kernel_abi::MANAGED_CONTROL_CONTEXT_V1_VERSION,
            size: kernel_abi::MANAGED_CONTROL_CONTEXT_V1_SIZE,
            ..Default::default()
        };
        let mut last = 0;
        let mut handles = [0; 2];
        for revision in 1..=2 {
            let bytes = signed_manifest(manifest(revision), &program).0;
            let uploaded = upload(&mut manager.lock(), 7, last, &bytes);
            manager.lock().managed_upload_finalize(7, uploaded).unwrap();
            assert!(service_worker(&mut worker, &slot, &manager));
            let receipt = manager.lock().managed_operation_query(uploaded).unwrap();
            assert_eq!(receipt.phase, MANAGED_OPERATION_RESIDENT);
            handles[(revision - 1) as usize] = receipt.artifact_handle;
            if revision == 1 {
                let mut manager = manager.lock();
                let cost = manager
                    .managed_artifact(receipt.artifact_handle)
                    .unwrap()
                    .wcet_cycles();
                manager.admission = AdmissionLedger::new(cost * 100, 1);
            }
            last = manager
                .lock()
                .request_installation(
                    &mut slot.lock(),
                    uploaded,
                    revision - 1,
                    LifecycleTarget::Candidate(receipt.artifact_handle),
                )
                .unwrap();
            assert!(service_worker(&mut worker, &slot, &manager));
            host_commit(&slot);
            assert!(service_worker(&mut worker, &slot, &manager));
            assert_eq!(slot.lock().execute(&context).unwrap().motor_pair().left, 0);
            assert_eq!(slot.lock().execute(&context).unwrap().motor_pair().left, 1);
        }
        let before = slot.lock().snapshot();
        assert_eq!(
            (before.active, before.previous),
            (Some(handles[1]), Some(handles[0]))
        );
        let (identities, contracts, floor, committed, reserved) = {
            let manager = manager.lock();
            let identities =
                handles.map(|handle| manager.managed_artifact(handle).unwrap().identity());
            let contracts =
                handles.map(|handle| manager.managed_artifact(handle).unwrap().contract());
            assert_eq!(manager.managed_instances.iter().flatten().count(), 1);
            let private = manager
                .maps
                .iter()
                .flatten()
                .find(|entry| entry.owner == crate::bpf::ObjectOwner::KernelManaged)
                .unwrap();
            let _lease = private.runtime.try_lease().unwrap();
            private
                .runtime
                .map
                .update(&0u32.to_ne_bytes(), &77u64.to_ne_bytes(), 0)
                .unwrap();
            (
                identities,
                contracts,
                manager.resource_usage(),
                manager.admission.committed_ns_per_s(),
                manager.admission.reserved_ns_per_s(),
            )
        };
        assert_eq!(before.active_charge_ns_per_s, Some(committed));
        assert_eq!(reserved, committed);
        let (candidate_manifest, candidate_program) = match failure {
            0 => (manifest(3), alloc::vec![BpfInsn::new(0xff, 0, 0, 0, 0)]),
            1 => (
                Manifest {
                    private_array: None,
                    ..manifest(3)
                },
                program.clone(),
            ),
            2 => {
                let mut expensive = alloc::vec![BpfInsn::mov64_imm(0, 0); 256];
                expensive.extend_from_slice(&program);
                (manifest(3), expensive)
            }
            _ => (manifest(3), program.clone()),
        };
        let bytes = signed_manifest(candidate_manifest, &candidate_program).0;
        let uploaded = upload(&mut manager.lock(), 7, last, &bytes);
        manager.lock().managed_upload_finalize(7, uploaded).unwrap();
        assert!(service_worker(&mut worker, &slot, &manager));
        let receipt = manager.lock().managed_operation_query(uploaded).unwrap();
        if failure < 2 {
            assert_eq!(receipt.phase, MANAGED_OPERATION_FAILED);
            assert_eq!(receipt.error, i32::from(ENOEXEC) as u32);
            // Authentication happened before the verifier rejected the candidate.
            assert_ne!(receipt.signer_fingerprint, [0; 32]);
            assert_eq!(manager.lock().resource_usage(), floor);
        } else {
            assert_eq!(receipt.phase, MANAGED_OPERATION_RESIDENT);
            let resident_floor = manager.lock().resource_usage();
            let expected_last = if failure == 2 {
                assert!(
                    manager
                        .lock()
                        .managed_artifact(receipt.artifact_handle)
                        .unwrap()
                        .wcet_cycles()
                        * 100
                        > committed
                );
                assert_eq!(
                    manager.lock().request_installation(
                        &mut slot.lock(),
                        uploaded,
                        before.generation,
                        LifecycleTarget::Candidate(receipt.artifact_handle)
                    ),
                    Err(ENOMEM)
                );
                uploaded
            } else {
                let operation = manager
                    .lock()
                    .request_installation(
                        &mut slot.lock(),
                        uploaded,
                        before.generation,
                        LifecycleTarget::Candidate(receipt.artifact_handle),
                    )
                    .unwrap();
                crate::bpf::managed::allocation_test::with_failure(failure - 2, || {
                    assert!(service_worker(&mut worker, &slot, &manager));
                });
                let rejected = manager.lock().managed_operation_query(operation).unwrap();
                assert_eq!(rejected.phase, MANAGED_OPERATION_FAILED);
                assert_eq!(rejected.error, i32::from(ENOMEM) as u32);
                operation
            };
            assert_eq!(slot.lock().snapshot(), before);
            assert_eq!(manager.lock().resource_usage(), resident_floor);
            assert_eq!(manager.lock().admission.committed_ns_per_s(), committed);
            assert_eq!(manager.lock().admission.reserved_ns_per_s(), reserved);
            // Retire the rejected candidate through the normal worker path.
            let retired = manager
                .lock()
                .request_installation(
                    &mut slot.lock(),
                    expected_last,
                    before.generation,
                    LifecycleTarget::Retire(receipt.artifact_handle),
                )
                .unwrap();
            assert!(service_worker(&mut worker, &slot, &manager));
            assert_eq!(
                manager
                    .lock()
                    .managed_operation_query(retired)
                    .unwrap()
                    .phase,
                MANAGED_OPERATION_COMMITTED
            );
            assert_eq!(manager.lock().resource_usage(), floor);
        }
        assert_eq!(slot.lock().snapshot(), before);
        {
            let manager = manager.lock();
            assert_eq!(
                handles.map(|handle| manager.managed_artifact(handle).unwrap().identity()),
                identities
            );
            assert_eq!(
                handles.map(|handle| manager.managed_artifact(handle).unwrap().contract()),
                contracts
            );
            assert_eq!(manager.admission.committed_ns_per_s(), committed);
            assert_eq!(manager.admission.reserved_ns_per_s(), reserved);
            assert_eq!(manager.managed_instances.iter().flatten().count(), 1);
            assert!(!manager.managed_slot_busy);
            assert!(manager.managed_instance_preparation.is_none());
        }
        assert_eq!(slot.lock().execute(&context).unwrap().motor_pair().left, 77);
        assert_eq!(slot.lock().execute(&context).unwrap().motor_pair().left, 78);
    }
}
