use enclava_engine::apply::types::DeployPhase;
use enclava_engine::apply::watch::{PodSnapshot, classify_pod_phase};

#[test]
fn pending_pod_maps_to_pods_scheduled_or_tee_booting() {
    let snap = PodSnapshot {
        phase: Some("Pending".to_string()),
        container_statuses_ready: false,
        init_containers_done: false,
        conditions_scheduled: true,
    };
    let phase = classify_pod_phase(&snap);
    // Scheduled but not ready: TEE is booting
    assert_eq!(phase, DeployPhase::TeeBooting);
}

#[test]
fn pending_not_scheduled_maps_to_pods_scheduled() {
    let snap = PodSnapshot {
        phase: Some("Pending".to_string()),
        container_statuses_ready: false,
        init_containers_done: false,
        conditions_scheduled: false,
    };
    let phase = classify_pod_phase(&snap);
    assert_eq!(phase, DeployPhase::PodsScheduled);
}

#[test]
fn running_ready_maps_to_running() {
    let snap = PodSnapshot {
        phase: Some("Running".to_string()),
        container_statuses_ready: true,
        init_containers_done: true,
        conditions_scheduled: true,
    };
    let phase = classify_pod_phase(&snap);
    assert_eq!(phase, DeployPhase::Running);
}

#[test]
fn running_not_ready_maps_to_attesting() {
    let snap = PodSnapshot {
        phase: Some("Running".to_string()),
        container_statuses_ready: false,
        init_containers_done: true,
        conditions_scheduled: true,
    };
    let phase = classify_pod_phase(&snap);
    assert_eq!(phase, DeployPhase::Attesting);
}

#[test]
fn failed_pod_maps_to_failed() {
    let snap = PodSnapshot {
        phase: Some("Failed".to_string()),
        container_statuses_ready: false,
        init_containers_done: false,
        conditions_scheduled: true,
    };
    let phase = classify_pod_phase(&snap);
    assert_eq!(phase, DeployPhase::Failed);
}

#[test]
fn unknown_phase_maps_to_tee_booting() {
    let snap = PodSnapshot {
        phase: Some("Unknown".to_string()),
        container_statuses_ready: false,
        init_containers_done: false,
        conditions_scheduled: true,
    };
    let phase = classify_pod_phase(&snap);
    // Unknown means the kubelet lost contact -- TEE VM may still be booting
    assert_eq!(phase, DeployPhase::TeeBooting);
}

/// Integration test: requires a running cluster.
#[tokio::test]
#[ignore]
async fn watch_rollout_times_out_on_missing_statefulset() {
    use enclava_engine::apply::engine::ApplyEngine;
    use enclava_engine::apply::types::ApplyConfig;
    use enclava_engine::apply::watch::watch_rollout;
    use std::time::Duration;

    let config = ApplyConfig {
        rollout_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_secs(1),
        ..Default::default()
    };
    let engine = ApplyEngine::try_with_config(config).await.unwrap();

    let result = watch_rollout(&engine, "nonexistent-ns", "nonexistent-sts").await;
    assert!(result.is_err());
}
