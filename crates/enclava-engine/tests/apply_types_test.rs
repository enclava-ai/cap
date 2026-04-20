use enclava_engine::apply::types::{DeployPhase, DeployStatus};
use std::time::Duration;

#[test]
fn deploy_status_starts_as_applying() {
    let status = DeployStatus::new();
    assert_eq!(status.phase, DeployPhase::Applying);
    assert!(status.message.is_none());
    assert!(!status.is_terminal());
}

#[test]
fn terminal_phases() {
    assert!(DeployStatus::with_phase(DeployPhase::Running).is_terminal());
    assert!(DeployStatus::with_phase(DeployPhase::Failed).is_terminal());
    assert!(DeployStatus::with_phase(DeployPhase::TimedOut).is_terminal());
}

#[test]
fn non_terminal_phases() {
    assert!(!DeployStatus::with_phase(DeployPhase::Applying).is_terminal());
    assert!(!DeployStatus::with_phase(DeployPhase::PodsScheduled).is_terminal());
    assert!(!DeployStatus::with_phase(DeployPhase::TeeBooting).is_terminal());
    assert!(!DeployStatus::with_phase(DeployPhase::Attesting).is_terminal());
}

#[test]
fn phase_ordering_is_monotonic() {
    assert!((DeployPhase::Applying as u8) < (DeployPhase::PodsScheduled as u8));
    assert!((DeployPhase::PodsScheduled as u8) < (DeployPhase::TeeBooting as u8));
    assert!((DeployPhase::TeeBooting as u8) < (DeployPhase::Attesting as u8));
    assert!((DeployPhase::Attesting as u8) < (DeployPhase::Running as u8));
}

#[test]
fn status_with_message() {
    let status = DeployStatus::failed("container crash loop: OOMKilled");
    assert_eq!(status.phase, DeployPhase::Failed);
    assert_eq!(
        status.message.as_deref(),
        Some("container crash loop: OOMKilled")
    );
    assert!(status.is_terminal());
}

#[test]
fn default_timeout_is_ten_minutes() {
    use enclava_engine::apply::types::ApplyConfig;
    let config = ApplyConfig::default();
    assert_eq!(config.rollout_timeout, Duration::from_secs(600));
}
