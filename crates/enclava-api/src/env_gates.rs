//! Production environment-variable safety gates.
//!
//! Refuses to start if dangerous developer-only flags are set in a release
//! build, or if mandatory secrets are empty (any build).

#[derive(Debug, thiserror::Error)]
pub enum EnvGateError {
    #[error("env var `{0}` is set but only allowed in debug builds")]
    DebugOnlyFlagInRelease(&'static str),
    #[error("env var `{0}` must be set and non-empty")]
    MissingRequired(&'static str),
}

const DEBUG_ONLY_FLAGS: &[&str] = &[
    "SKIP_COSIGN_VERIFY",
    "COSIGN_ALLOW_HTTP_REGISTRY",
    "ALLOW_EPHEMERAL_KEYS",
    "TENANT_TEE_ACCEPT_INVALID_CERTS",
    "ENCLAVA_TEE_ACCEPT_INVALID_CERTS",
];

const ALWAYS_REQUIRED: &[&str] = &["BTCPAY_WEBHOOK_SECRET"];

// Mirrors the precedence in `kbs::config_from_env`: REQUIRED implies enabled.
const KBS_TOGGLES: &[&str] = &["KBS_POLICY_MANAGEMENT_ENABLED", "KBS_POLICY_MANAGEMENT_REQUIRED"];

fn flag_is_truthy(value: &str) -> bool {
    matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES")
}

fn kbs_management_enabled(lookup: &impl Fn(&str) -> Option<String>) -> bool {
    KBS_TOGGLES
        .iter()
        .any(|name| lookup(name).is_some_and(|v| flag_is_truthy(&v)))
}

fn debug_assertions_on() -> bool {
    cfg!(debug_assertions)
}

/// Apply Phase-0 production gates. Should be called early in `main`, before
/// any subsystem reads environment variables.
pub fn enforce_production_env_gates() -> Result<(), EnvGateError> {
    enforce_with(debug_assertions_on(), |name| std::env::var(name).ok())
}

fn enforce_with(
    debug_assertions: bool,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<(), EnvGateError> {
    if !debug_assertions {
        for flag in DEBUG_ONLY_FLAGS {
            if let Some(value) = lookup(flag)
                && flag_is_truthy(&value)
            {
                return Err(EnvGateError::DebugOnlyFlagInRelease(flag));
            }
        }

        if let Some(mode) = lookup("TENANT_TEE_TLS_MODE")
            && matches!(mode.trim(), "staging" | "insecure")
        {
            return Err(EnvGateError::DebugOnlyFlagInRelease("TENANT_TEE_TLS_MODE"));
        }
    }

    for required in ALWAYS_REQUIRED {
        match lookup(required) {
            Some(value) if !value.trim().is_empty() => {}
            _ => return Err(EnvGateError::MissingRequired(required)),
        }
    }

    if kbs_management_enabled(&lookup) {
        match lookup("KBS_RESOURCE_WRITER_TOKEN") {
            Some(value) if !value.trim().is_empty() => {}
            _ => return Err(EnvGateError::MissingRequired("KBS_RESOURCE_WRITER_TOKEN")),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ok_required() -> HashMap<&'static str, &'static str> {
        let mut m = HashMap::new();
        m.insert("BTCPAY_WEBHOOK_SECRET", "secret");
        m
    }

    fn ok_required_with_kbs() -> HashMap<&'static str, &'static str> {
        let mut m = ok_required();
        m.insert("KBS_POLICY_MANAGEMENT_ENABLED", "1");
        m.insert("KBS_RESOURCE_WRITER_TOKEN", "token");
        m
    }

    fn run(env: HashMap<&'static str, &'static str>, debug: bool) -> Result<(), EnvGateError> {
        enforce_with(debug, |k| env.get(k).map(|v| v.to_string()))
    }

    #[test]
    fn release_rejects_skip_cosign_verify() {
        let mut env = ok_required();
        env.insert("SKIP_COSIGN_VERIFY", "1");
        let err = run(env, false).unwrap_err();
        assert!(matches!(
            err,
            EnvGateError::DebugOnlyFlagInRelease("SKIP_COSIGN_VERIFY")
        ));
    }

    #[test]
    fn release_rejects_tee_accept_invalid_certs() {
        for flag in [
            "TENANT_TEE_ACCEPT_INVALID_CERTS",
            "ENCLAVA_TEE_ACCEPT_INVALID_CERTS",
        ] {
            let mut env = ok_required();
            env.insert(flag, "true");
            assert!(run(env, false).is_err(), "{flag} should be rejected");
        }
    }

    #[test]
    fn release_rejects_insecure_tee_tls_mode() {
        let mut env = ok_required();
        env.insert("TENANT_TEE_TLS_MODE", "insecure");
        assert!(run(env, false).is_err());
    }

    #[test]
    fn debug_allows_debug_only_flags() {
        let mut env = ok_required();
        env.insert("SKIP_COSIGN_VERIFY", "1");
        env.insert("ALLOW_EPHEMERAL_KEYS", "1");
        run(env, true).expect("debug build should permit dev flags");
    }

    #[test]
    fn missing_btcpay_secret_rejected_in_debug() {
        let env = HashMap::new();
        assert!(matches!(
            run(env, true).unwrap_err(),
            EnvGateError::MissingRequired("BTCPAY_WEBHOOK_SECRET")
        ));
    }

    #[test]
    fn kbs_writer_token_not_required_when_management_disabled() {
        let env = ok_required();
        run(env, false).expect("kbs token is irrelevant when management is off");
    }

    #[test]
    fn kbs_writer_token_required_when_management_enabled() {
        let mut env = ok_required();
        env.insert("KBS_POLICY_MANAGEMENT_ENABLED", "true");
        assert!(matches!(
            run(env, false).unwrap_err(),
            EnvGateError::MissingRequired("KBS_RESOURCE_WRITER_TOKEN")
        ));
    }

    #[test]
    fn kbs_writer_token_required_when_management_required() {
        let mut env = ok_required();
        env.insert("KBS_POLICY_MANAGEMENT_REQUIRED", "1");
        assert!(matches!(
            run(env, false).unwrap_err(),
            EnvGateError::MissingRequired("KBS_RESOURCE_WRITER_TOKEN")
        ));
    }

    #[test]
    fn empty_kbs_writer_token_rejected_when_enabled() {
        let mut env = ok_required();
        env.insert("KBS_POLICY_MANAGEMENT_ENABLED", "1");
        env.insert("KBS_RESOURCE_WRITER_TOKEN", "   ");
        assert!(matches!(
            run(env, false).unwrap_err(),
            EnvGateError::MissingRequired("KBS_RESOURCE_WRITER_TOKEN")
        ));
    }

    #[test]
    fn kbs_writer_token_accepted_when_enabled() {
        let env = ok_required_with_kbs();
        run(env, false).expect("kbs token present should pass");
    }

    #[test]
    fn falsy_kbs_management_toggle_does_not_require_token() {
        let mut env = ok_required();
        env.insert("KBS_POLICY_MANAGEMENT_ENABLED", "0");
        run(env, false).expect("falsy toggle should not require kbs token");
    }

    #[test]
    fn falsy_debug_only_flag_is_allowed() {
        let mut env = ok_required();
        env.insert("SKIP_COSIGN_VERIFY", "0");
        run(env, false).expect("falsy flag should not trip the gate");
    }
}
