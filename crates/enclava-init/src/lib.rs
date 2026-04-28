//! enclava-init: in-TEE Rust replacement for the legacy bootstrap_script.sh.
//!
//! Runs as a Kubernetes initContainer inside a Kata SEV-SNP guest. Performs
//! Argon2id-based password unlock or KBS-fetched autounlock, opens both LUKS
//! devices (state and tls-state), runs the in-TEE Trustee policy verification
//! chain, and writes per-component HKDF-derived seeds. All secret types use
//! Zeroize so key material is wiped on drop.

pub mod chown;
pub mod config;
pub mod errors;
pub mod kbs_fetch;
pub mod luks;
pub mod secrets;
pub mod seeds;
pub mod socket;
pub mod trustee_verify;
pub mod unlock;
pub mod writes;
