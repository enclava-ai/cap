//! Volume and VolumeClaimTemplate builders for the StatefulSet.
//!
//! Phase 5 default: an unlock-socket emptyDir (memory-backed) shared between
//! attestation-proxy and enclava-init, plus an enclava-init-config ConfigMap.
//! Both PVCs are `volumeMode: Filesystem` because enclava-init formats them
//! as ext4 inside dm-crypt and then mounts the mapper as a filesystem — Block
//! mode breaks that hand-off.

use k8s_openapi::api::core::v1::{
    ConfigMapVolumeSource, EmptyDirVolumeSource, PersistentVolumeClaim, PersistentVolumeClaimSpec,
    Volume, VolumeResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use crate::manifest::containers::legacy_bootstrap_enabled;
use crate::manifest::enclava_init_config;
use crate::types::ConfidentialApp;

pub fn build_volumes(app: &ConfidentialApp) -> Vec<Volume> {
    let legacy = legacy_bootstrap_enabled();
    let mut v = vec![
        Volume {
            name: "logs".to_string(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Default::default()
        },
        Volume {
            name: "ownership-signal".to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: Some("Memory".to_string()),
                size_limit: Some(Quantity("1Mi".to_string())),
            }),
            ..Default::default()
        },
        Volume {
            name: "tenant-ingress-caddyfile".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: format!("{}-tenant-ingress", app.name),
                default_mode: Some(0o444),
                ..Default::default()
            }),
            ..Default::default()
        },
    ];

    if legacy {
        v.push(Volume {
            name: "secure-pv-bootstrap".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: "secure-pv-bootstrap-script".to_string(),
                default_mode: Some(0o555),
                ..Default::default()
            }),
            ..Default::default()
        });
        v.push(Volume {
            name: "startup".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: format!("{}-startup", app.name),
                default_mode: Some(0o755),
                ..Default::default()
            }),
            ..Default::default()
        });
    } else {
        v.push(Volume {
            name: "unlock-socket".to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: Some("Memory".to_string()),
                size_limit: Some(Quantity("1Mi".to_string())),
            }),
            ..Default::default()
        });
        v.push(Volume {
            name: "enclava-init-config".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: enclava_init_config::configmap_name(&app.name),
                default_mode: Some(0o400),
                ..Default::default()
            }),
            ..Default::default()
        });
    }
    v
}

pub fn build_volume_claim_templates(app: &ConfidentialApp) -> Vec<PersistentVolumeClaim> {
    let legacy = legacy_bootstrap_enabled();
    vec![
        build_vct("state", &app.storage.app_data.size, legacy),
        build_vct("tls-state", &app.storage.tls_data.size, legacy),
    ]
}

fn build_vct(name: &str, size: &str, legacy: bool) -> PersistentVolumeClaim {
    let mut requests = BTreeMap::new();
    requests.insert("storage".to_string(), Quantity(size.to_string()));
    // Filesystem mode is required by enclava-init's mount path: it opens the
    // LUKS device, formats ext4 if needed, and mounts /dev/mapper/<name>.
    // Block mode would hand the raw block device through and bypass mount.
    let volume_mode = if legacy { "Block" } else { "Filesystem" };

    PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            volume_mode: Some(volume_mode.to_string()),
            storage_class_name: Some("longhorn-wait".to_string()),
            resources: Some(VolumeResourceRequirements {
                requests: Some(requests),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}
