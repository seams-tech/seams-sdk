use ed25519_yao_generator::{
    build_provisional_artifact_bundle_v1, ProvisionalArtifactBundleV1,
    PROVISIONAL_ARTIFACT_ACTIVATION_SCHEDULE_FILE_V1, PROVISIONAL_ARTIFACT_EXPORT_SCHEDULE_FILE_V1,
};

const VENDORED_ACTIVATION_SCHEDULE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/ed25519-yao/artifacts/passive-benchmark-v1/activation.schedule.bin"
));
const VENDORED_EXPORT_SCHEDULE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/ed25519-yao/artifacts/passive-benchmark-v1/export.schedule.bin"
));

fn entry_bytes<'a>(bundle: &'a ProvisionalArtifactBundleV1, filename: &str) -> &'a [u8] {
    for entry in bundle.entries() {
        if entry.filename() == filename {
            return entry.bytes();
        }
    }
    panic!("missing fixed bundle entry {filename}");
}

#[test]
fn vendored_phase3_schedules_equal_fresh_generator_output() {
    let bundle = build_provisional_artifact_bundle_v1();
    assert_eq!(
        VENDORED_ACTIVATION_SCHEDULE,
        entry_bytes(&bundle, PROVISIONAL_ARTIFACT_ACTIVATION_SCHEDULE_FILE_V1)
    );
    assert_eq!(
        VENDORED_EXPORT_SCHEDULE,
        entry_bytes(&bundle, PROVISIONAL_ARTIFACT_EXPORT_SCHEDULE_FILE_V1)
    );
}
