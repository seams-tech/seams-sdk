use ed25519_yao_generator::{
    compile_phase4_private_output_activation_core_v1, compile_phase4_private_output_export_core_v1,
};

const VENDORED_ACTIVATION_SCHEDULE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/ed25519-yao/artifacts/passive-benchmark-v1/activation-private-output.schedule.bin"
));
const VENDORED_EXPORT_SCHEDULE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/ed25519-yao/artifacts/passive-benchmark-v1/export-private-output.schedule.bin"
));

#[test]
fn vendored_phase4_schedules_equal_fresh_joint_coin_generator_output() {
    let activation = compile_phase4_private_output_activation_core_v1();
    assert_eq!(
        VENDORED_ACTIVATION_SCHEDULE,
        activation.canonical_schedule_encoding()
    );
    assert_eq!(
        activation
            .benchmark_component_digest()
            .expose_public_bytes(),
        [
            0x65, 0xb0, 0x01, 0xc2, 0xf9, 0x4d, 0xe2, 0x7e, 0xe8, 0xcb, 0x9f, 0x0c, 0x07, 0x73,
            0xfb, 0xe5, 0x42, 0x58, 0xce, 0xab, 0x43, 0xd1, 0x83, 0x17, 0x4b, 0xee, 0x71, 0x0e,
            0xe8, 0xaa, 0x54, 0x6d,
        ]
    );
    assert_eq!(activation.metrics().and_gate_count(), 65_780);
    assert_eq!(activation.metrics().and_gate_count() * 32, 2_104_960);

    let export = compile_phase4_private_output_export_core_v1();
    assert_eq!(
        VENDORED_EXPORT_SCHEDULE,
        export.canonical_schedule_encoding()
    );
    assert_eq!(
        export.benchmark_component_digest().expose_public_bytes(),
        [
            0x31, 0xb0, 0x3d, 0x13, 0xe4, 0x1a, 0x72, 0x83, 0x42, 0xae, 0xdc, 0xe7, 0xaf, 0x40,
            0xf5, 0x40, 0x5d, 0xc5, 0x98, 0xd2, 0x8e, 0x78, 0x4d, 0xe4, 0x4d, 0x80, 0x44, 0xdb,
            0x9c, 0x60, 0x1a, 0x0c,
        ]
    );
    assert_eq!(export.metrics().and_gate_count(), 1_275);
    assert_eq!(export.metrics().and_gate_count() * 32, 40_800);
}
