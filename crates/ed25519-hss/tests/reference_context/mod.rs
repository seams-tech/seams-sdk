use ed25519_hss::shared::{add_le_bytes_mod_2_256, clamp_rfc8032, CanonicalContext};

#[test]
fn addition_is_little_endian_and_wraps_mod_2_256() {
    let sum = add_le_bytes_mod_2_256([0xff; 32], {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    });
    assert_eq!(sum, [0u8; 32]);

    let mut left = [0u8; 32];
    left[0] = 0xff;
    left[1] = 0x01;
    let mut right = [0u8; 32];
    right[0] = 0x02;
    let sum = add_le_bytes_mod_2_256(left, right);
    assert_eq!(sum[0], 0x01);
    assert_eq!(sum[1], 0x02);
}

#[test]
fn clamp_matches_rfc8032_bit_rules() {
    let clamped = clamp_rfc8032([0xff; 32]);
    assert_eq!(clamped[0] & 0b0000_0111, 0);
    assert_eq!(clamped[31] & 0b1000_0000, 0);
    assert_eq!(clamped[31] & 0b0100_0000, 0b0100_0000);
}

#[test]
fn context_binding_normalizes_participant_ids() {
    let with_duplicates = CanonicalContext {
        application_binding_digest: [0x21; 32],
        participant_ids: vec![2, 1, 2],
    };
    let normalized = CanonicalContext {
        participant_ids: vec![1, 2],
        ..with_duplicates.clone()
    };

    assert_eq!(
        with_duplicates.binding_digest().expect("binding digest"),
        normalized.binding_digest().expect("binding digest"),
    );
}

#[test]
fn context_binding_changes_when_context_changes() {
    let left = CanonicalContext {
        application_binding_digest: [0x21; 32],
        participant_ids: vec![1, 2],
    };
    let right = CanonicalContext {
        application_binding_digest: [0x22; 32],
        ..left.clone()
    };

    assert_ne!(
        left.binding_digest().expect("left binding digest"),
        right.binding_digest().expect("right binding digest"),
    );
}
