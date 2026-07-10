use ed25519_yao_generator::{
    ParticipantPosition, StableKeyDerivationContext, StableKeyDerivationContextError,
    STABLE_KEY_DERIVATION_CONTEXT_DOMAIN_V1, STABLE_KEY_DERIVATION_CONTEXT_ENCODED_LEN,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn context_encoding_is_golden_and_order_independent() {
    let digest = [0x42; 32];
    let forward = StableKeyDerivationContext::new(digest, 1, 2).expect("valid context");
    let reversed = StableKeyDerivationContext::new(digest, 2, 1).expect("valid context");

    assert_eq!(forward.participant_ids().as_array(), [1, 2]);
    assert_eq!(reversed.participant_ids().as_array(), [1, 2]);
    assert_eq!(forward.encode().as_bytes(), reversed.encode().as_bytes());
    assert_eq!(
        forward.binding_digest().as_bytes(),
        reversed.binding_digest().as_bytes()
    );
    assert_eq!(
        forward.encode().as_bytes().len(),
        STABLE_KEY_DERIVATION_CONTEXT_ENCODED_LEN
    );
    assert_eq!(
        &forward.encode().as_bytes()[..STABLE_KEY_DERIVATION_CONTEXT_DOMAIN_V1.len()],
        STABLE_KEY_DERIVATION_CONTEXT_DOMAIN_V1
    );
    assert_eq!(
        hex(forward.encode().as_bytes()),
        "7365616d732f726f757465722d61622f656432353531392d79616f2f737461626c652d6b65792d636f6e746578742f7631\
         4242424242424242424242424242424242424242424242424242424242424242\
         00010002"
    );
    assert_eq!(
        hex(forward.binding_digest().as_bytes()),
        "ce5305908b0c31bfe09072b549cb349b0c901f7d3fde60c63fa8e2dfb088a42d"
    );
}

#[test]
fn context_rejects_zero_and_duplicate_participants_without_filtering() {
    assert_eq!(
        StableKeyDerivationContext::new([0u8; 32], 0, 2).err(),
        Some(StableKeyDerivationContextError::ZeroParticipantId {
            position: ParticipantPosition::First,
        })
    );
    assert_eq!(
        StableKeyDerivationContext::new([0u8; 32], 1, 0).err(),
        Some(StableKeyDerivationContextError::ZeroParticipantId {
            position: ParticipantPosition::Second,
        })
    );
    assert_eq!(
        StableKeyDerivationContext::new([0u8; 32], 7, 7).err(),
        Some(StableKeyDerivationContextError::DuplicateParticipantIds)
    );
}

#[test]
fn every_context_component_changes_the_binding() {
    let baseline = StableKeyDerivationContext::new([0x11; 32], 1, 2).expect("valid context");
    let changed_digest = StableKeyDerivationContext::new([0x12; 32], 1, 2).expect("valid context");
    let changed_participant =
        StableKeyDerivationContext::new([0x11; 32], 1, 3).expect("valid context");

    assert_ne!(
        baseline.binding_digest().as_bytes(),
        changed_digest.binding_digest().as_bytes()
    );
    assert_ne!(
        baseline.binding_digest().as_bytes(),
        changed_participant.binding_digest().as_bytes()
    );
}
