use ed25519_dalek::{Signer, SigningKey};
use router_ab_core::{
    MpcPrfShareCommitmentWireV1, Role, RootShareCommitmentRegistryV1, TranscriptBinding,
};
use router_ab_ecdsa_client_protocol::{
    authenticate_ecdsa_commitment_registry_v1, EcdsaCommitmentAuthorityV1,
    EcdsaCommitmentPolicyManifestV1, EcdsaCommitmentPolicyPinsV1, EcdsaCommitmentRegistryBindingV1,
    EcdsaCommitmentStatementV1, EcdsaDeriverRoleV1, EcdsaSignedCommitmentPolicyV1,
    EcdsaSignedCommitmentRecordV1,
};

pub fn authenticated_registry(
    transcript: &TranscriptBinding,
    signer_a_commitment: &MpcPrfShareCommitmentWireV1,
    signer_b_commitment: &MpcPrfShareCommitmentWireV1,
) -> RootShareCommitmentRegistryV1 {
    let release_key = SigningKey::from_bytes(&[91; 32]);
    let signer_a_key = SigningKey::from_bytes(&[92; 32]);
    let signer_b_key = SigningKey::from_bytes(&[93; 32]);
    let signer_a_identity = signer_identity(transcript, Role::SignerA);
    let signer_b_identity = signer_identity(transcript, Role::SignerB);
    let manifest = EcdsaCommitmentPolicyManifestV1 {
        release_epoch: 1,
        minimum_root_version: 1,
        minimum_authority_key_epoch: 1,
        revoked_authority_key_epochs: Vec::new(),
        revoked_record_digests: Vec::new(),
        signer_a_authority: authority(EcdsaDeriverRoleV1::A, signer_a_identity, &signer_a_key),
        signer_b_authority: authority(EcdsaDeriverRoleV1::B, signer_b_identity, &signer_b_key),
    };
    let manifest_digest = manifest.digest().expect("commitment manifest digest");
    let policy = EcdsaSignedCommitmentPolicyV1 {
        release_authority_signature: release_key
            .sign(&manifest.signing_bytes().expect("commitment manifest bytes"))
            .to_bytes(),
        manifest,
        manifest_digest,
    };
    let binding = EcdsaCommitmentRegistryBindingV1 {
        now_ms: 10,
        root_share_epoch: transcript.context().root_share_epoch().as_str().to_owned(),
        signer_a_identity: signer_a_identity.to_owned(),
        signer_b_identity: signer_b_identity.to_owned(),
    };
    let signer_a_record = record(
        EcdsaDeriverRoleV1::A,
        signer_a_identity,
        &binding.root_share_epoch,
        signer_a_commitment,
        &signer_a_key,
    );
    let signer_b_record = record(
        EcdsaDeriverRoleV1::B,
        signer_b_identity,
        &binding.root_share_epoch,
        signer_b_commitment,
        &signer_b_key,
    );
    let authenticated = authenticate_ecdsa_commitment_registry_v1(
        &EcdsaCommitmentPolicyPinsV1 {
            release_authority_public_key: release_key.verifying_key().to_bytes(),
            exact_policy_digest: manifest_digest,
            minimum_release_epoch: 1,
        },
        &policy,
        &binding,
        &signer_a_record,
        &signer_b_record,
    )
    .expect("shared client commitment verifier");
    RootShareCommitmentRegistryV1::from_client_authenticated(
        &authenticated,
        &binding,
        &signer_a_record,
        &signer_b_record,
    )
    .expect("core commitment adapter")
}

fn signer_identity(transcript: &TranscriptBinding, role: Role) -> &str {
    transcript
        .signer_set()
        .signer_for_role(role)
        .expect("signer role")
        .signer_id()
}

fn authority(
    role: EcdsaDeriverRoleV1,
    operator_identity: &str,
    signing_key: &SigningKey,
) -> EcdsaCommitmentAuthorityV1 {
    EcdsaCommitmentAuthorityV1 {
        role,
        operator_identity: operator_identity.to_owned(),
        authority_key_epoch: 1,
        valid_from_ms: 1,
        valid_until_ms: 1_000,
        verifying_key: signing_key.verifying_key().to_bytes(),
    }
}

fn record(
    role: EcdsaDeriverRoleV1,
    operator_identity: &str,
    root_share_epoch: &str,
    commitment: &MpcPrfShareCommitmentWireV1,
    signing_key: &SigningKey,
) -> EcdsaSignedCommitmentRecordV1 {
    let share_id = match role {
        EcdsaDeriverRoleV1::A => 1,
        EcdsaDeriverRoleV1::B => 2,
    };
    let commitment_wire = commitment
        .as_bytes()
        .try_into()
        .expect("fixed commitment wire");
    let statement = EcdsaCommitmentStatementV1 {
        role,
        share_id,
        root_id: "root-1".to_owned(),
        root_version: 1,
        root_share_epoch: root_share_epoch.to_owned(),
        commitment_wire,
        operator_identity: operator_identity.to_owned(),
        authority_key_epoch: 1,
        valid_from_ms: 1,
        valid_until_ms: 1_000,
    };
    EcdsaSignedCommitmentRecordV1 {
        signed_digest: statement.digest().expect("commitment statement digest"),
        signature: signing_key
            .sign(
                &statement
                    .signing_bytes()
                    .expect("commitment statement bytes"),
            )
            .to_bytes(),
        statement,
    }
}
