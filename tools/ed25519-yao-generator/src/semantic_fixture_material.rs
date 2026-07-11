//! Canonical host-only synthetic source material for semantic fixture generation.

use curve25519_dalek::scalar::Scalar;

use crate::ceremony_context::CeremonyActivationEpochV1;
use crate::kdf_fixtures::{
    canonical_registered_public_key_v1, canonical_synthetic_kdf_material_v1,
    SYNTHETIC_CLIENT_ROOT_V1, SYNTHETIC_DERIVER_A_ROOT_V1, SYNTHETIC_DERIVER_B_ROOT_V1,
};
use crate::authenticated_store::AuthenticatedRegisteredStoreResolutionV1;
use crate::lifecycle_domain::{RecoveryRequestV1, RefreshRequestV1, RegistrationRequestV1};
use crate::provenance::RoleInputProvenancePairV1;
use crate::registration_evaluation_admission::{
    accept_host_only_registration_admission_v1, AcceptedRegistrationAdmissionV1,
    OpaqueRegistrationInputSelectionEvidenceDigest32V1, RegistrationAdmissionCheckedAtUnixMsV1,
    RegistrationSelectionAttemptId32V1,
};
use crate::recovery_evaluation_admission::{
    accept_host_only_recovery_admission_v1, AcceptedRecoveryAdmissionV1,
    OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1,
    RecoveryAdmissionCheckedAtUnixMsV1,
};
use crate::refresh_evaluation_admission::{
    accept_host_only_refresh_admission_v1, AcceptedRefreshAdmissionV1,
    OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1,
    RefreshAdmissionCheckedAtUnixMsV1,
};
use crate::semantic_artifacts::OneUseExecutionId32V1;
use crate::semantic_artifacts::{
    OpaqueHostReferenceActivationDeriverAClientPackageBindingsV1,
    OpaqueHostReferenceActivationDeriverBClientPackageBindingsV1,
    OpaqueHostReferenceActivationPackageBindingsV1,
    OpaqueHostReferenceDeriverASigningWorkerPackageBindingsV1,
    OpaqueHostReferenceDeriverBSigningWorkerPackageBindingsV1,
    OpaqueHostReferenceExportDeriverAClientPackageBindingsV1,
    OpaqueHostReferenceExportDeriverBClientPackageBindingsV1,
    OpaqueHostReferenceExportPackageBindingsV1, OpaqueHostReferenceOutputBindingDigest32V1,
    OpaqueHostReferencePackageAuthenticationDigest32V1,
    OpaqueHostReferenceRecipientCiphertextDigest32V1,
    OpaqueHostReferenceRecipientProtectionDigest32V1, SemanticCiphertextLengthV1,
};
use crate::{
    DeriverAContribution, DeriverBContribution, HostOnlyActivationOutputCoinsV1,
    HostOnlyClientScalarOutputCoinV1, HostOnlyExportIdealCoinV1, HostOnlyExportReferenceInputsV1,
    HostOnlyRecoveryIdealCoinsV1, HostOnlyRecoveryReferenceInputsV1, HostOnlyRefreshIdealCoinsV1,
    HostOnlyRefreshReferenceInputsV1, HostOnlyRegistrationIdealCoinsV1,
    HostOnlyRegistrationReferenceInputsV1, HostOnlySeedOutputCoinV1,
    HostOnlySigningWorkerScalarOutputCoinV1, RegisteredEd25519PublicKey32V1,
    StableKeyDerivationContext, SyntheticClientDerivationRootV1, SyntheticDeriverADerivationRootV1,
    SyntheticDeriverBDerivationRootV1,
};
use crate::{
    HostOnlyDeriverARefreshDeltaContributionV1, HostOnlyDeriverBRefreshDeltaContributionV1,
    HostOnlyJointRefreshDeltaCoinsV1,
};

pub(crate) struct ReferenceFixture {
    pub(crate) context: StableKeyDerivationContext,
    pub(crate) client_root: SyntheticClientDerivationRootV1,
    pub(crate) deriver_a_root: SyntheticDeriverADerivationRootV1,
    pub(crate) deriver_b_root: SyntheticDeriverBDerivationRootV1,
    pub(crate) deriver_a: DeriverAContribution,
    pub(crate) deriver_b: DeriverBContribution,
    pub(crate) registered_public_key: RegisteredEd25519PublicKey32V1,
}

pub(crate) fn reference_fixture() -> ReferenceFixture {
    let material = canonical_synthetic_kdf_material_v1();
    ReferenceFixture {
        context: material.context,
        client_root: SyntheticClientDerivationRootV1::from_fixture_bytes(SYNTHETIC_CLIENT_ROOT_V1),
        deriver_a_root: SyntheticDeriverADerivationRootV1::from_fixture_bytes(
            SYNTHETIC_DERIVER_A_ROOT_V1,
        ),
        deriver_b_root: SyntheticDeriverBDerivationRootV1::from_fixture_bytes(
            SYNTHETIC_DERIVER_B_ROOT_V1,
        ),
        deriver_a: material.deriver_a,
        deriver_b: material.deriver_b,
        registered_public_key: canonical_registered_public_key_v1(),
    }
}

pub(crate) fn registration_admission(
    request: &RegistrationRequestV1,
    provenance: &RoleInputProvenancePairV1,
    activation_epoch: CeremonyActivationEpochV1,
    one_use_execution_id: OneUseExecutionId32V1,
) -> AcceptedRegistrationAdmissionV1 {
    accept_host_only_registration_admission_v1(
        request,
        provenance,
        activation_epoch,
        one_use_execution_id,
        RegistrationAdmissionCheckedAtUnixMsV1::new(
            request.request_context().request_expiry().value(),
        )
        .expect("registration admission time"),
        RegistrationSelectionAttemptId32V1::new([0x90; 32])
            .expect("registration selection attempt"),
        OpaqueRegistrationInputSelectionEvidenceDigest32V1::new([0x91; 32])
            .expect("registration input-selection evidence"),
    )
    .expect("canonical registration admission")
}

pub(crate) fn recovery_admission(
    request: &RecoveryRequestV1,
    provenance: &RoleInputProvenancePairV1,
    state: AuthenticatedRegisteredStoreResolutionV1,
    activation_epoch: CeremonyActivationEpochV1,
    one_use_execution_id: OneUseExecutionId32V1,
) -> AcceptedRecoveryAdmissionV1 {
    accept_host_only_recovery_admission_v1(
        request,
        provenance,
        state,
        activation_epoch,
        one_use_execution_id,
        RecoveryAdmissionCheckedAtUnixMsV1::new(
            request.request_context().request_expiry().value(),
        )
        .expect("recovery admission time"),
        OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1::new([0x92; 32])
            .expect("recovery continuity acceptance evidence"),
    )
    .expect("canonical recovery admission")
}

pub(crate) fn refresh_admission(
    request: &RefreshRequestV1,
    provenance: &RoleInputProvenancePairV1,
    state: AuthenticatedRegisteredStoreResolutionV1,
    activation_epoch: CeremonyActivationEpochV1,
    one_use_execution_id: OneUseExecutionId32V1,
) -> AcceptedRefreshAdmissionV1 {
    accept_host_only_refresh_admission_v1(
        request,
        provenance,
        state,
        activation_epoch,
        one_use_execution_id,
        RefreshAdmissionCheckedAtUnixMsV1::new(
            request.request_context().request_expiry().value(),
        )
        .expect("refresh admission time"),
        OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1::new([0x93; 32])
            .expect("refresh transition acceptance evidence"),
    )
    .expect("canonical refresh admission")
}

pub(crate) fn activation_coins(client: u64, worker: u64) -> HostOnlyActivationOutputCoinsV1 {
    HostOnlyActivationOutputCoinsV1::new(
        HostOnlyClientScalarOutputCoinV1::from_canonical_fixture_bytes(scalar_bytes(client))
            .expect("client coin is canonical"),
        HostOnlySigningWorkerScalarOutputCoinV1::from_canonical_fixture_bytes(scalar_bytes(worker))
            .expect("SigningWorker coin is canonical"),
    )
}

pub(crate) fn export_coin() -> HostOnlySeedOutputCoinV1 {
    HostOnlySeedOutputCoinV1::from_fixture_bytes([0x77; 32])
}

pub(crate) fn registration_ideal_coins(
    client: u64,
    worker: u64,
) -> HostOnlyRegistrationIdealCoinsV1 {
    HostOnlyRegistrationIdealCoinsV1::from_host_only_fixture(activation_coins(client, worker))
}

pub(crate) fn recovery_ideal_coins(client: u64, worker: u64) -> HostOnlyRecoveryIdealCoinsV1 {
    HostOnlyRecoveryIdealCoinsV1::from_host_only_fixture(activation_coins(client, worker))
}

pub(crate) fn refresh_ideal_coins(client: u64, worker: u64) -> HostOnlyRefreshIdealCoinsV1 {
    HostOnlyRefreshIdealCoinsV1::from_host_only_fixture(activation_coins(client, worker))
}

pub(crate) fn export_ideal_coin() -> HostOnlyExportIdealCoinV1 {
    HostOnlyExportIdealCoinV1::from_host_only_fixture(export_coin())
}

pub(crate) fn registration_inputs(
    fixture: &ReferenceFixture,
) -> HostOnlyRegistrationReferenceInputsV1<'_> {
    HostOnlyRegistrationReferenceInputsV1::new(
        &fixture.client_root,
        &fixture.deriver_a_root,
        &fixture.deriver_b_root,
        &fixture.context,
    )
}

pub(crate) fn recovery_inputs(fixture: &ReferenceFixture) -> HostOnlyRecoveryReferenceInputsV1<'_> {
    HostOnlyRecoveryReferenceInputsV1::new(
        &fixture.client_root,
        &fixture.client_root,
        &fixture.context,
        &fixture.deriver_a,
        &fixture.deriver_b,
    )
}

pub(crate) fn refresh_inputs(fixture: &ReferenceFixture) -> HostOnlyRefreshReferenceInputsV1<'_> {
    HostOnlyRefreshReferenceInputsV1::new(
        &fixture.deriver_a,
        &fixture.deriver_b,
        HostOnlyJointRefreshDeltaCoinsV1::new(
            HostOnlyDeriverARefreshDeltaContributionV1::from_host_only_fixture(
                [0x3c; 32],
                Scalar::from(5_u64).to_bytes(),
            )
            .expect("Deriver A refresh contribution is valid"),
            HostOnlyDeriverBRefreshDeltaContributionV1::from_host_only_fixture(
                [0x69; 32],
                Scalar::from(12_u64).to_bytes(),
            )
            .expect("Deriver B refresh contribution is valid"),
        ),
    )
}

pub(crate) fn export_inputs(fixture: &ReferenceFixture) -> HostOnlyExportReferenceInputsV1<'_> {
    HostOnlyExportReferenceInputsV1::new(
        fixture.deriver_a.y_client(),
        fixture.deriver_a.y_server(),
        fixture.deriver_b.y_client(),
        fixture.deriver_b.y_server(),
    )
}

struct PackageBindingComponents {
    protection: OpaqueHostReferenceRecipientProtectionDigest32V1,
    ciphertext: OpaqueHostReferenceRecipientCiphertextDigest32V1,
    length: SemanticCiphertextLengthV1,
    output: OpaqueHostReferenceOutputBindingDigest32V1,
    authentication: OpaqueHostReferencePackageAuthenticationDigest32V1,
}

fn package_binding_components(
    seed: u8,
    ciphertext_digest_byte: u8,
    ciphertext_length: u64,
) -> PackageBindingComponents {
    PackageBindingComponents {
        protection: OpaqueHostReferenceRecipientProtectionDigest32V1::new([seed; 32])
            .expect("recipient protection"),
        ciphertext: OpaqueHostReferenceRecipientCiphertextDigest32V1::new(
            [ciphertext_digest_byte; 32],
        )
        .expect("ciphertext digest"),
        length: SemanticCiphertextLengthV1::new(ciphertext_length).expect("ciphertext length"),
        output: OpaqueHostReferenceOutputBindingDigest32V1::new([seed.wrapping_add(2); 32])
            .expect("output binding"),
        authentication: OpaqueHostReferencePackageAuthenticationDigest32V1::new(
            [seed.wrapping_add(3); 32],
        )
        .expect("package authentication"),
    }
}

fn activation_a_client_bindings(
    ciphertext_digest_byte: u8,
    ciphertext_length: u64,
) -> OpaqueHostReferenceActivationDeriverAClientPackageBindingsV1 {
    let value = package_binding_components(0x81, ciphertext_digest_byte, ciphertext_length);
    OpaqueHostReferenceActivationDeriverAClientPackageBindingsV1::new(
        value.protection,
        value.ciphertext,
        value.length,
        value.output,
        value.authentication,
    )
}

fn activation_b_client_bindings() -> OpaqueHostReferenceActivationDeriverBClientPackageBindingsV1 {
    let value = package_binding_components(0x85, 0x86, 197);
    OpaqueHostReferenceActivationDeriverBClientPackageBindingsV1::new(
        value.protection,
        value.ciphertext,
        value.length,
        value.output,
        value.authentication,
    )
}

fn deriver_a_worker_bindings() -> OpaqueHostReferenceDeriverASigningWorkerPackageBindingsV1 {
    let value = package_binding_components(0x89, 0x8a, 211);
    OpaqueHostReferenceDeriverASigningWorkerPackageBindingsV1::new(
        value.protection,
        value.ciphertext,
        value.length,
        value.output,
        value.authentication,
    )
}

fn deriver_b_worker_bindings() -> OpaqueHostReferenceDeriverBSigningWorkerPackageBindingsV1 {
    let value = package_binding_components(0x8d, 0x8e, 223);
    OpaqueHostReferenceDeriverBSigningWorkerPackageBindingsV1::new(
        value.protection,
        value.ciphertext,
        value.length,
        value.output,
        value.authentication,
    )
}

pub(crate) fn activation_bindings_with_a_client(
    ciphertext_digest_byte: u8,
    ciphertext_length: u64,
) -> OpaqueHostReferenceActivationPackageBindingsV1 {
    OpaqueHostReferenceActivationPackageBindingsV1::new(
        activation_a_client_bindings(ciphertext_digest_byte, ciphertext_length),
        activation_b_client_bindings(),
        deriver_a_worker_bindings(),
        deriver_b_worker_bindings(),
    )
}

pub(crate) fn activation_bindings() -> OpaqueHostReferenceActivationPackageBindingsV1 {
    activation_bindings_with_a_client(0x82, 193)
}

pub(crate) fn export_bindings() -> OpaqueHostReferenceExportPackageBindingsV1 {
    let a = package_binding_components(0x91, 0x92, 181);
    let b = package_binding_components(0x95, 0x96, 185);
    OpaqueHostReferenceExportPackageBindingsV1::new(
        OpaqueHostReferenceExportDeriverAClientPackageBindingsV1::new(
            a.protection,
            a.ciphertext,
            a.length,
            a.output,
            a.authentication,
        ),
        OpaqueHostReferenceExportDeriverBClientPackageBindingsV1::new(
            b.protection,
            b.ciphertext,
            b.length,
            b.output,
            b.authentication,
        ),
    )
}

fn scalar_bytes(value: u64) -> [u8; 32] {
    let mut output = [0; 32];
    output[..8].copy_from_slice(&value.to_le_bytes());
    output
}
