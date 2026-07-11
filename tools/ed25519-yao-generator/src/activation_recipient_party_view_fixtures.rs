//! Deterministic host fixtures for post-release activation recipient views.

use ed25519_dalek::{Signer, SigningKey};

use crate::activation_delivery::{
    HostOnlyActivationClientReleasedV1, HostOnlyActivationRecipientReleaseEvidenceV1,
    HostOnlyActivationRecipientsReleasedV1,
};
use crate::ceremony_context::CeremonySigningWorkerBindingV1;
use crate::lifecycle_domain::{ActivationMetadataConsumptionSuccessV1, ActivationPackageOriginV1};
use crate::output_sharing::reconstruct_host_only_signing_worker_scalar_output_v1;
use crate::semantic_artifacts::{
    OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1,
    OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1,
};
use crate::semantic_lifecycle_fixtures::canonical_activation_metadata_success_v1;
use crate::signing_worker_activation::{
    host_fixture_opened_signing_worker_shares_v1, origin_request_context,
    prepare_signing_worker_activation_v1, SigningWorkerActivationReceiptSignature64V1,
    SigningWorkerActivationSuccessV1, SigningWorkerOutputStorageReceiptDigest32V1,
    SigningWorkerReceiptKeyEpochV1, SigningWorkerReceiptVerifyingKeyV1,
};
use crate::CanonicalScalarBytes;

/// Canonical retained Client and strictly verified SigningWorker activation.
pub(crate) struct HostOnlyActivatedRecipientFixtureV1 {
    client: HostOnlyActivationClientReleasedV1,
    signing_worker: SigningWorkerActivationSuccessV1,
    x_server_base: CanonicalScalarBytes,
}

impl HostOnlyActivatedRecipientFixtureV1 {
    pub(crate) fn into_recipient_states(
        self,
    ) -> (
        HostOnlyActivationClientReleasedV1,
        SigningWorkerActivationSuccessV1,
    ) {
        (self.client, self.signing_worker)
    }

    #[cfg(test)]
    pub(crate) const fn client(&self) -> &HostOnlyActivationClientReleasedV1 {
        &self.client
    }

    #[cfg(test)]
    pub(crate) const fn signing_worker(&self) -> &SigningWorkerActivationSuccessV1 {
        &self.signing_worker
    }

    pub(crate) const fn x_server_base(&self) -> &CanonicalScalarBytes {
        &self.x_server_base
    }
}

pub(crate) fn canonical_activation_recipients_released_v1(
    origin: ActivationPackageOriginV1,
) -> HostOnlyActivationRecipientsReleasedV1 {
    let metadata = canonical_activation_metadata_success_v1(origin);
    let evidence = canonical_release_evidence(&metadata, origin);
    metadata
        .release_recipients_v1(evidence)
        .expect("canonical activation recipient release")
}

pub(crate) fn canonical_activated_recipient_fixture_v1(
    origin: ActivationPackageOriginV1,
) -> HostOnlyActivatedRecipientFixtureV1 {
    let metadata = canonical_activation_metadata_success_v1(origin);
    let output = metadata.post_state().committed_output();
    let x_server_base = reconstruct_host_only_signing_worker_scalar_output_v1(
        output.shares().deriver_a().signing_worker(),
        output.shares().deriver_b().signing_worker(),
    );
    let worker = origin_request_context(metadata.post_state())
        .signing_worker_binding()
        .clone();
    let (opened_a, opened_b) = host_fixture_opened_signing_worker_shares_v1(&metadata);
    let evidence = canonical_release_evidence(&metadata, origin);
    let (client, release_authority) = metadata
        .release_recipients_v1(evidence)
        .expect("canonical activation recipient release")
        .into_capabilities();
    let signing_key = SigningKey::from_bytes(&[0x61 + origin_index(origin); 32]);
    let verifying_key = signing_key.verifying_key().to_bytes();
    let authority = canonical_receipt_authority(&worker, verifying_key);
    let prepared = prepare_signing_worker_activation_v1(
        release_authority,
        worker,
        opened_a,
        opened_b,
        SigningWorkerOutputStorageReceiptDigest32V1::new([0xc1 + origin_index(origin); 32])
            .expect("storage evidence"),
        &authority,
    )
    .expect("canonical worker activation preparation");
    let signature = SigningWorkerActivationReceiptSignature64V1::from_bytes(
        signing_key
            .sign(&prepared.signing_bytes().expect("activation receipt bytes"))
            .to_bytes(),
    );
    let signing_worker = prepared
        .verify_receipt(signature, &authority)
        .expect("canonical worker activation receipt");
    HostOnlyActivatedRecipientFixtureV1 {
        client,
        signing_worker,
        x_server_base,
    }
}

fn canonical_release_evidence(
    metadata: &ActivationMetadataConsumptionSuccessV1,
    origin: ActivationPackageOriginV1,
) -> HostOnlyActivationRecipientReleaseEvidenceV1 {
    HostOnlyActivationRecipientReleaseEvidenceV1::for_metadata_consumed(
        metadata,
        OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1::new(
            [0xa1 + origin_index(origin); 32],
        )
        .expect("client delivery evidence"),
        OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1::new(
            [0xb1 + origin_index(origin); 32],
        )
        .expect("SigningWorker delivery evidence"),
    )
}

fn canonical_receipt_authority(
    worker: &CeremonySigningWorkerBindingV1,
    verifying_key: [u8; 32],
) -> SigningWorkerReceiptVerifyingKeyV1 {
    SigningWorkerReceiptVerifyingKeyV1::parse(
        worker.clone(),
        SigningWorkerReceiptKeyEpochV1::new(3).expect("receipt key epoch"),
        verifying_key,
    )
    .expect("receipt authority")
}

const fn origin_index(origin: ActivationPackageOriginV1) -> u8 {
    match origin {
        ActivationPackageOriginV1::Registration => 0,
        ActivationPackageOriginV1::Recovery => 1,
        ActivationPackageOriginV1::Refresh => 2,
    }
}
