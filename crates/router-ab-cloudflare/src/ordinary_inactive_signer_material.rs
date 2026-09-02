use crate::hpke::cloudflare_hpke_x25519_public_key_bytes_v1;
use crate::{
    activate_cloudflare_signing_worker_server_output_v1, cloudflare_now_unix_ms_v1,
    cloudflare_server_output_material_record_from_activation_request_v1,
    compare_and_set_cloudflare_signing_worker_private_d1_secret_v1,
    delete_cloudflare_signing_worker_output_activation_by_active_key_v1,
    derive_registration_source_relayer_share_v1, encode_base64url_bytes_v1,
    load_cloudflare_server_output_hpke_private_key_bytes_v1,
    load_cloudflare_signing_worker_private_d1_secret_v1,
    seal_cloudflare_signer_envelope_hpke_payload_v1, CloudflareEcdsaRegistrationSourceDerivationV1,
    CloudflareSecretMaterial32V1, CloudflareServerOutputMaterialRecordV1,
    CloudflareSignerEnvelopeHpkePublicKeyV1, CloudflareSigningWorkerOutputActivationReceiptV1,
    CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    CloudflareSigningWorkerRuntimeV1, SOURCE_PRESERVING_ECDSA_MATERIAL_HANDLE_PREFIX_V1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use router_ab_core::{
    decode_and_validate_signer_envelope_hpke_payload_v1, ActiveSigningWorkerStateV1,
    EncryptedPayloadV1, ExpensiveWorkKindV1, MpcMaterialActivationRefV1, OpenedShareKind,
    PublicDigest32, Role, RoleEncryptedEnvelopeV1,
    RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1,
    RouterAbEcdsaDerivationRegistrationBootstrapRequestV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, ServerIdentityV1,
};
use router_ab_ecdsa_client_protocol::{
    open_linked_device_ecdsa_source_contribution_v1,
    seal_linked_device_ecdsa_source_contribution_v1,
    LinkedDeviceEcdsaEncryptedSourceContributionV1, LinkedDeviceEcdsaSourceContributionBindingV1,
    LinkedDeviceEcdsaSourceContributionPackageV1,
};
use router_ab_ecdsa_derivation::{
    rebind_ecdsa_lane_relayer_share_bytes_v1, EcdsaLaneDelta, EcdsaLanePublicIdentityBindingV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Env, Request, Response};
use zeroize::{Zeroize, Zeroizing};

pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_RESERVE_INACTIVE_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/reserve-inactive";
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_RESERVE_INACTIVE_SOURCE_PRESERVING_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/reserve-inactive-source-preserving";
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_ACTIVATE_RESERVATION_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/activate-reservation";
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_DEACTIVATE_RESERVATION_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/deactivate-reservation";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEcdsaInactiveMaterialReservationRequestV1 {
    pub registration: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    pub activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
}

impl CloudflareEcdsaInactiveMaterialReservationRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.registration.validate()?;
        self.activation.validate()?;
        if self.activation.activation_context.lifecycle.work_kind
            != ExpensiveWorkKindV1::RegistrationPrepare
        {
            return Err(invalid_reservation(
                "ordinary ECDSA reservation requires a registration activation context",
            ));
        }
        let public_request = self.registration.to_threshold_prf_request()?;
        let context = &self.activation.activation_context;
        if self.registration.lifecycle != context.lifecycle
            || self.registration.signer_set != context.signer_set
            || public_request.transcript_digest != context.transcript_digest
        {
            return Err(invalid_reservation(
                "ordinary ECDSA reservation registration does not match its activation context",
            ));
        }
        Ok(())
    }
}

/// One linked-device source contribution consumed by the SigningWorker.
///
/// The encrypted delta is accepted at this boundary and is never included in
/// the durable reservation state. Replays are keyed by the complete public
/// contribution binding and return the committed target packages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEcdsaSourcePreservingInactiveMaterialReservationRequestV1 {
    pub source_derivation: CloudflareEcdsaRegistrationSourceDerivationV1,
    pub source_contribution: LinkedDeviceEcdsaSourceContributionPackageV1,
}

impl CloudflareEcdsaSourcePreservingInactiveMaterialReservationRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.source_derivation.validate()?;
        self.source_contribution.validate().map_err(|error| {
            invalid_reservation(format!(
                "linked-device ECDSA source contribution is invalid: {error:?}"
            ))
        })
    }

    fn target_material_activation(&self) -> RouterAbProtocolResult<MpcMaterialActivationRefV1> {
        mpc_material_activation_from_ecdsa_ref_v1(
            &self.source_contribution.binding.target.activation,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEcdsaActivateReservationRequestV1 {
    pub material_activation: MpcMaterialActivationRefV1,
    pub reservation_id: String,
}

impl CloudflareEcdsaActivateReservationRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.material_activation.validate()?;
        require_reservation_id(&self.reservation_id)
    }

    fn matches(
        &self,
        reservation_id: &str,
        material_activation: &MpcMaterialActivationRefV1,
    ) -> bool {
        self.reservation_id == reservation_id && &self.material_activation == material_activation
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEcdsaDeactivateReservationRequestV1 {
    pub material_activation: MpcMaterialActivationRefV1,
}

impl CloudflareEcdsaDeactivateReservationRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.material_activation.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEcdsaInactiveMaterialReservationResponseV1 {
    pub state: &'static str,
    pub reservation_id: String,
    pub material_activation: MpcMaterialActivationRefV1,
    pub deriver_a_client_package: RoleEncryptedEnvelopeV1,
    pub deriver_b_client_package: RoleEncryptedEnvelopeV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEcdsaSourcePreservingInactiveMaterialReservationResponseV1 {
    pub state: &'static str,
    pub reservation_id: String,
    pub material_activation: MpcMaterialActivationRefV1,
    pub binding: LinkedDeviceEcdsaSourceContributionBindingV1,
    pub source_derivation: CloudflareEcdsaRegistrationSourceDerivationV1,
    pub target_relayer_public_key33_b64u: String,
    pub threshold_public_key33_b64u: String,
    pub threshold_ethereum_address20_b64u: String,
    pub encrypted_target_client_share: LinkedDeviceEcdsaEncryptedSourceContributionV1,
    pub encrypted_target_server_share: LinkedDeviceEcdsaEncryptedSourceContributionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EcdsaClientPackagePairV1 {
    deriver_a_client_package: RoleEncryptedEnvelopeV1,
    deriver_b_client_package: RoleEncryptedEnvelopeV1,
}

impl EcdsaClientPackagePairV1 {
    fn validate_for_registration(
        &self,
        registration: &RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    ) -> RouterAbProtocolResult<()> {
        validate_client_package_v1(registration, Role::SignerA, &self.deriver_a_client_package)?;
        validate_client_package_v1(registration, Role::SignerB, &self.deriver_b_client_package)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEcdsaReservationActivationResponseV1 {
    pub receipt: CloudflareSigningWorkerOutputActivationReceiptV1,
}

pub type CloudflareEcdsaSourcePreservingReservationActivationResponseV1 =
    CloudflareEcdsaSourcePreservingInactiveMaterialReservationResponseV1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEcdsaReservationDeactivationResponseV1 {
    pub state: &'static str,
    pub reservation_id: String,
    pub material_activation: MpcMaterialActivationRefV1,
    pub revoked_at_ms: u64,
}

enum EcdsaReservationActivationResultV1 {
    Ordinary(CloudflareSigningWorkerOutputActivationReceiptV1),
    SourcePreserving(CloudflareEcdsaSourcePreservingReservationActivationResponseV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum EcdsaReservationStateV1 {
    Inactive {
        registration: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        material: CloudflareServerOutputMaterialRecordV1,
        material_activation: MpcMaterialActivationRefV1,
        reservation_id: String,
        client_packages: EcdsaClientPackagePairV1,
    },
    Activating {
        registration: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        material: CloudflareServerOutputMaterialRecordV1,
        material_activation: MpcMaterialActivationRefV1,
        reservation_id: String,
        client_packages: EcdsaClientPackagePairV1,
    },
    Active {
        registration: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        material: CloudflareServerOutputMaterialRecordV1,
        material_activation: MpcMaterialActivationRefV1,
        reservation_id: String,
        client_packages: EcdsaClientPackagePairV1,
        receipt: CloudflareSigningWorkerOutputActivationReceiptV1,
    },
    Revoked {
        registration: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        material_activation: MpcMaterialActivationRefV1,
        reservation_id: String,
        revoked_at_ms: u64,
    },
    Deactivating {
        registration: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        material_activation: MpcMaterialActivationRefV1,
        reservation_id: String,
        revoked_at_ms: u64,
    },
    SourcePreservingInactive {
        binding: LinkedDeviceEcdsaSourceContributionBindingV1,
        source_derivation: CloudflareEcdsaRegistrationSourceDerivationV1,
        material_activation: MpcMaterialActivationRefV1,
        reservation_id: String,
        target_relayer_public_key33_b64u: String,
        threshold_public_key33_b64u: String,
        threshold_ethereum_address20_b64u: String,
        encrypted_target_client_share: LinkedDeviceEcdsaEncryptedSourceContributionV1,
        encrypted_target_server_share: LinkedDeviceEcdsaEncryptedSourceContributionV1,
    },
    SourcePreservingActivating {
        binding: LinkedDeviceEcdsaSourceContributionBindingV1,
        source_derivation: CloudflareEcdsaRegistrationSourceDerivationV1,
        material_activation: MpcMaterialActivationRefV1,
        reservation_id: String,
        target_relayer_public_key33_b64u: String,
        threshold_public_key33_b64u: String,
        threshold_ethereum_address20_b64u: String,
        encrypted_target_client_share: LinkedDeviceEcdsaEncryptedSourceContributionV1,
        encrypted_target_server_share: LinkedDeviceEcdsaEncryptedSourceContributionV1,
    },
    SourcePreservingActive {
        binding: LinkedDeviceEcdsaSourceContributionBindingV1,
        source_derivation: CloudflareEcdsaRegistrationSourceDerivationV1,
        material_activation: MpcMaterialActivationRefV1,
        reservation_id: String,
        target_relayer_public_key33_b64u: String,
        threshold_public_key33_b64u: String,
        threshold_ethereum_address20_b64u: String,
        encrypted_target_client_share: LinkedDeviceEcdsaEncryptedSourceContributionV1,
        encrypted_target_server_share: LinkedDeviceEcdsaEncryptedSourceContributionV1,
    },
    SourcePreservingRevoked {
        binding: LinkedDeviceEcdsaSourceContributionBindingV1,
        source_derivation: CloudflareEcdsaRegistrationSourceDerivationV1,
        material_activation: MpcMaterialActivationRefV1,
        reservation_id: String,
        revoked_at_ms: u64,
    },
    SourcePreservingDeactivating {
        binding: LinkedDeviceEcdsaSourceContributionBindingV1,
        source_derivation: CloudflareEcdsaRegistrationSourceDerivationV1,
        material_activation: MpcMaterialActivationRefV1,
        reservation_id: String,
        revoked_at_ms: u64,
    },
}

impl EcdsaReservationStateV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::SourcePreservingInactive {
                binding,
                source_derivation,
                material_activation,
                reservation_id,
                target_relayer_public_key33_b64u,
                threshold_public_key33_b64u,
                threshold_ethereum_address20_b64u,
                encrypted_target_client_share,
                encrypted_target_server_share,
            }
            | Self::SourcePreservingActivating {
                binding,
                source_derivation,
                material_activation,
                reservation_id,
                target_relayer_public_key33_b64u,
                threshold_public_key33_b64u,
                threshold_ethereum_address20_b64u,
                encrypted_target_client_share,
                encrypted_target_server_share,
            }
            | Self::SourcePreservingActive {
                binding,
                source_derivation,
                material_activation,
                reservation_id,
                target_relayer_public_key33_b64u,
                threshold_public_key33_b64u,
                threshold_ethereum_address20_b64u,
                encrypted_target_client_share,
                encrypted_target_server_share,
            } => {
                validate_source_preserving_state_v1(
                    binding,
                    source_derivation,
                    material_activation,
                    reservation_id,
                    target_relayer_public_key33_b64u,
                    threshold_public_key33_b64u,
                    threshold_ethereum_address20_b64u,
                    encrypted_target_client_share,
                    encrypted_target_server_share,
                )?;
                return Ok(());
            }
            Self::SourcePreservingRevoked {
                binding,
                source_derivation,
                material_activation,
                reservation_id,
                revoked_at_ms,
            }
            | Self::SourcePreservingDeactivating {
                binding,
                source_derivation,
                material_activation,
                reservation_id,
                revoked_at_ms,
            } => {
                validate_source_preserving_identity_v1(
                    binding,
                    source_derivation,
                    material_activation,
                    reservation_id,
                )?;
                if *revoked_at_ms == 0 {
                    return Err(invalid_reservation(
                        "source-preserving ECDSA reservation transition timestamp is invalid",
                    ));
                }
                return Ok(());
            }
            _ => {}
        }
        let (
            registration,
            activation,
            material,
            material_activation,
            reservation_id,
            client_packages,
        ) = match self {
            Self::Inactive {
                registration,
                activation,
                material,
                material_activation,
                reservation_id,
                client_packages,
            }
            | Self::Active {
                registration,
                activation,
                material,
                material_activation,
                reservation_id,
                client_packages,
                ..
            }
            | Self::Activating {
                registration,
                activation,
                material,
                material_activation,
                reservation_id,
                client_packages,
            } => (
                registration,
                activation,
                material,
                material_activation,
                reservation_id,
                client_packages,
            ),
            Self::Revoked {
                registration,
                activation,
                material_activation,
                reservation_id,
                revoked_at_ms,
            }
            | Self::Deactivating {
                registration,
                activation,
                material_activation,
                reservation_id,
                revoked_at_ms,
            } => {
                CloudflareEcdsaInactiveMaterialReservationRequestV1 {
                    registration: registration.clone(),
                    activation: activation.clone(),
                }
                .validate()?;
                if &activation.material_activation != material_activation {
                    return Err(invalid_reservation(
                        "revoked ECDSA reservation material activation does not match its activation request",
                    ));
                }
                require_reservation_id(reservation_id)?;
                if *revoked_at_ms == 0 {
                    return Err(invalid_reservation(
                        "ECDSA reservation transition timestamp is invalid",
                    ));
                }
                return Ok(());
            }
            _ => unreachable!("source-preserving ECDSA state was handled above"),
        };
        CloudflareEcdsaInactiveMaterialReservationRequestV1 {
            registration: registration.clone(),
            activation: activation.clone(),
        }
        .validate()?;
        material.validate_for_activation_request(activation)?;
        if &activation.material_activation != material_activation {
            return Err(invalid_reservation(
                "ECDSA reservation material activation does not match its activation request",
            ));
        }
        client_packages.validate_for_registration(registration)?;
        if let Self::Active { receipt, .. } = self {
            receipt.validate()?;
        }
        require_reservation_id(reservation_id)
    }
}

pub async fn handle_cloudflare_signing_worker_ecdsa_reserve_inactive_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let reservation = request
        .json::<CloudflareEcdsaInactiveMaterialReservationRequestV1>()
        .await
        .map_err(|_| invalid_reservation("ECDSA inactive reservation JSON is malformed"))?;
    reservation.validate()?;
    let (reservation_id, material_activation, client_packages) =
        reserve_ecdsa_inactive_v1(env, &reservation).await?;
    Response::from_json(&CloudflareEcdsaInactiveMaterialReservationResponseV1 {
        state: "inactive",
        reservation_id,
        material_activation,
        deriver_a_client_package: client_packages.deriver_a_client_package,
        deriver_b_client_package: client_packages.deriver_b_client_package,
    })
    .map_err(|_| invalid_reservation("ECDSA inactive reservation response could not be encoded"))
}

pub async fn handle_cloudflare_signing_worker_ecdsa_reserve_inactive_source_preserving_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let reservation = request
        .json::<CloudflareEcdsaSourcePreservingInactiveMaterialReservationRequestV1>()
        .await
        .map_err(|_| {
            invalid_reservation("source-preserving ECDSA inactive reservation JSON is malformed")
        })?;
    reservation.validate()?;
    let response = reserve_source_preserving_ecdsa_inactive_v1(env, &reservation).await?;
    Response::from_json(&response).map_err(|_| {
        invalid_reservation(
            "source-preserving ECDSA inactive reservation response could not be encoded",
        )
    })
}

pub async fn handle_cloudflare_signing_worker_ecdsa_activate_reservation_v1(
    mut request: Request,
    env: &Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
) -> RouterAbProtocolResult<Response> {
    let activation = request
        .json::<CloudflareEcdsaActivateReservationRequestV1>()
        .await
        .map_err(|_| invalid_reservation("ECDSA reservation activation JSON is malformed"))?;
    activation.validate()?;
    match activate_ecdsa_reservation_v1(env, runtime, &activation).await? {
        EcdsaReservationActivationResultV1::Ordinary(receipt) => {
            Response::from_json(&CloudflareEcdsaReservationActivationResponseV1 { receipt })
        }
        EcdsaReservationActivationResultV1::SourcePreserving(response) => {
            Response::from_json(&response)
        }
    }
    .map_err(|_| invalid_reservation("ECDSA reservation response could not be encoded"))
}

pub async fn handle_cloudflare_signing_worker_ecdsa_deactivate_reservation_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let deactivation = request
        .json::<CloudflareEcdsaDeactivateReservationRequestV1>()
        .await
        .map_err(|_| invalid_reservation("ECDSA reservation deactivation JSON is malformed"))?;
    deactivation.validate()?;
    let response = deactivate_ecdsa_reservation_v1(env, &deactivation).await?;
    Response::from_json(&response)
        .map_err(|_| invalid_reservation("ECDSA deactivation response could not be encoded"))
}

async fn reserve_ecdsa_inactive_v1(
    env: &Env,
    request: &CloudflareEcdsaInactiveMaterialReservationRequestV1,
) -> RouterAbProtocolResult<(String, MpcMaterialActivationRefV1, EcdsaClientPackagePairV1)> {
    request.validate()?;
    let activation = &request.activation;
    let record_key = reservation_record_key_v1(&activation.material_activation)?;
    let reservation_id = format!(
        "ordinary-ecdsa-inactive-v1:{}",
        record_key.trim_start_matches("ecdsa/")
    );
    let runtime = CloudflareSigningWorkerRuntimeV1::from_worker_env(env)?;
    let selected_server = &activation.activation_context.signer_set().selected_server;
    runtime
        .server_output_decrypt_key()
        .validate_matches_server(&selected_server)?;
    let mut private_key = load_cloudflare_server_output_hpke_private_key_bytes_v1(
        env,
        runtime.server_output_decrypt_key(),
    )?;
    let material = cloudflare_server_output_material_record_from_activation_request_v1(
        activation,
        &private_key,
    );
    zeroize::Zeroize::zeroize(&mut private_key);
    let material = material?;
    for _ in 0..3 {
        let current =
            load_cloudflare_signing_worker_private_d1_secret_v1::<EcdsaReservationStateV1>(
                env,
                "ecdsa_inactive_reservations",
                &record_key,
            )
            .await?;
        if let Some(current) = current.as_ref() {
            current.value.validate()?;
            match &current.value {
                EcdsaReservationStateV1::Inactive {
                    registration: stored_registration,
                    activation: stored_activation,
                    material_activation: stored_ref,
                    reservation_id: stored_id,
                    client_packages,
                    ..
                } if stored_registration == &request.registration
                    && stored_activation == activation
                    && stored_ref == &activation.material_activation
                    && stored_id == &reservation_id =>
                {
                    return Ok((
                        reservation_id,
                        activation.material_activation.clone(),
                        client_packages.clone(),
                    ));
                }
                EcdsaReservationStateV1::Activating {
                    registration: stored_registration,
                    activation: stored_activation,
                    material_activation: stored_ref,
                    reservation_id: stored_id,
                    client_packages,
                    ..
                } if stored_registration == &request.registration
                    && stored_activation == activation
                    && stored_ref == &activation.material_activation
                    && stored_id == &reservation_id =>
                {
                    return Ok((
                        reservation_id,
                        activation.material_activation.clone(),
                        client_packages.clone(),
                    ));
                }
                EcdsaReservationStateV1::Active {
                    activation: stored_activation,
                    reservation_id: stored_id,
                    ..
                } if stored_activation == activation && stored_id == &reservation_id => {
                    return Err(invalid_reservation(
                        "ordinary ECDSA material reservation is already active",
                    ));
                }
                EcdsaReservationStateV1::Revoked {
                    material_activation: stored_ref,
                    reservation_id: stored_id,
                    ..
                } if stored_ref == &activation.material_activation
                    && stored_id == &reservation_id =>
                {
                    return Err(invalid_reservation(
                        "ordinary ECDSA material reservation is revoked",
                    ));
                }
                _ => {
                    return Err(invalid_reservation(
                        "ordinary ECDSA material reservation conflicts with the exact activation ref",
                    ));
                }
            }
        }
        let client_packages = build_client_package_pair_v1(&request.registration)?;
        let state = EcdsaReservationStateV1::Inactive {
            registration: request.registration.clone(),
            activation: activation.clone(),
            material: material.clone(),
            material_activation: activation.material_activation.clone(),
            reservation_id: reservation_id.clone(),
            client_packages: client_packages.clone(),
        };
        match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
            env,
            "ecdsa_inactive_reservations",
            &record_key,
            None,
            &state,
            cloudflare_now_unix_ms_v1()?,
        )
        .await
        {
            Err(error) if error.code() == RouterAbProtocolErrorCode::ConflictingPair => continue,
            Ok(()) => {
                return Ok((
                    reservation_id,
                    activation.material_activation.clone(),
                    client_packages,
                ))
            }
            Err(error) => return Err(error),
        }
    }
    Err(invalid_reservation(
        "ordinary ECDSA material reservation changed concurrently",
    ))
}

async fn reserve_source_preserving_ecdsa_inactive_v1(
    env: &Env,
    request: &CloudflareEcdsaSourcePreservingInactiveMaterialReservationRequestV1,
) -> RouterAbProtocolResult<CloudflareEcdsaSourcePreservingInactiveMaterialReservationResponseV1> {
    request.validate()?;
    let target_material_activation = request.target_material_activation()?;
    let binding = &request.source_contribution.binding;
    let binding_digest = binding.digest().map_err(|error| {
        invalid_reservation(format!(
            "linked-device ECDSA source contribution binding is invalid: {error:?}"
        ))
    })?;
    let record_key = reservation_record_key_v1(&target_material_activation)?;
    let reservation_id =
        source_preserving_reservation_id_v1(&target_material_activation, &binding_digest)?;
    let runtime = CloudflareSigningWorkerRuntimeV1::from_worker_env(env)?;
    validate_source_preserving_recipient_v1(&runtime, binding)?;

    for _ in 0..3 {
        let current =
            load_cloudflare_signing_worker_private_d1_secret_v1::<EcdsaReservationStateV1>(
                env,
                "ecdsa_inactive_reservations",
                &record_key,
            )
            .await?;
        if let Some(current) = current.as_ref() {
            current.value.validate()?;
            match &current.value {
                EcdsaReservationStateV1::SourcePreservingInactive {
                    binding: stored_binding,
                    source_derivation: stored_derivation,
                    material_activation: stored_ref,
                    reservation_id: stored_id,
                    ..
                }
                | EcdsaReservationStateV1::SourcePreservingActivating {
                    binding: stored_binding,
                    source_derivation: stored_derivation,
                    material_activation: stored_ref,
                    reservation_id: stored_id,
                    ..
                } if stored_binding == binding
                    && stored_derivation == &request.source_derivation
                    && stored_ref == &target_material_activation
                    && stored_id == &reservation_id =>
                {
                    return source_preserving_response_from_state_v1(&current.value, "inactive");
                }
                EcdsaReservationStateV1::SourcePreservingActive {
                    binding: stored_binding,
                    source_derivation: stored_derivation,
                    material_activation: stored_ref,
                    reservation_id: stored_id,
                    ..
                } if stored_binding == binding
                    && stored_derivation == &request.source_derivation
                    && stored_ref == &target_material_activation
                    && stored_id == &reservation_id =>
                {
                    return Err(invalid_reservation(
                        "source-preserving ECDSA material reservation is already active",
                    ));
                }
                EcdsaReservationStateV1::SourcePreservingRevoked {
                    binding: stored_binding,
                    material_activation: stored_ref,
                    reservation_id: stored_id,
                    ..
                } if stored_binding == binding
                    && stored_ref == &target_material_activation
                    && stored_id == &reservation_id =>
                {
                    return Err(invalid_reservation(
                        "source-preserving ECDSA material reservation is revoked",
                    ));
                }
                EcdsaReservationStateV1::Inactive { .. }
                | EcdsaReservationStateV1::Activating { .. }
                | EcdsaReservationStateV1::Active { .. }
                | EcdsaReservationStateV1::Revoked { .. }
                | EcdsaReservationStateV1::Deactivating { .. }
                | EcdsaReservationStateV1::SourcePreservingDeactivating { .. }
                | EcdsaReservationStateV1::SourcePreservingInactive { .. }
                | EcdsaReservationStateV1::SourcePreservingActivating { .. }
                | EcdsaReservationStateV1::SourcePreservingActive { .. }
                | EcdsaReservationStateV1::SourcePreservingRevoked { .. } => {
                    return Err(invalid_reservation(
                        "source-preserving ECDSA material reservation conflicts with the exact activation ref",
                    ));
                }
            }
        }

        let (
            target_relayer_public_key33_b64u,
            threshold_public_key33_b64u,
            threshold_ethereum_address20_b64u,
            encrypted_target_server_share,
        ) = build_source_preserving_target_outputs_v1(env, &runtime, request, &binding_digest)
            .await?;
        let state = EcdsaReservationStateV1::SourcePreservingInactive {
            binding: binding.clone(),
            source_derivation: request.source_derivation.clone(),
            material_activation: target_material_activation.clone(),
            reservation_id: reservation_id.clone(),
            target_relayer_public_key33_b64u,
            threshold_public_key33_b64u,
            threshold_ethereum_address20_b64u,
            encrypted_target_client_share: request
                .source_contribution
                .encrypted_target_client_share
                .clone(),
            encrypted_target_server_share,
        };
        match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
            env,
            "ecdsa_inactive_reservations",
            &record_key,
            None,
            &state,
            cloudflare_now_unix_ms_v1()?,
        )
        .await
        {
            Err(error) if error.code() == RouterAbProtocolErrorCode::ConflictingPair => continue,
            Ok(()) => return source_preserving_response_from_state_v1(&state, "inactive"),
            Err(error) => return Err(error),
        }
    }
    Err(invalid_reservation(
        "source-preserving ECDSA material reservation changed concurrently",
    ))
}

async fn build_source_preserving_target_outputs_v1(
    env: &Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    request: &CloudflareEcdsaSourcePreservingInactiveMaterialReservationRequestV1,
    binding_digest: &[u8; 32],
) -> RouterAbProtocolResult<(
    String,
    String,
    String,
    LinkedDeviceEcdsaEncryptedSourceContributionV1,
)> {
    let binding = &request.source_contribution.binding;
    let source_client_public_key33 = decode_fixed_b64_v1(
        "linked-device source client public key",
        &binding.source.client_public_key33_b64u,
    )?;
    let source_relayer_public_key33 = decode_fixed_b64_v1(
        "linked-device source relayer public key",
        &binding.source.relayer_public_key33_b64u,
    )?;
    let source_relayer_share32 = derive_registration_source_relayer_share_v1(
        env,
        &binding.source.activation,
        &request.source_derivation,
        &source_client_public_key33,
        &source_relayer_public_key33,
    )
    .await?;

    let mut server_output_private_key = load_cloudflare_server_output_hpke_private_key_bytes_v1(
        env,
        runtime.server_output_decrypt_key(),
    )?;
    let opened_delta = open_linked_device_ecdsa_source_contribution_v1(
        &request.source_contribution.encrypted_delta,
        &server_output_private_key,
        binding_digest,
    )
    .map(Zeroizing::new)
    .map_err(|error| {
        zeroize::Zeroize::zeroize(&mut server_output_private_key);
        invalid_reservation(format!(
            "linked-device ECDSA source contribution delta could not be opened: {error:?}"
        ))
    })?;
    zeroize::Zeroize::zeroize(&mut server_output_private_key);
    let delta32: [u8; 32] = opened_delta.as_slice().try_into().map_err(|_| {
        invalid_reservation("linked-device ECDSA source contribution delta must be 32 bytes")
    })?;
    let delta = EcdsaLaneDelta::from_bytes(delta32).map_err(|error| {
        invalid_reservation(format!(
            "linked-device ECDSA source contribution delta is invalid: {error}"
        ))
    })?;
    let source_identity = EcdsaLanePublicIdentityBindingV1 {
        source_client_public_key33,
        source_relayer_public_key33,
        threshold_public_key33: decode_fixed_b64_v1(
            "linked-device source threshold public key",
            &binding.source.threshold_public_key33_b64u,
        )?,
        threshold_ethereum_address20: decode_fixed_b64_20_v1(
            "linked-device source threshold Ethereum address",
            &binding.source.threshold_ethereum_address20_b64u,
        )?,
    };
    let target_client_public_key33 = decode_fixed_b64_v1(
        "linked-device target client public key",
        &binding.target_client_public_key33_b64u,
    )?;
    let rebound = rebind_ecdsa_lane_relayer_share_bytes_v1(
        *source_relayer_share32,
        &source_identity,
        &delta,
        target_client_public_key33,
    )
    .map_err(|error| {
        invalid_reservation(format!(
            "linked-device ECDSA source contribution rebind failed: {error}"
        ))
    })?;
    let target_relayer_public_key33_b64u =
        encode_base64url_bytes_v1(&rebound.target_relayer_public_key33);
    let threshold_public_key33_b64u =
        encode_base64url_bytes_v1(&rebound.target_threshold_public_key33);
    let threshold_ethereum_address20_b64u =
        encode_base64url_bytes_v1(&rebound.target_ethereum_address20);
    let target_relayer_share32 = Zeroizing::new(rebound.into_target_relayer_share32());
    let encrypted_target_server_share = seal_linked_device_ecdsa_source_contribution_v1(
        &binding.target.signing_worker_recipient_public_key_b64u,
        binding_digest,
        target_relayer_share32.as_ref(),
        random32_v1()?,
    )
    .map_err(|error| {
        invalid_reservation(format!(
            "linked-device ECDSA target server package could not be sealed: {error:?}"
        ))
    })?;
    Ok((
        target_relayer_public_key33_b64u,
        threshold_public_key33_b64u,
        threshold_ethereum_address20_b64u,
        encrypted_target_server_share,
    ))
}

fn source_preserving_response_from_state_v1(
    state: &EcdsaReservationStateV1,
    response_state: &'static str,
) -> RouterAbProtocolResult<CloudflareEcdsaSourcePreservingInactiveMaterialReservationResponseV1> {
    let (
        binding,
        source_derivation,
        material_activation,
        reservation_id,
        target_relayer_public_key33_b64u,
        threshold_public_key33_b64u,
        threshold_ethereum_address20_b64u,
        encrypted_target_client_share,
        encrypted_target_server_share,
    ) = match state {
        EcdsaReservationStateV1::SourcePreservingInactive {
            binding,
            source_derivation,
            material_activation,
            reservation_id,
            target_relayer_public_key33_b64u,
            threshold_public_key33_b64u,
            threshold_ethereum_address20_b64u,
            encrypted_target_client_share,
            encrypted_target_server_share,
        }
        | EcdsaReservationStateV1::SourcePreservingActivating {
            binding,
            source_derivation,
            material_activation,
            reservation_id,
            target_relayer_public_key33_b64u,
            threshold_public_key33_b64u,
            threshold_ethereum_address20_b64u,
            encrypted_target_client_share,
            encrypted_target_server_share,
        }
        | EcdsaReservationStateV1::SourcePreservingActive {
            binding,
            source_derivation,
            material_activation,
            reservation_id,
            target_relayer_public_key33_b64u,
            threshold_public_key33_b64u,
            threshold_ethereum_address20_b64u,
            encrypted_target_client_share,
            encrypted_target_server_share,
        } => (
            binding,
            source_derivation,
            material_activation,
            reservation_id,
            target_relayer_public_key33_b64u,
            threshold_public_key33_b64u,
            threshold_ethereum_address20_b64u,
            encrypted_target_client_share,
            encrypted_target_server_share,
        ),
        _ => {
            return Err(invalid_reservation(
                "source-preserving ECDSA reservation state cannot return inactive packages",
            ))
        }
    };
    Ok(
        CloudflareEcdsaSourcePreservingInactiveMaterialReservationResponseV1 {
            state: response_state,
            reservation_id: reservation_id.clone(),
            material_activation: material_activation.clone(),
            binding: binding.clone(),
            source_derivation: source_derivation.clone(),
            target_relayer_public_key33_b64u: target_relayer_public_key33_b64u.clone(),
            threshold_public_key33_b64u: threshold_public_key33_b64u.clone(),
            threshold_ethereum_address20_b64u: threshold_ethereum_address20_b64u.clone(),
            encrypted_target_client_share: encrypted_target_client_share.clone(),
            encrypted_target_server_share: encrypted_target_server_share.clone(),
        },
    )
}

fn validate_source_preserving_identity_v1(
    binding: &LinkedDeviceEcdsaSourceContributionBindingV1,
    source_derivation: &CloudflareEcdsaRegistrationSourceDerivationV1,
    material_activation: &MpcMaterialActivationRefV1,
    reservation_id: &str,
) -> RouterAbProtocolResult<()> {
    binding.validate().map_err(|error| {
        invalid_reservation(format!(
            "source-preserving ECDSA reservation binding is invalid: {error:?}"
        ))
    })?;
    source_derivation.validate()?;
    let expected_material_activation =
        mpc_material_activation_from_ecdsa_ref_v1(&binding.target.activation)?;
    if material_activation != &expected_material_activation {
        return Err(invalid_reservation(
            "source-preserving ECDSA target material activation does not match the binding",
        ));
    }
    let binding_digest = binding.digest().map_err(|error| {
        invalid_reservation(format!(
            "source-preserving ECDSA reservation binding digest is invalid: {error:?}"
        ))
    })?;
    let expected_reservation_id =
        source_preserving_reservation_id_v1(material_activation, &binding_digest)?;
    if reservation_id != &expected_reservation_id {
        return Err(invalid_reservation(
            "source-preserving ECDSA reservation id does not match the binding",
        ));
    }
    require_reservation_id(reservation_id)
}

#[allow(clippy::too_many_arguments)]
fn validate_source_preserving_state_v1(
    binding: &LinkedDeviceEcdsaSourceContributionBindingV1,
    source_derivation: &CloudflareEcdsaRegistrationSourceDerivationV1,
    material_activation: &MpcMaterialActivationRefV1,
    reservation_id: &str,
    target_relayer_public_key33_b64u: &str,
    threshold_public_key33_b64u: &str,
    threshold_ethereum_address20_b64u: &str,
    encrypted_target_client_share: &LinkedDeviceEcdsaEncryptedSourceContributionV1,
    encrypted_target_server_share: &LinkedDeviceEcdsaEncryptedSourceContributionV1,
) -> RouterAbProtocolResult<()> {
    validate_source_preserving_identity_v1(
        binding,
        source_derivation,
        material_activation,
        reservation_id,
    )?;
    let target_client_public_key33 = decode_fixed_b64_v1(
        "source-preserving ECDSA target client public key",
        &binding.target_client_public_key33_b64u,
    )?;
    let target_relayer_public_key33 = decode_fixed_b64_v1(
        "source-preserving ECDSA target relayer public key",
        target_relayer_public_key33_b64u,
    )?;
    let threshold_public_key33 = decode_fixed_b64_v1(
        "source-preserving ECDSA target threshold public key",
        threshold_public_key33_b64u,
    )?;
    let source_threshold_public_key33 = decode_fixed_b64_v1(
        "source-preserving ECDSA source threshold public key",
        &binding.source.threshold_public_key33_b64u,
    )?;
    if threshold_public_key33 != source_threshold_public_key33 {
        return Err(invalid_reservation(
            "source-preserving ECDSA target threshold key does not preserve the source key",
        ));
    }
    let threshold_ethereum_address20 = decode_fixed_b64_20_v1(
        "source-preserving ECDSA target threshold Ethereum address",
        threshold_ethereum_address20_b64u,
    )?;
    if threshold_ethereum_address20
        != decode_fixed_b64_20_v1(
            "source-preserving ECDSA source threshold Ethereum address",
            &binding.source.threshold_ethereum_address20_b64u,
        )?
    {
        return Err(invalid_reservation(
            "source-preserving ECDSA target Ethereum address does not preserve the source key",
        ));
    }
    let reconstructed_threshold =
        router_ab_ecdsa_derivation::shared::secp256k1::add_secp256k1_public_keys_33(
            &target_client_public_key33,
            &target_relayer_public_key33,
        )
        .map_err(|error| {
            invalid_reservation(format!(
                "source-preserving ECDSA target public identity is invalid: {error}"
            ))
        })?;
    if reconstructed_threshold != threshold_public_key33 {
        return Err(invalid_reservation(
            "source-preserving ECDSA target public shares do not reconstruct the threshold key",
        ));
    }
    let binding_digest = binding.digest().map_err(|error| {
        invalid_reservation(format!(
            "source-preserving ECDSA reservation binding digest is invalid: {error:?}"
        ))
    })?;
    validate_source_preserving_envelope_v1(
        encrypted_target_client_share,
        &binding_digest,
        &binding.target.client_recipient_public_key_b64u,
        "target client",
    )?;
    validate_source_preserving_envelope_v1(
        encrypted_target_server_share,
        &binding_digest,
        &binding.target.signing_worker_recipient_public_key_b64u,
        "target server",
    )
}

fn validate_source_preserving_envelope_v1(
    envelope: &LinkedDeviceEcdsaEncryptedSourceContributionV1,
    binding_digest: &[u8; 32],
    expected_recipient: &str,
    label: &str,
) -> RouterAbProtocolResult<()> {
    envelope.canonical_bytes().map_err(|error| {
        invalid_reservation(format!(
            "source-preserving ECDSA {label} package is invalid: {error:?}"
        ))
    })?;
    if envelope.binding_digest_b64u != encode_base64url_bytes_v1(binding_digest)
        || envelope.recipient_public_key_b64u != expected_recipient
    {
        return Err(invalid_reservation(format!(
            "source-preserving ECDSA {label} package does not match the binding"
        )));
    }
    Ok(())
}

fn validate_source_preserving_recipient_v1(
    runtime: &CloudflareSigningWorkerRuntimeV1,
    binding: &LinkedDeviceEcdsaSourceContributionBindingV1,
) -> RouterAbProtocolResult<()> {
    let configured = cloudflare_hpke_x25519_public_key_bytes_v1(
        &runtime.server_output_decrypt_key().public_key,
    )?;
    let admitted = decode_fixed_b64_32_v1(
        "source-preserving ECDSA target SigningWorker recipient",
        &binding.target.signing_worker_recipient_public_key_b64u,
    )?;
    if configured != admitted {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "source-preserving ECDSA target recipient does not match the active SigningWorker key",
        ));
    }
    Ok(())
}

fn mpc_material_activation_from_ecdsa_ref_v1(
    activation: &router_ab_ecdsa_client_protocol::EcdsaMaterialActivationRefV1,
) -> RouterAbProtocolResult<MpcMaterialActivationRefV1> {
    MpcMaterialActivationRefV1::new(
        activation.activation_id.clone(),
        activation.capability.clone(),
        activation.material_owner.clone(),
        activation.key_binding.clone(),
        activation.lifecycle_binding.clone(),
        activation.signing_worker.clone(),
    )
}

fn source_preserving_reservation_id_v1(
    target_material_activation: &MpcMaterialActivationRefV1,
    binding_digest: &[u8; 32],
) -> RouterAbProtocolResult<String> {
    let target_record_key = reservation_record_key_v1(target_material_activation)?;
    Ok(format!(
        "ordinary-ecdsa-source-preserving-inactive-v1:{}:{}",
        target_record_key.trim_start_matches("ecdsa/"),
        encode_hex(binding_digest),
    ))
}

fn reservation_id_matches_source_preserving_material_activation_v1(
    reservation_id: &str,
    material_activation: &MpcMaterialActivationRefV1,
    binding: &LinkedDeviceEcdsaSourceContributionBindingV1,
) -> bool {
    let Ok(binding_digest) = binding.digest() else {
        return false;
    };
    source_preserving_reservation_id_v1(material_activation, &binding_digest)
        .map(|expected| expected == reservation_id)
        .unwrap_or(false)
}

fn decode_fixed_b64_v1(label: &str, value: &str) -> RouterAbProtocolResult<[u8; 33]> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_reservation(format!("{label} is not unpadded base64url")))?
        .try_into()
        .map_err(|_| invalid_reservation(format!("{label} must decode to 33 bytes")))
}

fn decode_fixed_b64_20_v1(label: &str, value: &str) -> RouterAbProtocolResult<[u8; 20]> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_reservation(format!("{label} is not unpadded base64url")))?
        .try_into()
        .map_err(|_| invalid_reservation(format!("{label} must decode to 20 bytes")))
}

fn decode_fixed_b64_32_v1(label: &str, value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_reservation(format!("{label} is not unpadded base64url")))?
        .try_into()
        .map_err(|_| invalid_reservation(format!("{label} must decode to 32 bytes")))
}

fn random32_v1() -> RouterAbProtocolResult<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        invalid_reservation(format!(
            "source-preserving ECDSA target package randomness failed: {error}"
        ))
    })?;
    Ok(bytes)
}

fn build_client_package_pair_v1(
    registration: &RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
) -> RouterAbProtocolResult<EcdsaClientPackagePairV1> {
    Ok(EcdsaClientPackagePairV1 {
        deriver_a_client_package: build_client_package_v1(registration, Role::SignerA)?,
        deriver_b_client_package: build_client_package_v1(registration, Role::SignerB)?,
    })
}

fn build_client_package_v1(
    registration: &RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    role: Role,
) -> RouterAbProtocolResult<RoleEncryptedEnvelopeV1> {
    registration.validate()?;
    let aad = registration.header().role_aad(role)?;
    let plaintext = RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1::registration_for_request(
        registration,
        role,
        aad.digest(),
    )?
    .canonical_plaintext_bytes()?;
    let key_epoch = match role {
        Role::SignerA => registration.signer_set.signer_a.key_epoch.clone(),
        Role::SignerB => registration.signer_set.signer_b.key_epoch.clone(),
        _ => {
            return Err(invalid_reservation(
                "ordinary ECDSA client package requires a signer role",
            ))
        }
    };
    let recipient_key = CloudflareSignerEnvelopeHpkePublicKeyV1::new(
        role,
        key_epoch,
        registration.client_ephemeral_public_key.clone(),
    )?;
    let payload =
        seal_cloudflare_signer_envelope_hpke_payload_v1(&recipient_key, &aad, &plaintext)?;
    RoleEncryptedEnvelopeV1::new(
        role,
        registration.request_header_digest()?,
        aad.digest(),
        EncryptedPayloadV1::new(payload.canonical_bytes())?,
    )
}

fn validate_client_package_v1(
    registration: &RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    role: Role,
    package: &RoleEncryptedEnvelopeV1,
) -> RouterAbProtocolResult<()> {
    registration.validate()?;
    let aad = registration.header().role_aad(role)?;
    let expected_key_epoch = match role {
        Role::SignerA => &registration.signer_set.signer_a.key_epoch,
        Role::SignerB => &registration.signer_set.signer_b.key_epoch,
        _ => {
            return Err(invalid_reservation(
                "ordinary ECDSA client package requires a signer role",
            ))
        }
    };
    if package.header_digest != registration.request_header_digest()?
        || package.aad_digest != aad.digest()
    {
        return Err(invalid_reservation(
            "ordinary ECDSA client package public binding does not match registration",
        ));
    }
    decode_and_validate_signer_envelope_hpke_payload_v1(
        package,
        expected_key_epoch,
        &registration.client_ephemeral_public_key,
    )?;
    Ok(())
}

async fn activate_ecdsa_reservation_v1(
    env: &Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    request: &CloudflareEcdsaActivateReservationRequestV1,
) -> RouterAbProtocolResult<EcdsaReservationActivationResultV1> {
    let record_key = reservation_record_key_v1(&request.material_activation)?;
    let active_key = active_output_key_v1(&request.material_activation);
    for _ in 0..3 {
        let Some(current) = load_cloudflare_signing_worker_private_d1_secret_v1::<
            EcdsaReservationStateV1,
        >(env, "ecdsa_inactive_reservations", &record_key)
        .await?
        else {
            let ed25519_record_key = format!("ed25519/{}", record_key.trim_start_matches("ecdsa/"));
            if load_cloudflare_signing_worker_private_d1_secret_v1::<serde_json::Value>(
                env,
                "ed25519_yao_reservations",
                &ed25519_record_key,
            )
            .await?
            .is_some()
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ConflictingPair,
                    "ordinary ECDSA deactivation conflicts with an Ed25519 activation",
                ));
            }
            return Err(invalid_reservation(
                "ordinary ECDSA material reservation is missing",
            ));
        };
        current.value.validate()?;
        match current.value {
            EcdsaReservationStateV1::Active {
                registration: _,
                activation,
                reservation_id,
                client_packages: _,
                receipt,
                ..
            } => {
                if !request.matches(&reservation_id, &activation.material_activation) {
                    return Err(invalid_reservation(
                        "ordinary ECDSA reservation activation conflicts with the exact reservation",
                    ));
                }
                return Ok(EcdsaReservationActivationResultV1::Ordinary(receipt));
            }
            EcdsaReservationStateV1::Inactive {
                registration,
                activation,
                material,
                material_activation,
                reservation_id,
                client_packages,
            } => {
                if !request.matches(&reservation_id, &material_activation) {
                    return Err(invalid_reservation(
                        "ordinary ECDSA reservation activation conflicts with the exact reservation",
                    ));
                }
                let activating = EcdsaReservationStateV1::Activating {
                    registration,
                    activation,
                    material,
                    material_activation,
                    reservation_id,
                    client_packages,
                };
                match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
                    env,
                    "ecdsa_inactive_reservations",
                    &record_key,
                    Some(current.version),
                    &activating,
                    cloudflare_now_unix_ms_v1()?,
                )
                .await
                {
                    Err(error) if error.code() == RouterAbProtocolErrorCode::ConflictingPair => {
                        continue
                    }
                    Ok(()) => continue,
                    Err(error) => return Err(error),
                }
            }
            EcdsaReservationStateV1::Activating {
                registration,
                activation,
                material,
                material_activation,
                reservation_id,
                client_packages,
            } => {
                if !request.matches(&reservation_id, &material_activation) {
                    return Err(invalid_reservation(
                        "ordinary ECDSA reservation activation conflicts with the exact reservation",
                    ));
                }
                let receipt = activate_cloudflare_signing_worker_server_output_v1(
                    env,
                    runtime,
                    activation.clone(),
                    cloudflare_now_unix_ms_v1()?,
                )
                .await?;
                let active = EcdsaReservationStateV1::Active {
                    registration,
                    activation,
                    material,
                    material_activation,
                    reservation_id,
                    client_packages,
                    receipt: receipt.clone(),
                };
                match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
                    env,
                    "ecdsa_inactive_reservations",
                    &record_key,
                    Some(current.version),
                    &active,
                    cloudflare_now_unix_ms_v1()?,
                )
                .await
                {
                    Err(error) if error.code() == RouterAbProtocolErrorCode::ConflictingPair => {
                        let Some(latest) = load_cloudflare_signing_worker_private_d1_secret_v1::<
                            EcdsaReservationStateV1,
                        >(
                            env, "ecdsa_inactive_reservations", &record_key
                        )
                        .await?
                        else {
                            continue;
                        };
                        latest.value.validate()?;
                        match latest.value {
                            EcdsaReservationStateV1::Active {
                                activation,
                                material_activation,
                                reservation_id,
                                receipt,
                                ..
                            } if reservation_id == request.reservation_id
                                && material_activation == request.material_activation
                                && activation.material_activation
                                    == request.material_activation =>
                            {
                                return Ok(EcdsaReservationActivationResultV1::Ordinary(receipt));
                            }
                            EcdsaReservationStateV1::Deactivating {
                                material_activation,
                                reservation_id,
                                ..
                            }
                            | EcdsaReservationStateV1::Revoked {
                                material_activation,
                                reservation_id,
                                ..
                            } => {
                                if !request.matches(&reservation_id, &material_activation) {
                                    return Err(invalid_reservation(
                                        "ordinary ECDSA reservation activation conflicts with the exact reservation",
                                    ));
                                }
                                delete_cloudflare_signing_worker_output_activation_by_active_key_v1(
                                    env,
                                    &active_key,
                                    &request.material_activation,
                                )
                                .await?;
                                return Err(invalid_reservation(
                                    "ordinary ECDSA material reservation is revoked",
                                ));
                            }
                            _ => continue,
                        }
                    }
                    Ok(()) => return Ok(EcdsaReservationActivationResultV1::Ordinary(receipt)),
                    Err(error) => return Err(error),
                }
            }
            EcdsaReservationStateV1::Deactivating {
                material_activation,
                reservation_id,
                ..
            } => {
                if !request.matches(&reservation_id, &material_activation) {
                    return Err(invalid_reservation(
                        "ordinary ECDSA reservation activation conflicts with the exact reservation",
                    ));
                }
                return Err(invalid_reservation(
                    "ordinary ECDSA material reservation is being deactivated",
                ));
            }
            EcdsaReservationStateV1::Revoked {
                material_activation,
                reservation_id,
                ..
            } => {
                if !request.matches(&reservation_id, &material_activation) {
                    return Err(invalid_reservation(
                        "ordinary ECDSA reservation activation conflicts with the exact reservation",
                    ));
                }
                return Err(invalid_reservation(
                    "ordinary ECDSA material reservation is revoked",
                ));
            }
            EcdsaReservationStateV1::SourcePreservingActive {
                binding,
                source_derivation,
                material_activation,
                reservation_id,
                target_relayer_public_key33_b64u,
                threshold_public_key33_b64u,
                threshold_ethereum_address20_b64u,
                encrypted_target_client_share,
                encrypted_target_server_share,
            } => {
                if !request.matches(&reservation_id, &material_activation) {
                    return Err(invalid_reservation(
                        "source-preserving ECDSA reservation activation conflicts with the exact reservation",
                    ));
                }
                let active = EcdsaReservationStateV1::SourcePreservingActive {
                    binding,
                    source_derivation,
                    material_activation,
                    reservation_id,
                    target_relayer_public_key33_b64u,
                    threshold_public_key33_b64u,
                    threshold_ethereum_address20_b64u,
                    encrypted_target_client_share,
                    encrypted_target_server_share,
                };
                let source_response = source_preserving_response_from_state_v1(&active, "active")?;
                return Ok(EcdsaReservationActivationResultV1::SourcePreserving(
                    source_response,
                ));
            }
            EcdsaReservationStateV1::SourcePreservingInactive {
                binding,
                source_derivation,
                material_activation,
                reservation_id,
                target_relayer_public_key33_b64u,
                threshold_public_key33_b64u,
                threshold_ethereum_address20_b64u,
                encrypted_target_client_share,
                encrypted_target_server_share,
            } => {
                if !request.matches(&reservation_id, &material_activation) {
                    return Err(invalid_reservation(
                        "source-preserving ECDSA reservation activation conflicts with the exact reservation",
                    ));
                }
                let activating = EcdsaReservationStateV1::SourcePreservingActivating {
                    binding,
                    source_derivation,
                    material_activation,
                    reservation_id,
                    target_relayer_public_key33_b64u,
                    threshold_public_key33_b64u,
                    threshold_ethereum_address20_b64u,
                    encrypted_target_client_share,
                    encrypted_target_server_share,
                };
                match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
                    env,
                    "ecdsa_inactive_reservations",
                    &record_key,
                    Some(current.version),
                    &activating,
                    cloudflare_now_unix_ms_v1()?,
                )
                .await
                {
                    Err(error) if error.code() == RouterAbProtocolErrorCode::ConflictingPair => {
                        continue
                    }
                    Ok(()) => continue,
                    Err(error) => return Err(error),
                }
            }
            EcdsaReservationStateV1::SourcePreservingActivating {
                binding,
                source_derivation,
                material_activation,
                reservation_id,
                target_relayer_public_key33_b64u,
                threshold_public_key33_b64u,
                threshold_ethereum_address20_b64u,
                encrypted_target_client_share,
                encrypted_target_server_share,
            } => {
                if !request.matches(&reservation_id, &material_activation) {
                    return Err(invalid_reservation(
                        "source-preserving ECDSA reservation activation conflicts with the exact reservation",
                    ));
                }
                let active = EcdsaReservationStateV1::SourcePreservingActive {
                    binding,
                    source_derivation,
                    material_activation,
                    reservation_id,
                    target_relayer_public_key33_b64u,
                    threshold_public_key33_b64u,
                    threshold_ethereum_address20_b64u,
                    encrypted_target_client_share,
                    encrypted_target_server_share,
                };
                match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
                    env,
                    "ecdsa_inactive_reservations",
                    &record_key,
                    Some(current.version),
                    &active,
                    cloudflare_now_unix_ms_v1()?,
                )
                .await
                {
                    Err(error) if error.code() == RouterAbProtocolErrorCode::ConflictingPair => {
                        continue
                    }
                    Ok(()) => {
                        let source_response =
                            source_preserving_response_from_state_v1(&active, "active")?;
                        return Ok(EcdsaReservationActivationResultV1::SourcePreserving(
                            source_response,
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }
            EcdsaReservationStateV1::SourcePreservingDeactivating {
                material_activation,
                reservation_id,
                ..
            } => {
                if reservation_id != request.reservation_id
                    || material_activation != request.material_activation
                {
                    return Err(invalid_reservation(
                        "source-preserving ECDSA reservation activation conflicts with the exact reservation",
                    ));
                }
                return Err(invalid_reservation(
                    "source-preserving ECDSA material reservation is being deactivated",
                ));
            }
            EcdsaReservationStateV1::SourcePreservingRevoked {
                material_activation,
                reservation_id,
                ..
            } => {
                if reservation_id != request.reservation_id
                    || material_activation != request.material_activation
                {
                    return Err(invalid_reservation(
                        "source-preserving ECDSA reservation activation conflicts with the exact reservation",
                    ));
                }
                return Err(invalid_reservation(
                    "source-preserving ECDSA material reservation is revoked",
                ));
            }
        }
    }
    Err(invalid_reservation(
        "ordinary ECDSA reservation activation changed concurrently",
    ))
}

async fn deactivate_ecdsa_reservation_v1(
    env: &Env,
    request: &CloudflareEcdsaDeactivateReservationRequestV1,
) -> RouterAbProtocolResult<CloudflareEcdsaReservationDeactivationResponseV1> {
    request.validate()?;
    let record_key = reservation_record_key_v1(&request.material_activation)?;
    let reservation_id = format!(
        "ordinary-ecdsa-inactive-v1:{}",
        record_key.trim_start_matches("ecdsa/")
    );
    let active_key = active_output_key_v1(&request.material_activation);
    for _ in 0..3 {
        let current =
            load_cloudflare_signing_worker_private_d1_secret_v1::<EcdsaReservationStateV1>(
                env,
                "ecdsa_inactive_reservations",
                &record_key,
            )
            .await?
            .ok_or_else(|| invalid_reservation("ordinary ECDSA material reservation is missing"))?;
        current.value.validate()?;
        let (material_activation, revoked_at_ms, response_reservation_id) = match current.value {
            EcdsaReservationStateV1::Revoked {
                material_activation,
                reservation_id: stored_id,
                revoked_at_ms,
                ..
            } => {
                if stored_id != reservation_id || material_activation != request.material_activation
                {
                    return Err(invalid_reservation(
                        "ordinary ECDSA deactivation conflicts with the exact activation ref",
                    ));
                }
                delete_cloudflare_signing_worker_output_activation_by_active_key_v1(
                    env,
                    &active_key,
                    &request.material_activation,
                )
                .await?;
                (material_activation, revoked_at_ms, stored_id)
            }
            EcdsaReservationStateV1::Deactivating {
                registration,
                activation,
                material_activation,
                reservation_id: stored_id,
                revoked_at_ms,
            } => {
                if stored_id != reservation_id || material_activation != request.material_activation
                {
                    return Err(invalid_reservation(
                        "ordinary ECDSA deactivation conflicts with the exact activation ref",
                    ));
                }
                delete_cloudflare_signing_worker_output_activation_by_active_key_v1(
                    env,
                    &active_key,
                    &request.material_activation,
                )
                .await?;
                let revoked = EcdsaReservationStateV1::Revoked {
                    registration,
                    activation,
                    material_activation: material_activation.clone(),
                    reservation_id: reservation_id.clone(),
                    revoked_at_ms,
                };
                match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
                    env,
                    "ecdsa_inactive_reservations",
                    &record_key,
                    Some(current.version),
                    &revoked,
                    revoked_at_ms,
                )
                .await
                {
                    Err(error) if error.code() == RouterAbProtocolErrorCode::ConflictingPair => {
                        continue
                    }
                    Ok(()) => (material_activation, revoked_at_ms, reservation_id),
                    Err(error) => return Err(error),
                }
            }
            EcdsaReservationStateV1::Inactive {
                registration,
                activation,
                material_activation,
                reservation_id: stored_id,
                ..
            }
            | EcdsaReservationStateV1::Activating {
                registration,
                activation,
                material_activation,
                reservation_id: stored_id,
                ..
            }
            | EcdsaReservationStateV1::Active {
                registration,
                activation,
                material_activation,
                reservation_id: stored_id,
                ..
            } => {
                if stored_id != reservation_id || material_activation != request.material_activation
                {
                    return Err(invalid_reservation(
                        "ordinary ECDSA deactivation conflicts with the exact activation ref",
                    ));
                }
                let revoked_at_ms = cloudflare_now_unix_ms_v1()?;
                let deactivating = EcdsaReservationStateV1::Deactivating {
                    registration,
                    activation,
                    material_activation: material_activation.clone(),
                    reservation_id: reservation_id.clone(),
                    revoked_at_ms,
                };
                match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
                    env,
                    "ecdsa_inactive_reservations",
                    &record_key,
                    Some(current.version),
                    &deactivating,
                    revoked_at_ms,
                )
                .await
                {
                    Err(error) if error.code() == RouterAbProtocolErrorCode::ConflictingPair => {
                        continue
                    }
                    Ok(()) => continue,
                    Err(error) => return Err(error),
                }
            }
            EcdsaReservationStateV1::SourcePreservingRevoked {
                binding,
                source_derivation,
                material_activation,
                reservation_id: stored_id,
                revoked_at_ms,
            } => {
                if material_activation != request.material_activation
                    || !reservation_id_matches_source_preserving_material_activation_v1(
                        &stored_id,
                        &material_activation,
                        &binding,
                    )
                {
                    return Err(invalid_reservation(
                        "source-preserving ECDSA deactivation conflicts with the exact activation ref",
                    ));
                }
                let _ = source_derivation;
                (material_activation, revoked_at_ms, stored_id)
            }
            EcdsaReservationStateV1::SourcePreservingDeactivating {
                binding,
                source_derivation,
                material_activation,
                reservation_id: stored_id,
                revoked_at_ms,
            } => {
                if material_activation != request.material_activation
                    || !reservation_id_matches_source_preserving_material_activation_v1(
                        &stored_id,
                        &material_activation,
                        &binding,
                    )
                {
                    return Err(invalid_reservation(
                        "source-preserving ECDSA deactivation conflicts with the exact activation ref",
                    ));
                }
                let revoked = EcdsaReservationStateV1::SourcePreservingRevoked {
                    binding,
                    source_derivation,
                    material_activation: material_activation.clone(),
                    reservation_id: stored_id.clone(),
                    revoked_at_ms,
                };
                match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
                    env,
                    "ecdsa_inactive_reservations",
                    &record_key,
                    Some(current.version),
                    &revoked,
                    revoked_at_ms,
                )
                .await
                {
                    Err(error) if error.code() == RouterAbProtocolErrorCode::ConflictingPair => {
                        continue
                    }
                    Ok(()) => (material_activation, revoked_at_ms, stored_id),
                    Err(error) => return Err(error),
                }
            }
            EcdsaReservationStateV1::SourcePreservingInactive {
                binding,
                source_derivation,
                material_activation,
                reservation_id: stored_id,
                ..
            }
            | EcdsaReservationStateV1::SourcePreservingActivating {
                binding,
                source_derivation,
                material_activation,
                reservation_id: stored_id,
                ..
            }
            | EcdsaReservationStateV1::SourcePreservingActive {
                binding,
                source_derivation,
                material_activation,
                reservation_id: stored_id,
                ..
            } => {
                if material_activation != request.material_activation
                    || !reservation_id_matches_source_preserving_material_activation_v1(
                        &stored_id,
                        &material_activation,
                        &binding,
                    )
                {
                    return Err(invalid_reservation(
                        "source-preserving ECDSA deactivation conflicts with the exact activation ref",
                    ));
                }
                let revoked_at_ms = cloudflare_now_unix_ms_v1()?;
                let deactivating = EcdsaReservationStateV1::SourcePreservingDeactivating {
                    binding,
                    source_derivation,
                    material_activation: material_activation.clone(),
                    reservation_id: stored_id.clone(),
                    revoked_at_ms,
                };
                match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
                    env,
                    "ecdsa_inactive_reservations",
                    &record_key,
                    Some(current.version),
                    &deactivating,
                    revoked_at_ms,
                )
                .await
                {
                    Err(error) if error.code() == RouterAbProtocolErrorCode::ConflictingPair => {
                        continue
                    }
                    Ok(()) => continue,
                    Err(error) => return Err(error),
                }
            }
        };
        return Ok(CloudflareEcdsaReservationDeactivationResponseV1 {
            state: "revoked",
            reservation_id: response_reservation_id,
            material_activation,
            revoked_at_ms,
        });
    }
    Err(invalid_reservation(
        "ordinary ECDSA material deactivation changed concurrently",
    ))
}

pub(crate) async fn require_ecdsa_material_active_v1(
    env: &Env,
    material_activation: &MpcMaterialActivationRefV1,
) -> RouterAbProtocolResult<()> {
    let record_key = reservation_record_key_v1(material_activation)?;
    let Some(current) = load_cloudflare_signing_worker_private_d1_secret_v1::<
        EcdsaReservationStateV1,
    >(env, "ecdsa_inactive_reservations", &record_key)
    .await?
    else {
        return Ok(());
    };
    current.value.validate()?;
    match current.value {
        EcdsaReservationStateV1::Active {
            material_activation: stored_ref,
            ..
        } if stored_ref == *material_activation => Ok(()),
        EcdsaReservationStateV1::Inactive {
            material_activation: stored_ref,
            ..
        }
        | EcdsaReservationStateV1::Activating {
            material_activation: stored_ref,
            ..
        } if stored_ref == *material_activation => Err(invalid_reservation(
            "ordinary ECDSA material reservation is not active",
        )),
        EcdsaReservationStateV1::Deactivating {
            material_activation: stored_ref,
            ..
        }
        | EcdsaReservationStateV1::Revoked {
            material_activation: stored_ref,
            ..
        } if stored_ref == *material_activation => Err(invalid_reservation(
            "ordinary ECDSA material reservation is revoked",
        )),
        EcdsaReservationStateV1::SourcePreservingActive {
            material_activation: stored_ref,
            ..
        } if stored_ref == *material_activation => Ok(()),
        EcdsaReservationStateV1::SourcePreservingInactive {
            material_activation: stored_ref,
            ..
        }
        | EcdsaReservationStateV1::SourcePreservingActivating {
            material_activation: stored_ref,
            ..
        } if stored_ref == *material_activation => Err(invalid_reservation(
            "source-preserving ECDSA material reservation is not active",
        )),
        EcdsaReservationStateV1::SourcePreservingDeactivating {
            material_activation: stored_ref,
            ..
        }
        | EcdsaReservationStateV1::SourcePreservingRevoked {
            material_activation: stored_ref,
            ..
        } if stored_ref == *material_activation => Err(invalid_reservation(
            "source-preserving ECDSA material reservation is revoked",
        )),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "ordinary ECDSA material activation identity conflicts with the reservation",
        )),
    }
}

/// Resolves source-preserving ECDSA material into the same private material
/// shape consumed by the ordinary SigningWorker primitives.
///
/// Source-preserving reservations do not create a proof-bundle activation row.
/// This adapter projects their exact active reservation into a deterministic
/// active-state descriptor after rechecking the lifecycle fence and all public
/// target identity fields. The decrypted share never leaves this module except
/// inside the worker-owned `CloudflareServerOutputMaterialRecordV1`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn load_source_preserving_ecdsa_material_v1(
    env: &Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    material_activation: &MpcMaterialActivationRefV1,
    signing_worker: &ServerIdentityV1,
    target_client_public_key33_b64u: &str,
    target_relayer_public_key33_b64u: &str,
    threshold_public_key33_b64u: &str,
    threshold_ethereum_address20_b64u: &str,
) -> RouterAbProtocolResult<(
    ActiveSigningWorkerStateV1,
    CloudflareServerOutputMaterialRecordV1,
)> {
    material_activation.validate()?;
    signing_worker.validate()?;
    runtime
        .server_output_decrypt_key()
        .validate_matches_server(signing_worker)?;
    require_ecdsa_material_active_v1(env, material_activation).await?;

    let record_key = reservation_record_key_v1(material_activation)?;
    let Some(current) = load_cloudflare_signing_worker_private_d1_secret_v1::<
        EcdsaReservationStateV1,
    >(env, "ecdsa_inactive_reservations", &record_key)
    .await?
    else {
        return Err(source_preserving_material_missing_v1());
    };
    current.value.validate()?;
    let active =
        select_source_preserving_active_reservation_v1(&current.value, material_activation)?;
    let expected_worker_recipient_public_key_b64u =
        encode_base64url_bytes_v1(&cloudflare_hpke_x25519_public_key_bytes_v1(
            &runtime.server_output_decrypt_key().public_key,
        )?);
    let (expected_target_relayer_public_key33, binding_digest) =
        validate_source_preserving_target_identity_v1(
            &active,
            material_activation,
            signing_worker,
            &expected_worker_recipient_public_key_b64u,
            target_client_public_key33_b64u,
            target_relayer_public_key33_b64u,
            threshold_public_key33_b64u,
            threshold_ethereum_address20_b64u,
        )?;
    let mut private_key = load_cloudflare_server_output_hpke_private_key_bytes_v1(
        env,
        runtime.server_output_decrypt_key(),
    )?;
    let opened_share = decrypt_source_preserving_server_share_v1(
        active.encrypted_target_server_share,
        &private_key,
        &binding_digest,
        &expected_target_relayer_public_key33,
    );
    private_key.zeroize();
    let opened_share = opened_share?;
    let material = CloudflareServerOutputMaterialRecordV1::new(
        PublicDigest32::new(binding_digest),
        OpenedShareKind::XServerBase,
        Role::Server,
        signing_worker.server_id.clone(),
        opened_share,
    )?;
    let active = ActiveSigningWorkerStateV1::new(
        material_activation.material_owner.clone(),
        material_activation.clone(),
        threshold_public_key33_b64u.to_owned(),
        signing_worker.clone(),
        PublicDigest32::new(binding_digest),
        PublicDigest32::new(binding_digest),
        format!(
            "{SOURCE_PRESERVING_ECDSA_MATERIAL_HANDLE_PREFIX_V1}{}",
            active.reservation_id
        ),
        current.updated_at_ms,
    )?;
    Ok((active, material))
}

fn decrypt_source_preserving_server_share_v1(
    envelope: &LinkedDeviceEcdsaEncryptedSourceContributionV1,
    private_key: &[u8; 32],
    binding_digest: &[u8; 32],
    expected_relayer_public_key33: &[u8; 33],
) -> RouterAbProtocolResult<CloudflareSecretMaterial32V1> {
    let opened_share =
        open_linked_device_ecdsa_source_contribution_v1(envelope, private_key, binding_digest)
            .map_err(|error| {
                invalid_reservation(format!(
                    "source-preserving ECDSA target server share could not be opened: {error:?}"
                ))
            })?;
    let opened_share = Zeroizing::new(opened_share);
    let opened_share32 =
        Zeroizing::new(<[u8; 32]>::try_from(opened_share.as_slice()).map_err(|_| {
            invalid_reservation("source-preserving ECDSA target server share must be 32 bytes")
        })?);
    let opened_share_public_key33 =
        crate::ecdsa_lane_client_public_key_from_share32_v1(*opened_share32).map_err(|error| {
            invalid_reservation(format!(
                "source-preserving ECDSA target server share is invalid: {error}"
            ))
        })?;
    if opened_share_public_key33 != *expected_relayer_public_key33 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "source-preserving ECDSA target server share does not match the reserved relayer identity",
        ));
    }
    Ok(CloudflareSecretMaterial32V1::new(*opened_share32))
}

fn source_preserving_material_missing_v1() -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MissingLocalBinding,
        "source-preserving ECDSA material reservation is missing",
    )
}

struct SourcePreservingActiveReservationViewV1<'a> {
    binding: &'a LinkedDeviceEcdsaSourceContributionBindingV1,
    reservation_id: &'a str,
    material_activation: &'a MpcMaterialActivationRefV1,
    target_relayer_public_key33_b64u: &'a str,
    threshold_public_key33_b64u: &'a str,
    threshold_ethereum_address20_b64u: &'a str,
    encrypted_target_server_share: &'a LinkedDeviceEcdsaEncryptedSourceContributionV1,
}

fn select_source_preserving_active_reservation_v1<'a>(
    state: &'a EcdsaReservationStateV1,
    material_activation: &MpcMaterialActivationRefV1,
) -> RouterAbProtocolResult<SourcePreservingActiveReservationViewV1<'a>> {
    let view = match state {
        EcdsaReservationStateV1::SourcePreservingActive {
            binding,
            material_activation: stored_material_activation,
            reservation_id,
            target_relayer_public_key33_b64u,
            threshold_public_key33_b64u,
            threshold_ethereum_address20_b64u,
            encrypted_target_server_share,
            ..
        } => SourcePreservingActiveReservationViewV1 {
            binding,
            reservation_id,
            material_activation: stored_material_activation,
            target_relayer_public_key33_b64u,
            threshold_public_key33_b64u,
            threshold_ethereum_address20_b64u,
            encrypted_target_server_share,
        },
        EcdsaReservationStateV1::SourcePreservingInactive {
            material_activation: stored_ref,
            ..
        }
        | EcdsaReservationStateV1::SourcePreservingActivating {
            material_activation: stored_ref,
            ..
        } if stored_ref == material_activation => {
            return Err(invalid_reservation(
                "source-preserving ECDSA material reservation is not active",
            ));
        }
        EcdsaReservationStateV1::SourcePreservingDeactivating {
            material_activation: stored_ref,
            ..
        }
        | EcdsaReservationStateV1::SourcePreservingRevoked {
            material_activation: stored_ref,
            ..
        } if stored_ref == material_activation => {
            return Err(invalid_reservation(
                "source-preserving ECDSA material reservation is revoked",
            ));
        }
        _ => return Err(source_preserving_material_missing_v1()),
    };
    if view.material_activation != material_activation {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "source-preserving ECDSA material activation conflicts with the exact reservation",
        ));
    }
    Ok(view)
}

fn validate_source_preserving_target_identity_v1(
    view: &SourcePreservingActiveReservationViewV1<'_>,
    material_activation: &MpcMaterialActivationRefV1,
    signing_worker: &ServerIdentityV1,
    expected_worker_recipient_public_key_b64u: &str,
    target_client_public_key33_b64u: &str,
    target_relayer_public_key33_b64u: &str,
    threshold_public_key33_b64u: &str,
    threshold_ethereum_address20_b64u: &str,
) -> RouterAbProtocolResult<([u8; 33], [u8; 32])> {
    if view.binding.target.activation.signing_worker != signing_worker.server_id
        || view.binding.target.activation.material_owner != material_activation.material_owner
        || view.binding.target.signing_worker_recipient_public_key_b64u
            != expected_worker_recipient_public_key_b64u
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "source-preserving ECDSA reservation SigningWorker identity does not match the active worker",
        ));
    }
    let expected_target_client_public_key33 = decode_fixed_b64_v1(
        "source-preserving ECDSA expected target client public key",
        target_client_public_key33_b64u,
    )?;
    let expected_target_relayer_public_key33 = decode_fixed_b64_v1(
        "source-preserving ECDSA expected target relayer public key",
        target_relayer_public_key33_b64u,
    )?;
    let expected_threshold_public_key33 = decode_fixed_b64_v1(
        "source-preserving ECDSA expected threshold public key",
        threshold_public_key33_b64u,
    )?;
    let expected_threshold_ethereum_address20 = decode_fixed_b64_20_v1(
        "source-preserving ECDSA expected threshold Ethereum address",
        threshold_ethereum_address20_b64u,
    )?;
    if decode_fixed_b64_v1(
        "source-preserving ECDSA target client public key",
        &view.binding.target_client_public_key33_b64u,
    )? != expected_target_client_public_key33
        || decode_fixed_b64_v1(
            "source-preserving ECDSA target relayer public key",
            view.target_relayer_public_key33_b64u,
        )? != expected_target_relayer_public_key33
        || decode_fixed_b64_v1(
            "source-preserving ECDSA threshold public key",
            view.threshold_public_key33_b64u,
        )? != expected_threshold_public_key33
        || decode_fixed_b64_20_v1(
            "source-preserving ECDSA threshold Ethereum address",
            view.threshold_ethereum_address20_b64u,
        )? != expected_threshold_ethereum_address20
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "source-preserving ECDSA reservation public identity does not match the signing scope",
        ));
    }

    let binding_digest = view.binding.digest().map_err(|error| {
        invalid_reservation(format!(
            "source-preserving ECDSA reservation binding digest is invalid: {error:?}"
        ))
    })?;
    Ok((expected_target_relayer_public_key33, binding_digest))
}

fn reservation_record_key_v1(
    material_activation: &MpcMaterialActivationRefV1,
) -> RouterAbProtocolResult<String> {
    let canonical = serde_json::to_vec(material_activation)
        .map_err(|_| invalid_reservation("ECDSA reservation identity could not be encoded"))?;
    let digest = Sha256::digest(canonical);
    Ok(format!("ecdsa/{}", encode_hex(&digest)))
}

fn active_output_key_v1(material_activation: &MpcMaterialActivationRefV1) -> String {
    format!(
        "active-signing-worker/{}/{}/{}",
        material_activation.material_owner,
        material_activation.activation_id,
        material_activation.signing_worker
    )
}

fn require_reservation_id(value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() || value.chars().any(|character| character.is_ascii_control()) {
        return Err(invalid_reservation("ECDSA reservation id is invalid"));
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        output.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    output
}

fn invalid_reservation(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        message.into(),
    )
}

#[cfg(test)]
mod tests {
    use hpke_ng::{DhKemX25519HkdfSha256, Kem};
    use router_ab_core::{
        RouterAbEcdsaDerivationNormalSigningScopeV1, RouterAbEcdsaDerivationPublicIdentityV1,
        RouterAbEcdsaDerivationStableKeyContextV1,
    };
    use router_ab_ecdsa_derivation::{
        derive_client_share, derive_relayer_share_for_client_public,
        RouterAbEcdsaDerivationStableKeyContext,
    };

    use super::*;

    struct SourcePreservingTestFixture {
        state: EcdsaReservationStateV1,
        material_activation: MpcMaterialActivationRefV1,
        worker: ServerIdentityV1,
        worker_private_key: [u8; 32],
        worker_recipient_public_key_b64u: String,
        scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
        active_signing_worker: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
        target_client_public_key33_b64u: String,
        target_relayer_public_key33_b64u: String,
        threshold_public_key33_b64u: String,
        threshold_ethereum_address20_b64u: String,
        binding_digest: [u8; 32],
    }

    fn b64u<const N: usize>(bytes: &[u8; N]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn x25519_keypair(seed: u8) -> ([u8; 32], String) {
        let (private, public) =
            DhKemX25519HkdfSha256::derive_key_pair(&[seed; 32]).expect("test HPKE key pair");
        let private = DhKemX25519HkdfSha256::sk_to_bytes(&private);
        (
            private
                .as_slice()
                .try_into()
                .expect("test private key bytes"),
            URL_SAFE_NO_PAD.encode(DhKemX25519HkdfSha256::pk_to_bytes(&public).as_slice()),
        )
    }

    fn ecdsa_activation(
        activation_id: &str,
        key_binding: &str,
    ) -> router_ab_ecdsa_client_protocol::EcdsaMaterialActivationRefV1 {
        router_ab_ecdsa_client_protocol::EcdsaMaterialActivationRefV1 {
            kind: router_ab_ecdsa_client_protocol::EcdsaMaterialActivationRefKindV1::MpcMaterialActivationRef,
            activation_id: activation_id.to_owned(),
            capability: "ecdsa-capability".to_owned(),
            material_owner: "wallet-1".to_owned(),
            key_binding: key_binding.to_owned(),
            lifecycle_binding: "ecdsa-lifecycle-binding".to_owned(),
            signing_worker: "worker-1".to_owned(),
        }
    }

    fn source_preserving_fixture() -> SourcePreservingTestFixture {
        let application_binding_digest = [0x29_u8; 32];
        let derivation_context =
            RouterAbEcdsaDerivationStableKeyContext::new(application_binding_digest);
        let client =
            derive_client_share(&derivation_context, [0x11_u8; 32]).expect("test client share");
        let (relayer, identity) = derive_relayer_share_for_client_public(
            &derivation_context,
            [0x22_u8; 32],
            &client.derivation_client_share_public_key33,
            client.retry_counter,
        )
        .expect("test relayer share");

        let (client_recipient_private_key, client_recipient_public_key_b64u) = x25519_keypair(0x41);
        let (worker_private_key, worker_recipient_public_key_b64u) = x25519_keypair(0x42);
        assert_ne!(client_recipient_private_key, worker_private_key);
        let key_binding = b64u(&identity.context_binding32);
        let source_activation = ecdsa_activation("source-activation", &key_binding);
        let target_activation = ecdsa_activation("target-activation", &key_binding);
        let binding = LinkedDeviceEcdsaSourceContributionBindingV1 {
            link_session_id: "link-session-1".to_owned(),
            enrollment_id: "enrollment-1".to_owned(),
            source_authority_id: "authority-1".to_owned(),
            source: router_ab_ecdsa_client_protocol::LinkedDeviceEcdsaSourceSignerIdentityV1 {
                activation: source_activation,
                client_public_key33_b64u: b64u(&client.derivation_client_share_public_key33),
                relayer_public_key33_b64u: b64u(&identity.relayer_public_key33),
                threshold_public_key33_b64u: b64u(&identity.threshold_public_key33),
                threshold_ethereum_address20_b64u: b64u(&identity.threshold_ethereum_address20),
            },
            target:
                router_ab_ecdsa_client_protocol::LinkedDeviceEcdsaTargetRecipientPreparationV1 {
                    activation: target_activation,
                    target_device_id: "device-2".to_owned(),
                    target_factor_verification_digest_b64u: b64u(&[0x71_u8; 32]),
                    client_recipient_public_key_b64u,
                    signing_worker_recipient_public_key_b64u: worker_recipient_public_key_b64u
                        .clone(),
                },
            target_client_public_key33_b64u: b64u(&client.derivation_client_share_public_key33),
        };
        let binding_digest = binding.digest().expect("test binding digest");
        let encrypted_target_client_share = seal_linked_device_ecdsa_source_contribution_v1(
            &binding.target.client_recipient_public_key_b64u,
            &binding_digest,
            &client.x_client32,
            [0x51_u8; 32],
        )
        .expect("test client envelope");
        let encrypted_target_server_share = seal_linked_device_ecdsa_source_contribution_v1(
            &binding.target.signing_worker_recipient_public_key_b64u,
            &binding_digest,
            &relayer.x_relayer32,
            [0x52_u8; 32],
        )
        .expect("test server envelope");
        let material_activation = MpcMaterialActivationRefV1::new(
            "target-activation",
            "ecdsa-capability",
            "wallet-1",
            key_binding,
            "ecdsa-lifecycle-binding",
            "worker-1",
        )
        .expect("test material activation");
        let reservation_id =
            source_preserving_reservation_id_v1(&material_activation, &binding_digest)
                .expect("test reservation id");
        let state = EcdsaReservationStateV1::SourcePreservingActive {
            binding,
            source_derivation: CloudflareEcdsaRegistrationSourceDerivationV1 {
                application_binding_digest_b64u: b64u(&application_binding_digest),
                client_share_retry_counter: client.retry_counter,
            },
            material_activation: material_activation.clone(),
            reservation_id: reservation_id.clone(),
            target_relayer_public_key33_b64u: b64u(&identity.relayer_public_key33),
            threshold_public_key33_b64u: b64u(&identity.threshold_public_key33),
            threshold_ethereum_address20_b64u: b64u(&identity.threshold_ethereum_address20),
            encrypted_target_client_share,
            encrypted_target_server_share,
        };
        state.validate().expect("test active reservation");

        let worker = ServerIdentityV1::new(
            "worker-1",
            "worker-key-epoch-1",
            worker_recipient_public_key_b64u.clone(),
        )
        .expect("test worker identity");
        let context =
            RouterAbEcdsaDerivationStableKeyContextV1::new(b64u(&application_binding_digest))
                .expect("test scope context");
        let public_identity = RouterAbEcdsaDerivationPublicIdentityV1::new(
            b64u(&identity.context_binding32),
            b64u(&identity.derivation_client_share_public_key33),
            b64u(&identity.relayer_public_key33),
            b64u(&identity.threshold_public_key33),
            b64u(&identity.threshold_ethereum_address20),
            identity.client_share_retry_counter,
            identity.relayer_share_retry_counter,
        )
        .expect("test public identity");
        let scope = RouterAbEcdsaDerivationNormalSigningScopeV1::new(
            "wallet-1",
            "ecdsa-threshold-key-1",
            "signing-root-1",
            "signing-root-version-1",
            context,
            public_identity,
            worker.clone(),
            "activation-epoch-1",
            material_activation.clone(),
        )
        .expect("test normal-signing scope");
        let active_signing_worker = ActiveSigningWorkerStateV1::new(
            "wallet-1",
            material_activation.clone(),
            b64u(&identity.threshold_public_key33),
            worker.clone(),
            PublicDigest32::new(binding_digest),
            PublicDigest32::new(binding_digest),
            format!("source-preserving-ecdsa/{reservation_id}"),
            1,
        )
        .expect("test active worker state");
        let material = CloudflareServerOutputMaterialRecordV1::new(
            PublicDigest32::new(binding_digest),
            OpenedShareKind::XServerBase,
            Role::Server,
            worker.server_id.clone(),
            CloudflareSecretMaterial32V1::new(relayer.x_relayer32),
        )
        .expect("test server material");

        SourcePreservingTestFixture {
            state,
            material_activation,
            worker,
            worker_private_key,
            worker_recipient_public_key_b64u,
            scope,
            active_signing_worker,
            material,
            target_client_public_key33_b64u: b64u(&identity.derivation_client_share_public_key33),
            target_relayer_public_key33_b64u: b64u(&identity.relayer_public_key33),
            threshold_public_key33_b64u: b64u(&identity.threshold_public_key33),
            threshold_ethereum_address20_b64u: b64u(&identity.threshold_ethereum_address20),
            binding_digest,
        }
    }

    fn transition_state(state: EcdsaReservationStateV1, revoked: bool) -> EcdsaReservationStateV1 {
        let EcdsaReservationStateV1::SourcePreservingActive {
            binding,
            source_derivation,
            material_activation,
            reservation_id,
            target_relayer_public_key33_b64u,
            threshold_public_key33_b64u,
            threshold_ethereum_address20_b64u,
            encrypted_target_client_share,
            encrypted_target_server_share,
        } = state
        else {
            panic!("test state must be active");
        };
        if revoked {
            EcdsaReservationStateV1::SourcePreservingRevoked {
                binding,
                source_derivation,
                material_activation,
                reservation_id,
                revoked_at_ms: 2,
            }
        } else {
            EcdsaReservationStateV1::SourcePreservingInactive {
                binding,
                source_derivation,
                material_activation,
                reservation_id,
                target_relayer_public_key33_b64u,
                threshold_public_key33_b64u,
                threshold_ethereum_address20_b64u,
                encrypted_target_client_share,
                encrypted_target_server_share,
            }
        }
    }

    #[test]
    fn source_preserving_active_material_passes_ordinary_ecdsa_validation() {
        let fixture = source_preserving_fixture();
        let view = select_source_preserving_active_reservation_v1(
            &fixture.state,
            &fixture.material_activation,
        )
        .expect("active source-preserving reservation");
        let (target_relayer_public_key33, binding_digest) =
            validate_source_preserving_target_identity_v1(
                &view,
                &fixture.material_activation,
                &fixture.worker,
                &fixture.worker_recipient_public_key_b64u,
                &fixture.target_client_public_key33_b64u,
                &fixture.target_relayer_public_key33_b64u,
                &fixture.threshold_public_key33_b64u,
                &fixture.threshold_ethereum_address20_b64u,
            )
            .expect("source-preserving public identity");
        let opened = decrypt_source_preserving_server_share_v1(
            view.encrypted_target_server_share,
            &fixture.worker_private_key,
            &binding_digest,
            &target_relayer_public_key33,
        )
        .expect("target server share");
        assert_eq!(
            opened.as_bytes(),
            fixture.material.output_material.as_bytes()
        );
        crate::validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1(
            &fixture.scope,
            &fixture.active_signing_worker,
            &fixture.material,
        )
        .expect("ordinary ECDSA material validation");
    }

    #[test]
    fn source_preserving_inactive_material_is_refused() {
        let fixture = source_preserving_fixture();
        let inactive = transition_state(fixture.state, false);
        let error =
            select_source_preserving_active_reservation_v1(&inactive, &fixture.material_activation)
                .err()
                .expect("inactive reservation must be refused");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::InvalidLifecycleState
        );
    }

    #[test]
    fn source_preserving_revoked_material_is_refused() {
        let fixture = source_preserving_fixture();
        let revoked = transition_state(fixture.state, true);
        let error =
            select_source_preserving_active_reservation_v1(&revoked, &fixture.material_activation)
                .err()
                .expect("revoked reservation must be refused");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::InvalidLifecycleState
        );
    }

    #[test]
    fn source_preserving_exact_activation_mismatch_is_refused() {
        let fixture = source_preserving_fixture();
        let mismatched_activation = MpcMaterialActivationRefV1::new(
            "different-activation",
            "ecdsa-capability",
            "wallet-1",
            "ecdsa-key-binding",
            "ecdsa-lifecycle-binding",
            "worker-1",
        )
        .expect("mismatched activation");
        let error =
            select_source_preserving_active_reservation_v1(&fixture.state, &mismatched_activation)
                .err()
                .expect("activation mismatch must be refused");
        assert_eq!(error.code(), RouterAbProtocolErrorCode::ConflictingPair);
    }

    #[test]
    fn source_preserving_client_server_threshold_and_recipient_mismatches_are_refused() {
        let fixture = source_preserving_fixture();
        let view = select_source_preserving_active_reservation_v1(
            &fixture.state,
            &fixture.material_activation,
        )
        .expect("active source-preserving reservation");
        let mismatches = [
            (
                "client",
                b64u(&[0x02_u8; 33]),
                fixture.target_relayer_public_key33_b64u.clone(),
                fixture.threshold_public_key33_b64u.clone(),
                fixture.worker_recipient_public_key_b64u.clone(),
            ),
            (
                "server",
                fixture.target_client_public_key33_b64u.clone(),
                b64u(&[0x03_u8; 33]),
                fixture.threshold_public_key33_b64u.clone(),
                fixture.worker_recipient_public_key_b64u.clone(),
            ),
            (
                "threshold",
                fixture.target_client_public_key33_b64u.clone(),
                fixture.target_relayer_public_key33_b64u.clone(),
                b64u(&[0x02_u8; 33]),
                fixture.worker_recipient_public_key_b64u.clone(),
            ),
            (
                "recipient",
                fixture.target_client_public_key33_b64u.clone(),
                fixture.target_relayer_public_key33_b64u.clone(),
                fixture.threshold_public_key33_b64u.clone(),
                x25519_keypair(0x43).1,
            ),
        ];
        for (label, client, relayer, threshold, recipient) in mismatches {
            let error = validate_source_preserving_target_identity_v1(
                &view,
                &fixture.material_activation,
                &fixture.worker,
                &recipient,
                &client,
                &relayer,
                &threshold,
                &fixture.threshold_ethereum_address20_b64u,
            )
            .err()
            .unwrap_or_else(|| panic!("{label} mismatch must be refused"));
            assert_eq!(
                error.code(),
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "{label} mismatch"
            );
        }
    }

    #[test]
    fn source_preserving_decrypted_share_public_key_mismatch_is_refused() {
        let fixture = source_preserving_fixture();
        let view = select_source_preserving_active_reservation_v1(
            &fixture.state,
            &fixture.material_activation,
        )
        .expect("active source-preserving reservation");
        let error = decrypt_source_preserving_server_share_v1(
            view.encrypted_target_server_share,
            &fixture.worker_private_key,
            &fixture.binding_digest,
            &[0x02_u8; 33],
        )
        .err()
        .expect("decrypted share identity mismatch must be refused");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
        );
    }

    #[test]
    fn source_preserving_material_identity_mismatch_is_refused() {
        let fixture = source_preserving_fixture();
        let mismatched_material = CloudflareServerOutputMaterialRecordV1::new(
            fixture.material.transcript_digest,
            fixture.material.opened_share_kind,
            fixture.material.recipient_role,
            fixture.material.recipient_identity.clone(),
            CloudflareSecretMaterial32V1::new([0x33_u8; 32]),
        )
        .expect("mismatched source-preserving material");
        let error = crate::validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1(
            &fixture.scope,
            &fixture.active_signing_worker,
            &mismatched_material,
        )
        .err()
        .expect("material identity mismatch must be refused");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
        );
    }

    #[test]
    fn deactivation_uses_the_same_active_output_identity_as_activation() {
        let material_activation = MpcMaterialActivationRefV1::new(
            "activation",
            "capability",
            "wallet",
            "key-binding",
            "lifecycle-binding",
            "signing-worker",
        )
        .expect("valid material activation");

        assert_eq!(
            active_output_key_v1(&material_activation),
            "active-signing-worker/wallet/activation/signing-worker"
        );
    }

    #[test]
    fn deactivation_reservation_key_is_family_scoped() {
        let material_activation = MpcMaterialActivationRefV1::new(
            "activation",
            "capability",
            "wallet",
            "key-binding",
            "lifecycle-binding",
            "signing-worker",
        )
        .expect("valid material activation");

        let key = reservation_record_key_v1(&material_activation).expect("record key");
        assert!(key.starts_with("ecdsa/"));
        assert_eq!(key.len(), "ecdsa/".len() + 64);
    }

    #[test]
    fn source_preserving_reservation_id_is_stable_and_binding_scoped() {
        let material_activation = MpcMaterialActivationRefV1::new(
            "target-activation",
            "capability",
            "wallet",
            "target-key-binding",
            "lifecycle-binding",
            "signing-worker",
        )
        .expect("valid material activation");
        let first = source_preserving_reservation_id_v1(&material_activation, &[7_u8; 32])
            .expect("source reservation id");
        let replay = source_preserving_reservation_id_v1(&material_activation, &[7_u8; 32])
            .expect("source reservation replay id");
        let changed = source_preserving_reservation_id_v1(&material_activation, &[8_u8; 32])
            .expect("source reservation changed id");
        assert_eq!(first, replay);
        assert_ne!(first, changed);
        assert!(first.starts_with("ordinary-ecdsa-source-preserving-inactive-v1:"));
    }

    #[test]
    fn source_preserving_state_contains_outputs_without_the_consumed_delta() {
        let source_activation = router_ab_ecdsa_client_protocol::EcdsaMaterialActivationRefV1 {
            kind: router_ab_ecdsa_client_protocol::EcdsaMaterialActivationRefKindV1::MpcMaterialActivationRef,
            activation_id: "source-activation".to_owned(),
            capability: "source-capability".to_owned(),
            material_owner: "wallet".to_owned(),
            key_binding: "source-key-binding".to_owned(),
            lifecycle_binding: "source-lifecycle-binding".to_owned(),
            signing_worker: "signing-worker".to_owned(),
        };
        let target_activation = router_ab_ecdsa_client_protocol::EcdsaMaterialActivationRefV1 {
            kind: router_ab_ecdsa_client_protocol::EcdsaMaterialActivationRefKindV1::MpcMaterialActivationRef,
            activation_id: "target-activation".to_owned(),
            capability: "target-capability".to_owned(),
            material_owner: "wallet".to_owned(),
            key_binding: "target-key-binding".to_owned(),
            lifecycle_binding: "target-lifecycle-binding".to_owned(),
            signing_worker: "signing-worker".to_owned(),
        };
        let binding = LinkedDeviceEcdsaSourceContributionBindingV1 {
            link_session_id: "link-session".to_owned(),
            enrollment_id: "enrollment".to_owned(),
            source_authority_id: "source-authority".to_owned(),
            source: router_ab_ecdsa_client_protocol::LinkedDeviceEcdsaSourceSignerIdentityV1 {
                activation: source_activation,
                client_public_key33_b64u: "source-client".to_owned(),
                relayer_public_key33_b64u: "source-relayer".to_owned(),
                threshold_public_key33_b64u: "source-threshold".to_owned(),
                threshold_ethereum_address20_b64u: "source-address".to_owned(),
            },
            target:
                router_ab_ecdsa_client_protocol::LinkedDeviceEcdsaTargetRecipientPreparationV1 {
                    activation: target_activation,
                    target_device_id: "device-2".to_owned(),
                    target_factor_verification_digest_b64u: "factor".to_owned(),
                    client_recipient_public_key_b64u: "client-recipient".to_owned(),
                    signing_worker_recipient_public_key_b64u: "worker-recipient".to_owned(),
                },
            target_client_public_key33_b64u: "target-client".to_owned(),
        };
        let envelope = LinkedDeviceEcdsaEncryptedSourceContributionV1 {
            kind: "linked-device-envelope".to_owned(),
            recipient_public_key_b64u: "recipient".to_owned(),
            binding_digest_b64u: "digest".to_owned(),
            encapped_key_b64u: "encapped".to_owned(),
            ciphertext_b64u: "ciphertext".to_owned(),
        };
        let material_activation = MpcMaterialActivationRefV1::new(
            "target-activation",
            "target-capability",
            "wallet",
            "target-key-binding",
            "target-lifecycle-binding",
            "signing-worker",
        )
        .expect("valid target material activation");
        let state = EcdsaReservationStateV1::SourcePreservingInactive {
            binding,
            source_derivation: CloudflareEcdsaRegistrationSourceDerivationV1 {
                application_binding_digest_b64u: "application-binding".to_owned(),
                client_share_retry_counter: 0,
            },
            material_activation,
            reservation_id: "reservation".to_owned(),
            target_relayer_public_key33_b64u: "target-relayer".to_owned(),
            threshold_public_key33_b64u: "target-threshold".to_owned(),
            threshold_ethereum_address20_b64u: "target-address".to_owned(),
            encrypted_target_client_share: envelope.clone(),
            encrypted_target_server_share: envelope,
        };
        let encoded = serde_json::to_value(state).expect("source reservation JSON");
        assert!(encoded.get("encrypted_delta").is_none());
        assert!(encoded.get("encrypted_target_client_share").is_some());
        assert!(encoded.get("encrypted_target_server_share").is_some());
    }

    #[test]
    fn source_preserving_route_name_is_stable() {
        assert_eq!(
            CLOUDFLARE_SIGNING_WORKER_ECDSA_RESERVE_INACTIVE_SOURCE_PRESERVING_PATH,
            "/router-ab/signing-worker/ecdsa-derivation/reserve-inactive-source-preserving"
        );
    }
}
