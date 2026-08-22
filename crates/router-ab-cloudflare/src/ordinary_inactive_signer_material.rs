use crate::{
    activate_cloudflare_signing_worker_server_output_v1, cloudflare_now_unix_ms_v1,
    cloudflare_server_output_material_record_from_activation_request_v1,
    compare_and_set_cloudflare_signing_worker_private_d1_secret_v1,
    load_cloudflare_server_output_hpke_private_key_bytes_v1,
    load_cloudflare_signing_worker_private_d1_secret_v1, CloudflareServerOutputMaterialRecordV1,
    seal_cloudflare_signer_envelope_hpke_payload_v1,
    CloudflareSignerEnvelopeHpkePublicKeyV1,
    CloudflareSigningWorkerOutputActivationReceiptV1,
    CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    CloudflareSigningWorkerRuntimeV1,
};
use router_ab_core::{
    decode_and_validate_signer_envelope_hpke_payload_v1, EncryptedPayloadV1, ExpensiveWorkKindV1,
    MpcMaterialActivationRefV1, Role, RoleEncryptedEnvelopeV1,
    RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1,
    RouterAbEcdsaDerivationRegistrationBootstrapRequestV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Env, Request, Response};

pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_RESERVE_INACTIVE_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/reserve-inactive";
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_ACTIVATE_RESERVATION_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/activate-reservation";

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
        validate_client_package_v1(
            registration,
            Role::SignerA,
            &self.deriver_a_client_package,
        )?;
        validate_client_package_v1(
            registration,
            Role::SignerB,
            &self.deriver_b_client_package,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEcdsaReservationActivationResponseV1 {
    pub receipt: CloudflareSigningWorkerOutputActivationReceiptV1,
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
    Active {
        registration: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        material: CloudflareServerOutputMaterialRecordV1,
        material_activation: MpcMaterialActivationRefV1,
        reservation_id: String,
        client_packages: EcdsaClientPackagePairV1,
        receipt: CloudflareSigningWorkerOutputActivationReceiptV1,
    },
}

impl EcdsaReservationStateV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
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
            } => (
                registration,
                activation,
                material,
                material_activation,
                reservation_id,
                client_packages,
            ),
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
    let receipt = activate_ecdsa_reservation_v1(env, runtime, &activation).await?;
    Response::from_json(&CloudflareEcdsaReservationActivationResponseV1 { receipt })
        .map_err(|_| invalid_reservation("ECDSA reservation response could not be encoded"))
}

async fn reserve_ecdsa_inactive_v1(
    env: &Env,
    request: &CloudflareEcdsaInactiveMaterialReservationRequestV1,
) -> RouterAbProtocolResult<(
    String,
    MpcMaterialActivationRefV1,
    EcdsaClientPackagePairV1,
)> {
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
                EcdsaReservationStateV1::Active {
                    activation: stored_activation,
                    reservation_id: stored_id,
                    ..
                } if stored_activation == activation && stored_id == &reservation_id => {
                    return Err(invalid_reservation(
                        "ordinary ECDSA material reservation is already active",
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
    let payload = seal_cloudflare_signer_envelope_hpke_payload_v1(&recipient_key, &aad, &plaintext)?;
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
    if package.header_digest != registration.request_header_digest()? || package.aad_digest != aad.digest() {
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
) -> RouterAbProtocolResult<CloudflareSigningWorkerOutputActivationReceiptV1> {
    let record_key = reservation_record_key_v1(&request.material_activation)?;
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
        match current.value {
            EcdsaReservationStateV1::Active {
                registration: _,
                activation,
                reservation_id,
                client_packages: _,
                receipt,
                ..
            } => {
                if reservation_id != request.reservation_id
                    || activation.material_activation != request.material_activation
                {
                    return Err(invalid_reservation(
                        "ordinary ECDSA reservation activation conflicts with the exact reservation",
                    ));
                }
                return Ok(receipt);
            }
            EcdsaReservationStateV1::Inactive {
                registration,
                activation,
                material,
                material_activation,
                reservation_id,
                client_packages,
            } => {
                if reservation_id != request.reservation_id
                    || material_activation != request.material_activation
                {
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
                        continue
                    }
                    Ok(()) => return Ok(receipt),
                    Err(error) => return Err(error),
                }
            }
        }
    }
    Err(invalid_reservation(
        "ordinary ECDSA reservation activation changed concurrently",
    ))
}

fn reservation_record_key_v1(
    material_activation: &MpcMaterialActivationRefV1,
) -> RouterAbProtocolResult<String> {
    let canonical = serde_json::to_vec(material_activation)
        .map_err(|_| invalid_reservation("ECDSA reservation identity could not be encoded"))?;
    let digest = Sha256::digest(canonical);
    Ok(format!("ecdsa/{}", encode_hex(&digest)))
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
