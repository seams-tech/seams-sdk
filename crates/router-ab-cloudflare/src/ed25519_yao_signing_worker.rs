use router_ab_core::{
    ActiveSigningWorkerStateV1, Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1,
    Ed25519YaoEncryptedPackageV1, Ed25519YaoOperationV1, Ed25519YaoPackageKindV1, OpenedShareKind,
    PublicDigest32, Role, RouterAbEd25519YaoActivationPublicReceiptV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, ServerIdentityV1,
};
use router_ab_ed25519_yao::{
    combine_ed25519_yao_signing_worker_packages_v1, Ed25519YaoActiveSigningMaterialV1,
    Ed25519YaoRecipientPrivateKeyV1, Ed25519YaoSigningWorkerActivationCandidateV1,
    Ed25519YaoSigningWorkerActivationReceiptV1, Ed25519YaoSigningWorkerPackageDeliveryV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Env, Request, Response};

use crate::{
    cloudflare_now_unix_ms_v1, compare_and_set_cloudflare_signing_worker_private_d1_secret_v1,
    load_cloudflare_server_output_hpke_private_key_bytes_v1,
    load_cloudflare_signing_worker_private_d1_secret_v1,
    put_cloudflare_signing_worker_output_activation_record_v1, CloudflareSecretMaterial32V1,
    CloudflareServerOutputMaterialRecordV1, CloudflareSigningWorkerOutputActivationRecordV1,
    CloudflareSigningWorkerRuntimeV1,
};

pub const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_PACKAGES_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/activation/packages";
pub const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/recovery/promote";
pub const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RESERVE_INACTIVE_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/reserve-inactive";
pub const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_ACTIVATE_RESERVATION_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/activate-reservation";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareEd25519YaoOutputActivationPutV1 {
    pub record: CloudflareSigningWorkerOutputActivationRecordV1,
}

impl CloudflareEd25519YaoOutputActivationPutV1 {
    fn new(
        record: CloudflareSigningWorkerOutputActivationRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self { record };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn validate(&self) -> RouterAbProtocolResult<()> {
        self.record.validate()?;
        match &self.record {
            CloudflareSigningWorkerOutputActivationRecordV1::Ed25519Yao { .. } => Ok(()),
            CloudflareSigningWorkerOutputActivationRecordV1::RecipientProofBundle { .. } => Err(
                invalid_lifecycle("Ed25519 Yao output activation requires Ed25519 Yao material"),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoRecoveryPromotionRequestV1 {
    pub binding: Ed25519YaoCeremonyBindingV1,
    pub public_receipt: RouterAbEd25519YaoActivationPublicReceiptV1,
}

impl CloudflareEd25519YaoRecoveryPromotionRequestV1 {
    pub(crate) fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
        if self.binding.operation != Ed25519YaoOperationV1::Recovery {
            return Err(invalid_lifecycle(
                "Ed25519 Yao recovery promotion requires a recovery binding",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPackagePairDeliveryV1 {
    pub deriver_a: Ed25519YaoSigningWorkerPackageDeliveryV1,
    pub deriver_b: Ed25519YaoSigningWorkerPackageDeliveryV1,
}

impl CloudflareEd25519YaoPackagePairDeliveryV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.deriver_a
            .validate_for_deriver(Ed25519YaoDeriverRoleV1::DeriverA)?;
        self.deriver_b
            .validate_for_deriver(Ed25519YaoDeriverRoleV1::DeriverB)?;
        if self.deriver_a.binding != self.deriver_b.binding {
            return Err(invalid_lifecycle(
                "Signing Worker package pair must share one ceremony binding",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoInactiveReservationRequestV1 {
    pub delivery: CloudflareEd25519YaoPackagePairDeliveryV1,
    pub deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
    pub deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
}

impl CloudflareEd25519YaoInactiveReservationRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.delivery.validate()?;
        if self.delivery.deriver_a.binding.operation != Ed25519YaoOperationV1::Registration {
            return Err(invalid_lifecycle(
                "ordinary Ed25519 reservation requires a registration package pair",
            ));
        }
        validate_client_package_v1(
            &self.deriver_a_client_package,
            &self.delivery.deriver_a.binding,
            Ed25519YaoDeriverRoleV1::DeriverA,
        )?;
        validate_client_package_v1(
            &self.deriver_b_client_package,
            &self.delivery.deriver_b.binding,
            Ed25519YaoDeriverRoleV1::DeriverB,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoActivateReservationRequestV1 {
    pub binding: Ed25519YaoCeremonyBindingV1,
    pub reservation_id: String,
}

impl CloudflareEd25519YaoActivateReservationRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
        if self.binding.operation != Ed25519YaoOperationV1::Registration {
            return Err(invalid_lifecycle(
                "ordinary Ed25519 reservation activation requires a registration binding",
            ));
        }
        require_non_empty_reservation_id(&self.reservation_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum SigningWorkerYaoCommandV1 {
    DeliverPackages {
        delivery: CloudflareEd25519YaoPackagePairDeliveryV1,
    },
    PromoteRecovery {
        request: CloudflareEd25519YaoRecoveryPromotionRequestV1,
    },
}

impl SigningWorkerYaoCommandV1 {
    fn stable_context_binding(&self) -> [u8; 32] {
        match self {
            Self::DeliverPackages { delivery } => delivery
                .deriver_a
                .binding
                .stable_key_context_binding
                .into_bytes(),
            Self::PromoteRecovery { request } => {
                request.binding.stable_key_context_binding.into_bytes()
            }
        }
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::DeliverPackages { delivery } => delivery.validate(),
            Self::PromoteRecovery { request } => request.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum SigningWorkerYaoDurableStateV1 {
    RegistrationStaged {
        deriver_a: Ed25519YaoSigningWorkerPackageDeliveryV1,
        deriver_b: Ed25519YaoSigningWorkerPackageDeliveryV1,
        candidate: Ed25519YaoActiveSigningMaterialV1,
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
    },
    Active {
        deriver_a: Ed25519YaoSigningWorkerPackageDeliveryV1,
        deriver_b: Ed25519YaoSigningWorkerPackageDeliveryV1,
        material: Ed25519YaoActiveSigningMaterialV1,
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
    },
    RecoveryStaged {
        active_material: Ed25519YaoActiveSigningMaterialV1,
        active_receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
        deriver_a: Ed25519YaoSigningWorkerPackageDeliveryV1,
        deriver_b: Ed25519YaoSigningWorkerPackageDeliveryV1,
        candidate: Ed25519YaoActiveSigningMaterialV1,
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
    },
}

impl SigningWorkerYaoDurableStateV1 {
    fn stable_context_binding(&self) -> [u8; 32] {
        match self {
            Self::RegistrationStaged { deriver_a, .. } | Self::RecoveryStaged { deriver_a, .. } => {
                deriver_a.binding.stable_key_context_binding.into_bytes()
            }
            Self::Active { material, .. } => {
                material.binding().stable_key_context_binding.into_bytes()
            }
        }
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::RegistrationStaged {
                deriver_a,
                deriver_b,
                candidate,
                receipt,
            } => validate_staged_candidate(
                deriver_a,
                deriver_b,
                candidate,
                receipt,
                Ed25519YaoOperationV1::Registration,
            ),
            Self::Active {
                deriver_a,
                deriver_b,
                material,
                receipt,
            } => validate_staged_candidate(
                deriver_a,
                deriver_b,
                material,
                receipt,
                material.binding().operation,
            ),
            Self::RecoveryStaged {
                active_material,
                active_receipt,
                deriver_a,
                deriver_b,
                candidate,
                receipt,
            } => {
                validate_material_receipt(active_material, active_receipt)?;
                require_same_stable_identity(active_material.binding(), &deriver_a.binding)?;
                validate_staged_candidate(
                    deriver_a,
                    deriver_b,
                    candidate,
                    receipt,
                    Ed25519YaoOperationV1::Recovery,
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum SigningWorkerYaoCommandResponseV1 {
    Active {
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
    },
    Staged {
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum SigningWorkerYaoReservationStateV1 {
    Inactive {
        delivery: CloudflareEd25519YaoPackagePairDeliveryV1,
        deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
        deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
        candidate: Ed25519YaoActiveSigningMaterialV1,
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
        reservation_id: String,
    },
    Active {
        delivery: CloudflareEd25519YaoPackagePairDeliveryV1,
        deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
        deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
        candidate: Ed25519YaoActiveSigningMaterialV1,
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
        reservation_id: String,
    },
}

impl SigningWorkerYaoReservationStateV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        let (delivery, candidate, receipt, reservation_id) = match self {
            Self::Inactive {
                delivery,
                candidate,
                receipt,
                reservation_id,
                ..
            }
            | Self::Active {
                delivery,
                candidate,
                receipt,
                reservation_id,
                ..
            } => (delivery, candidate, receipt, reservation_id),
        };
        let (deriver_a_client_package, deriver_b_client_package) = match self {
            Self::Inactive {
                deriver_a_client_package,
                deriver_b_client_package,
                ..
            }
            | Self::Active {
                deriver_a_client_package,
                deriver_b_client_package,
                ..
            } => (deriver_a_client_package, deriver_b_client_package),
        };
        CloudflareEd25519YaoInactiveReservationRequestV1 {
            delivery: delivery.clone(),
            deriver_a_client_package: deriver_a_client_package.clone(),
            deriver_b_client_package: deriver_b_client_package.clone(),
        }
        .validate()?;
        validate_staged_candidate(
            &delivery.deriver_a,
            &delivery.deriver_b,
            candidate,
            receipt,
            Ed25519YaoOperationV1::Registration,
        )?;
        validate_client_package_v1(
            deriver_a_client_package,
            &delivery.deriver_a.binding,
            Ed25519YaoDeriverRoleV1::DeriverA,
        )?;
        validate_client_package_v1(
            deriver_b_client_package,
            &delivery.deriver_b.binding,
            Ed25519YaoDeriverRoleV1::DeriverB,
        )?;
        if deriver_a_client_package.transcript() != receipt.transcript
            || deriver_b_client_package.transcript() != receipt.transcript
        {
            return Err(invalid_lifecycle(
                "ordinary Ed25519 client packages do not match the activation transcript",
            ));
        }
        require_non_empty_reservation_id(reservation_id)
    }
}

pub async fn handle_cloudflare_signing_worker_ed25519_yao_packages_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let delivery = parse_request::<CloudflareEd25519YaoPackagePairDeliveryV1>(&mut request).await?;
    delivery.validate()?;
    let response = execute_signing_worker_yao_command(
        env,
        SigningWorkerYaoCommandV1::DeliverPackages { delivery },
    )
    .await?;
    json_response(&http_response_from_command(response)?)
}

pub async fn handle_cloudflare_signing_worker_ed25519_yao_recovery_promote_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let promotion =
        parse_request::<CloudflareEd25519YaoRecoveryPromotionRequestV1>(&mut request).await?;
    promotion.validate()?;
    let response = execute_signing_worker_yao_command(
        env,
        SigningWorkerYaoCommandV1::PromoteRecovery { request: promotion },
    )
    .await?;
    json_response(&http_response_from_command(response)?)
}

pub async fn handle_cloudflare_signing_worker_ed25519_yao_reserve_inactive_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let reservation =
        parse_request::<CloudflareEd25519YaoInactiveReservationRequestV1>(&mut request).await?;
    reservation.validate()?;
    let (reservation_id, receipt, deriver_a_client_package, deriver_b_client_package) =
        reserve_inactive_ed25519_yao_v1(env, &reservation).await?;
    json_response(&CloudflareEd25519YaoInactiveReservationResponseV1 {
        state: "inactive",
        reservation_id,
        receipt,
        deriver_a_client_package,
        deriver_b_client_package,
    })
}

pub async fn handle_cloudflare_signing_worker_ed25519_yao_activate_reservation_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let activation =
        parse_request::<CloudflareEd25519YaoActivateReservationRequestV1>(&mut request).await?;
    activation.validate()?;
    let receipt = activate_ed25519_yao_reservation_v1(env, &activation).await?;
    json_response(&CloudflareEd25519YaoReservationActivationResponseV1 { receipt })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoInactiveReservationResponseV1 {
    pub state: &'static str,
    pub reservation_id: String,
    pub receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
    pub deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
    pub deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoReservationActivationResponseV1 {
    pub receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
}

async fn reserve_inactive_ed25519_yao_v1(
    env: &Env,
    request: &CloudflareEd25519YaoInactiveReservationRequestV1,
) -> RouterAbProtocolResult<(
    String,
    Ed25519YaoSigningWorkerActivationReceiptV1,
    Ed25519YaoEncryptedPackageV1,
    Ed25519YaoEncryptedPackageV1,
)> {
    request.validate()?;
    let delivery = &request.delivery;
    let record_key = reservation_record_key_v1(delivery)?;
    let reservation_id = format!(
        "ordinary-ed25519-inactive-v1:{}",
        record_key.trim_start_matches("ed25519/")
    );
    for _ in 0..3 {
        let current = load_cloudflare_signing_worker_private_d1_secret_v1::<
            SigningWorkerYaoReservationStateV1,
        >(env, "ed25519_yao_reservations", &record_key)
        .await?;
        if let Some(current) = current.as_ref() {
            current.value.validate()?;
            match &current.value {
                SigningWorkerYaoReservationStateV1::Inactive {
                    delivery: stored_delivery,
                    deriver_a_client_package,
                    deriver_b_client_package,
                    receipt,
                    reservation_id: stored_id,
                    ..
                } if stored_id == &reservation_id && stored_delivery == delivery => {
                    return Ok((
                        reservation_id,
                        receipt.clone(),
                        deriver_a_client_package.clone(),
                        deriver_b_client_package.clone(),
                    ));
                }
                SigningWorkerYaoReservationStateV1::Active {
                    delivery: stored_delivery,
                    reservation_id: stored_id,
                    ..
                } if stored_delivery == delivery && stored_id == &reservation_id => {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 material reservation is already active",
                    ));
                }
                _ => {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 material reservation conflicts with the exact activation ref",
                    ));
                }
            }
        }
        let candidate = combine_signing_worker_yao_packages_v1(env, delivery, None)?;
        let (candidate, receipt) = candidate.into_parts();
        let state = SigningWorkerYaoReservationStateV1::Inactive {
            delivery: delivery.clone(),
            deriver_a_client_package: request.deriver_a_client_package.clone(),
            deriver_b_client_package: request.deriver_b_client_package.clone(),
            candidate,
            receipt: receipt.clone(),
            reservation_id: reservation_id.clone(),
        };
        match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
            env,
            "ed25519_yao_reservations",
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
                    receipt,
                    request.deriver_a_client_package.clone(),
                    request.deriver_b_client_package.clone(),
                ))
            }
            Err(error) => return Err(error),
        }
    }
    Err(invalid_lifecycle(
        "ordinary Ed25519 material reservation changed concurrently",
    ))
}

async fn activate_ed25519_yao_reservation_v1(
    env: &Env,
    request: &CloudflareEd25519YaoActivateReservationRequestV1,
) -> RouterAbProtocolResult<Ed25519YaoSigningWorkerActivationReceiptV1> {
    request.validate()?;
    let record_key = reservation_record_key_from_binding_v1(&request.binding)?;
    for _ in 0..3 {
        let current = load_cloudflare_signing_worker_private_d1_secret_v1::<
            SigningWorkerYaoReservationStateV1,
        >(env, "ed25519_yao_reservations", &record_key)
        .await?
        .ok_or_else(|| invalid_lifecycle("ordinary Ed25519 material reservation is missing"))?;
        current.value.validate()?;
        match current.value {
            SigningWorkerYaoReservationStateV1::Active {
                delivery,
                receipt,
                reservation_id,
                ..
            } => {
                if reservation_id != request.reservation_id
                    || delivery.deriver_a.binding != request.binding
                {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 reservation activation conflicts with the exact reservation",
                    ));
                }
                return Ok(receipt);
            }
            SigningWorkerYaoReservationStateV1::Inactive {
                delivery,
                deriver_a_client_package,
                deriver_b_client_package,
                candidate,
                receipt,
                reservation_id,
            } => {
                if reservation_id != request.reservation_id
                    || delivery.deriver_a.binding != request.binding
                {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 reservation activation conflicts with the exact reservation",
                    ));
                }
                persist_signing_worker_yao_active_output_v1(env, &candidate, &receipt).await?;
                let active = SigningWorkerYaoReservationStateV1::Active {
                    delivery,
                    deriver_a_client_package,
                    deriver_b_client_package,
                    candidate,
                    receipt: receipt.clone(),
                    reservation_id,
                };
                match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
                    env,
                    "ed25519_yao_reservations",
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
    Err(invalid_lifecycle(
        "ordinary Ed25519 reservation activation changed concurrently",
    ))
}

fn reservation_record_key_v1(
    delivery: &CloudflareEd25519YaoPackagePairDeliveryV1,
) -> RouterAbProtocolResult<String> {
    reservation_record_key_from_binding_v1(&delivery.deriver_a.binding)
}

fn reservation_record_key_from_binding_v1(
    binding: &Ed25519YaoCeremonyBindingV1,
) -> RouterAbProtocolResult<String> {
    let canonical = serde_json::to_vec(binding.material_activation()).map_err(|_| {
        invalid_lifecycle("ordinary Ed25519 reservation identity could not be encoded")
    })?;
    let digest = Sha256::digest(canonical);
    Ok(format!("ed25519/{}", encode_hex_slice(&digest)))
}

fn validate_client_package_v1(
    package: &Ed25519YaoEncryptedPackageV1,
    binding: &Ed25519YaoCeremonyBindingV1,
    expected_deriver: Ed25519YaoDeriverRoleV1,
) -> RouterAbProtocolResult<()> {
    package.validate()?;
    if package.kind() != Ed25519YaoPackageKindV1::ActivationClient
        || package.deriver() != expected_deriver
        || package.session() != binding.session_id.into_bytes()
    {
        return Err(invalid_lifecycle(
            "ordinary Ed25519 client package does not match its activation binding",
        ));
    }
    Ok(())
}

fn require_non_empty_reservation_id(value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() || value.chars().any(|character| character.is_ascii_control()) {
        return Err(invalid_lifecycle(
            "ordinary Ed25519 reservation id is invalid",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum CloudflareEd25519YaoSigningWorkerHttpResponseV1 {
    Active {
        session: [u8; 32],
        transcript: [u8; 32],
        registered_public_key: [u8; 32],
        joined_client_commitment: [u8; 32],
        joined_signing_worker_commitment: [u8; 32],
        signing_worker_verifying_share: [u8; 32],
        state_epoch: u64,
    },
    Staged {
        session: [u8; 32],
        transcript: [u8; 32],
        registered_public_key: [u8; 32],
        joined_client_commitment: [u8; 32],
        joined_signing_worker_commitment: [u8; 32],
        signing_worker_verifying_share: [u8; 32],
        state_epoch: u64,
    },
}

fn http_response_from_command(
    response: SigningWorkerYaoCommandResponseV1,
) -> RouterAbProtocolResult<CloudflareEd25519YaoSigningWorkerHttpResponseV1> {
    match response {
        SigningWorkerYaoCommandResponseV1::Active { receipt } => Ok(http_active_receipt(receipt)),
        SigningWorkerYaoCommandResponseV1::Staged { receipt } => Ok(http_staged_receipt(receipt)),
    }
}

fn http_active_receipt(
    receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
) -> CloudflareEd25519YaoSigningWorkerHttpResponseV1 {
    CloudflareEd25519YaoSigningWorkerHttpResponseV1::Active {
        session: receipt.session,
        transcript: receipt.transcript,
        registered_public_key: receipt.registered_public_key,
        joined_client_commitment: receipt.joined_client_commitment,
        joined_signing_worker_commitment: receipt.joined_signing_worker_commitment,
        signing_worker_verifying_share: receipt.signing_worker_verifying_share,
        state_epoch: receipt.state_epoch.get(),
    }
}

fn http_staged_receipt(
    receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
) -> CloudflareEd25519YaoSigningWorkerHttpResponseV1 {
    CloudflareEd25519YaoSigningWorkerHttpResponseV1::Staged {
        session: receipt.session,
        transcript: receipt.transcript,
        registered_public_key: receipt.registered_public_key,
        joined_client_commitment: receipt.joined_client_commitment,
        joined_signing_worker_commitment: receipt.joined_signing_worker_commitment,
        signing_worker_verifying_share: receipt.signing_worker_verifying_share,
        state_epoch: receipt.state_epoch.get(),
    }
}

async fn execute_signing_worker_yao_command(
    env: &Env,
    command: SigningWorkerYaoCommandV1,
) -> RouterAbProtocolResult<SigningWorkerYaoCommandResponseV1> {
    command.validate()?;
    let record_key = encode_hex(command.stable_context_binding());
    for _ in 0..3 {
        let current = load_cloudflare_signing_worker_private_d1_secret_v1::<
            SigningWorkerYaoDurableStateV1,
        >(env, "ed25519_yao_lifecycle", &record_key)
        .await?;
        if let Some(current) = current.as_ref() {
            current.value.validate()?;
            if current.value.stable_context_binding() != command.stable_context_binding() {
                return Err(invalid_lifecycle(
                    "Ed25519 Yao private D1 stable identity mismatch",
                ));
            }
        }
        match execute_signing_worker_yao_d1_transition_v1(env, &record_key, current, &command).await
        {
            Err(error) if error.code() == RouterAbProtocolErrorCode::ConflictingPair => continue,
            result => return result,
        }
    }
    Err(invalid_lifecycle(
        "Signing Worker Yao private D1 lifecycle changed concurrently",
    ))
}

async fn execute_signing_worker_yao_d1_transition_v1(
    env: &Env,
    record_key: &str,
    current: Option<
        crate::CloudflareSigningWorkerPrivateD1VersionedSecretV1<SigningWorkerYaoDurableStateV1>,
    >,
    command: &SigningWorkerYaoCommandV1,
) -> RouterAbProtocolResult<SigningWorkerYaoCommandResponseV1> {
    let expected_version = current.as_ref().map(|current| current.version);
    let current = current.map(|current| current.value);
    match command {
        SigningWorkerYaoCommandV1::DeliverPackages { delivery } => {
            execute_signing_worker_yao_delivery_d1_transition_v1(
                env,
                record_key,
                expected_version,
                current,
                delivery,
            )
            .await
        }
        SigningWorkerYaoCommandV1::PromoteRecovery { request } => {
            execute_signing_worker_yao_promotion_d1_transition_v1(
                env,
                record_key,
                expected_version,
                current,
                request,
            )
            .await
        }
    }
}

async fn execute_signing_worker_yao_delivery_d1_transition_v1(
    env: &Env,
    record_key: &str,
    expected_version: Option<i64>,
    current: Option<SigningWorkerYaoDurableStateV1>,
    delivery: &CloudflareEd25519YaoPackagePairDeliveryV1,
) -> RouterAbProtocolResult<SigningWorkerYaoCommandResponseV1> {
    match (delivery.deriver_a.binding.operation, current) {
        (Ed25519YaoOperationV1::Registration, None) => {
            let candidate = combine_signing_worker_yao_packages_v1(env, delivery, None)?;
            let (candidate, receipt) = candidate.into_parts();
            let staged = SigningWorkerYaoDurableStateV1::RegistrationStaged {
                deriver_a: delivery.deriver_a.clone(),
                deriver_b: delivery.deriver_b.clone(),
                candidate,
                receipt,
            };
            staged.validate()?;
            persist_signing_worker_yao_state_v1(env, record_key, expected_version, &staged).await?;
            let SigningWorkerYaoDurableStateV1::RegistrationStaged {
                deriver_a,
                deriver_b,
                candidate,
                receipt,
            } = staged
            else {
                unreachable!("registration branch constructs registration-staged state");
            };
            persist_signing_worker_yao_active_output_v1(env, &candidate, &receipt).await?;
            let active = SigningWorkerYaoDurableStateV1::Active {
                deriver_a,
                deriver_b,
                material: candidate,
                receipt: receipt.clone(),
            };
            persist_signing_worker_yao_state_v1(env, record_key, Some(1), &active).await?;
            Ok(SigningWorkerYaoCommandResponseV1::Active { receipt })
        }
        (
            Ed25519YaoOperationV1::Registration,
            Some(SigningWorkerYaoDurableStateV1::RegistrationStaged {
                deriver_a,
                deriver_b,
                candidate,
                receipt,
            }),
        ) if deriver_a == delivery.deriver_a && deriver_b == delivery.deriver_b => {
            persist_signing_worker_yao_active_output_v1(env, &candidate, &receipt).await?;
            let active = SigningWorkerYaoDurableStateV1::Active {
                deriver_a,
                deriver_b,
                material: candidate,
                receipt: receipt.clone(),
            };
            persist_signing_worker_yao_state_v1(env, record_key, expected_version, &active).await?;
            Ok(SigningWorkerYaoCommandResponseV1::Active { receipt })
        }
        (
            Ed25519YaoOperationV1::Registration,
            Some(SigningWorkerYaoDurableStateV1::Active {
                deriver_a,
                deriver_b,
                material,
                receipt,
            }),
        ) if deriver_a == delivery.deriver_a && deriver_b == delivery.deriver_b => {
            persist_signing_worker_yao_active_output_v1(env, &material, &receipt).await?;
            Ok(SigningWorkerYaoCommandResponseV1::Active { receipt })
        }
        (
            Ed25519YaoOperationV1::Recovery,
            Some(SigningWorkerYaoDurableStateV1::Active {
                deriver_a,
                deriver_b,
                material,
                receipt,
            }),
        ) if material.binding().operation == Ed25519YaoOperationV1::Recovery
            && deriver_a == delivery.deriver_a
            && deriver_b == delivery.deriver_b =>
        {
            Ok(SigningWorkerYaoCommandResponseV1::Staged { receipt })
        }
        (
            Ed25519YaoOperationV1::Recovery,
            Some(SigningWorkerYaoDurableStateV1::Active {
                material: active_material,
                receipt: active_receipt,
                ..
            }),
        ) => {
            require_same_stable_identity(active_material.binding(), &delivery.deriver_a.binding)?;
            let candidate =
                combine_signing_worker_yao_packages_v1(env, delivery, Some(&active_material))?;
            let (candidate, receipt) = candidate.into_parts();
            let staged = SigningWorkerYaoDurableStateV1::RecoveryStaged {
                active_material,
                active_receipt,
                deriver_a: delivery.deriver_a.clone(),
                deriver_b: delivery.deriver_b.clone(),
                candidate,
                receipt: receipt.clone(),
            };
            staged.validate()?;
            persist_signing_worker_yao_state_v1(env, record_key, expected_version, &staged).await?;
            Ok(SigningWorkerYaoCommandResponseV1::Staged { receipt })
        }
        (
            Ed25519YaoOperationV1::Recovery,
            Some(SigningWorkerYaoDurableStateV1::RecoveryStaged {
                deriver_a,
                deriver_b,
                receipt,
                ..
            }),
        ) if deriver_a == delivery.deriver_a && deriver_b == delivery.deriver_b => {
            Ok(SigningWorkerYaoCommandResponseV1::Staged { receipt })
        }
        _ => Err(invalid_lifecycle(
            "Signing Worker package pair conflicts with the Yao lifecycle state",
        )),
    }
}

async fn execute_signing_worker_yao_promotion_d1_transition_v1(
    env: &Env,
    record_key: &str,
    expected_version: Option<i64>,
    current: Option<SigningWorkerYaoDurableStateV1>,
    request: &CloudflareEd25519YaoRecoveryPromotionRequestV1,
) -> RouterAbProtocolResult<SigningWorkerYaoCommandResponseV1> {
    if let Some(SigningWorkerYaoDurableStateV1::Active {
        material, receipt, ..
    }) = current.as_ref()
    {
        if material.binding().operation == Ed25519YaoOperationV1::Recovery {
            validate_promotion_request(request, material.binding(), receipt)?;
            persist_signing_worker_yao_active_output_v1(env, material, receipt).await?;
            return Ok(SigningWorkerYaoCommandResponseV1::Active {
                receipt: receipt.clone(),
            });
        }
    }
    let Some(SigningWorkerYaoDurableStateV1::RecoveryStaged {
        deriver_a,
        deriver_b,
        candidate,
        receipt,
        ..
    }) = current
    else {
        return Err(invalid_lifecycle(
            "recovery promotion requires an exact staged candidate",
        ));
    };
    validate_promotion_request(request, candidate.binding(), &receipt)?;
    persist_signing_worker_yao_active_output_v1(env, &candidate, &receipt).await?;
    let active = SigningWorkerYaoDurableStateV1::Active {
        deriver_a,
        deriver_b,
        material: candidate,
        receipt: receipt.clone(),
    };
    persist_signing_worker_yao_state_v1(env, record_key, expected_version, &active).await?;
    Ok(SigningWorkerYaoCommandResponseV1::Active { receipt })
}

fn combine_signing_worker_yao_packages_v1(
    env: &Env,
    delivery: &CloudflareEd25519YaoPackagePairDeliveryV1,
    active: Option<&Ed25519YaoActiveSigningMaterialV1>,
) -> RouterAbProtocolResult<Ed25519YaoSigningWorkerActivationCandidateV1> {
    let runtime = CloudflareSigningWorkerRuntimeV1::from_worker_env(env)?;
    let private_key = load_cloudflare_server_output_hpke_private_key_bytes_v1(
        env,
        runtime.server_output_decrypt_key(),
    )?;
    combine_ed25519_yao_signing_worker_packages_v1(
        &Ed25519YaoRecipientPrivateKeyV1::from_bytes(private_key),
        delivery.deriver_a.clone(),
        delivery.deriver_b.clone(),
        active,
    )
}

async fn persist_signing_worker_yao_state_v1(
    env: &Env,
    record_key: &str,
    expected_version: Option<i64>,
    state: &SigningWorkerYaoDurableStateV1,
) -> RouterAbProtocolResult<()> {
    state.validate()?;
    compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
        env,
        "ed25519_yao_lifecycle",
        record_key,
        expected_version,
        state,
        cloudflare_now_unix_ms_v1()?,
    )
    .await
}

async fn persist_signing_worker_yao_active_output_v1(
    env: &Env,
    material: &Ed25519YaoActiveSigningMaterialV1,
    receipt: &Ed25519YaoSigningWorkerActivationReceiptV1,
) -> RouterAbProtocolResult<()> {
    let runtime = CloudflareSigningWorkerRuntimeV1::from_worker_env(env)?;
    let record = build_output_activation_record(&runtime, material, receipt)?;
    persist_cloudflare_ed25519_yao_output_activation_v1(env, &runtime, record).await
}

async fn persist_cloudflare_ed25519_yao_output_activation_v1(
    env: &Env,
    _runtime: &CloudflareSigningWorkerRuntimeV1,
    record: CloudflareSigningWorkerOutputActivationRecordV1,
) -> RouterAbProtocolResult<()> {
    let activation_request = CloudflareEd25519YaoOutputActivationPutV1::new(record)?;
    let activated_at_ms = activation_request
        .record
        .active_signing_worker_state()
        .activated_at_ms;
    put_cloudflare_signing_worker_output_activation_record_v1(
        env,
        &activation_request.record,
        activated_at_ms,
    )
    .await?;
    Ok(())
}

fn build_output_activation_record(
    runtime: &CloudflareSigningWorkerRuntimeV1,
    yao_material: &Ed25519YaoActiveSigningMaterialV1,
    receipt: &Ed25519YaoSigningWorkerActivationReceiptV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerOutputActivationRecordV1> {
    validate_material_receipt(yao_material, receipt)?;
    let binding = yao_material.binding();
    let decrypt_key = runtime.server_output_decrypt_key();
    let signing_worker = ServerIdentityV1::new(
        binding.lifecycle.selected_server_id.clone(),
        decrypt_key.key_epoch.clone(),
        decrypt_key.public_key.clone(),
    )?;
    decrypt_key.validate_matches_server(&signing_worker)?;
    let material_handle = format!(
        "signing-worker-private/ed25519-yao/{}/{}",
        encode_hex(binding.stable_key_context_binding.into_bytes()),
        yao_material.state_epoch().get()
    );
    let active_state = ActiveSigningWorkerStateV1::new(
        binding.lifecycle.account_id.clone(),
        binding.material_activation().clone(),
        format!(
            "ed25519:{}",
            bs58::encode(receipt.registered_public_key).into_string()
        ),
        signing_worker,
        PublicDigest32::new(receipt.transcript),
        PublicDigest32::new(receipt.registered_public_key),
        material_handle,
        cloudflare_now_unix_ms_v1()?,
    )?;
    let material = CloudflareServerOutputMaterialRecordV1::new(
        PublicDigest32::new(receipt.transcript),
        OpenedShareKind::XServerBase,
        Role::Server,
        binding.lifecycle.selected_server_id.clone(),
        CloudflareSecretMaterial32V1::new(*yao_material.scalar()),
    )?;
    CloudflareSigningWorkerOutputActivationRecordV1::ed25519_yao(
        binding.clone(),
        receipt.clone(),
        active_state,
        material,
    )
}

fn validate_staged_candidate(
    deriver_a: &Ed25519YaoSigningWorkerPackageDeliveryV1,
    deriver_b: &Ed25519YaoSigningWorkerPackageDeliveryV1,
    candidate: &Ed25519YaoActiveSigningMaterialV1,
    receipt: &Ed25519YaoSigningWorkerActivationReceiptV1,
    operation: Ed25519YaoOperationV1,
) -> RouterAbProtocolResult<()> {
    deriver_a.validate_for_deriver(Ed25519YaoDeriverRoleV1::DeriverA)?;
    deriver_b.validate_for_deriver(Ed25519YaoDeriverRoleV1::DeriverB)?;
    require_operation(&deriver_a.binding, operation)?;
    if deriver_a.binding != deriver_b.binding || candidate.binding() != &deriver_a.binding {
        return Err(invalid_lifecycle(
            "staged Signing Worker Yao packages do not share one binding",
        ));
    }
    validate_material_receipt(candidate, receipt)
}

fn validate_material_receipt(
    material: &Ed25519YaoActiveSigningMaterialV1,
    receipt: &Ed25519YaoSigningWorkerActivationReceiptV1,
) -> RouterAbProtocolResult<()> {
    material.validate()?;
    if receipt.session != material.binding().session_id.into_bytes()
        || receipt.transcript != material.transcript()
        || receipt.registered_public_key != material.registered_public_key()
        || receipt.state_epoch != material.state_epoch()
        || receipt.signing_worker_verifying_share != receipt.joined_signing_worker_commitment
    {
        return Err(invalid_lifecycle(
            "Signing Worker Yao material does not match its public receipt",
        ));
    }
    Ok(())
}

fn validate_promotion_request(
    request: &CloudflareEd25519YaoRecoveryPromotionRequestV1,
    candidate_binding: &Ed25519YaoCeremonyBindingV1,
    receipt: &Ed25519YaoSigningWorkerActivationReceiptV1,
) -> RouterAbProtocolResult<()> {
    request.validate()?;
    let public = &request.public_receipt;
    if &request.binding != candidate_binding
        || request.binding.session_id.into_bytes() != receipt.session
        || public.transcript() != receipt.transcript
        || public.registered_public_key() != receipt.registered_public_key
        || public.joined_client_commitment() != receipt.joined_client_commitment
        || public.joined_signing_worker_commitment() != receipt.joined_signing_worker_commitment
        || public.signing_worker_verifying_share() != receipt.signing_worker_verifying_share
        || public.state_epoch() != receipt.state_epoch
    {
        return Err(invalid_lifecycle(
            "recovery promotion does not match the exact staged Yao receipt",
        ));
    }
    Ok(())
}

fn require_operation(
    binding: &Ed25519YaoCeremonyBindingV1,
    expected: Ed25519YaoOperationV1,
) -> RouterAbProtocolResult<()> {
    binding.validate()?;
    if binding.operation == expected {
        return Ok(());
    }
    Err(invalid_lifecycle(
        "Signing Worker Yao lifecycle operation mismatch",
    ))
}

fn require_same_stable_identity(
    active: &Ed25519YaoCeremonyBindingV1,
    candidate: &Ed25519YaoCeremonyBindingV1,
) -> RouterAbProtocolResult<()> {
    if active.stable_key_context_binding == candidate.stable_key_context_binding
        && active.lifecycle.root_share_epoch == candidate.lifecycle.root_share_epoch
        && active.lifecycle.account_id == candidate.lifecycle.account_id
        && active.lifecycle.signer_set_id == candidate.lifecycle.signer_set_id
        && active.lifecycle.selected_server_id == candidate.lifecycle.selected_server_id
    {
        return Ok(());
    }
    Err(invalid_lifecycle(
        "Signing Worker Yao recovery changed the stable signing identity",
    ))
}

async fn parse_request<T>(request: &mut Request) -> RouterAbProtocolResult<T>
where
    T: serde::de::DeserializeOwned,
{
    request
        .json::<T>()
        .await
        .map_err(|_| invalid_lifecycle("Signing Worker Yao request JSON is malformed"))
}

fn json_response<T>(value: &T) -> RouterAbProtocolResult<Response>
where
    T: Serialize,
{
    Response::from_json(value)
        .map_err(|_| invalid_lifecycle("Signing Worker Yao response could not be encoded"))
}

fn invalid_lifecycle(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        message.into(),
    )
}

fn encode_hex(bytes: [u8; 32]) -> String {
    encode_hex_slice(&bytes)
}

fn encode_hex_slice(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        output.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    output
}
