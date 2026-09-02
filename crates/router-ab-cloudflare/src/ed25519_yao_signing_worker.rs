use router_ab_core::{
    ActiveSigningWorkerStateV1, Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1,
    Ed25519YaoEncryptedPackageV1, Ed25519YaoOperationV1, Ed25519YaoPackageKindV1, OpenedShareKind,
    PublicDigest32, Role, RouterAbEd25519YaoActivationPublicReceiptV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, ServerIdentityV1,
};
use router_ab_ed25519_yao::{
    combine_ed25519_yao_signing_worker_packages_source_preserving_v1,
    combine_ed25519_yao_signing_worker_packages_v1, Ed25519YaoActiveSigningMaterialV1,
    Ed25519YaoRecipientPrivateKeyV1, Ed25519YaoSigningWorkerActivationCandidateV1,
    Ed25519YaoSigningWorkerActivationReceiptV1, Ed25519YaoSigningWorkerPackageDeliveryV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Env, Request, Response};

use crate::{
    cloudflare_now_unix_ms_v1, compare_and_set_cloudflare_signing_worker_private_d1_secret_v1,
    delete_cloudflare_signing_worker_output_activation_by_active_key_v1,
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
pub const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RESERVE_INACTIVE_SOURCE_PRESERVING_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/reserve-inactive-source-preserving";
pub const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_ACTIVATE_RESERVATION_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/activate-reservation";
pub const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_DEACTIVATE_RESERVATION_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/deactivate-reservation";

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
    pub participant_ids: [u16; 2],
    pub deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
    pub deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
}

impl CloudflareEd25519YaoInactiveReservationRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        validate_inactive_reservation_parts_v1(
            &self.delivery,
            self.participant_ids,
            &self.deriver_a_client_package,
            &self.deriver_b_client_package,
            Ed25519YaoOperationV1::Registration,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoSourcePreservingInactiveReservationRequestV1 {
    pub source_binding: Ed25519YaoCeremonyBindingV1,
    pub delivery: CloudflareEd25519YaoPackagePairDeliveryV1,
    pub participant_ids: [u16; 2],
    pub deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
    pub deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
}

impl CloudflareEd25519YaoSourcePreservingInactiveReservationRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.source_binding.validate()?;
        if self.source_binding.operation != Ed25519YaoOperationV1::Registration {
            return Err(invalid_lifecycle(
                "source-preserving ordinary activation requires a registration source binding",
            ));
        }
        validate_inactive_reservation_parts_v1(
            &self.delivery,
            self.participant_ids,
            &self.deriver_a_client_package,
            &self.deriver_b_client_package,
            Ed25519YaoOperationV1::Registration,
        )?;
        if self.delivery.deriver_a.binding.material_activation
            == self.source_binding.material_activation
        {
            return Err(invalid_lifecycle(
                "source-preserving ordinary activation requires a fresh material activation",
            ));
        }
        require_same_stable_identity(&self.source_binding, &self.delivery.deriver_a.binding)
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
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoDeactivateReservationRequestV1 {
    pub material_activation: router_ab_core::MpcMaterialActivationRefV1,
}

impl CloudflareEd25519YaoDeactivateReservationRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.material_activation.validate()
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
        participant_ids: [u16; 2],
        deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
        deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
        candidate: Ed25519YaoActiveSigningMaterialV1,
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
        reservation_id: String,
    },
    Activating {
        delivery: CloudflareEd25519YaoPackagePairDeliveryV1,
        participant_ids: [u16; 2],
        deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
        deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
        candidate: Ed25519YaoActiveSigningMaterialV1,
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
        reservation_id: String,
    },
    Active {
        delivery: CloudflareEd25519YaoPackagePairDeliveryV1,
        participant_ids: [u16; 2],
        deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
        deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
        candidate: Ed25519YaoActiveSigningMaterialV1,
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
        reservation_id: String,
    },
    Revoked {
        binding: Ed25519YaoCeremonyBindingV1,
        reservation_id: String,
        revoked_at_ms: u64,
    },
    Deactivating {
        binding: Ed25519YaoCeremonyBindingV1,
        reservation_id: String,
        revoked_at_ms: u64,
    },
}

impl SigningWorkerYaoReservationStateV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        let (delivery, participant_ids, candidate, receipt, reservation_id) = match self {
            Self::Inactive {
                delivery,
                participant_ids,
                candidate,
                receipt,
                reservation_id,
                ..
            }
            | Self::Active {
                delivery,
                participant_ids,
                candidate,
                receipt,
                reservation_id,
                ..
            }
            | Self::Activating {
                delivery,
                participant_ids,
                candidate,
                receipt,
                reservation_id,
                ..
            } => {
                validate_participant_ids_v1(*participant_ids)?;
                (
                    delivery,
                    participant_ids,
                    candidate,
                    receipt,
                    reservation_id,
                )
            }
            Self::Revoked {
                binding,
                reservation_id,
                revoked_at_ms,
            }
            | Self::Deactivating {
                binding,
                reservation_id,
                revoked_at_ms,
            } => {
                binding.validate()?;
                if binding.operation != Ed25519YaoOperationV1::Registration {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 revoked reservation requires a registration binding",
                    ));
                }
                require_non_empty_reservation_id(reservation_id)?;
                if *revoked_at_ms == 0 {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 reservation transition timestamp is invalid",
                    ));
                }
                return Ok(());
            }
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
            }
            | Self::Activating {
                deriver_a_client_package,
                deriver_b_client_package,
                ..
            } => (deriver_a_client_package, deriver_b_client_package),
            Self::Revoked { .. } | Self::Deactivating { .. } => {
                return Err(invalid_lifecycle(
                    "ordinary Ed25519 revoked reservation cannot contain client packages",
                ))
            }
        };
        CloudflareEd25519YaoInactiveReservationRequestV1 {
            delivery: delivery.clone(),
            participant_ids: *participant_ids,
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
    let (
        reservation_id,
        participant_ids,
        activation_receipt,
        deriver_a_client_package,
        deriver_b_client_package,
    ) = reserve_inactive_ed25519_yao_v1(env, &reservation).await?;
    json_response(&CloudflareEd25519YaoInactiveReservationResponseV1 {
        state: "inactive".to_owned(),
        reservation_id,
        participant_ids,
        activation_receipt,
        deriver_a_client_package,
        deriver_b_client_package,
    })
}

pub async fn handle_cloudflare_signing_worker_ed25519_yao_reserve_inactive_source_preserving_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let reservation = parse_request::<
        CloudflareEd25519YaoSourcePreservingInactiveReservationRequestV1,
    >(&mut request)
    .await?;
    reservation.validate()?;
    let (
        reservation_id,
        participant_ids,
        activation_receipt,
        deriver_a_client_package,
        deriver_b_client_package,
    ) = reserve_source_preserving_inactive_ed25519_yao_v1(env, &reservation).await?;
    json_response(&CloudflareEd25519YaoInactiveReservationResponseV1 {
        state: "inactive".to_owned(),
        reservation_id,
        participant_ids,
        activation_receipt,
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

pub async fn handle_cloudflare_signing_worker_ed25519_yao_deactivate_reservation_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let deactivation =
        parse_request::<CloudflareEd25519YaoDeactivateReservationRequestV1>(&mut request).await?;
    deactivation.validate()?;
    let response = deactivate_ed25519_yao_reservation_v1(env, &deactivation).await?;
    json_response(&response)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoInactiveReservationResponseV1 {
    pub state: String,
    pub reservation_id: String,
    pub participant_ids: [u16; 2],
    pub activation_receipt: RouterAbEd25519YaoActivationPublicReceiptV1,
    pub deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
    pub deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoReservationActivationResponseV1 {
    pub receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoReservationDeactivationResponseV1 {
    pub state: &'static str,
    pub reservation_id: String,
    pub material_activation: router_ab_core::MpcMaterialActivationRefV1,
    pub revoked_at_ms: u64,
}

async fn reserve_inactive_ed25519_yao_v1(
    env: &Env,
    request: &CloudflareEd25519YaoInactiveReservationRequestV1,
) -> RouterAbProtocolResult<(
    String,
    [u16; 2],
    RouterAbEd25519YaoActivationPublicReceiptV1,
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
    reserve_inactive_ed25519_yao_parts_v1(
        env,
        delivery,
        request.participant_ids,
        &request.deriver_a_client_package,
        &request.deriver_b_client_package,
        &record_key,
        reservation_id,
        None,
    )
    .await
}

async fn reserve_source_preserving_inactive_ed25519_yao_v1(
    env: &Env,
    request: &CloudflareEd25519YaoSourcePreservingInactiveReservationRequestV1,
) -> RouterAbProtocolResult<(
    String,
    [u16; 2],
    RouterAbEd25519YaoActivationPublicReceiptV1,
    Ed25519YaoEncryptedPackageV1,
    Ed25519YaoEncryptedPackageV1,
)> {
    request.validate()?;
    let delivery = &request.delivery;
    let record_key = reservation_record_key_v1(delivery)?;
    let reservation_id = source_preserving_reservation_id_v1(&request.source_binding, delivery)?;
    reserve_inactive_ed25519_yao_parts_v1(
        env,
        delivery,
        request.participant_ids,
        &request.deriver_a_client_package,
        &request.deriver_b_client_package,
        &record_key,
        reservation_id,
        Some(&request.source_binding),
    )
    .await
}

async fn reserve_inactive_ed25519_yao_parts_v1(
    env: &Env,
    delivery: &CloudflareEd25519YaoPackagePairDeliveryV1,
    target_participant_ids: [u16; 2],
    deriver_a_client_package: &Ed25519YaoEncryptedPackageV1,
    deriver_b_client_package: &Ed25519YaoEncryptedPackageV1,
    record_key: &str,
    reservation_id: String,
    source_binding: Option<&Ed25519YaoCeremonyBindingV1>,
) -> RouterAbProtocolResult<(
    String,
    [u16; 2],
    RouterAbEd25519YaoActivationPublicReceiptV1,
    Ed25519YaoEncryptedPackageV1,
    Ed25519YaoEncryptedPackageV1,
)> {
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
                    participant_ids,
                    deriver_a_client_package: stored_deriver_a_client_package,
                    deriver_b_client_package: stored_deriver_b_client_package,
                    receipt,
                    reservation_id: stored_id,
                    ..
                } if stored_id == &reservation_id
                    && stored_delivery == delivery
                    && participant_ids == &target_participant_ids
                    && stored_deriver_a_client_package == deriver_a_client_package
                    && stored_deriver_b_client_package == deriver_b_client_package =>
                {
                    return Ok((
                        reservation_id.clone(),
                        *participant_ids,
                        public_activation_receipt_v1(&stored_delivery.deriver_a.binding, receipt)?,
                        stored_deriver_a_client_package.clone(),
                        stored_deriver_b_client_package.clone(),
                    ));
                }
                SigningWorkerYaoReservationStateV1::Activating {
                    delivery: stored_delivery,
                    participant_ids,
                    deriver_a_client_package: stored_deriver_a_client_package,
                    deriver_b_client_package: stored_deriver_b_client_package,
                    receipt,
                    reservation_id: stored_id,
                    ..
                } if stored_id == &reservation_id
                    && stored_delivery == delivery
                    && participant_ids == &target_participant_ids
                    && stored_deriver_a_client_package == deriver_a_client_package
                    && stored_deriver_b_client_package == deriver_b_client_package =>
                {
                    return Ok((
                        reservation_id.clone(),
                        *participant_ids,
                        public_activation_receipt_v1(&stored_delivery.deriver_a.binding, receipt)?,
                        stored_deriver_a_client_package.clone(),
                        stored_deriver_b_client_package.clone(),
                    ));
                }
                SigningWorkerYaoReservationStateV1::Active {
                    delivery: stored_delivery,
                    participant_ids,
                    deriver_a_client_package: stored_deriver_a_client_package,
                    deriver_b_client_package: stored_deriver_b_client_package,
                    reservation_id: stored_id,
                    ..
                } if stored_delivery == delivery
                    && stored_id == &reservation_id
                    && participant_ids == &target_participant_ids
                    && stored_deriver_a_client_package == deriver_a_client_package
                    && stored_deriver_b_client_package == deriver_b_client_package =>
                {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 material reservation is already active",
                    ));
                }
                SigningWorkerYaoReservationStateV1::Revoked {
                    binding: stored_binding,
                    reservation_id: stored_id,
                    ..
                } if stored_binding.material_activation
                    == delivery.deriver_a.binding.material_activation
                    && stored_id == &reservation_id =>
                {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 material reservation is revoked",
                    ));
                }
                _ => {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 material reservation conflicts with the exact activation ref",
                    ));
                }
            }
        }
        let candidate = match source_binding {
            Some(source_binding) => {
                let source = load_source_active_material_v1(env, source_binding).await?;
                combine_signing_worker_yao_packages_v1(env, delivery, Some(&source))?
            }
            None => combine_signing_worker_yao_packages_v1(env, delivery, None)?,
        };
        let (candidate, receipt) = candidate.into_parts();
        let state = SigningWorkerYaoReservationStateV1::Inactive {
            delivery: delivery.clone(),
            participant_ids: target_participant_ids,
            deriver_a_client_package: deriver_a_client_package.clone(),
            deriver_b_client_package: deriver_b_client_package.clone(),
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
                    reservation_id.clone(),
                    target_participant_ids,
                    public_activation_receipt_v1(&delivery.deriver_a.binding, &receipt)?,
                    deriver_a_client_package.clone(),
                    deriver_b_client_package.clone(),
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
    let active_key = active_output_key_v1(&request.binding.material_activation);
    for _ in 0..3 {
        let Some(current) = load_cloudflare_signing_worker_private_d1_secret_v1::<
            SigningWorkerYaoReservationStateV1,
        >(env, "ed25519_yao_reservations", &record_key)
        .await?
        else {
            let ecdsa_record_key = format!("ecdsa/{}", record_key.trim_start_matches("ed25519/"));
            if load_cloudflare_signing_worker_private_d1_secret_v1::<serde_json::Value>(
                env,
                "ecdsa_inactive_reservations",
                &ecdsa_record_key,
            )
            .await?
            .is_some()
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ConflictingPair,
                    "ordinary Ed25519 deactivation conflicts with an ECDSA activation",
                ));
            }
            return Err(invalid_lifecycle(
                "ordinary Ed25519 material reservation is missing",
            ));
        };
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
                participant_ids,
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
                let activating = SigningWorkerYaoReservationStateV1::Activating {
                    delivery,
                    participant_ids,
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
            SigningWorkerYaoReservationStateV1::Activating {
                delivery,
                participant_ids,
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
                    participant_ids,
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
                        let Some(latest) = load_cloudflare_signing_worker_private_d1_secret_v1::<
                            SigningWorkerYaoReservationStateV1,
                        >(
                            env, "ed25519_yao_reservations", &record_key
                        )
                        .await?
                        else {
                            continue;
                        };
                        latest.value.validate()?;
                        match latest.value {
                            SigningWorkerYaoReservationStateV1::Active {
                                delivery,
                                receipt,
                                reservation_id,
                                ..
                            } if reservation_id == request.reservation_id
                                && delivery.deriver_a.binding == request.binding =>
                            {
                                return Ok(receipt);
                            }
                            SigningWorkerYaoReservationStateV1::Deactivating {
                                binding,
                                reservation_id,
                                ..
                            }
                            | SigningWorkerYaoReservationStateV1::Revoked {
                                binding,
                                reservation_id,
                                ..
                            } => {
                                if reservation_id != request.reservation_id
                                    || binding != request.binding
                                {
                                    return Err(invalid_lifecycle(
                                        "ordinary Ed25519 reservation activation conflicts with the exact reservation",
                                    ));
                                }
                                delete_cloudflare_signing_worker_output_activation_by_active_key_v1(
                                    env,
                                    &active_key,
                                    &request.binding.material_activation,
                                )
                                .await?;
                                return Err(invalid_lifecycle(
                                    "ordinary Ed25519 material reservation is revoked",
                                ));
                            }
                            _ => continue,
                        }
                    }
                    Ok(()) => return Ok(receipt),
                    Err(error) => return Err(error),
                }
            }
            SigningWorkerYaoReservationStateV1::Deactivating {
                binding,
                reservation_id,
                ..
            } => {
                if reservation_id != request.reservation_id || binding != request.binding {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 reservation activation conflicts with the exact reservation",
                    ));
                }
                return Err(invalid_lifecycle(
                    "ordinary Ed25519 material reservation is being deactivated",
                ));
            }
            SigningWorkerYaoReservationStateV1::Revoked {
                binding,
                reservation_id,
                ..
            } => {
                if reservation_id != request.reservation_id || binding != request.binding {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 reservation activation conflicts with the exact reservation",
                    ));
                }
                return Err(invalid_lifecycle(
                    "ordinary Ed25519 material reservation is revoked",
                ));
            }
        }
    }
    Err(invalid_lifecycle(
        "ordinary Ed25519 reservation activation changed concurrently",
    ))
}

async fn deactivate_ed25519_yao_reservation_v1(
    env: &Env,
    request: &CloudflareEd25519YaoDeactivateReservationRequestV1,
) -> RouterAbProtocolResult<CloudflareEd25519YaoReservationDeactivationResponseV1> {
    request.validate()?;
    let record_key =
        reservation_record_key_from_material_activation_v1(&request.material_activation)?;
    let active_key = active_output_key_v1(&request.material_activation);
    for _ in 0..3 {
        let current = load_cloudflare_signing_worker_private_d1_secret_v1::<
            SigningWorkerYaoReservationStateV1,
        >(env, "ed25519_yao_reservations", &record_key)
        .await?
        .ok_or_else(|| invalid_lifecycle("ordinary Ed25519 material reservation is missing"))?;
        current.value.validate()?;
        let (binding, reservation_id, revoked_at_ms) = match current.value {
            SigningWorkerYaoReservationStateV1::Revoked {
                binding,
                reservation_id: stored_id,
                revoked_at_ms,
            } => {
                if !reservation_id_matches_material_activation_v1(
                    &stored_id,
                    &request.material_activation,
                ) || binding.material_activation != request.material_activation
                {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 deactivation conflicts with the exact activation ref",
                    ));
                }
                delete_cloudflare_signing_worker_output_activation_by_active_key_v1(
                    env,
                    &active_key,
                    &request.material_activation,
                )
                .await?;
                (binding, stored_id, revoked_at_ms)
            }
            SigningWorkerYaoReservationStateV1::Deactivating {
                binding,
                reservation_id: stored_id,
                revoked_at_ms,
            } => {
                if !reservation_id_matches_material_activation_v1(
                    &stored_id,
                    &request.material_activation,
                ) || binding.material_activation != request.material_activation
                {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 deactivation conflicts with the exact activation ref",
                    ));
                }
                delete_cloudflare_signing_worker_output_activation_by_active_key_v1(
                    env,
                    &active_key,
                    &request.material_activation,
                )
                .await?;
                let revoked = SigningWorkerYaoReservationStateV1::Revoked {
                    binding: binding.clone(),
                    reservation_id: stored_id.clone(),
                    revoked_at_ms,
                };
                match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
                    env,
                    "ed25519_yao_reservations",
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
                    Ok(()) => (binding, stored_id, revoked_at_ms),
                    Err(error) => return Err(error),
                }
            }
            SigningWorkerYaoReservationStateV1::Inactive {
                delivery,
                reservation_id: stored_id,
                ..
            }
            | SigningWorkerYaoReservationStateV1::Activating {
                delivery,
                reservation_id: stored_id,
                ..
            }
            | SigningWorkerYaoReservationStateV1::Active {
                delivery,
                reservation_id: stored_id,
                ..
            } => {
                if !reservation_id_matches_material_activation_v1(
                    &stored_id,
                    &request.material_activation,
                ) || delivery.deriver_a.binding.material_activation
                    != request.material_activation
                {
                    return Err(invalid_lifecycle(
                        "ordinary Ed25519 deactivation conflicts with the exact activation ref",
                    ));
                }
                let binding = delivery.deriver_a.binding.clone();
                let revoked_at_ms = cloudflare_now_unix_ms_v1()?;
                let deactivating = SigningWorkerYaoReservationStateV1::Deactivating {
                    binding: binding.clone(),
                    reservation_id: stored_id.clone(),
                    revoked_at_ms,
                };
                match compare_and_set_cloudflare_signing_worker_private_d1_secret_v1(
                    env,
                    "ed25519_yao_reservations",
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
        return Ok(CloudflareEd25519YaoReservationDeactivationResponseV1 {
            state: "revoked",
            reservation_id,
            material_activation: binding.material_activation,
            revoked_at_ms,
        });
    }
    Err(invalid_lifecycle(
        "ordinary Ed25519 material deactivation changed concurrently",
    ))
}

pub(crate) async fn require_ed25519_material_active_v1(
    env: &Env,
    material_activation: &router_ab_core::MpcMaterialActivationRefV1,
) -> RouterAbProtocolResult<()> {
    let record_key = reservation_record_key_from_material_activation_v1(material_activation)?;
    let Some(current) = load_cloudflare_signing_worker_private_d1_secret_v1::<
        SigningWorkerYaoReservationStateV1,
    >(env, "ed25519_yao_reservations", &record_key)
    .await?
    else {
        return Ok(());
    };
    current.value.validate()?;
    match current.value {
        SigningWorkerYaoReservationStateV1::Active { delivery, .. }
            if delivery.deriver_a.binding.material_activation == *material_activation =>
        {
            Ok(())
        }
        SigningWorkerYaoReservationStateV1::Inactive { delivery, .. }
        | SigningWorkerYaoReservationStateV1::Activating { delivery, .. }
            if delivery.deriver_a.binding.material_activation == *material_activation =>
        {
            Err(invalid_lifecycle(
                "ordinary Ed25519 material reservation is not active",
            ))
        }
        SigningWorkerYaoReservationStateV1::Deactivating { binding, .. }
        | SigningWorkerYaoReservationStateV1::Revoked { binding, .. }
            if binding.material_activation == *material_activation =>
        {
            Err(invalid_lifecycle(
                "ordinary Ed25519 material reservation is revoked",
            ))
        }
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "ordinary Ed25519 material activation identity conflicts with the reservation",
        )),
    }
}

fn reservation_record_key_v1(
    delivery: &CloudflareEd25519YaoPackagePairDeliveryV1,
) -> RouterAbProtocolResult<String> {
    reservation_record_key_from_binding_v1(&delivery.deriver_a.binding)
}

fn reservation_record_key_from_binding_v1(
    binding: &Ed25519YaoCeremonyBindingV1,
) -> RouterAbProtocolResult<String> {
    reservation_record_key_from_material_activation_v1(binding.material_activation())
}

fn reservation_record_key_from_material_activation_v1(
    material_activation: &router_ab_core::MpcMaterialActivationRefV1,
) -> RouterAbProtocolResult<String> {
    let canonical = serde_json::to_vec(material_activation).map_err(|_| {
        invalid_lifecycle("ordinary Ed25519 reservation identity could not be encoded")
    })?;
    let digest = Sha256::digest(canonical);
    Ok(format!("ed25519/{}", encode_hex_slice(&digest)))
}

async fn load_source_active_material_v1(
    env: &Env,
    source_binding: &Ed25519YaoCeremonyBindingV1,
) -> RouterAbProtocolResult<Ed25519YaoActiveSigningMaterialV1> {
    let record_key = reservation_record_key_from_binding_v1(source_binding)?;
    let current = load_cloudflare_signing_worker_private_d1_secret_v1::<
        SigningWorkerYaoReservationStateV1,
    >(env, "ed25519_yao_reservations", &record_key)
    .await?;
    let Some(current) = current else {
        return load_source_active_material_from_lifecycle_v1(env, source_binding).await;
    };
    current.value.validate()?;
    match current.value {
        SigningWorkerYaoReservationStateV1::Active {
            delivery,
            candidate,
            ..
        } if delivery.deriver_a.binding == *source_binding
            && candidate.binding() == source_binding =>
        {
            Ok(candidate)
        }
        SigningWorkerYaoReservationStateV1::Inactive { delivery, .. }
        | SigningWorkerYaoReservationStateV1::Activating { delivery, .. }
            if delivery.deriver_a.binding == *source_binding =>
        {
            Err(invalid_lifecycle(
                "source Ed25519 material reservation is not active",
            ))
        }
        SigningWorkerYaoReservationStateV1::Deactivating { binding, .. }
        | SigningWorkerYaoReservationStateV1::Revoked { binding, .. }
            if binding == *source_binding =>
        {
            Err(invalid_lifecycle(
                "source Ed25519 material reservation is revoked",
            ))
        }
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "source Ed25519 material activation identity conflicts with the reservation",
        )),
    }
}

async fn load_source_active_material_from_lifecycle_v1(
    env: &Env,
    source_binding: &Ed25519YaoCeremonyBindingV1,
) -> RouterAbProtocolResult<Ed25519YaoActiveSigningMaterialV1> {
    let record_key = encode_hex(source_binding.stable_key_context_binding.into_bytes());
    let current = load_cloudflare_signing_worker_private_d1_secret_v1::<
        SigningWorkerYaoDurableStateV1,
    >(env, "ed25519_yao_lifecycle", &record_key)
    .await?
    .ok_or_else(|| invalid_lifecycle("source Ed25519 material reservation is missing"))?;
    current.value.validate()?;
    match current.value {
        SigningWorkerYaoDurableStateV1::Active { material, .. }
            if material.binding() == source_binding =>
        {
            Ok(material)
        }
        SigningWorkerYaoDurableStateV1::Active { .. } => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "source Ed25519 material activation identity conflicts with the lifecycle state",
        )),
        SigningWorkerYaoDurableStateV1::RegistrationStaged { .. }
        | SigningWorkerYaoDurableStateV1::RecoveryStaged { .. } => Err(invalid_lifecycle(
            "source Ed25519 material reservation is not active",
        )),
    }
}

fn source_preserving_reservation_id_v1(
    source_binding: &Ed25519YaoCeremonyBindingV1,
    delivery: &CloudflareEd25519YaoPackagePairDeliveryV1,
) -> RouterAbProtocolResult<String> {
    let target_record_key = reservation_record_key_v1(delivery)?;
    let source_bytes = serde_json::to_vec(source_binding).map_err(|_| {
        invalid_lifecycle("source Ed25519 reservation identity could not be encoded")
    })?;
    let source_digest = Sha256::digest(source_bytes);
    Ok(format!(
        "ordinary-ed25519-source-preserving-inactive-v1:{}:{}",
        target_record_key.trim_start_matches("ed25519/"),
        encode_hex_slice(&source_digest),
    ))
}

fn reservation_id_matches_material_activation_v1(
    reservation_id: &str,
    material_activation: &router_ab_core::MpcMaterialActivationRefV1,
) -> bool {
    let Ok(record_key) = reservation_record_key_from_material_activation_v1(material_activation)
    else {
        return false;
    };
    let target_digest = record_key.trim_start_matches("ed25519/");
    reservation_id == format!("ordinary-ed25519-inactive-v1:{target_digest}")
        || reservation_id.starts_with(&format!(
            "ordinary-ed25519-source-preserving-inactive-v1:{target_digest}:"
        ))
}

fn active_output_key_v1(
    material_activation: &router_ab_core::MpcMaterialActivationRefV1,
) -> String {
    format!(
        "active-signing-worker/{}/{}/{}",
        material_activation.material_owner,
        material_activation.activation_id,
        material_activation.signing_worker,
    )
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

fn validate_inactive_reservation_parts_v1(
    delivery: &CloudflareEd25519YaoPackagePairDeliveryV1,
    participant_ids: [u16; 2],
    deriver_a_client_package: &Ed25519YaoEncryptedPackageV1,
    deriver_b_client_package: &Ed25519YaoEncryptedPackageV1,
    operation: Ed25519YaoOperationV1,
) -> RouterAbProtocolResult<()> {
    delivery.validate()?;
    require_operation(&delivery.deriver_a.binding, operation)?;
    validate_participant_ids_v1(participant_ids)?;
    validate_client_package_v1(
        deriver_a_client_package,
        &delivery.deriver_a.binding,
        Ed25519YaoDeriverRoleV1::DeriverA,
    )?;
    validate_client_package_v1(
        deriver_b_client_package,
        &delivery.deriver_b.binding,
        Ed25519YaoDeriverRoleV1::DeriverB,
    )
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
    let private_key = Ed25519YaoRecipientPrivateKeyV1::from_bytes(private_key);
    match active {
        Some(source)
            if delivery.deriver_a.binding.operation == Ed25519YaoOperationV1::Registration =>
        {
            combine_ed25519_yao_signing_worker_packages_source_preserving_v1(
                &private_key,
                delivery.deriver_a.clone(),
                delivery.deriver_b.clone(),
                source,
            )
        }
        _ => combine_ed25519_yao_signing_worker_packages_v1(
            &private_key,
            delivery.deriver_a.clone(),
            delivery.deriver_b.clone(),
            active,
        ),
    }
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

fn validate_participant_ids_v1(participant_ids: [u16; 2]) -> RouterAbProtocolResult<()> {
    if participant_ids[0] == 0
        || participant_ids[1] == 0
        || participant_ids[0] >= participant_ids[1]
    {
        return Err(invalid_lifecycle(
            "ordinary Ed25519 participant ids must be distinct, nonzero, ascending values",
        ));
    }
    Ok(())
}

fn public_activation_receipt_v1(
    binding: &Ed25519YaoCeremonyBindingV1,
    receipt: &Ed25519YaoSigningWorkerActivationReceiptV1,
) -> RouterAbProtocolResult<RouterAbEd25519YaoActivationPublicReceiptV1> {
    if receipt.session != binding.session_id.into_bytes()
        || receipt.transcript == [0; 32]
        || receipt.registered_public_key == [0; 32]
    {
        return Err(invalid_lifecycle(
            "ordinary Ed25519 activation receipt does not match its reservation binding",
        ));
    }
    RouterAbEd25519YaoActivationPublicReceiptV1::new(
        receipt.transcript,
        receipt.registered_public_key,
        receipt.joined_client_commitment,
        receipt.joined_signing_worker_commitment,
        receipt.signing_worker_verifying_share,
        receipt.state_epoch,
        binding.material_activation.clone(),
    )
}

fn invalid_lifecycle(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        message.into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deactivation_uses_the_same_active_output_identity_as_activation() {
        let material_activation = router_ab_core::MpcMaterialActivationRefV1::new(
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
        let material_activation = router_ab_core::MpcMaterialActivationRefV1::new(
            "activation",
            "capability",
            "wallet",
            "key-binding",
            "lifecycle-binding",
            "signing-worker",
        )
        .expect("valid material activation");

        let key = reservation_record_key_from_material_activation_v1(&material_activation)
            .expect("record key");
        assert!(key.starts_with("ed25519/"));
        assert_eq!(key.len(), "ed25519/".len() + 64);
    }

    #[test]
    fn ordinary_reservation_participant_ids_are_strictly_ordered() {
        assert!(validate_participant_ids_v1([1, 2]).is_ok());
        assert!(validate_participant_ids_v1([0, 2]).is_err());
        assert!(validate_participant_ids_v1([2, 2]).is_err());
        assert!(validate_participant_ids_v1([3, 2]).is_err());
    }

    fn source_preserving_test_binding(
        operation: Ed25519YaoOperationV1,
        session: u8,
        activation_id: &str,
    ) -> Ed25519YaoCeremonyBindingV1 {
        let work_kind = match operation {
            Ed25519YaoOperationV1::Registration => {
                router_ab_core::ExpensiveWorkKindV1::RegistrationPrepare
            }
            Ed25519YaoOperationV1::Recovery => router_ab_core::ExpensiveWorkKindV1::Recovery,
            _ => panic!("test binding only covers activation operations"),
        };
        Ed25519YaoCeremonyBindingV1::new(
            router_ab_core::LifecycleScopeV1::new(
                "test-lifecycle",
                work_kind,
                router_ab_core::RootShareEpoch::new("test-epoch").expect("root epoch"),
                "test-account",
                "test-wallet",
                "test-signer-set",
                "test-worker",
            )
            .expect("lifecycle"),
            operation,
            router_ab_core::Ed25519YaoSessionIdV1::new([session; 32]).expect("session"),
            router_ab_core::Ed25519YaoStableKeyContextBindingV1::new([0x42; 32]),
            router_ab_core::MpcMaterialActivationRefV1::new(
                activation_id,
                "test-capability",
                "test-account",
                "test-key",
                "test-lifecycle",
                "test-worker",
            )
            .expect("material activation"),
        )
        .expect("binding")
    }

    fn source_preserving_test_package(
        kind: Ed25519YaoPackageKindV1,
        deriver: Ed25519YaoDeriverRoleV1,
        binding: &Ed25519YaoCeremonyBindingV1,
    ) -> Ed25519YaoEncryptedPackageV1 {
        Ed25519YaoEncryptedPackageV1::new(
            kind,
            deriver,
            binding.session_id.into_bytes(),
            [0x51; 32],
            [0x52; 32],
            vec![0x53; 16],
        )
        .expect("test encrypted package")
    }

    fn source_preserving_test_delivery(
        binding: Ed25519YaoCeremonyBindingV1,
    ) -> CloudflareEd25519YaoPackagePairDeliveryV1 {
        CloudflareEd25519YaoPackagePairDeliveryV1 {
            deriver_a: Ed25519YaoSigningWorkerPackageDeliveryV1 {
                binding: binding.clone(),
                client_commitment: [0x61; 32],
                signing_worker_commitment: [0x62; 32],
                package: source_preserving_test_package(
                    Ed25519YaoPackageKindV1::ActivationSigningWorker,
                    Ed25519YaoDeriverRoleV1::DeriverA,
                    &binding,
                ),
            },
            deriver_b: Ed25519YaoSigningWorkerPackageDeliveryV1 {
                binding: binding.clone(),
                client_commitment: [0x63; 32],
                signing_worker_commitment: [0x64; 32],
                package: source_preserving_test_package(
                    Ed25519YaoPackageKindV1::ActivationSigningWorker,
                    Ed25519YaoDeriverRoleV1::DeriverB,
                    &binding,
                ),
            },
        }
    }

    #[test]
    fn source_preserving_reservation_request_is_strict_and_registration_only() {
        let source_binding = source_preserving_test_binding(
            Ed25519YaoOperationV1::Registration,
            1,
            "source-activation",
        );
        let target_binding = source_preserving_test_binding(
            Ed25519YaoOperationV1::Registration,
            2,
            "target-activation",
        );
        let delivery = source_preserving_test_delivery(target_binding.clone());
        let request = CloudflareEd25519YaoSourcePreservingInactiveReservationRequestV1 {
            source_binding: source_binding.clone(),
            delivery,
            participant_ids: [1, 2],
            deriver_a_client_package: source_preserving_test_package(
                Ed25519YaoPackageKindV1::ActivationClient,
                Ed25519YaoDeriverRoleV1::DeriverA,
                &target_binding,
            ),
            deriver_b_client_package: source_preserving_test_package(
                Ed25519YaoPackageKindV1::ActivationClient,
                Ed25519YaoDeriverRoleV1::DeriverB,
                &target_binding,
            ),
        };
        request.validate().expect("valid source-preserving request");

        let mut wire = serde_json::to_value(&request).expect("request wire");
        wire.as_object_mut()
            .expect("request object")
            .insert("unexpected".to_owned(), serde_json::Value::Null);
        assert!(serde_json::from_value::<
            CloudflareEd25519YaoSourcePreservingInactiveReservationRequestV1,
        >(wire)
        .is_err());

        let recovery_source = CloudflareEd25519YaoSourcePreservingInactiveReservationRequestV1 {
            source_binding: source_preserving_test_binding(
                Ed25519YaoOperationV1::Recovery,
                1,
                "source-activation",
            ),
            ..request
        };
        assert!(recovery_source.validate().is_err());
    }

    #[test]
    fn source_preserving_reservation_id_binds_source_and_target() {
        let source_binding = source_preserving_test_binding(
            Ed25519YaoOperationV1::Registration,
            1,
            "source-activation",
        );
        let target_binding = source_preserving_test_binding(
            Ed25519YaoOperationV1::Registration,
            2,
            "target-activation",
        );
        let delivery = source_preserving_test_delivery(target_binding);
        let first = source_preserving_reservation_id_v1(&source_binding, &delivery)
            .expect("source-preserving reservation id");
        let replay = source_preserving_reservation_id_v1(&source_binding, &delivery)
            .expect("source-preserving reservation id replay");
        assert_eq!(first, replay);
        assert!(first.starts_with("ordinary-ed25519-source-preserving-inactive-v1:"));

        let changed_source = source_preserving_test_binding(
            Ed25519YaoOperationV1::Registration,
            3,
            "source-activation",
        );
        let changed = source_preserving_reservation_id_v1(&changed_source, &delivery)
            .expect("changed source reservation id");
        assert_ne!(first, changed);
    }
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
