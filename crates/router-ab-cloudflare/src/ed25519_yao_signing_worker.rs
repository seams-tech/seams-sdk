use router_ab_core::{
    ActiveSigningWorkerStateV1, Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1,
    Ed25519YaoOperationV1, OpenedShareKind, PublicDigest32, Role,
    RouterAbEd25519YaoActivationPublicReceiptV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult, ServerIdentityV1,
};
use router_ab_ed25519_yao::{
    combine_ed25519_yao_signing_worker_packages_v1, Ed25519YaoActiveSigningMaterialV1,
    Ed25519YaoRecipientPrivateKeyV1, Ed25519YaoSigningWorkerActivationCandidateV1,
    Ed25519YaoSigningWorkerActivationReceiptV1, Ed25519YaoSigningWorkerPackageDeliveryV1,
};
use serde::{Deserialize, Serialize};
use worker::{Env, Method, Request, Response, State};

use crate::{
    cloudflare_now_unix_ms_v1, load_cloudflare_server_output_hpke_private_key_bytes_v1,
    CloudflareSecretMaterial32V1, CloudflareServerOutputMaterialRecordV1,
    CloudflareSigningWorkerOutputActivationRecordV1, CloudflareSigningWorkerRuntimeV1,
};

pub const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_DERIVER_A_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/activation/deriver-a";
pub const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_DERIVER_B_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/activation/deriver-b";
pub const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH: &str =
    "/router-ab/signing-worker/ed25519-yao/recovery/promote";

pub(crate) const SIGNING_WORKER_ED25519_YAO_DO_BINDING: &str = "SIGNING_WORKER_ED25519_YAO_DO";
const SIGNING_WORKER_ED25519_YAO_DO_URL: &str =
    "https://signing-worker-ed25519-yao.internal/command";
const SIGNING_WORKER_ED25519_YAO_STATE_KEY: &str = "lifecycle-v1";
pub(crate) const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_OUTPUT_ACTIVATE_DO_PATH: &str =
    "/router-ab/do/signing-worker-output/ed25519-yao-activate";
const SIGNING_WORKER_ED25519_YAO_OUTPUT_DO_URL: &str =
    "https://signing-worker-server-output.internal/router-ab/do/signing-worker-output/ed25519-yao-activate";

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
pub(crate) struct CloudflareEd25519YaoOutputActivationReceiptV1 {
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    pub activated: bool,
}

impl CloudflareEd25519YaoOutputActivationReceiptV1 {
    pub(crate) fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        activated: bool,
    ) -> RouterAbProtocolResult<Self> {
        let receipt = Self {
            active_signing_worker_state,
            activated,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub(crate) fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoRecoveryPromotionRequestV1 {
    pub binding: Ed25519YaoCeremonyBindingV1,
    pub public_receipt: RouterAbEd25519YaoActivationPublicReceiptV1,
}

impl CloudflareEd25519YaoRecoveryPromotionRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
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
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum SigningWorkerYaoCommandV1 {
    DeliverDeriverA {
        delivery: Ed25519YaoSigningWorkerPackageDeliveryV1,
    },
    DeliverDeriverB {
        delivery: Ed25519YaoSigningWorkerPackageDeliveryV1,
    },
    PromoteRecovery {
        request: CloudflareEd25519YaoRecoveryPromotionRequestV1,
    },
}

impl SigningWorkerYaoCommandV1 {
    fn stable_context_binding(&self) -> [u8; 32] {
        match self {
            Self::DeliverDeriverA { delivery } | Self::DeliverDeriverB { delivery } => {
                delivery.binding.stable_key_context_binding.into_bytes()
            }
            Self::PromoteRecovery { request } => {
                request.binding.stable_key_context_binding.into_bytes()
            }
        }
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::DeliverDeriverA { delivery } => {
                delivery.validate_for_deriver(Ed25519YaoDeriverRoleV1::DeriverA)
            }
            Self::DeliverDeriverB { delivery } => {
                delivery.validate_for_deriver(Ed25519YaoDeriverRoleV1::DeriverB)
            }
            Self::PromoteRecovery { request } => request.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum SigningWorkerYaoDurableStateV1 {
    RegistrationPending {
        deriver_a: Ed25519YaoSigningWorkerPackageDeliveryV1,
    },
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
    RecoveryPending {
        active_material: Ed25519YaoActiveSigningMaterialV1,
        active_receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
        deriver_a: Ed25519YaoSigningWorkerPackageDeliveryV1,
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
            Self::RegistrationPending { deriver_a }
            | Self::RegistrationStaged { deriver_a, .. }
            | Self::RecoveryPending { deriver_a, .. }
            | Self::RecoveryStaged { deriver_a, .. } => {
                deriver_a.binding.stable_key_context_binding.into_bytes()
            }
            Self::Active { material, .. } => {
                material.binding().stable_key_context_binding.into_bytes()
            }
        }
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::RegistrationPending { deriver_a } => {
                deriver_a.validate_for_deriver(Ed25519YaoDeriverRoleV1::DeriverA)?;
                require_operation(&deriver_a.binding, Ed25519YaoOperationV1::Registration)
            }
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
            Self::RecoveryPending {
                active_material,
                active_receipt,
                deriver_a,
            } => {
                validate_material_receipt(active_material, active_receipt)?;
                deriver_a.validate_for_deriver(Ed25519YaoDeriverRoleV1::DeriverA)?;
                require_operation(&deriver_a.binding, Ed25519YaoOperationV1::Recovery)?;
                require_same_stable_identity(active_material.binding(), &deriver_a.binding)
            }
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
    Pending {
        session: [u8; 32],
        transcript: [u8; 32],
    },
    Active {
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
    },
    Staged {
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
    },
}

#[worker::durable_object(fetch)]
pub struct RouterAbSigningWorkerEd25519YaoDurableObject {
    state: State,
    env: Env,
}

impl worker::DurableObject for RouterAbSigningWorkerEd25519YaoDurableObject {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut request: Request) -> worker::Result<Response> {
        if request.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        let command = request.json::<SigningWorkerYaoCommandV1>().await?;
        if let Err(error) = command.validate() {
            return Response::error(error.message(), 400);
        }
        let response = match self.execute_command(command).await {
            Ok(response) => response,
            Err(error) => return Response::error(error.message(), 409),
        };
        Response::from_json(&response)
    }
}

impl RouterAbSigningWorkerEd25519YaoDurableObject {
    async fn execute_command(
        &self,
        command: SigningWorkerYaoCommandV1,
    ) -> RouterAbProtocolResult<SigningWorkerYaoCommandResponseV1> {
        let storage = self.state.storage();
        let current = storage
            .get::<SigningWorkerYaoDurableStateV1>(SIGNING_WORKER_ED25519_YAO_STATE_KEY)
            .await
            .map_err(map_worker_storage_error)?;
        if let Some(current) = current.as_ref() {
            current.validate()?;
            if current.stable_context_binding() != command.stable_context_binding() {
                return Err(invalid_lifecycle(
                    "Ed25519 Yao Durable Object stable identity mismatch",
                ));
            }
        }
        match command {
            SigningWorkerYaoCommandV1::DeliverDeriverA { delivery } => {
                self.deliver_deriver_a(storage, current, delivery).await
            }
            SigningWorkerYaoCommandV1::DeliverDeriverB { delivery } => {
                self.deliver_deriver_b(storage, current, delivery).await
            }
            SigningWorkerYaoCommandV1::PromoteRecovery { request } => {
                self.promote_recovery(storage, current, request).await
            }
        }
    }

    async fn deliver_deriver_a(
        &self,
        storage: worker::Storage,
        current: Option<SigningWorkerYaoDurableStateV1>,
        delivery: Ed25519YaoSigningWorkerPackageDeliveryV1,
    ) -> RouterAbProtocolResult<SigningWorkerYaoCommandResponseV1> {
        let next = match (delivery.binding.operation, current) {
            (Ed25519YaoOperationV1::Registration, None) => {
                SigningWorkerYaoDurableStateV1::RegistrationPending {
                    deriver_a: delivery.clone(),
                }
            }
            (
                Ed25519YaoOperationV1::Registration,
                Some(SigningWorkerYaoDurableStateV1::RegistrationPending { deriver_a }),
            ) if deriver_a == delivery => {
                SigningWorkerYaoDurableStateV1::RegistrationPending { deriver_a }
            }
            (
                Ed25519YaoOperationV1::Registration,
                Some(SigningWorkerYaoDurableStateV1::RegistrationStaged {
                    deriver_a,
                    deriver_b,
                    candidate,
                    receipt,
                }),
            ) if deriver_a == delivery => SigningWorkerYaoDurableStateV1::RegistrationStaged {
                deriver_a,
                deriver_b,
                candidate,
                receipt,
            },
            (
                Ed25519YaoOperationV1::Registration,
                Some(SigningWorkerYaoDurableStateV1::Active {
                    deriver_a,
                    deriver_b,
                    material,
                    receipt,
                }),
            ) if deriver_a == delivery => SigningWorkerYaoDurableStateV1::Active {
                deriver_a,
                deriver_b,
                material,
                receipt,
            },
            (
                Ed25519YaoOperationV1::Recovery,
                Some(SigningWorkerYaoDurableStateV1::Active {
                    deriver_a,
                    deriver_b,
                    material,
                    receipt,
                }),
            ) if deriver_a == delivery => SigningWorkerYaoDurableStateV1::Active {
                deriver_a,
                deriver_b,
                material,
                receipt,
            },
            (
                Ed25519YaoOperationV1::Recovery,
                Some(SigningWorkerYaoDurableStateV1::Active {
                    material, receipt, ..
                }),
            ) => SigningWorkerYaoDurableStateV1::RecoveryPending {
                active_material: material,
                active_receipt: receipt,
                deriver_a: delivery.clone(),
            },
            (
                Ed25519YaoOperationV1::Recovery,
                Some(SigningWorkerYaoDurableStateV1::RecoveryPending {
                    active_material,
                    active_receipt,
                    deriver_a,
                }),
            ) if deriver_a == delivery => SigningWorkerYaoDurableStateV1::RecoveryPending {
                active_material,
                active_receipt,
                deriver_a,
            },
            (
                Ed25519YaoOperationV1::Recovery,
                Some(SigningWorkerYaoDurableStateV1::RecoveryStaged {
                    active_material,
                    active_receipt,
                    deriver_a,
                    deriver_b,
                    candidate,
                    receipt,
                }),
            ) if deriver_a == delivery => SigningWorkerYaoDurableStateV1::RecoveryStaged {
                active_material,
                active_receipt,
                deriver_a,
                deriver_b,
                candidate,
                receipt,
            },
            _ => {
                return Err(invalid_lifecycle(
                    "Deriver A delivery conflicts with Signing Worker Yao state",
                ));
            }
        };
        next.validate()?;
        storage
            .put(SIGNING_WORKER_ED25519_YAO_STATE_KEY, next)
            .await
            .map_err(map_worker_storage_error)?;
        Ok(SigningWorkerYaoCommandResponseV1::Pending {
            session: delivery.binding.session_id.into_bytes(),
            transcript: delivery.package.transcript(),
        })
    }

    async fn deliver_deriver_b(
        &self,
        storage: worker::Storage,
        current: Option<SigningWorkerYaoDurableStateV1>,
        delivery: Ed25519YaoSigningWorkerPackageDeliveryV1,
    ) -> RouterAbProtocolResult<SigningWorkerYaoCommandResponseV1> {
        match current {
            Some(SigningWorkerYaoDurableStateV1::RegistrationPending { deriver_a }) => {
                let candidate = self.combine(deriver_a.clone(), delivery.clone(), None)?;
                let (material, receipt) = candidate.into_parts();
                let staged = SigningWorkerYaoDurableStateV1::RegistrationStaged {
                    deriver_a,
                    deriver_b: delivery,
                    candidate: material,
                    receipt,
                };
                staged.validate()?;
                storage
                    .put(SIGNING_WORKER_ED25519_YAO_STATE_KEY, staged.clone())
                    .await
                    .map_err(map_worker_storage_error)?;
                self.activate_registration(storage, staged).await
            }
            Some(SigningWorkerYaoDurableStateV1::RegistrationStaged {
                deriver_a,
                deriver_b,
                candidate,
                receipt,
            }) if deriver_b == delivery => {
                let staged = SigningWorkerYaoDurableStateV1::RegistrationStaged {
                    deriver_a,
                    deriver_b,
                    candidate,
                    receipt,
                };
                self.activate_registration(storage, staged).await
            }
            Some(SigningWorkerYaoDurableStateV1::Active {
                deriver_b, receipt, ..
            }) if deriver_b == delivery => {
                Ok(SigningWorkerYaoCommandResponseV1::Active { receipt })
            }
            Some(SigningWorkerYaoDurableStateV1::RecoveryPending {
                active_material,
                active_receipt,
                deriver_a,
            }) => {
                let candidate =
                    self.combine(deriver_a.clone(), delivery.clone(), Some(&active_material))?;
                let (material, receipt) = candidate.into_parts();
                let staged = SigningWorkerYaoDurableStateV1::RecoveryStaged {
                    active_material,
                    active_receipt,
                    deriver_a,
                    deriver_b: delivery,
                    candidate: material,
                    receipt: receipt.clone(),
                };
                staged.validate()?;
                storage
                    .put(SIGNING_WORKER_ED25519_YAO_STATE_KEY, staged)
                    .await
                    .map_err(map_worker_storage_error)?;
                Ok(SigningWorkerYaoCommandResponseV1::Staged { receipt })
            }
            Some(SigningWorkerYaoDurableStateV1::RecoveryStaged {
                deriver_b, receipt, ..
            }) if deriver_b == delivery => {
                Ok(SigningWorkerYaoCommandResponseV1::Staged { receipt })
            }
            _ => Err(invalid_lifecycle(
                "Deriver B delivery requires the exact pending Deriver A package",
            )),
        }
    }

    fn combine(
        &self,
        deriver_a: Ed25519YaoSigningWorkerPackageDeliveryV1,
        deriver_b: Ed25519YaoSigningWorkerPackageDeliveryV1,
        active: Option<&Ed25519YaoActiveSigningMaterialV1>,
    ) -> RouterAbProtocolResult<Ed25519YaoSigningWorkerActivationCandidateV1> {
        let runtime = CloudflareSigningWorkerRuntimeV1::from_worker_env(&self.env)?;
        let private_key = load_cloudflare_server_output_hpke_private_key_bytes_v1(
            &self.env,
            runtime.server_output_decrypt_key(),
        )?;
        combine_ed25519_yao_signing_worker_packages_v1(
            &Ed25519YaoRecipientPrivateKeyV1::from_bytes(private_key),
            deriver_a,
            deriver_b,
            active,
        )
    }

    async fn activate_registration(
        &self,
        storage: worker::Storage,
        staged: SigningWorkerYaoDurableStateV1,
    ) -> RouterAbProtocolResult<SigningWorkerYaoCommandResponseV1> {
        let SigningWorkerYaoDurableStateV1::RegistrationStaged {
            deriver_a,
            deriver_b,
            candidate,
            receipt,
        } = staged
        else {
            return Err(invalid_lifecycle(
                "registration activation requires a staged candidate",
            ));
        };
        self.persist_active_output(&candidate, &receipt).await?;
        let active = SigningWorkerYaoDurableStateV1::Active {
            deriver_a,
            deriver_b,
            material: candidate,
            receipt: receipt.clone(),
        };
        active.validate()?;
        storage
            .put(SIGNING_WORKER_ED25519_YAO_STATE_KEY, active)
            .await
            .map_err(map_worker_storage_error)?;
        Ok(SigningWorkerYaoCommandResponseV1::Active { receipt })
    }

    async fn promote_recovery(
        &self,
        storage: worker::Storage,
        current: Option<SigningWorkerYaoDurableStateV1>,
        request: CloudflareEd25519YaoRecoveryPromotionRequestV1,
    ) -> RouterAbProtocolResult<SigningWorkerYaoCommandResponseV1> {
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
        validate_promotion_request(&request, candidate.binding(), &receipt)?;
        self.persist_active_output(&candidate, &receipt).await?;
        let active = SigningWorkerYaoDurableStateV1::Active {
            deriver_a,
            deriver_b,
            material: candidate,
            receipt: receipt.clone(),
        };
        active.validate()?;
        storage
            .put(SIGNING_WORKER_ED25519_YAO_STATE_KEY, active)
            .await
            .map_err(map_worker_storage_error)?;
        Ok(SigningWorkerYaoCommandResponseV1::Active { receipt })
    }

    async fn persist_active_output(
        &self,
        material: &Ed25519YaoActiveSigningMaterialV1,
        receipt: &Ed25519YaoSigningWorkerActivationReceiptV1,
    ) -> RouterAbProtocolResult<()> {
        let runtime = CloudflareSigningWorkerRuntimeV1::from_worker_env(&self.env)?;
        let record = build_output_activation_record(&runtime, material, receipt)?;
        persist_cloudflare_ed25519_yao_output_activation_v1(&self.env, &runtime, record).await
    }
}

pub async fn handle_cloudflare_signing_worker_ed25519_yao_deriver_a_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let delivery = parse_request::<Ed25519YaoSigningWorkerPackageDeliveryV1>(&mut request).await?;
    delivery.validate_for_deriver(Ed25519YaoDeriverRoleV1::DeriverA)?;
    let response = execute_signing_worker_yao_command(
        env,
        SigningWorkerYaoCommandV1::DeliverDeriverA { delivery },
    )
    .await?;
    let SigningWorkerYaoCommandResponseV1::Pending {
        session,
        transcript,
    } = response
    else {
        return Err(invalid_lifecycle(
            "Deriver A delivery returned the wrong lifecycle response",
        ));
    };
    json_response(&CloudflareEd25519YaoSigningWorkerHttpResponseV1::Pending {
        accepted_deriver: Ed25519YaoDeriverRoleV1::DeriverA,
        session,
        transcript,
    })
}

pub async fn handle_cloudflare_signing_worker_ed25519_yao_deriver_b_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let delivery = parse_request::<Ed25519YaoSigningWorkerPackageDeliveryV1>(&mut request).await?;
    delivery.validate_for_deriver(Ed25519YaoDeriverRoleV1::DeriverB)?;
    let response = execute_signing_worker_yao_command(
        env,
        SigningWorkerYaoCommandV1::DeliverDeriverB { delivery },
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum CloudflareEd25519YaoSigningWorkerHttpResponseV1 {
    Pending {
        accepted_deriver: Ed25519YaoDeriverRoleV1,
        session: [u8; 32],
        transcript: [u8; 32],
    },
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
        SigningWorkerYaoCommandResponseV1::Pending { .. } => Err(invalid_lifecycle(
            "Signing Worker activation returned an unexpected pending response",
        )),
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
    let namespace = env
        .durable_object(SIGNING_WORKER_ED25519_YAO_DO_BINDING)
        .map_err(|_| invalid_lifecycle("Signing Worker Yao Durable Object binding is missing"))?;
    let object_name = encode_hex(command.stable_context_binding());
    let stub = namespace
        .get_by_name(&object_name)
        .map_err(|_| invalid_lifecycle("Signing Worker Yao Durable Object lookup failed"))?;
    let body = serde_json::to_string(&command)
        .map_err(|_| invalid_lifecycle("Signing Worker Yao command encoding failed"))?;
    let mut init = worker::RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));
    let request = Request::new_with_init(SIGNING_WORKER_ED25519_YAO_DO_URL, &init)
        .map_err(|_| invalid_lifecycle("Signing Worker Yao request construction failed"))?;
    let mut response = stub
        .fetch_with_request(request)
        .await
        .map_err(|_| invalid_lifecycle("Signing Worker Yao Durable Object request failed"))?;
    if !(200..=299).contains(&response.status_code()) {
        return Err(invalid_lifecycle(
            "Signing Worker Yao Durable Object rejected the transition",
        ));
    }
    response
        .json::<SigningWorkerYaoCommandResponseV1>()
        .await
        .map_err(|_| invalid_lifecycle("Signing Worker Yao response is malformed"))
}

async fn persist_cloudflare_ed25519_yao_output_activation_v1(
    env: &Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    record: CloudflareSigningWorkerOutputActivationRecordV1,
) -> RouterAbProtocolResult<()> {
    let activation_request = CloudflareEd25519YaoOutputActivationPutV1::new(record)?;
    let namespace = env
        .durable_object(&runtime.bindings().server_output.binding_name)
        .map_err(|_| invalid_lifecycle("Signing Worker server-output binding is missing"))?;
    let stub = namespace
        .get_by_name(&runtime.bindings().server_output.object_name)
        .map_err(|_| invalid_lifecycle("Signing Worker server-output lookup failed"))?;
    let body = serde_json::to_string(&activation_request)
        .map_err(|_| invalid_lifecycle("Signing Worker Yao output encoding failed"))?;
    let mut init = worker::RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));
    let request = Request::new_with_init(SIGNING_WORKER_ED25519_YAO_OUTPUT_DO_URL, &init)
        .map_err(|_| invalid_lifecycle("Signing Worker Yao output request construction failed"))?;
    let mut response = stub
        .fetch_with_request(request)
        .await
        .map_err(|_| invalid_lifecycle("Signing Worker Yao output persistence failed"))?;
    if !(200..=299).contains(&response.status_code()) {
        return Err(invalid_lifecycle(
            "Signing Worker Yao output activation was rejected",
        ));
    }
    let receipt = response
        .json::<CloudflareEd25519YaoOutputActivationReceiptV1>()
        .await
        .map_err(|_| invalid_lifecycle("Signing Worker Yao output receipt is malformed"))?;
    receipt.validate()?;
    if receipt.active_signing_worker_state
        != *activation_request.record.active_signing_worker_state()
    {
        return Err(invalid_lifecycle(
            "Signing Worker Yao output receipt changed active state",
        ));
    }
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
        "{}ed25519-yao/{}/{}",
        runtime.bindings().server_output.key_prefix,
        encode_hex(binding.stable_key_context_binding.into_bytes()),
        yao_material.state_epoch().get()
    );
    let active_state = ActiveSigningWorkerStateV1::new(
        binding.lifecycle.account_id.clone(),
        binding.lifecycle.session_id.clone(),
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

fn map_worker_storage_error(_: worker::Error) -> RouterAbProtocolError {
    invalid_lifecycle("Signing Worker Yao Durable Object storage failed")
}

fn invalid_lifecycle(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        message.into(),
    )
}

fn encode_hex(bytes: [u8; 32]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        output.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    output
}
