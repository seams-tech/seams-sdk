use crate::{
    CloudflareActiveSigningWorkerStateLookupV1,
    CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    CloudflareSigningWorkerEcdsaPresignatureRecordV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use router_ab_core::{PublicDigest32, RouterAbEcdsaDerivationNormalSigningScopeV1};
use router_ab_ecdsa_pool::{
    AccountBinding, ActivationEpoch, AvailableRecord, ConsumeDecision, KeyEpoch,
    MaterialDisposition, MaterialLocator, PoolIdentityError, PoolRecordKey, PoolRole,
    PresignPairId, ProtocolBinding, RequestBinding, ReservationBinding, ReservationId,
    SigningScopeBinding, WalletBinding,
};
pub use router_ab_ecdsa_pool::{PoolRecord, TombstoneReason};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Fixed protocol bound into both role-local ECDSA presignature pools.
pub const CLOUDFLARE_FIXED_ECDSA_PRESIGN_PROTOCOL_ID_V1: &str =
    "seams/router-ab-ecdsa-presign/fixed-2of2/v1";

/// Maximum lifetime of one SigningWorker reservation.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_RESERVATION_LEASE_MS_V1: u64 = 60_000;

const WALLET_BINDING_DOMAIN: &[u8] = b"seams/ecdsa-pool/wallet/v1";
const ACCOUNT_BINDING_DOMAIN: &[u8] = b"seams/ecdsa-pool/account/v1";
const PAIR_BINDING_DOMAIN: &[u8] = b"seams/ecdsa-pool/pair/v1";
const KEY_EPOCH_BINDING_DOMAIN: &[u8] = b"seams/ecdsa-pool/key-epoch/v1";
const ACTIVATION_EPOCH_BINDING_DOMAIN: &[u8] = b"seams/ecdsa-pool/activation-epoch/v1";
const PROTOCOL_BINDING_DOMAIN: &[u8] = b"seams/ecdsa-pool/protocol/v1";
const MATERIAL_BINDING_DOMAIN: &[u8] = b"seams/ecdsa-pool/material/v1";
const REQUEST_BINDING_DOMAIN: &[u8] = b"seams/ecdsa-pool/request/v1";
const RESERVATION_BINDING_DOMAIN: &[u8] = b"seams/ecdsa-pool/reservation/v1";

/// Role-local secret material associated with one persistent lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum CloudflareSigningWorkerEcdsaPoolMaterialStateV1 {
    /// Material is admitted and available for one exact signing request.
    Available {
        /// Unbound SigningWorker presignature material.
        material: CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    },
    /// Material is reserved for the request embedded in the bound record.
    Reserved {
        /// Request-bound SigningWorker presignature material.
        material: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    },
    /// Material was atomically taken for one online attempt.
    Consumed,
    /// Secret material has been destroyed and only terminal lifecycle evidence remains.
    Tombstone,
}

/// Persistent SigningWorker adapter record for one fixed-role ECDSA presignature half.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1 {
    /// Complete authenticated normal-signing scope used to derive the pool identity.
    pub scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
    /// Stable pair identifier retained after secret material destruction.
    pub server_presignature_id: String,
    /// Monotonic storage-independent lifecycle state.
    pub lifecycle: PoolRecord,
    /// Role-local material whose variant must match the lifecycle state.
    pub material_state: CloudflareSigningWorkerEcdsaPoolMaterialStateV1,
}

/// Result of consuming an exact SigningWorker reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareSigningWorkerEcdsaPoolConsumeDecisionV1 {
    /// The exact attempt atomically consumed its one-use material.
    Consumed {
        /// Material-free absorbing record that must be persisted.
        record: CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1,
        /// One-use material returned only by the atomic mutation response.
        material: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    },
    /// The attempt was stale, expired, or substituted and became terminal.
    Burned(CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1),
}

/// Atomic mutation accepted by the SigningWorker Durable Object adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation")]
pub enum CloudflareSigningWorkerEcdsaPoolCommandV1 {
    /// Admit a newly generated role-local presignature half.
    PutAvailable {
        /// Authenticated material whose scope defines the full pool identity.
        material: CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    },
    /// Reserve available material for one exact online request.
    Reserve {
        /// Exact authenticated pool scope.
        scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
        /// Exact pair identifier.
        server_presignature_id: String,
        /// Revision that must still be current.
        expected_revision: u64,
        /// Canonical prepare request digest.
        request_digest: PublicDigest32,
        /// Router-admitted signing digest.
        admitted_signing_digest: PublicDigest32,
        /// SigningWorker contribution retained for finalization.
        signing_worker_rerandomization_contribution32_b64u: String,
        /// Reservation timestamp.
        reserved_at_ms: u64,
        /// Exclusive request expiry.
        request_expires_at_ms: u64,
    },
    /// Atomically consume the exact reservation and take its one-use material.
    Consume {
        /// Exact authenticated pool scope.
        scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
        /// Exact pair identifier.
        server_presignature_id: String,
        /// Revision that must still be current.
        expected_revision: u64,
        /// Canonical prepare request digest.
        request_digest: PublicDigest32,
        /// Consumption timestamp.
        now_unix_ms: u64,
    },
    /// Destroy an exact reserved attempt after an online failure.
    DestroyReserved {
        /// Exact authenticated pool scope.
        scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
        /// Exact pair identifier.
        server_presignature_id: String,
        /// Revision that must still be current.
        expected_revision: u64,
        /// Canonical prepare request digest.
        request_digest: PublicDigest32,
        /// Terminal failure reason.
        reason: TombstoneReason,
        /// Terminal timestamp.
        now_unix_ms: u64,
    },
    /// Burn interrupted reserved state during recovery.
    RecoverInterrupted {
        /// Exact authenticated pool scope.
        scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
        /// Exact pair identifier.
        server_presignature_id: String,
        /// Revision that must still be current.
        expected_revision: u64,
        /// Recovery timestamp.
        now_unix_ms: u64,
    },
    /// Burn material whose lifetime or reservation lease elapsed.
    Expire {
        /// Exact authenticated pool scope.
        scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
        /// Exact pair identifier.
        server_presignature_id: String,
        /// Revision that must still be current.
        expected_revision: u64,
        /// Cleanup timestamp.
        now_unix_ms: u64,
    },
    /// Burn material after key or activation epoch retirement.
    Retire {
        /// Exact authenticated pool scope.
        scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
        /// Exact pair identifier.
        server_presignature_id: String,
        /// Revision that must still be current.
        expected_revision: u64,
        /// Exact retirement reason.
        reason: TombstoneReason,
        /// Retirement timestamp.
        now_unix_ms: u64,
    },
}

impl CloudflareSigningWorkerEcdsaPoolCommandV1 {
    /// Validates command fields that do not depend on the persisted record.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::PutAvailable { material } => material.validate(),
            Self::Reserve {
                scope,
                server_presignature_id,
                reserved_at_ms,
                request_expires_at_ms,
                ..
            } => {
                validate_command_scope(scope, server_presignature_id)?;
                validate_positive_timestamp("reserved_at_ms", *reserved_at_ms)?;
                validate_positive_timestamp("request_expires_at_ms", *request_expires_at_ms)?;
                if request_expires_at_ms <= reserved_at_ms {
                    return Err(pool_state_error(
                        "request expiry must be later than reservation time",
                    ));
                }
                Ok(())
            }
            Self::Consume {
                scope,
                server_presignature_id,
                now_unix_ms,
                ..
            }
            | Self::RecoverInterrupted {
                scope,
                server_presignature_id,
                now_unix_ms,
                ..
            }
            | Self::Expire {
                scope,
                server_presignature_id,
                now_unix_ms,
                ..
            } => {
                validate_command_scope(scope, server_presignature_id)?;
                validate_positive_timestamp("now_unix_ms", *now_unix_ms)
            }
            Self::DestroyReserved {
                scope,
                server_presignature_id,
                now_unix_ms,
                ..
            } => {
                validate_command_scope(scope, server_presignature_id)?;
                validate_positive_timestamp("now_unix_ms", *now_unix_ms)
            }
            Self::Retire {
                scope,
                server_presignature_id,
                reason,
                now_unix_ms,
                ..
            } => {
                validate_command_scope(scope, server_presignature_id)?;
                if !matches!(
                    reason,
                    TombstoneReason::KeyEpochRetired | TombstoneReason::ActivationEpochRetired
                ) {
                    return Err(pool_state_error(
                        "retirement requires a key or activation epoch reason",
                    ));
                }
                validate_positive_timestamp("now_unix_ms", *now_unix_ms)
            }
        }
    }

    /// Returns the complete scope used to derive the Durable Object storage key.
    pub const fn scope(&self) -> &RouterAbEcdsaDerivationNormalSigningScopeV1 {
        match self {
            Self::PutAvailable { material } => &material.scope,
            Self::Reserve { scope, .. }
            | Self::Consume { scope, .. }
            | Self::DestroyReserved { scope, .. }
            | Self::RecoverInterrupted { scope, .. }
            | Self::Expire { scope, .. }
            | Self::Retire { scope, .. } => scope,
        }
    }

    /// Returns the pair identifier used to derive the Durable Object storage key.
    pub fn server_presignature_id(&self) -> &str {
        match self {
            Self::PutAvailable { material } => &material.server_presignature_id,
            Self::Reserve {
                server_presignature_id,
                ..
            }
            | Self::Consume {
                server_presignature_id,
                ..
            }
            | Self::DestroyReserved {
                server_presignature_id,
                ..
            }
            | Self::RecoverInterrupted {
                server_presignature_id,
                ..
            }
            | Self::Expire {
                server_presignature_id,
                ..
            }
            | Self::Retire {
                server_presignature_id,
                ..
            } => server_presignature_id,
        }
    }
}

/// Result of one atomic SigningWorker Durable Object pool mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1 {
    /// Available material was admitted or an exact idempotent put was observed.
    Available {
        /// Complete persisted record.
        record: CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1,
        /// Whether persistence changed.
        stored: bool,
    },
    /// Material was reserved for the exact request.
    Reserved {
        /// Complete persisted record.
        record: CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1,
    },
    /// Material was atomically consumed for one online attempt.
    Consumed {
        /// Material-free absorbing record persisted by the Durable Object.
        record: CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1,
        /// One-use material returned only to the caller of this mutation.
        material: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    },
    /// A stale, substituted, or expired commit became terminal.
    Burned {
        /// Complete material-free tombstone.
        record: CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1,
    },
    /// The requested terminal mutation completed.
    Finished {
        /// Complete material-free tombstone.
        record: CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1,
    },
}

impl CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1 {
    /// Validates persisted lifecycle state against the mutation outcome branch.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.record().validate()?;
        if let Self::Consumed { record, material } = self {
            material.validate()?;
            validate_material_pair_id(
                &record.server_presignature_id,
                &material.server_presignature_id,
            )?;
            let PoolRecord::Consumed(consumed) = &record.lifecycle else {
                return Err(pool_state_error(
                    "consumed outcome does not contain a consumed lifecycle",
                ));
            };
            validate_bound_material(&record.scope, consumed.binding(), material)?;
        }
        let valid = matches!(
            (self, &self.record().lifecycle),
            (Self::Available { .. }, PoolRecord::Available(_))
                | (Self::Reserved { .. }, PoolRecord::Reserved(_))
                | (Self::Consumed { .. }, PoolRecord::Consumed(_))
                | (Self::Burned { .. }, PoolRecord::Tombstone(_))
                | (Self::Finished { .. }, PoolRecord::Tombstone(_))
        );
        if valid {
            return Ok(());
        }
        Err(pool_state_error(
            "SigningWorker pool mutation outcome does not match lifecycle state",
        ))
    }

    /// Returns the replacement record that the Durable Object must persist atomically.
    pub const fn record(&self) -> &CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1 {
        match self {
            Self::Available { record, .. }
            | Self::Reserved { record }
            | Self::Consumed { record, .. }
            | Self::Burned { record }
            | Self::Finished { record } => record,
        }
    }
}

/// Applies one compare-and-swap command to the currently persisted pool record.
pub fn apply_cloudflare_signing_worker_ecdsa_pool_command_v1(
    current: Option<CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1>,
    command: CloudflareSigningWorkerEcdsaPoolCommandV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1> {
    command.validate()?;
    match command {
        CloudflareSigningWorkerEcdsaPoolCommandV1::PutAvailable { material } => {
            let replacement =
                CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::new_available(material)?;
            match current {
                None => Ok(
                    CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Available {
                        record: replacement,
                        stored: true,
                    },
                ),
                Some(existing) if existing == replacement => Ok(
                    CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Available {
                        record: existing,
                        stored: false,
                    },
                ),
                Some(_) => Err(pool_replay_error(
                    "SigningWorker ECDSA pair identity is already persisted",
                )),
            }
        }
        CloudflareSigningWorkerEcdsaPoolCommandV1::Reserve {
            scope,
            server_presignature_id,
            expected_revision,
            request_digest,
            admitted_signing_digest,
            signing_worker_rerandomization_contribution32_b64u,
            reserved_at_ms,
            request_expires_at_ms,
        } => {
            let current = require_current(current)?;
            validate_command_identity(
                &current,
                &scope,
                &server_presignature_id,
                expected_revision,
            )?;
            let record = current.reserve(
                request_digest,
                admitted_signing_digest,
                signing_worker_rerandomization_contribution32_b64u,
                reserved_at_ms,
                request_expires_at_ms,
            )?;
            Ok(CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Reserved { record })
        }
        CloudflareSigningWorkerEcdsaPoolCommandV1::Consume {
            scope,
            server_presignature_id,
            expected_revision,
            request_digest,
            now_unix_ms,
        } => {
            let current = require_current(current)?;
            validate_command_identity(
                &current,
                &scope,
                &server_presignature_id,
                expected_revision,
            )?;
            match current.consume(request_digest, now_unix_ms)? {
                CloudflareSigningWorkerEcdsaPoolConsumeDecisionV1::Consumed {
                    record,
                    material,
                } => Ok(
                    CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Consumed {
                        record,
                        material,
                    },
                ),
                CloudflareSigningWorkerEcdsaPoolConsumeDecisionV1::Burned(record) => {
                    Ok(CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Burned { record })
                }
            }
        }
        CloudflareSigningWorkerEcdsaPoolCommandV1::DestroyReserved {
            scope,
            server_presignature_id,
            expected_revision,
            request_digest,
            reason,
            now_unix_ms,
        } => {
            let current = require_current(current)?;
            validate_command_identity(
                &current,
                &scope,
                &server_presignature_id,
                expected_revision,
            )?;
            let record = current.destroy_reserved(request_digest, reason, now_unix_ms)?;
            Ok(CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Finished { record })
        }
        CloudflareSigningWorkerEcdsaPoolCommandV1::RecoverInterrupted {
            scope,
            server_presignature_id,
            expected_revision,
            now_unix_ms,
        } => {
            let current = require_current(current)?;
            validate_command_identity(
                &current,
                &scope,
                &server_presignature_id,
                expected_revision,
            )?;
            let record = current.recover_after_crash(now_unix_ms)?;
            Ok(CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Finished { record })
        }
        CloudflareSigningWorkerEcdsaPoolCommandV1::Expire {
            scope,
            server_presignature_id,
            expected_revision,
            now_unix_ms,
        } => {
            let current = require_current(current)?;
            validate_command_identity(
                &current,
                &scope,
                &server_presignature_id,
                expected_revision,
            )?;
            let record = current.expire(now_unix_ms)?;
            Ok(CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Finished { record })
        }
        CloudflareSigningWorkerEcdsaPoolCommandV1::Retire {
            scope,
            server_presignature_id,
            expected_revision,
            reason,
            now_unix_ms,
        } => {
            let current = require_current(current)?;
            validate_command_identity(
                &current,
                &scope,
                &server_presignature_id,
                expected_revision,
            )?;
            let record = current.retire(reason, now_unix_ms)?;
            Ok(CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Finished { record })
        }
    }
}

impl CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1 {
    /// Creates an available record from authenticated scope and admitted material.
    pub fn new_available(
        material: CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        material.validate()?;
        let scope = material.scope.clone();
        validate_active_scope(&scope, &material.active_signing_worker_state)?;
        let key = pool_key(&scope, &material.server_presignature_id)?;
        let locator = MaterialLocator::new(binding_digest(
            MATERIAL_BINDING_DOMAIN,
            &[
                scope.scope_digest()?.as_bytes(),
                material.server_presignature_id.as_bytes(),
            ],
        ))
        .map_err(pool_identity_error)?;
        let lifecycle =
            AvailableRecord::new(key, locator, material.created_at_ms, material.expires_at_ms)
                .map_err(pool_transition_error)?
                .into();
        let record = Self {
            scope,
            server_presignature_id: material.server_presignature_id.clone(),
            lifecycle,
            material_state: CloudflareSigningWorkerEcdsaPoolMaterialStateV1::Available { material },
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates exact identity, lifecycle, and material-state agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        if self.server_presignature_id.is_empty() {
            return Err(pool_state_error("SigningWorker presignature id is empty"));
        }
        if self.lifecycle.key() != &pool_key(&self.scope, &self.server_presignature_id)? {
            return Err(pool_state_error(
                "SigningWorker pool lifecycle identity drift",
            ));
        }
        match (&self.lifecycle, &self.material_state) {
            (
                PoolRecord::Available(_),
                CloudflareSigningWorkerEcdsaPoolMaterialStateV1::Available { material },
            ) => {
                material.validate()?;
                validate_material_pair_id(
                    &self.server_presignature_id,
                    &material.server_presignature_id,
                )?;
                validate_active_scope(&self.scope, &material.active_signing_worker_state)
            }
            (
                PoolRecord::Reserved(lifecycle),
                CloudflareSigningWorkerEcdsaPoolMaterialStateV1::Reserved { material },
            ) => {
                material.validate()?;
                validate_material_pair_id(
                    &self.server_presignature_id,
                    &material.server_presignature_id,
                )?;
                validate_bound_material(&self.scope, lifecycle.binding(), material)
            }
            (
                PoolRecord::Consumed(_),
                CloudflareSigningWorkerEcdsaPoolMaterialStateV1::Consumed,
            ) => Ok(()),
            (
                PoolRecord::Tombstone(_),
                CloudflareSigningWorkerEcdsaPoolMaterialStateV1::Tombstone,
            ) => Ok(()),
            _ => Err(pool_state_error(
                "SigningWorker pool lifecycle and material state disagree",
            )),
        }
    }

    /// Reserves available material for one exact prepare request.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        self,
        request_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        signing_worker_rerandomization_contribution32_b64u: impl Into<String>,
        reserved_at_ms: u64,
        request_expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        self.validate()?;
        let binding =
            reservation_binding(&self.scope, self.server_presignature_id()?, request_digest)?;
        let PoolRecord::Available(lifecycle) = &self.lifecycle else {
            return Err(pool_state_error(
                "SigningWorker ECDSA material is not available",
            ));
        };
        let CloudflareSigningWorkerEcdsaPoolMaterialStateV1::Available { material } =
            &self.material_state
        else {
            return Err(pool_state_error(
                "SigningWorker available lifecycle has no available material",
            ));
        };
        let lease_expires_at_ms = reserved_at_ms
            .checked_add(CLOUDFLARE_SIGNING_WORKER_ECDSA_RESERVATION_LEASE_MS_V1)
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidTimeRange,
                    "SigningWorker ECDSA reservation lease overflowed",
                )
            })?
            .min(request_expires_at_ms)
            .min(lifecycle.material_expires_at_ms());
        let mutation = lifecycle
            .reserve(binding, reserved_at_ms, lease_expires_at_ms)
            .map_err(pool_transition_error)?;
        let (lifecycle, disposition) = mutation.into_parts();
        if disposition != MaterialDisposition::Retain {
            return Err(pool_state_error(
                "SigningWorker reservation unexpectedly changed material disposition",
            ));
        }
        let bound_material = material.to_request_bound_record(
            request_digest,
            admitted_signing_digest,
            signing_worker_rerandomization_contribution32_b64u,
            reserved_at_ms,
            request_expires_at_ms,
        )?;
        let record = Self {
            scope: self.scope,
            server_presignature_id: self.server_presignature_id,
            lifecycle,
            material_state: CloudflareSigningWorkerEcdsaPoolMaterialStateV1::Reserved {
                material: bound_material,
            },
        };
        record.validate()?;
        Ok(record)
    }

    /// Atomically consumes an exact reservation or persists the required terminal burn.
    pub fn consume(
        self,
        request_digest: PublicDigest32,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPoolConsumeDecisionV1> {
        self.validate()?;
        let binding =
            reservation_binding(&self.scope, self.server_presignature_id()?, request_digest)?;
        let PoolRecord::Reserved(lifecycle) = &self.lifecycle else {
            return Err(pool_state_error(
                "SigningWorker ECDSA material is not reserved",
            ));
        };
        match lifecycle.consume(binding, now_unix_ms) {
            ConsumeDecision::Consumed(mutation) => {
                let CloudflareSigningWorkerEcdsaPoolMaterialStateV1::Reserved { material } =
                    self.material_state
                else {
                    return Err(pool_state_error(
                        "SigningWorker reservation has no reserved material",
                    ));
                };
                let (lifecycle, disposition) = mutation.into_parts();
                if !matches!(disposition, MaterialDisposition::Take(_)) {
                    return Err(pool_state_error(
                        "SigningWorker consumption did not take one-use material",
                    ));
                }
                let record = Self {
                    scope: self.scope,
                    server_presignature_id: self.server_presignature_id,
                    lifecycle,
                    material_state: CloudflareSigningWorkerEcdsaPoolMaterialStateV1::Consumed,
                };
                record.validate()?;
                Ok(
                    CloudflareSigningWorkerEcdsaPoolConsumeDecisionV1::Consumed {
                        record,
                        material,
                    },
                )
            }
            ConsumeDecision::Burned(mutation) => {
                let (lifecycle, disposition) = mutation.into_parts();
                if !matches!(disposition, MaterialDisposition::Destroy(_)) {
                    return Err(pool_state_error(
                        "SigningWorker burn did not destroy one-use material",
                    ));
                }
                let record = Self {
                    scope: self.scope,
                    server_presignature_id: self.server_presignature_id,
                    lifecycle,
                    material_state: CloudflareSigningWorkerEcdsaPoolMaterialStateV1::Tombstone,
                };
                record.validate()?;
                Ok(CloudflareSigningWorkerEcdsaPoolConsumeDecisionV1::Burned(
                    record,
                ))
            }
            ConsumeDecision::Rejected(error) => Err(pool_transition_error(error)),
        }
    }

    /// Destroys a reserved attempt after cancellation, peer abort, or rejection.
    pub fn destroy_reserved(
        self,
        request_digest: PublicDigest32,
        reason: TombstoneReason,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        self.validate()?;
        let PoolRecord::Reserved(lifecycle) = &self.lifecycle else {
            return Err(pool_state_error(
                "SigningWorker ECDSA material is not reserved",
            ));
        };
        let attempted_binding =
            reservation_binding(&self.scope, self.server_presignature_id()?, request_digest)?;
        let reason = if attempted_binding == lifecycle.binding() {
            reason
        } else {
            TombstoneReason::BindingRejected
        };
        let mutation = lifecycle
            .destroy(reason, now_unix_ms)
            .map_err(pool_transition_error)?;
        self.into_destroyed_tombstone(mutation)
    }

    /// Burns interrupted reserved state during startup recovery.
    pub fn recover_after_crash(self, now_unix_ms: u64) -> RouterAbProtocolResult<Self> {
        self.validate()?;
        let replacement = match &self.lifecycle {
            PoolRecord::Reserved(record) => record
                .recover_after_crash(now_unix_ms)
                .map_err(pool_transition_error)?,
            PoolRecord::Available(_) | PoolRecord::Consumed(_) | PoolRecord::Tombstone(_) => {
                return Err(pool_state_error(
                    "SigningWorker crash recovery requires interrupted material",
                ));
            }
        };
        self.into_destroyed_tombstone(replacement)
    }

    /// Burns available or reserved material after its first cleanup deadline.
    pub fn expire(self, now_unix_ms: u64) -> RouterAbProtocolResult<Self> {
        self.validate()?;
        let mutation = match &self.lifecycle {
            PoolRecord::Available(record) => record.expire(now_unix_ms),
            PoolRecord::Reserved(record) => record.expire(now_unix_ms),
            PoolRecord::Consumed(_) | PoolRecord::Tombstone(_) => {
                return Err(pool_state_error(
                    "SigningWorker ECDSA terminal material cannot expire again",
                ));
            }
        }
        .map_err(pool_transition_error)?;
        self.into_destroyed_tombstone(mutation)
    }

    /// Burns available or reserved material after key or activation retirement.
    pub fn retire(self, reason: TombstoneReason, now_unix_ms: u64) -> RouterAbProtocolResult<Self> {
        self.validate()?;
        let mutation = match &self.lifecycle {
            PoolRecord::Available(record) => record.retire(reason, now_unix_ms),
            PoolRecord::Reserved(record) => record.retire(reason, now_unix_ms),
            PoolRecord::Consumed(_) | PoolRecord::Tombstone(_) => {
                return Err(pool_state_error(
                    "SigningWorker ECDSA terminal material cannot retire again",
                ));
            }
        }
        .map_err(pool_transition_error)?;
        self.into_destroyed_tombstone(mutation)
    }

    /// Returns the first deadline at which persisted secret material must be burned.
    pub const fn cleanup_deadline_ms(&self) -> Option<u64> {
        match &self.lifecycle {
            PoolRecord::Available(record) => Some(record.material_expires_at_ms()),
            PoolRecord::Reserved(record) => Some(record.cleanup_deadline_ms()),
            PoolRecord::Consumed(_) | PoolRecord::Tombstone(_) => None,
        }
    }

    /// Returns request-bound material only after durable reservation.
    pub fn reserved_material(
        &self,
    ) -> RouterAbProtocolResult<&CloudflareSigningWorkerEcdsaPresignatureRecordV1> {
        self.validate()?;
        match &self.material_state {
            CloudflareSigningWorkerEcdsaPoolMaterialStateV1::Reserved { material } => Ok(material),
            _ => Err(pool_state_error(
                "SigningWorker material is unavailable before reservation",
            )),
        }
    }

    /// Returns the stable pair identifier in every lifecycle state.
    pub fn server_presignature_id(&self) -> RouterAbProtocolResult<&str> {
        Ok(&self.server_presignature_id)
    }

    fn into_destroyed_tombstone(
        self,
        mutation: router_ab_ecdsa_pool::PoolMutation,
    ) -> RouterAbProtocolResult<Self> {
        let (lifecycle, disposition) = mutation.into_parts();
        if !matches!(disposition, MaterialDisposition::Destroy(_)) {
            return Err(pool_state_error(
                "SigningWorker terminal transition did not destroy material",
            ));
        }
        let record = Self {
            scope: self.scope,
            server_presignature_id: self.server_presignature_id,
            lifecycle,
            material_state: CloudflareSigningWorkerEcdsaPoolMaterialStateV1::Tombstone,
        };
        record.validate()?;
        Ok(record)
    }
}

fn validate_bound_material(
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    binding: ReservationBinding,
    material: &CloudflareSigningWorkerEcdsaPresignatureRecordV1,
) -> RouterAbProtocolResult<()> {
    validate_active_scope(scope, &material.active_signing_worker_state)?;
    let expected = reservation_binding(
        scope,
        &material.server_presignature_id,
        material.request_digest,
    )?;
    if expected == binding {
        return Ok(());
    }
    Err(pool_state_error(
        "SigningWorker request-bound material does not match lifecycle binding",
    ))
}

fn validate_material_pair_id(expected: &str, actual: &str) -> RouterAbProtocolResult<()> {
    if expected == actual {
        return Ok(());
    }
    Err(pool_state_error(
        "SigningWorker material pair id does not match lifecycle identity",
    ))
}

fn validate_command_scope(
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    server_presignature_id: &str,
) -> RouterAbProtocolResult<()> {
    scope.validate()?;
    if server_presignature_id.is_empty() {
        return Err(pool_state_error("SigningWorker presignature id is empty"));
    }
    Ok(())
}

fn validate_positive_timestamp(field: &str, value: u64) -> RouterAbProtocolResult<()> {
    if value > 0 {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidTimeRange,
        format!("{field} must be positive"),
    ))
}

fn require_current(
    current: Option<CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1>,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1> {
    current.ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            "SigningWorker ECDSA pool record is missing",
        )
    })
}

fn validate_command_identity(
    current: &CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1,
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    server_presignature_id: &str,
    expected_revision: u64,
) -> RouterAbProtocolResult<()> {
    current.validate()?;
    scope.validate()?;
    if current.scope != *scope || current.server_presignature_id != server_presignature_id {
        return Err(pool_replay_error(
            "SigningWorker ECDSA pool command identity does not match persisted material",
        ));
    }
    if current.lifecycle.revision().value() != expected_revision {
        return Err(pool_replay_error(
            "SigningWorker ECDSA pool command used a stale revision",
        ));
    }
    Ok(())
}

fn validate_active_scope(
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    active: &router_ab_core::ActiveSigningWorkerStateV1,
) -> RouterAbProtocolResult<()> {
    CloudflareActiveSigningWorkerStateLookupV1::from_router_ab_ecdsa_derivation_normal_signing_scope(
        scope,
    )?
    .validate_active_state(active)
}

fn pool_key(
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    server_presignature_id: &str,
) -> RouterAbProtocolResult<PoolRecordKey> {
    scope.validate()?;
    if server_presignature_id.is_empty() {
        return Err(pool_state_error("SigningWorker presignature id is empty"));
    }
    let scope_digest = scope.scope_digest()?;
    Ok(PoolRecordKey::new(
        WalletBinding::new(binding_digest(
            WALLET_BINDING_DOMAIN,
            &[scope.wallet_key_id.as_bytes()],
        ))
        .map_err(pool_identity_error)?,
        AccountBinding::new(binding_digest(
            ACCOUNT_BINDING_DOMAIN,
            &[scope.wallet_id.as_bytes()],
        ))
        .map_err(pool_identity_error)?,
        SigningScopeBinding::new(*scope_digest.as_bytes()).map_err(pool_identity_error)?,
        PresignPairId::new(binding_digest(
            PAIR_BINDING_DOMAIN,
            &[server_presignature_id.as_bytes()],
        ))
        .map_err(pool_identity_error)?,
        PoolRole::SigningWorker,
        KeyEpoch::new(binding_digest(
            KEY_EPOCH_BINDING_DOMAIN,
            &[scope.signing_worker.key_epoch.as_bytes()],
        ))
        .map_err(pool_identity_error)?,
        ActivationEpoch::new(binding_digest(
            ACTIVATION_EPOCH_BINDING_DOMAIN,
            &[scope.activation_epoch.as_bytes()],
        ))
        .map_err(pool_identity_error)?,
        ProtocolBinding::new(binding_digest(
            PROTOCOL_BINDING_DOMAIN,
            &[CLOUDFLARE_FIXED_ECDSA_PRESIGN_PROTOCOL_ID_V1.as_bytes()],
        ))
        .map_err(pool_identity_error)?,
    ))
}

fn reservation_binding(
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    server_presignature_id: &str,
    request_digest: PublicDigest32,
) -> RouterAbProtocolResult<ReservationBinding> {
    let scope_digest = scope.scope_digest()?;
    let request = RequestBinding::new(binding_digest(
        REQUEST_BINDING_DOMAIN,
        &[scope_digest.as_bytes(), request_digest.as_bytes()],
    ))
    .map_err(pool_identity_error)?;
    let reservation = ReservationId::new(binding_digest(
        RESERVATION_BINDING_DOMAIN,
        &[
            scope_digest.as_bytes(),
            server_presignature_id.as_bytes(),
            request_digest.as_bytes(),
        ],
    ))
    .map_err(pool_identity_error)?;
    Ok(ReservationBinding::new(reservation, request))
}

fn binding_digest(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn pool_identity_error(error: PoolIdentityError) -> RouterAbProtocolError {
    pool_state_error(&error.to_string())
}

fn pool_transition_error(
    error: router_ab_ecdsa_pool::PoolTransitionError,
) -> RouterAbProtocolError {
    pool_state_error(&error.to_string())
}

fn pool_state_error(message: &str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        message,
    )
}

fn pool_replay_error(message: &str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::ReplayedLocalRequest, message)
}
