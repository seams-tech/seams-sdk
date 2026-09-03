//! Feature-independent wire types shared by the Cloudflare and native local adapters.

use router_ab_core::{
    Ed25519YaoDeriverAPrefaceInFlightV2, Ed25519YaoDeriverAToBTargetProofPayloadV2,
    Ed25519YaoDeriverBPrefaceInFlightV2, Ed25519YaoDeriverBToATargetProofPayloadV2,
    Ed25519YaoEncryptedInputV1, Ed25519YaoExecutionIdV1, Ed25519YaoInputPairBindingV1,
    Ed25519YaoLaneJobV1, Ed25519YaoOuterBindingV2, Ed25519YaoPairSessionIdV2,
    Ed25519YaoRoleReadinessReceiptV1, Ed25519YaoRoleStartAcceptanceV1, RouterAbDerivationError,
    RouterAbEd25519YaoApplicationBindingFactsV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult, RouterEd25519YaoBurnReasonV1, RouterEd25519YaoExecuteFailureCodeV1,
    RouterEd25519YaoGatewayExecuteTargetV2, TenantRootActivationReceiptBindingV1,
    TenantRootCustodyBindingV1, TenantRootDerivationNonceV1, TenantRootDerivationOperationIdV1,
    TenantRootDerivationSessionIdV1, TenantRootDeriverIdentitiesV1,
    TenantRootOnlineRoleShareBindingV1, TenantRootProtocolDigestV1,
    TenantRootSignedActivationReceiptV1, TwoPartyDeriverRole,
    VerifiedTenantRootSignedActivationReceiptV1,
};
use router_ab_ed25519_yao::{stable_key_derivation_context_v1, Ed25519YaoRoleExecutionV1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_deriver_a_server_contribution_v1,
    derive_ed25519_yao_deriver_b_server_contribution_v1, Ed25519YaoDeriverADerivationRootV1,
    Ed25519YaoDeriverAServerContributionV1, Ed25519YaoDeriverBDerivationRootV1,
    Ed25519YaoDeriverBServerContributionV1, Ed25519YaoStableKeyDerivationContextV1,
};
use threshold_prf::{
    prepare_ed25519_deriver_a_target_v1, prepare_ed25519_deriver_b_target_v1,
    SigningRootShareCommitment, SigningRootShareWire,
};

use crate::{CloudflareTenantRootCoordinatesV1, CloudflareTenantRootCustodyBindingWireV1};

/// Server-admitted execution envelope. Tenant-root selectors and stable-context
/// facts are supplied by the authenticated wallet server, never by the browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterEd25519YaoExecuteRequestV2 {
    pub tenant_root: CloudflareTenantRootCoordinatesV1,
    pub application: RouterAbEd25519YaoApplicationBindingFactsV1,
    pub participant_ids: [u16; 2],
    pub target: RouterEd25519YaoGatewayExecuteTargetV2,
}

impl CloudflareRouterEd25519YaoExecuteRequestV2 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.tenant_root.resolve()?;
        validate_participant_ids(self.participant_ids)?;
        if self.application.wallet_id() != self.target.ceremony_binding().lifecycle.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "server-resolved Ed25519 application wallet does not match the ceremony",
            ));
        }
        let stable_context =
            stable_key_derivation_context_v1(&self.application, self.participant_ids).map_err(
                |_| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLifecycleState,
                        "server-resolved Ed25519 stable context is invalid",
                    )
                },
            )?;
        if stable_context.binding_digest()
            != self
                .target
                .ceremony_binding()
                .stable_key_context_binding
                .into_bytes()
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "server-resolved Ed25519 facts do not match the ceremony stable context",
            ));
        }
        Ok(())
    }
}

fn validate_participant_ids(participant_ids: [u16; 2]) -> RouterAbProtocolResult<()> {
    if participant_ids[0] == 0
        || participant_ids[1] == 0
        || participant_ids[0] >= participant_ids[1]
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "Ed25519 Yao participant ids must be distinct, nonzero, ascending values",
        ));
    }
    Ok(())
}

/// Resolves the epoch-bound custody wire and outer binding from one issuer-
/// verified active receipt and one admitted pair.
pub fn cloudflare_ed25519_yao_tenant_root_bindings_v2(
    activation_receipt: &VerifiedTenantRootSignedActivationReceiptV1,
    derivers: TenantRootDeriverIdentitiesV1,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> RouterAbProtocolResult<(
    CloudflareTenantRootCustodyBindingWireV1,
    Ed25519YaoOuterBindingV2,
)> {
    pair_binding.validate()?;
    let pair_digest = pair_binding.pair_digest();
    let operation_id = derive_tenant_root_scope_id_v2(
        b"seams/ed25519-yao/tenant-root-operation/v2",
        pair_digest.as_bytes(),
    )?;
    let session_id = derive_tenant_root_scope_session_v2(
        b"seams/ed25519-yao/tenant-root-session/v2",
        pair_digest.as_bytes(),
    )?;
    let nonce = TenantRootDerivationNonceV1::from_bytes(derive_tenant_root_scope_bytes_v2(
        b"seams/ed25519-yao/tenant-root-nonce/v2",
        pair_digest.as_bytes(),
    ))
    .map_err(map_tenant_root_derivation_error)?;
    let wire = CloudflareTenantRootCustodyBindingWireV1::from_verified_activation_receipt(
        activation_receipt,
        operation_id,
        session_id,
        nonce,
        issued_at_ms,
        expires_at_ms,
    )?;
    let stable_context_digest = TenantRootProtocolDigestV1::from_bytes(
        pair_binding
            .binding()
            .stable_key_context_binding
            .into_bytes(),
    )
    .map_err(map_tenant_root_derivation_error)?;
    let custody_binding =
        TenantRootCustodyBindingV1::from_verified_activation_receipt_with_stable_context_digest(
            activation_receipt,
            derivers,
            operation_id,
            session_id,
            nonce,
            issued_at_ms,
            expires_at_ms,
            stable_context_digest,
            TenantRootProtocolDigestV1::from_bytes(*pair_digest.as_bytes())
                .map_err(map_tenant_root_derivation_error)?,
        )
        .map_err(map_tenant_root_derivation_error)?;
    let custody_digest = custody_binding
        .digest()
        .map_err(map_tenant_root_derivation_error)?;
    let outer_nonce_digest = derive_tenant_root_scope_bytes_v2(
        b"seams/ed25519-yao/outer-nonce/v2",
        custody_digest.as_bytes(),
    );
    let mut outer_nonce = [0_u8; 16];
    outer_nonce.copy_from_slice(&outer_nonce_digest[..16]);
    let outer_binding = Ed25519YaoOuterBindingV2::new(
        Ed25519YaoPairSessionIdV2::new(pair_binding.session())?,
        pair_binding.binding().stable_key_context_binding,
        router_ab_core::PublicDigest32::new(*custody_digest.as_bytes()),
        outer_nonce,
        issued_at_ms,
        expires_at_ms,
    )?;
    Ok((wire, outer_binding))
}

/// Builds the exact V2 context after the local or Worker boundary has
/// authenticated the active receipt and selected server-owned application facts.
pub fn cloudflare_ed25519_yao_tenant_root_context_v2(
    activation_receipt: &VerifiedTenantRootSignedActivationReceiptV1,
    derivers: TenantRootDeriverIdentitiesV1,
    application: RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    pair_binding: &Ed25519YaoInputPairBindingV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareEd25519YaoTenantRootContextV2> {
    let (custody_binding, outer_binding) = cloudflare_ed25519_yao_tenant_root_bindings_v2(
        activation_receipt,
        derivers,
        pair_binding,
        issued_at_ms,
        expires_at_ms,
    )?;
    let context = CloudflareEd25519YaoTenantRootContextV2 {
        custody_binding,
        outer_binding,
        application,
        participant_ids,
    };
    context.validate_for_pair(pair_binding)?;
    Ok(context)
}

fn derive_tenant_root_scope_bytes_v2(domain: &[u8], transcript: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(transcript);
    hasher.finalize().into()
}

fn derive_tenant_root_scope_id_v2(
    domain: &[u8],
    transcript: &[u8; 32],
) -> RouterAbProtocolResult<TenantRootDerivationOperationIdV1> {
    TenantRootDerivationOperationIdV1::from_bytes(
        derive_tenant_root_scope_bytes_v2(domain, transcript)[..16]
            .try_into()
            .expect("fixed tenant-root operation id length"),
    )
    .map_err(map_tenant_root_derivation_error)
}

fn derive_tenant_root_scope_session_v2(
    domain: &[u8],
    transcript: &[u8; 32],
) -> RouterAbProtocolResult<TenantRootDerivationSessionIdV1> {
    TenantRootDerivationSessionIdV1::from_bytes(
        derive_tenant_root_scope_bytes_v2(domain, transcript)[..16]
            .try_into()
            .expect("fixed tenant-root session id length"),
    )
    .map_err(map_tenant_root_derivation_error)
}

fn map_tenant_root_derivation_error(error: RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("Ed25519 Yao tenant-root binding is invalid: {error}"),
    )
}

/// Prepares Deriver A's authenticated V2 target-proof preface from its
/// already-resolved role share.
pub fn cloudflare_ed25519_yao_prepare_deriver_a_target_v2(
    context: &CloudflareEd25519YaoTenantRootContextV2,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    role_binding: &TenantRootOnlineRoleShareBindingV1,
    share_wire: &SigningRootShareWire,
) -> RouterAbProtocolResult<Ed25519YaoDeriverAPrefaceInFlightV2> {
    let stable_context = validate_target_preface_inputs(
        context,
        pair_binding,
        role_binding,
        share_wire,
        TwoPartyDeriverRole::DeriverA,
    )?;
    let share = share_wire.to_share().map_err(map_threshold_preface_error)?;
    let expected_peer_commitment = target_peer_commitment(context, TwoPartyDeriverRole::DeriverB)?;
    let mut rng = crate::hpke::CloudflareSignerProofGetrandomRngV1;
    let (prepared, outbound) = prepare_ed25519_deriver_a_target_v1(
        &share,
        expected_peer_commitment,
        &stable_context.encode(),
        &mut rng,
    )
    .map_err(map_threshold_preface_error)?;
    Ed25519YaoDeriverAPrefaceInFlightV2::new(context.outer_binding.clone(), prepared, outbound)
}

/// Completes Deriver A's V2 target-proof preface and derives its role-local
/// server contribution.
pub fn cloudflare_ed25519_yao_complete_deriver_a_target_v2(
    preface: Ed25519YaoDeriverAPrefaceInFlightV2,
    incoming: &Ed25519YaoDeriverBToATargetProofPayloadV2,
    incoming_plaintext: &[u8],
    context: &CloudflareEd25519YaoTenantRootContextV2,
) -> RouterAbProtocolResult<Ed25519YaoDeriverAServerContributionV1> {
    let stable_context =
        stable_key_derivation_context_v1(&context.application, context.participant_ids).map_err(
            |error| invalid_target_preface(format!("stable context is invalid: {error}")),
        )?;
    let ready = preface.complete(incoming, incoming_plaintext)?;
    if ready.binding() != &context.outer_binding
        || ready.binding().stable_context_binding().into_bytes() != stable_context.binding_digest()
    {
        return Err(invalid_target_preface(
            "Deriver A target-proof completion binding does not match tenant-root context",
        ));
    }
    let target_root = ready.into_threshold_prf_root().into_secret_bytes();
    derive_ed25519_yao_deriver_a_server_contribution_v1(
        &Ed25519YaoDeriverADerivationRootV1::from_secret_bytes(*target_root),
        &stable_context,
    )
    .map_err(|error| invalid_target_preface(format!("Deriver A contribution failed: {error}")))
}

/// Prepares Deriver B's authenticated V2 target-proof preface from its
/// already-resolved role share.
pub fn cloudflare_ed25519_yao_prepare_deriver_b_target_v2(
    context: &CloudflareEd25519YaoTenantRootContextV2,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    role_binding: &TenantRootOnlineRoleShareBindingV1,
    share_wire: &SigningRootShareWire,
) -> RouterAbProtocolResult<Ed25519YaoDeriverBPrefaceInFlightV2> {
    let stable_context = validate_target_preface_inputs(
        context,
        pair_binding,
        role_binding,
        share_wire,
        TwoPartyDeriverRole::DeriverB,
    )?;
    let share = share_wire.to_share().map_err(map_threshold_preface_error)?;
    let expected_peer_commitment = target_peer_commitment(context, TwoPartyDeriverRole::DeriverA)?;
    let mut rng = crate::hpke::CloudflareSignerProofGetrandomRngV1;
    let (prepared, outbound) = prepare_ed25519_deriver_b_target_v1(
        &share,
        expected_peer_commitment,
        &stable_context.encode(),
        &mut rng,
    )
    .map_err(map_threshold_preface_error)?;
    Ed25519YaoDeriverBPrefaceInFlightV2::new(context.outer_binding.clone(), prepared, outbound)
}

/// Completes Deriver B's V2 target-proof preface and derives its role-local
/// server contribution.
pub fn cloudflare_ed25519_yao_complete_deriver_b_target_v2(
    preface: Ed25519YaoDeriverBPrefaceInFlightV2,
    incoming: &Ed25519YaoDeriverAToBTargetProofPayloadV2,
    incoming_plaintext: &[u8],
    context: &CloudflareEd25519YaoTenantRootContextV2,
) -> RouterAbProtocolResult<Ed25519YaoDeriverBServerContributionV1> {
    let stable_context =
        stable_key_derivation_context_v1(&context.application, context.participant_ids).map_err(
            |error| invalid_target_preface(format!("stable context is invalid: {error}")),
        )?;
    let ready = preface.complete(incoming, incoming_plaintext)?;
    if ready.binding() != &context.outer_binding
        || ready.binding().stable_context_binding().into_bytes() != stable_context.binding_digest()
    {
        return Err(invalid_target_preface(
            "Deriver B target-proof completion binding does not match tenant-root context",
        ));
    }
    let target_root = ready.into_threshold_prf_root().into_secret_bytes();
    derive_ed25519_yao_deriver_b_server_contribution_v1(
        &Ed25519YaoDeriverBDerivationRootV1::from_secret_bytes(*target_root),
        &stable_context,
    )
    .map_err(|error| invalid_target_preface(format!("Deriver B contribution failed: {error}")))
}

fn validate_target_preface_inputs(
    context: &CloudflareEd25519YaoTenantRootContextV2,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    role_binding: &TenantRootOnlineRoleShareBindingV1,
    share_wire: &SigningRootShareWire,
    role: TwoPartyDeriverRole,
) -> RouterAbProtocolResult<Ed25519YaoStableKeyDerivationContextV1> {
    context.validate_for_pair(pair_binding)?;
    let receipt_bytes = context.custody_binding.activation_receipt_bytes()?;
    let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes)
        .map_err(|error| {
            invalid_target_preface(format!("activation receipt is invalid: {error}"))
        })?;
    let (identity, lineage, epoch, commitment) = active_receipt_role_binding(&receipt, role);
    if role_binding.role() != role
        || role_binding.identity_digest() != identity
        || role_binding.custody_lineage() != lineage
        || role_binding.epoch() != epoch
        || role_binding.share_commitment() != commitment
    {
        return Err(invalid_target_preface(
            "role share does not match the authenticated active receipt",
        ));
    }
    let share = share_wire.to_share().map_err(map_threshold_preface_error)?;
    if SigningRootShareCommitment::from_share(&share)
        .to_bytes()
        .as_ref()
        != role_binding.share_commitment().as_bytes()
    {
        return Err(invalid_target_preface(
            "role share wire does not match its authenticated commitment",
        ));
    }
    stable_key_derivation_context_v1(&context.application, context.participant_ids)
        .map_err(|error| invalid_target_preface(format!("stable context is invalid: {error}")))
}

fn active_receipt_role_binding(
    receipt: &TenantRootSignedActivationReceiptV1,
    role: TwoPartyDeriverRole,
) -> (
    router_ab_core::TenantRootIdentityDigestV1,
    router_ab_core::TenantRootCustodyLineageId,
    router_ab_core::TenantRootShareEpoch,
    &router_ab_core::MpcPrfShareCommitmentWireV1,
) {
    let binding = receipt.binding();
    match binding {
        TenantRootActivationReceiptBindingV1::InitialCreation(value) => {
            let commitment = match role {
                TwoPartyDeriverRole::DeriverA => value.commitments().deriver_a(),
                TwoPartyDeriverRole::DeriverB => value.commitments().deriver_b(),
            };
            (
                binding.identity_digest(),
                binding.custody_lineage(),
                value.epoch(),
                commitment,
            )
        }
        TenantRootActivationReceiptBindingV1::RefreshSwap(value) => {
            let commitment = match role {
                TwoPartyDeriverRole::DeriverA => value.next_commitments().deriver_a(),
                TwoPartyDeriverRole::DeriverB => value.next_commitments().deriver_b(),
            };
            (
                binding.identity_digest(),
                binding.custody_lineage(),
                value.next_epoch(),
                commitment,
            )
        }
    }
}

fn target_peer_commitment(
    context: &CloudflareEd25519YaoTenantRootContextV2,
    role: TwoPartyDeriverRole,
) -> RouterAbProtocolResult<SigningRootShareCommitment> {
    let receipt_bytes = context.custody_binding.activation_receipt_bytes()?;
    let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes)
        .map_err(|error| {
            invalid_target_preface(format!("activation receipt is invalid: {error}"))
        })?;
    let (_, _, _, commitment) = active_receipt_role_binding(&receipt, role);
    SigningRootShareCommitment::from_slice(commitment.as_bytes())
        .map_err(map_threshold_preface_error)
}

fn map_threshold_preface_error(error: threshold_prf::ThresholdPrfError) -> RouterAbProtocolError {
    invalid_target_preface(format!("Ed25519 Yao target proof failed: {error}"))
}

fn invalid_target_preface(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        message.into(),
    )
}

/// Exact public tenant-root context admitted by Router for both roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoTenantRootContextV2 {
    pub custody_binding: CloudflareTenantRootCustodyBindingWireV1,
    pub outer_binding: Ed25519YaoOuterBindingV2,
    pub application: RouterAbEd25519YaoApplicationBindingFactsV1,
    pub participant_ids: [u16; 2],
}

impl CloudflareEd25519YaoTenantRootContextV2 {
    pub fn validate_for_pair(
        &self,
        pair_binding: &Ed25519YaoInputPairBindingV1,
    ) -> RouterAbProtocolResult<()> {
        self.custody_binding.validate()?;
        self.outer_binding.validate()?;
        pair_binding.validate()?;
        if self.participant_ids[0] == 0
            || self.participant_ids[0] >= self.participant_ids[1]
            || self.outer_binding.pair_session().as_bytes() != &pair_binding.session()
            || self.outer_binding.stable_context_binding()
                != pair_binding.binding().stable_key_context_binding
            || self.application.wallet_id() != pair_binding.binding().lifecycle.account_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Ed25519 Yao tenant-root context does not match the admitted pair",
            ));
        }
        let stable_context =
            stable_key_derivation_context_v1(&self.application, self.participant_ids).map_err(
                |error| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        format!("Ed25519 Yao tenant-root stable context is invalid: {error}"),
                    )
                },
            )?;
        if stable_context.binding_digest()
            != pair_binding
                .binding()
                .stable_key_context_binding
                .into_bytes()
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Ed25519 Yao tenant-root stable context does not match the pair",
            ));
        }
        Ok(())
    }
}

/// Family-specific public context retained by each role for exact input opening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareEd25519YaoPairWorkV1 {
    /// Registration, recovery, or export uses the ceremony binding directly.
    Ceremony,
    /// Lane inputs additionally authenticate the complete admitted job in HPKE AAD.
    Lane { job: Ed25519YaoLaneJobV1 },
}

/// Exact pair and role envelope sent to one private prepare-pair route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPairPrepareRequestV1 {
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    pub tenant_root: CloudflareEd25519YaoTenantRootContextV2,
    pub work: CloudflareEd25519YaoPairWorkV1,
    pub input: Ed25519YaoEncryptedInputV1,
}

/// Exact pair, encrypted A input, and both readiness receipts sent to the A
/// execute-pair route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPairExecuteRequestV1 {
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    pub tenant_root: CloudflareEd25519YaoTenantRootContextV2,
    pub work: CloudflareEd25519YaoPairWorkV1,
    pub input: Ed25519YaoEncryptedInputV1,
    pub local_receipt: Ed25519YaoRoleReadinessReceiptV1,
    pub peer_receipt: Ed25519YaoRoleReadinessReceiptV1,
}

/// A's sealed execution plus B's opaque, already-persisted sealed execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPairExecuteResponseV1 {
    pub deriver_a_execution: Ed25519YaoRoleExecutionV1,
    pub deriver_b_sealed_execution_json: String,
}

/// Pair start confirmation sent after Deriver B accepted the exact execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPairStartRequestV1 {
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    pub execution_id: Ed25519YaoExecutionIdV1,
    pub acceptance: Ed25519YaoRoleStartAcceptanceV1,
}

/// Exact pair lookup sent to a role status or burn route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPairLookupRequestV1 {
    pub session: [u8; 32],
    pub pair_digest: [u8; 32],
}

/// Sanitized role-local state returned only to the MPC Router for exact replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareEd25519YaoPairStatusResponseV1 {
    Missing {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Prepared {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Running {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Completed {
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    Burned {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Expired {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
}

/// Sanitized role failure returned by a private pair route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareEd25519YaoRoleFailureResponseV1 {
    RecoverableFailure {
        code: RouterEd25519YaoExecuteFailureCodeV1,
        retry_after_ms: u64,
    },
    Rejected {
        code: RouterEd25519YaoExecuteFailureCodeV1,
    },
    Burned {
        reason: RouterEd25519YaoBurnReasonV1,
    },
}

impl CloudflareEd25519YaoRoleFailureResponseV1 {
    /// Converts a role-local protocol error into a sanitized result class.
    pub fn from_protocol_error(
        error: &RouterAbProtocolError,
    ) -> CloudflareEd25519YaoRoleFailureResponseV1 {
        if matches!(
            error.code(),
            RouterAbProtocolErrorCode::ExpiredLocalRequest
                | RouterAbProtocolErrorCode::PairPreparationExpired
        ) {
            return Self::RecoverableFailure {
                code: RouterEd25519YaoExecuteFailureCodeV1::CeremonyExpired,
                retry_after_ms: 1_000,
            };
        }
        if error.code() == RouterAbProtocolErrorCode::ConflictingPair {
            return Self::Rejected {
                code: RouterEd25519YaoExecuteFailureCodeV1::ConflictingPair,
            };
        }
        if error.code() == RouterAbProtocolErrorCode::MissingPairPreparation {
            return Self::Rejected {
                code: RouterEd25519YaoExecuteFailureCodeV1::MissingPreparation,
            };
        }
        if matches!(
            error.code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
                | RouterAbProtocolErrorCode::MissingLocalBinding
                | RouterAbProtocolErrorCode::ForbiddenLocalBinding
        ) {
            return Self::RecoverableFailure {
                code: RouterEd25519YaoExecuteFailureCodeV1::ServiceUnavailable,
                retry_after_ms: 1_000,
            };
        }
        Self::Rejected {
            code: RouterEd25519YaoExecuteFailureCodeV1::TerminalRoleFailure,
        }
    }
}
