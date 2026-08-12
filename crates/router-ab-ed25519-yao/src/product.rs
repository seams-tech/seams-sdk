use base64ct::{Base64UrlUnpadded, Encoding};
use curve25519_dalek::scalar::Scalar;
use rand_core_09::{CryptoRng, RngCore};
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoLaneJobV1, Ed25519YaoRefreshBindingV1,
    RouterAbEd25519YaoApplicationBindingFactsV1,
};
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_deriver_a_server_contribution_v1,
    derive_ed25519_yao_deriver_b_server_contribution_v1, Ed25519YaoDeriverAClientContributionV1,
    Ed25519YaoDeriverADerivationRootV1, Ed25519YaoDeriverAServerContributionV1,
    Ed25519YaoDeriverBClientContributionV1, Ed25519YaoDeriverBDerivationRootV1,
    Ed25519YaoDeriverBServerContributionV1, Ed25519YaoStableKeyDerivationContextV1,
};

use crate::{
    build_activation_deriver_a, build_activation_deriver_b, build_export_deriver_a,
    build_export_deriver_b, build_lane_materialization_deriver_a,
    build_lane_materialization_deriver_b, stable_key_derivation_context_v1, ActivationDeriverA,
    ActivationDeriverAContribution, ActivationDeriverB, ActivationDeriverBContribution,
    AdapterError, Ed25519YaoLaneDeriverAContributionV1, Ed25519YaoLaneDeriverBContributionV1,
    ExportDeriverA, ExportDeriverAContribution, ExportDeriverB, ExportDeriverBContribution,
    LaneMaterializationDeriverA, LaneMaterializationDeriverB,
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoClientContributionV1, LocalEd25519YaoExportDeriverARequestV1,
    LocalEd25519YaoExportDeriverBRequestV1, LocalEd25519YaoLaneDeriverARequestV1,
    LocalEd25519YaoLaneDeriverBRequestV1, LocalEd25519YaoRefreshDeriverARequestV1,
    LocalEd25519YaoRefreshDeriverBRequestV1,
};

/// Derives Deriver A's deterministic role-local server contribution.
pub fn derive_ed25519_yao_deriver_a_server_contribution_from_root_v1(
    root: [u8; 32],
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> Result<Ed25519YaoDeriverAServerContributionV1, AdapterError> {
    let context = product_context(application, participant_ids)?;
    derive_ed25519_yao_deriver_a_server_contribution_v1(
        &Ed25519YaoDeriverADerivationRootV1::from_secret_bytes(root),
        &context,
    )
    .map_err(|_| AdapterError::ServerContributionDerivation)
}

/// Derives Deriver B's deterministic role-local server contribution.
pub fn derive_ed25519_yao_deriver_b_server_contribution_from_root_v1(
    root: [u8; 32],
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> Result<Ed25519YaoDeriverBServerContributionV1, AdapterError> {
    let context = product_context(application, participant_ids)?;
    derive_ed25519_yao_deriver_b_server_contribution_v1(
        &Ed25519YaoDeriverBDerivationRootV1::from_secret_bytes(root),
        &context,
    )
    .map_err(|_| AdapterError::ServerContributionDerivation)
}

/// Builds one fixed activation Deriver A role from the A-only root and request.
pub fn build_product_activation_deriver_a_v1(
    root: [u8; 32],
    request: LocalEd25519YaoActivationDeriverARequestV1,
) -> Result<(Ed25519YaoCeremonyBindingV1, ActivationDeriverA), AdapterError> {
    let server = derive_ed25519_yao_deriver_a_server_contribution_from_root_v1(
        root,
        &request.application_binding,
        request.participant_ids,
    )?;
    build_product_activation_deriver_a_with_server_v1(request, server)
}

/// Builds one fixed activation Deriver B role from the B-only root and request.
pub fn build_product_activation_deriver_b_v1(
    root: [u8; 32],
    request: LocalEd25519YaoActivationDeriverBRequestV1,
) -> Result<(Ed25519YaoCeremonyBindingV1, ActivationDeriverB), AdapterError> {
    let server = derive_ed25519_yao_deriver_b_server_contribution_from_root_v1(
        root,
        &request.application_binding,
        request.participant_ids,
    )?;
    build_product_activation_deriver_b_with_server_v1(request, server)
}

/// Builds one fixed export Deriver A role from the A-only root and request.
pub fn build_product_export_deriver_a_v1(
    root: [u8; 32],
    request: LocalEd25519YaoExportDeriverARequestV1,
) -> Result<(Ed25519YaoCeremonyBindingV1, ExportDeriverA), AdapterError> {
    let server = derive_ed25519_yao_deriver_a_server_contribution_from_root_v1(
        root,
        &request.application_binding,
        request.participant_ids,
    )?;
    build_product_export_deriver_a_with_server_v1(request, server)
}

/// Builds one fixed export Deriver B role from the B-only root and request.
pub fn build_product_export_deriver_b_v1(
    root: [u8; 32],
    request: LocalEd25519YaoExportDeriverBRequestV1,
) -> Result<(Ed25519YaoCeremonyBindingV1, ExportDeriverB), AdapterError> {
    let server = derive_ed25519_yao_deriver_b_server_contribution_from_root_v1(
        root,
        &request.application_binding,
        request.participant_ids,
    )?;
    build_product_export_deriver_b_with_server_v1(request, server)
}

/// Builds the selected lane-materialization Deriver A from A-only stable roots.
pub fn build_product_lane_deriver_a_v1<R>(
    root: [u8; 32],
    request: LocalEd25519YaoLaneDeriverARequestV1,
    rng: &mut R,
) -> Result<
    (
        Ed25519YaoCeremonyBindingV1,
        Ed25519YaoLaneJobV1,
        LaneMaterializationDeriverA,
    ),
    AdapterError,
>
where
    R: CryptoRng + RngCore,
{
    let server = derive_ed25519_yao_deriver_a_server_contribution_from_root_v1(
        root,
        &request.application_binding,
        request.participant_ids,
    )?;
    let recipients = request.recipients;
    let job = request.job;
    let (binding, _context, client) = validate_a_request(
        request.binding,
        request.application_binding,
        request.participant_ids,
        request.client_contribution,
    )?;
    validate_lane_product_binding(&binding, &job, &recipients)?;
    let (client_y, _client_tau) = client.into_parts();
    let (server_y, _server_tau) = server.into_parts();
    let role = build_lane_materialization_deriver_a(
        &job,
        Ed25519YaoLaneDeriverAContributionV1 {
            source_holder_share: canonical_lane_y_share_v1(client_y.into_bytes()),
            source_signing_worker_share: canonical_lane_y_share_v1(server_y.into_bytes()),
            offset_share: random_scalar_v1(rng),
        },
    )
    .map_err(|_| AdapterError::RoleProtocol)?;
    Ok((binding, job, role))
}

/// Builds the selected lane-materialization Deriver B from B-only stable roots.
pub fn build_product_lane_deriver_b_v1<R>(
    root: [u8; 32],
    request: LocalEd25519YaoLaneDeriverBRequestV1,
    rng: &mut R,
) -> Result<
    (
        Ed25519YaoCeremonyBindingV1,
        Ed25519YaoLaneJobV1,
        LaneMaterializationDeriverB,
    ),
    AdapterError,
>
where
    R: CryptoRng + RngCore,
{
    let server = derive_ed25519_yao_deriver_b_server_contribution_from_root_v1(
        root,
        &request.application_binding,
        request.participant_ids,
    )?;
    let recipients = request.recipients;
    let job = request.job;
    let (binding, _context, client) = validate_b_request(
        request.binding,
        request.application_binding,
        request.participant_ids,
        request.client_contribution,
    )?;
    validate_lane_product_binding(&binding, &job, &recipients)?;
    let (client_y, _client_tau) = client.into_parts();
    let (server_y, _server_tau) = server.into_parts();
    let role = build_lane_materialization_deriver_b(
        &job,
        Ed25519YaoLaneDeriverBContributionV1 {
            source_holder_share: canonical_lane_y_share_v1(client_y.into_bytes()),
            source_signing_worker_share: canonical_lane_y_share_v1(server_y.into_bytes()),
            offset_share: random_scalar_v1(rng),
        },
    )
    .map_err(|_| AdapterError::RoleProtocol)?;
    Ok((binding, job, role))
}

fn validate_lane_product_binding(
    binding: &Ed25519YaoCeremonyBindingV1,
    job: &Ed25519YaoLaneJobV1,
    recipients: &crate::LocalEd25519YaoLaneRecipientsV1,
) -> Result<(), AdapterError> {
    job.validate()
        .map_err(|_| AdapterError::InvalidDerivationContext)?;
    if binding.operation != job.yao_request_kind.operation()
        || binding.session_id.into_bytes()
            != job
                .session_v1()
                .map_err(|_| AdapterError::InvalidDerivationContext)?
        || binding.stable_key_context_binding.into_bytes()
            != job
                .stable_context_binding_v1()
                .map_err(|_| AdapterError::InvalidDerivationContext)?
        || binding.material_activation() != job.source.material_activation()
        || recipients.holder_public_key
            != decode_lane_recipient_key_v1(&job.target_holder.hpke_public_key_b64u)?
        || recipients.signing_worker_public_key
            != decode_lane_recipient_key_v1(&job.target_signing_worker.hpke_public_key_b64u)?
    {
        return Err(AdapterError::InvalidDerivationContext);
    }
    Ok(())
}

fn decode_lane_recipient_key_v1(encoded: &str) -> Result<[u8; 32], AdapterError> {
    let mut decoded = [0_u8; 32];
    Base64UrlUnpadded::decode(encoded, &mut decoded)
        .map_err(|_| AdapterError::InvalidDerivationContext)?;
    Ok(decoded)
}

fn random_scalar_v1<R>(rng: &mut R) -> [u8; 32]
where
    R: CryptoRng + RngCore,
{
    let mut wide = [0_u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide).to_bytes()
}

/// Lane role inputs require canonical scalar encodings; Yao y contributions
/// remain raw HKDF bytes until they cross this boundary.
fn canonical_lane_y_share_v1(raw: [u8; 32]) -> [u8; 32] {
    Scalar::from_bytes_mod_order(raw).to_bytes()
}

/// Builds one activation Deriver A role from already selected effective state.
pub fn build_product_activation_deriver_a_with_server_v1(
    request: LocalEd25519YaoActivationDeriverARequestV1,
    server: Ed25519YaoDeriverAServerContributionV1,
) -> Result<(Ed25519YaoCeremonyBindingV1, ActivationDeriverA), AdapterError> {
    let (binding, context, client) = validate_a_request(
        request.binding,
        request.application_binding,
        request.participant_ids,
        request.client_contribution,
    )?;
    let role = build_activation_deriver_a(
        &binding,
        ActivationDeriverAContribution::base(&context, client, server),
    )?;
    Ok((binding, role))
}

/// Builds one activation Deriver B role from already selected effective state.
pub fn build_product_activation_deriver_b_with_server_v1(
    request: LocalEd25519YaoActivationDeriverBRequestV1,
    server: Ed25519YaoDeriverBServerContributionV1,
) -> Result<(Ed25519YaoCeremonyBindingV1, ActivationDeriverB), AdapterError> {
    let (binding, context, client) = validate_b_request(
        request.binding,
        request.application_binding,
        request.participant_ids,
        request.client_contribution,
    )?;
    let role = build_activation_deriver_b(
        &binding,
        ActivationDeriverBContribution::base(&context, client, server),
    )?;
    Ok((binding, role))
}

/// Builds one export Deriver A role from already selected effective state.
pub fn build_product_export_deriver_a_with_server_v1(
    request: LocalEd25519YaoExportDeriverARequestV1,
    server: Ed25519YaoDeriverAServerContributionV1,
) -> Result<(Ed25519YaoCeremonyBindingV1, ExportDeriverA), AdapterError> {
    let (binding, context, client) = validate_a_request(
        request.binding,
        request.application_binding,
        request.participant_ids,
        request.client_contribution,
    )?;
    let role = build_export_deriver_a(
        &binding,
        ExportDeriverAContribution::from_derived(&context, client, server),
    )?;
    Ok((binding, role))
}

/// Builds one export Deriver B role from already selected effective state.
pub fn build_product_export_deriver_b_with_server_v1(
    request: LocalEd25519YaoExportDeriverBRequestV1,
    server: Ed25519YaoDeriverBServerContributionV1,
) -> Result<(Ed25519YaoCeremonyBindingV1, ExportDeriverB), AdapterError> {
    let (binding, context, client) = validate_b_request(
        request.binding,
        request.application_binding,
        request.participant_ids,
        request.client_contribution,
    )?;
    let role = build_export_deriver_b(
        &binding,
        ExportDeriverBContribution::from_derived(&context, client, server),
    )?;
    Ok((binding, role))
}

/// Builds one refresh activation Deriver A role from prepared effective state.
pub fn build_product_refresh_deriver_a_with_server_v1(
    request: LocalEd25519YaoRefreshDeriverARequestV1,
    server: Ed25519YaoDeriverAServerContributionV1,
) -> Result<(Ed25519YaoRefreshBindingV1, ActivationDeriverA), AdapterError> {
    let LocalEd25519YaoRefreshDeriverARequestV1 {
        binding,
        application_binding,
        participant_ids,
        client_contribution,
        recipients: _,
    } = request;
    let (ceremony, context, client) = validate_a_request(
        binding.ceremony().clone(),
        application_binding,
        participant_ids,
        client_contribution,
    )?;
    let role = build_activation_deriver_a(
        &ceremony,
        ActivationDeriverAContribution::refresh(&context, client, server),
    )?;
    Ok((binding, role))
}

/// Builds one refresh activation Deriver B role from prepared effective state.
pub fn build_product_refresh_deriver_b_with_server_v1(
    request: LocalEd25519YaoRefreshDeriverBRequestV1,
    server: Ed25519YaoDeriverBServerContributionV1,
) -> Result<(Ed25519YaoRefreshBindingV1, ActivationDeriverB), AdapterError> {
    let LocalEd25519YaoRefreshDeriverBRequestV1 {
        binding,
        application_binding,
        participant_ids,
        client_contribution,
        recipients: _,
    } = request;
    let (ceremony, context, client) = validate_b_request(
        binding.ceremony().clone(),
        application_binding,
        participant_ids,
        client_contribution,
    )?;
    let role = build_activation_deriver_b(
        &ceremony,
        ActivationDeriverBContribution::refresh(&context, client, server),
    )?;
    Ok((binding, role))
}

fn validate_a_request(
    binding: Ed25519YaoCeremonyBindingV1,
    application: RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    mut contribution: LocalEd25519YaoClientContributionV1,
) -> Result<
    (
        Ed25519YaoCeremonyBindingV1,
        Ed25519YaoStableKeyDerivationContextV1,
        Ed25519YaoDeriverAClientContributionV1,
    ),
    AdapterError,
> {
    let context = validate_common_request(&binding, &application, participant_ids)?;
    let client = Ed25519YaoDeriverAClientContributionV1::from_secret_bytes(
        core::mem::take(&mut contribution.y),
        core::mem::take(&mut contribution.tau),
    );
    Ok((binding, context, client))
}

fn validate_b_request(
    binding: Ed25519YaoCeremonyBindingV1,
    application: RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    mut contribution: LocalEd25519YaoClientContributionV1,
) -> Result<
    (
        Ed25519YaoCeremonyBindingV1,
        Ed25519YaoStableKeyDerivationContextV1,
        Ed25519YaoDeriverBClientContributionV1,
    ),
    AdapterError,
> {
    let context = validate_common_request(&binding, &application, participant_ids)?;
    let client = Ed25519YaoDeriverBClientContributionV1::from_secret_bytes(
        core::mem::take(&mut contribution.y),
        core::mem::take(&mut contribution.tau),
    );
    Ok((binding, context, client))
}

fn validate_common_request(
    binding: &Ed25519YaoCeremonyBindingV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> Result<Ed25519YaoStableKeyDerivationContextV1, AdapterError> {
    binding
        .validate()
        .map_err(|_| AdapterError::InvalidDerivationContext)?;
    let context = product_context(application, participant_ids)?;
    if context.binding_digest() != binding.stable_key_context_binding.into_bytes() {
        return Err(AdapterError::InvalidDerivationContext);
    }
    Ok(context)
}

fn product_context(
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> Result<Ed25519YaoStableKeyDerivationContextV1, AdapterError> {
    stable_key_derivation_context_v1(application, participant_ids)
}

#[cfg(test)]
mod tests {
    use super::canonical_lane_y_share_v1;
    use crate::{YaoLaneDeriverAInputs, YaoLaneDeriverBInputs};
    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn lane_materialization_reduces_raw_y_before_role_inputs() {
        let raw = [0xff_u8; 32];
        let offset = Scalar::ONE.to_bytes();

        assert!(YaoLaneDeriverAInputs::new(raw, raw, offset).is_err());
        assert!(YaoLaneDeriverBInputs::new(raw, raw, offset).is_err());

        let canonical = canonical_lane_y_share_v1(raw);
        assert_eq!(canonical, Scalar::from_bytes_mod_order(raw).to_bytes());
        assert!(YaoLaneDeriverAInputs::new(canonical, canonical, offset).is_ok());
        assert!(YaoLaneDeriverBInputs::new(canonical, canonical, offset).is_ok());
    }
}
