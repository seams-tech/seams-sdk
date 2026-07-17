use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoRefreshBindingV1,
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
    build_export_deriver_b, stable_key_derivation_context_v1, ActivationDeriverA,
    ActivationDeriverAContribution, ActivationDeriverB, ActivationDeriverBContribution,
    AdapterError, ExportDeriverA, ExportDeriverAContribution, ExportDeriverB,
    ExportDeriverBContribution, LocalEd25519YaoActivationDeriverARequestV1,
    LocalEd25519YaoActivationDeriverBRequestV1, LocalEd25519YaoClientContributionV1,
    LocalEd25519YaoExportDeriverARequestV1, LocalEd25519YaoExportDeriverBRequestV1,
    LocalEd25519YaoRefreshDeriverARequestV1, LocalEd25519YaoRefreshDeriverBRequestV1,
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
