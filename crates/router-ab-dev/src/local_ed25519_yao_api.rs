use super::{LocalDeriverAWorkerConfigV1, LocalDeriverBWorkerConfigV1};
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoRefreshBindingV1,
    RouterAbEd25519YaoApplicationBindingFactsV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult,
};
use router_ab_ed25519_yao::{
    build_activation_deriver_a, build_activation_deriver_b, build_export_deriver_a,
    build_export_deriver_b, stable_key_derivation_context_v1, ActivationDeriverA,
    ActivationDeriverAContribution, ActivationDeriverB, ActivationDeriverBContribution,
    ExportDeriverA, ExportDeriverAContribution, ExportDeriverB, ExportDeriverBContribution,
};
pub use router_ab_ed25519_yao::{
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoActivationRecipientsV1, LocalEd25519YaoClientContributionV1,
    LocalEd25519YaoExportDeriverARequestV1, LocalEd25519YaoExportDeriverBRequestV1,
    LocalEd25519YaoExportRecipientV1, LocalEd25519YaoRefreshDeriverARequestV1,
    LocalEd25519YaoRefreshDeriverBRequestV1,
};
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_deriver_a_server_contribution_v1,
    derive_ed25519_yao_deriver_b_server_contribution_v1, Ed25519YaoDeriverAClientContributionV1,
    Ed25519YaoDeriverADerivationRootV1, Ed25519YaoDeriverAServerContributionV1,
    Ed25519YaoDeriverBClientContributionV1, Ed25519YaoDeriverBDerivationRootV1,
    Ed25519YaoDeriverBServerContributionV1, Ed25519YaoStableKeyDerivationContextV1,
};

pub fn derive_local_ed25519_yao_deriver_a_initial_contribution_v1(
    config: &LocalDeriverAWorkerConfigV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> RouterAbProtocolResult<Ed25519YaoDeriverAServerContributionV1> {
    let context = stable_context(&application, participant_ids)?;
    let root = Ed25519YaoDeriverADerivationRootV1::from_secret_bytes(decode_root(
        &config.ed25519_yao_derivation_root_hex,
    )?);
    derive_ed25519_yao_deriver_a_server_contribution_v1(&root, &context)
        .map_err(map_signer_core_error)
}

pub fn derive_local_ed25519_yao_deriver_b_initial_contribution_v1(
    config: &LocalDeriverBWorkerConfigV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> RouterAbProtocolResult<Ed25519YaoDeriverBServerContributionV1> {
    let context = stable_context(&application, participant_ids)?;
    let root = Ed25519YaoDeriverBDerivationRootV1::from_secret_bytes(decode_root(
        &config.ed25519_yao_derivation_root_hex,
    )?);
    derive_ed25519_yao_deriver_b_server_contribution_v1(&root, &context)
        .map_err(map_signer_core_error)
}

macro_rules! build_local_role {
    ($function:ident, $with_server:ident, $config:ty, $request:ty, $root:ty, $client:ty, $server:ty, $derive:ident, $build:ident, $contribution:ident, $constructor:ident, $role:ty, $validate:ident) => {
        pub fn $function(
            config: &$config,
            request: $request,
        ) -> RouterAbProtocolResult<(Ed25519YaoCeremonyBindingV1, $role)> {
            let context = stable_context(&request.application_binding, request.participant_ids)?;
            let root =
                <$root>::from_secret_bytes(decode_root(&config.ed25519_yao_derivation_root_hex)?);
            let server = $derive(&root, &context).map_err(map_signer_core_error)?;
            $with_server(request, server)
        }

        pub fn $with_server(
            request: $request,
            server: $server,
        ) -> RouterAbProtocolResult<(Ed25519YaoCeremonyBindingV1, $role)> {
            let (binding, context, client) = $validate(
                request.binding,
                request.application_binding,
                request.participant_ids,
                request.client_contribution,
            )?;
            let role = $build(
                &binding,
                $contribution::$constructor(&context, client, server),
            )
            .map_err(map_adapter_error)?;
            Ok((binding, role))
        }
    };
}

build_local_role!(
    build_local_activation_deriver_a_v1,
    build_local_activation_deriver_a_with_server_v1,
    LocalDeriverAWorkerConfigV1,
    LocalEd25519YaoActivationDeriverARequestV1,
    Ed25519YaoDeriverADerivationRootV1,
    Ed25519YaoDeriverAClientContributionV1,
    Ed25519YaoDeriverAServerContributionV1,
    derive_ed25519_yao_deriver_a_server_contribution_v1,
    build_activation_deriver_a,
    ActivationDeriverAContribution,
    base,
    ActivationDeriverA,
    validate_a_request
);

pub fn build_local_refresh_deriver_a_v1(
    request: LocalEd25519YaoRefreshDeriverARequestV1,
    server: Ed25519YaoDeriverAServerContributionV1,
) -> RouterAbProtocolResult<(Ed25519YaoRefreshBindingV1, ActivationDeriverA)> {
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
    )
    .map_err(map_adapter_error)?;
    Ok((binding, role))
}

pub fn build_local_refresh_deriver_b_v1(
    request: LocalEd25519YaoRefreshDeriverBRequestV1,
    server: Ed25519YaoDeriverBServerContributionV1,
) -> RouterAbProtocolResult<(Ed25519YaoRefreshBindingV1, ActivationDeriverB)> {
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
    )
    .map_err(map_adapter_error)?;
    Ok((binding, role))
}
build_local_role!(
    build_local_activation_deriver_b_v1,
    build_local_activation_deriver_b_with_server_v1,
    LocalDeriverBWorkerConfigV1,
    LocalEd25519YaoActivationDeriverBRequestV1,
    Ed25519YaoDeriverBDerivationRootV1,
    Ed25519YaoDeriverBClientContributionV1,
    Ed25519YaoDeriverBServerContributionV1,
    derive_ed25519_yao_deriver_b_server_contribution_v1,
    build_activation_deriver_b,
    ActivationDeriverBContribution,
    base,
    ActivationDeriverB,
    validate_b_request
);
build_local_role!(
    build_local_export_deriver_a_v1,
    build_local_export_deriver_a_with_server_v1,
    LocalDeriverAWorkerConfigV1,
    LocalEd25519YaoExportDeriverARequestV1,
    Ed25519YaoDeriverADerivationRootV1,
    Ed25519YaoDeriverAClientContributionV1,
    Ed25519YaoDeriverAServerContributionV1,
    derive_ed25519_yao_deriver_a_server_contribution_v1,
    build_export_deriver_a,
    ExportDeriverAContribution,
    from_derived,
    ExportDeriverA,
    validate_a_request
);
build_local_role!(
    build_local_export_deriver_b_v1,
    build_local_export_deriver_b_with_server_v1,
    LocalDeriverBWorkerConfigV1,
    LocalEd25519YaoExportDeriverBRequestV1,
    Ed25519YaoDeriverBDerivationRootV1,
    Ed25519YaoDeriverBClientContributionV1,
    Ed25519YaoDeriverBServerContributionV1,
    derive_ed25519_yao_deriver_b_server_contribution_v1,
    build_export_deriver_b,
    ExportDeriverBContribution,
    from_derived,
    ExportDeriverB,
    validate_b_request
);

fn validate_a_request(
    binding: Ed25519YaoCeremonyBindingV1,
    application: RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    mut contribution: LocalEd25519YaoClientContributionV1,
) -> RouterAbProtocolResult<(
    Ed25519YaoCeremonyBindingV1,
    Ed25519YaoStableKeyDerivationContextV1,
    Ed25519YaoDeriverAClientContributionV1,
)> {
    let context = validate_common_request(&binding, application, participant_ids)?;
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
) -> RouterAbProtocolResult<(
    Ed25519YaoCeremonyBindingV1,
    Ed25519YaoStableKeyDerivationContextV1,
    Ed25519YaoDeriverBClientContributionV1,
)> {
    let context = validate_common_request(&binding, application, participant_ids)?;
    let client = Ed25519YaoDeriverBClientContributionV1::from_secret_bytes(
        core::mem::take(&mut contribution.y),
        core::mem::take(&mut contribution.tau),
    );
    Ok((binding, context, client))
}

fn validate_common_request(
    binding: &Ed25519YaoCeremonyBindingV1,
    application: RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> RouterAbProtocolResult<Ed25519YaoStableKeyDerivationContextV1> {
    binding.validate()?;
    let context = stable_context(&application, participant_ids)?;
    if context.binding_digest() != binding.stable_key_context_binding.into_bytes() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local Ed25519 Yao stable context does not match Router admission",
        ));
    }
    Ok(context)
}

pub(crate) fn stable_context(
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> RouterAbProtocolResult<Ed25519YaoStableKeyDerivationContextV1> {
    stable_key_derivation_context_v1(application, participant_ids).map_err(map_adapter_error)
}

fn decode_root(value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    hex::decode(value)
        .map_err(|_| invalid_local_input("invalid Yao derivation root"))?
        .try_into()
        .map_err(|_| invalid_local_input("invalid Yao derivation root length"))
}

fn map_signer_core_error(error: signer_core::error::SignerCoreError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
        format!("local Ed25519 Yao KDF input failed: {error}"),
    )
}

fn map_adapter_error(error: router_ab_ed25519_yao::AdapterError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        format!("local Ed25519 Yao role construction failed: {error}"),
    )
}

fn invalid_local_input(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        message,
    )
}
