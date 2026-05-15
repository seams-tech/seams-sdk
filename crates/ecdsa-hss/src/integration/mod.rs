use crate::shared::context::EcdsaHssStableKeyContextV1;
use signer_core::error::CoreResult;
use signer_core::secp256k1::{
    add_secp256k1_public_keys_33, map_additive_share_to_threshold_signatures_share_2p,
    secp256k1_private_key_32_to_public_key_33, secp256k1_public_key_33_to_ethereum_address_20,
    THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID, THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
};
use signer_core::threshold_ecdsa::{
    threshold_ecdsa_compute_signature_share, threshold_ecdsa_finalize_signature,
    ThresholdEcdsaPresignEvent, ThresholdEcdsaPresignSession,
};

use crate::client::ClientOutputV1;
use crate::server::{RespondResponseV1, ServerPrepareInputsV1, StagedServerSessionV1};
use crate::wire::{PrepareEnvelopeV1, RespondRequestV1, ServerEvalOperationV1};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const ECDSA_HSS_EVM_THRESHOLD_V1_PARTICIPANT_IDS: [u32; 2] = [
    THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
    THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmThresholdIdentityV1 {
    pub participant_ids: [u32; 2],
    pub client_verifying_share33: [u8; 33],
    pub relayer_verifying_share33: [u8; 33],
    pub group_public_key33: [u8; 33],
    pub ethereum_address20: [u8; 20],
    pub retry_counter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdPartyBootstrapMaterialV1 {
    #[zeroize(skip)]
    pub participant_ids: [u32; 2],
    pub participant_id: u32,
    pub additive_share32: [u8; 32],
    pub threshold_private_share32: [u8; 32],
    pub group_public_key33: [u8; 33],
    pub ethereum_address20: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdBootstrapAdapterV1 {
    #[zeroize(skip)]
    pub identity: EvmThresholdIdentityV1,
    pub client: EvmThresholdPartyBootstrapMaterialV1,
    pub relayer: EvmThresholdPartyBootstrapMaterialV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdBootstrapRequestV1 {
    #[zeroize(skip)]
    pub operation: ServerEvalOperationV1,
    #[zeroize(skip)]
    pub context: EcdsaHssStableKeyContextV1,
    pub y_client32_le: [u8; 32],
    pub y_relayer32_le: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdBootstrapResultV1 {
    pub response: RespondResponseV1,
    pub adapter: EvmThresholdBootstrapAdapterV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmThresholdSigningOperationV1 {
    RegistrationBootstrap,
    SessionBootstrap,
    NonExportSign,
}

impl EvmThresholdSigningOperationV1 {
    fn to_server_operation(self) -> ServerEvalOperationV1 {
        match self {
            EvmThresholdSigningOperationV1::RegistrationBootstrap => {
                ServerEvalOperationV1::RegistrationBootstrap
            }
            EvmThresholdSigningOperationV1::SessionBootstrap => {
                ServerEvalOperationV1::SessionBootstrap
            }
            EvmThresholdSigningOperationV1::NonExportSign => ServerEvalOperationV1::NonExportSign,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdExportRequestV1 {
    #[zeroize(skip)]
    pub context: EcdsaHssStableKeyContextV1,
    pub y_client32_le: [u8; 32],
    pub y_relayer32_le: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdExplicitExportV1 {
    pub canonical_x32: [u8; 32],
    pub canonical_public_key33: [u8; 33],
    pub canonical_ethereum_address20: [u8; 20],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub retry_counter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdExportResultV1 {
    pub bootstrap: EvmThresholdBootstrapResultV1,
    pub exported: EvmThresholdExplicitExportV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdSigningSessionV1 {
    #[zeroize(skip)]
    pub operation: EvmThresholdSigningOperationV1,
    pub bootstrap: EvmThresholdBootstrapResultV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdExplicitExportSessionV1 {
    pub export: EvmThresholdExportResultV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdPresignatureV1 {
    pub big_r33: [u8; 33],
    pub k_share32: [u8; 32],
    pub sigma_share32: [u8; 32],
}

impl EvmThresholdBootstrapAdapterV1 {
    pub fn from_respond_response(response: &RespondResponseV1) -> CoreResult<Self> {
        validate_threshold_response_cryptographic_consistency(response)?;

        let (x_client32, client_verifying_share33) = match &response.client_output {
            ClientOutputV1::NonExport(output) => (output.x_client32, output.client_public_key33),
            ClientOutputV1::ExplicitExport(output) => {
                (output.x_client32, output.client_public_key33)
            }
        };

        let relayer_threshold_share32 = map_share(
            &response
                .finalized_server_session
                .retained
                .relayer_threshold_share32,
            THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
        )?;
        let client_threshold_share32 =
            map_share(&x_client32, THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID)?;

        let identity = EvmThresholdIdentityV1 {
            participant_ids: ECDSA_HSS_EVM_THRESHOLD_V1_PARTICIPANT_IDS,
            client_verifying_share33,
            relayer_verifying_share33: response
                .finalized_server_session
                .retained
                .relayer_public_key33,
            group_public_key33: response
                .finalized_server_session
                .retained
                .threshold_public_key33,
            ethereum_address20: response
                .finalized_server_session
                .retained
                .threshold_ethereum_address20,
            retry_counter: response.finalized_server_session.retained.retry_counter,
        };

        let client = EvmThresholdPartyBootstrapMaterialV1 {
            participant_ids: identity.participant_ids,
            participant_id: THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
            additive_share32: x_client32,
            threshold_private_share32: client_threshold_share32,
            group_public_key33: identity.group_public_key33,
            ethereum_address20: identity.ethereum_address20,
        };
        let relayer = EvmThresholdPartyBootstrapMaterialV1 {
            participant_ids: identity.participant_ids,
            participant_id: THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
            additive_share32: response
                .finalized_server_session
                .retained
                .relayer_threshold_share32,
            threshold_private_share32: relayer_threshold_share32,
            group_public_key33: identity.group_public_key33,
            ethereum_address20: identity.ethereum_address20,
        };

        Ok(Self {
            identity,
            client,
            relayer,
        })
    }
}

pub fn export_from_respond_response_v1(
    response: &RespondResponseV1,
) -> CoreResult<EvmThresholdExplicitExportV1> {
    validate_threshold_response_cryptographic_consistency(response)?;
    extract_explicit_export_v1(response)
}

fn extract_explicit_export_v1(
    response: &RespondResponseV1,
) -> CoreResult<EvmThresholdExplicitExportV1> {
    if response.finalized_server_session.operation != ServerEvalOperationV1::ExplicitKeyExport {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "canonical export requires ExplicitKeyExport operation",
        ));
    }

    let ClientOutputV1::ExplicitExport(output) = &response.client_output else {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "canonical export requires explicit-export client output",
        ));
    };

    if output.canonical_public_key33
        != response
            .finalized_server_session
            .retained
            .threshold_public_key33
    {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "exported canonical public key does not match threshold public key",
        ));
    }
    if output.canonical_ethereum_address20
        != response
            .finalized_server_session
            .retained
            .threshold_ethereum_address20
    {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "exported canonical ethereum address does not match threshold ethereum address",
        ));
    }

    Ok(EvmThresholdExplicitExportV1 {
        canonical_x32: output.canonical_x32,
        canonical_public_key33: output.canonical_public_key33,
        canonical_ethereum_address20: output.canonical_ethereum_address20,
        threshold_public_key33: output.threshold_public_key33,
        threshold_ethereum_address20: output.threshold_ethereum_address20,
        retry_counter: output.retry_counter,
    })
}

pub fn bootstrap_evm_threshold_v1(
    request: EvmThresholdBootstrapRequestV1,
) -> CoreResult<EvmThresholdBootstrapResultV1> {
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: request.operation,
            context: request.context.clone(),
        },
        y_relayer32_le: request.y_relayer32_le,
    })?;
    let response = staged.respond(&RespondRequestV1 {
        y_client32_le: request.y_client32_le,
    })?;
    let adapter = EvmThresholdBootstrapAdapterV1::from_respond_response(&response)?;

    Ok(EvmThresholdBootstrapResultV1 { response, adapter })
}

pub fn bootstrap_registration_evm_threshold_v1(
    context: EcdsaHssStableKeyContextV1,
    y_client32_le: [u8; 32],
    y_relayer32_le: [u8; 32],
) -> CoreResult<EvmThresholdBootstrapResultV1> {
    bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: EvmThresholdSigningOperationV1::RegistrationBootstrap.to_server_operation(),
        context,
        y_client32_le,
        y_relayer32_le,
    })
}

pub fn bootstrap_session_evm_threshold_v1(
    context: EcdsaHssStableKeyContextV1,
    y_client32_le: [u8; 32],
    y_relayer32_le: [u8; 32],
) -> CoreResult<EvmThresholdBootstrapResultV1> {
    bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: EvmThresholdSigningOperationV1::SessionBootstrap.to_server_operation(),
        context,
        y_client32_le,
        y_relayer32_le,
    })
}

pub fn prepare_signing_session_v1(
    operation: EvmThresholdSigningOperationV1,
    context: EcdsaHssStableKeyContextV1,
    y_client32_le: [u8; 32],
    y_relayer32_le: [u8; 32],
) -> CoreResult<EvmThresholdSigningSessionV1> {
    let bootstrap = bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: operation.to_server_operation(),
        context,
        y_client32_le,
        y_relayer32_le,
    })?;
    Ok(EvmThresholdSigningSessionV1 {
        operation,
        bootstrap,
    })
}

pub fn export_evm_threshold_v1(
    request: EvmThresholdExportRequestV1,
) -> CoreResult<EvmThresholdExportResultV1> {
    let bootstrap = bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: ServerEvalOperationV1::ExplicitKeyExport,
        context: request.context.clone(),
        y_client32_le: request.y_client32_le,
        y_relayer32_le: request.y_relayer32_le,
    })?;
    let exported = extract_explicit_export_v1(&bootstrap.response)?;
    Ok(EvmThresholdExportResultV1 {
        bootstrap,
        exported,
    })
}

pub fn prepare_explicit_export_session_v1(
    context: EcdsaHssStableKeyContextV1,
    y_client32_le: [u8; 32],
    y_relayer32_le: [u8; 32],
) -> CoreResult<EvmThresholdExplicitExportSessionV1> {
    Ok(EvmThresholdExplicitExportSessionV1 {
        export: export_evm_threshold_v1(EvmThresholdExportRequestV1 {
            context,
            y_client32_le,
            y_relayer32_le,
        })?,
    })
}

pub fn init_client_presign_session_v1(
    adapter: &EvmThresholdBootstrapAdapterV1,
) -> CoreResult<ThresholdEcdsaPresignSession> {
    ThresholdEcdsaPresignSession::new(
        &adapter.identity.participant_ids,
        adapter.client.participant_id,
        2,
        &adapter.client.threshold_private_share32,
        &adapter.identity.group_public_key33,
    )
}

pub fn init_relayer_presign_session_v1(
    adapter: &EvmThresholdBootstrapAdapterV1,
) -> CoreResult<ThresholdEcdsaPresignSession> {
    ThresholdEcdsaPresignSession::new(
        &adapter.identity.participant_ids,
        adapter.relayer.participant_id,
        2,
        &adapter.relayer.threshold_private_share32,
        &adapter.identity.group_public_key33,
    )
}

pub fn parse_presignature97_v1(bytes: &[u8]) -> CoreResult<EvmThresholdPresignatureV1> {
    if bytes.len() != 97 {
        return Err(signer_core::error::SignerCoreError::invalid_length(
            format!("presignature97 must be 97 bytes (got {})", bytes.len()),
        ));
    }
    let mut big_r33 = [0u8; 33];
    big_r33.copy_from_slice(&bytes[..33]);
    let mut k_share32 = [0u8; 32];
    k_share32.copy_from_slice(&bytes[33..65]);
    let mut sigma_share32 = [0u8; 32];
    sigma_share32.copy_from_slice(&bytes[65..97]);
    Ok(EvmThresholdPresignatureV1 {
        big_r33,
        k_share32,
        sigma_share32,
    })
}

pub fn compute_client_signature_share_v1(
    adapter: &EvmThresholdBootstrapAdapterV1,
    presignature: &EvmThresholdPresignatureV1,
    digest32: &[u8; 32],
    entropy32: &[u8; 32],
) -> CoreResult<[u8; 32]> {
    let out = threshold_ecdsa_compute_signature_share(
        &adapter.identity.participant_ids,
        adapter.client.participant_id,
        &adapter.identity.group_public_key33,
        &presignature.big_r33,
        &presignature.k_share32,
        &presignature.sigma_share32,
        digest32,
        entropy32,
    )?;
    out.try_into().map_err(|_| {
        signer_core::error::SignerCoreError::invalid_length(
            "client signature share must be exactly 32 bytes",
        )
    })
}

pub fn finalize_signature_v1(
    adapter: &EvmThresholdBootstrapAdapterV1,
    relayer_presignature: &EvmThresholdPresignatureV1,
    digest32: &[u8; 32],
    entropy32: &[u8; 32],
    client_signature_share32: &[u8; 32],
) -> CoreResult<[u8; 65]> {
    let out = threshold_ecdsa_finalize_signature(
        &adapter.identity.participant_ids,
        adapter.relayer.participant_id,
        &adapter.identity.group_public_key33,
        &relayer_presignature.big_r33,
        &relayer_presignature.k_share32,
        &relayer_presignature.sigma_share32,
        digest32,
        entropy32,
        client_signature_share32,
    )?;
    out.try_into().map_err(|_| {
        signer_core::error::SignerCoreError::invalid_length(
            "finalized signature must be exactly 65 bytes",
        )
    })
}

pub fn complete_presign_roundtrip_v1(
    adapter: &EvmThresholdBootstrapAdapterV1,
) -> CoreResult<(EvmThresholdPresignatureV1, EvmThresholdPresignatureV1)> {
    let mut client = init_client_presign_session_v1(adapter)?;
    let mut relayer = init_relayer_presign_session_v1(adapter)?;

    for _ in 0..64 {
        if client.is_triples_done() && relayer.is_triples_done() {
            client.start_presign()?;
            relayer.start_presign()?;
        }

        pump_presign_pair_until_wait_or_done(
            &mut client,
            &mut relayer,
            adapter.client.participant_id,
            adapter.relayer.participant_id,
        )?;

        if client.is_done() && relayer.is_done() {
            let client_presignature = parse_presignature97_v1(&client.take_presignature_97()?)?;
            let relayer_presignature = parse_presignature97_v1(&relayer.take_presignature_97()?)?;
            if client_presignature.big_r33 != relayer_presignature.big_r33 {
                return Err(signer_core::error::SignerCoreError::crypto_error(
                    "client and relayer presignatures disagree on big R",
                ));
            }
            return Ok((client_presignature, relayer_presignature));
        }
    }

    Err(signer_core::error::SignerCoreError::internal(
        "presign/sign session did not complete within step budget",
    ))
}

pub fn sign_with_session_v1(
    session: &EvmThresholdSigningSessionV1,
    digest32: &[u8; 32],
    entropy32: &[u8; 32],
) -> CoreResult<[u8; 65]> {
    let adapter = &session.bootstrap.adapter;
    let (client_presignature, relayer_presignature) = complete_presign_roundtrip_v1(adapter)?;
    let client_signature_share32 =
        compute_client_signature_share_v1(adapter, &client_presignature, digest32, entropy32)?;
    finalize_signature_v1(
        adapter,
        &relayer_presignature,
        digest32,
        entropy32,
        &client_signature_share32,
    )
}

fn pump_presign_pair_until_wait_or_done(
    client: &mut ThresholdEcdsaPresignSession,
    relayer: &mut ThresholdEcdsaPresignSession,
    client_participant_id: u32,
    relayer_participant_id: u32,
) -> CoreResult<()> {
    loop {
        let mut progressed = false;

        let client_progress = client.poll_internal()?;
        if client_progress.event != ThresholdEcdsaPresignEvent::None
            || !client_progress.outgoing.is_empty()
        {
            progressed = true;
        }
        for msg in client_progress.outgoing {
            relayer.message(client_participant_id, &msg)?;
        }

        let relayer_progress = relayer.poll_internal()?;
        if relayer_progress.event != ThresholdEcdsaPresignEvent::None
            || !relayer_progress.outgoing.is_empty()
        {
            progressed = true;
        }
        for msg in relayer_progress.outgoing {
            client.message(relayer_participant_id, &msg)?;
        }

        if client.is_done() && relayer.is_done() {
            return Ok(());
        }
        if !progressed {
            return Ok(());
        }
    }
}

pub fn export_from_session_v1(
    session: &EvmThresholdExplicitExportSessionV1,
) -> EvmThresholdExplicitExportV1 {
    session.export.exported.clone()
}

fn map_share(additive_share32: &[u8; 32], participant_id: u32) -> CoreResult<[u8; 32]> {
    let mapped =
        map_additive_share_to_threshold_signatures_share_2p(additive_share32, participant_id)?;
    mapped.try_into().map_err(|_| {
        signer_core::error::SignerCoreError::invalid_length(
            "mapped threshold share must be exactly 32 bytes",
        )
    })
}

fn validate_threshold_response_cryptographic_consistency(
    response: &RespondResponseV1,
) -> CoreResult<()> {
    response
        .finalized_server_session
        .validate_finalize_envelope(&response.finalize)?;

    if response
        .finalized_server_session
        .operation
        .allowed_output_kind()
        != response.client_output.allowed_output_kind()
    {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "client output kind does not match operation output policy",
        ));
    }

    let retained = &response.finalized_server_session.retained;
    let (
        x_client32,
        client_public_key33,
        output_threshold_public_key33,
        output_threshold_address20,
    ) = match &response.client_output {
        ClientOutputV1::NonExport(output) => (
            output.x_client32,
            output.client_public_key33,
            output.threshold_public_key33,
            output.threshold_ethereum_address20,
        ),
        ClientOutputV1::ExplicitExport(output) => (
            output.x_client32,
            output.client_public_key33,
            output.threshold_public_key33,
            output.threshold_ethereum_address20,
        ),
    };

    let derived_client_public_key33 =
        derive_public_key33_from_secret32(&x_client32, "client additive share")?;
    if derived_client_public_key33 != client_public_key33 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "client public key does not match x_client32",
        ));
    }

    let derived_relayer_public_key33 = derive_public_key33_from_secret32(
        &retained.relayer_threshold_share32,
        "relayer additive share",
    )?;
    if derived_relayer_public_key33 != retained.relayer_public_key33 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "relayer public key does not match retained relayer share",
        ));
    }

    let derived_threshold_public_key33 =
        derive_threshold_public_key33(&derived_client_public_key33, &derived_relayer_public_key33)?;
    if derived_threshold_public_key33 != retained.threshold_public_key33 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "retained threshold public key does not match additive-share public keys",
        ));
    }
    if derived_threshold_public_key33 != output_threshold_public_key33 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "client output threshold public key does not match additive-share public keys",
        ));
    }

    let derived_threshold_ethereum_address20 =
        derive_ethereum_address20_from_public_key33(&derived_threshold_public_key33)?;
    if derived_threshold_ethereum_address20 != retained.threshold_ethereum_address20 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "retained threshold ethereum address does not match threshold public key",
        ));
    }
    if derived_threshold_ethereum_address20 != output_threshold_address20 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "client output threshold ethereum address does not match threshold public key",
        ));
    }

    if let ClientOutputV1::ExplicitExport(output) = &response.client_output {
        let derived_canonical_public_key33 =
            derive_public_key33_from_secret32(&output.canonical_x32, "canonical x")?;
        if derived_canonical_public_key33 != output.canonical_public_key33 {
            return Err(signer_core::error::SignerCoreError::invalid_input(
                "canonical public key does not match canonical_x32",
            ));
        }

        let derived_canonical_ethereum_address20 =
            derive_ethereum_address20_from_public_key33(&derived_canonical_public_key33)?;
        if derived_canonical_ethereum_address20 != output.canonical_ethereum_address20 {
            return Err(signer_core::error::SignerCoreError::invalid_input(
                "canonical ethereum address does not match canonical public key",
            ));
        }
    }

    Ok(())
}

fn derive_public_key33_from_secret32(
    secret32: &[u8; 32],
    field_name: &str,
) -> CoreResult<[u8; 33]> {
    let public_key33 = secp256k1_private_key_32_to_public_key_33(secret32)?;
    public_key33.try_into().map_err(|_| {
        signer_core::error::SignerCoreError::invalid_length(format!(
            "{field_name} public key must be exactly 33 bytes",
        ))
    })
}

fn derive_threshold_public_key33(
    client_public_key33: &[u8; 33],
    relayer_public_key33: &[u8; 33],
) -> CoreResult<[u8; 33]> {
    let threshold_public_key33 =
        add_secp256k1_public_keys_33(client_public_key33, relayer_public_key33)?;
    threshold_public_key33.try_into().map_err(|_| {
        signer_core::error::SignerCoreError::invalid_length(
            "threshold public key must be exactly 33 bytes",
        )
    })
}

fn derive_ethereum_address20_from_public_key33(public_key33: &[u8; 33]) -> CoreResult<[u8; 20]> {
    let address20 = secp256k1_public_key_33_to_ethereum_address_20(public_key33)?;
    address20.try_into().map_err(|_| {
        signer_core::error::SignerCoreError::invalid_length(
            "ethereum address must be exactly 20 bytes",
        )
    })
}
