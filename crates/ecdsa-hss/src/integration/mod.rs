use crate::shared::derive::{reconstruct_export_key_v1, ClientRoleShareV1, PublicIdentityV1};
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
use crate::server::{FinalizedServerSessionV1, RespondResponseV1};
use crate::wire::ServerEvalOperationV1;
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
    pub client_share_retry_counter: u32,
    pub relayer_share_retry_counter: u32,
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
pub struct EvmThresholdClientBootstrapV1 {
    #[zeroize(skip)]
    pub identity: EvmThresholdIdentityV1,
    pub material: EvmThresholdPartyBootstrapMaterialV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdRelayerBootstrapV1 {
    #[zeroize(skip)]
    pub identity: EvmThresholdIdentityV1,
    pub material: EvmThresholdPartyBootstrapMaterialV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdExplicitExportV1 {
    pub x_export32: [u8; 32],
    pub export_public_key33: [u8; 33],
    pub export_ethereum_address20: [u8; 20],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub client_share_retry_counter: u32,
    pub relayer_share_retry_counter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EvmThresholdPresignatureV1 {
    pub big_r33: [u8; 33],
    pub k_share32: [u8; 32],
    pub sigma_share32: [u8; 32],
}

impl EvmThresholdClientBootstrapV1 {
    pub fn from_client_response(
        response: &RespondResponseV1,
        client_share: &ClientRoleShareV1,
    ) -> CoreResult<Self> {
        validate_client_response_public_consistency(response)?;

        let client_verifying_share33 = client_output_client_public_key33(&response.client_output);
        if client_share.client_public_key33 != client_verifying_share33 {
            return Err(signer_core::error::SignerCoreError::invalid_input(
                "client share public key does not match response",
            ));
        }

        let client_threshold_share32 = map_share(
            &client_share.x_client32,
            THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
        )?;

        let identity = EvmThresholdIdentityV1 {
            participant_ids: ECDSA_HSS_EVM_THRESHOLD_V1_PARTICIPANT_IDS,
            client_verifying_share33,
            relayer_verifying_share33: client_output_relayer_public_key33(&response.client_output),
            group_public_key33: client_output_threshold_public_key33(&response.client_output),
            ethereum_address20: client_output_threshold_address20(&response.client_output),
            client_share_retry_counter: client_output_client_retry_counter(&response.client_output),
            relayer_share_retry_counter: client_output_relayer_retry_counter(
                &response.client_output,
            ),
        };

        let material = EvmThresholdPartyBootstrapMaterialV1 {
            participant_ids: identity.participant_ids,
            participant_id: THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
            additive_share32: client_share.x_client32,
            threshold_private_share32: client_threshold_share32,
            group_public_key33: identity.group_public_key33,
            ethereum_address20: identity.ethereum_address20,
        };

        Ok(Self { identity, material })
    }
}

impl EvmThresholdRelayerBootstrapV1 {
    pub fn from_finalized_server_session(session: &FinalizedServerSessionV1) -> CoreResult<Self> {
        let retained = &session.retained;
        validate_server_session_cryptographic_consistency(session)?;
        let relayer_mapped_share32 = map_share(
            &retained.relayer_share32,
            THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
        )?;
        let identity = EvmThresholdIdentityV1 {
            participant_ids: ECDSA_HSS_EVM_THRESHOLD_V1_PARTICIPANT_IDS,
            client_verifying_share33: retained.client_public_key33,
            relayer_verifying_share33: retained.relayer_public_key33,
            group_public_key33: retained.threshold_public_key33,
            ethereum_address20: retained.threshold_ethereum_address20,
            client_share_retry_counter: retained.client_share_retry_counter,
            relayer_share_retry_counter: retained.relayer_share_retry_counter,
        };
        let material = EvmThresholdPartyBootstrapMaterialV1 {
            participant_ids: identity.participant_ids,
            participant_id: THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
            additive_share32: retained.relayer_share32,
            threshold_private_share32: relayer_mapped_share32,
            group_public_key33: identity.group_public_key33,
            ethereum_address20: identity.ethereum_address20,
        };

        Ok(Self { identity, material })
    }
}

pub fn export_from_respond_response_v1(
    response: &RespondResponseV1,
    client_share: &ClientRoleShareV1,
) -> CoreResult<EvmThresholdExplicitExportV1> {
    validate_client_response_public_consistency(response)?;
    extract_explicit_export_v1(response, client_share)
}

fn extract_explicit_export_v1(
    response: &RespondResponseV1,
    client_share: &ClientRoleShareV1,
) -> CoreResult<EvmThresholdExplicitExportV1> {
    if response.finalize.operation != ServerEvalOperationV1::ExplicitKeyExport {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "export requires ExplicitKeyExport operation",
        ));
    }

    let ClientOutputV1::ExplicitExport(output) = &response.client_output else {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "export requires explicit-export client output",
        ));
    };

    let identity = public_identity_from_client_response(response)?;
    let x_export32 =
        reconstruct_export_key_v1(client_share, &output.relayer_export_share32, &identity)?;
    let export_public_key33 = derive_public_key33_from_secret32(&x_export32, "export x")?;
    let export_ethereum_address20 =
        derive_ethereum_address20_from_public_key33(&export_public_key33)?;

    Ok(EvmThresholdExplicitExportV1 {
        x_export32,
        export_public_key33,
        export_ethereum_address20,
        threshold_public_key33: output.threshold_public_key33,
        threshold_ethereum_address20: output.threshold_ethereum_address20,
        client_share_retry_counter: output.client_share_retry_counter,
        relayer_share_retry_counter: output.relayer_share_retry_counter,
    })
}

pub fn init_client_presign_session_v1(
    client: &EvmThresholdClientBootstrapV1,
) -> CoreResult<ThresholdEcdsaPresignSession> {
    ThresholdEcdsaPresignSession::new(
        &client.identity.participant_ids,
        client.material.participant_id,
        2,
        &client.material.threshold_private_share32,
        &client.identity.group_public_key33,
    )
}

pub fn init_relayer_presign_session_v1(
    relayer: &EvmThresholdRelayerBootstrapV1,
) -> CoreResult<ThresholdEcdsaPresignSession> {
    ThresholdEcdsaPresignSession::new(
        &relayer.identity.participant_ids,
        relayer.material.participant_id,
        2,
        &relayer.material.threshold_private_share32,
        &relayer.identity.group_public_key33,
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
    client: &EvmThresholdClientBootstrapV1,
    presignature: &EvmThresholdPresignatureV1,
    digest32: &[u8; 32],
    entropy32: &[u8; 32],
) -> CoreResult<[u8; 32]> {
    let out = threshold_ecdsa_compute_signature_share(
        &client.identity.participant_ids,
        client.material.participant_id,
        &client.identity.group_public_key33,
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
    relayer: &EvmThresholdRelayerBootstrapV1,
    relayer_presignature: &EvmThresholdPresignatureV1,
    digest32: &[u8; 32],
    entropy32: &[u8; 32],
    client_signature_share32: &[u8; 32],
) -> CoreResult<[u8; 65]> {
    let out = threshold_ecdsa_finalize_signature(
        &relayer.identity.participant_ids,
        relayer.material.participant_id,
        &relayer.identity.group_public_key33,
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
    client_bootstrap: &EvmThresholdClientBootstrapV1,
    relayer_bootstrap: &EvmThresholdRelayerBootstrapV1,
) -> CoreResult<(EvmThresholdPresignatureV1, EvmThresholdPresignatureV1)> {
    validate_same_threshold_identity(&client_bootstrap.identity, &relayer_bootstrap.identity)?;
    let mut client = init_client_presign_session_v1(client_bootstrap)?;
    let mut relayer = init_relayer_presign_session_v1(relayer_bootstrap)?;

    for _ in 0..64 {
        if client.is_triples_done() && relayer.is_triples_done() {
            client.start_presign()?;
            relayer.start_presign()?;
        }

        pump_presign_pair_until_wait_or_done(
            &mut client,
            &mut relayer,
            client_bootstrap.material.participant_id,
            relayer_bootstrap.material.participant_id,
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

pub fn sign_with_role_materials_v1(
    client: &EvmThresholdClientBootstrapV1,
    relayer: &EvmThresholdRelayerBootstrapV1,
    digest32: &[u8; 32],
    entropy32: &[u8; 32],
) -> CoreResult<[u8; 65]> {
    validate_same_threshold_identity(&client.identity, &relayer.identity)?;
    let (client_presignature, relayer_presignature) =
        complete_presign_roundtrip_v1(client, relayer)?;
    let client_signature_share32 =
        compute_client_signature_share_v1(client, &client_presignature, digest32, entropy32)?;
    finalize_signature_v1(
        relayer,
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

fn map_share(additive_share32: &[u8; 32], participant_id: u32) -> CoreResult<[u8; 32]> {
    let mapped =
        map_additive_share_to_threshold_signatures_share_2p(additive_share32, participant_id)?;
    mapped.try_into().map_err(|_| {
        signer_core::error::SignerCoreError::invalid_length(
            "mapped threshold share must be exactly 32 bytes",
        )
    })
}

fn validate_client_response_public_consistency(response: &RespondResponseV1) -> CoreResult<()> {
    if response.finalize.operation.allowed_output_kind()
        != response.client_output.allowed_output_kind()
    {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "client output kind does not match operation output policy",
        ));
    }

    let client_public_key33 = client_output_client_public_key33(&response.client_output);
    let relayer_public_key33 = client_output_relayer_public_key33(&response.client_output);
    let output_threshold_public_key33 =
        client_output_threshold_public_key33(&response.client_output);
    let output_threshold_address20 = client_output_threshold_address20(&response.client_output);
    let client_share_retry_counter = client_output_client_retry_counter(&response.client_output);
    let relayer_share_retry_counter = client_output_relayer_retry_counter(&response.client_output);

    if client_public_key33 != response.finalize.client_public_key33 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "client output public key does not match finalize envelope",
        ));
    }
    if relayer_public_key33 != response.finalize.relayer_public_key33 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "client output relayer public key does not match finalize envelope",
        ));
    }
    if client_share_retry_counter != response.finalize.client_share_retry_counter {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "client output retry counter does not match finalize envelope",
        ));
    }
    if relayer_share_retry_counter != response.finalize.relayer_share_retry_counter {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "relayer output retry counter does not match finalize envelope",
        ));
    }

    let derived_threshold_public_key33 =
        derive_threshold_public_key33(&client_public_key33, &relayer_public_key33)?;
    if derived_threshold_public_key33 != response.finalize.threshold_public_key33 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "finalize threshold public key does not match additive-share public keys",
        ));
    }
    if derived_threshold_public_key33 != output_threshold_public_key33 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "client output threshold public key does not match additive-share public keys",
        ));
    }

    let derived_threshold_ethereum_address20 =
        derive_ethereum_address20_from_public_key33(&derived_threshold_public_key33)?;
    if derived_threshold_ethereum_address20 != response.finalize.threshold_ethereum_address20 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "finalize threshold ethereum address does not match threshold public key",
        ));
    }
    if derived_threshold_ethereum_address20 != output_threshold_address20 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "client output threshold ethereum address does not match threshold public key",
        ));
    }

    Ok(())
}

fn validate_server_session_cryptographic_consistency(
    session: &FinalizedServerSessionV1,
) -> CoreResult<()> {
    let retained = &session.retained;
    let derived_relayer_public_key33 =
        derive_public_key33_from_secret32(&retained.relayer_share32, "relayer additive share")?;
    if derived_relayer_public_key33 != retained.relayer_public_key33 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "relayer public key does not match retained relayer share",
        ));
    }

    let derived_threshold_public_key33 = derive_threshold_public_key33(
        &retained.client_public_key33,
        &derived_relayer_public_key33,
    )?;
    if derived_threshold_public_key33 != retained.threshold_public_key33 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "retained threshold public key does not match additive-share public keys",
        ));
    }

    let derived_threshold_ethereum_address20 =
        derive_ethereum_address20_from_public_key33(&derived_threshold_public_key33)?;
    if derived_threshold_ethereum_address20 != retained.threshold_ethereum_address20 {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "retained threshold ethereum address does not match threshold public key",
        ));
    }

    Ok(())
}

fn validate_same_threshold_identity(
    left: &EvmThresholdIdentityV1,
    right: &EvmThresholdIdentityV1,
) -> CoreResult<()> {
    if left != right {
        return Err(signer_core::error::SignerCoreError::invalid_input(
            "client and relayer threshold identities do not match",
        ));
    }
    Ok(())
}

fn public_identity_from_client_response(
    response: &RespondResponseV1,
) -> CoreResult<PublicIdentityV1> {
    Ok(PublicIdentityV1 {
        context_bytes: Vec::new(),
        context_binding32: response.finalize.context_binding32,
        client_public_key33: response.finalize.client_public_key33,
        relayer_public_key33: response.finalize.relayer_public_key33,
        threshold_public_key33: response.finalize.threshold_public_key33,
        threshold_ethereum_address20: response.finalize.threshold_ethereum_address20,
        client_share_retry_counter: response.finalize.client_share_retry_counter,
        relayer_share_retry_counter: response.finalize.relayer_share_retry_counter,
    })
}

fn client_output_client_public_key33(output: &ClientOutputV1) -> [u8; 33] {
    match output {
        ClientOutputV1::NonExport(output) => output.client_public_key33,
        ClientOutputV1::ExplicitExport(output) => output.client_public_key33,
    }
}

fn client_output_relayer_public_key33(output: &ClientOutputV1) -> [u8; 33] {
    match output {
        ClientOutputV1::NonExport(output) => output.relayer_public_key33,
        ClientOutputV1::ExplicitExport(output) => output.relayer_public_key33,
    }
}

fn client_output_threshold_public_key33(output: &ClientOutputV1) -> [u8; 33] {
    match output {
        ClientOutputV1::NonExport(output) => output.threshold_public_key33,
        ClientOutputV1::ExplicitExport(output) => output.threshold_public_key33,
    }
}

fn client_output_threshold_address20(output: &ClientOutputV1) -> [u8; 20] {
    match output {
        ClientOutputV1::NonExport(output) => output.threshold_ethereum_address20,
        ClientOutputV1::ExplicitExport(output) => output.threshold_ethereum_address20,
    }
}

fn client_output_client_retry_counter(output: &ClientOutputV1) -> u32 {
    match output {
        ClientOutputV1::NonExport(output) => output.client_share_retry_counter,
        ClientOutputV1::ExplicitExport(output) => output.client_share_retry_counter,
    }
}

fn client_output_relayer_retry_counter(output: &ClientOutputV1) -> u32 {
    match output {
        ClientOutputV1::NonExport(output) => output.relayer_share_retry_counter,
        ClientOutputV1::ExplicitExport(output) => output.relayer_share_retry_counter,
    }
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
