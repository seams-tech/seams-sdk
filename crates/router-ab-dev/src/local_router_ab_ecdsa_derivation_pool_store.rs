use router_ab_core::{
    ActiveSigningWorkerStateV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

use super::{
    encode_base64url_bytes_v1, require_non_empty, require_positive_unix_ms_v1,
    LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolRecordV1,
};

fn local_signing_worker_router_ab_ecdsa_derivation_presignature_pool_store_v1() -> &'static Mutex<
    BTreeMap<String, LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolLifecycleV1>,
> {
    static STORE: OnceLock<
        Mutex<
            BTreeMap<String, LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolLifecycleV1>,
        >,
    > = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn local_signing_worker_router_ab_ecdsa_derivation_presignature_pool_store_key_v1(
    active_signing_worker_state: &ActiveSigningWorkerStateV1,
    server_presignature_id: &str,
) -> RouterAbProtocolResult<String> {
    active_signing_worker_state.validate()?;
    require_non_empty(
        "Router A/B ECDSA derivation pool key server_presignature_id",
        server_presignature_id,
    )?;
    let active_state_bytes = serde_json::to_vec(active_signing_worker_state).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local Router A/B ECDSA derivation active SigningWorker state JSON serialization failed: {error}"
            ),
        )
    })?;
    let digest = Sha256::digest(active_state_bytes);
    Ok(format!(
        "{}:{}",
        encode_base64url_bytes_v1(&digest),
        server_presignature_id
    ))
}

pub(crate) fn local_signing_worker_router_ab_ecdsa_derivation_presignature_pool_store_put_v1(
    record: LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolRecordV1,
) -> RouterAbProtocolResult<bool> {
    record.validate()?;
    let key = local_signing_worker_router_ab_ecdsa_derivation_presignature_pool_store_key_v1(
        &record.active_signing_worker_state,
        &record.server_presignature_id,
    )?;
    let mut store = local_signing_worker_router_ab_ecdsa_derivation_presignature_pool_store_v1()
        .lock()
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local Router A/B ECDSA derivation presignature pool store lock poisoned",
            )
        })?;
    if let Some(existing) = store.get(&key) {
        match existing {
            LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolLifecycleV1::Available(
                existing,
            ) => {
                if existing.same_pool_identity_and_material(&record) {
                    return Ok(false);
                }
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLifecycleState,
                    "local Router A/B ECDSA derivation presignature pool duplicate id has different scope or material",
                ));
            }
            LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolLifecycleV1::Consumed => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLifecycleState,
                    "local Router A/B ECDSA derivation presignature id has already been consumed",
                ));
            }
        }
    }
    store.insert(
        key,
        LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolLifecycleV1::Available(record),
    );
    Ok(true)
}

pub(crate) fn local_signing_worker_router_ab_ecdsa_derivation_presignature_pool_store_take_v1(
    active_signing_worker_state: &ActiveSigningWorkerStateV1,
    server_presignature_id: &str,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolRecordV1> {
    require_non_empty(
        "Router A/B ECDSA derivation pool lookup server_presignature_id",
        server_presignature_id,
    )?;
    require_positive_unix_ms_v1(
        "Router A/B ECDSA derivation pool lookup now_unix_ms",
        now_unix_ms,
    )?;
    let mut store = local_signing_worker_router_ab_ecdsa_derivation_presignature_pool_store_v1()
        .lock()
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local Router A/B ECDSA derivation presignature pool store lock poisoned",
            )
        })?;
    let key = local_signing_worker_router_ab_ecdsa_derivation_presignature_pool_store_key_v1(
        active_signing_worker_state,
        server_presignature_id,
    )?;
    let Some(lifecycle) = store.get(&key) else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local Router A/B ECDSA derivation presignature pool entry is not prepared",
        ));
    };
    let LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolLifecycleV1::Available(record) =
        lifecycle
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local Router A/B ECDSA derivation presignature id has already been consumed",
        ));
    };
    let record = record.clone();
    record.validate()?;
    if record.active_signing_worker_state != *active_signing_worker_state {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local Router A/B ECDSA derivation presignature pool active SigningWorker mismatch",
        ));
    }
    if now_unix_ms >= record.expires_at_ms {
        store.insert(
            key,
            LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolLifecycleV1::Consumed,
        );
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "local Router A/B ECDSA derivation presignature pool entry expired",
        ));
    }
    store.insert(
        key,
        LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolLifecycleV1::Consumed,
    );
    Ok(record)
}

#[derive(Clone, PartialEq, Eq)]
enum LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolLifecycleV1 {
    Available(LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolRecordV1),
    Consumed,
}
