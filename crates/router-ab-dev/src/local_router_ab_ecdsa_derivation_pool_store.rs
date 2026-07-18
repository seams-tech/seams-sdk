use router_ab_cloudflare::{
    apply_cloudflare_signing_worker_ecdsa_pool_command_v1,
    CloudflareSigningWorkerEcdsaPoolCommandV1, CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1,
    CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1,
};
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

use super::{encode_base64url_bytes_v1, require_non_empty};

fn local_signing_worker_ecdsa_pool_store_v1(
) -> &'static Mutex<BTreeMap<String, CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1>> {
    static STORE: OnceLock<
        Mutex<BTreeMap<String, CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1>>,
    > = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn local_signing_worker_ecdsa_pool_store_key_v1(
    command: &CloudflareSigningWorkerEcdsaPoolCommandV1,
) -> RouterAbProtocolResult<String> {
    command.validate()?;
    let scope_bytes = command.scope().canonical_scope_bytes()?;
    let mut hasher = Sha256::new();
    hasher.update(b"router-ab-dev/signing-worker-ecdsa-pool/v1");
    hasher.update((scope_bytes.len() as u64).to_be_bytes());
    hasher.update(scope_bytes);
    let server_presignature_id = command.server_presignature_id();
    require_non_empty(
        "local SigningWorker ECDSA pool server_presignature_id",
        server_presignature_id,
    )?;
    Ok(format!(
        "{}:{}",
        encode_base64url_bytes_v1(&hasher.finalize()),
        server_presignature_id
    ))
}

pub(crate) fn local_signing_worker_ecdsa_pool_mutate_v1(
    command: CloudflareSigningWorkerEcdsaPoolCommandV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1> {
    let key = local_signing_worker_ecdsa_pool_store_key_v1(&command)?;
    let mut store = local_signing_worker_ecdsa_pool_store_v1()
        .lock()
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local SigningWorker ECDSA pool store lock poisoned",
            )
        })?;
    let outcome =
        apply_cloudflare_signing_worker_ecdsa_pool_command_v1(store.get(&key).cloned(), command)?;
    store.insert(key, outcome.record().clone());
    Ok(outcome)
}
