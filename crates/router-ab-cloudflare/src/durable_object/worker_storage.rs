use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    encode_base64url_bytes_v1, require_non_empty, CloudflareSigningWorkerPresignSessionBindingV1,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};

pub(crate) async fn execute_cloudflare_durable_object_custom_json_call_v1<TRequest, TResponse>(
    env: &worker::Env,
    binding: &CloudflareSigningWorkerPresignSessionBindingV1,
    path: &str,
    // Stable per-session identifier shared by all phases of one presign.
    routing_key: &str,
    request: &TRequest,
) -> RouterAbProtocolResult<TResponse>
where
    TRequest: Serialize,
    TResponse: DeserializeOwned,
{
    binding.validate()?;
    require_non_empty("Durable Object custom path", path)?;
    let object_name = deterministic_presign_session_object_name(binding, routing_key)?;
    let namespace = env.durable_object(&binding.binding_name).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            format!("Durable Object namespace lookup failed: {error}"),
        )
    })?;
    let stub = namespace.get_by_name(&object_name).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Durable Object stub lookup failed: {error}"),
        )
    })?;
    let request_body = serde_json::to_string(request).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Durable Object custom request encoding failed: {error}"),
        )
    })?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&request_body)));
    let url = format!("https://router-ab-do.internal{path}");
    let request = worker::Request::new_with_init(&url, &init).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Durable Object custom request construction failed: {error}"),
        )
    })?;
    let mut response = stub.fetch_with_request(request).await.map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Durable Object custom request failed: {error}"),
        )
    })?;
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        let body = response.text().await.unwrap_or_default();
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Durable Object custom request returned HTTP {status}: {body}"),
        ));
    }
    response.json::<TResponse>().await.map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Durable Object custom response JSON is invalid: {error}"),
        )
    })
}

fn deterministic_presign_session_object_name(
    binding: &CloudflareSigningWorkerPresignSessionBindingV1,
    routing_key: &str,
) -> RouterAbProtocolResult<String> {
    require_non_empty("Durable Object presign session routing key", routing_key)?;
    let digest = Sha256::digest(routing_key.as_bytes());
    Ok(format!(
        "{}-{}",
        binding.object_name,
        encode_base64url_bytes_v1(&digest),
    ))
}

#[cfg(test)]
mod tests {
    use super::deterministic_presign_session_object_name;
    use crate::CloudflareSigningWorkerPresignSessionBindingV1;

    #[test]
    fn presign_session_shards_are_stable_and_isolated() {
        let binding = CloudflareSigningWorkerPresignSessionBindingV1::new(
            "PRESIGN_DO",
            "presign-session",
            "unused-key-prefix",
        )
        .expect("valid binding");
        let first =
            deterministic_presign_session_object_name(&binding, "session-a").expect("first shard");
        let first_replay = deterministic_presign_session_object_name(&binding, "session-a")
            .expect("replayed shard");
        let second =
            deterministic_presign_session_object_name(&binding, "session-b").expect("second shard");

        assert_eq!(first, first_replay);
        assert_ne!(first, second);
        assert!(first.starts_with("presign-session-"));
        assert!(!first.contains("session-a"));
    }

    #[test]
    fn presign_session_shards_reject_empty_routing_keys() {
        let binding = CloudflareSigningWorkerPresignSessionBindingV1::new(
            "PRESIGN_DO",
            "presign-session",
            "unused-key-prefix",
        )
        .expect("valid binding");

        assert!(deterministic_presign_session_object_name(&binding, "").is_err());
    }
}
