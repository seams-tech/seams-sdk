use serde::{de::DeserializeOwned, Serialize};

use crate::{
    require_non_empty, CloudflareDurableObjectBindingV1, CloudflareWorkerRoleV1,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};

pub(crate) async fn execute_cloudflare_durable_object_custom_json_call_v1<TRequest, TResponse>(
    env: &worker::Env,
    binding: &CloudflareDurableObjectBindingV1,
    path: &str,
    request: &TRequest,
) -> RouterAbProtocolResult<TResponse>
where
    TRequest: Serialize,
    TResponse: DeserializeOwned,
{
    binding.validate_visible_to(CloudflareWorkerRoleV1::SigningWorker)?;
    require_non_empty("Durable Object custom path", path)?;
    let namespace = env.durable_object(&binding.binding_name).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            format!("Durable Object namespace lookup failed: {error}"),
        )
    })?;
    let stub = namespace
        .get_by_name(&binding.object_name)
        .map_err(|error| {
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
