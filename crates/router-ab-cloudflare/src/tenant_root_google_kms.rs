use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use router_ab_core::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const GOOGLE_OAUTH_TOKEN_URL_V1: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_KMS_API_PREFIX_V1: &str = "https://cloudkms.googleapis.com/v1/";
const GOOGLE_CLOUD_KMS_SCOPE_V1: &str = "https://www.googleapis.com/auth/cloudkms";
const GOOGLE_SERVICE_ACCOUNT_EMAIL_SUFFIX_V1: &str = ".iam.gserviceaccount.com";
const MAX_GOOGLE_CREDENTIALS_JSON_BYTES_V1: usize = 32 * 1024;
const MAX_KMS_PAYLOAD_BYTES_V1: usize = 64 * 1024;

#[derive(Deserialize)]
struct GoogleServiceAccountCredentialsWireV1 {
    #[serde(rename = "type")]
    credential_type: String,
    client_email: String,
    private_key: String,
    token_uri: String,
}

struct GoogleServiceAccountCredentialsV1 {
    client_email: String,
    private_key_der: Zeroizing<Vec<u8>>,
}

pub(crate) struct CloudflareTenantRootGoogleKmsBackupProviderV1 {
    key_version: String,
    credentials: GoogleServiceAccountCredentialsV1,
}

impl CloudflareTenantRootGoogleKmsBackupProviderV1 {
    pub(crate) fn new(
        role: threshold_prf::TwoPartyDeriverRole,
        provider_id: String,
        key_version: String,
        credentials_json: Zeroizing<Vec<u8>>,
    ) -> RouterAbDerivationResult<Self> {
        let expected_provider_id = match role {
            threshold_prf::TwoPartyDeriverRole::DeriverA => {
                crate::env::DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_GOOGLE_PROVIDER_ID_V1
            }
            threshold_prf::TwoPartyDeriverRole::DeriverB => {
                crate::env::DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_GOOGLE_PROVIDER_ID_V1
            }
        };
        if provider_id != expected_provider_id {
            return Err(malformed(
                "tenant-root Google Cloud KMS provider id does not match this role",
            ));
        }
        crate::env::validate_google_cloud_kms_key_version_v1(&key_version)
            .map_err(|error| malformed(error.message()))?;
        let credentials = parse_credentials(credentials_json)?;
        Ok(Self {
            key_version,
            credentials,
        })
    }

    pub(crate) async fn seal(
        &self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> RouterAbDerivationResult<Vec<u8>> {
        let ciphertext = self.kms_encrypt(aad, plaintext).await?;
        if ciphertext.is_empty() || ciphertext.len() > MAX_KMS_PAYLOAD_BYTES_V1 {
            return Err(malformed(
                "tenant-root Google Cloud KMS ciphertext has an invalid length",
            ));
        }
        Ok(ciphertext)
    }

    pub(crate) async fn open(
        &self,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> RouterAbDerivationResult<Zeroizing<Vec<u8>>> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_KMS_PAYLOAD_BYTES_V1 {
            return Err(malformed(
                "tenant-root Google Cloud KMS ciphertext has an invalid length",
            ));
        }
        let plaintext = Zeroizing::new(self.kms_decrypt(aad, ciphertext).await?);
        if plaintext.is_empty() || plaintext.len() > MAX_KMS_PAYLOAD_BYTES_V1 {
            return Err(malformed(
                "tenant-root Google Cloud KMS plaintext has an invalid length",
            ));
        }
        Ok(plaintext)
    }

    async fn kms_encrypt(&self, aad: &[u8], plaintext: &[u8]) -> RouterAbDerivationResult<Vec<u8>> {
        if plaintext.is_empty() || plaintext.len() > MAX_KMS_PAYLOAD_BYTES_V1 {
            return Err(malformed(
                "tenant-root Google Cloud KMS plaintext has an invalid length",
            ));
        }
        let token = self.oauth_access_token().await?;
        let mut request = GoogleKmsEncryptRequestV1 {
            plaintext: STANDARD.encode(plaintext),
            additional_authenticated_data: STANDARD.encode(aad),
        };
        let body = Zeroizing::new(
            serde_json::to_string(&request)
                .map_err(|_| malformed("tenant-root Google Cloud KMS request encoding failed"))?,
        );
        request.plaintext.zeroize();
        request.additional_authenticated_data.zeroize();
        let endpoint = format!("{GOOGLE_KMS_API_PREFIX_V1}{}:encrypt", self.key_version);
        let response =
            post_google_request_v1(&endpoint, body.as_str(), "application/json", &token).await?;
        let response: GoogleKmsEncryptResponseV1 = serde_json::from_str(&response)
            .map_err(|_| malformed("tenant-root Google Cloud KMS encrypt response is invalid"))?;
        if response.name != self.key_version {
            return Err(malformed(
                "tenant-root Google Cloud KMS encrypt response used the wrong key version",
            ));
        }
        STANDARD.decode(response.ciphertext).map_err(|_| {
            malformed("tenant-root Google Cloud KMS encrypt response ciphertext is invalid")
        })
    }

    async fn kms_decrypt(
        &self,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> RouterAbDerivationResult<Vec<u8>> {
        let token = self.oauth_access_token().await?;
        let mut request = GoogleKmsDecryptRequestV1 {
            ciphertext: STANDARD.encode(ciphertext),
            additional_authenticated_data: STANDARD.encode(aad),
        };
        let body = Zeroizing::new(
            serde_json::to_string(&request)
                .map_err(|_| malformed("tenant-root Google Cloud KMS request encoding failed"))?,
        );
        request.ciphertext.zeroize();
        request.additional_authenticated_data.zeroize();
        let crypto_key = crate::env::google_cloud_kms_crypto_key_from_version_v1(&self.key_version)
            .map_err(|error| malformed(error.message()))?;
        let endpoint = format!("{GOOGLE_KMS_API_PREFIX_V1}{crypto_key}:decrypt");
        let response = Zeroizing::new(
            post_google_request_v1(&endpoint, body.as_str(), "application/json", &token).await?,
        );
        let mut response: GoogleKmsDecryptResponseV1 = serde_json::from_str(response.as_str())
            .map_err(|_| malformed("tenant-root Google Cloud KMS decrypt response is invalid"))?;
        let plaintext = STANDARD.decode(&response.plaintext).map_err(|_| {
            malformed("tenant-root Google Cloud KMS decrypt response plaintext is invalid")
        });
        response.plaintext.zeroize();
        plaintext
    }

    async fn oauth_access_token(&self) -> RouterAbDerivationResult<Zeroizing<String>> {
        let assertion = build_service_account_assertion_v1(&self.credentials).await?;
        let mut body = Zeroizing::new(String::from(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=",
        ));
        body.push_str(assertion.as_str());
        let response = post_google_request_v1(
            GOOGLE_OAUTH_TOKEN_URL_V1,
            body.as_str(),
            "application/x-www-form-urlencoded",
            "",
        )
        .await?;
        let response = Zeroizing::new(response);
        let mut token: GoogleOAuthTokenResponseV1 = serde_json::from_str(response.as_str())
            .map_err(|_| malformed("Google OAuth token response is invalid"))?;
        if token.token_type != "Bearer" || token.access_token.is_empty() {
            return Err(malformed("Google OAuth token response is invalid"));
        }
        Ok(Zeroizing::new(std::mem::take(&mut token.access_token)))
    }
}

#[derive(Serialize)]
struct GoogleKmsEncryptRequestV1 {
    plaintext: String,
    #[serde(rename = "additionalAuthenticatedData")]
    additional_authenticated_data: String,
}

#[derive(Serialize)]
struct GoogleKmsDecryptRequestV1 {
    ciphertext: String,
    #[serde(rename = "additionalAuthenticatedData")]
    additional_authenticated_data: String,
}

#[derive(Deserialize)]
struct GoogleKmsEncryptResponseV1 {
    name: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct GoogleKmsDecryptResponseV1 {
    plaintext: String,
}

#[derive(Deserialize)]
struct GoogleOAuthTokenResponseV1 {
    access_token: String,
    token_type: String,
}

#[derive(Serialize)]
struct GoogleJwtHeaderV1 {
    alg: &'static str,
    typ: &'static str,
}

#[derive(Serialize)]
struct GoogleJwtClaimsV1<'a> {
    iss: &'a str,
    scope: &'static str,
    aud: &'static str,
    iat: u64,
    exp: u64,
}

async fn build_service_account_assertion_v1(
    credentials: &GoogleServiceAccountCredentialsV1,
) -> RouterAbDerivationResult<Zeroizing<String>> {
    let now_ms = worker::js_sys::Date::now();
    if !now_ms.is_finite() || now_ms < 0.0 {
        return Err(malformed("Google OAuth clock is invalid"));
    }
    let issued_at = (now_ms / 1000.0).floor() as u64;
    let expires_at = issued_at
        .checked_add(3600)
        .ok_or_else(|| malformed("Google OAuth assertion lifetime is invalid"))?;
    let header = serde_json::to_vec(&GoogleJwtHeaderV1 {
        alg: "RS256",
        typ: "JWT",
    })
    .map_err(|_| malformed("Google OAuth assertion encoding failed"))?;
    let claims = serde_json::to_vec(&GoogleJwtClaimsV1 {
        iss: &credentials.client_email,
        scope: GOOGLE_CLOUD_KMS_SCOPE_V1,
        aud: GOOGLE_OAUTH_TOKEN_URL_V1,
        iat: issued_at,
        exp: expires_at,
    })
    .map_err(|_| malformed("Google OAuth assertion encoding failed"))?;
    let encoded_header = URL_SAFE_NO_PAD.encode(header);
    let encoded_claims = URL_SAFE_NO_PAD.encode(claims);
    let mut signing_input = Zeroizing::new(format!("{encoded_header}.{encoded_claims}"));
    let signature = sign_rs256_v1(
        credentials.private_key_der.as_slice(),
        signing_input.as_bytes(),
    )
    .await?;
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature);
    signing_input.push('.');
    signing_input.push_str(&encoded_signature);
    Ok(signing_input)
}

async fn sign_rs256_v1(
    private_key_der: &[u8],
    signing_input: &[u8],
) -> RouterAbDerivationResult<Zeroizing<Vec<u8>>> {
    use wasm_bindgen::JsCast;

    let worker: worker::web_sys::WorkerGlobalScope = worker::js_sys::global().unchecked_into();
    let crypto = worker
        .crypto()
        .map_err(|_| malformed("Google OAuth Web Crypto is unavailable"))?;
    let subtle = crypto.subtle();
    let algorithm = worker::web_sys::RsaHashedImportParams::new_with_str("SHA-256");
    worker::js_sys::Reflect::set(
        algorithm.unchecked_ref(),
        &worker::wasm_bindgen::JsValue::from_str("name"),
        &worker::wasm_bindgen::JsValue::from_str("RSASSA-PKCS1-v1_5"),
    )
    .map_err(|_| malformed("Google OAuth Web Crypto algorithm is unavailable"))?;
    let key_data = worker::js_sys::Uint8Array::from(private_key_der);
    let usages = worker::js_sys::Array::new();
    usages.push(&worker::wasm_bindgen::JsValue::from_str("sign"));
    let usages: worker::wasm_bindgen::JsValue = usages.into();
    let key_promise = subtle
        .import_key_with_object(
            "pkcs8",
            key_data.unchecked_ref(),
            algorithm.unchecked_ref(),
            false,
            &usages,
        )
        .map_err(|_| malformed("Google OAuth private key import failed"))?;
    let key = worker::js_sys::futures::JsFuture::from(key_promise)
        .await
        .map_err(|_| malformed("Google OAuth private key import failed"))?
        .dyn_into::<worker::web_sys::CryptoKey>()
        .map_err(|_| malformed("Google OAuth private key import failed"))?;
    let signature_promise = subtle
        .sign_with_str_and_u8_array("RSASSA-PKCS1-v1_5", &key, signing_input)
        .map_err(|_| malformed("Google OAuth assertion signing failed"))?;
    let signature = worker::js_sys::futures::JsFuture::from(signature_promise)
        .await
        .map_err(|_| malformed("Google OAuth assertion signing failed"))?;
    Ok(Zeroizing::new(
        worker::js_sys::Uint8Array::new(&signature).to_vec(),
    ))
}

async fn post_google_request_v1(
    url: &str,
    body: &str,
    content_type: &str,
    access_token: &str,
) -> RouterAbDerivationResult<String> {
    let headers = worker::Headers::new();
    headers
        .set("content-type", content_type)
        .map_err(|_| malformed("Google request headers are invalid"))?;
    if !access_token.is_empty() {
        let mut authorization = Zeroizing::new(String::from("Bearer "));
        authorization.push_str(access_token);
        headers
            .set("authorization", authorization.as_str())
            .map_err(|_| malformed("Google request headers are invalid"))?;
    }
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(body)));
    let request = worker::Request::new_with_init(url, &init)
        .map_err(|_| malformed("Google request construction failed"))?;
    let mut response = worker::Fetch::Request(request)
        .send()
        .await
        .map_err(|_| malformed("Google request failed"))?;
    let status = response.status_code();
    let response_body = response
        .text()
        .await
        .map_err(|_| malformed("Google response read failed"))?;
    if !(200..=299).contains(&status) {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("Google request returned HTTP {status}"),
        ));
    }
    Ok(response_body)
}

fn parse_credentials(
    credentials_json: Zeroizing<Vec<u8>>,
) -> RouterAbDerivationResult<GoogleServiceAccountCredentialsV1> {
    if credentials_json.is_empty() || credentials_json.len() > MAX_GOOGLE_CREDENTIALS_JSON_BYTES_V1
    {
        return Err(malformed(
            "tenant-root Google service-account credentials JSON has an invalid length",
        ));
    }
    let mut wire: GoogleServiceAccountCredentialsWireV1 = serde_json::from_slice(&credentials_json)
        .map_err(|_| malformed("tenant-root Google service-account credentials JSON is invalid"))?;
    if wire.credential_type != "service_account"
        || wire.token_uri != GOOGLE_OAUTH_TOKEN_URL_V1
        || wire.client_email.len() > 256
        || wire.client_email.trim() != wire.client_email
        || wire.client_email.chars().any(char::is_whitespace)
        || !wire
            .client_email
            .ends_with(GOOGLE_SERVICE_ACCOUNT_EMAIL_SUFFIX_V1)
    {
        wire.private_key.zeroize();
        return Err(malformed(
            "tenant-root Google service-account credentials JSON has invalid identity fields",
        ));
    }
    let private_key_der = decode_private_key_pem(&wire.private_key);
    wire.private_key.zeroize();
    let private_key_der = private_key_der?;
    Ok(GoogleServiceAccountCredentialsV1 {
        client_email: wire.client_email,
        private_key_der,
    })
}

fn decode_private_key_pem(value: &str) -> RouterAbDerivationResult<Zeroizing<Vec<u8>>> {
    let body = value
        .trim()
        .strip_prefix("-----BEGIN PRIVATE KEY-----")
        .and_then(|value| value.strip_suffix("-----END PRIVATE KEY-----"))
        .ok_or_else(|| malformed("Google service-account private key PEM is invalid"))?;
    let encoded = Zeroizing::new(
        body.chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>(),
    );
    let der = STANDARD
        .decode(encoded.as_str())
        .map_err(|_| malformed("Google service-account private key PEM is invalid"))?;
    if der.is_empty() || der.len() > 16 * 1024 {
        return Err(malformed("Google service-account private key is invalid"));
    }
    Ok(Zeroizing::new(der))
}

fn malformed(message: impl Into<String>) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}
