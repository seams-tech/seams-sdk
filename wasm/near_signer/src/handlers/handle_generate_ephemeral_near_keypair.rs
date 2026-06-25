use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct GenerateEphemeralNearKeypairRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GenerateEphemeralNearKeypairResult {
    pub public_key: String,
    pub private_key: String,
}

pub(crate) async fn handle_generate_ephemeral_near_keypair(
    _request: GenerateEphemeralNearKeypairRequest,
) -> Result<GenerateEphemeralNearKeypairResult, String> {
    let mut seed_bytes = [0u8; 32];
    getrandom::getrandom(&mut seed_bytes)
        .map_err(|e| format!("Failed to generate ephemeral key entropy: {e}"))?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
    let public_key_bytes = signing_key.verifying_key().to_bytes();

    // NEAR Ed25519 private key format is 64 bytes: 32-byte seed + 32-byte public key.
    let mut private_key_bytes = [0u8; 64];
    private_key_bytes[0..32].copy_from_slice(&signing_key.to_bytes());
    private_key_bytes[32..64].copy_from_slice(&public_key_bytes);

    Ok(GenerateEphemeralNearKeypairResult {
        public_key: format!("ed25519:{}", bs58::encode(public_key_bytes).into_string()),
        private_key: format!("ed25519:{}", bs58::encode(private_key_bytes).into_string()),
    })
}
