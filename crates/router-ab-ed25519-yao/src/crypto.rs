use core::fmt;

use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_core_09::{CryptoRng, RngCore};
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1,
    Ed25519YaoEncryptedPackageV1, Ed25519YaoInputKindV1, Ed25519YaoOperationV1,
    Ed25519YaoPackageKindV1, Ed25519YaoRefreshBindingV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    ed25519_yao_input_aad_v1, ed25519_yao_recipient_package_aad_v1,
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoExportDeriverARequestV1, LocalEd25519YaoExportDeriverBRequestV1,
    ED25519_YAO_INPUT_HPKE_INFO_V1, ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1,
};

type ProductHpkeV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;

/// One role-local X25519 private key for opening Yao protocol envelopes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519YaoRecipientPrivateKeyV1([u8; 32]);

impl Ed25519YaoRecipientPrivateKeyV1 {
    /// Creates one private key from an exact 32-byte secret.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the private key bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Ed25519YaoRecipientPrivateKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519YaoRecipientPrivateKeyV1([REDACTED])")
    }
}

/// One X25519 key pair used at a Yao recipient boundary.
pub struct Ed25519YaoRecipientKeyPairV1 {
    /// Zeroizing private key.
    pub private_key: Ed25519YaoRecipientPrivateKeyV1,
    /// Public key distributed to the protocol peer.
    pub public_key: [u8; 32],
}

impl fmt::Debug for Ed25519YaoRecipientKeyPairV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ed25519YaoRecipientKeyPairV1")
            .field("private_key", &"[REDACTED]")
            .field("public_key", &"[PUBLIC KEY]")
            .finish()
    }
}

/// Generates one recipient key pair with the caller's platform CSPRNG.
pub fn generate_ed25519_yao_recipient_key_pair_v1<R>(
    rng: &mut R,
) -> RouterAbProtocolResult<Ed25519YaoRecipientKeyPairV1>
where
    R: CryptoRng + RngCore,
{
    let (private_key, public_key) =
        DhKemX25519HkdfSha256::generate(rng).map_err(map_hpke_config_error)?;
    key_pair_from_hpke(private_key, public_key)
}

/// Derives one deterministic recipient key pair from at least 32 bytes of IKM.
pub fn derive_ed25519_yao_recipient_key_pair_v1(
    input_key_material: &[u8],
) -> RouterAbProtocolResult<Ed25519YaoRecipientKeyPairV1> {
    if input_key_material.len() < 32 {
        return Err(invalid_crypto_config(
            "recipient key derivation input must contain at least 32 bytes",
        ));
    }
    let (private_key, public_key) = DhKemX25519HkdfSha256::derive_key_pair(input_key_material)
        .map_err(map_hpke_config_error)?;
    key_pair_from_hpke(private_key, public_key)
}

/// Opens one exact Deriver A activation input.
pub fn open_ed25519_yao_activation_deriver_a_input_v1(
    envelope: &Ed25519YaoEncryptedInputV1,
    private_key: &Ed25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<LocalEd25519YaoActivationDeriverARequestV1> {
    open_input(
        envelope,
        Ed25519YaoInputKindV1::Activation,
        Ed25519YaoDeriverRoleV1::DeriverA,
        private_key,
    )
}

/// Opens one exact Deriver B activation input.
pub fn open_ed25519_yao_activation_deriver_b_input_v1(
    envelope: &Ed25519YaoEncryptedInputV1,
    private_key: &Ed25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<LocalEd25519YaoActivationDeriverBRequestV1> {
    open_input(
        envelope,
        Ed25519YaoInputKindV1::Activation,
        Ed25519YaoDeriverRoleV1::DeriverB,
        private_key,
    )
}

/// Opens one exact Deriver A export input.
pub fn open_ed25519_yao_export_deriver_a_input_v1(
    envelope: &Ed25519YaoEncryptedInputV1,
    private_key: &Ed25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<LocalEd25519YaoExportDeriverARequestV1> {
    open_input(
        envelope,
        Ed25519YaoInputKindV1::Export,
        Ed25519YaoDeriverRoleV1::DeriverA,
        private_key,
    )
}

/// Opens one exact Deriver B export input.
pub fn open_ed25519_yao_export_deriver_b_input_v1(
    envelope: &Ed25519YaoEncryptedInputV1,
    private_key: &Ed25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<LocalEd25519YaoExportDeriverBRequestV1> {
    open_input(
        envelope,
        Ed25519YaoInputKindV1::Export,
        Ed25519YaoDeriverRoleV1::DeriverB,
        private_key,
    )
}

/// Seals one circuit output to its exact recipient.
pub fn seal_ed25519_yao_package_v1<R>(
    rng: &mut R,
    kind: Ed25519YaoPackageKindV1,
    deriver: Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    transcript: [u8; 32],
    recipient_public_key: [u8; 32],
    plaintext: &[u8],
) -> RouterAbProtocolResult<Ed25519YaoEncryptedPackageV1>
where
    R: CryptoRng + RngCore,
{
    if plaintext.is_empty() {
        return Err(invalid_crypto_config(
            "recipient package plaintext is empty",
        ));
    }
    let public_key = DhKemX25519HkdfSha256::pk_from_bytes(&recipient_public_key)
        .map_err(map_hpke_config_error)?;
    let aad = ed25519_yao_recipient_package_aad_v1(kind, deriver, session, transcript);
    let (encapsulated_key, ciphertext) = ProductHpkeV1::seal_base(
        rng,
        &public_key,
        ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1,
        &aad,
        plaintext,
    )
    .map_err(map_hpke_config_error)?;
    let encapsulated_key = encapsulated_key
        .as_ref()
        .try_into()
        .map_err(|_| invalid_crypto_config("HPKE encapsulated key has wrong length"))?;
    Ed25519YaoEncryptedPackageV1::new(
        kind,
        deriver,
        session,
        transcript,
        encapsulated_key,
        ciphertext,
    )
}

/// Opens one Client recipient package.
pub fn open_ed25519_yao_client_package_v1(
    envelope: &Ed25519YaoEncryptedPackageV1,
    private_key: &Ed25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
    if !envelope.kind().is_client() {
        return Err(malformed_envelope(
            "Client cannot open a SigningWorker recipient package",
        ));
    }
    open_package(envelope, private_key)
}

/// Opens one SigningWorker activation package.
pub fn open_ed25519_yao_signing_worker_package_v1(
    envelope: &Ed25519YaoEncryptedPackageV1,
    private_key: &Ed25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
    if envelope.kind() != Ed25519YaoPackageKindV1::ActivationSigningWorker {
        return Err(malformed_envelope(
            "SigningWorker cannot open a Client recipient package",
        ));
    }
    open_package(envelope, private_key)
}

/// Computes the exact digest binding one refresh transition.
pub fn ed25519_yao_refresh_binding_digest_v1(binding: &Ed25519YaoRefreshBindingV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"seams/router-ab/ed25519-yao/refresh-binding/v1");
    hasher.update(binding.ceremony().session_id.into_bytes());
    hasher.update(binding.ceremony().stable_key_context_binding.into_bytes());
    hasher.update(binding.registered_public_key());
    for transition in [
        binding.epochs().deriver_a,
        binding.epochs().deriver_b,
        binding.epochs().signing_worker,
    ] {
        hasher.update(transition.current().get().to_be_bytes());
        hasher.update(transition.next().get().to_be_bytes());
    }
    hasher.finalize().into()
}

fn open_input<Request>(
    envelope: &Ed25519YaoEncryptedInputV1,
    expected_kind: Ed25519YaoInputKindV1,
    expected_deriver: Ed25519YaoDeriverRoleV1,
    private_key: &Ed25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<Request>
where
    Request: DeserializeOwned + BoundInput,
{
    envelope.validate()?;
    if envelope.kind() != expected_kind || envelope.deriver() != expected_deriver {
        return Err(malformed_envelope(
            "Deriver input role or circuit family is invalid",
        ));
    }
    let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(envelope.encapsulated_key())
        .map_err(map_hpke_envelope_error)?;
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(private_key.as_bytes())
        .map_err(map_hpke_config_error)?;
    let aad = ed25519_yao_input_aad_v1(
        envelope.kind(),
        envelope.deriver(),
        envelope.operation(),
        envelope.session(),
        envelope.stable_context_binding(),
    );
    let mut plaintext = Zeroizing::new(
        ProductHpkeV1::open_base(
            &encapsulated_key,
            &private_key,
            ED25519_YAO_INPUT_HPKE_INFO_V1,
            &aad,
            envelope.ciphertext(),
        )
        .map_err(map_hpke_envelope_error)?,
    );
    let request = serde_json::from_slice::<Request>(&plaintext)
        .map_err(|_| malformed_envelope("Deriver input plaintext is malformed"))?;
    plaintext.zeroize();
    let binding = request.binding();
    if binding.operation != envelope.operation()
        || binding.session_id.into_bytes() != envelope.session()
        || binding.stable_key_context_binding.into_bytes() != envelope.stable_context_binding()
        || !operation_matches_kind(binding.operation, expected_kind)
    {
        return Err(malformed_envelope(
            "Deriver input envelope does not match its admitted binding",
        ));
    }
    Ok(request)
}

fn open_package(
    envelope: &Ed25519YaoEncryptedPackageV1,
    private_key: &Ed25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
    envelope.validate()?;
    let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(envelope.encapsulated_key())
        .map_err(map_hpke_envelope_error)?;
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(private_key.as_bytes())
        .map_err(map_hpke_config_error)?;
    let aad = ed25519_yao_recipient_package_aad_v1(
        envelope.kind(),
        envelope.deriver(),
        envelope.session(),
        envelope.transcript(),
    );
    ProductHpkeV1::open_base(
        &encapsulated_key,
        &private_key,
        ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1,
        &aad,
        envelope.ciphertext(),
    )
    .map(Zeroizing::new)
    .map_err(map_hpke_envelope_error)
}

fn key_pair_from_hpke(
    private_key: <DhKemX25519HkdfSha256 as Kem>::PrivateKey,
    public_key: <DhKemX25519HkdfSha256 as Kem>::PublicKey,
) -> RouterAbProtocolResult<Ed25519YaoRecipientKeyPairV1> {
    let private_key = DhKemX25519HkdfSha256::sk_to_bytes(&private_key)
        .as_slice()
        .try_into()
        .map_err(|_| invalid_crypto_config("HPKE private key has wrong length"))?;
    let public_key = DhKemX25519HkdfSha256::pk_to_bytes(&public_key)
        .as_slice()
        .try_into()
        .map_err(|_| invalid_crypto_config("HPKE public key has wrong length"))?;
    Ok(Ed25519YaoRecipientKeyPairV1 {
        private_key: Ed25519YaoRecipientPrivateKeyV1(private_key),
        public_key,
    })
}

trait BoundInput {
    fn binding(&self) -> &Ed25519YaoCeremonyBindingV1;
}

macro_rules! impl_bound_input {
    ($($request:ty),+ $(,)?) => {
        $(
            impl BoundInput for $request {
                fn binding(&self) -> &Ed25519YaoCeremonyBindingV1 {
                    &self.binding
                }
            }
        )+
    };
}

impl_bound_input!(
    LocalEd25519YaoActivationDeriverARequestV1,
    LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoExportDeriverARequestV1,
    LocalEd25519YaoExportDeriverBRequestV1,
);

fn operation_matches_kind(operation: Ed25519YaoOperationV1, kind: Ed25519YaoInputKindV1) -> bool {
    matches!(
        (operation, kind),
        (
            Ed25519YaoOperationV1::Registration | Ed25519YaoOperationV1::Recovery,
            Ed25519YaoInputKindV1::Activation
        ) | (Ed25519YaoOperationV1::Export, Ed25519YaoInputKindV1::Export)
    )
}

fn map_hpke_config_error(error: hpke_ng::HpkeError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("Ed25519 Yao HPKE configuration failed: {error}"),
    )
}

fn map_hpke_envelope_error(_: hpke_ng::HpkeError) -> RouterAbProtocolError {
    malformed_envelope("Ed25519 Yao HPKE envelope failed authentication")
}

fn invalid_crypto_config(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        message,
    )
}

fn malformed_envelope(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}
