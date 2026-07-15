use core::fmt;

use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_core_09::{OsRng, TryRngCore};
use router_ab_core::{
    Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedPackageV1, Ed25519YaoPackageKindV1,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use router_ab_ed25519_yao::{
    ed25519_yao_recipient_package_aad_v1, ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1,
};

type RecipientHpkeV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LocalEd25519YaoRecipientPrivateKeyV1([u8; 32]);

impl LocalEd25519YaoRecipientPrivateKeyV1 {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LocalEd25519YaoRecipientPrivateKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalEd25519YaoRecipientPrivateKeyV1([REDACTED])")
    }
}

pub struct LocalEd25519YaoRecipientKeyPairV1 {
    pub private_key: LocalEd25519YaoRecipientPrivateKeyV1,
    pub public_key: [u8; 32],
}

impl fmt::Debug for LocalEd25519YaoRecipientKeyPairV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalEd25519YaoRecipientKeyPairV1")
            .field("private_key", &"[REDACTED]")
            .field("public_key", &hex::encode(self.public_key))
            .finish()
    }
}

pub fn generate_local_ed25519_yao_recipient_key_pair_v1(
) -> RouterAbProtocolResult<LocalEd25519YaoRecipientKeyPairV1> {
    let mut os_rng = OsRng;
    let mut rng = os_rng.unwrap_mut();
    let (private_key, public_key) =
        DhKemX25519HkdfSha256::generate(&mut rng).map_err(map_hpke_error)?;
    key_pair_from_hpke(private_key, public_key)
}

pub fn derive_local_ed25519_yao_recipient_key_pair_v1(
    input_key_material: &[u8],
) -> RouterAbProtocolResult<LocalEd25519YaoRecipientKeyPairV1> {
    if input_key_material.len() < 32 {
        return Err(invalid_delivery(
            "recipient key derivation input must contain at least 32 bytes",
        ));
    }
    let (private_key, public_key) =
        DhKemX25519HkdfSha256::derive_key_pair(input_key_material).map_err(map_hpke_error)?;
    key_pair_from_hpke(private_key, public_key)
}

pub fn seal_local_ed25519_yao_package_v1(
    kind: Ed25519YaoPackageKindV1,
    deriver: Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    transcript: [u8; 32],
    recipient_public_key: [u8; 32],
    plaintext: &[u8],
) -> RouterAbProtocolResult<Ed25519YaoEncryptedPackageV1> {
    if plaintext.is_empty() {
        return Err(invalid_delivery("recipient package plaintext is empty"));
    }
    let public_key =
        DhKemX25519HkdfSha256::pk_from_bytes(&recipient_public_key).map_err(map_hpke_error)?;
    let aad = ed25519_yao_recipient_package_aad_v1(kind, deriver, session, transcript);
    let mut os_rng = OsRng;
    let mut rng = os_rng.unwrap_mut();
    let (encapsulated_key, ciphertext) = RecipientHpkeV1::seal_base(
        &mut rng,
        &public_key,
        ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1,
        &aad,
        plaintext,
    )
    .map_err(map_hpke_error)?;
    let encapsulated_key: [u8; 32] = encapsulated_key
        .as_ref()
        .try_into()
        .map_err(|_| invalid_delivery("HPKE encapsulated key has wrong length"))?;
    Ed25519YaoEncryptedPackageV1::new(
        kind,
        deriver,
        session,
        transcript,
        encapsulated_key,
        ciphertext,
    )
}

pub fn open_local_ed25519_yao_client_package_v1(
    envelope: &Ed25519YaoEncryptedPackageV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
    if !envelope.kind().is_client() {
        return Err(invalid_delivery(
            "Client cannot open a SigningWorker recipient package",
        ));
    }
    open_package(envelope, private_key)
}

pub fn open_local_ed25519_yao_signing_worker_package_v1(
    envelope: &Ed25519YaoEncryptedPackageV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
    if envelope.kind() != Ed25519YaoPackageKindV1::ActivationSigningWorker {
        return Err(invalid_delivery(
            "SigningWorker cannot open a Client recipient package",
        ));
    }
    open_package(envelope, private_key)
}

fn open_package(
    envelope: &Ed25519YaoEncryptedPackageV1,
    private_key: &LocalEd25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
    envelope.validate()?;
    let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(envelope.encapsulated_key())
        .map_err(map_hpke_error)?;
    let private_key =
        DhKemX25519HkdfSha256::sk_from_bytes(private_key.as_bytes()).map_err(map_hpke_error)?;
    let aad = ed25519_yao_recipient_package_aad_v1(
        envelope.kind(),
        envelope.deriver(),
        envelope.session(),
        envelope.transcript(),
    );
    RecipientHpkeV1::open_base(
        &encapsulated_key,
        &private_key,
        ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1,
        &aad,
        envelope.ciphertext(),
    )
    .map(Zeroizing::new)
    .map_err(map_hpke_error)
}

fn key_pair_from_hpke(
    private_key: <DhKemX25519HkdfSha256 as Kem>::PrivateKey,
    public_key: <DhKemX25519HkdfSha256 as Kem>::PublicKey,
) -> RouterAbProtocolResult<LocalEd25519YaoRecipientKeyPairV1> {
    let private_bytes = DhKemX25519HkdfSha256::sk_to_bytes(&private_key);
    let private_bytes: [u8; 32] = private_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_delivery("HPKE private key has wrong length"))?;
    let public_bytes = DhKemX25519HkdfSha256::pk_to_bytes(&public_key);
    let public_key: [u8; 32] = public_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_delivery("HPKE public key has wrong length"))?;
    Ok(LocalEd25519YaoRecipientKeyPairV1 {
        private_key: LocalEd25519YaoRecipientPrivateKeyV1(private_bytes),
        public_key,
    })
}

fn map_hpke_error(error: hpke_ng::HpkeError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("local Ed25519 Yao recipient HPKE failed: {error}"),
    )
}

fn invalid_delivery(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        message,
    )
}
