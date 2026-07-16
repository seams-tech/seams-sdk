use base64ct::{Base64UrlUnpadded, Encoding};
use hpke_ng::{DhKemX25519HkdfSha256, Kem};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::{
    seal_ecdsa_signer_envelope_v1, EcdsaClientProtocolError, EcdsaDeriverRoleV1,
    EcdsaRoleEnvelopeAadV1, EcdsaSelectedServerIdentityV1, EcdsaSignerEnvelopePublicKeyV1,
    EcdsaSignerIdentityV1,
};

const CONTEXT_DOMAIN_V1: &[u8] = b"router-ab-ecdsa-derivation/context/v1";
const CONTEXT_BINDING_DOMAIN_V1: &[u8] =
    b"router-ab-ecdsa-derivation/role-local/context-binding/v1";
const CONTEXT_SCHEME_V1: &str = "router-ab-ecdsa-derivation-v1";
const CONTEXT_CURVE_V1: &str = "secp256k1";
const REGISTRATION_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/registration-request/v1";
const DERIVER_PLAINTEXT_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/deriver-envelope-plaintext/v1";
const ROLE_ENCRYPTED_ENVELOPE_DIGEST_VERSION_V1: &[u8] =
    b"router-ab-protocol/role-encrypted-envelope-digest/v1";
const DERIVATION_CONTEXT_VERSION_V1: &[u8] = b"router-ab-ecdsa-threshold-prf/context/v1";
const DERIVATION_TRANSCRIPT_VERSION_V1: &[u8] = b"router-ab-derivation/transcript/v1";
const REGISTRATION_WORK_KIND_V1: &str = "registration_prepare";
const REGISTRATION_PRIMITIVE_KIND_V1: &str = "registration";
const REGISTRATION_REQUEST_KIND_V1: &str = "registration_bootstrap";
const SIGNING_WORKER_OUTPUT_KIND_V1: &str = "signing_worker_activation";
const KEY_SCOPE_V1: &str = "evm-family";
const SIGNER_SET_POLICY_V1: &str = "all_2";
const TRANSCRIPT_SIGNER_SET_POLICY_V1: &str = "all(2)";

/// Product lifecycle purpose for a client-built ECDSA registration request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaRegistrationPurposeV1 {
    /// Bootstrap the first ECDSA signer during wallet registration.
    WalletRegistration,
    /// Bootstrap an additional ECDSA signer for an existing wallet.
    WalletAddSigner,
}

impl EcdsaRegistrationPurposeV1 {
    /// Parses an exact public registration-purpose label.
    pub fn from_wire_label(label: &str) -> Result<Self, EcdsaClientProtocolError> {
        match label {
            "wallet_registration" => Ok(Self::WalletRegistration),
            "wallet_add_signer" => Ok(Self::WalletAddSigner),
            _ => Err(EcdsaClientProtocolError::InvalidShape),
        }
    }

    /// Returns the canonical public registration-purpose label.
    pub fn wire_label(self) -> &'static str {
        match self {
            Self::WalletRegistration => "wallet_registration",
            Self::WalletAddSigner => "wallet_add_signer",
        }
    }
}

/// Stable application binding used by ECDSA registration and later ceremonies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaStableKeyContextV1 {
    application_binding_digest_b64u: String,
    application_binding_digest: [u8; 32],
}

impl EcdsaStableKeyContextV1 {
    /// Parses and validates an unpadded base64url application-binding digest.
    pub fn new(
        application_binding_digest_b64u: impl Into<String>,
    ) -> Result<Self, EcdsaClientProtocolError> {
        let application_binding_digest_b64u = application_binding_digest_b64u.into();
        let decoded = Base64UrlUnpadded::decode_vec(&application_binding_digest_b64u)
            .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
        let application_binding_digest = decoded
            .try_into()
            .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
        Ok(Self {
            application_binding_digest_b64u,
            application_binding_digest,
        })
    }

    /// Returns the unpadded base64url application-binding digest.
    pub fn application_binding_digest_b64u(&self) -> &str {
        &self.application_binding_digest_b64u
    }

    /// Returns canonical backend-compatible stable-context bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        let mut output = Vec::new();
        output.extend_from_slice(CONTEXT_DOMAIN_V1);
        push_ascii_u16(&mut output, CONTEXT_SCHEME_V1)?;
        push_ascii_u16(&mut output, CONTEXT_CURVE_V1)?;
        output.extend_from_slice(&self.application_binding_digest);
        output.push(2);
        output.extend_from_slice(&1_u16.to_be_bytes());
        output.extend_from_slice(&2_u16.to_be_bytes());
        Ok(output)
    }

    /// Returns the stable context-binding digest used by public identities.
    pub fn binding_digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        let context = self.canonical_bytes()?;
        let length =
            u16::try_from(context.len()).map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
        let mut frame = Vec::new();
        frame.extend_from_slice(CONTEXT_BINDING_DOMAIN_V1);
        frame.push(1);
        frame.push(1);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&context);
        sha256(&frame)
    }
}

/// Raw lifecycle labels and fields accepted at the registration boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRegistrationLifecycleWireV1 {
    /// Router-assigned lifecycle id.
    pub lifecycle_id: String,
    /// Product work-kind label.
    pub work_kind: String,
    /// Primitive request-kind label.
    pub primitive_request_kind: String,
    /// Public signing-root share epoch.
    pub root_share_epoch: String,
    /// Canonical wallet or account id.
    pub account_id: String,
    /// Canonical session id.
    pub session_id: String,
    /// Transcript-bound signer-set id.
    pub signer_set_id: String,
    /// Selected SigningWorker id.
    pub selected_server_id: String,
}

/// Registration-only lifecycle state with fixed work and primitive kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRegistrationLifecycleV1 {
    lifecycle_id: String,
    root_share_epoch: String,
    account_id: String,
    session_id: String,
    signer_set_id: String,
    selected_server_id: String,
}

impl EcdsaRegistrationLifecycleV1 {
    /// Parses an untrusted lifecycle and rejects unknown or mismatched kinds.
    pub fn from_wire(
        wire: EcdsaRegistrationLifecycleWireV1,
    ) -> Result<Self, EcdsaClientProtocolError> {
        if wire.work_kind != REGISTRATION_WORK_KIND_V1
            || wire.primitive_request_kind != REGISTRATION_PRIMITIVE_KIND_V1
        {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        require_fields_non_empty(&[
            &wire.lifecycle_id,
            &wire.root_share_epoch,
            &wire.account_id,
            &wire.session_id,
            &wire.signer_set_id,
            &wire.selected_server_id,
        ])?;
        Ok(Self {
            lifecycle_id: wire.lifecycle_id,
            root_share_epoch: wire.root_share_epoch,
            account_id: wire.account_id,
            session_id: wire.session_id,
            signer_set_id: wire.signer_set_id,
            selected_server_id: wire.selected_server_id,
        })
    }

    /// Returns the Router-assigned lifecycle id.
    pub fn lifecycle_id(&self) -> &str {
        &self.lifecycle_id
    }

    /// Returns the fixed registration work-kind label.
    pub fn work_kind(&self) -> &'static str {
        REGISTRATION_WORK_KIND_V1
    }

    /// Returns the fixed registration primitive-kind label.
    pub fn primitive_request_kind(&self) -> &'static str {
        REGISTRATION_PRIMITIVE_KIND_V1
    }

    /// Returns the signing-root share epoch.
    pub fn root_share_epoch(&self) -> &str {
        &self.root_share_epoch
    }

    /// Returns the canonical wallet or account id.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Returns the canonical session id.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the transcript-bound signer-set id.
    pub fn signer_set_id(&self) -> &str {
        &self.signer_set_id
    }

    /// Returns the selected SigningWorker id.
    pub fn selected_server_id(&self) -> &str {
        &self.selected_server_id
    }
}

/// Strict all(2) signer set selected for registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRegistrationSignerSetV1 {
    signer_set_id: String,
    signer_a: EcdsaSignerIdentityV1,
    signer_b: EcdsaSignerIdentityV1,
    selected_server: EcdsaSelectedServerIdentityV1,
}

impl EcdsaRegistrationSignerSetV1 {
    /// Creates a validated all(2) A/B signer set.
    pub fn new(
        signer_set_id: impl Into<String>,
        signer_a: EcdsaSignerIdentityV1,
        signer_b: EcdsaSignerIdentityV1,
        selected_server: EcdsaSelectedServerIdentityV1,
    ) -> Result<Self, EcdsaClientProtocolError> {
        let signer_set = Self {
            signer_set_id: signer_set_id.into(),
            signer_a,
            signer_b,
            selected_server,
        };
        signer_set.validate()?;
        Ok(signer_set)
    }

    /// Returns the canonical signer-set id.
    pub fn signer_set_id(&self) -> &str {
        &self.signer_set_id
    }

    /// Returns Deriver A identity.
    pub fn signer_a(&self) -> &EcdsaSignerIdentityV1 {
        &self.signer_a
    }

    /// Returns Deriver B identity.
    pub fn signer_b(&self) -> &EcdsaSignerIdentityV1 {
        &self.signer_b
    }

    /// Returns the selected SigningWorker identity.
    pub fn selected_server(&self) -> &EcdsaSelectedServerIdentityV1 {
        &self.selected_server
    }

    fn validate(&self) -> Result<(), EcdsaClientProtocolError> {
        require_fields_non_empty(&[
            &self.signer_set_id,
            &self.signer_a.signer_id,
            &self.signer_a.key_epoch,
            &self.signer_b.signer_id,
            &self.signer_b.key_epoch,
            &self.selected_server.server_id,
            &self.selected_server.key_epoch,
            &self.selected_server.recipient_encryption_key,
        ])?;
        if self.signer_a.role != EcdsaDeriverRoleV1::A
            || self.signer_b.role != EcdsaDeriverRoleV1::B
            || self.signer_a.signer_id == self.signer_b.signer_id
        {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        Ok(())
    }

    fn signer(&self, role: EcdsaDeriverRoleV1) -> &EcdsaSignerIdentityV1 {
        match role {
            EcdsaDeriverRoleV1::A => &self.signer_a,
            EcdsaDeriverRoleV1::B => &self.signer_b,
        }
    }
}

/// Validated public fields used to construct a registration header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRegistrationHeaderInputV1 {
    /// Product registration purpose.
    pub registration_purpose: EcdsaRegistrationPurposeV1,
    /// Stable application binding.
    pub context: EcdsaStableKeyContextV1,
    /// Registration-only lifecycle.
    pub lifecycle: EcdsaRegistrationLifecycleV1,
    /// Selected strict all(2) signer set.
    pub signer_set: EcdsaRegistrationSignerSetV1,
    /// Router identity bound into the transcript.
    pub router_id: String,
    /// Client identity bound into the transcript.
    pub client_id: String,
    /// Client ephemeral X25519 public key.
    pub client_ephemeral_public_key: String,
    /// Request-scoped replay nonce.
    pub replay_nonce: String,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Compressed client secp256k1 public key in unpadded base64url.
    pub derivation_client_share_public_key33_b64u: String,
    /// Client-share retry counter.
    pub client_share_retry_counter: u32,
}

/// Canonical public registration header committed before envelope sealing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRegistrationHeaderV1 {
    input: EcdsaRegistrationHeaderInputV1,
}

impl EcdsaRegistrationHeaderV1 {
    /// Creates a header after checking cross-field lifecycle and signer bindings.
    pub fn new(input: EcdsaRegistrationHeaderInputV1) -> Result<Self, EcdsaClientProtocolError> {
        input.signer_set.validate()?;
        require_ascii_fields(&[
            &input.router_id,
            &input.client_id,
            &input.client_ephemeral_public_key,
            &input.replay_nonce,
        ])?;
        validate_compressed_public_key_b64u(&input.derivation_client_share_public_key33_b64u)?;
        if input.expires_at_ms == 0
            || input.lifecycle.signer_set_id != input.signer_set.signer_set_id
            || input.lifecycle.selected_server_id != input.signer_set.selected_server.server_id
        {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        Ok(Self { input })
    }

    /// Returns the product registration purpose.
    pub fn registration_purpose(&self) -> EcdsaRegistrationPurposeV1 {
        self.input.registration_purpose
    }

    /// Returns the stable application binding.
    pub fn context(&self) -> &EcdsaStableKeyContextV1 {
        &self.input.context
    }

    /// Returns the registration lifecycle.
    pub fn lifecycle(&self) -> &EcdsaRegistrationLifecycleV1 {
        &self.input.lifecycle
    }

    /// Returns the selected signer set.
    pub fn signer_set(&self) -> &EcdsaRegistrationSignerSetV1 {
        &self.input.signer_set
    }

    /// Returns the Router identity.
    pub fn router_id(&self) -> &str {
        &self.input.router_id
    }

    /// Returns the client identity.
    pub fn client_id(&self) -> &str {
        &self.input.client_id
    }

    /// Returns the client ephemeral public key.
    pub fn client_ephemeral_public_key(&self) -> &str {
        &self.input.client_ephemeral_public_key
    }

    /// Returns the replay nonce.
    pub fn replay_nonce(&self) -> &str {
        &self.input.replay_nonce
    }

    /// Returns the request expiry.
    pub fn expires_at_ms(&self) -> u64 {
        self.input.expires_at_ms
    }

    /// Returns the compressed client secp256k1 public key.
    pub fn derivation_client_share_public_key33_b64u(&self) -> &str {
        &self.input.derivation_client_share_public_key33_b64u
    }

    /// Returns the client-share retry counter.
    pub fn client_share_retry_counter(&self) -> u32 {
        self.input.client_share_retry_counter
    }

    /// Returns canonical backend-compatible pre-envelope header bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        let mut output = Vec::new();
        push_bytes(&mut output, REGISTRATION_REQUEST_VERSION_V1);
        push_bytes(
            &mut output,
            self.input.registration_purpose.wire_label().as_bytes(),
        );
        push_bytes(&mut output, &self.input.context.canonical_bytes()?);
        push_registration_lifecycle(&mut output, &self.input.lifecycle);
        push_signer_set(&mut output, &self.input.signer_set);
        push_bytes(&mut output, self.input.router_id.as_bytes());
        push_bytes(&mut output, self.input.client_id.as_bytes());
        push_bytes(
            &mut output,
            self.input.client_ephemeral_public_key.as_bytes(),
        );
        push_bytes(&mut output, self.input.replay_nonce.as_bytes());
        output.extend_from_slice(&self.input.expires_at_ms.to_be_bytes());
        push_bytes(
            &mut output,
            self.input
                .derivation_client_share_public_key33_b64u
                .as_bytes(),
        );
        output.extend_from_slice(&self.input.client_share_retry_counter.to_be_bytes());
        Ok(output)
    }

    /// Returns the SHA-256 pre-envelope header digest.
    pub fn digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        sha256(&self.canonical_bytes()?)
    }

    /// Returns the canonical threshold-PRF transcript digest.
    pub fn transcript_digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        let mut context = Vec::new();
        push_bytes(&mut context, DERIVATION_CONTEXT_VERSION_V1);
        push_bytes(&mut context, REGISTRATION_PRIMITIVE_KIND_V1.as_bytes());
        push_bytes(&mut context, KEY_SCOPE_V1.as_bytes());
        push_bytes(&mut context, self.input.lifecycle.account_id.as_bytes());
        push_bytes(
            &mut context,
            self.input
                .derivation_client_share_public_key33_b64u
                .as_bytes(),
        );
        push_bytes(
            &mut context,
            self.input.lifecycle.root_share_epoch.as_bytes(),
        );
        push_bytes(&mut context, self.input.lifecycle.lifecycle_id.as_bytes());

        let mut transcript = Vec::new();
        push_bytes(&mut transcript, DERIVATION_TRANSCRIPT_VERSION_V1);
        push_bytes(&mut transcript, &context);
        push_bytes(&mut transcript, self.input.router_id.as_bytes());
        push_bytes(
            &mut transcript,
            self.input.signer_set.signer_set_id.as_bytes(),
        );
        push_bytes(&mut transcript, TRANSCRIPT_SIGNER_SET_POLICY_V1.as_bytes());
        push_bytes(&mut transcript, b"2");
        push_transcript_signer(&mut transcript, 0, &self.input.signer_set.signer_a);
        push_transcript_signer(&mut transcript, 1, &self.input.signer_set.signer_b);
        push_bytes(
            &mut transcript,
            self.input.signer_set.selected_server.server_id.as_bytes(),
        );
        push_bytes(
            &mut transcript,
            self.input
                .signer_set
                .selected_server
                .recipient_encryption_key
                .as_bytes(),
        );
        push_bytes(&mut transcript, self.input.client_id.as_bytes());
        push_bytes(
            &mut transcript,
            self.input.client_ephemeral_public_key.as_bytes(),
        );
        sha256(&transcript)
    }

    /// Builds exact role-specific envelope AAD.
    pub fn role_aad(
        &self,
        role: EcdsaDeriverRoleV1,
    ) -> Result<EcdsaRoleEnvelopeAadV1, EcdsaClientProtocolError> {
        Ok(EcdsaRoleEnvelopeAadV1 {
            lifecycle_id: self.input.lifecycle.lifecycle_id.clone(),
            work_kind: REGISTRATION_WORK_KIND_V1.to_owned(),
            primitive_request_kind: REGISTRATION_PRIMITIVE_KIND_V1.to_owned(),
            signer_set_id: self.input.signer_set.signer_set_id.clone(),
            recipient: self.input.signer_set.signer(role).clone(),
            selected_server: self.input.signer_set.selected_server.clone(),
            transcript_digest: self.transcript_digest()?,
            router_request_digest: self.digest()?,
            expires_at_ms: self.input.expires_at_ms,
        })
    }

    fn deriver_plaintext(
        &self,
        role: EcdsaDeriverRoleV1,
        aad_digest: [u8; 32],
    ) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        let mut output = Vec::new();
        push_bytes(&mut output, DERIVER_PLAINTEXT_VERSION_V1);
        push_bytes(&mut output, REGISTRATION_REQUEST_KIND_V1.as_bytes());
        push_bytes(&mut output, SIGNING_WORKER_OUTPUT_KIND_V1.as_bytes());
        push_bytes(&mut output, &self.input.context.canonical_bytes()?);
        push_registration_lifecycle(&mut output, &self.input.lifecycle);
        push_signer_set(&mut output, &self.input.signer_set);
        push_signer_identity(&mut output, self.input.signer_set.signer(role));
        push_bytes(&mut output, self.input.router_id.as_bytes());
        push_bytes(&mut output, self.input.client_id.as_bytes());
        push_bytes(
            &mut output,
            self.input.client_ephemeral_public_key.as_bytes(),
        );
        output.extend_from_slice(&self.digest()?);
        output.extend_from_slice(&aad_digest);
        output.extend_from_slice(&self.input.expires_at_ms.to_be_bytes());
        push_bytes(
            &mut output,
            self.input.registration_purpose.wire_label().as_bytes(),
        );
        push_bytes(
            &mut output,
            self.input
                .derivation_client_share_public_key33_b64u
                .as_bytes(),
        );
        output.extend_from_slice(&self.input.client_share_retry_counter.to_be_bytes());
        Ok(output)
    }
}

/// Public Deriver recipient keys authenticated by deployment configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRegistrationRecipientKeysV1 {
    /// Deriver A recipient key.
    pub deriver_a: EcdsaSignerEnvelopePublicKeyV1,
    /// Deriver B recipient key.
    pub deriver_b: EcdsaSignerEnvelopePublicKeyV1,
}

/// Independent deterministic sealing seeds supplied by the client worker CSPRNG.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct EcdsaRegistrationSealSeedsV1 {
    /// Deriver A HPKE sealing seed.
    pub deriver_a: [u8; 32],
    /// Deriver B HPKE sealing seed.
    pub deriver_b: [u8; 32],
}

/// One canonical role-encrypted envelope in a client-built request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRegistrationEncryptedEnvelopeV1 {
    pub(super) recipient_role: EcdsaDeriverRoleV1,
    pub(super) header_digest: [u8; 32],
    pub(super) aad_digest: [u8; 32],
    pub(super) ciphertext: Vec<u8>,
}

impl EcdsaRegistrationEncryptedEnvelopeV1 {
    /// Returns the recipient Deriver role.
    pub fn recipient_role(&self) -> EcdsaDeriverRoleV1 {
        self.recipient_role
    }

    /// Returns the exact registration-header digest.
    pub fn header_digest(&self) -> [u8; 32] {
        self.header_digest
    }

    /// Returns the exact role-envelope AAD digest.
    pub fn aad_digest(&self) -> [u8; 32] {
        self.aad_digest
    }

    /// Returns canonical signer-envelope HPKE payload bytes.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the canonical backend-compatible envelope digest.
    pub fn digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        if self.ciphertext.is_empty() {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        let mut output = Vec::new();
        push_bytes(&mut output, ROLE_ENCRYPTED_ENVELOPE_DIGEST_VERSION_V1);
        push_bytes(&mut output, self.recipient_role.wire_label().as_bytes());
        push_bytes(&mut output, &self.header_digest);
        push_bytes(&mut output, &self.aad_digest);
        push_bytes(&mut output, &self.ciphertext);
        sha256(&output)
    }
}

/// Complete client-built strict Router A/B ECDSA registration request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRegistrationRequestV1 {
    header: EcdsaRegistrationHeaderV1,
    deriver_a_envelope: EcdsaRegistrationEncryptedEnvelopeV1,
    deriver_b_envelope: EcdsaRegistrationEncryptedEnvelopeV1,
}

impl EcdsaRegistrationRequestV1 {
    /// Returns the committed public header.
    pub fn header(&self) -> &EcdsaRegistrationHeaderV1 {
        &self.header
    }

    /// Returns the Deriver A envelope.
    pub fn deriver_a_envelope(&self) -> &EcdsaRegistrationEncryptedEnvelopeV1 {
        &self.deriver_a_envelope
    }

    /// Returns the Deriver B envelope.
    pub fn deriver_b_envelope(&self) -> &EcdsaRegistrationEncryptedEnvelopeV1 {
        &self.deriver_b_envelope
    }

    /// Rejects a request presented to a route for another registration purpose.
    pub fn validate_for_registration_purpose(
        &self,
        expected: EcdsaRegistrationPurposeV1,
    ) -> Result<(), EcdsaClientProtocolError> {
        if self.header.registration_purpose() != expected {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        Ok(())
    }

    /// Returns canonical request bytes including both envelope digests.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        let mut output = self.header.canonical_bytes()?;
        output.extend_from_slice(&self.deriver_a_envelope.digest()?);
        output.extend_from_slice(&self.deriver_b_envelope.digest()?);
        Ok(output)
    }

    /// Returns the canonical registration request digest.
    pub fn digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        sha256(&self.canonical_bytes()?)
    }
}

/// Builds and seals one exact strict Router A/B ECDSA registration request.
pub fn build_ecdsa_registration_request_v1(
    header: EcdsaRegistrationHeaderV1,
    recipient_keys: EcdsaRegistrationRecipientKeysV1,
    seal_seeds: EcdsaRegistrationSealSeedsV1,
) -> Result<EcdsaRegistrationRequestV1, EcdsaClientProtocolError> {
    validate_recipient_key(&recipient_keys.deriver_a, header.signer_set().signer_a())?;
    validate_recipient_key(&recipient_keys.deriver_b, header.signer_set().signer_b())?;
    let deriver_a_envelope =
        seal_registration_role(&header, &recipient_keys.deriver_a, seal_seeds.deriver_a)?;
    let deriver_b_envelope =
        seal_registration_role(&header, &recipient_keys.deriver_b, seal_seeds.deriver_b)?;
    Ok(EcdsaRegistrationRequestV1 {
        header,
        deriver_a_envelope,
        deriver_b_envelope,
    })
}

/// Worker-owned X25519 keypair for encrypted client-output delivery.
pub struct EcdsaClientEphemeralKeyPairV1 {
    private_key: Zeroizing<[u8; 32]>,
    public_key: String,
}

impl EcdsaClientEphemeralKeyPairV1 {
    /// Returns the public key carried by registration and transcript metadata.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Borrows private key bytes for a Rust-only worker proof-opening operation.
    pub fn private_key_bytes(&self) -> &[u8; 32] {
        &self.private_key
    }
}

/// Derives an ephemeral X25519 keypair from worker-supplied CSPRNG seed material.
pub fn derive_ecdsa_client_ephemeral_keypair_v1(
    seed: [u8; 32],
) -> Result<EcdsaClientEphemeralKeyPairV1, EcdsaClientProtocolError> {
    let (private_key, public_key) = DhKemX25519HkdfSha256::derive_key_pair(&seed)
        .map_err(|_| EcdsaClientProtocolError::HpkeFailed)?;
    let private_key = DhKemX25519HkdfSha256::sk_to_bytes(&private_key)
        .as_slice()
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::HpkeFailed)?;
    let public_key_bytes = DhKemX25519HkdfSha256::pk_to_bytes(&public_key);
    let public_key = format!("x25519:{}", lower_hex(public_key_bytes.as_slice()),);
    Ok(EcdsaClientEphemeralKeyPairV1 {
        private_key: Zeroizing::new(private_key),
        public_key,
    })
}

fn seal_registration_role(
    header: &EcdsaRegistrationHeaderV1,
    recipient_key: &EcdsaSignerEnvelopePublicKeyV1,
    seal_seed: [u8; 32],
) -> Result<EcdsaRegistrationEncryptedEnvelopeV1, EcdsaClientProtocolError> {
    let aad = header.role_aad(recipient_key.role)?;
    let aad_digest = aad.digest()?;
    let plaintext = header.deriver_plaintext(recipient_key.role, aad_digest)?;
    let payload = seal_ecdsa_signer_envelope_v1(recipient_key, &aad, &plaintext, seal_seed)?;
    Ok(EcdsaRegistrationEncryptedEnvelopeV1 {
        recipient_role: recipient_key.role,
        header_digest: header.digest()?,
        aad_digest,
        ciphertext: payload.canonical_bytes()?,
    })
}

pub(super) fn validate_recipient_key(
    key: &EcdsaSignerEnvelopePublicKeyV1,
    signer: &EcdsaSignerIdentityV1,
) -> Result<(), EcdsaClientProtocolError> {
    if key.role != signer.role || key.key_epoch != signer.key_epoch {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

fn validate_compressed_public_key_b64u(value: &str) -> Result<(), EcdsaClientProtocolError> {
    let bytes =
        Base64UrlUnpadded::decode_vec(value).map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    if bytes.len() != 33 || !matches!(bytes[0], 0x02 | 0x03) {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

pub(super) fn push_registration_lifecycle(
    output: &mut Vec<u8>,
    lifecycle: &EcdsaRegistrationLifecycleV1,
) {
    push_bytes(output, lifecycle.lifecycle_id.as_bytes());
    push_bytes(output, REGISTRATION_WORK_KIND_V1.as_bytes());
    push_bytes(output, REGISTRATION_PRIMITIVE_KIND_V1.as_bytes());
    push_bytes(output, lifecycle.root_share_epoch.as_bytes());
    push_bytes(output, lifecycle.account_id.as_bytes());
    push_bytes(output, lifecycle.session_id.as_bytes());
    push_bytes(output, lifecycle.signer_set_id.as_bytes());
    push_bytes(output, lifecycle.selected_server_id.as_bytes());
}

pub(super) fn push_signer_set(output: &mut Vec<u8>, signer_set: &EcdsaRegistrationSignerSetV1) {
    push_bytes(output, signer_set.signer_set_id.as_bytes());
    push_bytes(output, SIGNER_SET_POLICY_V1.as_bytes());
    push_bytes(output, signer_set.signer_a.signer_id.as_bytes());
    push_bytes(output, signer_set.signer_a.key_epoch.as_bytes());
    push_bytes(output, signer_set.signer_b.signer_id.as_bytes());
    push_bytes(output, signer_set.signer_b.key_epoch.as_bytes());
    push_bytes(output, signer_set.selected_server.server_id.as_bytes());
    push_bytes(output, signer_set.selected_server.key_epoch.as_bytes());
    push_bytes(
        output,
        signer_set
            .selected_server
            .recipient_encryption_key
            .as_bytes(),
    );
}

pub(super) fn push_signer_identity(output: &mut Vec<u8>, signer: &EcdsaSignerIdentityV1) {
    push_bytes(output, signer.role.wire_label().as_bytes());
    push_bytes(output, signer.signer_id.as_bytes());
    push_bytes(output, signer.key_epoch.as_bytes());
}

fn push_transcript_signer(output: &mut Vec<u8>, index: u8, signer: &EcdsaSignerIdentityV1) {
    push_bytes(output, index.to_string().as_bytes());
    push_signer_identity(output, signer);
}

fn push_ascii_u16(output: &mut Vec<u8>, value: &str) -> Result<(), EcdsaClientProtocolError> {
    if value.is_empty() || !value.is_ascii() {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let length = u16::try_from(value.len()).map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

pub(super) fn push_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

pub(super) fn require_fields_non_empty(values: &[&str]) -> Result<(), EcdsaClientProtocolError> {
    if values.iter().any(|value| value.is_empty()) {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

pub(super) fn require_ascii_fields(values: &[&str]) -> Result<(), EcdsaClientProtocolError> {
    if values
        .iter()
        .any(|value| value.is_empty() || !value.is_ascii())
    {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

pub(super) fn sha256(bytes: &[u8]) -> Result<[u8; 32], EcdsaClientProtocolError> {
    Sha256::digest(bytes)
        .as_slice()
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
