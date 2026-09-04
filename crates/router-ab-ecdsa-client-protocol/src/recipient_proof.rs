use super::*;

const RECIPIENT_PROOF_BUNDLE_CIPHERTEXT_VERSION_V1: &[u8] =
    b"router-ab-protocol/recipient-proof-bundle-ciphertext/v1";
const RECIPIENT_PROOF_BUNDLE_CIPHERTEXT_AAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/recipient-proof-bundle-ciphertext-aad/v1";
const RECIPIENT_PROOF_BUNDLE_PAYLOAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/recipient-proof-bundle-payload/v1";
const ECDSA_THRESHOLD_PRF_PROOF_BATCH_PAYLOAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/ecdsa-threshold-prf-proof-batch-payload/v1";
const MPC_PRF_STABLE_PROOF_BUNDLE_WIRE_VERSION_V2: &[u8] =
    b"router-ab-protocol/mpc-prf-stable-proof-bundle-wire/v2";
const MPC_PRF_STABLE_RECIPIENT_PROOF_BUNDLE_PAYLOAD_VERSION_V2: &[u8] =
    b"router-ab-protocol/mpc-prf-stable-recipient-proof-bundle-payload/v2";
const RECIPIENT_PROOF_BUNDLE_HPKE_INFO_V1: &[u8] =
    b"router-ab-cloudflare/recipient-proof-bundle/hpke-x25519-hkdf-sha256-aes256gcm/v1";
const RECIPIENT_PROOF_BUNDLE_ALGORITHM_V1: &[u8] = b"hpke_x25519_hkdf_sha256_aes256gcm_v1";
const MPC_PRF_SUITE_ID_V1: &[u8] = b"threshold_prf_ristretto255_sha512";
const MPC_PRF_CONTEXT_BYTES_VERSION_V1: &[u8] = b"router-ab-derivation/mpc-prf/context-bytes/v1";
const MPC_PRF_OUTPUT_ENCODING_V1: &[u8] = b"canonical_ed25519_scalar_32";
const CLIENT_ROLE_V1: &[u8] = b"client";
const X_CLIENT_BASE_V1: &[u8] = b"x_client_base";
const RECIPIENT_PROOF_BUNDLE_NONCE_LEN_V1: usize = 12;

/// One strict public Router proof-bundle envelope addressed to the browser client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaClientProofBundleEnvelopeV1 {
    /// Deriver that produced the encrypted proof bundle.
    pub signer: EcdsaSignerIdentityV1,
    /// Exact client identity selected by the ceremony.
    pub recipient_identity: String,
    /// Canonical `x25519:<64 lowercase hex chars>` client ephemeral public key.
    pub recipient_public_key: String,
    /// Exact Router transcript digest.
    pub transcript_digest: [u8; 32],
    /// Digest of the canonical encrypted payload.
    pub payload_digest: [u8; 32],
    /// Public fixed-width envelope nonce committed into HPKE AAD.
    pub nonce: [u8; RECIPIENT_PROOF_BUNDLE_NONCE_LEN_V1],
    /// HPKE encapsulated key followed by ciphertext and authentication tag.
    pub ciphertext_and_tag: Vec<u8>,
}

impl EcdsaClientProofBundleEnvelopeV1 {
    fn validate(&self) -> Result<(), EcdsaClientProtocolError> {
        require_non_empty(&self.signer.signer_id)?;
        require_non_empty(&self.signer.key_epoch)?;
        require_non_empty(&self.recipient_identity)?;
        decode_x25519_public_key(&self.recipient_public_key)?;
        if self.ciphertext_and_tag.len()
            <= DhKemX25519HkdfSha256::ENCAPPED_KEY_LEN + SIGNER_ENVELOPE_HPKE_TAG_LEN_V1
        {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        Ok(())
    }

    fn aad_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        self.validate()?;
        let mut out = Vec::new();
        push_bytes(&mut out, RECIPIENT_PROOF_BUNDLE_CIPHERTEXT_AAD_VERSION_V1);
        push_bytes(&mut out, PRF_SUITE_V1);
        push_bytes(&mut out, RECIPIENT_PROOF_BUNDLE_ALGORITHM_V1);
        push_signer_identity(&mut out, &self.signer);
        push_bytes(&mut out, CLIENT_ROLE_V1);
        push_bytes(&mut out, X_CLIENT_BASE_V1);
        push_string(&mut out, &self.recipient_identity);
        push_string(&mut out, &self.recipient_public_key);
        push_bytes(&mut out, &self.transcript_digest);
        push_bytes(&mut out, &self.payload_digest);
        push_bytes(&mut out, &self.nonce);
        Ok(out)
    }
}

/// Decrypted and fully binding-checked client proof bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaOpenedClientProofBundleV1 {
    /// Exact lifecycle that produced the proof.
    pub lifecycle_id: String,
    /// Exact root-share epoch used by the Deriver.
    pub root_share_epoch: String,
    /// Exact Router transcript digest.
    pub transcript_digest: [u8; 32],
    /// Exact client recipient identity.
    pub recipient_identity: String,
    /// Exact Deriver identity that produced the proof.
    pub signer: EcdsaSignerIdentityV1,
    /// Exact opposite Deriver identity authenticated inside the proof batch.
    pub peer: EcdsaSignerIdentityV1,
    /// Role-bound public proof material accepted by the client finalizer.
    pub role_bound_proof: EcdsaRoleBoundPrfProofV1,
}

/// Exact A/B client proof-bundle pair accepted for one finalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaOpenedClientProofBundlePairV1 {
    signer_a: EcdsaOpenedClientProofBundleV1,
    signer_b: EcdsaOpenedClientProofBundleV1,
}

impl EcdsaOpenedClientProofBundlePairV1 {
    /// Returns the exact Deriver A proof bundle.
    pub fn signer_a(&self) -> &EcdsaOpenedClientProofBundleV1 {
        &self.signer_a
    }

    /// Returns the exact Deriver B proof bundle.
    pub fn signer_b(&self) -> &EcdsaOpenedClientProofBundleV1 {
        &self.signer_b
    }

    /// Builds the exact threshold-PRF public context for this pair.
    pub fn prf_context(&self) -> Result<EcdsaPrfPublicContextV1, EcdsaClientProtocolError> {
        ecdsa_client_prf_public_context_v1(
            self.signer_a.transcript_digest,
            &self.signer_a.recipient_identity,
        )
    }
}

/// Requires two opened client proof bundles to describe one exact A/B lifecycle.
pub fn pair_ecdsa_opened_client_proof_bundles_v1(
    signer_a: EcdsaOpenedClientProofBundleV1,
    signer_b: EcdsaOpenedClientProofBundleV1,
) -> Result<EcdsaOpenedClientProofBundlePairV1, EcdsaClientProtocolError> {
    if signer_a.role_bound_proof.role != EcdsaDeriverRoleV1::A
        || signer_b.role_bound_proof.role != EcdsaDeriverRoleV1::B
        || signer_a.signer.role != EcdsaDeriverRoleV1::A
        || signer_b.signer.role != EcdsaDeriverRoleV1::B
        || signer_a.lifecycle_id != signer_b.lifecycle_id
        || signer_a.root_share_epoch != signer_b.root_share_epoch
        || signer_a.transcript_digest != signer_b.transcript_digest
        || signer_a.recipient_identity != signer_b.recipient_identity
        || signer_a.peer != signer_b.signer
        || signer_b.peer != signer_a.signer
    {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(EcdsaOpenedClientProofBundlePairV1 { signer_a, signer_b })
}

/// Decodes one strict Router `recipient_proof_bundle` wire payload.
pub fn decode_ecdsa_client_proof_bundle_envelope_v1(
    bytes: &[u8],
) -> Result<EcdsaClientProofBundleEnvelopeV1, EcdsaClientProtocolError> {
    let mut decoder = Decoder::new(bytes);
    decoder.expect_bytes(RECIPIENT_PROOF_BUNDLE_CIPHERTEXT_VERSION_V1)?;
    decoder.expect_bytes(RECIPIENT_PROOF_BUNDLE_ALGORITHM_V1)?;
    let signer = decoder.read_signer_identity()?;
    decoder.expect_bytes(CLIENT_ROLE_V1)?;
    decoder.expect_bytes(X_CLIENT_BASE_V1)?;
    let recipient_identity = decoder.read_string()?;
    let recipient_public_key = decoder.read_string()?;
    let transcript_digest = decoder.read_fixed::<32>()?;
    let payload_digest = decoder.read_fixed::<32>()?;
    let nonce = decoder.read_fixed::<RECIPIENT_PROOF_BUNDLE_NONCE_LEN_V1>()?;
    let ciphertext_and_tag = decoder.read_bytes()?.to_vec();
    decoder.finish()?;
    let envelope = EcdsaClientProofBundleEnvelopeV1 {
        signer,
        recipient_identity,
        recipient_public_key,
        transcript_digest,
        payload_digest,
        nonce,
        ciphertext_and_tag,
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Opens one strict Router client proof bundle and verifies every public binding.
pub fn open_ecdsa_client_proof_bundle_v1(
    envelope: &EcdsaClientProofBundleEnvelopeV1,
    recipient_private_key: &[u8; 32],
) -> Result<EcdsaOpenedClientProofBundleV1, EcdsaClientProtocolError> {
    let plaintext = open_ecdsa_client_proof_bundle_payload_v1(envelope, recipient_private_key)?;
    decode_opened_client_payload(&plaintext, envelope)
}

/// Opens one recipient proof bundle and returns its authenticated plaintext.
///
/// The outer envelope remains V1 so callers can dispatch a newer inner payload
/// without duplicating HPKE or transport parsing.
fn open_ecdsa_client_proof_bundle_payload_v1(
    envelope: &EcdsaClientProofBundleEnvelopeV1,
    recipient_private_key: &[u8; 32],
) -> Result<Vec<u8>, EcdsaClientProtocolError> {
    envelope.validate()?;
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(recipient_private_key)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let (encapped_key, ciphertext) = envelope
        .ciphertext_and_tag
        .split_at(DhKemX25519HkdfSha256::ENCAPPED_KEY_LEN);
    let encapped_key = DhKemX25519HkdfSha256::enc_from_bytes(encapped_key)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let plaintext = SignerEnvelopeHpkeV1::open_base(
        &encapped_key,
        &private_key,
        RECIPIENT_PROOF_BUNDLE_HPKE_INFO_V1,
        &envelope.aad_bytes()?,
        ciphertext,
    )
    .map_err(|_| EcdsaClientProtocolError::HpkeFailed)?;
    let computed_payload_digest = digest32(&plaintext)?;
    if !bool::from(computed_payload_digest.ct_eq(&envelope.payload_digest)) {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(plaintext)
}

/// Opens one stable tenant-root client proof bundle in the existing outer
/// recipient envelope.
pub fn open_ecdsa_client_proof_bundle_v2(
    envelope: &EcdsaClientProofBundleEnvelopeV1,
    recipient_private_key: &[u8; 32],
) -> Result<EcdsaOpenedClientProofBundleV2, EcdsaClientProtocolError> {
    let plaintext = open_ecdsa_client_proof_bundle_payload_v1(envelope, recipient_private_key)?;
    let opened =
        decode_ecdsa_client_proof_bundle_payload_v2(&plaintext, envelope.transcript_digest)?;
    if opened.signer != envelope.signer || opened.recipient_identity != envelope.recipient_identity
    {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(opened)
}

/// Decodes one strict stable tenant-root client recipient payload.
pub(crate) fn decode_ecdsa_client_proof_bundle_payload_v2(
    bytes: &[u8],
    transcript_digest: [u8; 32],
) -> Result<EcdsaOpenedClientProofBundleV2, EcdsaClientProtocolError> {
    let mut decoder = Decoder::new(bytes);
    decoder.expect_bytes(MPC_PRF_STABLE_RECIPIENT_PROOF_BUNDLE_PAYLOAD_VERSION_V2)?;
    let signer = decoder.read_signer_identity()?;
    decoder.expect_bytes(CLIENT_ROLE_V1)?;
    let recipient_identity = decoder.read_string()?;
    let (proof_signer_role, stable_context_digest, custody_binding_digest, proof_bundle) =
        decode_stable_proof_bundle_wire_v2(decoder.read_bytes()?)?;
    decoder.finish()?;
    if proof_signer_role != signer.role {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(EcdsaOpenedClientProofBundleV2 {
        transcript_digest,
        signer,
        recipient_identity,
        proof: EcdsaStablePrfPublicProofBundleV2 {
            stable_context_digest,
            custody_binding_digest,
            proof: proof_bundle,
        },
    })
}

fn decode_stable_proof_bundle_wire_v2(
    bytes: &[u8],
) -> Result<
    (
        EcdsaDeriverRoleV1,
        [u8; 32],
        [u8; 32],
        EcdsaPrfPublicProofBundleV1,
    ),
    EcdsaClientProtocolError,
> {
    let mut decoder = Decoder::new(bytes);
    decoder.expect_bytes(MPC_PRF_STABLE_PROOF_BUNDLE_WIRE_VERSION_V2)?;
    let stable_context_digest = decoder.read_nonzero_fixed::<32>()?;
    let custody_binding_digest = decoder.read_nonzero_fixed::<32>()?;
    decoder.expect_bytes(EcdsaPrfPurposeV1::XClientBase.wire_label())?;
    let signer_role = decoder.read_deriver_role()?;
    let partial_wire = decoder.read_fixed::<66>()?;
    let commitment_wire = decoder.read_fixed::<34>()?;
    let proof_wire = decoder.read_fixed::<64>()?;
    decoder.finish()?;
    let partial_share_id = u16::from_be_bytes([partial_wire[0], partial_wire[1]]);
    let commitment_share_id = u16::from_be_bytes([commitment_wire[0], commitment_wire[1]]);
    let expected_share_id = match signer_role {
        EcdsaDeriverRoleV1::A => 1,
        EcdsaDeriverRoleV1::B => 2,
    };
    if partial_share_id != commitment_share_id || partial_share_id != expected_share_id {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok((
        signer_role,
        stable_context_digest,
        custody_binding_digest,
        EcdsaPrfPublicProofBundleV1 {
            partial_wire,
            commitment_wire,
            proof_wire,
        },
    ))
}

/// Builds the exact threshold-PRF context for one opened client proof bundle.
pub fn ecdsa_client_prf_public_context_v1(
    transcript_digest: [u8; 32],
    recipient_identity: &str,
) -> Result<EcdsaPrfPublicContextV1, EcdsaClientProtocolError> {
    require_non_empty(recipient_identity)?;
    let mut context_bytes = Vec::new();
    push_bytes(&mut context_bytes, MPC_PRF_CONTEXT_BYTES_VERSION_V1);
    push_bytes(&mut context_bytes, MPC_PRF_SUITE_ID_V1);
    push_bytes(&mut context_bytes, PRF_SUITE_V1);
    push_bytes(
        &mut context_bytes,
        EcdsaPrfPurposeV1::XClientBase.wire_label(),
    );
    push_bytes(&mut context_bytes, MPC_PRF_OUTPUT_ENCODING_V1);
    push_bytes(&mut context_bytes, &transcript_digest);
    push_bytes(&mut context_bytes, X_CLIENT_BASE_V1);
    push_bytes(&mut context_bytes, CLIENT_ROLE_V1);
    push_string(&mut context_bytes, recipient_identity);
    Ok(EcdsaPrfPublicContextV1 {
        purpose: EcdsaPrfPurposeV1::XClientBase,
        context_bytes,
    })
}

fn decode_opened_client_payload(
    plaintext: &[u8],
    envelope: &EcdsaClientProofBundleEnvelopeV1,
) -> Result<EcdsaOpenedClientProofBundleV1, EcdsaClientProtocolError> {
    let mut decoder = Decoder::new(plaintext);
    decoder.expect_bytes(RECIPIENT_PROOF_BUNDLE_PAYLOAD_VERSION_V1)?;
    let lifecycle_id = decoder.read_string()?;
    let payload_signer = decoder.read_signer_identity()?;
    decoder.expect_bytes(CLIENT_ROLE_V1)?;
    decoder.expect_bytes(X_CLIENT_BASE_V1)?;
    let recipient_identity = decoder.read_string()?;
    let transcript_digest = decoder.read_fixed::<32>()?;
    let proof_batch_bytes = decoder.read_bytes()?;
    decoder.finish()?;
    if payload_signer != envelope.signer
        || recipient_identity != envelope.recipient_identity
        || transcript_digest != envelope.transcript_digest
    {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let proof_batch = decode_client_proof_batch(proof_batch_bytes, envelope)?;
    Ok(EcdsaOpenedClientProofBundleV1 {
        lifecycle_id,
        root_share_epoch: proof_batch.root_share_epoch,
        transcript_digest,
        recipient_identity,
        signer: payload_signer,
        peer: proof_batch.peer,
        role_bound_proof: EcdsaRoleBoundPrfProofV1 {
            role: envelope.signer.role,
            proof: proof_batch.proof,
        },
    })
}

struct DecodedClientProofBatchV1 {
    root_share_epoch: String,
    peer: EcdsaSignerIdentityV1,
    proof: EcdsaPrfPublicProofBundleV1,
}

fn decode_client_proof_batch(
    bytes: &[u8],
    envelope: &EcdsaClientProofBundleEnvelopeV1,
) -> Result<DecodedClientProofBatchV1, EcdsaClientProtocolError> {
    let mut decoder = Decoder::new(bytes);
    decoder.expect_bytes(ECDSA_THRESHOLD_PRF_PROOF_BATCH_PAYLOAD_VERSION_V1)?;
    let from = decoder.read_signer_identity()?;
    let to = decoder.read_signer_identity()?;
    let transcript_digest = decoder.read_fixed::<32>()?;
    let root_share_epoch = decoder.read_string()?;
    if decoder.read_u32()? != 1
        || from != envelope.signer
        || to.role == from.role
        || transcript_digest != envelope.transcript_digest
        || root_share_epoch.is_empty()
    {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    decoder.expect_bytes(MPC_PRF_SUITE_ID_V1)?;
    let proof_transcript_digest = decoder.read_fixed::<32>()?;
    let proof_root_share_epoch = decoder.read_string()?;
    decoder.expect_bytes(X_CLIENT_BASE_V1)?;
    decoder.expect_bytes(CLIENT_ROLE_V1)?;
    let proof_recipient_identity = decoder.read_string()?;
    let proof_signer_role = decoder.read_deriver_role()?;
    let proof_signer_identity = decoder.read_string()?;
    let partial_wire = decoder.read_fixed::<66>()?;
    let commitment_wire = decoder.read_fixed::<34>()?;
    let proof_wire = decoder.read_fixed::<64>()?;
    decoder.finish()?;
    if proof_transcript_digest != transcript_digest
        || proof_root_share_epoch != root_share_epoch
        || proof_recipient_identity != envelope.recipient_identity
        || proof_signer_role != envelope.signer.role
        || proof_signer_identity != envelope.signer.signer_id
    {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(DecodedClientProofBatchV1 {
        root_share_epoch,
        peer: to,
        proof: EcdsaPrfPublicProofBundleV1 {
            partial_wire,
            commitment_wire,
            proof_wire,
        },
    })
}

fn push_signer_identity(output: &mut Vec<u8>, identity: &EcdsaSignerIdentityV1) {
    push_bytes(output, identity.role.wire_label().as_bytes());
    push_string(output, &identity.signer_id);
    push_string(output, &identity.key_epoch);
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> Result<(), EcdsaClientProtocolError> {
        if self.offset == self.bytes.len() {
            return Ok(());
        }
        Err(EcdsaClientProtocolError::InvalidShape)
    }

    fn expect_bytes(&mut self, expected: &[u8]) -> Result<(), EcdsaClientProtocolError> {
        if self.read_bytes()? == expected {
            return Ok(());
        }
        Err(EcdsaClientProtocolError::InvalidShape)
    }

    fn read_deriver_role(&mut self) -> Result<EcdsaDeriverRoleV1, EcdsaClientProtocolError> {
        match self.read_bytes()? {
            b"signer_a" => Ok(EcdsaDeriverRoleV1::A),
            b"signer_b" => Ok(EcdsaDeriverRoleV1::B),
            _ => Err(EcdsaClientProtocolError::InvalidShape),
        }
    }

    fn read_signer_identity(&mut self) -> Result<EcdsaSignerIdentityV1, EcdsaClientProtocolError> {
        let role = self.read_deriver_role()?;
        let signer_id = self.read_string()?;
        let key_epoch = self.read_string()?;
        require_non_empty(&signer_id)?;
        require_non_empty(&key_epoch)?;
        Ok(EcdsaSignerIdentityV1 {
            role,
            signer_id,
            key_epoch,
        })
    }

    fn read_string(&mut self) -> Result<String, EcdsaClientProtocolError> {
        core::str::from_utf8(self.read_bytes()?)
            .map(str::to_owned)
            .map_err(|_| EcdsaClientProtocolError::InvalidShape)
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], EcdsaClientProtocolError> {
        self.read_bytes()?
            .try_into()
            .map_err(|_| EcdsaClientProtocolError::InvalidShape)
    }

    fn read_nonzero_fixed<const N: usize>(&mut self) -> Result<[u8; N], EcdsaClientProtocolError> {
        let value = self.read_fixed::<N>()?;
        if value.iter().all(|byte| *byte == 0) {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, EcdsaClientProtocolError> {
        let end = self
            .offset
            .checked_add(4)
            .ok_or(EcdsaClientProtocolError::InvalidShape)?;
        if end > self.bytes.len() {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        let bytes: [u8; 4] = self.bytes[self.offset..end]
            .try_into()
            .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
        self.offset = end;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], EcdsaClientProtocolError> {
        let length = self.read_u32()? as usize;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(EcdsaClientProtocolError::InvalidShape)?;
        if end > self.bytes.len() {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    struct SealedClientFixture {
        envelope: EcdsaClientProofBundleEnvelopeV1,
        recipient_private_key: [u8; 32],
    }

    fn signer(role: EcdsaDeriverRoleV1, signer_id: &str, key_epoch: &str) -> EcdsaSignerIdentityV1 {
        EcdsaSignerIdentityV1 {
            role,
            signer_id: signer_id.to_owned(),
            key_epoch: key_epoch.to_owned(),
        }
    }

    fn opened(
        role: EcdsaDeriverRoleV1,
        signer_identity: EcdsaSignerIdentityV1,
        peer: EcdsaSignerIdentityV1,
    ) -> EcdsaOpenedClientProofBundleV1 {
        EcdsaOpenedClientProofBundleV1 {
            lifecycle_id: "lifecycle-1".to_owned(),
            root_share_epoch: "root-epoch-1".to_owned(),
            transcript_digest: [0x31; 32],
            recipient_identity: "client-1".to_owned(),
            signer: signer_identity,
            peer,
            role_bound_proof: EcdsaRoleBoundPrfProofV1 {
                role,
                proof: EcdsaPrfPublicProofBundleV1 {
                    partial_wire: [0x41; 66],
                    commitment_wire: [0x51; 34],
                    proof_wire: [0x61; 64],
                },
            },
        }
    }

    fn exact_pair() -> (
        EcdsaOpenedClientProofBundleV1,
        EcdsaOpenedClientProofBundleV1,
    ) {
        let signer_a = signer(EcdsaDeriverRoleV1::A, "deriver-a", "a-epoch-1");
        let signer_b = signer(EcdsaDeriverRoleV1::B, "deriver-b", "b-epoch-1");
        (
            opened(EcdsaDeriverRoleV1::A, signer_a.clone(), signer_b.clone()),
            opened(EcdsaDeriverRoleV1::B, signer_b, signer_a),
        )
    }

    #[test]
    fn client_proof_hpke_binds_recipient_transcript_payload_digest_nonce_output_and_suite() {
        let fixture = sealed_client_fixture(CLIENT_ROLE_V1, X_CLIENT_BASE_V1, MPC_PRF_SUITE_ID_V1);
        let opened =
            open_ecdsa_client_proof_bundle_v1(&fixture.envelope, &fixture.recipient_private_key)
                .expect("exact client proof bundle opens");
        assert_eq!(opened.lifecycle_id, "lifecycle-1");
        assert_eq!(opened.root_share_epoch, "root-epoch-1");
        assert_eq!(opened.transcript_digest, [0x31; 32]);
        assert_eq!(opened.recipient_identity, "client-1");
        assert_eq!(opened.role_bound_proof.role, EcdsaDeriverRoleV1::A);

        let mut recipient_substitution = fixture.envelope.clone();
        recipient_substitution.recipient_identity = "substituted-client".to_owned();
        assert_open_rejected(&fixture, recipient_substitution);

        let mut transcript_substitution = fixture.envelope.clone();
        transcript_substitution.transcript_digest[0] ^= 1;
        assert_open_rejected(&fixture, transcript_substitution);

        let mut payload_digest_substitution = fixture.envelope.clone();
        payload_digest_substitution.payload_digest[0] ^= 1;
        assert_open_rejected(&fixture, payload_digest_substitution);

        let mut nonce_substitution = fixture.envelope.clone();
        nonce_substitution.nonce[0] ^= 1;
        assert_open_rejected(&fixture, nonce_substitution);

        let mut signer_substitution = fixture.envelope.clone();
        signer_substitution.signer.key_epoch = "substituted-key-epoch".to_owned();
        assert_open_rejected(&fixture, signer_substitution);

        let wrong_output = sealed_client_fixture(b"server", b"x_server_base", PRF_SUITE_V1);
        assert!(open_ecdsa_client_proof_bundle_v1(
            &wrong_output.envelope,
            &wrong_output.recipient_private_key,
        )
        .is_err());

        let wrong_suite = sealed_client_fixture(CLIENT_ROLE_V1, X_CLIENT_BASE_V1, b"other-suite");
        assert!(open_ecdsa_client_proof_bundle_v1(
            &wrong_suite.envelope,
            &wrong_suite.recipient_private_key,
        )
        .is_err());
    }

    #[test]
    fn stable_client_recipient_payload_decodes_the_frozen_core_wire() {
        let bytes = decode_hex(concat!(
            "00000043726f757465722d61622d70726f746f636f6c2f6d70632d7072662d737461626c652d",
            "726563697069656e742d70726f6f662d62756e646c652d7061796c6f61642f763200000008",
            "7369676e65725f6100000009646572697665722d610000000765706f63682d610000000663",
            "6c69656e7400000008636c69656e742d310000015c00000036726f757465722d61622d7072",
            "6f746f636f6c2f6d70632d7072662d737461626c652d70726f6f662d62756e646c652d7769",
            "72652f7632000000202d00f67a1dae5c4e3082901eba78cd4513ad9f65ba58333024a151132daf5a52",
            "000000202828282828282828282828282828282828282828282828282828282828282828",
            "0000001a726f757465722d61622f785f636c69656e745f626173652f7631000000087369676e",
            "65725f6100000042000108832fb788136a60f4b0836e704d38ea7e2b8f5afd8e5d641c0c9114c748820a98cdafdc40f431925883fd3fe1bfa8206602e947d1727913eba172fc6ab6e749",
            "0000002200016cc14ead8beae3d1e9d5dc37702c8eab83fb49a4abd6e18fb5fc60d89ec65c5f",
            "0000004075a57a8c5acc4279a0d295ee46bd6cf282bec45a1c002e3119cd8822b77e60095b906e7d8a46c750c97c46bd45cea63054fa2cec65385d054dd89e9775471f0e",
        ));
        let opened = decode_ecdsa_client_proof_bundle_payload_v2(&bytes, [0x91; 32])
            .expect("frozen stable recipient payload decodes");
        assert_eq!(opened.transcript_digest, [0x91; 32]);
        assert_eq!(opened.signer.role, EcdsaDeriverRoleV1::A);
        assert_eq!(opened.signer.signer_id, "deriver-a");
        assert_eq!(opened.signer.key_epoch, "epoch-a");
        assert_eq!(opened.recipient_identity, "client-1");
        assert_eq!(
            opened.proof.stable_context_digest,
            hex_array("2d00f67a1dae5c4e3082901eba78cd4513ad9f65ba58333024a151132daf5a52"),
        );
        assert_eq!(opened.proof.custody_binding_digest, [0x28; 32]);
        assert_eq!(opened.proof.proof.partial_wire[0..2], [0, 1]);
        assert_eq!(
            opened.proof.proof.partial_wire[2..34],
            hex_array::<32>("08832fb788136a60f4b0836e704d38ea7e2b8f5afd8e5d641c0c9114c748820a",),
        );
        assert_eq!(
            opened.proof.proof.commitment_wire[2..34],
            hex_array::<32>("6cc14ead8beae3d1e9d5dc37702c8eab83fb49a4abd6e18fb5fc60d89ec65c5f",),
        );
        assert_eq!(
            opened.proof.proof.proof_wire,
            hex_array("75a57a8c5acc4279a0d295ee46bd6cf282bec45a1c002e3119cd8822b77e60095b906e7d8a46c750c97c46bd45cea63054fa2cec65385d054dd89e9775471f0e"),
        );
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid test hex"),
        }
    }

    fn hex_array<const N: usize>(value: &str) -> [u8; N] {
        decode_hex(value).try_into().expect("fixed test hex length")
    }

    fn assert_open_rejected(
        fixture: &SealedClientFixture,
        envelope: EcdsaClientProofBundleEnvelopeV1,
    ) {
        assert!(
            open_ecdsa_client_proof_bundle_v1(&envelope, &fixture.recipient_private_key,).is_err()
        );
    }

    fn sealed_client_fixture(
        payload_recipient_role: &[u8],
        payload_output_kind: &[u8],
        proof_suite: &[u8],
    ) -> SealedClientFixture {
        let signer_identity = signer(EcdsaDeriverRoleV1::A, "deriver-a", "a-epoch-1");
        let peer_identity = signer(EcdsaDeriverRoleV1::B, "deriver-b", "b-epoch-1");
        let transcript_digest = [0x31; 32];
        let proof_batch = encoded_client_proof_batch(
            &signer_identity,
            &peer_identity,
            &transcript_digest,
            payload_recipient_role,
            payload_output_kind,
            proof_suite,
        );
        let mut plaintext = Vec::new();
        push_bytes(&mut plaintext, RECIPIENT_PROOF_BUNDLE_PAYLOAD_VERSION_V1);
        push_string(&mut plaintext, "lifecycle-1");
        push_signer_identity(&mut plaintext, &signer_identity);
        push_bytes(&mut plaintext, payload_recipient_role);
        push_bytes(&mut plaintext, payload_output_kind);
        push_string(&mut plaintext, "client-1");
        push_bytes(&mut plaintext, &transcript_digest);
        push_bytes(&mut plaintext, &proof_batch);

        let (recipient_private_key, recipient_public_key) =
            DhKemX25519HkdfSha256::derive_key_pair(&[0x71; 32]).expect("recipient keypair");
        let recipient_private_key = DhKemX25519HkdfSha256::sk_to_bytes(&recipient_private_key)
            .as_slice()
            .try_into()
            .expect("recipient private key bytes");
        let recipient_public_key_bytes: [u8; 32] =
            DhKemX25519HkdfSha256::pk_to_bytes(&recipient_public_key)
                .as_slice()
                .try_into()
                .expect("fixed recipient public key");
        let recipient_public_key = encode_x25519_public_key(&recipient_public_key_bytes);
        let mut envelope = EcdsaClientProofBundleEnvelopeV1 {
            signer: signer_identity,
            recipient_identity: "client-1".to_owned(),
            recipient_public_key,
            transcript_digest,
            payload_digest: digest32(&plaintext).expect("payload digest"),
            nonce: [0x72; RECIPIENT_PROOF_BUNDLE_NONCE_LEN_V1],
            ciphertext_and_tag: vec![0; 80],
        };
        let recipient_public_key_bytes =
            decode_x25519_public_key(&envelope.recipient_public_key).expect("recipient key");
        let recipient_public_key =
            DhKemX25519HkdfSha256::pk_from_bytes(&recipient_public_key_bytes)
                .expect("recipient public key");
        let mut rng = ChaCha20Rng::from_seed([0x73; 32]);
        let (encapped_key, ciphertext_and_tag) = SignerEnvelopeHpkeV1::seal_base(
            &mut rng,
            &recipient_public_key,
            RECIPIENT_PROOF_BUNDLE_HPKE_INFO_V1,
            &envelope.aad_bytes().expect("client proof AAD"),
            &plaintext,
        )
        .expect("client proof seal");
        envelope.ciphertext_and_tag = encapped_key
            .as_ref()
            .iter()
            .copied()
            .chain(ciphertext_and_tag)
            .collect();
        SealedClientFixture {
            envelope,
            recipient_private_key,
        }
    }

    fn encoded_client_proof_batch(
        signer: &EcdsaSignerIdentityV1,
        peer: &EcdsaSignerIdentityV1,
        transcript_digest: &[u8; 32],
        recipient_role: &[u8],
        output_kind: &[u8],
        proof_suite: &[u8],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_bytes(
            &mut bytes,
            ECDSA_THRESHOLD_PRF_PROOF_BATCH_PAYLOAD_VERSION_V1,
        );
        push_signer_identity(&mut bytes, signer);
        push_signer_identity(&mut bytes, peer);
        push_bytes(&mut bytes, transcript_digest);
        push_string(&mut bytes, "root-epoch-1");
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        push_bytes(&mut bytes, proof_suite);
        push_bytes(&mut bytes, transcript_digest);
        push_string(&mut bytes, "root-epoch-1");
        push_bytes(&mut bytes, output_kind);
        push_bytes(&mut bytes, recipient_role);
        push_string(&mut bytes, "client-1");
        push_bytes(&mut bytes, signer.role.wire_label().as_bytes());
        push_string(&mut bytes, &signer.signer_id);
        push_bytes(&mut bytes, &[0x41; 66]);
        push_bytes(&mut bytes, &[0x51; 34]);
        push_bytes(&mut bytes, &[0x61; 64]);
        bytes
    }

    #[test]
    fn exact_client_proof_pair_rejects_lifecycle_root_transcript_recipient_role_and_peer_drift() {
        let (signer_a, signer_b) = exact_pair();
        pair_ecdsa_opened_client_proof_bundles_v1(signer_a.clone(), signer_b.clone())
            .expect("exact pair");

        let mut wrong_peer_id = signer_a.clone();
        wrong_peer_id.peer.signer_id = "substituted-deriver-b".to_owned();
        assert_pair_rejected(wrong_peer_id, signer_b.clone());

        let mut wrong_peer_epoch = signer_a.clone();
        wrong_peer_epoch.peer.key_epoch = "substituted-b-epoch".to_owned();
        assert_pair_rejected(wrong_peer_epoch, signer_b.clone());

        let mut wrong_lifecycle = signer_a.clone();
        wrong_lifecycle.lifecycle_id = "substituted-lifecycle".to_owned();
        assert_pair_rejected(wrong_lifecycle, signer_b.clone());

        let mut wrong_root_epoch = signer_a.clone();
        wrong_root_epoch.root_share_epoch = "substituted-root-epoch".to_owned();
        assert_pair_rejected(wrong_root_epoch, signer_b.clone());

        let mut wrong_transcript = signer_a.clone();
        wrong_transcript.transcript_digest[0] ^= 1;
        assert_pair_rejected(wrong_transcript, signer_b.clone());

        let mut wrong_recipient = signer_a.clone();
        wrong_recipient.recipient_identity = "substituted-client".to_owned();
        assert_pair_rejected(wrong_recipient, signer_b.clone());

        let mut wrong_proof_role = signer_a;
        wrong_proof_role.role_bound_proof.role = EcdsaDeriverRoleV1::B;
        assert_pair_rejected(wrong_proof_role, signer_b);
    }

    fn assert_pair_rejected(
        signer_a: EcdsaOpenedClientProofBundleV1,
        signer_b: EcdsaOpenedClientProofBundleV1,
    ) {
        assert_eq!(
            pair_ecdsa_opened_client_proof_bundles_v1(signer_a, signer_b),
            Err(EcdsaClientProtocolError::InvalidShape),
        );
    }
}
