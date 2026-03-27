use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use blake3::Hasher as Blake3Hasher;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hidden_eval::{
    FixedFunctionHssBackend, HiddenEvalInputOwner, HiddenEvalProgram, HssPrimitiveKind,
};
use crate::{ProtoError, ProtoResult};

pub const DDH_HSS_BACKEND_VERSION: &str = "ddh_hss_backend_v0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssParams {
    pub backend_version: String,
    pub scalar_bits: u16,
    pub generator_compressed: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssEvaluationKey {
    pub backend_version: String,
    pub primitive_kind: HssPrimitiveKind,
    pub context_binding: [u8; 32],
    pub candidate_digest: [u8; 32],
    pub program_digest: [u8; 32],
    pub key_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHssSharedWord {
    pub width_bits: u16,
    pub left_word: u64,
    pub right_word: u64,
    pub left_commitment: [u8; 32],
    pub right_commitment: [u8; 32],
    pub provenance_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHssInputShareBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub words: Vec<DdhHssSharedWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdhHssShareSide {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssTransportWord {
    pub width_bits: u16,
    pub share_side: DdhHssShareSide,
    pub share_word: u64,
    pub share_commitment: [u8; 32],
    pub counterparty_commitment: [u8; 32],
    pub provenance_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssTransportBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub share_side: DdhHssShareSide,
    pub words: Vec<DdhHssTransportWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdhHssTransportPurpose {
    ServerInput,
    ClientOutput,
    ServerOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHssMulMaterial {
    pub width_bits: u16,
    pub triple_a: DdhHssSharedWord,
    pub triple_b: DdhHssSharedWord,
    pub triple_c: DdhHssSharedWord,
    pub provenance_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtEncryptedBranch {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub payload_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtWordOffer {
    pub width_bits: u16,
    pub sender_public: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtInputBundleOffer {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub words: Vec<DdhHssOtWordOffer>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtRemoteWord {
    pub width_bits: u16,
    pub share_word: u64,
    pub share_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtRemoteBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub share_side: DdhHssShareSide,
    pub words: Vec<DdhHssOtRemoteWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtSenderStateWord {
    pub width_bits: u16,
    pub sender_scalar: [u8; 32],
    pub sender_public: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtSenderStateBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub words: Vec<DdhHssOtSenderStateWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtSelectionWord {
    pub width_bits: u16,
    pub receiver_public: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtSelectionBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub words: Vec<DdhHssOtSelectionWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtReceiverStateWord {
    pub width_bits: u16,
    pub selected_branch: u8,
    pub receiver_scalar: [u8; 32],
    pub sender_public: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtReceiverStateBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub words: Vec<DdhHssOtReceiverStateWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtResponseWord {
    pub width_bits: u16,
    pub zero_branch: DdhHssOtEncryptedBranch,
    pub one_branch: DdhHssOtEncryptedBranch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtResponseBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub words: Vec<DdhHssOtResponseWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtReleasedRemoteBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub share_side: DdhHssShareSide,
    pub words: Vec<DdhHssOtRemoteWord>,
    pub commitment: [u8; 32],
    pub offer_commitment: [u8; 32],
    pub request_commitment: [u8; 32],
    pub response_commitment: [u8; 32],
    pub transcript_binding: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssBackend {
    params: DdhHssParams,
    evaluation_key: DdhHssEvaluationKey,
    secret_seed: DdhHssSecretSeed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssPublicState {
    params: DdhHssParams,
    evaluation_key: DdhHssEvaluationKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssGarbler {
    backend: DdhHssBackend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssEvaluator {
    public_state: DdhHssPublicState,
    server_input_transport_key: DdhHssTransportKey,
    client_output_transport_key: DdhHssTransportKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssRoleSet {
    pub garbler: DdhHssGarbler,
    pub evaluator: DdhHssEvaluator,
}

pub trait DdhHssArithmeticBackend {
    fn evaluation_key(&self) -> &DdhHssEvaluationKey;
    fn share_word(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        value: u64,
        width_bits: u16,
    ) -> ProtoResult<DdhHssSharedWord>;
    fn input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        words: &[DdhHssSharedWord],
    ) -> [u8; 32];
    fn share_input_bit_bundle(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<DdhHssInputShareBundle> {
        let mut words = Vec::with_capacity(input.len() * 8);
        for (byte_idx, byte) in input.iter().enumerate() {
            for bit_idx in 0..8 {
                words.push(self.share_word(
                    owner,
                    &format!("{label}/{byte_idx}/{bit_idx}"),
                    u64::from((byte >> bit_idx) & 1),
                    1,
                )?);
            }
        }
        let commitment = self.input_commitment(owner, label, &words);
        Ok(DdhHssInputShareBundle {
            owner,
            label: label.to_string(),
            words,
            commitment,
        })
    }
    fn combined_input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        bundles: &[&DdhHssInputShareBundle],
    ) -> [u8; 32];
    fn eval_add_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord>;
    fn prepare_mul_material(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssMulMaterial>;
    fn eval_mul_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
        material: &DdhHssMulMaterial,
    ) -> ProtoResult<DdhHssSharedWord>;
    fn eval_mul_bit(
        &self,
        label: &str,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        if left.width_bits != 1 || right.width_bits != 1 {
            return Err(ProtoError::InvalidInput(format!(
                "bit multiplication requires 1-bit operands, got {} and {}",
                left.width_bits, right.width_bits
            )));
        }
        let material = self.prepare_mul_material(left, right)?;
        let _ = label;
        self.eval_mul_mod_2_pow_n(left, right, &material)
    }
    fn compose_word_from_share_bits(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        bits: &[DdhHssSharedWord],
    ) -> ProtoResult<DdhHssSharedWord>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct DdhHssSecretSeed([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct DdhHssTransportKey([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DdhHssOtBranchPayload {
    width_bits: u16,
    share_word: u64,
    share_commitment: [u8; 32],
    counterparty_commitment: [u8; 32],
    provenance_digest: [u8; 32],
}

pub fn keygen_prime_order_ddh_hss_backend(
    context_binding: [u8; 32],
    candidate_digest: [u8; 32],
    program: &HiddenEvalProgram,
) -> ProtoResult<DdhHssBackend> {
    if program.primitive_kind != HssPrimitiveKind::PrimeOrderDdh {
        return Err(ProtoError::InvalidInput(format!(
            "DDH backend requires prime_order_ddh program, got {:?}",
            program.primitive_kind
        )));
    }

    let program_digest = hash_hidden_eval_program(program)?;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/keygen/v0");
    transcript.append_message(b"context_binding", &context_binding);
    transcript.append_message(b"candidate_digest", &candidate_digest);
    transcript.append_message(b"program_digest", &program_digest);
    transcript.append_message(b"seed", &seed);

    let mut key_id = [0u8; 32];
    transcript.challenge_bytes(b"key_id", &mut key_id);

    Ok(DdhHssBackend {
        params: DdhHssParams {
            backend_version: DDH_HSS_BACKEND_VERSION.to_string(),
            scalar_bits: 252,
            generator_compressed: ED25519_BASEPOINT_POINT.compress().to_bytes(),
        },
        evaluation_key: DdhHssEvaluationKey {
            backend_version: DDH_HSS_BACKEND_VERSION.to_string(),
            primitive_kind: HssPrimitiveKind::PrimeOrderDdh,
            context_binding,
            candidate_digest,
            program_digest,
            key_id,
        },
        secret_seed: DdhHssSecretSeed(seed),
    })
}

pub fn keygen_prime_order_ddh_hss_roles(
    context_binding: [u8; 32],
    candidate_digest: [u8; 32],
    program: &HiddenEvalProgram,
) -> ProtoResult<DdhHssRoleSet> {
    let backend = keygen_prime_order_ddh_hss_backend(context_binding, candidate_digest, program)?;
    Ok(role_views_for_backend(&backend))
}

pub fn role_views_for_backend(backend: &DdhHssBackend) -> DdhHssRoleSet {
    DdhHssRoleSet {
        garbler: DdhHssGarbler {
            backend: backend.clone(),
        },
        evaluator: DdhHssEvaluator {
            public_state: backend.public_state(),
            server_input_transport_key: DdhHssTransportKey(
                backend.transport_key_for_purpose(DdhHssTransportPurpose::ServerInput.as_str()),
            ),
            client_output_transport_key: DdhHssTransportKey(
                backend.transport_key_for_purpose(DdhHssTransportPurpose::ClientOutput.as_str()),
            ),
        },
    }
}

impl DdhHssBackend {
    pub fn params(&self) -> &DdhHssParams {
        &self.params
    }

    pub fn evaluation_key(&self) -> &DdhHssEvaluationKey {
        &self.evaluation_key
    }

    pub fn public_state(&self) -> DdhHssPublicState {
        DdhHssPublicState {
            params: self.params.clone(),
            evaluation_key: self.evaluation_key.clone(),
        }
    }

    pub fn share_input_bundle(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<DdhHssInputShareBundle> {
        let words = self.share_input(owner, label, input)?;
        let commitment = self.input_commitment(owner, label, &words);
        Ok(DdhHssInputShareBundle {
            owner,
            label: label.to_string(),
            words,
            commitment,
        })
    }

    pub fn share_input_bit_bundle(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<DdhHssInputShareBundle> {
        let mut words = Vec::with_capacity(input.len() * 8);
        for (byte_idx, byte) in input.iter().enumerate() {
            for bit_idx in 0..8 {
                words.push(self.share_word(
                    owner,
                    &format!("{label}/{byte_idx}/{bit_idx}"),
                    u64::from((byte >> bit_idx) & 1),
                    1,
                )?);
            }
        }
        let commitment = self.input_commitment(owner, label, &words);
        Ok(DdhHssInputShareBundle {
            owner,
            label: label.to_string(),
            words,
            commitment,
        })
    }

    pub fn split_share_bundle(
        &self,
        bundle: &DdhHssInputShareBundle,
    ) -> (DdhHssTransportBundle, DdhHssTransportBundle) {
        let left = DdhHssTransportBundle {
            owner: bundle.owner,
            label: bundle.label.clone(),
            share_side: DdhHssShareSide::Left,
            words: bundle
                .words
                .iter()
                .map(|word| DdhHssTransportWord {
                    width_bits: word.width_bits,
                    share_side: DdhHssShareSide::Left,
                    share_word: word.left_word,
                    share_commitment: word.left_commitment,
                    counterparty_commitment: word.right_commitment,
                    provenance_digest: word.provenance_digest,
                })
                .collect(),
            commitment: bundle.commitment,
        };
        let right = DdhHssTransportBundle {
            owner: bundle.owner,
            label: bundle.label.clone(),
            share_side: DdhHssShareSide::Right,
            words: bundle
                .words
                .iter()
                .map(|word| DdhHssTransportWord {
                    width_bits: word.width_bits,
                    share_side: DdhHssShareSide::Right,
                    share_word: word.right_word,
                    share_commitment: word.right_commitment,
                    counterparty_commitment: word.left_commitment,
                    provenance_digest: word.provenance_digest,
                })
                .collect(),
            commitment: bundle.commitment,
        };
        (left, right)
    }

    pub fn prepare_client_input_ot_bundle_offer(
        &self,
        label: &str,
        bit_count: usize,
    ) -> ProtoResult<(
        DdhHssOtInputBundleOffer,
        DdhHssOtRemoteBundle,
        DdhHssOtSenderStateBundle,
    )> {
        if bit_count == 0 {
            return Err(ProtoError::InvalidInput(
                "client input OT offer requires at least one bit".to_string(),
            ));
        }

        let mut offer_words = Vec::with_capacity(bit_count);
        let mut remote_words = Vec::with_capacity(bit_count);
        let mut sender_state_words = Vec::with_capacity(bit_count);
        for bit_idx in 0..bit_count {
            let bit_label = format!("{label}/{bit_idx}");
            let mut wide = [0u8; 64];
            OsRng.fill_bytes(&mut wide);
            let sender_scalar = Scalar::from_bytes_mod_order_wide(&wide);
            let sender_public = (ED25519_BASEPOINT_POINT * sender_scalar)
                .compress()
                .to_bytes();
            let right_word = self.derive_masked_word(
                b"client-input-ot/right-share",
                HiddenEvalInputOwner::Client,
                bit_label.as_bytes(),
                0,
                1,
                &[],
            );
            let zero_left_word = reduce_word(modulus_for_width(1) - u128::from(right_word), 1);
            let one_left_word = reduce_word(
                u128::from(1u8)
                    .wrapping_add(modulus_for_width(1))
                    .wrapping_sub(u128::from(right_word)),
                1,
            );

            let zero_provenance_digest = self.derive_digest(
                b"client-input-ot/zero-branch",
                HiddenEvalInputOwner::Client,
                bit_label.as_bytes(),
                1,
                zero_left_word,
                right_word,
                &[],
            );
            let one_provenance_digest = self.derive_digest(
                b"client-input-ot/one-branch",
                HiddenEvalInputOwner::Client,
                bit_label.as_bytes(),
                1,
                one_left_word,
                right_word,
                &[],
            );

            let _zero_left_commitment = commit_word(
                HiddenEvalInputOwner::Client,
                b"left",
                zero_left_word,
                &zero_provenance_digest,
            );
            let _one_left_commitment = commit_word(
                HiddenEvalInputOwner::Client,
                b"left",
                one_left_word,
                &one_provenance_digest,
            );
            let right_commitment = commit_word(
                HiddenEvalInputOwner::Client,
                b"right",
                right_word,
                &zero_provenance_digest,
            );

            offer_words.push(DdhHssOtWordOffer {
                width_bits: 1,
                sender_public,
            });
            remote_words.push(DdhHssOtRemoteWord {
                width_bits: 1,
                share_word: right_word,
                share_commitment: right_commitment,
            });
            sender_state_words.push(DdhHssOtSenderStateWord {
                width_bits: 1,
                sender_scalar: sender_scalar.to_bytes(),
                sender_public,
            });
        }

        let offer = DdhHssOtInputBundleOffer {
            owner: HiddenEvalInputOwner::Client,
            label: label.to_string(),
            commitment: ot_offer_bundle_commitment(
                HiddenEvalInputOwner::Client,
                label,
                &offer_words,
            ),
            words: offer_words,
        };
        let remote = DdhHssOtRemoteBundle {
            owner: HiddenEvalInputOwner::Client,
            label: label.to_string(),
            share_side: DdhHssShareSide::Right,
            commitment: ot_remote_bundle_commitment(
                HiddenEvalInputOwner::Client,
                label,
                DdhHssShareSide::Right,
                &remote_words,
            ),
            words: remote_words,
        };
        let sender_state = DdhHssOtSenderStateBundle {
            owner: HiddenEvalInputOwner::Client,
            label: label.to_string(),
            commitment: ot_sender_state_bundle_commitment(
                HiddenEvalInputOwner::Client,
                label,
                &sender_state_words,
            ),
            words: sender_state_words,
        };
        Ok((offer, remote, sender_state))
    }

    pub fn prepare_client_input_ot_request(
        &self,
        offer: &DdhHssOtInputBundleOffer,
        input: &[u8],
    ) -> ProtoResult<(DdhHssOtSelectionBundle, DdhHssOtReceiverStateBundle)> {
        if offer.owner != HiddenEvalInputOwner::Client {
            return Err(ProtoError::InvalidInput(
                "OT request requires a client-owned offer".to_string(),
            ));
        }
        let bit_count = input.len() * 8;
        if offer.words.len() != bit_count {
            return Err(ProtoError::InvalidInput(format!(
                "OT offer word count does not match input bit count: {} vs {}",
                offer.words.len(),
                bit_count
            )));
        }

        let mut request_words = Vec::with_capacity(bit_count);
        let mut local_state_words = Vec::with_capacity(bit_count);
        for (bit_idx, word_offer) in offer.words.iter().enumerate() {
            if word_offer.width_bits != 1 {
                return Err(ProtoError::InvalidInput(format!(
                    "OT offer word width must be 1, got {} at index {}",
                    word_offer.width_bits, bit_idx
                )));
            }
            let byte_idx = bit_idx / 8;
            let inner_bit_idx = bit_idx % 8;
            let selected_branch = (input[byte_idx] >> inner_bit_idx) & 1;
            let mut wide = [0u8; 64];
            OsRng.fill_bytes(&mut wide);
            let receiver_scalar = Scalar::from_bytes_mod_order_wide(&wide);
            let receiver_public_point = if selected_branch == 0 {
                ED25519_BASEPOINT_POINT * receiver_scalar
            } else {
                CompressedEdwardsY(word_offer.sender_public)
                    .decompress()
                    .ok_or_else(|| {
                        ProtoError::InvalidInput(format!(
                            "OT sender public point is invalid at index {}",
                            bit_idx
                        ))
                    })?
                    + (ED25519_BASEPOINT_POINT * receiver_scalar)
            };
            request_words.push(DdhHssOtSelectionWord {
                width_bits: 1,
                receiver_public: receiver_public_point.compress().to_bytes(),
            });
            local_state_words.push(DdhHssOtReceiverStateWord {
                width_bits: 1,
                selected_branch,
                receiver_scalar: receiver_scalar.to_bytes(),
                sender_public: word_offer.sender_public,
            });
        }

        let request = DdhHssOtSelectionBundle {
            owner: HiddenEvalInputOwner::Client,
            label: offer.label.clone(),
            commitment: ot_request_bundle_commitment(
                HiddenEvalInputOwner::Client,
                &offer.label,
                &request_words,
            ),
            words: request_words,
        };
        let local_state = DdhHssOtReceiverStateBundle {
            owner: HiddenEvalInputOwner::Client,
            label: offer.label.clone(),
            commitment: ot_receiver_state_bundle_commitment(
                HiddenEvalInputOwner::Client,
                &offer.label,
                &local_state_words,
            ),
            words: local_state_words,
        };
        Ok((request, local_state))
    }

    pub fn join_share_bundle(
        &self,
        left: &DdhHssTransportBundle,
        right: &DdhHssTransportBundle,
    ) -> ProtoResult<DdhHssInputShareBundle> {
        join_share_bundle_public(&self.evaluation_key, left, right)
    }

    pub fn join_client_ot_bundle(
        &self,
        local: &DdhHssTransportBundle,
        remote: &DdhHssOtReleasedRemoteBundle,
    ) -> ProtoResult<DdhHssInputShareBundle> {
        if local.owner != HiddenEvalInputOwner::Client
            || remote.owner != HiddenEvalInputOwner::Client
        {
            return Err(ProtoError::InvalidInput(
                "client OT bundle join requires client-owned bundles".to_string(),
            ));
        }
        if local.label != remote.label {
            return Err(ProtoError::InvalidInput(format!(
                "client OT bundle labels do not match: {} vs {}",
                local.label, remote.label
            )));
        }
        if local.share_side != DdhHssShareSide::Left || remote.share_side != DdhHssShareSide::Right
        {
            return Err(ProtoError::InvalidInput(
                "client OT bundles must be joined in left/right order".to_string(),
            ));
        }
        if local.words.len() != remote.words.len() {
            return Err(ProtoError::InvalidInput(format!(
                "client OT bundle word counts do not match: {} vs {}",
                local.words.len(),
                remote.words.len()
            )));
        }
        if local.commitment
            != transport_bundle_commitment(
                local.owner,
                &local.label,
                local.share_side,
                &local.words,
            )
        {
            return Err(ProtoError::InvalidInput(
                "client OT local bundle commitment is invalid".to_string(),
            ));
        }
        if remote.commitment
            != ot_remote_bundle_commitment(
                remote.owner,
                &remote.label,
                remote.share_side,
                &remote.words,
            )
        {
            return Err(ProtoError::InvalidInput(
                "client OT remote bundle commitment is invalid".to_string(),
            ));
        }
        let expected_remote_binding = ot_remote_release_transcript_binding(
            remote.owner,
            &remote.label,
            remote.offer_commitment,
            remote.request_commitment,
            remote.response_commitment,
            remote.commitment,
        );
        if remote.transcript_binding != expected_remote_binding {
            return Err(ProtoError::InvalidInput(
                "client OT remote-share release transcript binding is invalid".to_string(),
            ));
        }

        let mut words = Vec::with_capacity(local.words.len());
        for (left_word, right_word) in local.words.iter().zip(&remote.words) {
            if left_word.width_bits != right_word.width_bits {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT word widths do not match: {} vs {}",
                    left_word.width_bits, right_word.width_bits
                )));
            }
            if left_word.counterparty_commitment != right_word.share_commitment {
                return Err(ProtoError::InvalidInput(
                    "client OT counterparty commitment does not match remote share commitment"
                        .to_string(),
                ));
            }
            let expected_left_commitment = commit_word(
                local.owner,
                b"left",
                left_word.share_word,
                &left_word.provenance_digest,
            );
            if left_word.share_commitment != expected_left_commitment {
                return Err(ProtoError::InvalidInput(
                    "client OT left-share commitment is invalid".to_string(),
                ));
            }
            words.push(DdhHssSharedWord {
                width_bits: left_word.width_bits,
                left_word: left_word.share_word,
                right_word: right_word.share_word,
                left_commitment: left_word.share_commitment,
                right_commitment: right_word.share_commitment,
                provenance_digest: left_word.provenance_digest,
            });
        }

        let commitment = self.input_commitment(HiddenEvalInputOwner::Client, &local.label, &words);
        Ok(DdhHssInputShareBundle {
            owner: HiddenEvalInputOwner::Client,
            label: local.label.clone(),
            words,
            commitment,
        })
    }

    pub fn open_client_input_ot_bundle(
        &self,
        response: &DdhHssOtResponseBundle,
        local_state: &DdhHssOtReceiverStateBundle,
    ) -> ProtoResult<DdhHssTransportBundle> {
        if response.owner != HiddenEvalInputOwner::Client
            || local_state.owner != HiddenEvalInputOwner::Client
        {
            return Err(ProtoError::InvalidInput(
                "client OT response opening requires client-owned bundles".to_string(),
            ));
        }
        if response.label != local_state.label {
            return Err(ProtoError::InvalidInput(format!(
                "client OT response label does not match local state: {} vs {}",
                response.label, local_state.label
            )));
        }
        if response.words.len() != local_state.words.len() {
            return Err(ProtoError::InvalidInput(format!(
                "client OT response word count does not match local state: {} vs {}",
                response.words.len(),
                local_state.words.len()
            )));
        }
        if response.commitment
            != ot_response_bundle_commitment(response.owner, &response.label, &response.words)
        {
            return Err(ProtoError::InvalidInput(
                "client OT response commitment is invalid".to_string(),
            ));
        }
        if local_state.commitment
            != ot_receiver_state_bundle_commitment(
                local_state.owner,
                &local_state.label,
                &local_state.words,
            )
        {
            return Err(ProtoError::InvalidInput(
                "client OT local state commitment is invalid".to_string(),
            ));
        }

        let mut local_words = Vec::with_capacity(response.words.len());
        for (bit_idx, (response_word, state_word)) in
            response.words.iter().zip(&local_state.words).enumerate()
        {
            if response_word.width_bits != 1 || state_word.width_bits != 1 {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT response words must be 1-bit at index {bit_idx}"
                )));
            }
            if state_word.selected_branch > 1 {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT local state branch must be 0 or 1 at index {bit_idx}, got {}",
                    state_word.selected_branch
                )));
            }
            let sender_public_point = CompressedEdwardsY(state_word.sender_public)
                .decompress()
                .ok_or_else(|| {
                    ProtoError::InvalidInput(format!(
                        "client OT sender public point is invalid at bit index {bit_idx}"
                    ))
                })?;
            let receiver_scalar = Scalar::from_bytes_mod_order(state_word.receiver_scalar);
            let shared_point = (sender_public_point * receiver_scalar)
                .compress()
                .to_bytes();
            let selected_branch = if state_word.selected_branch == 0 {
                &response_word.zero_branch
            } else {
                &response_word.one_branch
            };
            let key = self.derive_ot_branch_key_from_point(
                HiddenEvalInputOwner::Client,
                &response.label,
                bit_idx,
                state_word.selected_branch,
                shared_point,
            );
            let payload = DdhHssBackend::open_ot_branch_with_key(
                key,
                HiddenEvalInputOwner::Client,
                &response.label,
                bit_idx,
                state_word.selected_branch,
                selected_branch,
            )?;
            local_words.push(DdhHssTransportWord {
                width_bits: 1,
                share_side: DdhHssShareSide::Left,
                share_word: payload.share_word,
                share_commitment: payload.share_commitment,
                counterparty_commitment: payload.counterparty_commitment,
                provenance_digest: payload.provenance_digest,
            });
        }

        Ok(DdhHssTransportBundle {
            owner: HiddenEvalInputOwner::Client,
            label: response.label.clone(),
            share_side: DdhHssShareSide::Left,
            commitment: transport_bundle_commitment(
                HiddenEvalInputOwner::Client,
                &response.label,
                DdhHssShareSide::Left,
                &local_words,
            ),
            words: local_words,
        })
    }

    pub fn seal_transport_message(
        &self,
        purpose: &str,
        aad: &[u8],
        plaintext: &[u8],
    ) -> ProtoResult<([u8; 12], Vec<u8>)> {
        let cipher = ChaCha20Poly1305::new(&self.transport_key_for_purpose(purpose).into());
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|err| {
                ProtoError::Decode(format!(
                    "failed to seal DDH transport message for {purpose}: {err}"
                ))
            })?;
        Ok((nonce, ciphertext))
    }

    pub fn open_transport_message(
        &self,
        purpose: &str,
        aad: &[u8],
        nonce: [u8; 12],
        ciphertext: &[u8],
    ) -> ProtoResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.transport_key_for_purpose(purpose).into());
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|err| {
                ProtoError::Decode(format!(
                    "failed to open DDH transport message for {purpose}: {err}"
                ))
            })
    }

    fn seal_ot_branch_with_key(
        key: [u8; 32],
        owner: HiddenEvalInputOwner,
        label: &str,
        bit_idx: usize,
        branch_bit: u8,
        payload: &DdhHssOtBranchPayload,
    ) -> ProtoResult<DdhHssOtEncryptedBranch> {
        let plaintext = bincode::serialize(payload).map_err(|err| {
            ProtoError::Decode(format!("failed to serialize OT branch payload: {err}"))
        })?;
        let payload_digest = Sha256::digest(&plaintext);
        let mut payload_digest_array = [0u8; 32];
        payload_digest_array.copy_from_slice(&payload_digest);

        let cipher = ChaCha20Poly1305::new(&key.into());
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &ot_branch_aad(owner, label, bit_idx, branch_bit),
                },
            )
            .map_err(|err| {
                ProtoError::Decode(format!(
                    "failed to seal OT branch payload for {label}/{bit_idx}/{branch_bit}: {err}"
                ))
            })?;

        Ok(DdhHssOtEncryptedBranch {
            nonce,
            ciphertext,
            payload_digest: payload_digest_array,
        })
    }

    fn open_ot_branch_with_key(
        key: [u8; 32],
        owner: HiddenEvalInputOwner,
        label: &str,
        bit_idx: usize,
        branch_bit: u8,
        branch: &DdhHssOtEncryptedBranch,
    ) -> ProtoResult<DdhHssOtBranchPayload> {
        let cipher = ChaCha20Poly1305::new(&key.into());
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&branch.nonce),
                Payload {
                    msg: branch.ciphertext.as_ref(),
                    aad: &ot_branch_aad(owner, label, bit_idx, branch_bit),
                },
            )
            .map_err(|err| {
                ProtoError::Decode(format!(
                    "failed to open OT branch payload for {label}/{bit_idx}/{branch_bit}: {err}"
                ))
            })?;
        let payload_digest = Sha256::digest(&plaintext);
        if payload_digest.as_slice() != branch.payload_digest.as_slice() {
            return Err(ProtoError::Decode(format!(
                "OT branch payload digest mismatch for {label}/{bit_idx}/{branch_bit}"
            )));
        }
        bincode::deserialize(&plaintext).map_err(|err| {
            ProtoError::Decode(format!(
                "failed to decode OT branch payload for {label}/{bit_idx}/{branch_bit}: {err}"
            ))
        })
    }

    pub fn input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        words: &[DdhHssSharedWord],
    ) -> [u8; 32] {
        let mut transcript =
            Transcript::new(b"succinct-garbling-proto/ddh-hss/input-commitment/v0");
        transcript.append_message(b"key_id", &self.evaluation_key.key_id);
        transcript.append_message(b"owner", owner_tag(owner));
        transcript.append_message(b"label", label.as_bytes());
        transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
        for word in words {
            transcript.append_message(b"left_commitment", &word.left_commitment);
            transcript.append_message(b"right_commitment", &word.right_commitment);
            transcript.append_message(b"provenance", &word.provenance_digest);
        }
        let mut out = [0u8; 32];
        transcript.challenge_bytes(b"input_commitment", &mut out);
        out
    }

    pub fn run_binding(
        &self,
        artifact_digest: [u8; 32],
        client_input_commitment: [u8; 32],
        server_input_commitment: [u8; 32],
    ) -> [u8; 32] {
        let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/run-binding/v0");
        transcript.append_message(b"key_id", &self.evaluation_key.key_id);
        transcript.append_message(b"artifact_digest", &artifact_digest);
        transcript.append_message(b"context_binding", &self.evaluation_key.context_binding);
        transcript.append_message(b"candidate_digest", &self.evaluation_key.candidate_digest);
        transcript.append_message(b"client_input_commitment", &client_input_commitment);
        transcript.append_message(b"server_input_commitment", &server_input_commitment);
        let mut out = [0u8; 32];
        transcript.challenge_bytes(b"run_binding", &mut out);
        out
    }

    pub fn combined_input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        bundles: &[&DdhHssInputShareBundle],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"succinct-garbling-proto/ddh-hss/combined-input-commitment/v0");
        hasher.update(self.evaluation_key.key_id);
        match owner {
            HiddenEvalInputOwner::Client => hasher.update(b"client"),
            HiddenEvalInputOwner::Server => hasher.update(b"server"),
            HiddenEvalInputOwner::Derived => hasher.update(b"derived"),
        }
        for bundle in bundles {
            hasher.update(bundle.commitment);
            hasher.update(bundle.label.as_bytes());
        }
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    pub fn share_word(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        value: u64,
        width_bits: u16,
    ) -> ProtoResult<DdhHssSharedWord> {
        if !(1..=64).contains(&width_bits) {
            return Err(ProtoError::InvalidInput(format!(
                "shared word width must be in 1..=64 bits, got {width_bits}"
            )));
        }

        let clear_value = reduce_word(u128::from(value), width_bits);
        let left_word = self.derive_masked_word(
            b"share-left",
            owner,
            label.as_bytes(),
            clear_value,
            width_bits,
            &[],
        );
        let right_word = reduce_word(
            u128::from(clear_value)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(left_word)),
            width_bits,
        );

        Ok(self.build_shared_word(
            b"share-word",
            owner,
            label.as_bytes(),
            width_bits,
            left_word,
            right_word,
            &[],
        ))
    }

    pub fn decode_word(&self, value: &DdhHssSharedWord) -> u64 {
        reduce_word(
            u128::from(value.left_word) + u128::from(value.right_word),
            value.width_bits,
        )
    }

    pub fn eval_add_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        ensure_same_width(left, right)?;
        let width_bits = left.width_bits;
        if width_bits == 1 {
            return Ok(eval_add_bit_for_key(self.evaluation_key(), left, right));
        }
        let left_word = reduce_word(
            u128::from(left.left_word) + u128::from(right.left_word),
            width_bits,
        );
        let right_word = reduce_word(
            u128::from(left.right_word) + u128::from(right.right_word),
            width_bits,
        );
        Ok(self.build_shared_word(
            b"eval-add",
            HiddenEvalInputOwner::Derived,
            b"add",
            width_bits,
            left_word,
            right_word,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &right.left_commitment,
            ],
        ))
    }

    pub fn prepare_mul_material(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssMulMaterial> {
        ensure_same_width(left, right)?;
        let width_bits = left.width_bits;
        let triple_a_clear = self.derive_masked_word(
            b"eval-mul/triple-a",
            HiddenEvalInputOwner::Derived,
            b"mul",
            0,
            width_bits,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
            ],
        );
        let triple_b_clear = self.derive_masked_word(
            b"eval-mul/triple-b",
            HiddenEvalInputOwner::Derived,
            b"mul",
            0,
            width_bits,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
            ],
        );
        let triple_c_clear = reduce_word(
            u128::from(triple_a_clear) * u128::from(triple_b_clear),
            width_bits,
        );
        let triple_a = self.share_word(
            HiddenEvalInputOwner::Derived,
            "mul/triple_a",
            triple_a_clear,
            width_bits,
        )?;
        let triple_b = self.share_word(
            HiddenEvalInputOwner::Derived,
            "mul/triple_b",
            triple_b_clear,
            width_bits,
        )?;
        let triple_c = self.share_word(
            HiddenEvalInputOwner::Derived,
            "mul/triple_c",
            triple_c_clear,
            width_bits,
        )?;
        let provenance_digest = self.derive_digest(
            b"eval-mul-material",
            HiddenEvalInputOwner::Derived,
            b"mul",
            width_bits,
            triple_a_clear,
            triple_b_clear,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
                &triple_c.provenance_digest,
            ],
        );
        Ok(DdhHssMulMaterial {
            width_bits,
            triple_a,
            triple_b,
            triple_c,
            provenance_digest,
        })
    }

    pub fn eval_mul_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
        material: &DdhHssMulMaterial,
    ) -> ProtoResult<DdhHssSharedWord> {
        ensure_same_width(left, right)?;
        let width_bits = left.width_bits;
        if material.width_bits != width_bits {
            return Err(ProtoError::InvalidInput(format!(
                "multiplication material width does not match operands: {} vs {}",
                material.width_bits, width_bits
            )));
        }
        let d_left = reduce_word(
            u128::from(left.left_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_a.left_word)),
            width_bits,
        );
        let d_right = reduce_word(
            u128::from(left.right_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_a.right_word)),
            width_bits,
        );
        let e_left = reduce_word(
            u128::from(right.left_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_b.left_word)),
            width_bits,
        );
        let e_right = reduce_word(
            u128::from(right.right_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_b.right_word)),
            width_bits,
        );
        let d_open = reduce_word(u128::from(d_left) + u128::from(d_right), width_bits);
        let e_open = reduce_word(u128::from(e_left) + u128::from(e_right), width_bits);

        let left_word = reduce_word(
            u128::from(material.triple_c.left_word)
                + (u128::from(d_open) * u128::from(material.triple_b.left_word))
                + (u128::from(e_open) * u128::from(material.triple_a.left_word))
                + (u128::from(d_open) * u128::from(e_open)),
            width_bits,
        );
        let right_word = reduce_word(
            u128::from(material.triple_c.right_word)
                + (u128::from(d_open) * u128::from(material.triple_b.right_word))
                + (u128::from(e_open) * u128::from(material.triple_a.right_word)),
            width_bits,
        );

        Ok(self.build_shared_word(
            b"eval-mul",
            HiddenEvalInputOwner::Derived,
            b"mul",
            width_bits,
            left_word,
            right_word,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
                &material.provenance_digest,
            ],
        ))
    }

    pub fn eval_mul_bit(
        &self,
        label: &str,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        eval_mul_bit_for_key(self.evaluation_key(), label.as_bytes(), left, right)
    }

    pub fn compose_word_from_share_bits(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        bits: &[DdhHssSharedWord],
    ) -> ProtoResult<DdhHssSharedWord> {
        if bits.is_empty() || bits.len() > 64 {
            return Err(ProtoError::InvalidInput(format!(
                "bit composition requires 1..=64 bits, got {}",
                bits.len()
            )));
        }

        let mut left_word = 0u64;
        let mut right_word = 0u64;
        let mut extra_material = Vec::with_capacity(bits.len() * 3);
        for (idx, bit) in bits.iter().enumerate() {
            if bit.width_bits != 1 {
                return Err(ProtoError::InvalidInput(format!(
                    "bit composition requires 1-bit words, got {} at index {}",
                    bit.width_bits, idx
                )));
            }
            left_word |= (bit.left_word & 1) << idx;
            right_word |= (bit.right_word & 1) << idx;
            extra_material.push(bit.provenance_digest.as_slice());
            extra_material.push(bit.left_commitment.as_slice());
            extra_material.push(bit.right_commitment.as_slice());
        }

        Ok(self.build_shared_word(
            b"compose-word-from-share-bits",
            owner,
            label.as_bytes(),
            bits.len() as u16,
            left_word,
            right_word,
            &extra_material,
        ))
    }

    fn build_shared_word(
        &self,
        domain: &'static [u8],
        owner: HiddenEvalInputOwner,
        label: &[u8],
        width_bits: u16,
        left_word: u64,
        right_word: u64,
        extra_material: &[&[u8]],
    ) -> DdhHssSharedWord {
        let provenance_digest = self.derive_digest(
            domain,
            owner,
            label,
            width_bits,
            left_word,
            right_word,
            extra_material,
        );
        let left_commitment = commit_word(owner, b"left", left_word, &provenance_digest);
        let right_commitment = commit_word(owner, b"right", right_word, &provenance_digest);

        DdhHssSharedWord {
            width_bits,
            left_word,
            right_word,
            left_commitment,
            right_commitment,
            provenance_digest,
        }
    }

    fn derive_masked_word(
        &self,
        domain: &'static [u8],
        owner: HiddenEvalInputOwner,
        label: &[u8],
        clear_value: u64,
        width_bits: u16,
        extra_material: &[&[u8]],
    ) -> u64 {
        let digest = self.derive_digest(
            domain,
            owner,
            label,
            width_bits,
            clear_value,
            0,
            extra_material,
        );
        let sample = u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"));
        reduce_word(u128::from(sample), width_bits)
    }

    fn derive_digest(
        &self,
        domain: &'static [u8],
        owner: HiddenEvalInputOwner,
        label: &[u8],
        width_bits: u16,
        left_word: u64,
        right_word: u64,
        extra_material: &[&[u8]],
    ) -> [u8; 32] {
        let mut transcript = Transcript::new(domain);
        transcript.append_message(b"key_id", &self.evaluation_key.key_id);
        transcript.append_message(b"seed", &self.secret_seed.0);
        transcript.append_message(b"label", label);
        transcript.append_message(b"owner", owner_tag(owner));
        transcript.append_message(b"width_bits", &width_bits.to_le_bytes());
        transcript.append_message(b"left_word", &left_word.to_le_bytes());
        transcript.append_message(b"right_word", &right_word.to_le_bytes());
        for material in extra_material {
            transcript.append_message(b"extra", material);
        }
        let mut out = [0u8; 32];
        transcript.challenge_bytes(b"digest", &mut out);
        out
    }

    fn transport_key_for_purpose(&self, purpose: &str) -> [u8; 32] {
        let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/transport-key/v0");
        transcript.append_message(b"key_id", &self.evaluation_key.key_id);
        transcript.append_message(b"seed", &self.secret_seed.0);
        transcript.append_message(b"purpose", purpose.as_bytes());
        let mut out = [0u8; 32];
        transcript.challenge_bytes(b"transport_key", &mut out);
        out
    }

    fn derive_ot_branch_key_from_point(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        bit_idx: usize,
        branch_bit: u8,
        shared_point: [u8; 32],
    ) -> [u8; 32] {
        let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-branch-key/v1");
        transcript.append_message(b"key_id", &self.evaluation_key.key_id);
        transcript.append_message(b"owner", owner_tag(owner));
        transcript.append_message(b"label", label.as_bytes());
        transcript.append_message(b"bit_idx", &(bit_idx as u64).to_le_bytes());
        transcript.append_message(b"branch_bit", &[branch_bit]);
        transcript.append_message(b"shared_point", &shared_point);
        let mut out = [0u8; 32];
        transcript.challenge_bytes(b"ot_branch_key", &mut out);
        out
    }
}

impl DdhHssGarbler {
    pub fn evaluation_key(&self) -> &DdhHssEvaluationKey {
        self.backend.evaluation_key()
    }

    pub fn share_server_input_bundle(
        &self,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<DdhHssInputShareBundle> {
        self.backend
            .share_input_bundle(HiddenEvalInputOwner::Server, label, input)
    }

    pub fn share_server_input_bit_bundle(
        &self,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<DdhHssInputShareBundle> {
        self.backend
            .share_input_bit_bundle(HiddenEvalInputOwner::Server, label, input)
    }

    pub fn split_share_bundle(
        &self,
        bundle: &DdhHssInputShareBundle,
    ) -> (DdhHssTransportBundle, DdhHssTransportBundle) {
        self.backend.split_share_bundle(bundle)
    }

    pub fn join_share_bundle(
        &self,
        left: &DdhHssTransportBundle,
        right: &DdhHssTransportBundle,
    ) -> ProtoResult<DdhHssInputShareBundle> {
        self.backend.join_share_bundle(left, right)
    }

    pub fn prepare_client_input_ot_bundle_offer(
        &self,
        label: &str,
        bit_count: usize,
    ) -> ProtoResult<(
        DdhHssOtInputBundleOffer,
        DdhHssOtRemoteBundle,
        DdhHssOtSenderStateBundle,
    )> {
        self.backend
            .prepare_client_input_ot_bundle_offer(label, bit_count)
    }

    pub fn validate_client_input_ot_bundle_offer(
        &self,
        offer: &DdhHssOtInputBundleOffer,
        sender_state: &DdhHssOtSenderStateBundle,
        remote: &DdhHssOtRemoteBundle,
    ) -> ProtoResult<()> {
        if offer.owner != HiddenEvalInputOwner::Client
            || sender_state.owner != HiddenEvalInputOwner::Client
            || remote.owner != HiddenEvalInputOwner::Client
        {
            return Err(ProtoError::InvalidInput(
                "client OT validation requires client-owned offer, sender state, and remote bundles"
                    .to_string(),
            ));
        }
        if offer.label != sender_state.label || offer.label != remote.label {
            return Err(ProtoError::InvalidInput(format!(
                "client OT offer label does not match sender state or remote bundle: {}, {}, {}",
                offer.label, sender_state.label, remote.label
            )));
        }
        if remote.share_side != DdhHssShareSide::Right {
            return Err(ProtoError::InvalidInput(
                "client OT remote bundle must carry right-side shares".to_string(),
            ));
        }
        if offer.words.len() != remote.words.len() || offer.words.len() != sender_state.words.len()
        {
            return Err(ProtoError::InvalidInput(format!(
                "client OT offer word count does not match sender state / remote bundle: {} vs {} / {}",
                offer.words.len(),
                sender_state.words.len(),
                remote.words.len()
            )));
        }
        if remote.commitment
            != ot_remote_bundle_commitment(
                remote.owner,
                &remote.label,
                remote.share_side,
                &remote.words,
            )
        {
            return Err(ProtoError::InvalidInput(
                "client OT remote bundle commitment is invalid".to_string(),
            ));
        }
        if offer.commitment != ot_offer_bundle_commitment(offer.owner, &offer.label, &offer.words) {
            return Err(ProtoError::InvalidInput(
                "client OT offer commitment is invalid".to_string(),
            ));
        }
        if sender_state.commitment
            != ot_sender_state_bundle_commitment(
                sender_state.owner,
                &sender_state.label,
                &sender_state.words,
            )
        {
            return Err(ProtoError::InvalidInput(
                "client OT sender-state commitment is invalid".to_string(),
            ));
        }

        for (bit_idx, ((word_offer, sender_state_word), remote_word)) in offer
            .words
            .iter()
            .zip(&sender_state.words)
            .zip(&remote.words)
            .enumerate()
        {
            if word_offer.width_bits != 1
                || sender_state_word.width_bits != 1
                || remote_word.width_bits != 1
            {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT words must be 1-bit at index {bit_idx}"
                )));
            }
            let sender_public_point = CompressedEdwardsY(word_offer.sender_public)
                .decompress()
                .ok_or_else(|| {
                    ProtoError::InvalidInput(format!(
                        "client OT sender public point is invalid at bit index {bit_idx}"
                    ))
                })?;
            if sender_state_word.sender_public != word_offer.sender_public {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT sender-state public point does not match offer at bit index {bit_idx}"
                )));
            }
            let sender_scalar = Scalar::from_bytes_mod_order(sender_state_word.sender_scalar);
            if sender_public_point != (ED25519_BASEPOINT_POINT * sender_scalar) {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT sender-state scalar does not match offer public point at bit index {bit_idx}"
                )));
            }
        }

        Ok(())
    }

    pub fn resolve_client_input_ot_selection(
        &self,
        offer: &DdhHssOtInputBundleOffer,
        sender_state: &DdhHssOtSenderStateBundle,
        remote: &DdhHssOtRemoteBundle,
        request: &DdhHssOtSelectionBundle,
    ) -> ProtoResult<(DdhHssOtResponseBundle, DdhHssOtReleasedRemoteBundle)> {
        self.validate_client_input_ot_bundle_offer(offer, sender_state, remote)?;
        if request.owner != HiddenEvalInputOwner::Client {
            return Err(ProtoError::InvalidInput(
                "client OT request must be client-owned".to_string(),
            ));
        }
        if request.label != offer.label {
            return Err(ProtoError::InvalidInput(format!(
                "client OT request label does not match offer: {} vs {}",
                request.label, offer.label
            )));
        }
        if request.words.len() != offer.words.len() {
            return Err(ProtoError::InvalidInput(format!(
                "client OT request word count does not match offer: {} vs {}",
                request.words.len(),
                offer.words.len()
            )));
        }
        if request.commitment
            != ot_request_bundle_commitment(request.owner, &request.label, &request.words)
        {
            return Err(ProtoError::InvalidInput(
                "client OT request commitment is invalid".to_string(),
            ));
        }

        let mut response_words = Vec::with_capacity(request.words.len());
        for (bit_idx, (((request_word, word_offer), sender_state_word), remote_word)) in request
            .words
            .iter()
            .zip(&offer.words)
            .zip(&sender_state.words)
            .zip(&remote.words)
            .enumerate()
        {
            let bit_label = format!("{}/{bit_idx}", offer.label);
            if request_word.width_bits != 1
                || word_offer.width_bits != 1
                || sender_state_word.width_bits != 1
                || remote_word.width_bits != 1
            {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT request words must be 1-bit at index {bit_idx}"
                )));
            }
            let sender_scalar = Scalar::from_bytes_mod_order(sender_state_word.sender_scalar);
            let sender_public_point = CompressedEdwardsY(word_offer.sender_public)
                .decompress()
                .ok_or_else(|| {
                    ProtoError::InvalidInput(format!(
                        "client OT sender public point is invalid at bit index {bit_idx}"
                    ))
                })?;
            let receiver_public_point = CompressedEdwardsY(request_word.receiver_public)
                .decompress()
                .ok_or_else(|| {
                    ProtoError::InvalidInput(format!(
                        "client OT receiver public point is invalid at bit index {bit_idx}"
                    ))
                })?;
            if sender_state_word.sender_public != word_offer.sender_public {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT sender-state public point does not match offer at bit index {bit_idx}"
                )));
            }
            if sender_public_point != (ED25519_BASEPOINT_POINT * sender_scalar) {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT sender-state scalar does not match sender public point at bit index {bit_idx}"
                )));
            }

            let zero_left_word = reduce_word(
                modulus_for_width(1).wrapping_sub(u128::from(remote_word.share_word)),
                1,
            );
            let one_left_word = reduce_word(
                u128::from(1u8)
                    .wrapping_add(modulus_for_width(1))
                    .wrapping_sub(u128::from(remote_word.share_word)),
                1,
            );
            let zero_provenance_digest = self.backend.derive_digest(
                b"client-input-ot/zero-branch",
                HiddenEvalInputOwner::Client,
                bit_label.as_bytes(),
                1,
                zero_left_word,
                remote_word.share_word,
                &[],
            );
            let one_provenance_digest = self.backend.derive_digest(
                b"client-input-ot/one-branch",
                HiddenEvalInputOwner::Client,
                bit_label.as_bytes(),
                1,
                one_left_word,
                remote_word.share_word,
                &[],
            );
            let zero_payload = DdhHssOtBranchPayload {
                width_bits: 1,
                share_word: zero_left_word,
                share_commitment: commit_word(
                    HiddenEvalInputOwner::Client,
                    b"left",
                    zero_left_word,
                    &zero_provenance_digest,
                ),
                counterparty_commitment: remote_word.share_commitment,
                provenance_digest: zero_provenance_digest,
            };
            let one_payload = DdhHssOtBranchPayload {
                width_bits: 1,
                share_word: one_left_word,
                share_commitment: commit_word(
                    HiddenEvalInputOwner::Client,
                    b"left",
                    one_left_word,
                    &one_provenance_digest,
                ),
                counterparty_commitment: remote_word.share_commitment,
                provenance_digest: one_provenance_digest,
            };

            let zero_shared = (receiver_public_point * sender_scalar)
                .compress()
                .to_bytes();
            let one_shared = ((receiver_public_point - sender_public_point) * sender_scalar)
                .compress()
                .to_bytes();
            let zero_key = self.backend.derive_ot_branch_key_from_point(
                HiddenEvalInputOwner::Client,
                &offer.label,
                bit_idx,
                0,
                zero_shared,
            );
            let one_key = self.backend.derive_ot_branch_key_from_point(
                HiddenEvalInputOwner::Client,
                &offer.label,
                bit_idx,
                1,
                one_shared,
            );
            response_words.push(DdhHssOtResponseWord {
                width_bits: 1,
                zero_branch: DdhHssBackend::seal_ot_branch_with_key(
                    zero_key,
                    HiddenEvalInputOwner::Client,
                    &offer.label,
                    bit_idx,
                    0,
                    &zero_payload,
                )?,
                one_branch: DdhHssBackend::seal_ot_branch_with_key(
                    one_key,
                    HiddenEvalInputOwner::Client,
                    &offer.label,
                    bit_idx,
                    1,
                    &one_payload,
                )?,
            });
        }

        let response_commitment = ot_response_bundle_commitment(
            HiddenEvalInputOwner::Client,
            &offer.label,
            &response_words,
        );
        let response = DdhHssOtResponseBundle {
            owner: HiddenEvalInputOwner::Client,
            label: offer.label.clone(),
            commitment: response_commitment,
            words: response_words,
        };
        let released_remote = DdhHssOtReleasedRemoteBundle {
            owner: remote.owner,
            label: remote.label.clone(),
            share_side: remote.share_side,
            words: remote.words.clone(),
            commitment: remote.commitment,
            offer_commitment: offer.commitment,
            request_commitment: request.commitment,
            response_commitment,
            transcript_binding: ot_remote_release_transcript_binding(
                remote.owner,
                &remote.label,
                offer.commitment,
                request.commitment,
                response_commitment,
                remote.commitment,
            ),
        };
        Ok((response, released_remote))
    }

    pub fn share_derived_bundle(
        &self,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<DdhHssInputShareBundle> {
        self.backend
            .share_input_bundle(HiddenEvalInputOwner::Derived, label, input)
    }

    pub fn combined_input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        bundles: &[&DdhHssInputShareBundle],
    ) -> [u8; 32] {
        self.backend.combined_input_commitment(owner, bundles)
    }

    pub fn run_binding(
        &self,
        artifact_digest: [u8; 32],
        client_input_commitment: [u8; 32],
        server_input_commitment: [u8; 32],
    ) -> [u8; 32] {
        self.backend.run_binding(
            artifact_digest,
            client_input_commitment,
            server_input_commitment,
        )
    }

    pub fn seal_message(
        &self,
        purpose: DdhHssTransportPurpose,
        aad: &[u8],
        plaintext: &[u8],
    ) -> ProtoResult<([u8; 12], Vec<u8>)> {
        if purpose != DdhHssTransportPurpose::ServerInput
            && purpose != DdhHssTransportPurpose::ServerOutput
        {
            return Err(ProtoError::InvalidInput(format!(
                "garbler cannot seal transport purpose {}",
                purpose.as_str()
            )));
        }
        self.backend
            .seal_transport_message(purpose.as_str(), aad, plaintext)
    }

    pub fn open_message(
        &self,
        purpose: DdhHssTransportPurpose,
        aad: &[u8],
        nonce: [u8; 12],
        ciphertext: &[u8],
    ) -> ProtoResult<Vec<u8>> {
        if purpose != DdhHssTransportPurpose::ServerInput
            && purpose != DdhHssTransportPurpose::ServerOutput
        {
            return Err(ProtoError::InvalidInput(format!(
                "garbler cannot open transport purpose {}",
                purpose.as_str()
            )));
        }
        self.backend
            .open_transport_message(purpose.as_str(), aad, nonce, ciphertext)
    }

    pub fn decode_server_bundle(&self, bundle: &DdhHssInputShareBundle) -> ProtoResult<Vec<u8>> {
        if bundle.owner != HiddenEvalInputOwner::Server {
            return Err(ProtoError::InvalidInput(
                "garbler can only decode server-owned bundles".to_string(),
            ));
        }
        self.backend.decode_words(&bundle.words)
    }

    pub fn decode_server_bit_bundle_array(
        &self,
        bundle: &DdhHssInputShareBundle,
    ) -> ProtoResult<[u8; 32]> {
        if bundle.owner != HiddenEvalInputOwner::Server {
            return Err(ProtoError::InvalidInput(
                "garbler can only decode server-owned bundles".to_string(),
            ));
        }
        decode_bit_bundle_array(&self.backend, bundle)
    }
}

impl DdhHssEvaluator {
    pub fn evaluation_key(&self) -> &DdhHssEvaluationKey {
        &self.public_state.evaluation_key
    }

    pub fn prepare_client_input_ot_request(
        &self,
        offer: &DdhHssOtInputBundleOffer,
        input: &[u8],
    ) -> ProtoResult<(DdhHssOtSelectionBundle, DdhHssOtReceiverStateBundle)> {
        prepare_client_input_ot_request_public(offer, input)
    }

    pub fn open_client_input_ot_bundle(
        &self,
        response: &DdhHssOtResponseBundle,
        local_state: &DdhHssOtReceiverStateBundle,
    ) -> ProtoResult<DdhHssTransportBundle> {
        open_client_input_ot_bundle_public(&self.public_state.evaluation_key, response, local_state)
    }

    pub fn join_client_ot_bundle(
        &self,
        local: &DdhHssTransportBundle,
        remote: &DdhHssOtReleasedRemoteBundle,
    ) -> ProtoResult<DdhHssInputShareBundle> {
        join_client_ot_bundle_public(&self.public_state.evaluation_key, local, remote)
    }

    pub fn join_share_bundle(
        &self,
        left: &DdhHssTransportBundle,
        right: &DdhHssTransportBundle,
    ) -> ProtoResult<DdhHssInputShareBundle> {
        join_share_bundle_public(&self.public_state.evaluation_key, left, right)
    }

    pub fn combined_input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        bundles: &[&DdhHssInputShareBundle],
    ) -> [u8; 32] {
        combined_input_commitment_for_key(&self.public_state.evaluation_key, owner, bundles)
    }

    pub fn run_binding(
        &self,
        artifact_digest: [u8; 32],
        client_input_commitment: [u8; 32],
        server_input_commitment: [u8; 32],
    ) -> [u8; 32] {
        run_binding_for_key(
            &self.public_state.evaluation_key,
            artifact_digest,
            client_input_commitment,
            server_input_commitment,
        )
    }

    pub fn share_word(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        value: u64,
        width_bits: u16,
    ) -> ProtoResult<DdhHssSharedWord> {
        share_word_for_key(
            &self.public_state.evaluation_key,
            owner,
            label,
            value,
            width_bits,
        )
    }

    pub fn input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        words: &[DdhHssSharedWord],
    ) -> [u8; 32] {
        input_commitment_for_key(&self.public_state.evaluation_key, owner, label, words)
    }

    pub fn eval_add_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        ensure_same_width(left, right)?;
        let width_bits = left.width_bits;
        if width_bits == 1 {
            return Ok(eval_add_bit_for_key(&self.public_state.evaluation_key, left, right));
        }
        let left_word = reduce_word(
            u128::from(left.left_word) + u128::from(right.left_word),
            width_bits,
        );
        let right_word = reduce_word(
            u128::from(left.right_word) + u128::from(right.right_word),
            width_bits,
        );
        Ok(build_shared_word_for_key(
            &self.public_state.evaluation_key,
            b"eval-add-public",
            HiddenEvalInputOwner::Derived,
            b"add",
            width_bits,
            left_word,
            right_word,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &right.left_commitment,
            ],
        ))
    }

    pub fn prepare_mul_material(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssMulMaterial> {
        ensure_same_width(left, right)?;
        let width_bits = left.width_bits;
        let triple_a_clear = derive_masked_word_for_key(
            &self.public_state.evaluation_key,
            b"eval-mul/triple-a-public",
            HiddenEvalInputOwner::Derived,
            b"mul",
            0,
            width_bits,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
            ],
        );
        let triple_b_clear = derive_masked_word_for_key(
            &self.public_state.evaluation_key,
            b"eval-mul/triple-b-public",
            HiddenEvalInputOwner::Derived,
            b"mul",
            0,
            width_bits,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
            ],
        );
        let triple_c_clear = reduce_word(
            u128::from(triple_a_clear) * u128::from(triple_b_clear),
            width_bits,
        );
        let triple_a = share_word_for_key(
            &self.public_state.evaluation_key,
            HiddenEvalInputOwner::Derived,
            "mul/triple_a",
            triple_a_clear,
            width_bits,
        )?;
        let triple_b = share_word_for_key(
            &self.public_state.evaluation_key,
            HiddenEvalInputOwner::Derived,
            "mul/triple_b",
            triple_b_clear,
            width_bits,
        )?;
        let triple_c = share_word_for_key(
            &self.public_state.evaluation_key,
            HiddenEvalInputOwner::Derived,
            "mul/triple_c",
            triple_c_clear,
            width_bits,
        )?;
        let provenance_digest = derive_digest_for_key(
            &self.public_state.evaluation_key,
            b"eval-mul-material-public",
            HiddenEvalInputOwner::Derived,
            b"mul",
            width_bits,
            triple_a_clear,
            triple_b_clear,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
                &triple_c.provenance_digest,
            ],
        );
        Ok(DdhHssMulMaterial {
            width_bits,
            triple_a,
            triple_b,
            triple_c,
            provenance_digest,
        })
    }

    pub fn eval_mul_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
        material: &DdhHssMulMaterial,
    ) -> ProtoResult<DdhHssSharedWord> {
        ensure_same_width(left, right)?;
        let width_bits = left.width_bits;
        if material.width_bits != width_bits {
            return Err(ProtoError::InvalidInput(format!(
                "multiplication material width does not match operands: {} vs {}",
                material.width_bits, width_bits
            )));
        }
        let d_left = reduce_word(
            u128::from(left.left_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_a.left_word)),
            width_bits,
        );
        let d_right = reduce_word(
            u128::from(left.right_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_a.right_word)),
            width_bits,
        );
        let e_left = reduce_word(
            u128::from(right.left_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_b.left_word)),
            width_bits,
        );
        let e_right = reduce_word(
            u128::from(right.right_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_b.right_word)),
            width_bits,
        );
        let d_open = reduce_word(u128::from(d_left) + u128::from(d_right), width_bits);
        let e_open = reduce_word(u128::from(e_left) + u128::from(e_right), width_bits);

        let left_word = reduce_word(
            u128::from(material.triple_c.left_word)
                + (u128::from(d_open) * u128::from(material.triple_b.left_word))
                + (u128::from(e_open) * u128::from(material.triple_a.left_word))
                + (u128::from(d_open) * u128::from(e_open)),
            width_bits,
        );
        let right_word = reduce_word(
            u128::from(material.triple_c.right_word)
                + (u128::from(d_open) * u128::from(material.triple_b.right_word))
                + (u128::from(e_open) * u128::from(material.triple_a.right_word)),
            width_bits,
        );

        Ok(build_shared_word_for_key(
            &self.public_state.evaluation_key,
            b"eval-mul-public",
            HiddenEvalInputOwner::Derived,
            b"mul",
            width_bits,
            left_word,
            right_word,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
                &material.provenance_digest,
            ],
        ))
    }

    pub fn eval_mul_bit(
        &self,
        label: &str,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        eval_mul_bit_for_key(
            &self.public_state.evaluation_key,
            label.as_bytes(),
            left,
            right,
        )
    }

    pub fn compose_word_from_share_bits(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        bits: &[DdhHssSharedWord],
    ) -> ProtoResult<DdhHssSharedWord> {
        if bits.is_empty() || bits.len() > 64 {
            return Err(ProtoError::InvalidInput(format!(
                "bit composition requires 1..=64 bits, got {}",
                bits.len()
            )));
        }

        let mut left_word = 0u64;
        let mut right_word = 0u64;
        let mut extra_material = Vec::with_capacity(bits.len() * 3);
        for (idx, bit) in bits.iter().enumerate() {
            if bit.width_bits != 1 {
                return Err(ProtoError::InvalidInput(format!(
                    "bit composition requires 1-bit words, got {} at index {}",
                    bit.width_bits, idx
                )));
            }
            left_word |= (bit.left_word & 1) << idx;
            right_word |= (bit.right_word & 1) << idx;
            extra_material.push(bit.provenance_digest.as_slice());
            extra_material.push(bit.left_commitment.as_slice());
            extra_material.push(bit.right_commitment.as_slice());
        }

        Ok(build_shared_word_for_key(
            &self.public_state.evaluation_key,
            b"compose-word-from-share-bits-public",
            owner,
            label.as_bytes(),
            bits.len() as u16,
            left_word,
            right_word,
            &extra_material,
        ))
    }

    pub fn seal_message(
        &self,
        purpose: DdhHssTransportPurpose,
        aad: &[u8],
        plaintext: &[u8],
    ) -> ProtoResult<([u8; 12], Vec<u8>)> {
        if purpose != DdhHssTransportPurpose::ClientOutput {
            return Err(ProtoError::InvalidInput(format!(
                "evaluator cannot seal transport purpose {}",
                purpose.as_str()
            )));
        }
        seal_transport_message_with_key(
            &self.client_output_transport_key,
            purpose.as_str(),
            aad,
            plaintext,
        )
    }

    pub fn open_message(
        &self,
        purpose: DdhHssTransportPurpose,
        aad: &[u8],
        nonce: [u8; 12],
        ciphertext: &[u8],
    ) -> ProtoResult<Vec<u8>> {
        let key = match purpose {
            DdhHssTransportPurpose::ServerInput => &self.server_input_transport_key,
            DdhHssTransportPurpose::ClientOutput => &self.client_output_transport_key,
            DdhHssTransportPurpose::ServerOutput => {
                return Err(ProtoError::InvalidInput(format!(
                    "evaluator cannot open transport purpose {}",
                    purpose.as_str()
                )));
            }
        };
        open_transport_message_with_key(key, purpose.as_str(), aad, nonce, ciphertext)
    }

    pub fn server_input_transport_key(&self) -> &[u8; 32] {
        &self.server_input_transport_key.0
    }

    pub fn client_output_transport_key(&self) -> &[u8; 32] {
        &self.client_output_transport_key.0
    }

    pub fn decode_client_bundle(&self, bundle: &DdhHssInputShareBundle) -> ProtoResult<Vec<u8>> {
        if bundle.owner != HiddenEvalInputOwner::Client {
            return Err(ProtoError::InvalidInput(format!(
                "evaluator can only decode client-owned bundles"
            )));
        }
        decode_words_public(&bundle.words)
    }

    pub fn decode_client_bit_bundle_array(
        &self,
        bundle: &DdhHssInputShareBundle,
    ) -> ProtoResult<[u8; 32]> {
        if bundle.owner != HiddenEvalInputOwner::Client {
            return Err(ProtoError::InvalidInput(
                "evaluator can only decode client-owned bundles".to_string(),
            ));
        }
        decode_bit_bundle_array_public(bundle)
    }
}

impl FixedFunctionHssBackend for DdhHssBackend {
    type SharedValue = DdhHssSharedWord;

    fn primitive_kind(&self) -> HssPrimitiveKind {
        HssPrimitiveKind::PrimeOrderDdh
    }

    fn share_input(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<Vec<Self::SharedValue>> {
        input
            .iter()
            .enumerate()
            .map(|(idx, value)| {
                self.share_word(owner, &format!("{label}/{idx}"), u64::from(*value), 8)
            })
            .collect()
    }

    fn eval_add(
        &self,
        left: &Self::SharedValue,
        right: &Self::SharedValue,
    ) -> ProtoResult<Self::SharedValue> {
        self.eval_add_mod_2_pow_n(left, right)
    }

    fn eval_mul(
        &self,
        left: &Self::SharedValue,
        right: &Self::SharedValue,
    ) -> ProtoResult<Self::SharedValue> {
        let material = self.prepare_mul_material(left, right)?;
        self.eval_mul_mod_2_pow_n(left, right, &material)
    }

    fn decode_words(&self, values: &[Self::SharedValue]) -> ProtoResult<Vec<u8>> {
        let mut out = Vec::new();
        for value in values {
            let word = self.decode_word(value);
            let width_bytes = usize::from((value.width_bits + 7) / 8);
            let bytes = word.to_le_bytes();
            out.extend_from_slice(&bytes[..width_bytes]);
        }
        Ok(out)
    }
}

impl DdhHssArithmeticBackend for DdhHssBackend {
    fn evaluation_key(&self) -> &DdhHssEvaluationKey {
        self.evaluation_key()
    }

    fn share_word(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        value: u64,
        width_bits: u16,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssBackend::share_word(self, owner, label, value, width_bits)
    }

    fn input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        words: &[DdhHssSharedWord],
    ) -> [u8; 32] {
        DdhHssBackend::input_commitment(self, owner, label, words)
    }

    fn combined_input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        bundles: &[&DdhHssInputShareBundle],
    ) -> [u8; 32] {
        DdhHssBackend::combined_input_commitment(self, owner, bundles)
    }

    fn eval_add_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssBackend::eval_add_mod_2_pow_n(self, left, right)
    }

    fn prepare_mul_material(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssMulMaterial> {
        DdhHssBackend::prepare_mul_material(self, left, right)
    }

    fn eval_mul_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
        material: &DdhHssMulMaterial,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssBackend::eval_mul_mod_2_pow_n(self, left, right, material)
    }

    fn eval_mul_bit(
        &self,
        label: &str,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssBackend::eval_mul_bit(self, label, left, right)
    }

    fn compose_word_from_share_bits(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        bits: &[DdhHssSharedWord],
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssBackend::compose_word_from_share_bits(self, owner, label, bits)
    }
}

impl DdhHssArithmeticBackend for DdhHssEvaluator {
    fn evaluation_key(&self) -> &DdhHssEvaluationKey {
        self.evaluation_key()
    }

    fn share_word(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        value: u64,
        width_bits: u16,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssEvaluator::share_word(self, owner, label, value, width_bits)
    }

    fn input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        words: &[DdhHssSharedWord],
    ) -> [u8; 32] {
        DdhHssEvaluator::input_commitment(self, owner, label, words)
    }

    fn combined_input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        bundles: &[&DdhHssInputShareBundle],
    ) -> [u8; 32] {
        DdhHssEvaluator::combined_input_commitment(self, owner, bundles)
    }

    fn eval_add_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssEvaluator::eval_add_mod_2_pow_n(self, left, right)
    }

    fn prepare_mul_material(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssMulMaterial> {
        DdhHssEvaluator::prepare_mul_material(self, left, right)
    }

    fn eval_mul_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
        material: &DdhHssMulMaterial,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssEvaluator::eval_mul_mod_2_pow_n(self, left, right, material)
    }

    fn eval_mul_bit(
        &self,
        label: &str,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssEvaluator::eval_mul_bit(self, label, left, right)
    }

    fn compose_word_from_share_bits(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        bits: &[DdhHssSharedWord],
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssEvaluator::compose_word_from_share_bits(self, owner, label, bits)
    }
}

impl DdhHssTransportPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            DdhHssTransportPurpose::ServerInput => "server_input",
            DdhHssTransportPurpose::ClientOutput => "client_output",
            DdhHssTransportPurpose::ServerOutput => "server_output",
        }
    }
}

fn hash_hidden_eval_program(program: &HiddenEvalProgram) -> ProtoResult<[u8; 32]> {
    let json = serde_json::to_vec(program).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to serialize hidden-eval program for digest: {err}"
        ))
    })?;
    let digest = Sha256::digest(json);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn ensure_same_width(left: &DdhHssSharedWord, right: &DdhHssSharedWord) -> ProtoResult<()> {
    if left.width_bits != right.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "shared word widths do not match: {} vs {}",
            left.width_bits, right.width_bits
        )));
    }
    Ok(())
}

fn modulus_for_width(width_bits: u16) -> u128 {
    if width_bits == 64 {
        u128::from(u64::MAX) + 1
    } else {
        1u128 << width_bits
    }
}

fn reduce_word(value: u128, width_bits: u16) -> u64 {
    let masked = if width_bits == 64 {
        value & u128::from(u64::MAX)
    } else {
        value & ((1u128 << width_bits) - 1)
    };
    masked as u64
}

fn commit_word(
    owner: HiddenEvalInputOwner,
    side_label: &'static [u8],
    word: u64,
    provenance_digest: &[u8; 32],
) -> [u8; 32] {
    match owner {
        HiddenEvalInputOwner::Client | HiddenEvalInputOwner::Server => (ED25519_BASEPOINT_POINT
            * Scalar::from(word))
        .compress()
        .to_bytes(),
        HiddenEvalInputOwner::Derived => {
            let mut hasher = Blake3Hasher::new();
            hasher.update(b"succinct-garbling-proto/ddh-hss/derived-commitment/v0");
            hasher.update(side_label);
            hasher.update(&word.to_le_bytes());
            hasher.update(provenance_digest);
            *hasher.finalize().as_bytes()
        }
    }
}

fn owner_tag(owner: HiddenEvalInputOwner) -> &'static [u8] {
    match owner {
        HiddenEvalInputOwner::Client => b"client",
        HiddenEvalInputOwner::Server => b"server",
        HiddenEvalInputOwner::Derived => b"derived",
    }
}

fn input_commitment_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    owner: HiddenEvalInputOwner,
    label: &str,
    words: &[DdhHssSharedWord],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/input-commitment/v0");
    transcript.append_message(b"key_id", &evaluation_key.key_id);
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"left_commitment", &word.left_commitment);
        transcript.append_message(b"right_commitment", &word.right_commitment);
        transcript.append_message(b"provenance", &word.provenance_digest);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"input_commitment", &mut out);
    out
}

fn share_word_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    owner: HiddenEvalInputOwner,
    label: &str,
    value: u64,
    width_bits: u16,
) -> ProtoResult<DdhHssSharedWord> {
    let (left_word, right_word) = split_clear_word_for_key(
        evaluation_key,
        b"share-left-public",
        owner,
        label.as_bytes(),
        value,
        width_bits,
        &[],
    )?;

    Ok(build_shared_word_for_key(
        evaluation_key,
        b"share-word-public",
        owner,
        label.as_bytes(),
        width_bits,
        left_word,
        right_word,
        &[],
    ))
}

fn split_clear_word_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    owner: HiddenEvalInputOwner,
    label: &[u8],
    value: u64,
    width_bits: u16,
    extra_material: &[&[u8]],
) -> ProtoResult<(u64, u64)> {
    if !(1..=64).contains(&width_bits) {
        return Err(ProtoError::InvalidInput(format!(
            "shared word width must be in 1..=64 bits, got {width_bits}"
        )));
    }

    let clear_value = reduce_word(u128::from(value), width_bits);
    let left_word = derive_masked_word_for_key(
        evaluation_key,
        domain,
        owner,
        label,
        clear_value,
        width_bits,
        extra_material,
    );
    let right_word = reduce_word(
        u128::from(clear_value)
            .wrapping_add(modulus_for_width(width_bits))
            .wrapping_sub(u128::from(left_word)),
        width_bits,
    );
    Ok((left_word, right_word))
}

fn combined_input_commitment_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    owner: HiddenEvalInputOwner,
    bundles: &[&DdhHssInputShareBundle],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/ddh-hss/combined-input-commitment/v0");
    hasher.update(&evaluation_key.key_id);
    match owner {
        HiddenEvalInputOwner::Client => hasher.update(b"client"),
        HiddenEvalInputOwner::Server => hasher.update(b"server"),
        HiddenEvalInputOwner::Derived => hasher.update(b"derived"),
    }
    for bundle in bundles {
        hasher.update(bundle.commitment);
        hasher.update(bundle.label.as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn run_binding_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    artifact_digest: [u8; 32],
    client_input_commitment: [u8; 32],
    server_input_commitment: [u8; 32],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/run-binding/v0");
    transcript.append_message(b"key_id", &evaluation_key.key_id);
    transcript.append_message(b"artifact_digest", &artifact_digest);
    transcript.append_message(b"context_binding", &evaluation_key.context_binding);
    transcript.append_message(b"candidate_digest", &evaluation_key.candidate_digest);
    transcript.append_message(b"client_input_commitment", &client_input_commitment);
    transcript.append_message(b"server_input_commitment", &server_input_commitment);
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"run_binding", &mut out);
    out
}

fn derive_digest_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    owner: HiddenEvalInputOwner,
    label: &[u8],
    width_bits: u16,
    left_word: u64,
    right_word: u64,
    extra_material: &[&[u8]],
) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(domain);
    hasher.update(&evaluation_key.key_id);
    hasher.update(label);
    hasher.update(owner_tag(owner));
    hasher.update(&width_bits.to_le_bytes());
    hasher.update(&left_word.to_le_bytes());
    hasher.update(&right_word.to_le_bytes());
    for material in extra_material {
        hasher.update(&(material.len() as u64).to_le_bytes());
        hasher.update(material);
    }
    *hasher.finalize().as_bytes()
}

fn derive_masked_word_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    owner: HiddenEvalInputOwner,
    label: &[u8],
    clear_value: u64,
    width_bits: u16,
    extra_material: &[&[u8]],
) -> u64 {
    let digest = derive_digest_for_key(
        evaluation_key,
        domain,
        owner,
        label,
        width_bits,
        clear_value,
        0,
        extra_material,
    );
    let sample = u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"));
    reduce_word(u128::from(sample), width_bits)
}

fn build_shared_word_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    owner: HiddenEvalInputOwner,
    label: &[u8],
    width_bits: u16,
    left_word: u64,
    right_word: u64,
    extra_material: &[&[u8]],
) -> DdhHssSharedWord {
    let provenance_digest = derive_digest_for_key(
        evaluation_key,
        domain,
        owner,
        label,
        width_bits,
        left_word,
        right_word,
        extra_material,
    );
    let left_commitment = commit_word(owner, b"left", left_word, &provenance_digest);
    let right_commitment = commit_word(owner, b"right", right_word, &provenance_digest);

    DdhHssSharedWord {
        width_bits,
        left_word,
        right_word,
        left_commitment,
        right_commitment,
        provenance_digest,
    }
}

fn eval_add_bit_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    left: &DdhHssSharedWord,
    right: &DdhHssSharedWord,
) -> DdhHssSharedWord {
    let left_word = (left.left_word ^ right.left_word) & 1;
    let right_word = (left.right_word ^ right.right_word) & 1;

    let mut hasher = Blake3Hasher::new();
    hasher.update(b"succinct-garbling-proto/ddh-hss/eval-add-bit/v0");
    hasher.update(&evaluation_key.key_id);
    hasher.update(&left.provenance_digest);
    hasher.update(&right.provenance_digest);
    hasher.update(&left.left_commitment);
    hasher.update(&right.left_commitment);
    let provenance_digest = *hasher.finalize().as_bytes();

    let left_commitment = commit_word(
        HiddenEvalInputOwner::Derived,
        b"left",
        left_word,
        &provenance_digest,
    );
    let right_commitment = commit_word(
        HiddenEvalInputOwner::Derived,
        b"right",
        right_word,
        &provenance_digest,
    );

    DdhHssSharedWord {
        width_bits: 1,
        left_word,
        right_word,
        left_commitment,
        right_commitment,
        provenance_digest,
    }
}

fn eval_mul_bit_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    gate_key: &[u8],
    left: &DdhHssSharedWord,
    right: &DdhHssSharedWord,
) -> ProtoResult<DdhHssSharedWord> {
    ensure_same_width(left, right)?;
    if left.width_bits != 1 {
        return Err(ProtoError::InvalidInput(format!(
            "bit multiplication requires 1-bit operands, got {}",
            left.width_bits
        )));
    }

    let mut material_hasher = Blake3Hasher::new();
    material_hasher.update(b"succinct-garbling-proto/ddh-hss/eval-mul-bit/v1");
    material_hasher.update(&evaluation_key.key_id);
    material_hasher.update(gate_key);
    material_hasher.update(owner_tag(HiddenEvalInputOwner::Derived));
    material_hasher.update(&1u16.to_le_bytes());
    material_hasher.update(&left.provenance_digest);
    material_hasher.update(&right.provenance_digest);
    material_hasher.update(&left.left_commitment);
    material_hasher.update(&left.right_commitment);
    material_hasher.update(&right.left_commitment);
    material_hasher.update(&right.right_commitment);
    let material_digest = material_hasher.finalize();

    let mut triple_bytes = [0u8; 5];
    triple_bytes.copy_from_slice(&material_digest.as_bytes()[..5]);

    let triple_a_clear = u64::from(triple_bytes[0] & 1);
    let triple_b_clear = u64::from(triple_bytes[1] & 1);
    let triple_a_left = u64::from(triple_bytes[2] & 1);
    let triple_b_left = u64::from(triple_bytes[3] & 1);
    let triple_c_left = u64::from(triple_bytes[4] & 1);

    let triple_a_right = triple_a_clear ^ triple_a_left;
    let triple_b_right = triple_b_clear ^ triple_b_left;
    let triple_c_clear = triple_a_clear & triple_b_clear;
    let triple_c_right = triple_c_clear ^ triple_c_left;

    let mut output_seed_hasher = Blake3Hasher::new();
    output_seed_hasher.update(b"succinct-garbling-proto/ddh-hss/eval-mul-bit-output/v1");
    output_seed_hasher.update(material_digest.as_bytes());
    let output_seed = *output_seed_hasher.finalize().as_bytes();

    let d_left = reduce_word(
        u128::from(left.left_word)
            .wrapping_add(modulus_for_width(1))
            .wrapping_sub(u128::from(triple_a_left)),
        1,
    );
    let d_right = reduce_word(
        u128::from(left.right_word)
            .wrapping_add(modulus_for_width(1))
            .wrapping_sub(u128::from(triple_a_right)),
        1,
    );
    let e_left = reduce_word(
        u128::from(right.left_word)
            .wrapping_add(modulus_for_width(1))
            .wrapping_sub(u128::from(triple_b_left)),
        1,
    );
    let e_right = reduce_word(
        u128::from(right.right_word)
            .wrapping_add(modulus_for_width(1))
            .wrapping_sub(u128::from(triple_b_right)),
        1,
    );
    let d_open = reduce_word(u128::from(d_left) + u128::from(d_right), 1);
    let e_open = reduce_word(u128::from(e_left) + u128::from(e_right), 1);

    let left_word = reduce_word(
        u128::from(triple_c_left)
            + (u128::from(d_open) * u128::from(triple_b_left))
            + (u128::from(e_open) * u128::from(triple_a_left))
            + (u128::from(d_open) * u128::from(e_open)),
        1,
    );
    let right_word = reduce_word(
        u128::from(triple_c_right)
            + (u128::from(d_open) * u128::from(triple_b_right))
            + (u128::from(e_open) * u128::from(triple_a_right)),
        1,
    );

    let output_material = [
        &left.provenance_digest[..],
        &right.provenance_digest[..],
        &output_seed[..],
    ];
    Ok(build_shared_word_for_key(
        evaluation_key,
        b"eval-mul-public",
        HiddenEvalInputOwner::Derived,
        b"mul",
        1,
        left_word,
        right_word,
        &output_material,
    ))
}

fn decode_word_public(value: &DdhHssSharedWord) -> u64 {
    reduce_word(
        u128::from(value.left_word) + u128::from(value.right_word),
        value.width_bits,
    )
}

fn decode_words_public(values: &[DdhHssSharedWord]) -> ProtoResult<Vec<u8>> {
    let mut out = Vec::new();
    for value in values {
        let word = decode_word_public(value);
        let width_bytes = usize::from((value.width_bits + 7) / 8);
        let bytes = word.to_le_bytes();
        out.extend_from_slice(&bytes[..width_bytes]);
    }
    Ok(out)
}

fn decode_bit_bundle_array(
    backend: &DdhHssBackend,
    bundle: &DdhHssInputShareBundle,
) -> ProtoResult<[u8; 32]> {
    if bundle.words.len() != 256 {
        return Err(ProtoError::Decode(format!(
            "bit bundle must contain exactly 256 words, got {}",
            bundle.words.len()
        )));
    }
    if bundle.words.iter().any(|word| word.width_bits != 1) {
        return Err(ProtoError::Decode(
            "bit bundle must contain only 1-bit words".to_string(),
        ));
    }

    let mut out = [0u8; 32];
    for byte_idx in 0..32 {
        let mut value = 0u8;
        for bit_idx in 0..8 {
            let bit = backend.decode_word(&bundle.words[byte_idx * 8 + bit_idx]);
            value |= ((bit & 1) as u8) << bit_idx;
        }
        out[byte_idx] = value;
    }
    Ok(out)
}

fn decode_bit_bundle_array_public(bundle: &DdhHssInputShareBundle) -> ProtoResult<[u8; 32]> {
    if bundle.words.len() != 256 {
        return Err(ProtoError::Decode(format!(
            "bit bundle must contain exactly 256 words, got {}",
            bundle.words.len()
        )));
    }
    if bundle.words.iter().any(|word| word.width_bits != 1) {
        return Err(ProtoError::Decode(
            "bit bundle must contain only 1-bit words".to_string(),
        ));
    }

    let mut out = [0u8; 32];
    for byte_idx in 0..32 {
        let mut value = 0u8;
        for bit_idx in 0..8 {
            let bit = decode_word_public(&bundle.words[byte_idx * 8 + bit_idx]);
            value |= ((bit & 1) as u8) << bit_idx;
        }
        out[byte_idx] = value;
    }
    Ok(out)
}

fn prepare_client_input_ot_request_public(
    offer: &DdhHssOtInputBundleOffer,
    input: &[u8],
) -> ProtoResult<(DdhHssOtSelectionBundle, DdhHssOtReceiverStateBundle)> {
    if offer.owner != HiddenEvalInputOwner::Client {
        return Err(ProtoError::InvalidInput(
            "OT request requires a client-owned offer".to_string(),
        ));
    }
    let bit_count = input.len() * 8;
    if offer.words.len() != bit_count {
        return Err(ProtoError::InvalidInput(format!(
            "OT offer word count does not match input bit count: {} vs {}",
            offer.words.len(),
            bit_count
        )));
    }

    let mut request_words = Vec::with_capacity(bit_count);
    let mut local_state_words = Vec::with_capacity(bit_count);
    for (bit_idx, word_offer) in offer.words.iter().enumerate() {
        if word_offer.width_bits != 1 {
            return Err(ProtoError::InvalidInput(format!(
                "OT offer word width must be 1, got {} at index {}",
                word_offer.width_bits, bit_idx
            )));
        }
        let byte_idx = bit_idx / 8;
        let inner_bit_idx = bit_idx % 8;
        let selected_branch = (input[byte_idx] >> inner_bit_idx) & 1;
        let mut wide = [0u8; 64];
        OsRng.fill_bytes(&mut wide);
        let receiver_scalar = Scalar::from_bytes_mod_order_wide(&wide);
        let receiver_public_point = if selected_branch == 0 {
            ED25519_BASEPOINT_POINT * receiver_scalar
        } else {
            CompressedEdwardsY(word_offer.sender_public)
                .decompress()
                .ok_or_else(|| {
                    ProtoError::InvalidInput(format!(
                        "OT sender public point is invalid at index {}",
                        bit_idx
                    ))
                })?
                + (ED25519_BASEPOINT_POINT * receiver_scalar)
        };
        request_words.push(DdhHssOtSelectionWord {
            width_bits: 1,
            receiver_public: receiver_public_point.compress().to_bytes(),
        });
        local_state_words.push(DdhHssOtReceiverStateWord {
            width_bits: 1,
            selected_branch,
            receiver_scalar: receiver_scalar.to_bytes(),
            sender_public: word_offer.sender_public,
        });
    }

    let request = DdhHssOtSelectionBundle {
        owner: HiddenEvalInputOwner::Client,
        label: offer.label.clone(),
        commitment: ot_request_bundle_commitment(
            HiddenEvalInputOwner::Client,
            &offer.label,
            &request_words,
        ),
        words: request_words,
    };
    let local_state = DdhHssOtReceiverStateBundle {
        owner: HiddenEvalInputOwner::Client,
        label: offer.label.clone(),
        commitment: ot_receiver_state_bundle_commitment(
            HiddenEvalInputOwner::Client,
            &offer.label,
            &local_state_words,
        ),
        words: local_state_words,
    };
    Ok((request, local_state))
}

fn derive_ot_branch_key_from_point_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    owner: HiddenEvalInputOwner,
    label: &str,
    bit_idx: usize,
    branch_bit: u8,
    shared_point: [u8; 32],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-branch-key/v1");
    transcript.append_message(b"key_id", &evaluation_key.key_id);
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"bit_idx", &(bit_idx as u64).to_le_bytes());
    transcript.append_message(b"branch_bit", &[branch_bit]);
    transcript.append_message(b"shared_point", &shared_point);
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_branch_key", &mut out);
    out
}

fn open_client_input_ot_bundle_public(
    evaluation_key: &DdhHssEvaluationKey,
    response: &DdhHssOtResponseBundle,
    local_state: &DdhHssOtReceiverStateBundle,
) -> ProtoResult<DdhHssTransportBundle> {
    if response.owner != HiddenEvalInputOwner::Client
        || local_state.owner != HiddenEvalInputOwner::Client
    {
        return Err(ProtoError::InvalidInput(
            "client OT response opening requires client-owned bundles".to_string(),
        ));
    }
    if response.label != local_state.label {
        return Err(ProtoError::InvalidInput(format!(
            "client OT response label does not match local state: {} vs {}",
            response.label, local_state.label
        )));
    }
    if response.words.len() != local_state.words.len() {
        return Err(ProtoError::InvalidInput(format!(
            "client OT response word count does not match local state: {} vs {}",
            response.words.len(),
            local_state.words.len()
        )));
    }
    if response.commitment
        != ot_response_bundle_commitment(response.owner, &response.label, &response.words)
    {
        return Err(ProtoError::InvalidInput(
            "client OT response commitment is invalid".to_string(),
        ));
    }
    if local_state.commitment
        != ot_receiver_state_bundle_commitment(
            local_state.owner,
            &local_state.label,
            &local_state.words,
        )
    {
        return Err(ProtoError::InvalidInput(
            "client OT local state commitment is invalid".to_string(),
        ));
    }

    let mut local_words = Vec::with_capacity(response.words.len());
    for (bit_idx, (response_word, state_word)) in
        response.words.iter().zip(&local_state.words).enumerate()
    {
        if response_word.width_bits != 1 || state_word.width_bits != 1 {
            return Err(ProtoError::InvalidInput(format!(
                "client OT response words must be 1-bit at index {bit_idx}"
            )));
        }
        if state_word.selected_branch > 1 {
            return Err(ProtoError::InvalidInput(format!(
                "client OT local state branch must be 0 or 1 at index {bit_idx}, got {}",
                state_word.selected_branch
            )));
        }
        let sender_public_point = CompressedEdwardsY(state_word.sender_public)
            .decompress()
            .ok_or_else(|| {
                ProtoError::InvalidInput(format!(
                    "client OT sender public point is invalid at bit index {bit_idx}"
                ))
            })?;
        let receiver_scalar = Scalar::from_bytes_mod_order(state_word.receiver_scalar);
        let shared_point = (sender_public_point * receiver_scalar)
            .compress()
            .to_bytes();
        let selected_branch = if state_word.selected_branch == 0 {
            &response_word.zero_branch
        } else {
            &response_word.one_branch
        };
        let key = derive_ot_branch_key_from_point_for_key(
            evaluation_key,
            HiddenEvalInputOwner::Client,
            &response.label,
            bit_idx,
            state_word.selected_branch,
            shared_point,
        );
        let payload = DdhHssBackend::open_ot_branch_with_key(
            key,
            HiddenEvalInputOwner::Client,
            &response.label,
            bit_idx,
            state_word.selected_branch,
            selected_branch,
        )?;
        local_words.push(DdhHssTransportWord {
            width_bits: 1,
            share_side: DdhHssShareSide::Left,
            share_word: payload.share_word,
            share_commitment: payload.share_commitment,
            counterparty_commitment: payload.counterparty_commitment,
            provenance_digest: payload.provenance_digest,
        });
    }

    Ok(DdhHssTransportBundle {
        owner: HiddenEvalInputOwner::Client,
        label: response.label.clone(),
        share_side: DdhHssShareSide::Left,
        commitment: transport_bundle_commitment(
            HiddenEvalInputOwner::Client,
            &response.label,
            DdhHssShareSide::Left,
            &local_words,
        ),
        words: local_words,
    })
}

fn join_client_ot_bundle_public(
    evaluation_key: &DdhHssEvaluationKey,
    local: &DdhHssTransportBundle,
    remote: &DdhHssOtReleasedRemoteBundle,
) -> ProtoResult<DdhHssInputShareBundle> {
    if local.owner != HiddenEvalInputOwner::Client || remote.owner != HiddenEvalInputOwner::Client {
        return Err(ProtoError::InvalidInput(
            "client OT bundle join requires client-owned bundles".to_string(),
        ));
    }
    if local.label != remote.label {
        return Err(ProtoError::InvalidInput(format!(
            "client OT bundle labels do not match: {} vs {}",
            local.label, remote.label
        )));
    }
    if local.share_side != DdhHssShareSide::Left || remote.share_side != DdhHssShareSide::Right {
        return Err(ProtoError::InvalidInput(
            "client OT bundles must be joined in left/right order".to_string(),
        ));
    }
    if local.words.len() != remote.words.len() {
        return Err(ProtoError::InvalidInput(format!(
            "client OT bundle word counts do not match: {} vs {}",
            local.words.len(),
            remote.words.len()
        )));
    }
    if local.commitment
        != transport_bundle_commitment(local.owner, &local.label, local.share_side, &local.words)
    {
        return Err(ProtoError::InvalidInput(
            "client OT local bundle commitment is invalid".to_string(),
        ));
    }
    if remote.commitment
        != ot_remote_bundle_commitment(
            remote.owner,
            &remote.label,
            remote.share_side,
            &remote.words,
        )
    {
        return Err(ProtoError::InvalidInput(
            "client OT remote bundle commitment is invalid".to_string(),
        ));
    }
    let expected_remote_binding = ot_remote_release_transcript_binding(
        remote.owner,
        &remote.label,
        remote.offer_commitment,
        remote.request_commitment,
        remote.response_commitment,
        remote.commitment,
    );
    if remote.transcript_binding != expected_remote_binding {
        return Err(ProtoError::InvalidInput(
            "client OT remote-share release transcript binding is invalid".to_string(),
        ));
    }

    let mut words = Vec::with_capacity(local.words.len());
    for (left_word, right_word) in local.words.iter().zip(&remote.words) {
        if left_word.width_bits != right_word.width_bits {
            return Err(ProtoError::InvalidInput(format!(
                "client OT word widths do not match: {} vs {}",
                left_word.width_bits, right_word.width_bits
            )));
        }
        if left_word.counterparty_commitment != right_word.share_commitment {
            return Err(ProtoError::InvalidInput(
                "client OT counterparty commitment does not match remote share commitment"
                    .to_string(),
            ));
        }
        let expected_left_commitment = commit_word(
            local.owner,
            b"left",
            left_word.share_word,
            &left_word.provenance_digest,
        );
        if left_word.share_commitment != expected_left_commitment {
            return Err(ProtoError::InvalidInput(
                "client OT left-share commitment is invalid".to_string(),
            ));
        }
        words.push(DdhHssSharedWord {
            width_bits: left_word.width_bits,
            left_word: left_word.share_word,
            right_word: right_word.share_word,
            left_commitment: left_word.share_commitment,
            right_commitment: right_word.share_commitment,
            provenance_digest: left_word.provenance_digest,
        });
    }

    let commitment = input_commitment_for_key(
        evaluation_key,
        HiddenEvalInputOwner::Client,
        &local.label,
        &words,
    );
    Ok(DdhHssInputShareBundle {
        owner: HiddenEvalInputOwner::Client,
        label: local.label.clone(),
        words,
        commitment,
    })
}

fn join_share_bundle_public(
    evaluation_key: &DdhHssEvaluationKey,
    left: &DdhHssTransportBundle,
    right: &DdhHssTransportBundle,
) -> ProtoResult<DdhHssInputShareBundle> {
    validate_transport_bundle_pair_public(evaluation_key, left, right)?;

    let mut words = Vec::with_capacity(left.words.len());
    for (left_word, right_word) in left.words.iter().zip(&right.words) {
        words.push(join_transport_word_pair_public(
            left.owner,
            right.owner,
            left_word,
            right_word,
        )?);
    }

    Ok(DdhHssInputShareBundle {
        owner: left.owner,
        label: left.label.clone(),
        words,
        commitment: left.commitment,
    })
}

pub(crate) fn join_transport_word_pair_public(
    left_owner: HiddenEvalInputOwner,
    right_owner: HiddenEvalInputOwner,
    left_word: &DdhHssTransportWord,
    right_word: &DdhHssTransportWord,
) -> ProtoResult<DdhHssSharedWord> {
    validate_transport_word_pair_public(left_owner, right_owner, left_word, right_word)?;

    Ok(DdhHssSharedWord {
        width_bits: left_word.width_bits,
        left_word: left_word.share_word,
        right_word: right_word.share_word,
        left_commitment: left_word.share_commitment,
        right_commitment: right_word.share_commitment,
        provenance_digest: left_word.provenance_digest,
    })
}

pub(crate) fn validate_transport_word_pair_public(
    left_owner: HiddenEvalInputOwner,
    right_owner: HiddenEvalInputOwner,
    left_word: &DdhHssTransportWord,
    right_word: &DdhHssTransportWord,
) -> ProtoResult<()> {
    if left_word.width_bits != right_word.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "transport word widths do not match: {} vs {}",
            left_word.width_bits, right_word.width_bits
        )));
    }
    if left_word.share_side != DdhHssShareSide::Left
        || right_word.share_side != DdhHssShareSide::Right
    {
        return Err(ProtoError::InvalidInput(
            "transport words must be joined in left/right order".to_string(),
        ));
    }
    if left_word.provenance_digest != right_word.provenance_digest {
        return Err(ProtoError::InvalidInput(
            "transport word provenance digests do not match".to_string(),
        ));
    }

    let expected_left_commitment = commit_word(
        left_owner,
        b"left",
        left_word.share_word,
        &left_word.provenance_digest,
    );
    let expected_right_commitment = commit_word(
        right_owner,
        b"right",
        right_word.share_word,
        &right_word.provenance_digest,
    );
    if left_word.share_commitment != expected_left_commitment
        || right_word.share_commitment != expected_right_commitment
    {
        return Err(ProtoError::InvalidInput(
            "transport word commitments are invalid".to_string(),
        ));
    }
    if left_word.counterparty_commitment != right_word.share_commitment
        || right_word.counterparty_commitment != left_word.share_commitment
    {
        return Err(ProtoError::InvalidInput(
            "transport word counterparty commitments do not match".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_transport_bundle_pair_public(
    evaluation_key: &DdhHssEvaluationKey,
    left: &DdhHssTransportBundle,
    right: &DdhHssTransportBundle,
) -> ProtoResult<()> {
    if left.owner != right.owner {
        return Err(ProtoError::InvalidInput(format!(
            "transport bundle owners do not match: {:?} vs {:?}",
            left.owner, right.owner
        )));
    }
    if left.label != right.label {
        return Err(ProtoError::InvalidInput(format!(
            "transport bundle labels do not match: {} vs {}",
            left.label, right.label
        )));
    }
    if left.share_side != DdhHssShareSide::Left || right.share_side != DdhHssShareSide::Right {
        return Err(ProtoError::InvalidInput(
            "transport bundles must be joined in left/right order".to_string(),
        ));
    }
    if left.commitment != right.commitment {
        return Err(ProtoError::InvalidInput(
            "transport bundle commitments do not match".to_string(),
        ));
    }
    if left.words.len() != right.words.len() {
        return Err(ProtoError::InvalidInput(format!(
            "transport bundle word counts do not match: {} vs {}",
            left.words.len(),
            right.words.len()
        )));
    }

    for (left_word, right_word) in left.words.iter().zip(&right.words) {
        let _ = join_transport_word_pair_public(left.owner, right.owner, left_word, right_word)?;
    }

    let joint_words = left
        .words
        .iter()
        .zip(&right.words)
        .map(|(left_word, right_word)| {
            join_transport_word_pair_public(left.owner, right.owner, left_word, right_word)
        })
        .collect::<ProtoResult<Vec<_>>>()?;
    let expected_commitment =
        input_commitment_for_key(evaluation_key, left.owner, &left.label, &joint_words);
    if expected_commitment != left.commitment {
        return Err(ProtoError::InvalidInput(
            "reconstructed input bundle commitment is invalid".to_string(),
        ));
    }

    Ok(())
}

pub(crate) fn eval_add_shared_with_transport_pair_public(
    evaluation_key: &DdhHssEvaluationKey,
    left: &DdhHssSharedWord,
    right_left: &DdhHssTransportWord,
    right_right: &DdhHssTransportWord,
) -> ProtoResult<DdhHssSharedWord> {
    validate_transport_word_pair_public(
        HiddenEvalInputOwner::Server,
        HiddenEvalInputOwner::Server,
        right_left,
        right_right,
    )?;
    if left.width_bits != right_left.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "shared/transport add width mismatch: {} vs {}",
            left.width_bits, right_left.width_bits
        )));
    }

    let width_bits = left.width_bits;
    let left_word = reduce_word(
        u128::from(left.left_word) + u128::from(right_left.share_word),
        width_bits,
    );
    let right_word = reduce_word(
        u128::from(left.right_word) + u128::from(right_right.share_word),
        width_bits,
    );
    Ok(build_shared_word_for_key(
        evaluation_key,
        b"eval-add-public",
        HiddenEvalInputOwner::Derived,
        b"add",
        width_bits,
        left_word,
        right_word,
        &[
            &left.provenance_digest,
            &right_left.provenance_digest,
            &left.left_commitment,
            &right_left.share_commitment,
        ],
    ))
}

fn seal_transport_message_with_key(
    transport_key: &DdhHssTransportKey,
    purpose: &str,
    aad: &[u8],
    plaintext: &[u8],
) -> ProtoResult<([u8; 12], Vec<u8>)> {
    let cipher = ChaCha20Poly1305::new(&transport_key.0.into());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|err| {
            ProtoError::Decode(format!(
                "failed to seal DDH transport message for {purpose}: {err}"
            ))
        })?;
    Ok((nonce, ciphertext))
}

fn open_transport_message_with_key(
    transport_key: &DdhHssTransportKey,
    purpose: &str,
    aad: &[u8],
    nonce: [u8; 12],
    ciphertext: &[u8],
) -> ProtoResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&transport_key.0.into());
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|err| {
            ProtoError::Decode(format!(
                "failed to open DDH transport message for {purpose}: {err}"
            ))
        })
}

fn transport_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    share_side: DdhHssShareSide,
    words: &[DdhHssTransportWord],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/transport-bundle/v0");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(
        b"share_side",
        match share_side {
            DdhHssShareSide::Left => b"left",
            DdhHssShareSide::Right => b"right",
        },
    );
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"share_word", &word.share_word.to_le_bytes());
        transcript.append_message(b"share_commitment", &word.share_commitment);
        transcript.append_message(b"counterparty_commitment", &word.counterparty_commitment);
        transcript.append_message(b"provenance_digest", &word.provenance_digest);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"transport_bundle_commitment", &mut out);
    out
}

fn ot_branch_aad(
    owner: HiddenEvalInputOwner,
    label: &str,
    bit_idx: usize,
    branch_bit: u8,
) -> Vec<u8> {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-branch-aad/v0");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"bit_idx", &(bit_idx as u64).to_le_bytes());
    transcript.append_message(b"branch_bit", &[branch_bit]);
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_branch_aad", &mut out);
    out.to_vec()
}

fn ot_offer_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    words: &[DdhHssOtWordOffer],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-offer-bundle/v0");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"width_bits", &word.width_bits.to_le_bytes());
        transcript.append_message(b"sender_public", &word.sender_public);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_offer_bundle_commitment", &mut out);
    out
}

fn ot_remote_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    share_side: DdhHssShareSide,
    words: &[DdhHssOtRemoteWord],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-remote-bundle/v0");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(
        b"share_side",
        match share_side {
            DdhHssShareSide::Left => b"left",
            DdhHssShareSide::Right => b"right",
        },
    );
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"share_word", &word.share_word.to_le_bytes());
        transcript.append_message(b"share_commitment", &word.share_commitment);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_remote_bundle_commitment", &mut out);
    out
}

fn ot_request_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    words: &[DdhHssOtSelectionWord],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-request-bundle/v1");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"width_bits", &word.width_bits.to_le_bytes());
        transcript.append_message(b"receiver_public", &word.receiver_public);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_request_bundle_commitment", &mut out);
    out
}

fn ot_receiver_state_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    words: &[DdhHssOtReceiverStateWord],
) -> [u8; 32] {
    let mut transcript =
        Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-receiver-state-bundle/v1");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"width_bits", &word.width_bits.to_le_bytes());
        transcript.append_message(b"selected_branch", &[word.selected_branch]);
        transcript.append_message(b"receiver_scalar", &word.receiver_scalar);
        transcript.append_message(b"sender_public", &word.sender_public);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_receiver_state_bundle_commitment", &mut out);
    out
}

fn ot_sender_state_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    words: &[DdhHssOtSenderStateWord],
) -> [u8; 32] {
    let mut transcript =
        Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-sender-state-bundle/v0");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"width_bits", &word.width_bits.to_le_bytes());
        transcript.append_message(b"sender_scalar", &word.sender_scalar);
        transcript.append_message(b"sender_public", &word.sender_public);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_sender_state_bundle_commitment", &mut out);
    out
}

fn ot_response_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    words: &[DdhHssOtResponseWord],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-response-bundle/v1");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"width_bits", &word.width_bits.to_le_bytes());
        transcript.append_message(b"zero_nonce", &word.zero_branch.nonce);
        transcript.append_message(b"zero_payload_digest", &word.zero_branch.payload_digest);
        transcript.append_message(
            b"zero_ciphertext_len",
            &(word.zero_branch.ciphertext.len() as u64).to_le_bytes(),
        );
        transcript.append_message(b"zero_ciphertext", &word.zero_branch.ciphertext);
        transcript.append_message(b"one_nonce", &word.one_branch.nonce);
        transcript.append_message(b"one_payload_digest", &word.one_branch.payload_digest);
        transcript.append_message(
            b"one_ciphertext_len",
            &(word.one_branch.ciphertext.len() as u64).to_le_bytes(),
        );
        transcript.append_message(b"one_ciphertext", &word.one_branch.ciphertext);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_response_bundle_commitment", &mut out);
    out
}

fn ot_remote_release_transcript_binding(
    owner: HiddenEvalInputOwner,
    label: &str,
    offer_commitment: [u8; 32],
    request_commitment: [u8; 32],
    response_commitment: [u8; 32],
    remote_commitment: [u8; 32],
) -> [u8; 32] {
    let mut transcript =
        Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-remote-release-binding/v0");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"offer_commitment", &offer_commitment);
    transcript.append_message(b"request_commitment", &request_commitment);
    transcript.append_message(b"response_commitment", &response_commitment);
    transcript.append_message(b"remote_commitment", &remote_commitment);
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_remote_release_binding", &mut out);
    out
}
