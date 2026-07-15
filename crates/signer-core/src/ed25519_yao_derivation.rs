use core::fmt;

use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CoreResult, SignerCoreError};

pub const ED25519_YAO_APPLICATION_BINDING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/application-binding/v1";
pub const ED25519_YAO_APPLICATION_BINDING_WALLET_ID_LABEL_V1: &[u8] = b"walletId";
pub const ED25519_YAO_APPLICATION_BINDING_SIGNING_KEY_ID_LABEL_V1: &[u8] =
    b"nearEd25519SigningKeyId";
pub const ED25519_YAO_APPLICATION_BINDING_SIGNING_ROOT_ID_LABEL_V1: &[u8] = b"signingRootId";
pub const ED25519_YAO_APPLICATION_BINDING_KEY_CREATION_SIGNER_SLOT_LABEL_V1: &[u8] =
    b"keyCreationSignerSlot";
pub const ED25519_YAO_STABLE_KEY_CONTEXT_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/stable-key-context/v1";
pub const ED25519_YAO_STABLE_KEY_CONTEXT_BINDING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/stable-key-context-binding/v1";
pub const ED25519_YAO_STABLE_KEY_CONTEXT_ENCODED_LEN_V1: usize =
    ED25519_YAO_STABLE_KEY_CONTEXT_DOMAIN_V1.len() + 32 + 2 + 2;
pub const ED25519_YAO_CONTRIBUTION_KDF_EXTRACT_SALT_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/contribution-kdf/hkdf-sha256/extract/v1";
pub const ED25519_YAO_CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/contribution-kdf/hkdf-sha256/expand/v1";
pub const ED25519_YAO_CONTRIBUTION_KDF_EXPAND_INFO_LEN_V1: usize =
    ED25519_YAO_CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1.len() + 1 + 1 + 1 + 1 + 32;
/// HKDF extract salt for deriving the Yao Client root from passkey PRF.first.
pub const ED25519_YAO_PASSKEY_CLIENT_ROOT_KDF_EXTRACT_SALT_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/client-root/passkey-prf-first/hkdf-sha256/extract/v1";
/// HKDF expand domain for the passkey-derived Yao Client root.
pub const ED25519_YAO_PASSKEY_CLIENT_ROOT_KDF_EXPAND_INFO_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/client-root/passkey-prf-first/hkdf-sha256/expand/v1";
/// Exact passkey Client-root HKDF expand-info length.
pub const ED25519_YAO_PASSKEY_CLIENT_ROOT_KDF_EXPAND_INFO_LEN_V1: usize =
    ED25519_YAO_PASSKEY_CLIENT_ROOT_KDF_EXPAND_INFO_DOMAIN_V1.len() + 32;
/// HKDF extract salt for deriving the Yao Client root from an Email OTP factor secret.
pub const ED25519_YAO_EMAIL_OTP_CLIENT_ROOT_KDF_EXTRACT_SALT_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/client-root/email-otp-factor/hkdf-sha256/extract/v1";
/// HKDF expand domain for the Email OTP-derived Yao Client root.
pub const ED25519_YAO_EMAIL_OTP_CLIENT_ROOT_KDF_EXPAND_INFO_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/client-root/email-otp-factor/hkdf-sha256/expand/v1";
/// Exact Email OTP Client-root HKDF expand-info length.
pub const ED25519_YAO_EMAIL_OTP_CLIENT_ROOT_KDF_EXPAND_INFO_LEN_V1: usize =
    ED25519_YAO_EMAIL_OTP_CLIENT_ROOT_KDF_EXPAND_INFO_DOMAIN_V1.len() + 32;

const ROLE_A_TAG: u8 = 0x01;
const ROLE_B_TAG: u8 = 0x02;
const CLIENT_SOURCE_TAG: u8 = 0x01;
const SERVER_SOURCE_TAG: u8 = 0x02;
const Y_OUTPUT_TAG: u8 = 0x01;
const TAU_OUTPUT_TAG: u8 = 0x02;

fn validate_identifier(label: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{label} must be non-empty"
        )));
    }
    if u32::try_from(value.len()).is_err() {
        return Err(SignerCoreError::invalid_length(format!(
            "{label} exceeds the U32 length-delimited encoding"
        )));
    }
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(SignerCoreError::invalid_input(format!(
            "{label} must contain only visible ASCII bytes"
        )));
    }
    Ok(())
}

macro_rules! define_identifier {
    ($name:ident, $label:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: &str) -> CoreResult<Self> {
                validate_identifier($label, value)?;
                Ok(Self(value.to_owned()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

define_identifier!(Ed25519YaoApplicationBindingWalletIdV1, "walletId");
define_identifier!(
    Ed25519YaoApplicationBindingSigningKeyIdV1,
    "nearEd25519SigningKeyId"
);
define_identifier!(Ed25519YaoApplicationBindingSigningRootIdV1, "signingRootId");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519YaoApplicationBindingKeyCreationSignerSlotV1(u32);

impl Ed25519YaoApplicationBindingKeyCreationSignerSlotV1 {
    pub fn new(value: u32) -> CoreResult<Self> {
        if value == 0 {
            return Err(SignerCoreError::invalid_input(
                "keyCreationSignerSlot must be positive",
            ));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

pub struct Ed25519YaoApplicationBindingFactsV1 {
    wallet_id: Ed25519YaoApplicationBindingWalletIdV1,
    signing_key_id: Ed25519YaoApplicationBindingSigningKeyIdV1,
    signing_root_id: Ed25519YaoApplicationBindingSigningRootIdV1,
    key_creation_signer_slot: Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
}

impl Ed25519YaoApplicationBindingFactsV1 {
    pub const fn new(
        wallet_id: Ed25519YaoApplicationBindingWalletIdV1,
        signing_key_id: Ed25519YaoApplicationBindingSigningKeyIdV1,
        signing_root_id: Ed25519YaoApplicationBindingSigningRootIdV1,
        key_creation_signer_slot: Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    ) -> Self {
        Self {
            wallet_id,
            signing_key_id,
            signing_root_id,
            key_creation_signer_slot,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_length_delimited(&mut bytes, ED25519_YAO_APPLICATION_BINDING_DOMAIN_V1);
        push_labeled_field(
            &mut bytes,
            ED25519_YAO_APPLICATION_BINDING_WALLET_ID_LABEL_V1,
            self.wallet_id.as_str().as_bytes(),
        );
        push_labeled_field(
            &mut bytes,
            ED25519_YAO_APPLICATION_BINDING_SIGNING_KEY_ID_LABEL_V1,
            self.signing_key_id.as_str().as_bytes(),
        );
        push_labeled_field(
            &mut bytes,
            ED25519_YAO_APPLICATION_BINDING_SIGNING_ROOT_ID_LABEL_V1,
            self.signing_root_id.as_str().as_bytes(),
        );
        push_labeled_field(
            &mut bytes,
            ED25519_YAO_APPLICATION_BINDING_KEY_CREATION_SIGNER_SLOT_LABEL_V1,
            &self.key_creation_signer_slot.get().to_be_bytes(),
        );
        bytes
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

fn push_labeled_field(output: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    push_length_delimited(output, label);
    push_length_delimited(output, value);
}

fn push_length_delimited(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("validated field length fits in U32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519YaoParticipantIdsV1([u16; 2]);

impl Ed25519YaoParticipantIdsV1 {
    pub fn new(first: u16, second: u16) -> CoreResult<Self> {
        if first == 0 || second == 0 {
            return Err(SignerCoreError::invalid_input(
                "participant identifiers must be nonzero",
            ));
        }
        if first == second {
            return Err(SignerCoreError::invalid_input(
                "participant identifiers must be distinct",
            ));
        }
        Ok(Self(if first < second {
            [first, second]
        } else {
            [second, first]
        }))
    }

    pub const fn as_array(self) -> [u16; 2] {
        self.0
    }
}

pub struct Ed25519YaoStableKeyDerivationContextV1 {
    application_binding_digest: [u8; 32],
    participant_ids: Ed25519YaoParticipantIdsV1,
}

impl Ed25519YaoStableKeyDerivationContextV1 {
    pub fn new(
        application_binding_digest: [u8; 32],
        first_participant_id: u16,
        second_participant_id: u16,
    ) -> CoreResult<Self> {
        Ok(Self {
            application_binding_digest,
            participant_ids: Ed25519YaoParticipantIdsV1::new(
                first_participant_id,
                second_participant_id,
            )?,
        })
    }

    pub const fn application_binding_digest(&self) -> &[u8; 32] {
        &self.application_binding_digest
    }

    pub const fn participant_ids(&self) -> Ed25519YaoParticipantIdsV1 {
        self.participant_ids
    }

    pub fn encode(&self) -> [u8; ED25519_YAO_STABLE_KEY_CONTEXT_ENCODED_LEN_V1] {
        let mut bytes = [0_u8; ED25519_YAO_STABLE_KEY_CONTEXT_ENCODED_LEN_V1];
        let domain_end = ED25519_YAO_STABLE_KEY_CONTEXT_DOMAIN_V1.len();
        bytes[..domain_end].copy_from_slice(ED25519_YAO_STABLE_KEY_CONTEXT_DOMAIN_V1);
        let digest_end = domain_end + 32;
        bytes[domain_end..digest_end].copy_from_slice(&self.application_binding_digest);
        let ids = self.participant_ids.as_array();
        bytes[digest_end..digest_end + 2].copy_from_slice(&ids[0].to_be_bytes());
        bytes[digest_end + 2..].copy_from_slice(&ids[1].to_be_bytes());
        bytes
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ED25519_YAO_STABLE_KEY_CONTEXT_BINDING_DOMAIN_V1);
        hasher.update(self.encode());
        hasher.finalize().into()
    }
}

macro_rules! define_root {
    ($name:ident) => {
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn from_secret_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_root!(Ed25519YaoClientDerivationRootV1);
define_root!(Ed25519YaoDeriverADerivationRootV1);
define_root!(Ed25519YaoDeriverBDerivationRootV1);

/// Derives the stable Client root from wallet-origin passkey PRF.first material.
pub fn derive_ed25519_yao_client_root_from_passkey_prf_first_v1(
    passkey_prf_first: &[u8; 32],
    application_binding_digest: &[u8; 32],
) -> CoreResult<Ed25519YaoClientDerivationRootV1> {
    let hkdf = Hkdf::<Sha256>::new(
        Some(ED25519_YAO_PASSKEY_CLIENT_ROOT_KDF_EXTRACT_SALT_V1),
        passkey_prf_first,
    );
    let mut info = [0_u8; ED25519_YAO_PASSKEY_CLIENT_ROOT_KDF_EXPAND_INFO_LEN_V1];
    let domain_end = ED25519_YAO_PASSKEY_CLIENT_ROOT_KDF_EXPAND_INFO_DOMAIN_V1.len();
    info[..domain_end].copy_from_slice(ED25519_YAO_PASSKEY_CLIENT_ROOT_KDF_EXPAND_INFO_DOMAIN_V1);
    info[domain_end..].copy_from_slice(application_binding_digest);
    let mut root = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, &mut *root)
        .map_err(|_| SignerCoreError::hkdf_error("Ed25519 Yao passkey Client root HKDF failed"))?;
    Ok(Ed25519YaoClientDerivationRootV1::from_secret_bytes(
        core::mem::take(&mut *root),
    ))
}

/// Derives the stable Client root from the Email OTP enrollment factor secret.
pub fn derive_ed25519_yao_client_root_from_email_otp_factor_v1(
    email_otp_factor: &[u8; 32],
    application_binding_digest: &[u8; 32],
) -> CoreResult<Ed25519YaoClientDerivationRootV1> {
    let hkdf = Hkdf::<Sha256>::new(
        Some(ED25519_YAO_EMAIL_OTP_CLIENT_ROOT_KDF_EXTRACT_SALT_V1),
        email_otp_factor,
    );
    let mut info = [0_u8; ED25519_YAO_EMAIL_OTP_CLIENT_ROOT_KDF_EXPAND_INFO_LEN_V1];
    let domain_end = ED25519_YAO_EMAIL_OTP_CLIENT_ROOT_KDF_EXPAND_INFO_DOMAIN_V1.len();
    info[..domain_end].copy_from_slice(ED25519_YAO_EMAIL_OTP_CLIENT_ROOT_KDF_EXPAND_INFO_DOMAIN_V1);
    info[domain_end..].copy_from_slice(application_binding_digest);
    let mut root = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, &mut *root).map_err(|_| {
        SignerCoreError::hkdf_error("Ed25519 Yao Email OTP Client root HKDF failed")
    })?;
    Ok(Ed25519YaoClientDerivationRootV1::from_secret_bytes(
        core::mem::take(&mut *root),
    ))
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519YaoYContributionV1([u8; 32]);

impl Ed25519YaoYContributionV1 {
    pub fn into_bytes(mut self) -> [u8; 32] {
        core::mem::take(&mut self.0)
    }
}

impl fmt::Debug for Ed25519YaoYContributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519YaoYContributionV1([REDACTED])")
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519YaoTauContributionV1([u8; 32]);

impl Ed25519YaoTauContributionV1 {
    pub fn into_bytes(mut self) -> [u8; 32] {
        core::mem::take(&mut self.0)
    }
}

impl fmt::Debug for Ed25519YaoTauContributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519YaoTauContributionV1([REDACTED])")
    }
}

macro_rules! define_contribution {
    ($name:ident) => {
        pub struct $name {
            y: Ed25519YaoYContributionV1,
            tau: Ed25519YaoTauContributionV1,
        }

        impl $name {
            pub const fn from_secret_bytes(y: [u8; 32], tau: [u8; 32]) -> Self {
                Self {
                    y: Ed25519YaoYContributionV1(y),
                    tau: Ed25519YaoTauContributionV1(tau),
                }
            }

            pub fn into_parts(self) -> (Ed25519YaoYContributionV1, Ed25519YaoTauContributionV1) {
                (self.y, self.tau)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_contribution!(Ed25519YaoDeriverAClientContributionV1);
define_contribution!(Ed25519YaoDeriverBClientContributionV1);
define_contribution!(Ed25519YaoDeriverAServerContributionV1);
define_contribution!(Ed25519YaoDeriverBServerContributionV1);

macro_rules! define_refresh_delta_contribution {
    ($name:ident, $role:literal) => {
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name {
            delta_y: [u8; 32],
            delta_tau: Scalar,
        }

        impl $name {
            pub fn from_secret_bytes(delta_y: [u8; 32], delta_tau: [u8; 32]) -> CoreResult<Self> {
                let delta_tau = Option::<Scalar>::from(Scalar::from_canonical_bytes(delta_tau))
                    .ok_or_else(|| {
                        SignerCoreError::invalid_input(concat!(
                            $role,
                            " refresh delta_tau must be canonical"
                        ))
                    })?;
                Ok(Self { delta_y, delta_tau })
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_refresh_delta_contribution!(Ed25519YaoDeriverARefreshDeltaContributionV1, "Deriver A");
define_refresh_delta_contribution!(Ed25519YaoDeriverBRefreshDeltaContributionV1, "Deriver B");

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519YaoJointRefreshDeltaV1 {
    delta_y: [u8; 32],
    delta_tau: Scalar,
}

impl Ed25519YaoJointRefreshDeltaV1 {
    pub const fn delta_y_bytes(&self) -> [u8; 32] {
        self.delta_y
    }

    pub fn delta_tau_bytes(&self) -> [u8; 32] {
        self.delta_tau.to_bytes()
    }
}

impl fmt::Debug for Ed25519YaoJointRefreshDeltaV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519YaoJointRefreshDeltaV1([REDACTED])")
    }
}

pub fn derive_ed25519_yao_joint_refresh_delta_v1(
    deriver_a: Ed25519YaoDeriverARefreshDeltaContributionV1,
    deriver_b: Ed25519YaoDeriverBRefreshDeltaContributionV1,
) -> CoreResult<Ed25519YaoJointRefreshDeltaV1> {
    let delta_y = wrapping_add_le_256(deriver_a.delta_y, deriver_b.delta_y, 0);
    if delta_y == [0_u8; 32] {
        return Err(SignerCoreError::invalid_input(
            "joint refresh delta_y must be nonzero",
        ));
    }
    let delta_tau = deriver_a.delta_tau + deriver_b.delta_tau;
    if delta_tau == Scalar::ZERO {
        return Err(SignerCoreError::invalid_input(
            "joint refresh delta_tau must be nonzero",
        ));
    }
    Ok(Ed25519YaoJointRefreshDeltaV1 { delta_y, delta_tau })
}

pub fn apply_ed25519_yao_refresh_delta_to_deriver_a_v1(
    current: Ed25519YaoDeriverAServerContributionV1,
    delta: &Ed25519YaoJointRefreshDeltaV1,
) -> CoreResult<Ed25519YaoDeriverAServerContributionV1> {
    let (current_y, current_tau) = current.into_parts();
    let current_tau = canonical_refresh_scalar(current_tau.into_bytes())?;
    Ok(Ed25519YaoDeriverAServerContributionV1::from_secret_bytes(
        wrapping_add_le_256(current_y.into_bytes(), delta.delta_y, 0),
        (current_tau + delta.delta_tau).to_bytes(),
    ))
}

pub fn apply_ed25519_yao_refresh_delta_to_deriver_b_v1(
    current: Ed25519YaoDeriverBServerContributionV1,
    delta: &Ed25519YaoJointRefreshDeltaV1,
) -> CoreResult<Ed25519YaoDeriverBServerContributionV1> {
    let (current_y, current_tau) = current.into_parts();
    let current_tau = canonical_refresh_scalar(current_tau.into_bytes())?;
    Ok(Ed25519YaoDeriverBServerContributionV1::from_secret_bytes(
        wrapping_add_le_256(current_y.into_bytes(), ones_complement(delta.delta_y), 1),
        (current_tau - delta.delta_tau).to_bytes(),
    ))
}

fn canonical_refresh_scalar(bytes: [u8; 32]) -> CoreResult<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).ok_or_else(|| {
        SignerCoreError::invalid_input("persisted refresh tau contribution must be canonical")
    })
}

fn wrapping_add_le_256(left: [u8; 32], right: [u8; 32], initial_carry: u16) -> [u8; 32] {
    let mut output = [0_u8; 32];
    let mut carry = initial_carry;
    for index in 0..32 {
        let sum = u16::from(left[index]) + u16::from(right[index]) + carry;
        output[index] = sum as u8;
        carry = sum >> 8;
    }
    output
}

fn ones_complement(mut bytes: [u8; 32]) -> [u8; 32] {
    for byte in &mut bytes {
        *byte = !*byte;
    }
    bytes
}

pub struct Ed25519YaoClientContributionsV1 {
    deriver_a: Ed25519YaoDeriverAClientContributionV1,
    deriver_b: Ed25519YaoDeriverBClientContributionV1,
}

impl Ed25519YaoClientContributionsV1 {
    pub fn into_parts(
        self,
    ) -> (
        Ed25519YaoDeriverAClientContributionV1,
        Ed25519YaoDeriverBClientContributionV1,
    ) {
        (self.deriver_a, self.deriver_b)
    }
}

pub fn derive_ed25519_yao_client_contributions_v1(
    root: &Ed25519YaoClientDerivationRootV1,
    context: &Ed25519YaoStableKeyDerivationContextV1,
) -> CoreResult<Ed25519YaoClientContributionsV1> {
    let deriver_a = derive_contribution(root.as_bytes(), context, ROLE_A_TAG, CLIENT_SOURCE_TAG)?;
    let deriver_b = derive_contribution(root.as_bytes(), context, ROLE_B_TAG, CLIENT_SOURCE_TAG)?;
    Ok(Ed25519YaoClientContributionsV1 {
        deriver_a: Ed25519YaoDeriverAClientContributionV1 {
            y: deriver_a.0,
            tau: deriver_a.1,
        },
        deriver_b: Ed25519YaoDeriverBClientContributionV1 {
            y: deriver_b.0,
            tau: deriver_b.1,
        },
    })
}

pub fn derive_ed25519_yao_deriver_a_server_contribution_v1(
    root: &Ed25519YaoDeriverADerivationRootV1,
    context: &Ed25519YaoStableKeyDerivationContextV1,
) -> CoreResult<Ed25519YaoDeriverAServerContributionV1> {
    let (y, tau) = derive_contribution(root.as_bytes(), context, ROLE_A_TAG, SERVER_SOURCE_TAG)?;
    Ok(Ed25519YaoDeriverAServerContributionV1 { y, tau })
}

pub fn derive_ed25519_yao_deriver_b_server_contribution_v1(
    root: &Ed25519YaoDeriverBDerivationRootV1,
    context: &Ed25519YaoStableKeyDerivationContextV1,
) -> CoreResult<Ed25519YaoDeriverBServerContributionV1> {
    let (y, tau) = derive_contribution(root.as_bytes(), context, ROLE_B_TAG, SERVER_SOURCE_TAG)?;
    Ok(Ed25519YaoDeriverBServerContributionV1 { y, tau })
}

fn derive_contribution(
    root: &[u8; 32],
    context: &Ed25519YaoStableKeyDerivationContextV1,
    role_tag: u8,
    source_tag: u8,
) -> CoreResult<(Ed25519YaoYContributionV1, Ed25519YaoTauContributionV1)> {
    let hkdf = Hkdf::<Sha256>::new(Some(ED25519_YAO_CONTRIBUTION_KDF_EXTRACT_SALT_V1), root);
    let context_binding = context.binding_digest();
    let y_info = contribution_expand_info(role_tag, source_tag, Y_OUTPUT_TAG, &context_binding);
    let mut y = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&y_info, &mut *y)
        .map_err(|_| SignerCoreError::hkdf_error("Ed25519 Yao y contribution HKDF failed"))?;
    let y_output = Ed25519YaoYContributionV1(core::mem::take(&mut *y));

    let tau_info = contribution_expand_info(role_tag, source_tag, TAU_OUTPUT_TAG, &context_binding);
    let mut tau_wide = Zeroizing::new([0_u8; 64]);
    hkdf.expand(&tau_info, &mut *tau_wide)
        .map_err(|_| SignerCoreError::hkdf_error("Ed25519 Yao tau contribution HKDF failed"))?;
    let tau_output =
        Ed25519YaoTauContributionV1(Scalar::from_bytes_mod_order_wide(&tau_wide).to_bytes());
    Ok((y_output, tau_output))
}

fn contribution_expand_info(
    role_tag: u8,
    source_tag: u8,
    output_tag: u8,
    context_binding: &[u8; 32],
) -> [u8; ED25519_YAO_CONTRIBUTION_KDF_EXPAND_INFO_LEN_V1] {
    let mut info = [0_u8; ED25519_YAO_CONTRIBUTION_KDF_EXPAND_INFO_LEN_V1];
    let domain_end = ED25519_YAO_CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1.len();
    info[..domain_end].copy_from_slice(ED25519_YAO_CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1);
    info[domain_end] = 0x00;
    info[domain_end + 1] = role_tag;
    info[domain_end + 2] = source_tag;
    info[domain_end + 3] = output_tag;
    info[domain_end + 4..].copy_from_slice(context_binding);
    info
}

#[cfg(test)]
mod tests {
    use super::{
        derive_ed25519_yao_client_root_from_email_otp_factor_v1,
        derive_ed25519_yao_client_root_from_passkey_prf_first_v1,
    };

    #[test]
    fn passkey_client_root_kdf_matches_independent_hkdf_vector() {
        let root =
            derive_ed25519_yao_client_root_from_passkey_prf_first_v1(&[0x42; 32], &[0x24; 32])
                .expect("passkey Client root");
        assert_eq!(
            root.as_bytes(),
            &[
                0x3f, 0x3d, 0x66, 0x0e, 0x32, 0x43, 0xcc, 0x35, 0x53, 0x19, 0x08, 0x28, 0x52, 0xe9,
                0xa8, 0xa4, 0xa0, 0x44, 0xa5, 0x02, 0xd8, 0xba, 0x3b, 0x82, 0x1c, 0x73, 0x4c, 0x17,
                0xc5, 0xa5, 0xbf, 0x11,
            ]
        );
    }

    #[test]
    fn passkey_client_root_kdf_binds_application_digest() {
        let first =
            derive_ed25519_yao_client_root_from_passkey_prf_first_v1(&[0x42; 32], &[0x24; 32])
                .expect("first root");
        let second =
            derive_ed25519_yao_client_root_from_passkey_prf_first_v1(&[0x42; 32], &[0x25; 32])
                .expect("second root");
        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn email_otp_client_root_kdf_binds_application_digest_and_factor_domain() {
        let first =
            derive_ed25519_yao_client_root_from_email_otp_factor_v1(&[0x42; 32], &[0x24; 32])
                .expect("first Email OTP root");
        let second =
            derive_ed25519_yao_client_root_from_email_otp_factor_v1(&[0x42; 32], &[0x25; 32])
                .expect("second Email OTP root");
        let passkey =
            derive_ed25519_yao_client_root_from_passkey_prf_first_v1(&[0x42; 32], &[0x24; 32])
                .expect("passkey root");
        assert_ne!(first.as_bytes(), second.as_bytes());
        assert_ne!(first.as_bytes(), passkey.as_bytes());
    }
}
