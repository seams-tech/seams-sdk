#![allow(dead_code)]

use core::fmt;

use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CircuitDigest32, ScheduleDigest32};

const LABEL_BYTES: usize = 16;
const MESSAGE_MAGIC: &[u8; 8] = b"EYAOP401";
const MESSAGE_VERSION: u8 = 1;
const MESSAGE_HEADER_BYTES: usize = 156;
const ACTIVATION_FAMILY_TAG: u8 = 0x93;
const EXPORT_FAMILY_TAG: u8 = 0x94;
const A_DIRECT_INPUT_LABELS_KIND: u8 = 1;
const B_OUTPUT_DECODE_BITS_KIND: u8 = 2;
const A_SELECTED_OUTPUT_LABELS_KIND: u8 = 3;
const GATE_DOMAIN_TAG: &[u8] = b"seams:ed25519-yao:phase4:gate-domain:v1";

const ACTIVATION_CIRCUIT_DIGEST: [u8; 32] = [
    0x65, 0xb0, 0x01, 0xc2, 0xf9, 0x4d, 0xe2, 0x7e, 0xe8, 0xcb, 0x9f, 0x0c, 0x07, 0x73, 0xfb, 0xe5,
    0x42, 0x58, 0xce, 0xab, 0x43, 0xd1, 0x83, 0x17, 0x4b, 0xee, 0x71, 0x0e, 0xe8, 0xaa, 0x54, 0x6d,
];
const ACTIVATION_SCHEDULE_DIGEST: [u8; 32] = [
    0xfb, 0x04, 0xa1, 0x39, 0xde, 0xc1, 0x5e, 0x9d, 0x52, 0xe4, 0x96, 0xdc, 0x4f, 0xc0, 0x11, 0xcf,
    0x88, 0x5c, 0x8f, 0x3f, 0x6f, 0x2d, 0x18, 0xbf, 0x38, 0x60, 0xe4, 0x60, 0x71, 0xf0, 0xe6, 0x9a,
];
const EXPORT_CIRCUIT_DIGEST: [u8; 32] = [
    0x31, 0xb0, 0x3d, 0x13, 0xe4, 0x1a, 0x72, 0x83, 0x42, 0xae, 0xdc, 0xe7, 0xaf, 0x40, 0xf5, 0x40,
    0x5d, 0xc5, 0x98, 0xd2, 0x8e, 0x78, 0x4d, 0xe4, 0x4d, 0x80, 0x44, 0xdb, 0x9c, 0x60, 0x1a, 0x0c,
];
const EXPORT_SCHEDULE_DIGEST: [u8; 32] = [
    0x66, 0xdd, 0xc2, 0x0f, 0x84, 0x07, 0xe3, 0x69, 0xb7, 0x4f, 0x2a, 0x21, 0x02, 0x87, 0xd2, 0x13,
    0x1e, 0x78, 0xc7, 0x52, 0x5f, 0x47, 0xfc, 0x82, 0x9c, 0x57, 0xf6, 0x41, 0x8b, 0x0d, 0x97, 0xd0,
];

pub(super) const ACTIVATION_INPUT_BITS_PER_ROLE: usize = 6 * 256;
pub(super) const EXPORT_INPUT_BITS_PER_ROLE: usize = 3 * 256;
pub(super) const ACTIVATION_OUTPUT_BITS_PER_ROLE: usize = 2 * 256;
pub(super) const EXPORT_OUTPUT_BITS_PER_ROLE: usize = 256;

const ACTIVATION_ROLE_INPUT_BYTES: usize = ACTIVATION_INPUT_BITS_PER_ROLE / 8;
const EXPORT_ROLE_INPUT_BYTES: usize = EXPORT_INPUT_BITS_PER_ROLE / 8;
const ACTIVATION_A_DIRECT_LABEL_BYTES: usize = ACTIVATION_INPUT_BITS_PER_ROLE * LABEL_BYTES;
const EXPORT_A_DIRECT_LABEL_BYTES: usize = EXPORT_INPUT_BITS_PER_ROLE * LABEL_BYTES;
const ACTIVATION_B_OT_PAIR_BYTES: usize = ACTIVATION_INPUT_BITS_PER_ROLE * 2 * LABEL_BYTES;
const EXPORT_B_OT_PAIR_BYTES: usize = EXPORT_INPUT_BITS_PER_ROLE * 2 * LABEL_BYTES;
const ACTIVATION_B_OUTPUT_DECODE_BYTES: usize = ACTIVATION_OUTPUT_BITS_PER_ROLE / 8;
const EXPORT_B_OUTPUT_DECODE_BYTES: usize = EXPORT_OUTPUT_BITS_PER_ROLE / 8;
const ACTIVATION_A_SELECTED_OUTPUT_BYTES: usize = ACTIVATION_OUTPUT_BITS_PER_ROLE * LABEL_BYTES;
const EXPORT_A_SELECTED_OUTPUT_BYTES: usize = EXPORT_OUTPUT_BITS_PER_ROLE * LABEL_BYTES;

const SCALAR_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RoleBoundaryError {
    Randomness,
    ZeroSessionId,
    ZeroTranscriptDigest,
    NonCanonicalScalar,
    DecodedOutputLength,
    PayloadLength,
    MessageLength,
    Magic,
    Version,
    Family,
    MessageKind,
    Reserved,
    Session,
    GateDomain,
    CircuitDigest,
    ScheduleDigest,
    Transcript,
    ItemCount,
}

impl fmt::Display for RoleBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Phase 4 passive-role boundary value")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SessionId([u8; 32]);

impl SessionId {
    pub(super) fn random_os() -> Result<Self, RoleBoundaryError> {
        loop {
            let mut bytes = [0_u8; 32];
            getrandom::getrandom(&mut bytes).map_err(|_| RoleBoundaryError::Randomness)?;
            match Self::new(bytes) {
                Ok(session) => return Ok(session),
                Err(RoleBoundaryError::ZeroSessionId) => bytes.zeroize(),
                Err(error) => return Err(error),
            }
        }
    }

    pub(super) fn new(bytes: [u8; 32]) -> Result<Self, RoleBoundaryError> {
        if bytes.iter().all(|byte| *byte == 0) {
            Err(RoleBoundaryError::ZeroSessionId)
        } else {
            Ok(Self(bytes))
        }
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TranscriptDigest32([u8; 32]);

impl TranscriptDigest32 {
    pub(super) fn new(bytes: [u8; 32]) -> Result<Self, RoleBoundaryError> {
        if bytes.iter().all(|byte| *byte == 0) {
            Err(RoleBoundaryError::ZeroTranscriptDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionBindingCore {
    session_id: SessionId,
    gate_domain: u64,
    circuit_digest: CircuitDigest32,
    schedule_digest: ScheduleDigest32,
}

impl SessionBindingCore {
    fn fixed(
        session_id: SessionId,
        family_tag: u8,
        circuit_digest_bytes: [u8; 32],
        schedule_digest_bytes: [u8; 32],
    ) -> Self {
        let gate_domain = derive_gate_domain(family_tag, session_id, circuit_digest_bytes);
        let circuit_digest = CircuitDigest32::new(circuit_digest_bytes)
            .expect("pinned Phase 4 circuit digest is nonzero");
        let schedule_digest = ScheduleDigest32::new(schedule_digest_bytes)
            .expect("pinned Phase 4 schedule digest is nonzero");
        Self {
            session_id,
            gate_domain,
            circuit_digest,
            schedule_digest,
        }
    }

    const fn session_bytes(&self) -> &[u8; 32] {
        self.session_id.as_bytes()
    }

    const fn gate_domain(&self) -> u64 {
        self.gate_domain
    }

    const fn circuit_digest(&self) -> CircuitDigest32 {
        self.circuit_digest
    }

    const fn schedule_digest(&self) -> ScheduleDigest32 {
        self.schedule_digest
    }
}

fn derive_gate_domain(family_tag: u8, session_id: SessionId, circuit_digest: [u8; 32]) -> u64 {
    let digest = Sha256::new()
        .chain_update(GATE_DOMAIN_TAG)
        .chain_update([family_tag])
        .chain_update(session_id.as_bytes())
        .chain_update(circuit_digest)
        .finalize();
    let mut encoded = [0_u8; 8];
    encoded.copy_from_slice(&digest[..8]);
    let candidate = u64::from_be_bytes(encoded);
    if candidate == 0 {
        1
    } else {
        candidate
    }
}

macro_rules! define_family_binding {
    (
        $binding:ident,
        $context:ident,
        $family_tag:expr,
        $circuit_digest:expr,
        $schedule_digest:expr
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(super) struct $binding(SessionBindingCore);

        impl $binding {
            pub(super) fn new(session_id: SessionId) -> Self {
                Self(SessionBindingCore::fixed(
                    session_id,
                    $family_tag,
                    $circuit_digest,
                    $schedule_digest,
                ))
            }

            const fn core(self) -> SessionBindingCore {
                self.0
            }

            pub(super) const fn session_bytes(&self) -> &[u8; 32] {
                self.0.session_bytes()
            }

            pub(super) const fn gate_domain(&self) -> u64 {
                self.0.gate_domain()
            }

            pub(super) const fn circuit_digest(&self) -> CircuitDigest32 {
                self.0.circuit_digest()
            }

            pub(super) const fn schedule_digest(&self) -> ScheduleDigest32 {
                self.0.schedule_digest()
            }

            pub(super) const fn bind_transcript(self, predecessor: TranscriptDigest32) -> $context {
                $context {
                    binding: self,
                    predecessor,
                }
            }
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(super) struct $context {
            binding: $binding,
            predecessor: TranscriptDigest32,
        }

        impl $context {
            const fn core(self) -> SessionBindingCore {
                self.binding.core()
            }

            const fn predecessor(self) -> TranscriptDigest32 {
                self.predecessor
            }
        }
    };
}

define_family_binding!(
    ActivationSessionBinding,
    ActivationMessageContext,
    ACTIVATION_FAMILY_TAG,
    ACTIVATION_CIRCUIT_DIGEST,
    ACTIVATION_SCHEDULE_DIGEST
);
define_family_binding!(
    ExportSessionBinding,
    ExportMessageContext,
    EXPORT_FAMILY_TAG,
    EXPORT_CIRCUIT_DIGEST,
    EXPORT_SCHEDULE_DIGEST
);

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretField32([u8; 32]);

impl SecretField32 {
    const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn append_to(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }

    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretField32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretField32([REDACTED])")
    }
}

fn parse_canonical_scalar(bytes: [u8; 32]) -> Result<SecretField32, RoleBoundaryError> {
    let mut borrow = 0_u16;
    let mut index = 0_usize;
    while index < bytes.len() {
        let difference = (bytes[index] as u16)
            .wrapping_sub(SCALAR_ORDER_LE[index] as u16)
            .wrapping_sub(borrow);
        borrow = difference >> 15;
        index += 1;
    }
    if borrow == 1 {
        Ok(SecretField32::new(bytes))
    } else {
        Err(RoleBoundaryError::NonCanonicalScalar)
    }
}

macro_rules! define_unrestricted_field {
    ($name:ident) => {
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub(super) struct $name(SecretField32);

        impl $name {
            pub(super) const fn from_secret_bytes(bytes: [u8; 32]) -> Self {
                Self(SecretField32::new(bytes))
            }
        }
    };
}

macro_rules! define_scalar_field {
    ($name:ident) => {
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub(super) struct $name(SecretField32);

        impl $name {
            pub(super) fn from_canonical_secret_bytes(
                bytes: [u8; 32],
            ) -> Result<Self, RoleBoundaryError> {
                parse_canonical_scalar(bytes).map(Self)
            }
        }
    };
}

define_unrestricted_field!(DeriverAClientY);
define_unrestricted_field!(DeriverAServerY);
define_unrestricted_field!(DeriverBClientY);
define_unrestricted_field!(DeriverBServerY);
define_unrestricted_field!(DeriverASeedOutputCoin);
define_unrestricted_field!(DeriverBSeedOutputCoin);
define_scalar_field!(DeriverAClientTau);
define_scalar_field!(DeriverAServerTau);
define_scalar_field!(DeriverBClientTau);
define_scalar_field!(DeriverBServerTau);
define_scalar_field!(DeriverAClientScalarOutputCoin);
define_scalar_field!(DeriverASigningWorkerScalarOutputCoin);
define_scalar_field!(DeriverBClientScalarOutputCoin);
define_scalar_field!(DeriverBSigningWorkerScalarOutputCoin);

fn random_scalar_field() -> Result<SecretField32, RoleBoundaryError> {
    let mut wide = [0_u8; 64];
    getrandom::getrandom(&mut wide).map_err(|_| RoleBoundaryError::Randomness)?;
    let mut bytes = Scalar::from_bytes_mod_order_wide(&wide).to_bytes();
    wide.zeroize();
    let output = SecretField32::new(bytes);
    bytes.zeroize();
    Ok(output)
}

macro_rules! implement_random_scalar_coin {
    ($name:ident) => {
        impl $name {
            pub(super) fn random_os() -> Result<Self, RoleBoundaryError> {
                random_scalar_field().map(Self)
            }
        }
    };
}

implement_random_scalar_coin!(DeriverAClientScalarOutputCoin);
implement_random_scalar_coin!(DeriverASigningWorkerScalarOutputCoin);
implement_random_scalar_coin!(DeriverBClientScalarOutputCoin);
implement_random_scalar_coin!(DeriverBSigningWorkerScalarOutputCoin);

impl DeriverASeedOutputCoin {
    pub(super) fn random_os() -> Result<Self, RoleBoundaryError> {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| RoleBoundaryError::Randomness)?;
        let output = Self(SecretField32::new(bytes));
        bytes.zeroize();
        Ok(output)
    }
}

impl DeriverBSeedOutputCoin {
    pub(super) fn random_os() -> Result<Self, RoleBoundaryError> {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| RoleBoundaryError::Randomness)?;
        let output = Self(SecretField32::new(bytes));
        bytes.zeroize();
        Ok(output)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ClientScalarShare(SecretField32);

#[derive(Zeroize, ZeroizeOnDrop)]
struct SigningWorkerScalarShare(SecretField32);

fn parse_activation_output(
    decoded: &[u8],
) -> Result<(ClientScalarShare, SigningWorkerScalarShare), RoleBoundaryError> {
    if decoded.len() != ACTIVATION_OUTPUT_BITS_PER_ROLE / 8 {
        return Err(RoleBoundaryError::DecodedOutputLength);
    }
    let mut client_bytes = [0_u8; 32];
    let mut signing_worker_bytes = [0_u8; 32];
    client_bytes.copy_from_slice(&decoded[..32]);
    signing_worker_bytes.copy_from_slice(&decoded[32..]);

    let parsed_client = parse_canonical_scalar(client_bytes);
    client_bytes.zeroize();
    let client = ClientScalarShare(parsed_client?);

    let parsed_signing_worker = parse_canonical_scalar(signing_worker_bytes);
    signing_worker_bytes.zeroize();
    let signing_worker = SigningWorkerScalarShare(parsed_signing_worker?);
    Ok((client, signing_worker))
}

macro_rules! define_activation_role_shares {
    ($name:ident) => {
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub(super) struct $name {
            client: ClientScalarShare,
            signing_worker: SigningWorkerScalarShare,
        }

        impl $name {
            pub(super) fn from_decoded_output(decoded: &[u8]) -> Result<Self, RoleBoundaryError> {
                let (client, signing_worker) = parse_activation_output(decoded)?;
                Ok(Self {
                    client,
                    signing_worker,
                })
            }

            pub(super) const fn client_share_bytes(&self) -> &[u8; 32] {
                self.client.0.as_bytes()
            }

            pub(super) const fn signing_worker_share_bytes(&self) -> &[u8; 32] {
                self.signing_worker.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_activation_role_shares!(DecodedDeriverAActivationShares);
define_activation_role_shares!(DecodedDeriverBActivationShares);

macro_rules! define_export_role_share {
    ($name:ident) => {
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub(super) struct $name(SecretField32);

        impl $name {
            pub(super) fn from_decoded_output(decoded: &[u8]) -> Result<Self, RoleBoundaryError> {
                if decoded.len() != EXPORT_OUTPUT_BITS_PER_ROLE / 8 {
                    return Err(RoleBoundaryError::DecodedOutputLength);
                }
                let mut share = [0_u8; 32];
                share.copy_from_slice(decoded);
                let output = Self(SecretField32::new(share));
                share.zeroize();
                Ok(output)
            }

            pub(super) const fn share_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_export_role_share!(DecodedDeriverAExportSeedShare);
define_export_role_share!(DecodedDeriverBExportSeedShare);

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct ActivationDeriverAInputs {
    y_client: DeriverAClientY,
    y_server: DeriverAServerY,
    tau_client: DeriverAClientTau,
    tau_server: DeriverAServerTau,
    client_output_coin: DeriverAClientScalarOutputCoin,
    signing_worker_output_coin: DeriverASigningWorkerScalarOutputCoin,
}

impl ActivationDeriverAInputs {
    pub(super) const fn new(
        y_client: DeriverAClientY,
        y_server: DeriverAServerY,
        tau_client: DeriverAClientTau,
        tau_server: DeriverAServerTau,
        client_output_coin: DeriverAClientScalarOutputCoin,
        signing_worker_output_coin: DeriverASigningWorkerScalarOutputCoin,
    ) -> Self {
        Self {
            y_client,
            y_server,
            tau_client,
            tau_server,
            client_output_coin,
            signing_worker_output_coin,
        }
    }

    fn into_role_bytes(self) -> SecretRoleInputBytes {
        encode_role_fields(
            ACTIVATION_ROLE_INPUT_BYTES,
            [
                &self.y_client.0,
                &self.y_server.0,
                &self.tau_client.0,
                &self.tau_server.0,
                &self.client_output_coin.0,
                &self.signing_worker_output_coin.0,
            ],
        )
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct ActivationDeriverBInputs {
    y_client: DeriverBClientY,
    y_server: DeriverBServerY,
    tau_client: DeriverBClientTau,
    tau_server: DeriverBServerTau,
    client_output_coin: DeriverBClientScalarOutputCoin,
    signing_worker_output_coin: DeriverBSigningWorkerScalarOutputCoin,
}

impl ActivationDeriverBInputs {
    pub(super) const fn new(
        y_client: DeriverBClientY,
        y_server: DeriverBServerY,
        tau_client: DeriverBClientTau,
        tau_server: DeriverBServerTau,
        client_output_coin: DeriverBClientScalarOutputCoin,
        signing_worker_output_coin: DeriverBSigningWorkerScalarOutputCoin,
    ) -> Self {
        Self {
            y_client,
            y_server,
            tau_client,
            tau_server,
            client_output_coin,
            signing_worker_output_coin,
        }
    }

    fn into_role_bytes(self) -> SecretRoleInputBytes {
        encode_role_fields(
            ACTIVATION_ROLE_INPUT_BYTES,
            [
                &self.y_client.0,
                &self.y_server.0,
                &self.tau_client.0,
                &self.tau_server.0,
                &self.client_output_coin.0,
                &self.signing_worker_output_coin.0,
            ],
        )
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct ExportDeriverAInputs {
    y_client: DeriverAClientY,
    y_server: DeriverAServerY,
    seed_output_coin: DeriverASeedOutputCoin,
}

impl ExportDeriverAInputs {
    pub(super) const fn new(
        y_client: DeriverAClientY,
        y_server: DeriverAServerY,
        seed_output_coin: DeriverASeedOutputCoin,
    ) -> Self {
        Self {
            y_client,
            y_server,
            seed_output_coin,
        }
    }

    fn into_role_bytes(self) -> SecretRoleInputBytes {
        encode_role_fields(
            EXPORT_ROLE_INPUT_BYTES,
            [&self.y_client.0, &self.y_server.0, &self.seed_output_coin.0],
        )
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct ExportDeriverBInputs {
    y_client: DeriverBClientY,
    y_server: DeriverBServerY,
    seed_output_coin: DeriverBSeedOutputCoin,
}

impl ExportDeriverBInputs {
    pub(super) const fn new(
        y_client: DeriverBClientY,
        y_server: DeriverBServerY,
        seed_output_coin: DeriverBSeedOutputCoin,
    ) -> Self {
        Self {
            y_client,
            y_server,
            seed_output_coin,
        }
    }

    fn into_role_bytes(self) -> SecretRoleInputBytes {
        encode_role_fields(
            EXPORT_ROLE_INPUT_BYTES,
            [&self.y_client.0, &self.y_server.0, &self.seed_output_coin.0],
        )
    }
}

fn encode_role_fields<const FIELD_COUNT: usize>(
    capacity: usize,
    fields: [&SecretField32; FIELD_COUNT],
) -> SecretRoleInputBytes {
    let mut bytes = Vec::with_capacity(capacity);
    for field in fields {
        field.append_to(&mut bytes);
    }
    debug_assert_eq!(bytes.len(), capacity);
    SecretRoleInputBytes(bytes)
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretRoleInputBytes(Vec<u8>);

impl SecretRoleInputBytes {
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct SecretPayload(Vec<u8>);

impl SecretPayload {
    fn copy_exact(bytes: &[u8], expected: usize) -> Result<Self, RoleBoundaryError> {
        if bytes.len() != expected {
            return Err(RoleBoundaryError::PayloadLength);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretPayload([REDACTED])")
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct SecretMessageBytes(Vec<u8>);

impl SecretMessageBytes {
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretMessageBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMessageBytes([REDACTED])")
    }
}

trait MessageContext: Copy {
    const FAMILY_TAG: u8;

    fn core(self) -> SessionBindingCore;
    fn predecessor(self) -> TranscriptDigest32;
}

impl MessageContext for ActivationMessageContext {
    const FAMILY_TAG: u8 = ACTIVATION_FAMILY_TAG;

    fn core(self) -> SessionBindingCore {
        self.core()
    }

    fn predecessor(self) -> TranscriptDigest32 {
        self.predecessor()
    }
}

impl MessageContext for ExportMessageContext {
    const FAMILY_TAG: u8 = EXPORT_FAMILY_TAG;

    fn core(self) -> SessionBindingCore {
        self.core()
    }

    fn predecessor(self) -> TranscriptDigest32 {
        self.predecessor()
    }
}

fn encode_message<C: MessageContext>(
    context: C,
    kind: u8,
    item_count: usize,
    payload: &[u8],
) -> SecretMessageBytes {
    let core = context.core();
    let mut encoded = vec![0_u8; MESSAGE_HEADER_BYTES + payload.len()];
    encoded[..8].copy_from_slice(MESSAGE_MAGIC);
    encoded[8] = MESSAGE_VERSION;
    encoded[9] = C::FAMILY_TAG;
    encoded[10] = kind;
    encoded[11] = 0;
    encoded[12..44].copy_from_slice(&core.session_id.0);
    encoded[44..52].copy_from_slice(&core.gate_domain.to_be_bytes());
    encoded[52..84].copy_from_slice(core.circuit_digest.as_bytes());
    encoded[84..116].copy_from_slice(core.schedule_digest.as_bytes());
    encoded[116..148].copy_from_slice(&context.predecessor().0);
    encoded[148..152].copy_from_slice(&(item_count as u32).to_be_bytes());
    encoded[152..156].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    encoded[MESSAGE_HEADER_BYTES..].copy_from_slice(payload);
    SecretMessageBytes(encoded)
}

fn decode_message<C: MessageContext>(
    context: C,
    kind: u8,
    item_count: usize,
    payload_bytes: usize,
    encoded: &[u8],
) -> Result<SecretPayload, RoleBoundaryError> {
    let expected_length = MESSAGE_HEADER_BYTES
        .checked_add(payload_bytes)
        .ok_or(RoleBoundaryError::MessageLength)?;
    if encoded.len() != expected_length {
        return Err(RoleBoundaryError::MessageLength);
    }
    if &encoded[..8] != MESSAGE_MAGIC {
        return Err(RoleBoundaryError::Magic);
    }
    if encoded[8] != MESSAGE_VERSION {
        return Err(RoleBoundaryError::Version);
    }
    if encoded[9] != C::FAMILY_TAG {
        return Err(RoleBoundaryError::Family);
    }
    if encoded[10] != kind {
        return Err(RoleBoundaryError::MessageKind);
    }
    if encoded[11] != 0 {
        return Err(RoleBoundaryError::Reserved);
    }
    let core = context.core();
    if encoded[12..44] != core.session_id.0 {
        return Err(RoleBoundaryError::Session);
    }
    if encoded[44..52] != core.gate_domain.to_be_bytes() {
        return Err(RoleBoundaryError::GateDomain);
    }
    if encoded[52..84] != *core.circuit_digest.as_bytes() {
        return Err(RoleBoundaryError::CircuitDigest);
    }
    if encoded[84..116] != *core.schedule_digest.as_bytes() {
        return Err(RoleBoundaryError::ScheduleDigest);
    }
    if encoded[116..148] != context.predecessor().0 {
        return Err(RoleBoundaryError::Transcript);
    }
    let encoded_item_count = u32::from_be_bytes(
        encoded[148..152]
            .try_into()
            .expect("fixed message header has a four-byte item count"),
    ) as usize;
    if encoded_item_count != item_count {
        return Err(RoleBoundaryError::ItemCount);
    }
    let encoded_payload_bytes = u32::from_be_bytes(
        encoded[152..156]
            .try_into()
            .expect("fixed message header has a four-byte payload length"),
    ) as usize;
    if encoded_payload_bytes != payload_bytes {
        return Err(RoleBoundaryError::PayloadLength);
    }
    SecretPayload::copy_exact(&encoded[MESSAGE_HEADER_BYTES..], payload_bytes)
}

macro_rules! define_message_type {
    (
        $name:ident,
        $context:ident,
        $kind:expr,
        $item_count:expr,
        $payload_bytes:expr
    ) => {
        pub(super) struct $name {
            context: $context,
            payload: SecretPayload,
        }

        impl $name {
            pub(super) fn from_secret_payload(
                context: $context,
                payload: &[u8],
            ) -> Result<Self, RoleBoundaryError> {
                Ok(Self {
                    context,
                    payload: SecretPayload::copy_exact(payload, $payload_bytes)?,
                })
            }

            pub(super) fn decode(
                context: $context,
                encoded: &[u8],
            ) -> Result<Self, RoleBoundaryError> {
                Ok(Self {
                    context,
                    payload: decode_message(context, $kind, $item_count, $payload_bytes, encoded)?,
                })
            }

            pub(super) fn encode(&self) -> SecretMessageBytes {
                encode_message(self.context, $kind, $item_count, self.payload.as_slice())
            }

            pub(super) fn into_secret_payload(self) -> SecretPayload {
                self.payload
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_message_type!(
    ActivationADirectInputLabels,
    ActivationMessageContext,
    A_DIRECT_INPUT_LABELS_KIND,
    ACTIVATION_INPUT_BITS_PER_ROLE,
    ACTIVATION_A_DIRECT_LABEL_BYTES
);
define_message_type!(
    ExportADirectInputLabels,
    ExportMessageContext,
    A_DIRECT_INPUT_LABELS_KIND,
    EXPORT_INPUT_BITS_PER_ROLE,
    EXPORT_A_DIRECT_LABEL_BYTES
);
define_message_type!(
    ActivationBOutputDecodeBits,
    ActivationMessageContext,
    B_OUTPUT_DECODE_BITS_KIND,
    ACTIVATION_OUTPUT_BITS_PER_ROLE,
    ACTIVATION_B_OUTPUT_DECODE_BYTES
);
define_message_type!(
    ExportBOutputDecodeBits,
    ExportMessageContext,
    B_OUTPUT_DECODE_BITS_KIND,
    EXPORT_OUTPUT_BITS_PER_ROLE,
    EXPORT_B_OUTPUT_DECODE_BYTES
);
define_message_type!(
    ActivationASelectedOutputLabels,
    ActivationMessageContext,
    A_SELECTED_OUTPUT_LABELS_KIND,
    ACTIVATION_OUTPUT_BITS_PER_ROLE,
    ACTIVATION_A_SELECTED_OUTPUT_BYTES
);
define_message_type!(
    ExportASelectedOutputLabels,
    ExportMessageContext,
    A_SELECTED_OUTPUT_LABELS_KIND,
    EXPORT_OUTPUT_BITS_PER_ROLE,
    EXPORT_A_SELECTED_OUTPUT_BYTES
);

macro_rules! define_bound_secret_payload {
    ($name:ident, $binding:ident, $payload_bytes:expr) => {
        pub(super) struct $name {
            binding: $binding,
            payload: SecretPayload,
        }

        impl $name {
            pub(super) fn from_secret_payload(
                binding: $binding,
                payload: &[u8],
            ) -> Result<Self, RoleBoundaryError> {
                Ok(Self {
                    binding,
                    payload: SecretPayload::copy_exact(payload, $payload_bytes)?,
                })
            }

            pub(super) const fn binding(&self) -> $binding {
                self.binding
            }

            pub(super) fn secret_payload(&self) -> &[u8] {
                self.payload.as_slice()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_bound_secret_payload!(
    ActivationBOtSenderPairs,
    ActivationSessionBinding,
    ACTIVATION_B_OT_PAIR_BYTES
);
define_bound_secret_payload!(
    ExportBOtSenderPairs,
    ExportSessionBinding,
    EXPORT_B_OT_PAIR_BYTES
);
define_bound_secret_payload!(
    ActivationBSelectedInputLabels,
    ActivationSessionBinding,
    ACTIVATION_A_DIRECT_LABEL_BYTES
);
define_bound_secret_payload!(
    ExportBSelectedInputLabels,
    ExportSessionBinding,
    EXPORT_A_DIRECT_LABEL_BYTES
);

pub(super) struct ActivationBOtChoices {
    binding: ActivationSessionBinding,
    choices: SecretRoleInputBytes,
}

impl ActivationBOtChoices {
    pub(super) const fn binding(&self) -> ActivationSessionBinding {
        self.binding
    }

    pub(super) fn bitpacked_lsb0(&self) -> &[u8] {
        self.choices.as_slice()
    }
}

impl fmt::Debug for ActivationBOtChoices {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActivationBOtChoices([REDACTED])")
    }
}

pub(super) struct ExportBOtChoices {
    binding: ExportSessionBinding,
    choices: SecretRoleInputBytes,
}

impl ExportBOtChoices {
    pub(super) const fn binding(&self) -> ExportSessionBinding {
        self.binding
    }

    pub(super) fn bitpacked_lsb0(&self) -> &[u8] {
        self.choices.as_slice()
    }
}

impl fmt::Debug for ExportBOtChoices {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportBOtChoices([REDACTED])")
    }
}

pub(super) struct ActivationDeriverAStart {
    binding: ActivationSessionBinding,
    inputs: ActivationDeriverAInputs,
}

impl ActivationDeriverAStart {
    pub(super) const fn new(
        binding: ActivationSessionBinding,
        inputs: ActivationDeriverAInputs,
    ) -> Self {
        Self { binding, inputs }
    }

    pub(super) const fn binding(&self) -> ActivationSessionBinding {
        self.binding
    }

    pub(super) fn into_garbler_input(self) -> ActivationDeriverAGarblerInput {
        ActivationDeriverAGarblerInput {
            binding: self.binding,
            inputs: self.inputs.into_role_bytes(),
        }
    }
}

pub(super) struct ActivationDeriverAGarblerInput {
    binding: ActivationSessionBinding,
    inputs: SecretRoleInputBytes,
}

impl ActivationDeriverAGarblerInput {
    pub(super) const fn binding(&self) -> ActivationSessionBinding {
        self.binding
    }

    pub(super) fn bitpacked_lsb0(&self) -> &[u8] {
        self.inputs.as_slice()
    }
}

pub(super) struct ActivationDeriverBStart {
    binding: ActivationSessionBinding,
    inputs: ActivationDeriverBInputs,
}

impl ActivationDeriverBStart {
    pub(super) const fn new(
        binding: ActivationSessionBinding,
        inputs: ActivationDeriverBInputs,
    ) -> Self {
        Self { binding, inputs }
    }

    pub(super) fn into_ot_choices(self) -> ActivationBOtChoices {
        ActivationBOtChoices {
            binding: self.binding,
            choices: self.inputs.into_role_bytes(),
        }
    }
}

pub(super) struct ExportDeriverAStart {
    binding: ExportSessionBinding,
    inputs: ExportDeriverAInputs,
}

impl ExportDeriverAStart {
    pub(super) const fn new(binding: ExportSessionBinding, inputs: ExportDeriverAInputs) -> Self {
        Self { binding, inputs }
    }

    pub(super) const fn binding(&self) -> ExportSessionBinding {
        self.binding
    }

    pub(super) fn into_garbler_input(self) -> ExportDeriverAGarblerInput {
        ExportDeriverAGarblerInput {
            binding: self.binding,
            inputs: self.inputs.into_role_bytes(),
        }
    }
}

pub(super) struct ExportDeriverAGarblerInput {
    binding: ExportSessionBinding,
    inputs: SecretRoleInputBytes,
}

impl ExportDeriverAGarblerInput {
    pub(super) const fn binding(&self) -> ExportSessionBinding {
        self.binding
    }

    pub(super) fn bitpacked_lsb0(&self) -> &[u8] {
        self.inputs.as_slice()
    }
}

pub(super) struct ExportDeriverBStart {
    binding: ExportSessionBinding,
    inputs: ExportDeriverBInputs,
}

impl ExportDeriverBStart {
    pub(super) const fn new(binding: ExportSessionBinding, inputs: ExportDeriverBInputs) -> Self {
        Self { binding, inputs }
    }

    pub(super) fn into_ot_choices(self) -> ExportBOtChoices {
        ExportBOtChoices {
            binding: self.binding,
            choices: self.inputs.into_role_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activation_binding() -> ActivationSessionBinding {
        ActivationSessionBinding::new(SessionId::new([1; 32]).expect("session"))
    }

    fn export_binding() -> ExportSessionBinding {
        ExportSessionBinding::new(SessionId::new([1; 32]).expect("session"))
    }

    fn transcript() -> TranscriptDigest32 {
        TranscriptDigest32::new([9; 32]).expect("transcript")
    }

    fn canonical_scalar(marker: u8) -> [u8; 32] {
        let mut scalar = [0_u8; 32];
        scalar[0] = marker;
        scalar
    }

    fn activation_b_inputs() -> ActivationDeriverBInputs {
        ActivationDeriverBInputs::new(
            DeriverBClientY::from_secret_bytes([0x11; 32]),
            DeriverBServerY::from_secret_bytes([0x22; 32]),
            DeriverBClientTau::from_canonical_secret_bytes(canonical_scalar(3)).expect("tau"),
            DeriverBServerTau::from_canonical_secret_bytes(canonical_scalar(4)).expect("tau"),
            DeriverBClientScalarOutputCoin::from_canonical_secret_bytes(canonical_scalar(5))
                .expect("coin"),
            DeriverBSigningWorkerScalarOutputCoin::from_canonical_secret_bytes(canonical_scalar(6))
                .expect("coin"),
        )
    }

    #[test]
    fn scalar_parser_accepts_zero_and_l_minus_one_and_rejects_l() {
        assert!(parse_canonical_scalar([0; 32]).is_ok());
        let mut below = SCALAR_ORDER_LE;
        below[0] = below[0].wrapping_sub(1);
        assert!(parse_canonical_scalar(below).is_ok());
        assert_eq!(
            parse_canonical_scalar(SCALAR_ORDER_LE).err(),
            Some(RoleBoundaryError::NonCanonicalScalar)
        );
    }

    #[test]
    fn non_vector_session_and_output_coin_constructors_use_os_randomness() {
        let first_session = SessionId::random_os().expect("OS session randomness");
        let second_session = SessionId::random_os().expect("OS session randomness");
        assert_ne!(first_session, second_session);

        let a_client = DeriverAClientScalarOutputCoin::random_os().expect("OS scalar coin");
        let a_worker = DeriverASigningWorkerScalarOutputCoin::random_os().expect("OS scalar coin");
        let b_client = DeriverBClientScalarOutputCoin::random_os().expect("OS scalar coin");
        let b_worker = DeriverBSigningWorkerScalarOutputCoin::random_os().expect("OS scalar coin");
        for coin in [&a_client.0, &a_worker.0, &b_client.0, &b_worker.0] {
            assert!(parse_canonical_scalar(*coin.as_bytes()).is_ok());
        }

        let a_seed = DeriverASeedOutputCoin::random_os().expect("OS seed coin");
        let b_seed = DeriverBSeedOutputCoin::random_os().expect("OS seed coin");
        assert_ne!(a_seed.0.as_bytes(), b_seed.0.as_bytes());
    }

    #[test]
    fn family_bindings_pin_artifacts_and_derive_disjoint_nonzero_gate_domains() {
        let activation = activation_binding();
        let export = export_binding();
        assert_eq!(activation.session_bytes(), &[1; 32]);
        assert_eq!(export.session_bytes(), &[1; 32]);
        assert_eq!(
            activation.circuit_digest().as_bytes(),
            &ACTIVATION_CIRCUIT_DIGEST
        );
        assert_eq!(
            activation.schedule_digest().as_bytes(),
            &ACTIVATION_SCHEDULE_DIGEST
        );
        assert_eq!(export.circuit_digest().as_bytes(), &EXPORT_CIRCUIT_DIGEST);
        assert_eq!(export.schedule_digest().as_bytes(), &EXPORT_SCHEDULE_DIGEST);
        assert_ne!(activation.gate_domain(), 0);
        assert_ne!(export.gate_domain(), 0);
        assert_ne!(activation.gate_domain(), export.gate_domain());
        assert_eq!(activation.gate_domain(), activation_binding().gate_domain());
    }

    #[test]
    fn b_activation_choices_have_fixed_role_only_order_and_count() {
        let choices = ActivationDeriverBStart::new(activation_binding(), activation_b_inputs())
            .into_ot_choices();
        assert_eq!(choices.bitpacked_lsb0().len(), ACTIVATION_ROLE_INPUT_BYTES);
        assert_eq!(&choices.bitpacked_lsb0()[..32], &[0x11; 32]);
        assert_eq!(&choices.bitpacked_lsb0()[32..64], &[0x22; 32]);
        assert_eq!(choices.bitpacked_lsb0()[64], 3);
        assert_eq!(choices.bitpacked_lsb0()[96], 4);
        assert_eq!(choices.bitpacked_lsb0()[128], 5);
        assert_eq!(choices.bitpacked_lsb0()[160], 6);
    }

    #[test]
    fn exact_message_round_trip_rejects_family_session_kind_and_trailing_bytes() {
        let context = activation_binding().bind_transcript(transcript());
        let message = ActivationBOutputDecodeBits::from_secret_payload(
            context,
            &[0x5a; ACTIVATION_B_OUTPUT_DECODE_BYTES],
        )
        .expect("message");
        let encoded = message.encode();
        let decoded = ActivationBOutputDecodeBits::decode(context, encoded.as_slice())
            .expect("strict decode");
        let decoded_payload = decoded.into_secret_payload();
        assert_eq!(
            decoded_payload.as_slice(),
            &[0x5a; ACTIVATION_B_OUTPUT_DECODE_BYTES]
        );

        let mut wrong_family = encoded.as_slice().to_vec();
        wrong_family[9] = EXPORT_FAMILY_TAG;
        assert_eq!(
            ActivationBOutputDecodeBits::decode(context, &wrong_family).err(),
            Some(RoleBoundaryError::Family)
        );

        let mut wrong_kind = encoded.as_slice().to_vec();
        wrong_kind[10] = A_SELECTED_OUTPUT_LABELS_KIND;
        assert_eq!(
            ActivationBOutputDecodeBits::decode(context, &wrong_kind).err(),
            Some(RoleBoundaryError::MessageKind)
        );

        let other_session =
            ActivationSessionBinding::new(SessionId::new([8; 32]).expect("session"))
                .bind_transcript(transcript());
        assert_eq!(
            ActivationBOutputDecodeBits::decode(other_session, encoded.as_slice()).err(),
            Some(RoleBoundaryError::Session)
        );

        let mut trailing = encoded.as_slice().to_vec();
        trailing.push(0);
        assert_eq!(
            ActivationBOutputDecodeBits::decode(context, &trailing).err(),
            Some(RoleBoundaryError::MessageLength)
        );
    }

    #[test]
    fn family_message_payloads_use_phase4_private_share_counts() {
        let activation_context = activation_binding().bind_transcript(transcript());
        let export_context = export_binding().bind_transcript(transcript());
        assert!(ActivationADirectInputLabels::from_secret_payload(
            activation_context,
            &vec![0; ACTIVATION_A_DIRECT_LABEL_BYTES]
        )
        .is_ok());
        assert!(ExportADirectInputLabels::from_secret_payload(
            export_context,
            &vec![0; EXPORT_A_DIRECT_LABEL_BYTES]
        )
        .is_ok());
        assert!(ActivationASelectedOutputLabels::from_secret_payload(
            activation_context,
            &vec![0; ACTIVATION_A_SELECTED_OUTPUT_BYTES]
        )
        .is_ok());
        assert!(ExportASelectedOutputLabels::from_secret_payload(
            export_context,
            &vec![0; EXPORT_A_SELECTED_OUTPUT_BYTES]
        )
        .is_ok());
    }

    #[test]
    fn local_ot_material_is_exact_width_and_has_no_wire_codec() {
        let activation_pairs = ActivationBOtSenderPairs::from_secret_payload(
            activation_binding(),
            &vec![0x44; ACTIVATION_B_OT_PAIR_BYTES],
        )
        .expect("pairs");
        assert_eq!(
            activation_pairs.secret_payload().len(),
            ACTIVATION_B_OT_PAIR_BYTES
        );
        assert_eq!(activation_pairs.binding(), activation_binding());

        let export_selected = ExportBSelectedInputLabels::from_secret_payload(
            export_binding(),
            &vec![0x55; EXPORT_A_DIRECT_LABEL_BYTES],
        )
        .expect("selected labels");
        assert_eq!(
            export_selected.secret_payload().len(),
            EXPORT_A_DIRECT_LABEL_BYTES
        );
        assert_eq!(export_selected.binding(), export_binding());
    }

    #[test]
    fn activation_role_outputs_require_two_canonical_scalars() {
        let mut decoded = [0_u8; 64];
        decoded[0] = 3;
        decoded[32] = 5;
        let a = DecodedDeriverAActivationShares::from_decoded_output(&decoded)
            .expect("canonical A shares");
        let b = DecodedDeriverBActivationShares::from_decoded_output(&decoded)
            .expect("canonical B shares");
        assert_eq!(a.client_share_bytes()[0], 3);
        assert_eq!(a.signing_worker_share_bytes()[0], 5);
        assert_eq!(b.client_share_bytes()[0], 3);
        assert_eq!(b.signing_worker_share_bytes()[0], 5);

        decoded[..32].copy_from_slice(&SCALAR_ORDER_LE);
        assert_eq!(
            DecodedDeriverAActivationShares::from_decoded_output(&decoded).err(),
            Some(RoleBoundaryError::NonCanonicalScalar)
        );
        assert_eq!(
            DecodedDeriverBActivationShares::from_decoded_output(&decoded[..63]).err(),
            Some(RoleBoundaryError::DecodedOutputLength)
        );
    }

    #[test]
    fn export_role_outputs_accept_every_exact_256_bit_share() {
        let decoded = [0xff_u8; 32];
        let a =
            DecodedDeriverAExportSeedShare::from_decoded_output(&decoded).expect("A seed share");
        let b =
            DecodedDeriverBExportSeedShare::from_decoded_output(&decoded).expect("B seed share");
        assert_eq!(a.share_bytes(), &decoded);
        assert_eq!(b.share_bytes(), &decoded);
        assert_eq!(
            DecodedDeriverAExportSeedShare::from_decoded_output(&decoded[..31]).err(),
            Some(RoleBoundaryError::DecodedOutputLength)
        );
    }
}
