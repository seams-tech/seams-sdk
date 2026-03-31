use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::context::CanonicalContext;
use crate::error::{ProtoError, ProtoResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FExpandInput {
    pub context: CanonicalContext,
    pub y_client: [u8; 32],
    pub y_relayer: [u8; 32],
    pub tau_client: [u8; 32],
    pub tau_relayer: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FExpandOutput {
    pub context_binding: [u8; 32],
    pub m: [u8; 32],
    pub d: [u8; 32],
    pub h: [u8; 64],
    pub a_bytes: [u8; 32],
    pub a: [u8; 32],
    pub tau: [u8; 32],
    pub x_client_base: [u8; 32],
    pub x_relayer_base: [u8; 32],
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonlinearExpansionOutput {
    pub h: [u8; 64],
    pub a_bytes: [u8; 32],
    pub a: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputShareDerivationOutput {
    pub tau: [u8; 32],
    pub x_client_base: [u8; 32],
    pub x_relayer_base: [u8; 32],
}

pub fn add_le_bytes_mod_2_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;

    for idx in 0..32 {
        let sum = left[idx] as u16 + right[idx] as u16 + carry;
        out[idx] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }

    out
}

pub fn clamp_rfc8032(mut input: [u8; 32]) -> [u8; 32] {
    input[0] &= 248;
    input[31] &= 63;
    input[31] |= 64;
    input
}

pub fn sha512_one_block(d: [u8; 32]) -> [u8; 64] {
    let hash = Sha512::digest(d);
    let mut out = [0u8; 64];
    out.copy_from_slice(&hash);
    out
}

pub fn extract_a_bytes_from_hash(h: [u8; 64]) -> [u8; 32] {
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&h[..32]);
    clamp_rfc8032(a_bytes)
}

pub fn reduce_scalar_mod_l(input: [u8; 32]) -> [u8; 32] {
    Scalar::from_bytes_mod_order(input).to_bytes()
}

pub fn eval_nonlinear_expansion(d: [u8; 32]) -> NonlinearExpansionOutput {
    let h = sha512_one_block(d);
    let a_bytes = extract_a_bytes_from_hash(h);
    let a_scalar = Scalar::from_bytes_mod_order(a_bytes);

    NonlinearExpansionOutput {
        h,
        a_bytes,
        a: a_scalar.to_bytes(),
    }
}

pub fn eval_f_expand(input: &FExpandInput) -> ProtoResult<FExpandOutput> {
    let context_binding = input.context.binding_digest()?;
    let tau_client = parse_canonical_scalar("tau_client", input.tau_client)?;
    let tau_relayer = parse_canonical_scalar("tau_relayer", input.tau_relayer)?;

    let m = add_le_bytes_mod_2_256(input.y_client, input.y_relayer);
    let d = m;
    let nonlinear = eval_nonlinear_expansion(d);
    let output_shares =
        derive_output_shares(nonlinear.a, tau_client.to_bytes(), tau_relayer.to_bytes())?;
    let public_key = public_key_from_scalar_bytes(nonlinear.a)?;

    Ok(FExpandOutput {
        context_binding,
        m,
        d,
        h: nonlinear.h,
        a_bytes: nonlinear.a_bytes,
        a: nonlinear.a,
        tau: output_shares.tau,
        x_client_base: output_shares.x_client_base,
        x_relayer_base: output_shares.x_relayer_base,
        public_key,
    })
}

pub fn derive_output_shares(
    a: [u8; 32],
    tau_client: [u8; 32],
    tau_relayer: [u8; 32],
) -> ProtoResult<OutputShareDerivationOutput> {
    let a_scalar = parse_canonical_scalar("a", a)?;
    let tau_client = parse_canonical_scalar("tau_client", tau_client)?;
    let tau_relayer = parse_canonical_scalar("tau_relayer", tau_relayer)?;
    let tau = tau_client + tau_relayer;
    let x_client_base = a_scalar + tau;
    let x_relayer_base = a_scalar + tau + tau;

    Ok(OutputShareDerivationOutput {
        tau: tau.to_bytes(),
        x_client_base: x_client_base.to_bytes(),
        x_relayer_base: x_relayer_base.to_bytes(),
    })
}

pub fn recover_a_from_base_shares(
    x_client_base: [u8; 32],
    x_relayer_base: [u8; 32],
) -> ProtoResult<[u8; 32]> {
    let x_client = parse_canonical_scalar("x_client_base", x_client_base)?;
    let x_relayer = parse_canonical_scalar("x_relayer_base", x_relayer_base)?;
    Ok((x_client + x_client - x_relayer).to_bytes())
}

pub fn public_key_from_scalar_bytes(a: [u8; 32]) -> ProtoResult<[u8; 32]> {
    let scalar = parse_canonical_scalar("a", a)?;
    Ok((ED25519_BASEPOINT_POINT * scalar).compress().to_bytes())
}

pub fn public_key_from_base_shares(
    x_client_base: [u8; 32],
    x_relayer_base: [u8; 32],
) -> ProtoResult<[u8; 32]> {
    let a = recover_a_from_base_shares(x_client_base, x_relayer_base)?;
    public_key_from_scalar_bytes(a)
}

fn parse_canonical_scalar(label: &str, bytes: [u8; 32]) -> ProtoResult<Scalar> {
    Scalar::from_canonical_bytes(bytes)
        .into_option()
        .ok_or_else(|| ProtoError::Decode(format!("{label} must be canonical scalar bytes")))
}
