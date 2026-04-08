//! Verification entrypoint for `src/shared/reference.rs`.
//!
//! Planned proof targets:
//! - `add_le_bytes_mod_2_256`
//! - `clamp_rfc8032`
//! - `extract_a_bytes_from_hash`
//! - `eval_nonlinear_expansion`
//! - `derive_output_shares`
//! - `recover_a_from_base_shares`
//! - `public_key_from_scalar_bytes`
//! - `public_key_from_base_shares`
//! - `eval_f_expand`

use vstd::prelude::*;
use vstd::contrib::auto_spec;

verus! {

pub type Bytes32 = [u8; 32];
pub type Bytes64 = [u8; 64];

#[derive(Debug, PartialEq, Eq)]
pub struct CanonicalContext {
    pub org_id: String,
    pub account_id: String,
    pub key_purpose: String,
    pub key_version: String,
    pub participant_ids: Vec<u16>,
    pub derivation_version: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FExpandInput {
    pub context: CanonicalContext,
    pub y_client: Bytes32,
    pub y_relayer: Bytes32,
    pub tau_client: Bytes32,
    pub tau_relayer: Bytes32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FExpandOutput {
    pub context_binding: Bytes32,
    pub m: Bytes32,
    pub d: Bytes32,
    pub h: Bytes64,
    pub a_bytes: Bytes32,
    pub a: Bytes32,
    pub tau: Bytes32,
    pub x_client_base: Bytes32,
    pub x_relayer_base: Bytes32,
    pub public_key: Bytes32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct NonlinearExpansionOutput {
    pub h: Bytes64,
    pub a_bytes: Bytes32,
    pub a: Bytes32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct OutputShareDerivationOutput {
    pub tau: Bytes32,
    pub x_client_base: Bytes32,
    pub x_relayer_base: Bytes32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FExpandVisibleBoundary {
    pub canonical_seed: Bytes32,
    pub x_client_base: Bytes32,
    pub x_relayer_base: Bytes32,
}

pub uninterp spec fn context_binding_spec(context: CanonicalContext) -> Bytes32;

pub uninterp spec fn sha512_one_block_spec(d: Bytes32) -> Bytes64;

pub uninterp spec fn reduce_scalar_mod_l_spec(input: Bytes32) -> Bytes32;

pub uninterp spec fn scalar_add_spec(left: Bytes32, right: Bytes32) -> Bytes32;

pub uninterp spec fn scalar_sub_spec(left: Bytes32, right: Bytes32) -> Bytes32;

pub uninterp spec fn basepoint_mul_compress_spec(scalar: Bytes32) -> Bytes32;

pub uninterp spec fn add_le_bytes_mod_2_256_spec(left: Bytes32, right: Bytes32) -> Bytes32;

pub uninterp spec fn extract_a_bytes_from_hash_spec(h: Bytes64) -> Bytes32;

pub open spec fn add_le_bytes_mod_2_256_carry_spec(left: Seq<u8>, right: Seq<u8>, idx: nat) -> int
    decreases idx,
{
    if idx == 0 {
        0
    } else {
        let prev = (idx - 1) as nat;
        let byte_index = prev as int;
        let sum =
            left[byte_index] as int
            + right[byte_index] as int
            + add_le_bytes_mod_2_256_carry_spec(left, right, prev);
        sum / 256
    }
}

pub open spec fn add_le_bytes_mod_2_256_byte_spec(left: Seq<u8>, right: Seq<u8>, idx: nat) -> int
    recommends idx < 32,
{
    let byte_index = idx as int;
    let sum =
        left[byte_index] as int
        + right[byte_index] as int
        + add_le_bytes_mod_2_256_carry_spec(left, right, idx);
    sum % 256
}

// Proves the carry chain for little-endian byte addition never exceeds a
// single carry bit at any byte boundary.
pub proof fn lemma_add_le_bytes_mod_2_256_carry_bound(left: Seq<u8>, right: Seq<u8>, idx: nat)
    requires
        left.len() == 32,
        right.len() == 32,
        idx <= 32,
    ensures
        0 <= add_le_bytes_mod_2_256_carry_spec(left, right, idx) <= 1,
    decreases idx,
{
    if idx == 0 {
    } else {
        let prev = (idx - 1) as nat;
        lemma_add_le_bytes_mod_2_256_carry_bound(left, right, prev);
        let byte_index = prev as int;
        let prev_carry = add_le_bytes_mod_2_256_carry_spec(left, right, prev);
        let sum = left[byte_index] as int + right[byte_index] as int + prev_carry;
        assert(0 <= left[byte_index] as int <= 255);
        assert(0 <= right[byte_index] as int <= 255);
        assert(0 <= prev_carry <= 1);
        assert(0 <= sum <= 511);
        assert(0 <= sum / 256 <= 1);
    }
}

// Proves each modeled output byte from little-endian byte addition stays in
// the valid u8 range before we relate it back to the exec implementation.
pub proof fn lemma_add_le_bytes_mod_2_256_byte_bound(left: Seq<u8>, right: Seq<u8>, idx: nat)
    requires
        left.len() == 32,
        right.len() == 32,
        idx < 32,
    ensures
        0 <= add_le_bytes_mod_2_256_byte_spec(left, right, idx) < 256,
{
    lemma_add_le_bytes_mod_2_256_carry_bound(left, right, idx);
    let byte_index = idx as int;
    let carry = add_le_bytes_mod_2_256_carry_spec(left, right, idx);
    let sum = left[byte_index] as int + right[byte_index] as int + carry;
    assert(0 <= left[byte_index] as int <= 255);
    assert(0 <= right[byte_index] as int <= 255);
    assert(0 <= carry <= 1);
    assert(0 <= sum <= 511);
    assert(0 <= sum % 256 < 256);
}

pub open spec fn eval_f_expand_canonical_seed_byte_spec(input: FExpandInput, idx: nat) -> int
    recommends idx < 32,
{
    add_le_bytes_mod_2_256_byte_spec(input.y_client@, input.y_relayer@, idx)
}

pub open spec fn eval_f_expand_canonical_seed_spec(input: FExpandInput) -> Bytes32 {
    add_le_bytes_mod_2_256_spec(input.y_client, input.y_relayer)
}

pub open spec fn eval_f_expand_tau_spec(input: FExpandInput) -> Bytes32 {
    scalar_add_spec(input.tau_client, input.tau_relayer)
}

pub open spec fn eval_f_expand_a_bytes_spec(input: FExpandInput) -> Bytes32 {
    extract_a_bytes_from_hash_spec(
        sha512_one_block_spec(eval_f_expand_canonical_seed_spec(input)),
    )
}

pub open spec fn eval_f_expand_a_spec(input: FExpandInput) -> Bytes32 {
    reduce_scalar_mod_l_spec(eval_f_expand_a_bytes_spec(input))
}

pub open spec fn eval_f_expand_x_client_base_spec(input: FExpandInput) -> Bytes32 {
    scalar_add_spec(eval_f_expand_a_spec(input), eval_f_expand_tau_spec(input))
}

pub open spec fn eval_f_expand_x_relayer_base_spec(input: FExpandInput) -> Bytes32 {
    scalar_add_spec(eval_f_expand_x_client_base_spec(input), eval_f_expand_tau_spec(input))
}

pub broadcast axiom fn axiom_add_le_bytes_mod_2_256_spec(left: Bytes32, right: Bytes32)
    ensures
        #![trigger add_le_bytes_mod_2_256_spec(left, right)]
        forall|i: int|
            0 <= i < 32 ==> #[trigger] add_le_bytes_mod_2_256_spec(left, right)[i] as int
                == add_le_bytes_mod_2_256_byte_spec(left@, right@, i as nat),
;

pub broadcast axiom fn axiom_extract_a_bytes_from_hash_spec(h: Bytes64)
    ensures
        #![trigger extract_a_bytes_from_hash_spec(h)]
        extract_a_bytes_from_hash_spec(h)[0] == (h[0] & 248u8),
        extract_a_bytes_from_hash_spec(h)[31] == ((h[31] & 63u8) | 64u8),
        forall|i: int|
            0 <= i < 32 && i != 0 && i != 31
                ==> #[trigger] extract_a_bytes_from_hash_spec(h)[i] == h[i],
;

#[verifier::external_body]
pub fn context_binding(context: CanonicalContext) -> (out: Bytes32)
    ensures
        out == context_binding_spec(context),
{
    let _ = context;
    unimplemented!()
}

#[verifier::external_body]
pub fn sha512_one_block(d: Bytes32) -> (out: Bytes64)
    ensures
        out == sha512_one_block_spec(d),
{
    let _ = d;
    unimplemented!()
}

#[verifier::external_body]
pub fn reduce_scalar_mod_l(input: Bytes32) -> (out: Bytes32)
    ensures
        out == reduce_scalar_mod_l_spec(input),
{
    let _ = input;
    unimplemented!()
}

#[verifier::external_body]
pub fn scalar_add(left: Bytes32, right: Bytes32) -> (out: Bytes32)
    ensures
        out == scalar_add_spec(left, right),
{
    let _ = left;
    let _ = right;
    unimplemented!()
}

#[verifier::external_body]
pub fn scalar_sub(left: Bytes32, right: Bytes32) -> (out: Bytes32)
    ensures
        out == scalar_sub_spec(left, right),
{
    let _ = left;
    let _ = right;
    unimplemented!()
}

#[verifier::external_body]
pub fn basepoint_mul_compress(scalar: Bytes32) -> (out: Bytes32)
    ensures
        out == basepoint_mul_compress_spec(scalar),
{
    let _ = scalar;
    unimplemented!()
}

pub fn add_le_bytes_mod_2_256(left: Bytes32, right: Bytes32) -> (out: Bytes32)
    ensures
        out == add_le_bytes_mod_2_256_spec(left, right),
        forall|i: int| 0 <= i < 32 ==> out[i] as int == add_le_bytes_mod_2_256_byte_spec(left@, right@, i as nat),
{
    let mut out = [0u8; 32];
    let mut carry: u32 = 0;

    let mut idx: usize = 0;
    while idx < 32
        invariant
            idx <= 32,
            carry <= 1u32,
            carry as int == add_le_bytes_mod_2_256_carry_spec(left@, right@, idx as nat),
            forall|i: int| 0 <= i < idx ==> out[i] as int == add_le_bytes_mod_2_256_byte_spec(left@, right@, i as nat),
        decreases 32usize - idx,
    {
        proof {
            let idx_nat = idx as nat;
            lemma_add_le_bytes_mod_2_256_carry_bound(left@, right@, idx_nat);
        }
        let left_byte = left[idx];
        let right_byte = right[idx];
        assert(0 <= left_byte < 256);
        assert(0 <= right_byte < 256);
        assert(left_byte + right_byte + carry <= 0x1ff);
        let sum = (left_byte as u32) + (right_byte as u32) + carry;
        assert(sum == left_byte + right_byte + carry);
        assert(sum <= 0x1ff);
        assert(carry as int == add_le_bytes_mod_2_256_carry_spec(left@, right@, idx as nat));
        assert(sum as int
            == left[idx as int] as int
                + right[idx as int] as int
                + add_le_bytes_mod_2_256_carry_spec(left@, right@, idx as nat));
        assert((sum & 0xffu32) < 256u32) by (bit_vector);
        assert(sum <= 0x1ff ==> (sum >> 8) <= 1u32) by (bit_vector);
        assert((sum >> 8) <= 1u32);
        proof {
            let idx_nat = idx as nat;
            lemma_add_le_bytes_mod_2_256_byte_bound(left@, right@, idx_nat);
        }
        assert(
            add_le_bytes_mod_2_256_byte_spec(left@, right@, idx as nat)
                == (
                    left[idx as int] as int
                    + right[idx as int] as int
                    + add_le_bytes_mod_2_256_carry_spec(left@, right@, idx as nat)
                ) % 256
        );
        assert(((sum & 0xffu32) as int) == (sum as int % 256)) by (bit_vector);
        assert(((sum & 0xffu32) as int) == add_le_bytes_mod_2_256_byte_spec(left@, right@, idx as nat));
        out[idx] = (sum & 0xffu32) as u8;
        carry = sum >> 8;
        assert(
            add_le_bytes_mod_2_256_carry_spec(left@, right@, (idx + 1) as nat)
                == (
                    left[idx as int] as int
                    + right[idx as int] as int
                    + add_le_bytes_mod_2_256_carry_spec(left@, right@, idx as nat)
                ) / 256
        );
        assert((sum >> 8) as int == (sum as int / 256)) by (bit_vector);
        assert((sum >> 8) as int == add_le_bytes_mod_2_256_carry_spec(left@, right@, (idx + 1) as nat));
        assert(carry <= 1u32);
        idx += 1;
    }

    proof {
        broadcast use axiom_add_le_bytes_mod_2_256_spec;
        assert forall|i: int| 0 <= i < 32 implies out[i] == add_le_bytes_mod_2_256_spec(left, right)[i] by {
        }
    }

    out
}

pub fn clamp_rfc8032(mut input: Bytes32) -> (out: Bytes32)
    ensures
        out[0] == (input[0] & 248u8),
        out[31] == ((input[31] & 63u8) | 64u8),
        forall|i: int| 0 <= i < 32 && i != 0 && i != 31 ==> out[i] == input[i],
{
    input[0] &= 248u8;
    input[31] &= 63u8;
    input[31] |= 64u8;
    input
}

pub fn extract_a_bytes_from_hash(h: Bytes64) -> (out: Bytes32)
    ensures
        out == extract_a_bytes_from_hash_spec(h),
        out[0] == (h[0] & 248u8),
        out[31] == ((h[31] & 63u8) | 64u8),
        forall|i: int| 0 <= i < 32 && i != 0 && i != 31 ==> out[i] == h[i],
{
    let mut a_bytes = [0u8; 32];
    let mut idx: usize = 0;
    while idx < 32
        invariant
            idx <= 32,
            forall|i: int| 0 <= i < idx ==> a_bytes[i] == h[i],
        decreases 32usize - idx,
    {
        a_bytes[idx] = h[idx];
        idx += 1;
    }

    let out = clamp_rfc8032(a_bytes);
    proof {
        broadcast use axiom_extract_a_bytes_from_hash_spec;
        assert forall|i: int| 0 <= i < 32 implies out[i] == extract_a_bytes_from_hash_spec(h)[i] by {
        }
    }
    out
}

pub fn eval_nonlinear_expansion(d: Bytes32) -> (out: NonlinearExpansionOutput)
    ensures
        out.h == sha512_one_block_spec(d),
        out.a_bytes == extract_a_bytes_from_hash_spec(sha512_one_block_spec(d)),
        out.a_bytes[0] == (sha512_one_block_spec(d)[0] & 248u8),
        out.a_bytes[31] == ((sha512_one_block_spec(d)[31] & 63u8) | 64u8),
        forall|i: int| #![auto] 0 <= i < 32 && i != 0 && i != 31 ==> out.a_bytes[i] == sha512_one_block_spec(d)[i],
        out.a == reduce_scalar_mod_l_spec(out.a_bytes),
{
    let h = sha512_one_block(d);
    let a_bytes = extract_a_bytes_from_hash(h);
    let a = reduce_scalar_mod_l(a_bytes);

    NonlinearExpansionOutput { h, a_bytes, a }
}

pub fn derive_output_shares(
    a: Bytes32,
    tau_client: Bytes32,
    tau_relayer: Bytes32,
) -> (out: OutputShareDerivationOutput)
    ensures
        out.tau == scalar_add_spec(tau_client, tau_relayer),
        out.x_client_base == scalar_add_spec(a, out.tau),
        out.x_relayer_base == scalar_add_spec(out.x_client_base, out.tau),
{
    let tau = scalar_add(tau_client, tau_relayer);
    let x_client_base = scalar_add(a, tau);
    let x_relayer_base = scalar_add(x_client_base, tau);

    OutputShareDerivationOutput { tau, x_client_base, x_relayer_base }
}

pub fn recover_a_from_base_shares(
    x_client_base: Bytes32,
    x_relayer_base: Bytes32,
) -> (out: Bytes32)
    ensures
        out == scalar_sub_spec(scalar_add_spec(x_client_base, x_client_base), x_relayer_base),
{
    let double_client = scalar_add(x_client_base, x_client_base);
    scalar_sub(double_client, x_relayer_base)
}

pub fn public_key_from_scalar_bytes(a: Bytes32) -> (out: Bytes32)
    ensures
        out == basepoint_mul_compress_spec(a),
{
    basepoint_mul_compress(a)
}

pub fn public_key_from_base_shares(
    x_client_base: Bytes32,
    x_relayer_base: Bytes32,
) -> (out: Bytes32)
    ensures
        out == basepoint_mul_compress_spec(
            scalar_sub_spec(scalar_add_spec(x_client_base, x_client_base), x_relayer_base)
        ),
{
    let a = recover_a_from_base_shares(x_client_base, x_relayer_base);
    public_key_from_scalar_bytes(a)
}

pub fn eval_f_expand(input: FExpandInput) -> (out: FExpandOutput)
    ensures
        out.context_binding == context_binding_spec(input.context),
        out.m == add_le_bytes_mod_2_256_spec(input.y_client, input.y_relayer),
        forall|i: int| 0 <= i < 32 ==> out.m[i] as int == add_le_bytes_mod_2_256_byte_spec(input.y_client@, input.y_relayer@, i as nat),
        out.d == out.m,
        out.h == sha512_one_block_spec(out.d),
        out.a_bytes == extract_a_bytes_from_hash_spec(out.h),
        out.a_bytes[0] == (sha512_one_block_spec(out.d)[0] & 248u8),
        out.a_bytes[31] == ((sha512_one_block_spec(out.d)[31] & 63u8) | 64u8),
        forall|i: int| #![auto] 0 <= i < 32 && i != 0 && i != 31 ==> out.a_bytes[i] == sha512_one_block_spec(out.d)[i],
        out.a == reduce_scalar_mod_l_spec(out.a_bytes),
        out.tau == scalar_add_spec(input.tau_client, input.tau_relayer),
        out.x_client_base == scalar_add_spec(out.a, out.tau),
        out.x_relayer_base == scalar_add_spec(out.x_client_base, out.tau),
        out.public_key == basepoint_mul_compress_spec(out.a),
{
    let context = input.context;
    let y_client = input.y_client;
    let y_relayer = input.y_relayer;
    let tau_client = input.tau_client;
    let tau_relayer = input.tau_relayer;

    let context_binding = context_binding(context);
    let m = add_le_bytes_mod_2_256(y_client, y_relayer);
    let d = m;
    let nonlinear = eval_nonlinear_expansion(d);
    let output_shares = derive_output_shares(nonlinear.a, tau_client, tau_relayer);
    let public_key = public_key_from_scalar_bytes(nonlinear.a);

    FExpandOutput {
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
    }
}

pub fn eval_f_expand_canonical_seed_boundary(input: FExpandInput) -> (out: Bytes32)
    ensures
        forall|i: int| 0 <= i < 32 ==> out[i] as int == eval_f_expand_canonical_seed_byte_spec(input, i as nat),
{
    let expanded = eval_f_expand(input);
    expanded.d
}

// Projects the production-visible `F_expand` boundary into the stable
// three-field shape consumed by the executor-side proof layer.
#[auto_spec]
pub fn f_expand_visible_boundary_from_output(expanded: FExpandOutput) -> (out: FExpandVisibleBoundary)
    ensures
        out.canonical_seed == expanded.d,
        out.x_client_base == expanded.x_client_base,
        out.x_relayer_base == expanded.x_relayer_base,
{
    FExpandVisibleBoundary {
        canonical_seed: expanded.d,
        x_client_base: expanded.x_client_base,
        x_relayer_base: expanded.x_relayer_base,
    }
}

// Projects the visible `F_expand` boundary directly from the input-level
// helper path so downstream proof code does not duplicate that wiring.
pub fn eval_f_expand_visible_boundary_from_input(input: FExpandInput) -> (out: FExpandVisibleBoundary)
    ensures
        out.canonical_seed == eval_f_expand_canonical_seed_spec(input),
        out.x_client_base == eval_f_expand_x_client_base_spec(input),
        out.x_relayer_base == eval_f_expand_x_relayer_base_spec(input),
        forall|i: int| 0 <= i < 32 ==> out.canonical_seed[i] as int == eval_f_expand_canonical_seed_byte_spec(input, i as nat),
{
    let expanded = eval_f_expand(input);
    f_expand_visible_boundary_from_output(expanded)
}

// Proves the shared visible-boundary projection depends only on the three
// allowed visible fields and ignores the remaining clear `F_expand` fields.
pub proof fn f_expand_visible_boundary_depends_only_on_visible_fields(
    left: FExpandOutput,
    right: FExpandOutput,
)
    requires
        left.d == right.d,
        left.x_client_base == right.x_client_base,
        left.x_relayer_base == right.x_relayer_base,
    ensures
        f_expand_visible_boundary_from_output(left)
            == f_expand_visible_boundary_from_output(right),
{
}

} // verus!
