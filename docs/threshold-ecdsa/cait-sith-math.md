# Cait-Sith Threshold ECDSA Math

Last updated: 2026-05-16

This note explains the math shape used by Cait-Sith-style threshold ECDSA and
our `near/threshold-signatures` integration. It focuses on the signing algebra,
presignature shape, rerandomization, and single-use requirements.

## Symbols

Let:

$$
G
$$

be the secp256k1 generator point, and let:

$$
q
$$

be the secp256k1 scalar field order.

All scalar arithmetic below is modulo:

$$
q
$$

The ECDSA private key scalar is:

$$
x \in \mathbb{Z}_q^\*
$$

The public key is:

$$
X = xG
$$

The message digest interpreted as a scalar is:

$$
z
$$

## Standard ECDSA

Standard ECDSA uses a unique nonce scalar:

$$
n \in \mathbb{Z}_q^\*
$$

It computes the nonce point:

$$
R = nG
$$

and extracts:

$$
r = \operatorname{xcoord}(R)
$$

The signature scalar is:

$$
s = n^{-1}(z + rx)
$$

The signature is:

$$
(r, s)
$$

Nonce reuse is catastrophic. If the same effective nonce is used for two
different message digests, the private key can be recovered from the two
signatures.

## Why Cait-Sith Uses Inverse Nonce `k`

Cait-Sith works with the inverse nonce scalar:

$$
k = n^{-1}
$$

Then:

$$
n = k^{-1}
$$

So the ECDSA nonce point can be written as:

$$
R = nG = k^{-1}G
$$

Substitute:

$$
k = n^{-1}
$$

into the standard ECDSA equation:

$$
s = n^{-1}(z + rx)
$$

This gives:

$$
s = k(z + rx)
$$

Expand:

$$
s = zk + r(kx)
$$

This is the key threshold-friendly form. Online signing only needs linear
shares of:

$$
k
$$

and:

$$
\sigma = kx
$$

Each participant can compute a partial signature share:

$$
s_i = z k_i + r \sigma_i
$$

and the coordinator can add the shares:

$$
s = \sum_i s_i
$$

The use of inverse nonce `k` is therefore by construction: it makes online ECDSA
signing a linear aggregation of presigned secrets.

That is why Cait-Sith presigns:

$$
(R, k_i, \sigma_i)
$$

It turns online ECDSA signing into linear share aggregation.

## Shamir Shares And Linearization

Cait-Sith works with Shamir-style shares. For a signing set, each participant
has a Lagrange coefficient:

$$
\lambda_i
$$

Shared values are reconstructed by linearization:

$$
v = \sum_i \lambda_i v_i
$$

For the secret key:

$$
x = \sum_i \lambda_i x_i
$$

For the inverse nonce:

$$
k = \sum_i \lambda_i k_i
$$

For the product:

$$
\sigma = kx = \sum_i \lambda_i \sigma_i
$$

Lagrange reconstruction reconstructs shared algebraic values such as:

$$
k
$$

and:

$$
\sigma = kx
$$

It does not require any participant or coordinator to learn the private key:

$$
x
$$

## Our 2P Additive Share Mapping

Our Router A/B derivation layer derives additive shares:

$$
x = x_{client} + x_{relayer}
$$

`near/threshold-signatures` expects Shamir-style backend shares. For the pinned
implementation, participant IDs:

$$
\{1, 2\}
$$

use scalar coordinates:

$$
\{2, 3\}
$$

For evaluation at zero, the Lagrange coefficients are:

$$
\lambda_{client} = 3
$$

and:

$$
\lambda_{relayer} = -2
$$

We map additive shares into backend shares by dividing by the corresponding
Lagrange coefficient:

$$
\widehat{x}_{client} = x_{client} \cdot 3^{-1}
$$

$$
\widehat{x}_{relayer} = x_{relayer} \cdot (-2)^{-1}
$$

Then Cait-Sith linearization recovers the additive secret:

$$
3\widehat{x}_{client} + (-2)\widehat{x}_{relayer}
= 3(x_{client}3^{-1}) + (-2)(x_{relayer}(-2)^{-1})
$$

Therefore:

$$
3\widehat{x}_{client} + (-2)\widehat{x}_{relayer}
= x_{client} + x_{relayer}
= x
$$

## Beaver Triple Multiplication

The goal of presigning is to create shares of:

$$
k
$$

and:

$$
\sigma = kx
$$

without revealing either:

$$
k
$$

or:

$$
x
$$

To multiply hidden values, Cait-Sith uses Beaver triples. A multiplication
triple is:

$$
(a, b, c)
$$

where:

$$
c = ab
$$

The parties hold shares of `a`, `b`, and `c`. The values `a` and `b` are random
masks.

To compute shares of:

$$
kx
$$

the participants reveal masked values:

$$
\alpha = k + a
$$

and:

$$
\beta = x + b
$$

Because `a` and `b` are random masks, revealing `alpha` and `beta` does not
reveal `k` or `x`.

Now compute:

$$
\alpha x - \beta a + c
$$

Substitute:

$$
\alpha = k + a
$$

and:

$$
\beta = x + b
$$

Then:

$$
\alpha x - \beta a + c
= (k + a)x - (x + b)a + ab
$$

Expand:

$$
(k + a)x - (x + b)a + ab
= kx + ax - xa - ba + ab
$$

Since scalar multiplication commutes:

$$
ax = xa
$$

and:

$$
ba = ab
$$

the masked terms cancel:

$$
kx + ax - xa - ba + ab = kx
$$

So each participant can compute a share:

$$
\sigma_i = \alpha x_i - \beta a_i + c_i
$$

and linearization gives:

$$
\sum_i \lambda_i \sigma_i = kx
$$

## Constructing `R = k^{-1}G`

Cait-Sith also uses a triple:

$$
(k, d, e)
$$

where:

$$
e = kd
$$

The participants can reveal and verify:

$$
e
$$

and use the public point:

$$
D = dG
$$

Then:

$$
R = e^{-1}D
$$

Substitute:

$$
e = kd
$$

and:

$$
D = dG
$$

Then:

$$
R = (kd)^{-1}(dG)
$$

which simplifies to:

$$
R = k^{-1}d^{-1}dG
$$

Therefore:

$$
R = k^{-1}G
$$

This is the same nonce point shape required by ECDSA when:

$$
k = n^{-1}
$$

## Presignature Shape

After presigning, each participant holds:

$$
(R, k_i, \sigma_i)
$$

where:

$$
R = k^{-1}G
$$

and:

$$
k = \sum_i \lambda_i k_i
$$

and:

$$
\sigma = \sum_i \lambda_i \sigma_i = kx
$$

This material is message-independent. That is why it can be generated before
the transaction digest is known.

It is still single-use. If enough presignature shares are exposed, an attacker
can reconstruct:

$$
k
$$

and:

$$
\sigma = kx
$$

Then they can recover:

$$
x = \sigma k^{-1}
$$

## Online Signing

Given a digest:

$$
z
$$

and presignature:

$$
(R, k_i, \sigma_i)
$$

each participant first linearizes its own shares:

$$
k_i' = \lambda_i k_i
$$

and:

$$
\sigma_i' = \lambda_i \sigma_i
$$

Let:

$$
r = \operatorname{xcoord}(R)
$$

Each participant computes:

$$
s_i = z k_i' + r\sigma_i'
$$

The coordinator sums the partial signatures:

$$
s = \sum_i s_i
$$

Expand:

$$
s = \sum_i (z k_i' + r\sigma_i')
$$

Distribute:

$$
s = z\sum_i k_i' + r\sum_i \sigma_i'
$$

Use:

$$
\sum_i k_i' = k
$$

and:

$$
\sum_i \sigma_i' = kx
$$

Then:

$$
s = zk + r(kx)
$$

Factor:

$$
s = k(z + rx)
$$

This is exactly the standard ECDSA signing equation with:

$$
k = n^{-1}
$$

The final signature is:

$$
(r, s)
$$

where:

$$
r = \operatorname{xcoord}(R)
$$

## Rerandomization

NEAR's Cait-Sith variant rerandomizes presignatures before online signing.

Let:

$$
\epsilon
$$

be an optional public key tweak. A tweaked signing key is:

$$
x' = x + \epsilon
$$

and its public key is:

$$
X' = X + \epsilon G
$$

To adapt a presignature from `x` to `x'`, the protocol must adapt:

$$
\sigma = kx
$$

into:

$$
\sigma' = kx'
$$

Substitute:

$$
x' = x + \epsilon
$$

Then:

$$
\sigma' = k(x + \epsilon)
$$

Expand:

$$
\sigma' = kx + k\epsilon
$$

Therefore:

$$
\sigma' = \sigma + \epsilon k
$$

Each party can compute this locally on shares:

$$
\sigma_i' = \sigma_i + \epsilon k_i
$$

NEAR also multiplies through by a public scalar:

$$
\delta
$$

derived from:

$$
\delta = \operatorname{HKDF}(pk, \epsilon, z, R, participants, \rho)
$$

where:

$$
\rho
$$

is fresh public entropy for the signing request.

The rerandomized values are:

$$
R_\delta = \delta R
$$

$$
k_\delta = k\delta^{-1}
$$

$$
\sigma_\delta = (\sigma + \epsilon k)\delta^{-1}
$$

Check the nonce point:

$$
R_\delta = \delta(k^{-1}G)
$$

So:

$$
R_\delta = (k\delta^{-1})^{-1}G
$$

Therefore:

$$
R_\delta = k_\delta^{-1}G
$$

Check the sigma value:

$$
\sigma_\delta
= (\sigma + \epsilon k)\delta^{-1}
$$

Substitute:

$$
\sigma = kx
$$

Then:

$$
\sigma_\delta = (kx + \epsilon k)\delta^{-1}
$$

Factor:

$$
\sigma_\delta = k(x + \epsilon)\delta^{-1}
$$

Use:

$$
k_\delta = k\delta^{-1}
$$

Then:

$$
\sigma_\delta = k_\delta(x + \epsilon)
$$

So:

$$
\sigma_\delta = k_\delta x'
$$

After rerandomization, the presignature still has the same required form:

$$
(R_\delta, k_\delta, \sigma_\delta)
$$

where:

$$
R_\delta = k_\delta^{-1}G
$$

and:

$$
\sigma_\delta = k_\delta x'
$$

## Why Rerandomization Exists

Rerandomization serves two purposes:

1. It adapts a master-key presignature to a public additive tweak:

$$
x' = x + \epsilon
$$

2. It binds the effective presignature to the signing request through:

$$
\delta = \operatorname{HKDF}(pk, \epsilon, z, R, participants, \rho)
$$

This gives defense in depth if a bug, crash, or retry path accidentally serves
the same presignature under different request contexts.

Rerandomization is not a replacement for single-use presignature handling. The
system must still enforce:

$$
\text{one presignature} \rightarrow \text{one signing attempt} \rightarrow \text{burn/delete}
$$

## Our Current Use

Our current signer-core integration calls NEAR's rerandomization API with:

$$
\epsilon = 0
$$

So we use request-bound multiplicative rerandomization:

$$
R_\delta = \delta R
$$

$$
k_\delta = k\delta^{-1}
$$

$$
\sigma_\delta = \sigma\delta^{-1}
$$

The signing equation remains:

$$
s = k_\delta(z + r_\delta x)
$$

where:

$$
r_\delta = \operatorname{xcoord}(R_\delta)
$$

The relayer generates fresh public entropy:

$$
\rho
$$

for each signing session.

## Single-Use Requirement

Every presignature must be treated as burn-after-use.

The intended lifecycle is:

$$
\text{available} \rightarrow \text{reserved} \rightarrow \text{consumed}
$$

or:

$$
\text{available} \rightarrow \text{reserved} \rightarrow \text{burned}
$$

Expired, malformed, mismatched, aborted, or failed presignatures must not return
to:

$$
\text{available}
$$

A bounded tombstone window for used presignature IDs is useful defense in depth,
but the main invariant is that no retry, crash recovery, owner-forwarding path,
or store race can resurrect used or suspect presignature material.

## Local Code References

- `crates/signer-core/src/threshold_ecdsa.rs`
  - computes participant signature shares as `h * k_i + r * sigma_i`
  - finalizes by adding client and relayer shares
  - calls `RerandomizedPresignOutput::rerandomize_presign`
- `crates/signer-core/src/secp256k1.rs`
  - maps additive role-local shares into Cait-Sith backend shares for participants `1`
    and `2`
- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
  - creates per-signing entropy
  - reserves and consumes relayer presignatures
- `client/src/core/signingEngine/threshold/ecdsa/presignPool.ts`
  - stores client presignature shares in memory
  - checks `bigR` consistency with the server

## External References

- [NEAR threshold-signatures repository](https://github.com/near/threshold-signatures)
- [NEAR ECDSA preliminaries](https://github.com/near/threshold-signatures/blob/main/docs/ecdsa/preliminaries.md)
- [Alin Tomescu, Notes on NEAR's MPC](https://alinush.github.io/near)
- [Cait-Sith repository](https://github.com/cronokirby/cait-sith)
