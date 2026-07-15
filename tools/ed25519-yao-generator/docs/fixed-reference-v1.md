# Ed25519 Yao Fixed Reference V1

Status: **frozen host-reference encodings, arithmetic, contribution KDF,
canonical ceremony context, proof-system-neutral provenance outer bytes,
public semantic-artifact lifecycle bytes, host-only output-custody party views,
and golden corpus commitments**

This specification owns the version-one byte and arithmetic conventions already
implemented by `tools/ed25519-yao-generator`. It is a host-only reference
contract. It does not define a deployed two-party protocol or authorize Router,
Cloudflare Worker, SigningWorker, SDK, or persistence integration.

The keywords **MUST**, **MUST NOT**, and **REQUIRED** are normative.

## 1. Scope and authority

This document freezes:

- the fixed protocol, activation-family, export-family, and output-schema
  identifiers listed in the generated region;
- the immutable application-binding grammar and encoding;
- the stable key-derivation context encoding and binding;
- the role-, source-, and output-separated contribution KDF;
- the clear Ed25519 reference arithmetic and export identity relation;
- the three-layer public ceremony-context digest DAG in
  `docs/ceremony-context-v1.md`;
- the proof-system-neutral role-input provenance outer encodings;
- the exact committed arithmetic, KDF-continuity, ceremony-context, host-only
  lifecycle-continuity, host-only provenance, host-only output-sharing, and
  public semantic-artifact lifecycle and synthetic output-party-view JSON
  corpora identified by canonical byte length and SHA-256.

The generated identifiers and corpus commitments are derived from the
executable host reference and exact canonical corpus builders. Companion-
specification commitments are derived from the exact included document bytes.
The prose outside that region owns the meaning of those bytes. A change to
either side requires an explicit version change or a reviewed update that keeps
the prose, implementation, independent verifier, and committed corpora aligned.

The provenance outer contract treats production root records, commitments,
proofs, transcripts, authorization artifacts, and continuity evidence as
opaque digest slots. This version defines no transport encoding, production
lifecycle artifact construction, proof relation, active-security construction,
circuit gate schedule, or circuit wire layout.

## 2. Primitive conventions

`LP32(x)` is `BE32(byte_length(x)) || x`. Concatenation is written `||`.
Fixed-width integers use the byte order stated at their field. Hex in the
generated region is lowercase and contains no prefix or separators.

`y` values are 32-byte little-endian integers in `Z_(2^256)`. Addition discards
the carry beyond byte 31. Scalar values are canonical 32-byte little-endian
representatives in `Z_l`, where `l` is the generated Ed25519 scalar order.
Scalar decoders MUST reject encodings greater than or equal to `l`.

RFC 8032 pruning of a 32-byte SHA-512 lower half is:

```text
bytes[0]  = bytes[0]  & 0xf8
bytes[31] = bytes[31] & 0x3f
bytes[31] = bytes[31] | 0x40
```

The generated zero and all-ones clamp fixtures bind these masks to the
executable helper.

## 3. Immutable application binding

The application-binding facts are exactly:

1. `walletId`;
2. `nearEd25519SigningKeyId`;
3. `signingRootId`;
4. positive `keyCreationSignerSlot`.

Each string MUST contain one or more visible ASCII bytes in `0x21..=0x7e`.
There is no trimming, normalization, or alternate Unicode representation. The
slot is a positive unsigned 32-bit integer.

```text
Ed25519YaoApplicationBindingV1 =
    LP32(application_binding_domain)
    || LP32(wallet_id_label)
    || LP32(UTF8(walletId))
    || LP32(signing_key_id_label)
    || LP32(UTF8(nearEd25519SigningKeyId))
    || LP32(signing_root_id_label)
    || LP32(UTF8(signingRootId))
    || LP32(key_creation_signer_slot_label)
    || LP32(BE32(keyCreationSignerSlot))

application_binding_digest = SHA-256(Ed25519YaoApplicationBindingV1)
```

No mutable lifecycle, authorization, deployment, credential, recipient, or
epoch value enters this binding.

## 4. Stable key-derivation context

The two participant identifiers are nonzero, distinct unsigned 16-bit integers.
The encoder sorts them in ascending order.

```text
participant_low  = min(participant_id_1, participant_id_2)
participant_high = max(participant_id_1, participant_id_2)

StableKeyDerivationContextV1 =
    stable_context_domain
    || application_binding_digest[32]
    || BE16(participant_low)
    || BE16(participant_high)

StableKeyDerivationContextBindingV1 =
    SHA-256(stable_context_binding_domain || StableKeyDerivationContextV1)
```

## 5. Contribution KDF

The contribution KDF is HKDF-SHA256. Every derivation root is exactly 32 bytes.
The generated role, source, and output tags are fixed and mutually interpreted
only within their own tag position.

```text
PRK = HKDF-Extract-SHA256(contribution_kdf_extract_salt, root[32])

info = contribution_kdf_expand_domain
       || 0x00
       || role_tag
       || source_tag
       || output_tag
       || StableKeyDerivationContextBindingV1[32]

y = HKDF-Expand-SHA256(PRK, info(output=y), 32)
tau_wide = HKDF-Expand-SHA256(PRK, info(output=tau), 64)
tau = LE512(tau_wide) mod l, encoded as canonical LE32
```

One synthetic client root derives the client/A and client/B rows. Independent
synthetic Deriver A and Deriver B roots derive only their own server rows. The
eight generated rows commit the exact expand-info bytes and canonical output.
The roots and outputs are public test material only.

## 6. Clear reference arithmetic

```text
y_A = y_client_A + y_server_A mod 2^256
y_B = y_client_B + y_server_B mod 2^256
d   = LE32(y_A + y_B mod 2^256)
h   = SHA-512(d)
a   = LE256(clamp(h[0..32])) mod l

tau_A = tau_client_A + tau_server_A mod l
tau_B = tau_client_B + tau_server_B mod l
tau   = tau_A + tau_B mod l

x_client_base = a + tau mod l
x_server_base = a + 2 * tau mod l
X_client      = [x_client_base]B
X_server      = [x_server_base]B
A_pub         = [a]B
```

Every canonical case MUST satisfy `2 * X_client - X_server = A_pub`. Export
returns exactly `d`; standard RFC 8032 public-key derivation from that seed MUST
reproduce `A_pub`. A non-export output never contains `d`.

## 7. Canonical corpus encoding

Each committed JSON corpus is the UTF-8 output of `serde_json::to_string_pretty`
for its strict version-one schema, followed by exactly one LF. Object field
order follows the declared version-one Rust structures. Unknown fields and
invalid tagged-union shapes are rejected.

The files listed in the generated region are normative attachments to this
specification. Their byte length and SHA-256 are computed from the canonical
builders, rather than by hashing unchecked repository files.

## 8. Generated goldens

The following region MUST occur exactly once. Its markers occupy standalone LF
lines. The file ends with exactly one LF.

<!-- prettier-ignore-start -->
<!-- BEGIN GENERATED: ED25519_YAO_FIXED_REFERENCE_V1 -->
Generated schema: `seams:router-ab:ed25519-yao:fixed-reference-goldens:v1`

### Fixed identifiers

| Identifier | UTF-8 value | Byte length | Hex |
| --- | --- | ---: | --- |
| protocol | `router_ab_ed25519_yao_v1` | 24 | `726f757465725f61625f656432353531395f79616f5f7631` |
| activation circuit family | `ed25519_yao_activation_v1` | 25 | `656432353531395f79616f5f61637469766174696f6e5f7631` |
| export circuit family | `ed25519_yao_export_v1` | 21 | `656432353531395f79616f5f6578706f72745f7631` |
| activation output schema | `ed25519_yao_activation_output_schema_v1` | 39 | `656432353531395f79616f5f61637469766174696f6e5f6f75747075745f736368656d615f7631` |
| export output schema | `ed25519_yao_export_output_schema_v1` | 35 | `656432353531395f79616f5f6578706f72745f6f75747075745f736368656d615f7631` |

### Domains and labels

| Constant | Byte length | Hex |
| --- | ---: | --- |
| application binding domain | 50 | `7365616d732f726f757465722d61622f656432353531392d79616f2f6170706c69636174696f6e2d62696e64696e672f7631` |
| wallet ID label | 8 | `77616c6c65744964` |
| signing-key ID label | 23 | `6e656172456432353531395369676e696e674b65794964` |
| signing-root ID label | 13 | `7369676e696e67526f6f744964` |
| key-creation signer-slot label | 21 | `6b65794372656174696f6e5369676e6572536c6f74` |
| stable context domain | 49 | `7365616d732f726f757465722d61622f656432353531392d79616f2f737461626c652d6b65792d636f6e746578742f7631` |
| stable context binding domain | 57 | `7365616d732f726f757465722d61622f656432353531392d79616f2f737461626c652d6b65792d636f6e746578742d62696e64696e672f7631` |
| contribution KDF extract salt | 67 | `7365616d732f726f757465722d61622f656432353531392d79616f2f636f6e747269627574696f6e2d6b64662f686b64662d7368613235362f657874726163742f7631` |
| contribution KDF expand domain | 66 | `7365616d732f726f757465722d61622f656432353531392d79616f2f636f6e747269627574696f6e2d6b64662f686b64662d7368613235362f657870616e642f7631` |

### Arithmetic constants and fixtures

- Scalar order `l`, canonical LE32: `edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010`
- Compressed Ed25519 basepoint: `5866666666666666666666666666666666666666666666666666666666666666`
- `clamp_rfc8032(00 * 32)`: `0000000000000000000000000000000000000000000000000000000000000040`
- `clamp_rfc8032(ff * 32)`: `f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f`
- Contribution expand-info byte length: `102`

### Application-binding and stable-context golden

- Wallet ID: `wallet-fixture`
- NEAR Ed25519 signing-key ID: `ed25519ks_fixture`
- Signing-root ID: `project-fixture:env-fixture`
- Key-creation signer slot: `1`
- Application-binding bytes: `000000327365616d732f726f757465722d61622f656432353531392d79616f2f6170706c69636174696f6e2d62696e64696e672f76310000000877616c6c657449640000000e77616c6c65742d66697874757265000000176e656172456432353531395369676e696e674b6579496400000011656432353531396b735f666978747572650000000d7369676e696e67526f6f7449640000001b70726f6a6563742d666978747572653a656e762d66697874757265000000156b65794372656174696f6e5369676e6572536c6f740000000400000001`
- Application-binding SHA-256: `b1dbafce5fd696ae4bd5611e3684a778febfdf7f716e2dfe3211ce0cff708121`
- Participant IDs: `[1, 2]`
- Stable-context bytes: `7365616d732f726f757465722d61622f656432353531392d79616f2f737461626c652d6b65792d636f6e746578742f7631b1dbafce5fd696ae4bd5611e3684a778febfdf7f716e2dfe3211ce0cff70812100010002`
- Stable-context binding SHA-256: `b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655`
- `0x42 * 32`, participants `[1, 2]`, stable-context bytes: `7365616d732f726f757465722d61622f656432353531392d79616f2f737461626c652d6b65792d636f6e746578742f7631424242424242424242424242424242424242424242424242424242424242424200010002`
- `0x42 * 32`, participants `[1, 2]`, binding SHA-256: `ce5305908b0c31bfe09072b549cb349b0c901f7d3fde60c63fa8e2dfb088a42d`

### Contribution KDF golden

Synthetic roots: client=`1111111111111111111111111111111111111111111111111111111111111111`, Deriver A=`2222222222222222222222222222222222222222222222222222222222222222`, Deriver B=`3333333333333333333333333333333333333333333333333333333333333333`.

| Role | Role tag | Source | Source tag | Output | Output tag | Expand info hex | Canonical output hex |
| --- | ---: | --- | ---: | --- | ---: | --- | --- |
| A | `0x01` | client | `0x01` | y | `0x01` | `7365616d732f726f757465722d61622f656432353531392d79616f2f636f6e747269627574696f6e2d6b64662f686b64662d7368613235362f657870616e642f763100010101b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655` | `8c667b5043a1f3e59821d2253c010c83a26b9f3426bb8295cd39ad2782425c10` |
| A | `0x01` | client | `0x01` | tau | `0x02` | `7365616d732f726f757465722d61622f656432353531392d79616f2f636f6e747269627574696f6e2d6b64662f686b64662d7368613235362f657870616e642f763100010102b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655` | `389a362ee32913daaf80b9d8e35c97ca1fa02b7e10e986960331a1d027ccc205` |
| B | `0x02` | client | `0x01` | y | `0x01` | `7365616d732f726f757465722d61622f656432353531392d79616f2f636f6e747269627574696f6e2d6b64662f686b64662d7368613235362f657870616e642f763100020101b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655` | `edf3deaa4f175aaede186013471bc3bb9a868853b3c9f3332a0b55aa72423550` |
| B | `0x02` | client | `0x01` | tau | `0x02` | `7365616d732f726f757465722d61622f656432353531392d79616f2f636f6e747269627574696f6e2d6b64662f686b64662d7368613235362f657870616e642f763100020102b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655` | `667ec12757d3220783ed081d4bd69e494693ae9bcf56d05f5e825f0f003d5a03` |
| A | `0x01` | server | `0x02` | y | `0x01` | `7365616d732f726f757465722d61622f656432353531392d79616f2f636f6e747269627574696f6e2d6b64662f686b64662d7368613235362f657870616e642f763100010201b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655` | `6055ecaf750422a7f04b112d9fe584947c2f6538a39247b15c4b5425059365d9` |
| A | `0x01` | server | `0x02` | tau | `0x02` | `7365616d732f726f757465722d61622f656432353531392d79616f2f636f6e747269627574696f6e2d6b64662f686b64662d7368613235362f657870616e642f763100010202b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655` | `cf2ea34b870e9c78e98afe6c7f0bfd7210884c4a788dbee39e3b63e7b327b607` |
| B | `0x02` | server | `0x02` | y | `0x01` | `7365616d732f726f757465722d61622f656432353531392d79616f2f636f6e747269627574696f6e2d6b64662f686b64662d7368613235362f657870616e642f763100020201b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655` | `ed2b1b79ee4139a7a6408b0e50d5fe3c1c26796b87bd7f18bd2284bfd933e8a2` |
| B | `0x02` | server | `0x02` | tau | `0x02` | `7365616d732f726f757465722d61622f656432353531392d79616f2f636f6e747269627574696f6e2d6b64662f686b64662d7368613235362f657870616e642f763100020202b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655` | `8ec75518784e99df254b0c996f811576b0fa71d970b29cd48640df39886e380c` |

Joined seed: `c6db6124f7fea8e20ec7ce7472d75210d647062c04d53d9311b3dab6d34bdfdc`.
Ed25519 public key: `ccd255d0b88721771947038f1a7c29b49eee3902d6aa732e5e448251537bf077`.

### Normative companion specification commitments

| Repository-relative path | Bytes | SHA-256 |
| --- | ---: | --- |
| `docs/output-sharing-v1.md` | 7716 | `5035da5d3669bf9a310bb4fa4299ad9eaf8ded700f5805f40f1b0893f716f5e3` |
| `docs/circuit-ir-v1.md` | 35777 | `7124434078de370c9a31bd33efd14a8a6df15478934a8f1bba5ddc39ac73dbdd` |
| `docs/ceremony-context-v1.md` | 8082 | `46f8cbec72b105a92a1257c267b672820e8eff4a6b12d7aa07075fd0a6f948c8` |
| `docs/input-provenance-v1.md` | 55505 | `8d7a36f33c22019551591ded3e21316d469f79a6ca339fc2176a22d595e79c57` |
| `docs/semantic-artifact-lifecycle-v1.md` | 17384 | `ebb6acb308d7a56fa02d673cdf1acb1a466bb67f215ec4f20581320e8c55fe61` |
| `docs/output-party-views-v1.md` | 38990 | `d6ed4dc130f4f6adb4e13235f16310e9e8b5e6e505647d9a236cf78240528764` |
| `docs/evaluation-input-party-views-v1.md` | 42549 | `846cbc27617be1e701f021c9d52268e818fed26dac5c6dfe6e65e7b8fdc231f7` |
| `docs/uniform-abort-envelope-v1.md` | 5305 | `11f5808b6ad1432e242b69de9859753bfbda8fac194ac61e7e38e156546a88bc` |
| `docs/evaluator-abort-state-party-views-v1.md` | 5782 | `70ae211b75295e33856d614ff6e2465c14cd17fe5c51316445118db55788d55a` |
| `docs/authenticated-store-resolution-v1.md` | 7253 | `2c1999c2519c011c10ad0b187d78c4f51528931f0dd493247de0a8d162a97267` |
| `docs/signing-worker-activation-v1.md` | 8358 | `af154c8deb162cf45f919f33c6dbddb62a2f985eacde1765b8be9420ef9ffd50` |
| `docs/refresh-promotion-v1.md` | 4142 | `3c75567e45267cb79f87214eae622183498ffa1f2f8c8ecf1f0b114184ab290b` |
| `docs/benchmark-manifest-v1.md` | 5162 | `8ab45bef81a1fe9ab1f2df5acbb10365f607fdc2eb447c5e5f20db590766fcfa` |
| `docs/artifact-filesystem-policy-v1.md` | 4507 | `1c2d8c6765a9df076fb1fe62450934ce764d0b31e4b8fb94dc60223107e9b27d` |
| `docs/joint-refresh-delta-v1.md` | 4984 | `d37dea6f3a8c4b5eebae4e497e19d936019ae12ee2ff2b2491d9280940313efd` |
| `docs/export-delivery-lifecycle-v1.md` | 6885 | `a8ba5905102bdf25ae8bfa04b0067073a05197d0d023c1bc849a8e320490e41c` |
| `docs/activation-delivery-lifecycle-v1.md` | 3880 | `f0714698b5b8ca2cf1aedc711aa97c1f7e27ac0efa2f2c7b8f7d7e58fe4f1c23` |
| `docs/activation-recipient-party-views-v1.md` | 8371 | `aa1d1e4c0d9a2564c0ba5729a7af67404de0bdde7e2bdad24cb4d9bd4c3e5e4c` |
| `docs/recovery-credential-transition-v1.md` | 9583 | `f36b173807f31accd8d2321be29f7a9829ff812c64569f84d500d943ffeb61c0` |
| `docs/export-evaluator-authorization-v1.md` | 7715 | `812c168a15ea5bd0423da598b33ba2374d2d6fc3391fb71a44a93a912a684ce5` |
| `docs/registration-evaluator-admission-v1.md` | 9883 | `42e3872538c30b82f271774194f89258a088b89e84b6f021e477990e3e1c29dc` |
| `docs/recovery-evaluator-admission-v1.md` | 10236 | `797ddbd57c0712250fe6f7cc900c7ed803c50203dcc4f9fffdb24dbc39e47e51` |
| `docs/refresh-evaluator-admission-v1.md` | 14554 | `333714a6990fcc77a187c62d18d2a32db1174360233be7e5e7d77d04cd3de664` |
| `docs/semantic-frame-party-views-v1.md` | 31603 | `21ada5d4dd3789b870a646797010fec8ecf242247b45156b349cafcbf85e7168` |
| `docs/phase2b-core-reconciliation-v1.md` | 32091 | `71ff72963c8119487847fabb5b0c354eadf80a7b1ebe0c5adbc73917c868cbd1` |

### Canonical corpus commitments

| Repository-relative path | Schema | Cases | Bytes | SHA-256 |
| --- | --- | ---: | ---: | --- |
| `vectors/ed25519-yao-v1.json` | `seams:router-ab:ed25519-yao:vectors:v1` | 5 | 14826 | `13934b86ed57e6634c2a3d8ff1361923e9caf28c2aad160251d0b2af779a7e36` |
| `vectors/ed25519-yao-kdf-v1.json` | `seams:router-ab:ed25519-yao:kdf-continuity-vectors:v1` | 1 | 4036 | `9b2c99469aaf09c1f63318315bd7c5e359039548365e62d11424e5875bceb469` |
| `vectors/ed25519-yao-ceremony-context-v1.json` | `seams:router-ab:ed25519-yao:ceremony-context-vectors:v1` | 5 | 31447 | `82c6c085f4b5d3b8e9b04e288aa3576763676e90f12fda5644de20dd89f2ee26` |
| `vectors/ed25519-yao-lifecycle-continuity-v1.json` | `seams:router-ab:ed25519-yao:lifecycle-continuity-vectors:v1` | 6 | 39978 | `c115e81252345985fffd5b6b544d601c5a751b657aca4d1740c27f2f59fc32cd` |
| `vectors/ed25519-yao-provenance-v1.json` | `seams:router-ab:ed25519-yao:role-input-provenance-vectors:v1` | 4 | 50672 | `8a39d15ddb384fa32111815614a30246e167ec1861d215b89c681e364318d4ba` |
| `vectors/ed25519-yao-output-sharing-v1.json` | `seams:router-ab:ed25519-yao:output-sharing-vectors:v1` | 6 | 11643 | `c3b340c7f8e181ae38aabb654db7cf6631a11ef634b29e9c46c68c5af6d21965` |
| `vectors/ed25519-yao-semantic-lifecycle-v1.json` | `seams:router-ab:ed25519-yao:semantic-artifact-lifecycle-vectors:v1` | 5 | 96134 | `758ae82455c6847e04d1b2ad56bc231f6a6a4f44522a9a6d20401a789ef1ca6f` |
| `vectors/ed25519-yao-output-party-views-v1.json` | `seams:router-ab:ed25519-yao:output-party-views-vectors:v1` | 5 | 36950 | `5aa0c4cbde69125a995c89598dffac41d0924a9cfc05c64af41ccad289c0f9ae` |
| `vectors/ed25519-yao-evaluation-input-party-views-v1.json` | `seams:router-ab:ed25519-yao:evaluation-input-party-views-vectors:v1` | 5 | 20929 | `da76dfe6e93be9e2dfe4ebfd1c6f7e269a05cd69732c302b8573126f85409f80` |
| `vectors/ed25519-yao-uniform-abort-envelope-v1.json` | `seams:router-ab:ed25519-yao:uniform-abort-envelope-vectors:v1` | 5 | 1965 | `bf71321d0896c3a6591b0a0f2f57db9a01994209bfcf12dd1ec905e9d6599df0` |
| `vectors/ed25519-yao-evaluator-abort-state-party-views-v1.json` | `seams:router-ab:ed25519-yao:evaluator-abort-state-party-views:v1` | 4 | 11508 | `9aa77f2cf1b7f74145789bde79d71b53da3c967081d26e609a95f8829a35ed37` |
| `vectors/ed25519-yao-export-delivery-v1.json` | `seams:router-ab:ed25519-yao:export-delivery-vectors:v1` | 1 | 5856 | `4fae90165fde33a2642eca0704bbe4ebcf126141a8a7d02d410676a0b3cdbe71` |
| `vectors/ed25519-yao-activation-delivery-v1.json` | `seams:router-ab:ed25519-yao:activation-delivery-vectors:v1` | 3 | 23164 | `8a27dfff5b56be062241667026c0c7cc69ae3d1a395a08a87728afc031df1ccb` |
| `vectors/ed25519-yao-activation-recipient-party-views-v1.json` | `seams:router-ab:ed25519-yao:activation-recipient-party-views:v1` | 3 | 17058 | `27500219743d5f103f7d39a2af80ac8ab897a93e0a9c373291666e2f2429d420` |
| `vectors/ed25519-yao-recovery-credential-transition-v1.json` | `seams:router-ab:ed25519-yao:recovery-credential-transition-vectors:v1` | 1 | 7228 | `5293dde1a79a1ceea5fc48e2fe6ff71126c2cd56faec43374e8f087b23ce78b2` |
| `vectors/ed25519-yao-export-evaluator-authorization-v1.json` | `seams:router-ab:ed25519-yao:export-evaluator-authorization-vectors:v1` | 1 | 9805 | `b9059e1d931227863375afd20af009b056e7b9daa976206236cb307dfe920702` |
| `vectors/ed25519-yao-registration-evaluator-admission-v1.json` | `seams:router-ab:ed25519-yao:registration-evaluator-admission-vectors:v1` | 1 | 13763 | `ceab8a1b60963313716fc6493bf18736f385362e4a04b479bd78005672b6e7d5` |
| `vectors/ed25519-yao-recovery-evaluator-admission-v1.json` | `seams:router-ab:ed25519-yao:recovery-evaluator-admission-vectors:v1` | 1 | 13727 | `2555067e3a8bbe0b5242aa370a6db650586ab2da533767dcdc53db8b3afdf19f` |
| `vectors/ed25519-yao-refresh-evaluator-admission-v1.json` | `seams:router-ab:ed25519-yao:refresh-evaluator-admission-vectors:v1` | 1 | 15627 | `9d5327e9a9623fc101be48f414025d9f6fc108542a72b7126b1ed740b2e0c77a` |
| `vectors/ed25519-yao-semantic-frame-party-views-v1.json` | `seams:router-ab:ed25519-yao:semantic-frame-party-views:v1` | 8 | 249622 | `3dc6d30e9c48b3ff55513bc254193e7ad1c1756b42b4a999773adfa6b89a45e9` |
| `vectors/ed25519-yao-phase2b-core-reconciliation-v1.json` | `seams:router-ab:ed25519-yao:phase2b-core-reconciliation:v1` | 5 | 20840 | `1442406f3fb7e844724a908b511eee9b68fffde7fde89ae09e0829783874ffea` |

<!-- END GENERATED: ED25519_YAO_FIXED_REFERENCE_V1 -->
<!-- prettier-ignore-end -->
