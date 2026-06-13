# Vector Format

The initial fixture format is `router_ab_split_derivation_candidates_v1`.

Required fields:

- `case_id`
- `candidate_id`
- `request_kind`
- `correctness_level`
- `network_id`
- `account_id`
- `account_public_key`
- `root_share_epoch`
- `ceremony_id`
- `expected_context_digest_hex`
- `expected_transcript_digest_hex`

Digest fields are committed lowercase hex values. The fixture parser derives
the canonical context and local transcript for each case and rejects mismatches.

## Future Cases

The vector corpus should include:

- registration success for both candidates
- export success for both candidates
- refresh success for both candidates
- deriver identity mismatch
- root epoch mismatch
- transcript replay with a changed ceremony id
- swapped A/B deriver identity
- malformed public key
- malformed digest
- Minimum Level C output acceptance
- public-share-binding output acceptance
