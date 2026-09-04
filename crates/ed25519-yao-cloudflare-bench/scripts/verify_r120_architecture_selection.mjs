import { createHash, createPublicKey, verify as verifyEd25519 } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { pathToFileURL } from 'node:url';

import { r120ApprovalPayloadSha256 } from './evaluate_r120_architecture_selection.mjs';

const MAX_ARTIFACT_BYTES = 32 * 1024 * 1024;
const SIGNATURE_DOMAIN = Buffer.from('seams/r120-threshold-prf-architecture-selection/v1', 'ascii');
const AUTHORITY_KEY_DIGEST_DOMAIN = Buffer.from(
  'seams/r120-threshold-prf-release-authority-key-digest/v1',
  'ascii',
);
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const REVIEWER_ROLE = 'architecture_selection_reviewer';

export class R120SelectionSignatureError extends Error {
  constructor(message) {
    super(message);
    this.name = 'R120SelectionSignatureError';
  }
}

function fail(message) {
  throw new R120SelectionSignatureError(message);
}

function requiredRecord(value, field, requiredKeys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${field} must be an object`);
  }
  if (!isDeepStrictEqual(Object.keys(value).sort(), [...requiredKeys].sort())) {
    fail(`${field} has an invalid field set`);
  }
  return value;
}

function requiredSha256(value, field) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    fail(`${field} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requiredU64(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${field} must be a nonnegative safe integer`);
  }
  return value;
}

function requiredAuthorityId(value, field) {
  if (typeof value !== 'string') {
    fail(`${field} must be a string`);
  }
  const bytes = Buffer.from(value, 'utf8');
  if (
    bytes.length === 0 ||
    bytes.length > 65_535 ||
    bytes.toString('utf8') !== value ||
    /[\0\r\n]/.test(value)
  ) {
    fail(`${field} must be bounded canonical UTF-8 without control separators`);
  }
  return Object.freeze({ value, bytes });
}

function requiredHex(value, bytes, field) {
  if (typeof value !== 'string' || value.length !== bytes * 2 || !/^[0-9a-f]+$/.test(value)) {
    fail(`${field} must be ${bytes} bytes of lowercase hexadecimal`);
  }
  return Buffer.from(value, 'hex');
}

function be64(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

function be16(value) {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16BE(value);
  return bytes;
}

function lp32(value) {
  if (value.length > 0xffff_ffff) {
    fail('R120 authority digest field exceeds LP32 capacity');
  }
  const length = Buffer.alloc(4);
  length.writeUInt32BE(value.length);
  return Buffer.concat([length, value]);
}

export function r120ReleaseAuthorityKeyDigest(authority) {
  const authorityId = requiredAuthorityId(authority.authority_id, 'authority.authority_id');
  const keyEpoch = requiredU64(authority.key_epoch, 'authority.key_epoch');
  const verifyingKey = requiredHex(authority.verifying_key_hex, 32, 'authority.verifying_key_hex');
  return createHash('sha256')
    .update(lp32(AUTHORITY_KEY_DIGEST_DOMAIN))
    .update(lp32(Buffer.from(REVIEWER_ROLE, 'ascii')))
    .update(lp32(authorityId.bytes))
    .update(lp32(be64(keyEpoch)))
    .update(lp32(verifyingKey))
    .digest('hex');
}

function validateCandidate(candidate) {
  requiredRecord(candidate, 'candidate', [
    'schema',
    'decision',
    'reasons',
    'approval_payload',
    'approval_payload_sha256',
    'signature',
  ]);
  if (
    candidate.schema !== 'r120-threshold-prf-architecture-selection-candidate-v1' ||
    candidate.decision !== 'ready-for-release-signature' ||
    !Array.isArray(candidate.reasons) ||
    candidate.reasons.length !== 0
  ) {
    fail('candidate is not ready for a release signature');
  }
  const signature = requiredRecord(candidate.signature, 'candidate.signature', [
    'status',
    'selection_ready',
  ]);
  if (signature.status !== 'required' || signature.selection_ready !== false) {
    fail('candidate has an invalid unsigned-selection state');
  }
  const payload = candidate.approval_payload;
  if (
    payload === null ||
    typeof payload !== 'object' ||
    Array.isArray(payload) ||
    payload.schema !== 'r120-threshold-prf-architecture-approval-payload-v1' ||
    payload.architecture !== 'role-targeted-threshold-prf-preface-v1' ||
    payload.yao_circuit_change !== false
  ) {
    fail('candidate approval payload has an invalid identity');
  }
  const digest = requiredSha256(
    candidate.approval_payload_sha256,
    'candidate.approval_payload_sha256',
  );
  if (r120ApprovalPayloadSha256(payload) !== digest) {
    fail('candidate approval payload digest does not match its evidence');
  }
  return Object.freeze({ payload, digest });
}

function validatePolicy(policy) {
  requiredRecord(policy, 'policy', [
    'schema',
    'policy_scope',
    'minimum_approval_sequence',
    'reviewer',
  ]);
  if (
    policy.schema !== 'r120-threshold-prf-release-authority-policy-v1' ||
    policy.policy_scope !== 'r120_threshold_prf_architecture_selection_v1'
  ) {
    fail('release-authority policy has an invalid identity');
  }
  const minimumSequence = requiredU64(
    policy.minimum_approval_sequence,
    'policy.minimum_approval_sequence',
  );
  const reviewer = requiredRecord(policy.reviewer, 'policy.reviewer', [
    'role',
    'authority_id',
    'key_epoch',
    'verifying_key_hex',
    'authority_key_digest',
  ]);
  if (reviewer.role !== REVIEWER_ROLE) {
    fail('policy.reviewer.role is invalid');
  }
  const authorityId = requiredAuthorityId(reviewer.authority_id, 'policy.reviewer.authority_id');
  const keyEpoch = requiredU64(reviewer.key_epoch, 'policy.reviewer.key_epoch');
  const verifyingKey = requiredHex(
    reviewer.verifying_key_hex,
    32,
    'policy.reviewer.verifying_key_hex',
  );
  const authorityKeyDigest = requiredSha256(
    reviewer.authority_key_digest,
    'policy.reviewer.authority_key_digest',
  );
  if (r120ReleaseAuthorityKeyDigest(reviewer) !== authorityKeyDigest) {
    fail('policy reviewer authority-key digest is invalid');
  }
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, verifyingKey]),
      format: 'der',
      type: 'spki',
    });
  } catch {
    fail('policy reviewer key is not a valid Ed25519 public key');
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    fail('policy reviewer key is not Ed25519');
  }
  return Object.freeze({
    minimumSequence,
    authorityId,
    keyEpoch,
    authorityKeyDigest,
    publicKey,
  });
}

function validateSignedSelection(record, candidate, policy) {
  requiredRecord(record, 'signed_selection', [
    'schema',
    'approval_payload_sha256',
    'approval_sequence',
    'reviewer_authority_id',
    'reviewer_key_epoch',
    'reviewer_authority_key_digest',
    'signature_algorithm',
    'signature_hex',
  ]);
  if (record.schema !== 'r120-threshold-prf-signed-architecture-selection-v1') {
    fail('signed selection has an invalid identity');
  }
  const approvalDigest = requiredSha256(
    record.approval_payload_sha256,
    'signed_selection.approval_payload_sha256',
  );
  const approvalSequence = requiredU64(
    record.approval_sequence,
    'signed_selection.approval_sequence',
  );
  const authorityId = requiredAuthorityId(
    record.reviewer_authority_id,
    'signed_selection.reviewer_authority_id',
  );
  const keyEpoch = requiredU64(record.reviewer_key_epoch, 'signed_selection.reviewer_key_epoch');
  const authorityKeyDigest = requiredSha256(
    record.reviewer_authority_key_digest,
    'signed_selection.reviewer_authority_key_digest',
  );
  const signature = requiredHex(record.signature_hex, 64, 'signed_selection.signature_hex');
  if (record.signature_algorithm !== 'ed25519') {
    fail('signed selection must use Ed25519');
  }
  if (approvalDigest !== candidate.digest) {
    fail('signed selection does not bind the candidate approval payload');
  }
  if (approvalSequence < policy.minimumSequence) {
    fail('signed selection approval sequence is below the rollback floor');
  }
  if (
    authorityId.value !== policy.authorityId.value ||
    keyEpoch !== policy.keyEpoch ||
    authorityKeyDigest !== policy.authorityKeyDigest
  ) {
    fail('signed selection does not match the pinned release authority');
  }
  return Object.freeze({
    approvalDigest,
    approvalSequence,
    authorityId,
    keyEpoch,
    authorityKeyDigest,
    signature,
  });
}

export function r120ArchitectureSelectionSignedBytes(record) {
  const approvalDigest = requiredHex(
    record.approval_payload_sha256,
    32,
    'signed_selection.approval_payload_sha256',
  );
  const approvalSequence = requiredU64(
    record.approval_sequence,
    'signed_selection.approval_sequence',
  );
  const authorityId = requiredAuthorityId(
    record.reviewer_authority_id,
    'signed_selection.reviewer_authority_id',
  );
  const keyEpoch = requiredU64(record.reviewer_key_epoch, 'signed_selection.reviewer_key_epoch');
  const authorityKeyDigest = requiredHex(
    record.reviewer_authority_key_digest,
    32,
    'signed_selection.reviewer_authority_key_digest',
  );
  return Buffer.concat([
    SIGNATURE_DOMAIN,
    Buffer.from([0]),
    approvalDigest,
    be64(approvalSequence),
    be64(keyEpoch),
    be16(authorityId.bytes.length),
    authorityId.bytes,
    authorityKeyDigest,
  ]);
}

function validateArtifact(artifact, field) {
  requiredRecord(artifact, field, ['value', 'sha256']);
  requiredSha256(artifact.sha256, `${field}.sha256`);
  return artifact;
}

export function verifyR120ArchitectureSelection(input) {
  requiredRecord(input, 'verification_input', ['candidate', 'policy', 'signedSelection']);
  const candidateArtifact = validateArtifact(input.candidate, 'candidate_artifact');
  const policyArtifact = validateArtifact(input.policy, 'policy_artifact');
  const signedSelectionArtifact = validateArtifact(
    input.signedSelection,
    'signed_selection_artifact',
  );
  const candidate = validateCandidate(candidateArtifact.value);
  const policy = validatePolicy(policyArtifact.value);
  const signedSelection = validateSignedSelection(signedSelectionArtifact.value, candidate, policy);
  const signedBytes = r120ArchitectureSelectionSignedBytes(signedSelectionArtifact.value);
  if (!verifyEd25519(null, signedBytes, policy.publicKey, signedSelection.signature)) {
    fail('signed selection has an invalid Ed25519 signature');
  }
  return Object.freeze({
    schema: 'r120-threshold-prf-architecture-selection-record-v1',
    selection_ready: true,
    architecture: candidate.payload.architecture,
    yao_circuit_change: candidate.payload.yao_circuit_change,
    approval_payload: candidate.payload,
    approval_payload_sha256: candidate.digest,
    approval_sequence: signedSelection.approvalSequence,
    reviewer_authority_id: signedSelection.authorityId.value,
    reviewer_key_epoch: signedSelection.keyEpoch,
    reviewer_authority_key_digest: signedSelection.authorityKeyDigest,
    signature_algorithm: 'ed25519',
    signature_hex: signedSelectionArtifact.value.signature_hex,
    selection_candidate_sha256: candidateArtifact.sha256,
    release_authority_policy_sha256: policyArtifact.sha256,
    signed_selection_sha256: signedSelectionArtifact.sha256,
  });
}

function artifactPath(environment, name) {
  const path = environment[name];
  if (
    typeof path !== 'string' ||
    !isAbsolute(path) ||
    !path.endsWith('.json') ||
    /[\r\n\0]/.test(path)
  ) {
    fail(`${name} must be an absolute JSON path`);
  }
  return path;
}

function readJsonArtifact(path) {
  let size;
  try {
    size = statSync(path).size;
  } catch {
    fail(`R120 selection artifact is unavailable: ${path}`);
  }
  if (size <= 0 || size > MAX_ARTIFACT_BYTES) {
    fail(`R120 selection artifact has an invalid size: ${path}`);
  }
  let bytes;
  let value;
  try {
    bytes = readFileSync(path);
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(`R120 selection artifact is invalid JSON: ${path}`);
  }
  return Object.freeze({
    value,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  });
}

function main() {
  const result = verifyR120ArchitectureSelection(
    Object.freeze({
      candidate: readJsonArtifact(artifactPath(process.env, 'YAOS_AB_R120_SELECTION_CANDIDATE')),
      policy: readJsonArtifact(artifactPath(process.env, 'YAOS_AB_R120_RELEASE_AUTHORITY_POLICY')),
      signedSelection: readJsonArtifact(artifactPath(process.env, 'YAOS_AB_R120_SIGNED_SELECTION')),
    }),
  );
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

function handleFatal(error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
  try {
    main();
  } catch (error) {
    handleFatal(error);
  }
}
