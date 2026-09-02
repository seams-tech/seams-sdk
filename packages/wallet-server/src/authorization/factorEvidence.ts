import {
  AUTHORIZATION_EVIDENCE_KINDS,
  isAuthorizationEvidenceKind,
  parseCapabilityOperationRef,
  parseAuthorizationEvidenceId,
  parseAuthorizationEvidenceSetId,
  parsePrincipalId,
  parseTenantId,
  type AuthFactorId,
  type AuthorizationParseResult,
  type CapabilityOperationRef,
  type AuthorizationEvidenceId,
  type AuthorizationEvidenceSetId,
  type PrincipalId,
  type TenantId,
} from '@shared/authorization/capabilityKinds';
import {
  computeCapabilityOperationFingerprintDigest,
  type CapabilityOperationEnvelope,
} from '@shared/authorization/operationFingerprint';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseWalletId,
  parseProviderSubject,
  type EmailOtpChallengeId,
  type WalletId,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type {
  OwnerOperationBinding,
  SessionOrigin,
  VerifiedOwnerProofFields,
  VerifiedAuthorizationEvidence,
  VerifiedOwnerProofId,
  VerifiedOwnerProofMethod,
} from './domain';
import { parseSessionOrigin } from './domain';

const FACTOR_EVIDENCE_DIGEST_DOMAIN_V1 = 'seams:authorization:factor-evidence:v1';
const EVIDENCE_SET_DIGEST_DOMAIN_V1 = 'seams:authorization:evidence-set:v1';

type VerifiedWalletOperationEvidenceSetFields = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authorityRef: WalletAuthAuthorityRef;
  readonly requestOrigin: SessionOrigin;
  readonly audience: SessionOrigin;
  readonly evidenceSetId: AuthorizationEvidenceSetId;
  readonly evidence: readonly [VerifiedAuthorizationEvidence, ...VerifiedAuthorizationEvidence[]];
  readonly evidenceSetDigest: DigestB64u;
  readonly operation: CapabilityOperationRef;
  readonly laneDigest: DigestB64u;
  readonly intentDigest: DigestB64u;
  readonly displayDigest: DigestB64u;
  readonly assurance: 'step_up';
  readonly verifiedAtMs: number;
  readonly expiresAtMs: number;
};

class VerifiedWalletOperationEvidenceSetProof {
  readonly kind = 'verified_wallet_operation_evidence_set' as const;
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authorityRef: WalletAuthAuthorityRef;
  readonly requestOrigin: SessionOrigin;
  readonly audience: SessionOrigin;
  readonly evidenceSetId: AuthorizationEvidenceSetId;
  readonly evidence: readonly [VerifiedAuthorizationEvidence, ...VerifiedAuthorizationEvidence[]];
  readonly evidenceSetDigest: DigestB64u;
  readonly operation: CapabilityOperationRef;
  readonly laneDigest: DigestB64u;
  readonly intentDigest: DigestB64u;
  readonly displayDigest: DigestB64u;
  readonly assurance = 'step_up' as const;
  readonly verifiedAtMs: number;
  readonly expiresAtMs: number;

  private retainVerifiedEvidenceProof(): true {
    return true;
  }

  constructor(fields: VerifiedWalletOperationEvidenceSetFields) {
    void this.retainVerifiedEvidenceProof();
    requireWalletOperationEvidenceSetFields(fields);
    this.tenantId = fields.tenantId;
    this.principalId = fields.principalId;
    this.walletId = fields.walletId;
    this.authorityRef = fields.authorityRef;
    this.requestOrigin = fields.requestOrigin;
    this.audience = fields.audience;
    this.evidenceSetId = fields.evidenceSetId;
    this.evidence = fields.evidence;
    this.evidenceSetDigest = fields.evidenceSetDigest;
    this.operation = fields.operation;
    this.laneDigest = fields.laneDigest;
    this.intentDigest = fields.intentDigest;
    this.displayDigest = fields.displayDigest;
    this.verifiedAtMs = fields.verifiedAtMs;
    this.expiresAtMs = fields.expiresAtMs;
  }
}

export type VerifiedAuthorizationEvidenceSet = VerifiedWalletOperationEvidenceSetProof;

type VerifiedWalletOperationFactorBinding = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authorityRef: WalletAuthAuthorityRef;
  readonly requestOrigin: SessionOrigin;
  readonly audience: SessionOrigin;
  readonly factorId: AuthFactorId;
  readonly operation: CapabilityOperationEnvelope;
  readonly verifiedAtMs: number;
  readonly expiresAtMs: number;
};

export type VerifiedWalletOperationPasskeyFactorResult = VerifiedWalletOperationFactorBinding & {
  readonly kind: 'verified_wallet_operation_passkey_factor';
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly assertionDigest: DigestB64u;
};

export type VerifiedWalletOperationEmailOtpFactorResult = VerifiedWalletOperationFactorBinding & {
  readonly kind: 'verified_wallet_operation_email_otp_factor';
  readonly challengeId: EmailOtpChallengeId;
  readonly verificationReceiptDigest: DigestB64u;
};

export type VerifiedWalletOperationFactorResult =
  | VerifiedWalletOperationPasskeyFactorResult
  | VerifiedWalletOperationEmailOtpFactorResult;

type VerifiedWalletSessionFactorBinding = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authorityRef: WalletAuthAuthorityRef;
  readonly requestOrigin: SessionOrigin;
  readonly audience: SessionOrigin;
  readonly factorId: AuthFactorId;
  readonly verifiedAtMs: number;
  readonly expiresAtMs: number;
};

export type VerifiedWalletSessionPasskeyFactorResult =
  VerifiedWalletSessionFactorBinding & {
    readonly kind: 'verified_wallet_session_passkey_factor';
    readonly credentialIdB64u: WebAuthnCredentialIdB64u;
    readonly assertionDigest: DigestB64u;
  };

export type VerifiedWalletSessionEmailOtpFactorResult =
  VerifiedWalletSessionFactorBinding & {
    readonly kind: 'verified_wallet_session_email_otp_factor';
    readonly challengeId: EmailOtpChallengeId;
    readonly verificationReceiptDigest: DigestB64u;
  };

export type VerifiedWalletSessionFactorResult =
  | VerifiedWalletSessionPasskeyFactorResult
  | VerifiedWalletSessionEmailOtpFactorResult;

export type VerifiedWalletOperationFactorEvidenceSetInput = {
  readonly operation: CapabilityOperationEnvelope;
  readonly evidenceId: AuthorizationEvidenceId;
  readonly evidenceSetId: AuthorizationEvidenceSetId;
  readonly factor: VerifiedWalletOperationFactorResult;
};

export type VerifiedOwnerProofInput =
  | {
      readonly purpose: 'wallet_session';
      readonly proofId: VerifiedOwnerProofId;
      readonly factor: VerifiedWalletSessionFactorResult;
    }
  | {
      readonly purpose: 'operation';
      readonly proofId: VerifiedOwnerProofId;
      readonly factor: VerifiedWalletOperationFactorResult;
    };

export function buildVerifiedWalletOperationPasskeyFactorResult(
  fields: Omit<VerifiedWalletOperationPasskeyFactorResult, 'kind'>,
): VerifiedWalletOperationPasskeyFactorResult {
  requireVerificationWindow(fields.verifiedAtMs, fields.expiresAtMs);
  return { kind: 'verified_wallet_operation_passkey_factor', ...fields };
}

export function buildVerifiedWalletOperationEmailOtpFactorResult(
  fields: Omit<VerifiedWalletOperationEmailOtpFactorResult, 'kind'>,
): VerifiedWalletOperationEmailOtpFactorResult {
  requireVerificationWindow(fields.verifiedAtMs, fields.expiresAtMs);
  return { kind: 'verified_wallet_operation_email_otp_factor', ...fields };
}

export function buildVerifiedWalletSessionPasskeyFactorResult(
  fields: Omit<VerifiedWalletSessionPasskeyFactorResult, 'kind'>,
): VerifiedWalletSessionPasskeyFactorResult {
  requireVerificationWindow(fields.verifiedAtMs, fields.expiresAtMs);
  return {
    kind: 'verified_wallet_session_passkey_factor',
    tenantId: fields.tenantId,
    principalId: fields.principalId,
    walletId: fields.walletId,
    authorityRef: fields.authorityRef,
    requestOrigin: fields.requestOrigin,
    audience: fields.audience,
    factorId: fields.factorId,
    credentialIdB64u: fields.credentialIdB64u,
    assertionDigest: fields.assertionDigest,
    verifiedAtMs: fields.verifiedAtMs,
    expiresAtMs: fields.expiresAtMs,
  };
}

export function buildVerifiedWalletSessionEmailOtpFactorResult(
  fields: Omit<VerifiedWalletSessionEmailOtpFactorResult, 'kind'>,
): VerifiedWalletSessionEmailOtpFactorResult {
  requireVerificationWindow(fields.verifiedAtMs, fields.expiresAtMs);
  return {
    kind: 'verified_wallet_session_email_otp_factor',
    tenantId: fields.tenantId,
    principalId: fields.principalId,
    walletId: fields.walletId,
    authorityRef: fields.authorityRef,
    requestOrigin: fields.requestOrigin,
    audience: fields.audience,
    factorId: fields.factorId,
    challengeId: fields.challengeId,
    verificationReceiptDigest: fields.verificationReceiptDigest,
    verifiedAtMs: fields.verifiedAtMs,
    expiresAtMs: fields.expiresAtMs,
  };
}

/** Nominal server-only owner proofs; private constructors block browser forgery. */
class VerifiedOwnerWalletSessionProof {
  private readonly __proofBrand = true;
  readonly kind = 'verified_owner_proof_v1' as const;
  readonly proofId: VerifiedOwnerProofId;
  readonly method: VerifiedOwnerProofMethod;
  readonly authSource: VerifiedOwnerProofFields['authSource'];
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authority: WalletAuthAuthorityRef;
  readonly origin: SessionOrigin;
  readonly audience: SessionOrigin;
  readonly replayIdentity: string;
  readonly verifiedAtMs: number;
  readonly expiresAtMs: number;
  readonly purpose = 'wallet_session' as const;
  readonly operation?: never;

  constructor(fields: Extract<VerifiedOwnerProofFields, { readonly purpose: 'wallet_session' }>) {
    requireOwnerProofFields(fields);
    this.proofId = fields.proofId;
    this.method = fields.method;
    this.authSource = fields.authSource;
    this.tenantId = fields.tenantId;
    this.principalId = fields.principalId;
    this.walletId = fields.walletId;
    this.authority = fields.authority;
    this.origin = fields.origin;
    this.audience = fields.audience;
    this.replayIdentity = fields.replayIdentity;
    this.verifiedAtMs = fields.verifiedAtMs;
    this.expiresAtMs = fields.expiresAtMs;
  }
}

class VerifiedOwnerOperationProof {
  private readonly __proofBrand = true;
  readonly kind = 'verified_owner_proof_v1' as const;
  readonly proofId: VerifiedOwnerProofId;
  readonly method: VerifiedOwnerProofMethod;
  readonly authSource: VerifiedOwnerProofFields['authSource'];
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authority: WalletAuthAuthorityRef;
  readonly origin: SessionOrigin;
  readonly audience: SessionOrigin;
  readonly replayIdentity: string;
  readonly verifiedAtMs: number;
  readonly expiresAtMs: number;
  readonly purpose = 'operation' as const;
  readonly operation: OwnerOperationBinding;

  constructor(fields: Extract<VerifiedOwnerProofFields, { readonly purpose: 'operation' }>) {
    requireOwnerProofFields(fields);
    this.proofId = fields.proofId;
    this.method = fields.method;
    this.authSource = fields.authSource;
    this.tenantId = fields.tenantId;
    this.principalId = fields.principalId;
    this.walletId = fields.walletId;
    this.authority = fields.authority;
    this.origin = fields.origin;
    this.audience = fields.audience;
    this.replayIdentity = fields.replayIdentity;
    this.verifiedAtMs = fields.verifiedAtMs;
    this.expiresAtMs = fields.expiresAtMs;
    this.operation = fields.operation;
  }
}

export type VerifiedOwnerProof =
  | VerifiedOwnerWalletSessionProof
  | VerifiedOwnerOperationProof;

export function buildVerifiedOwnerProof(
  input: Extract<VerifiedOwnerProofInput, { readonly purpose: 'wallet_session' }>,
): Promise<VerifiedOwnerWalletSessionProof>;
export function buildVerifiedOwnerProof(
  input: Extract<VerifiedOwnerProofInput, { readonly purpose: 'operation' }>,
): Promise<VerifiedOwnerOperationProof>;
export function buildVerifiedOwnerProof(input: VerifiedOwnerProofInput): Promise<VerifiedOwnerProof>;
export async function buildVerifiedOwnerProof(
  input: VerifiedOwnerProofInput,
): Promise<VerifiedOwnerProof> {
  const fields = await buildOwnerProofFields(input);
  switch (fields.purpose) {
    case 'wallet_session':
      return new VerifiedOwnerWalletSessionProof(fields);
    case 'operation':
      return new VerifiedOwnerOperationProof(fields);
  }
}

export async function buildVerifiedWalletOperationFactorEvidenceSet(
  input: VerifiedWalletOperationFactorEvidenceSetInput,
): Promise<VerifiedAuthorizationEvidenceSet> {
  await requireExactWalletOperationFactorBinding(input);
  const evidence = await buildWalletOperationFactorEvidence(input.evidenceId, input.factor);
  const evidenceSetDigest = await digestCanonicalEvidenceSet({
    tenantId: input.factor.tenantId,
    principalId: input.factor.principalId,
    walletId: input.factor.walletId,
    authorityRef: input.factor.authorityRef,
    requestOrigin: input.factor.requestOrigin,
    audience: input.factor.audience,
    operationFingerprintDigest: await computeCapabilityOperationFingerprintDigest(input.operation),
    evidence,
  });
  return new VerifiedWalletOperationEvidenceSetProof({
    tenantId: input.factor.tenantId,
    principalId: input.factor.principalId,
    walletId: input.factor.walletId,
    authorityRef: input.factor.authorityRef,
    requestOrigin: input.factor.requestOrigin,
    audience: input.factor.audience,
    evidenceSetId: input.evidenceSetId,
    evidence: [evidence],
    evidenceSetDigest,
    operation: input.operation.operation,
    laneDigest: input.operation.digests.laneDigest,
    intentDigest: input.operation.digests.intentDigest,
    displayDigest: input.operation.digests.displayDigest,
    assurance: 'step_up',
    verifiedAtMs: input.factor.verifiedAtMs,
    expiresAtMs: input.factor.expiresAtMs,
  });
}

export function parseVerifiedAuthorizationEvidenceSetFromPersistence(
  raw: unknown,
): VerifiedAuthorizationEvidenceSet {
  return parseVerifiedWalletOperationEvidenceSetFromPersistence(raw);
}

function parseVerifiedWalletOperationEvidenceSetFromPersistence(
  raw: unknown,
): VerifiedAuthorizationEvidenceSet {
  const record = requireExactRecord(raw, [
    'kind',
    'tenantId',
    'principalId',
    'walletId',
    'authorityRef',
    'requestOrigin',
    'audience',
    'evidenceSetId',
    'evidence',
    'evidenceSetDigest',
    'operation',
    'laneDigest',
    'intentDigest',
    'displayDigest',
    'assurance',
    'verifiedAtMs',
    'expiresAtMs',
  ]);
  if (record.kind !== 'verified_wallet_operation_evidence_set' || record.assurance !== 'step_up') {
    throw new Error('persisted wallet operation evidence set kind is invalid');
  }
  const authorityRef = parseWalletAuthAuthorityRef(record.authorityRef);
  if (!authorityRef) {
    throw new Error('persisted wallet operation evidence authority is invalid');
  }
  const walletId = parseWalletId(record.walletId);
  if (!walletId.ok) {
    throw new Error('persisted wallet operation evidence wallet is invalid');
  }
  return new VerifiedWalletOperationEvidenceSetProof({
    tenantId: parseAuthorizationField(record.tenantId, parseTenantId, 'tenantId'),
    principalId: parseAuthorizationField(record.principalId, parsePrincipalId, 'principalId'),
    walletId: walletId.value,
    authorityRef,
    requestOrigin: parseSessionOrigin(record.requestOrigin),
    audience: parseSessionOrigin(record.audience),
    evidenceSetId: parseAuthorizationField(
      record.evidenceSetId,
      parseAuthorizationEvidenceSetId,
      'evidenceSetId',
    ),
    evidence: parsePersistedEvidence(record.evidence),
    evidenceSetDigest: parsePersistenceDigest(record.evidenceSetDigest, 'evidenceSetDigest'),
    operation: parseAuthorizationField(record.operation, parseCapabilityOperationRef, 'operation'),
    laneDigest: parsePersistenceDigest(record.laneDigest, 'laneDigest'),
    intentDigest: parsePersistenceDigest(record.intentDigest, 'intentDigest'),
    displayDigest: parsePersistenceDigest(record.displayDigest, 'displayDigest'),
    assurance: 'step_up',
    verifiedAtMs: requirePositiveSafeInteger(record.verifiedAtMs, 'verifiedAtMs'),
    expiresAtMs: requirePositiveSafeInteger(record.expiresAtMs, 'expiresAtMs'),
  });
}

async function requireExactWalletOperationFactorBinding(
  input: VerifiedWalletOperationFactorEvidenceSetInput,
): Promise<void> {
  const factor = input.factor;
  if (
    factor.tenantId !== input.operation.tenantId ||
    factor.principalId !== input.operation.principalId ||
    factor.authorityRef.walletId !== factor.walletId
  ) {
    throw new Error('verified factor does not match the wallet operation identity');
  }
  const verifiedFingerprint = await computeCapabilityOperationFingerprintDigest(factor.operation);
  const requestedFingerprint = await computeCapabilityOperationFingerprintDigest(input.operation);
  if (verifiedFingerprint !== requestedFingerprint) {
    throw new Error('verified factor does not match the capability operation');
  }
}

async function buildWalletOperationFactorEvidence(
  evidenceId: AuthorizationEvidenceId,
  factor: VerifiedWalletOperationFactorResult,
): Promise<VerifiedAuthorizationEvidence> {
  const operationFingerprintDigest = await computeCapabilityOperationFingerprintDigest(
    factor.operation,
  );
  const common = {
    tenantId: factor.tenantId,
    principalId: factor.principalId,
    walletId: factor.walletId,
    authorityRef: factor.authorityRef,
    requestOrigin: factor.requestOrigin,
    audience: factor.audience,
    factorId: factor.factorId,
    operationFingerprintDigest,
    verifiedAtMs: factor.verifiedAtMs,
    expiresAtMs: factor.expiresAtMs,
  };
  switch (factor.kind) {
    case 'verified_wallet_operation_passkey_factor':
      return {
        evidenceId,
        evidenceKind: AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion,
        evidenceDigest: await digestCanonicalEvidence({
          kind: factor.kind,
          ...common,
          credentialIdB64u: factor.credentialIdB64u,
          assertionDigest: factor.assertionDigest,
        }),
      };
    case 'verified_wallet_operation_email_otp_factor':
      return {
        evidenceId,
        evidenceKind: AUTHORIZATION_EVIDENCE_KINDS.emailOtp,
        evidenceDigest: await digestCanonicalEvidence({
          kind: factor.kind,
          ...common,
          challengeId: factor.challengeId,
          verificationReceiptDigest: factor.verificationReceiptDigest,
        }),
      };
  }
}

async function buildOwnerProofFields(input: VerifiedOwnerProofInput): Promise<VerifiedOwnerProofFields> {
  const factor = input.factor;
  if (factor.authorityRef.walletId !== factor.walletId) {
    throw new Error('owner factor authority must identify the exact wallet');
  }
  requireVerificationWindow(factor.verifiedAtMs, factor.expiresAtMs);
  const common = {
    kind: 'verified_owner_proof_v1' as const,
    proofId: input.proofId,
    method: ownerProofMethod(factor),
    authSource: ownerProofAuthSource(factor),
    tenantId: factor.tenantId,
    principalId: factor.principalId,
    walletId: factor.walletId,
    authority: factor.authorityRef,
    origin: factor.requestOrigin,
    audience: factor.audience,
    replayIdentity: ownerProofReplayIdentity(factor),
    verifiedAtMs: factor.verifiedAtMs,
    expiresAtMs: factor.expiresAtMs,
  };
  if (input.purpose === 'wallet_session') {
    return { ...common, purpose: 'wallet_session' };
  }
  if (!('operation' in factor)) {
    throw new Error('operation owner proof requires operation-bound factor evidence');
  }
  if (
    factor.operation.tenantId !== factor.tenantId ||
    factor.operation.principalId !== factor.principalId
  ) {
    throw new Error('operation owner factor identity does not match its operation');
  }
  const operationFingerprintDigest = await computeCapabilityOperationFingerprintDigest(
    factor.operation,
  );
  return {
    ...common,
    purpose: 'operation',
    operation: {
      operationFingerprintDigest,
      operation: factor.operation.operation,
      laneDigest: factor.operation.digests.laneDigest,
      intentDigest: factor.operation.digests.intentDigest,
      displayDigest: factor.operation.digests.displayDigest,
    },
  };
}

function ownerProofMethod(
  factor: VerifiedWalletSessionFactorResult | VerifiedWalletOperationFactorResult,
): VerifiedOwnerProofMethod {
  switch (factor.kind) {
    case 'verified_wallet_session_passkey_factor':
    case 'verified_wallet_operation_passkey_factor':
      return 'passkey';
    case 'verified_wallet_session_email_otp_factor':
    case 'verified_wallet_operation_email_otp_factor':
      return 'email_otp';
  }
}

function ownerProofAuthSource(
  factor: VerifiedWalletSessionFactorResult | VerifiedWalletOperationFactorResult,
): VerifiedOwnerProofFields['authSource'] {
  switch (factor.kind) {
    case 'verified_wallet_session_passkey_factor':
    case 'verified_wallet_operation_passkey_factor':
      return { kind: 'passkey', credentialIdB64u: factor.credentialIdB64u };
    case 'verified_wallet_session_email_otp_factor':
    case 'verified_wallet_operation_email_otp_factor': {
      const providerSubject = parseProviderSubject(factor.principalId);
      if (!providerSubject.ok) throw new Error(providerSubject.error.message);
      return {
        kind: 'oidc_provider',
        providerId: providerSubject.value.startsWith('google:') ? 'google_oidc' : 'oidc',
        providerSubject: providerSubject.value,
      };
    }
  }
}

function ownerProofReplayIdentity(
  factor: VerifiedWalletSessionFactorResult | VerifiedWalletOperationFactorResult,
): string {
  switch (factor.kind) {
    case 'verified_wallet_session_passkey_factor':
    case 'verified_wallet_operation_passkey_factor':
      return `passkey:${String(factor.factorId)}:${String(factor.assertionDigest)}`;
    case 'verified_wallet_session_email_otp_factor':
    case 'verified_wallet_operation_email_otp_factor':
      return `email_otp:${String(factor.factorId)}:${String(factor.challengeId)}:${String(factor.verificationReceiptDigest)}`;
  }
}

function requireOwnerProofFields(fields: VerifiedOwnerProofFields): void {
  if (fields.authority.walletId !== fields.walletId) {
    throw new Error('owner proof authority must identify the exact wallet');
  }
  requireVerificationWindow(fields.verifiedAtMs, fields.expiresAtMs);
  if (fields.replayIdentity.trim() !== fields.replayIdentity || fields.replayIdentity.length === 0) {
    throw new Error('owner proof replay identity is invalid');
  }
  if (fields.purpose === 'operation') {
    if (fields.operation.operationFingerprintDigest.length === 0) {
      throw new Error('owner proof operation fingerprint is required');
    }
  }
}

function requireVerificationWindow(verifiedAtMs: number, expiresAtMs: number): void {
  if (
    !Number.isSafeInteger(verifiedAtMs) ||
    !Number.isSafeInteger(expiresAtMs) ||
    verifiedAtMs <= 0 ||
    expiresAtMs <= verifiedAtMs
  ) {
    throw new Error('verified factor expiry must follow verification');
  }
}

async function digestCanonicalEvidence(value: Record<string, unknown>): Promise<DigestB64u> {
  return await digestCanonical(FACTOR_EVIDENCE_DIGEST_DOMAIN_V1, value);
}

async function digestCanonicalEvidenceSet(value: Record<string, unknown>): Promise<DigestB64u> {
  return await digestCanonical(EVIDENCE_SET_DIGEST_DOMAIN_V1, value);
}

async function digestCanonical(
  domain: string,
  value: Record<string, unknown>,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256BytesUtf8(`${domain}|${alphabetizeStringify(value)}`)),
  );
}

function requireWalletOperationEvidenceSetFields(
  fields: VerifiedWalletOperationEvidenceSetFields,
): void {
  if (fields.authorityRef.walletId !== fields.walletId) {
    throw new Error('wallet operation evidence authority must identify the wallet');
  }
  if (fields.evidence.length === 0) {
    throw new Error('wallet operation evidence set requires evidence');
  }
  const evidenceIds = new Set(fields.evidence.map(evidenceIdFromEvidence));
  if (evidenceIds.size !== fields.evidence.length) {
    throw new Error('wallet operation evidence set cannot repeat evidence');
  }
  requireVerificationWindow(fields.verifiedAtMs, fields.expiresAtMs);
}

function evidenceIdFromEvidence(evidence: VerifiedAuthorizationEvidence): AuthorizationEvidenceId {
  return evidence.evidenceId;
}

function parsePersistedEvidence(
  raw: unknown,
): readonly [VerifiedAuthorizationEvidence, ...VerifiedAuthorizationEvidence[]] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error('persisted evidence set requires evidence');
  }
  const evidence = raw.map(parsePersistedEvidenceEntry);
  const [first, ...remaining] = evidence;
  if (!first) throw new Error('persisted evidence set requires evidence');
  return [first, ...remaining];
}

function parsePersistedEvidenceEntry(raw: unknown): VerifiedAuthorizationEvidence {
  const record = requireExactRecord(raw, ['evidenceId', 'evidenceKind', 'evidenceDigest']);
  if (!isAuthorizationEvidenceKind(record.evidenceKind)) {
    throw new Error('persisted evidence kind is invalid');
  }
  return {
    evidenceId: parseAuthorizationField(
      record.evidenceId,
      parseAuthorizationEvidenceId,
      'evidenceId',
    ),
    evidenceKind: record.evidenceKind,
    evidenceDigest: parsePersistenceDigest(record.evidenceDigest, 'evidenceDigest'),
  };
}

function parseAuthorizationField<T>(
  raw: unknown,
  parser: (value: unknown) => AuthorizationParseResult<T>,
  field: string,
): T {
  const parsed = parser(raw);
  if (!parsed.ok) {
    throw new Error(`persisted evidence set ${field} is invalid: ${parsed.error.message}`);
  }
  return parsed.value;
}

function parsePersistenceDigest(raw: unknown, field: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch {
    throw new Error(`persisted evidence set ${field} is invalid`);
  }
}

function requirePositiveSafeInteger(raw: unknown, field: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) <= 0) {
    throw new Error(`persisted evidence set ${field} must be a positive safe integer`);
  }
  return Number(raw);
}

function requireExactRecord(raw: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('persisted evidence set must be an object');
  }
  const record = raw as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== fields.length) {
    throw new Error('persisted evidence set fields are invalid');
  }
  for (const key of keys) {
    if (!fields.includes(key)) {
      throw new Error('persisted evidence set fields are invalid');
    }
  }
  return record;
}

function isRecordValue(raw: unknown): raw is Record<string, unknown> {
  return raw !== null && typeof raw === 'object' && !Array.isArray(raw);
}
