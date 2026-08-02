import {
  AUTHORIZATION_EVIDENCE_KINDS,
  isAuthorizationEvidenceKind,
  parseCapabilityOperationRef,
  parseDeviceId,
  parseAuthorizationEvidenceId,
  parseAuthorizationEvidenceSetId,
  parsePrincipalId,
  parseSeamsSessionId,
  parseTenantId,
  type AuthFactorId,
  type AuthorizationParseResult,
  type CapabilityOperationRef,
  type DeviceId,
  type AuthorizationEvidenceId,
  type AuthorizationEvidenceSetId,
  type PrincipalId,
  type SeamsSessionId,
  type TenantId,
} from '@shared/authorization/capabilityKinds';
import {
  computeCapabilityOperationFingerprintDigest,
  type CapabilityOperationEnvelope,
} from '@shared/authorization/operationFingerprint';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { EmailOtpChallengeId, WebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type {
  ActiveAuthorizationSession,
  VerifiedAuthorizationEvidence,
} from './domain';

const FACTOR_EVIDENCE_DIGEST_DOMAIN_V1 = 'seams:authorization:factor-evidence:v1';
const SESSION_EVIDENCE_DIGEST_DOMAIN_V1 = 'seams:authorization:session-evidence:v1';
const EVIDENCE_SET_DIGEST_DOMAIN_V1 = 'seams:authorization:evidence-set:v1';

type VerifiedAuthorizationEvidenceSetFields = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly sessionId: SeamsSessionId;
  readonly deviceId: DeviceId;
  readonly evidenceSetId: AuthorizationEvidenceSetId;
  readonly evidence: readonly [VerifiedAuthorizationEvidence, ...VerifiedAuthorizationEvidence[]];
  readonly evidenceSetDigest: DigestB64u;
  readonly operation: CapabilityOperationRef;
  readonly laneDigest: DigestB64u;
  readonly intentDigest: DigestB64u;
  readonly displayDigest: DigestB64u;
  readonly assurance: 'session' | 'step_up';
  readonly expiresAtMs: number;
};

class VerifiedAuthorizationEvidenceSetProof {
  readonly kind = 'verified_authorization_evidence_set' as const;
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly sessionId: SeamsSessionId;
  readonly deviceId: DeviceId;
  readonly evidenceSetId: AuthorizationEvidenceSetId;
  readonly evidence: readonly [VerifiedAuthorizationEvidence, ...VerifiedAuthorizationEvidence[]];
  readonly evidenceSetDigest: DigestB64u;
  readonly operation: CapabilityOperationRef;
  readonly laneDigest: DigestB64u;
  readonly intentDigest: DigestB64u;
  readonly displayDigest: DigestB64u;
  readonly assurance: 'session' | 'step_up';
  readonly expiresAtMs: number;

  private retainVerifiedEvidenceProof(): true {
    return true;
  }

  constructor(fields: VerifiedAuthorizationEvidenceSetFields) {
    void this.retainVerifiedEvidenceProof();
    requireEvidenceSetFields(fields);
    this.tenantId = fields.tenantId;
    this.principalId = fields.principalId;
    this.sessionId = fields.sessionId;
    this.deviceId = fields.deviceId;
    this.evidenceSetId = fields.evidenceSetId;
    this.evidence = fields.evidence;
    this.evidenceSetDigest = fields.evidenceSetDigest;
    this.operation = fields.operation;
    this.laneDigest = fields.laneDigest;
    this.intentDigest = fields.intentDigest;
    this.displayDigest = fields.displayDigest;
    this.assurance = fields.assurance;
    this.expiresAtMs = fields.expiresAtMs;
  }
}

export type VerifiedAuthorizationEvidenceSet = VerifiedAuthorizationEvidenceSetProof;

type VerifiedFactorBinding = {
  readonly tenantId: ActiveAuthorizationSession['tenantId'];
  readonly principalId: ActiveAuthorizationSession['principalId'];
  readonly sessionId: ActiveAuthorizationSession['sessionId'];
  readonly deviceId: ActiveAuthorizationSession['deviceId'];
  readonly factorId: AuthFactorId;
  readonly authorityRef: WalletAuthAuthorityRef;
  readonly operation: CapabilityOperationEnvelope;
  readonly verifiedAtMs: number;
  readonly expiresAtMs: number;
};

export type VerifiedPasskeyFactorResult = VerifiedFactorBinding & {
  readonly kind: 'verified_passkey_factor';
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly assertionDigest: DigestB64u;
};

export type VerifiedEmailOtpFactorResult = VerifiedFactorBinding & {
  readonly kind: 'verified_email_otp_factor';
  readonly challengeId: EmailOtpChallengeId;
  readonly verificationReceiptDigest: DigestB64u;
};

export type VerifiedAuthorizationFactorResult =
  | VerifiedPasskeyFactorResult
  | VerifiedEmailOtpFactorResult;

export type VerifiedFactorEvidenceSetInput = {
  readonly session: ActiveAuthorizationSession;
  readonly operation: CapabilityOperationEnvelope;
  readonly evidenceId: AuthorizationEvidenceId;
  readonly evidenceSetId: AuthorizationEvidenceSetId;
  readonly factor: VerifiedAuthorizationFactorResult;
};

export type VerifiedSessionEvidenceSetInput = {
  readonly session: ActiveAuthorizationSession;
  readonly operation: CapabilityOperationEnvelope;
  readonly evidenceId: AuthorizationEvidenceId;
  readonly evidenceSetId: AuthorizationEvidenceSetId;
  readonly expiresAtMs: number;
};

export function buildVerifiedPasskeyFactorResult(
  fields: Omit<VerifiedPasskeyFactorResult, 'kind'>,
): VerifiedPasskeyFactorResult {
  requireVerificationWindow(fields.verifiedAtMs, fields.expiresAtMs);
  return {
    kind: 'verified_passkey_factor',
    tenantId: fields.tenantId,
    principalId: fields.principalId,
    sessionId: fields.sessionId,
    deviceId: fields.deviceId,
    factorId: fields.factorId,
    authorityRef: fields.authorityRef,
    operation: fields.operation,
    credentialIdB64u: fields.credentialIdB64u,
    assertionDigest: fields.assertionDigest,
    verifiedAtMs: fields.verifiedAtMs,
    expiresAtMs: fields.expiresAtMs,
  };
}

export function buildVerifiedEmailOtpFactorResult(
  fields: Omit<VerifiedEmailOtpFactorResult, 'kind'>,
): VerifiedEmailOtpFactorResult {
  requireVerificationWindow(fields.verifiedAtMs, fields.expiresAtMs);
  return {
    kind: 'verified_email_otp_factor',
    tenantId: fields.tenantId,
    principalId: fields.principalId,
    sessionId: fields.sessionId,
    deviceId: fields.deviceId,
    factorId: fields.factorId,
    authorityRef: fields.authorityRef,
    operation: fields.operation,
    challengeId: fields.challengeId,
    verificationReceiptDigest: fields.verificationReceiptDigest,
    verifiedAtMs: fields.verifiedAtMs,
    expiresAtMs: fields.expiresAtMs,
  };
}

export async function buildVerifiedFactorEvidenceSet(
  input: VerifiedFactorEvidenceSetInput,
): Promise<VerifiedAuthorizationEvidenceSet> {
  await requireExactFactorBinding(input);
  const evidence = await buildFactorEvidence(input.evidenceId, input.factor);
  return await buildVerifiedEvidenceSet({
    session: input.session,
    operation: input.operation,
    evidenceSetId: input.evidenceSetId,
    evidence,
    assurance: 'step_up',
    expiresAtMs: Math.min(input.factor.expiresAtMs, input.session.lifecycle.expiresAtMs),
  });
}

export async function buildVerifiedSessionEvidenceSet(
  input: VerifiedSessionEvidenceSetInput,
): Promise<VerifiedAuthorizationEvidenceSet> {
  requireOperationSessionMatch(input.session, input.operation);
  if (
    !Number.isSafeInteger(input.expiresAtMs) ||
    input.expiresAtMs <= input.session.createdAtMs ||
    input.expiresAtMs > input.session.lifecycle.expiresAtMs
  ) {
    throw new Error('session evidence expiry must be within the authorization session');
  }
  const operationFingerprintDigest = await computeCapabilityOperationFingerprintDigest(
    input.operation,
  );
  const evidence: VerifiedAuthorizationEvidence = {
    evidenceId: input.evidenceId,
    evidenceKind: AUTHORIZATION_EVIDENCE_KINDS.seamsSession,
    evidenceDigest: await digestCanonical(SESSION_EVIDENCE_DIGEST_DOMAIN_V1, {
      tenantId: input.session.tenantId,
      principalId: input.session.principalId,
      sessionId: input.session.sessionId,
      deviceId: input.session.deviceId,
      operationFingerprintDigest,
      assurance: input.session.assurance,
      expiresAtMs: input.expiresAtMs,
    }),
  };
  return await buildVerifiedEvidenceSet({
    session: input.session,
    operation: input.operation,
    evidenceSetId: input.evidenceSetId,
    evidence,
    assurance: input.session.assurance,
    expiresAtMs: input.expiresAtMs,
  });
}

async function buildVerifiedEvidenceSet(input: {
  readonly session: ActiveAuthorizationSession;
  readonly operation: CapabilityOperationEnvelope;
  readonly evidenceSetId: AuthorizationEvidenceSetId;
  readonly evidence: VerifiedAuthorizationEvidence;
  readonly assurance: VerifiedAuthorizationEvidenceSet['assurance'];
  readonly expiresAtMs: number;
}): Promise<VerifiedAuthorizationEvidenceSet> {
  const evidenceSetDigest = await digestCanonicalEvidenceSet({
    tenantId: input.session.tenantId,
    principalId: input.session.principalId,
    sessionId: input.session.sessionId,
    deviceId: input.session.deviceId,
    operationFingerprintDigest: await computeCapabilityOperationFingerprintDigest(input.operation),
    evidence: input.evidence,
  });
  return new VerifiedAuthorizationEvidenceSetProof({
    tenantId: input.session.tenantId,
    principalId: input.session.principalId,
    sessionId: input.session.sessionId,
    deviceId: input.session.deviceId,
    evidenceSetId: input.evidenceSetId,
    evidence: [input.evidence],
    evidenceSetDigest,
    operation: input.operation.operation,
    laneDigest: input.operation.digests.laneDigest,
    intentDigest: input.operation.digests.intentDigest,
    displayDigest: input.operation.digests.displayDigest,
    assurance: input.assurance,
    expiresAtMs: input.expiresAtMs,
  });
}

export function parseVerifiedAuthorizationEvidenceSetFromPersistence(
  raw: unknown,
): VerifiedAuthorizationEvidenceSet {
  const record = requireExactRecord(raw, [
    'kind',
    'tenantId',
    'principalId',
    'sessionId',
    'deviceId',
    'evidenceSetId',
    'evidence',
    'evidenceSetDigest',
    'operation',
    'laneDigest',
    'intentDigest',
    'displayDigest',
    'assurance',
    'expiresAtMs',
  ]);
  if (record.kind !== 'verified_authorization_evidence_set') {
    throw new Error('persisted evidence set kind is invalid');
  }
  const evidence = parsePersistedEvidence(record.evidence);
  const assurance = record.assurance;
  if (assurance !== 'session' && assurance !== 'step_up') {
    throw new Error('persisted evidence set assurance is invalid');
  }
  return new VerifiedAuthorizationEvidenceSetProof({
    tenantId: parseAuthorizationField(record.tenantId, parseTenantId, 'tenantId'),
    principalId: parseAuthorizationField(record.principalId, parsePrincipalId, 'principalId'),
    sessionId: parseAuthorizationField(record.sessionId, parseSeamsSessionId, 'sessionId'),
    deviceId: parseAuthorizationField(record.deviceId, parseDeviceId, 'deviceId'),
    evidenceSetId: parseAuthorizationField(
      record.evidenceSetId,
      parseAuthorizationEvidenceSetId,
      'evidenceSetId',
    ),
    evidence,
    evidenceSetDigest: parsePersistenceDigest(record.evidenceSetDigest, 'evidenceSetDigest'),
    operation: parseAuthorizationField(record.operation, parseCapabilityOperationRef, 'operation'),
    laneDigest: parsePersistenceDigest(record.laneDigest, 'laneDigest'),
    intentDigest: parsePersistenceDigest(record.intentDigest, 'intentDigest'),
    displayDigest: parsePersistenceDigest(record.displayDigest, 'displayDigest'),
    assurance,
    expiresAtMs: requirePositiveSafeInteger(record.expiresAtMs, 'expiresAtMs'),
  });
}

async function requireExactFactorBinding(input: VerifiedFactorEvidenceSetInput): Promise<void> {
  const session = input.session;
  const factor = input.factor;
  if (
    factor.tenantId !== session.tenantId ||
    factor.principalId !== session.principalId ||
    factor.sessionId !== session.sessionId ||
    factor.deviceId !== session.deviceId
  ) {
    throw new Error('verified factor does not match the authorization session');
  }
  requireOperationSessionMatch(session, input.operation);
  const verifiedFingerprint = await computeCapabilityOperationFingerprintDigest(factor.operation);
  const requestedFingerprint = await computeCapabilityOperationFingerprintDigest(input.operation);
  if (verifiedFingerprint !== requestedFingerprint) {
    throw new Error('verified factor does not match the capability operation');
  }
  if (
    factor.verifiedAtMs < session.createdAtMs ||
    factor.verifiedAtMs >= session.lifecycle.expiresAtMs
  ) {
    throw new Error('verified factor is outside the authorization session lifecycle');
  }
}

function requireOperationSessionMatch(
  session: ActiveAuthorizationSession,
  operation: CapabilityOperationEnvelope,
): void {
  if (operation.tenantId !== session.tenantId || operation.principalId !== session.principalId) {
    throw new Error('capability operation does not match the authorization session');
  }
}

async function buildFactorEvidence(
  evidenceId: AuthorizationEvidenceId,
  factor: VerifiedAuthorizationFactorResult,
): Promise<VerifiedAuthorizationEvidence> {
  const operationFingerprintDigest = await computeCapabilityOperationFingerprintDigest(
    factor.operation,
  );
  switch (factor.kind) {
    case 'verified_passkey_factor':
      return {
        evidenceId,
        evidenceKind: AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion,
        evidenceDigest: await digestCanonicalEvidence({
          kind: factor.kind,
          tenantId: factor.tenantId,
          principalId: factor.principalId,
          sessionId: factor.sessionId,
          deviceId: factor.deviceId,
          factorId: factor.factorId,
          authorityRef: factor.authorityRef,
          operationFingerprintDigest,
          credentialIdB64u: factor.credentialIdB64u,
          assertionDigest: factor.assertionDigest,
          verifiedAtMs: factor.verifiedAtMs,
          expiresAtMs: factor.expiresAtMs,
        }),
      };
    case 'verified_email_otp_factor':
      return {
        evidenceId,
        evidenceKind: AUTHORIZATION_EVIDENCE_KINDS.emailOtp,
        evidenceDigest: await digestCanonicalEvidence({
          kind: factor.kind,
          tenantId: factor.tenantId,
          principalId: factor.principalId,
          sessionId: factor.sessionId,
          deviceId: factor.deviceId,
          factorId: factor.factorId,
          authorityRef: factor.authorityRef,
          operationFingerprintDigest,
          challengeId: factor.challengeId,
          verificationReceiptDigest: factor.verificationReceiptDigest,
          verifiedAtMs: factor.verifiedAtMs,
          expiresAtMs: factor.expiresAtMs,
        }),
      };
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

function requireEvidenceSetFields(fields: VerifiedAuthorizationEvidenceSetFields): void {
  if (fields.evidence.length === 0) {
    throw new Error('verified authorization evidence set requires evidence');
  }
  const evidenceIds = new Set(fields.evidence.map(evidenceIdFromEvidence));
  if (evidenceIds.size !== fields.evidence.length) {
    throw new Error('verified authorization evidence set cannot repeat evidence');
  }
  requirePositiveSafeInteger(fields.expiresAtMs, 'evidence set expiry');
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
