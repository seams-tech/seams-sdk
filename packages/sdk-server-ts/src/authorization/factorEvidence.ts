import {
  GRANT_EVIDENCE_KINDS,
  type AuthFactorId,
  type GrantEvidenceId,
  type GrantEvidenceSetId,
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
  ActiveCapabilityGrant,
  VerifiedGrantEvidence,
  VerifiedGrantEvidenceSet,
} from './domain';
import { buildVerifiedGrantEvidenceSet } from './domain';

const FACTOR_EVIDENCE_DIGEST_DOMAIN_V1 = 'seams:authorization:factor-evidence:v1';
const EVIDENCE_SET_DIGEST_DOMAIN_V1 = 'seams:authorization:evidence-set:v1';

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

export type VerifiedGrantFactorResult = VerifiedPasskeyFactorResult | VerifiedEmailOtpFactorResult;

export type VerifiedFactorEvidenceSetInput = {
  readonly session: ActiveAuthorizationSession;
  readonly operation: CapabilityOperationEnvelope;
  readonly evidenceId: GrantEvidenceId;
  readonly evidenceSetId: GrantEvidenceSetId;
  readonly factor: VerifiedGrantFactorResult;
};

export type CapabilityGrantRequest = {
  readonly kind: 'capability_grant_request';
  readonly operation: CapabilityOperationEnvelope;
  readonly evidenceSet: VerifiedGrantEvidenceSet;
  readonly grant: ActiveCapabilityGrant;
};

export type CapabilityGrantRequestInput = Omit<CapabilityGrantRequest, 'kind'>;

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
): Promise<VerifiedGrantEvidenceSet> {
  await requireExactFactorBinding(input);
  const evidence = await buildFactorEvidence(input.evidenceId, input.factor);
  const evidenceSetDigest = await digestCanonicalEvidenceSet({
    tenantId: input.session.tenantId,
    principalId: input.session.principalId,
    sessionId: input.session.sessionId,
    deviceId: input.session.deviceId,
    operationFingerprintDigest: await computeCapabilityOperationFingerprintDigest(input.operation),
    evidence,
  });
  return buildVerifiedGrantEvidenceSet({
    tenantId: input.session.tenantId,
    principalId: input.session.principalId,
    sessionId: input.session.sessionId,
    deviceId: input.session.deviceId,
    evidenceSetId: input.evidenceSetId,
    evidence: [evidence],
    evidenceSetDigest,
    operation: input.operation.operation,
    laneDigest: input.operation.digests.laneDigest,
    intentDigest: input.operation.digests.intentDigest,
    displayDigest: input.operation.digests.displayDigest,
    assurance: input.session.assurance,
    expiresAtMs: Math.min(input.factor.expiresAtMs, input.session.lifecycle.expiresAtMs),
  });
}

export function buildCapabilityGrantRequest(
  input: CapabilityGrantRequestInput,
): CapabilityGrantRequest {
  const operation = input.operation;
  const evidenceSet = input.evidenceSet;
  const grant = input.grant;
  if (
    operation.tenantId !== evidenceSet.tenantId ||
    operation.tenantId !== grant.tenantId ||
    operation.principalId !== evidenceSet.principalId ||
    operation.principalId !== grant.principalId ||
    operation.capabilityId !== grant.capabilityId
  ) {
    throw new Error('capability grant identity does not match verified evidence');
  }
  if (
    !sameOperation(operation.operation, evidenceSet.operation) ||
    !sameOperation(operation.operation, grant.operation)
  ) {
    throw new Error('capability grant operation does not match verified evidence');
  }
  if (
    operation.digests.laneDigest !== evidenceSet.laneDigest ||
    operation.digests.laneDigest !== grant.laneDigest ||
    operation.digests.intentDigest !== evidenceSet.intentDigest ||
    operation.digests.intentDigest !== grant.intentDigest ||
    operation.digests.displayDigest !== evidenceSet.displayDigest ||
    operation.digests.displayDigest !== grant.displayDigest
  ) {
    throw new Error('capability grant digests do not match verified evidence');
  }
  if (
    evidenceSet.evidenceSetId !== grant.evidenceSetId ||
    evidenceSet.evidenceSetDigest !== grant.evidenceSetDigest
  ) {
    throw new Error('capability grant evidence reference does not match verified evidence');
  }
  if (grant.expiresAtMs > evidenceSet.expiresAtMs) {
    throw new Error('capability grant cannot outlive verified evidence');
  }
  return {
    kind: 'capability_grant_request',
    operation,
    evidenceSet,
    grant,
  };
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
  if (
    input.operation.tenantId !== session.tenantId ||
    input.operation.principalId !== session.principalId
  ) {
    throw new Error('capability operation does not match the authorization session');
  }
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

async function buildFactorEvidence(
  evidenceId: GrantEvidenceId,
  factor: VerifiedGrantFactorResult,
): Promise<VerifiedGrantEvidence> {
  const operationFingerprintDigest = await computeCapabilityOperationFingerprintDigest(
    factor.operation,
  );
  switch (factor.kind) {
    case 'verified_passkey_factor':
      return {
        evidenceId,
        evidenceKind: GRANT_EVIDENCE_KINDS.passkeyAssertion,
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
        evidenceKind: GRANT_EVIDENCE_KINDS.emailOtp,
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

function sameOperation(
  left: CapabilityOperationEnvelope['operation'],
  right: CapabilityOperationEnvelope['operation'],
): boolean {
  return left.capabilityKind === right.capabilityKind && left.operationKind === right.operationKind;
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
