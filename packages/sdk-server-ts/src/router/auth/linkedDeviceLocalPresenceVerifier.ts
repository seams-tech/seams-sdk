import {
  parseAuthorizedOperationId,
  type AuthorizedOperationId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseWebAuthnCredentialIdB64u,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import type { WebAuthnAuthenticationCredential } from '../../core/types';
import {
  parseWebAuthnAuthenticationCredential,
  webAuthnCredentialIdB64uFromCredential,
} from './webAuthnCredentialCodecs';
import type { LinkedDeviceLocalPresenceEvidenceV1 } from '../domains/signingOperations/walletExecutionAdmission';

export type LinkedDeviceLocalPresenceAssertionV1 = {
  readonly kind: 'linked_device_local_presence_assertion_v1';
  readonly authorizedOperationId: unknown;
  readonly deviceId: unknown;
  readonly enrollmentId: unknown;
  readonly credentialIdB64u: unknown;
  readonly intentDigestB64u: unknown;
  readonly challengeDigestB64u: unknown;
  readonly issuedAtMs: unknown;
  readonly expiresAtMs: unknown;
  readonly assertion: unknown;
};

export type LinkedDeviceLocalPresenceVerificationPortInputV1 = {
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly intentDigestB64u: DigestB64u;
  readonly challengeDigestB64u: DigestB64u;
  readonly assertion: WebAuthnAuthenticationCredential;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type LinkedDeviceLocalPresenceVerificationPortResultV1 =
  | {
      readonly kind: 'verified';
      readonly verifiedAtMs: number;
    }
  | {
      readonly kind: 'refused';
      readonly reason: 'assertion_invalid' | 'assertion_binding_mismatch' | 'assertion_expired';
    };

export type LinkedDeviceLocalPresenceVerifierPortV1 = {
  verify(
    input: LinkedDeviceLocalPresenceVerificationPortInputV1,
  ): Promise<LinkedDeviceLocalPresenceVerificationPortResultV1>;
};

export type LinkedDeviceLocalPresenceVerificationResultV1 =
  | {
      readonly kind: 'verified';
      readonly evidence: LinkedDeviceLocalPresenceEvidenceV1;
    }
  | {
      readonly kind: 'refused';
      readonly reason:
        | 'assertion_invalid'
        | 'assertion_binding_mismatch'
        | 'assertion_expired'
        | 'assertion_malformed'
        | 'assertion_credential_mismatch'
        | 'assertion_time_invalid';
    };

type ParsedLinkedDeviceLocalPresenceAssertionV1 = {
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly intentDigestB64u: DigestB64u;
  readonly challengeDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly assertion: WebAuthnAuthenticationCredential;
};

function parseFiniteTimestamp(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export function parseLinkedDeviceLocalPresenceAssertionV1(
  input: unknown,
): ParsedLinkedDeviceLocalPresenceAssertionV1 | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const record = input as Record<string, unknown>;
  if (record.kind !== 'linked_device_local_presence_assertion_v1') return null;
  const authorizedOperationId = parseAuthorizedOperationId(record.authorizedOperationId);
  const deviceId = parseLinkedDeviceId(record.deviceId);
  const enrollmentId = parseLinkedDeviceEnrollmentId(record.enrollmentId);
  const credentialId = parseWebAuthnCredentialIdB64u(record.credentialIdB64u);
  let intentDigestB64u: DigestB64u;
  let challengeDigestB64u: DigestB64u;
  try {
    intentDigestB64u = parseDigestB64u(record.intentDigestB64u);
    challengeDigestB64u = parseDigestB64u(record.challengeDigestB64u);
  } catch {
    return null;
  }
  const issuedAtMs = parseFiniteTimestamp(record.issuedAtMs);
  const expiresAtMs = parseFiniteTimestamp(record.expiresAtMs);
  const assertion = parseWebAuthnAuthenticationCredential(record.assertion);
  if (
    !authorizedOperationId.ok ||
    !deviceId.ok ||
    !enrollmentId.ok ||
    !credentialId.ok ||
    issuedAtMs === null ||
    expiresAtMs === null ||
    issuedAtMs >= expiresAtMs ||
    !assertion
  ) {
    return null;
  }
  const assertionCredentialId = webAuthnCredentialIdB64uFromCredential(assertion);
  if (!assertionCredentialId.ok) return null;
  const parsedAssertionCredentialId = parseWebAuthnCredentialIdB64u(
    assertionCredentialId.credentialIdB64u,
  );
  if (!parsedAssertionCredentialId.ok || parsedAssertionCredentialId.value !== credentialId.value) {
    return null;
  }
  return {
    authorizedOperationId: authorizedOperationId.value,
    deviceId: deviceId.value,
    enrollmentId: enrollmentId.value,
    credentialIdB64u: credentialId.value,
    intentDigestB64u,
    challengeDigestB64u,
    issuedAtMs,
    expiresAtMs,
    assertion,
  };
}

export async function verifyLinkedDeviceLocalPresenceV1(input: {
  readonly assertion: unknown;
  readonly verifier: LinkedDeviceLocalPresenceVerifierPortV1;
  readonly nowMs?: () => number;
}): Promise<LinkedDeviceLocalPresenceVerificationResultV1> {
  const parsed = parseLinkedDeviceLocalPresenceAssertionV1(input.assertion);
  if (!parsed) return { kind: 'refused', reason: 'assertion_malformed' };
  const nowMs = input.nowMs ? input.nowMs() : Date.now();
  if (!Number.isSafeInteger(nowMs) || nowMs < parsed.issuedAtMs || nowMs >= parsed.expiresAtMs) {
    return { kind: 'refused', reason: 'assertion_time_invalid' };
  }
  let verification: LinkedDeviceLocalPresenceVerificationPortResultV1;
  try {
    verification = await input.verifier.verify({
      authorizedOperationId: parsed.authorizedOperationId,
      deviceId: parsed.deviceId,
      enrollmentId: parsed.enrollmentId,
      credentialIdB64u: parsed.credentialIdB64u,
      intentDigestB64u: parsed.intentDigestB64u,
      challengeDigestB64u: parsed.challengeDigestB64u,
      assertion: parsed.assertion,
      issuedAtMs: parsed.issuedAtMs,
      expiresAtMs: parsed.expiresAtMs,
    });
  } catch {
    return { kind: 'refused', reason: 'assertion_invalid' };
  }
  if (verification.kind !== 'verified') {
    return { kind: 'refused', reason: verification.reason };
  }
  if (
    !Number.isSafeInteger(verification.verifiedAtMs) ||
    verification.verifiedAtMs < parsed.issuedAtMs ||
    verification.verifiedAtMs >= parsed.expiresAtMs
  ) {
    return { kind: 'refused', reason: 'assertion_time_invalid' };
  }
  const assertionDigestB64u = parseDigestB64u(
    base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(parsed.assertion))),
  );
  return {
    kind: 'verified',
    evidence: {
      kind: 'linked_device_local_presence_evidence_v1',
      authorizedOperationId: parsed.authorizedOperationId,
      deviceId: parsed.deviceId,
      enrollmentId: parsed.enrollmentId,
      credentialIdB64u: parsed.credentialIdB64u,
      intentDigestB64u: parsed.intentDigestB64u,
      verifiedAtMs: verification.verifiedAtMs,
      assertionDigestB64u,
    },
  };
}
