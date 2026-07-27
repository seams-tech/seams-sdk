import { expect, test } from '@playwright/test';
import {
  GRANT_EVIDENCE_KINDS,
  buildEvmEcdsaMpcOperationRef,
  buildGrantEvidenceRequirement,
  parseDeviceId,
  parseGrantEvidenceId,
  parseGrantEvidenceSetId,
  parsePrincipalId,
  parseSeamsSessionId,
  parseTenantId,
  type AuthorizationParseResult,
} from '@shared/authorization/capabilityKinds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  evaluateGrantEvidenceRequirement,
  parseGrantEvidenceRequirement,
} from '../../packages/sdk-server-ts/src/authorization/capabilityPolicy';
import { buildVerifiedGrantEvidenceSet } from '../../packages/sdk-server-ts/src/authorization/domain';

test('flat policy parsing canonicalizes current evidence kinds', () => {
  expect(
    parseGrantEvidenceRequirement({
      mode: 'all',
      evidenceKinds: [
        GRANT_EVIDENCE_KINDS.passkeyAssertion,
        GRANT_EVIDENCE_KINDS.emailOtp,
        GRANT_EVIDENCE_KINDS.passkeyAssertion,
      ],
    }),
  ).toEqual({
    kind: 'parsed',
    requirement: {
      mode: 'all',
      evidenceKinds: [GRANT_EVIDENCE_KINDS.emailOtp, GRANT_EVIDENCE_KINDS.passkeyAssertion],
    },
  });
});

test('raw policies fail closed for MPC signer proof and recursive shapes', () => {
  expect(
    parseGrantEvidenceRequirement({
      mode: 'any',
      evidenceKinds: ['mpc_signer_proof'],
    }),
  ).toEqual({
    kind: 'rejected',
    reason: {
      kind: 'unsupported_evidence_kind',
      evidenceKind: 'mpc_signer_proof',
    },
  });

  expect(
    parseGrantEvidenceRequirement({
      mode: 'all',
      evidenceKinds: [GRANT_EVIDENCE_KINDS.passkeyAssertion],
      nested: {
        mode: 'any',
        evidenceKinds: [GRANT_EVIDENCE_KINDS.emailOtp],
      },
    }),
  ).toEqual({
    kind: 'rejected',
    reason: {
      kind: 'invalid_requirement',
      message: 'grant evidence requirement must contain exact mode and evidenceKinds fields',
    },
  });
});

test('all requires every kind and any accepts one kind', () => {
  const evidenceSet = buildEvidenceSet();

  expect(
    evaluateGrantEvidenceRequirement(
      buildGrantEvidenceRequirement({
        mode: 'all',
        evidenceKinds: [GRANT_EVIDENCE_KINDS.passkeyAssertion, GRANT_EVIDENCE_KINDS.emailOtp],
      }),
      evidenceSet,
    ),
  ).toEqual({
    kind: 'unsatisfied',
    mode: 'all',
    missingEvidenceKinds: [GRANT_EVIDENCE_KINDS.emailOtp],
  });

  expect(
    evaluateGrantEvidenceRequirement(
      buildGrantEvidenceRequirement({
        mode: 'any',
        evidenceKinds: [GRANT_EVIDENCE_KINDS.passkeyAssertion, GRANT_EVIDENCE_KINDS.emailOtp],
      }),
      evidenceSet,
    ),
  ).toEqual({
    kind: 'satisfied',
    mode: 'any',
    matchedEvidenceKinds: [GRANT_EVIDENCE_KINDS.passkeyAssertion],
  });
});

function buildEvidenceSet() {
  return buildVerifiedGrantEvidenceSet({
    tenantId: parsed('tenant-policy', parseTenantId),
    principalId: parsed('principal-policy', parsePrincipalId),
    sessionId: parsed('session-policy', parseSeamsSessionId),
    deviceId: parsed('device-policy', parseDeviceId),
    evidenceSetId: parsed('evidence-set-policy', parseGrantEvidenceSetId),
    evidence: [
      {
        evidenceId: parsed('evidence-policy', parseGrantEvidenceId),
        evidenceKind: GRANT_EVIDENCE_KINDS.passkeyAssertion,
        evidenceDigest: fixtureDigest(1),
      },
    ],
    evidenceSetDigest: fixtureDigest(2),
    operation: buildEvmEcdsaMpcOperationRef('evm.sign_transaction'),
    laneDigest: fixtureDigest(3),
    intentDigest: fixtureDigest(4),
    displayDigest: fixtureDigest(5),
    assurance: 'step_up',
    expiresAtMs: 1_900_000_000_000,
  });
}

function parsed<T>(value: string, parser: (raw: unknown) => AuthorizationParseResult<T>): T {
  const result = parser(value);
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function fixtureDigest(fill: number) {
  return parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(fill)));
}
