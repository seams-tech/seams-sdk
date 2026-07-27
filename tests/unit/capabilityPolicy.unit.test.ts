import { expect, test } from '@playwright/test';
import {
  GRANT_EVIDENCE_KINDS,
  buildGrantEvidenceRequirement,
} from '@shared/authorization/capabilityKinds';
import {
  evaluateGrantEvidenceRequirement,
  parseGrantEvidenceRequirement,
} from '../../packages/sdk-server-ts/src/authorization/capabilityPolicy';
import { buildReusableAuthorizationCoreFixture } from './helpers/authorizationCore.fixtures';

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

test('all requires every kind and any accepts one kind', async () => {
  const { evidenceSet } = await buildReusableAuthorizationCoreFixture();

  expect(
    evaluateGrantEvidenceRequirement(
      buildGrantEvidenceRequirement({
        mode: 'all',
        evidenceKinds: [GRANT_EVIDENCE_KINDS.seamsSession, GRANT_EVIDENCE_KINDS.emailOtp],
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
        evidenceKinds: [GRANT_EVIDENCE_KINDS.passkeyAssertion, GRANT_EVIDENCE_KINDS.seamsSession],
      }),
      evidenceSet,
    ),
  ).toEqual({
    kind: 'satisfied',
    mode: 'any',
    matchedEvidenceKinds: [GRANT_EVIDENCE_KINDS.seamsSession],
  });
});
