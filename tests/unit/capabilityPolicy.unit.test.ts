import { expect, test } from '@playwright/test';
import {
  AUTHORIZATION_EVIDENCE_KINDS,
  buildAuthorizationEvidenceRequirement,
} from '@shared/authorization/capabilityKinds';
import {
  evaluateAuthorizationEvidenceRequirement,
  parseAuthorizationEvidenceRequirement,
} from '../../packages/wallet-server/src/authorization/capabilityPolicy';
import { buildReusableAuthorizationCoreFixture } from './helpers/authorizationCore.fixtures';

test('flat policy parsing canonicalizes current evidence kinds', () => {
  expect(
    parseAuthorizationEvidenceRequirement({
      mode: 'all',
      evidenceKinds: [
        AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion,
        AUTHORIZATION_EVIDENCE_KINDS.emailOtp,
        AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion,
      ],
    }),
  ).toEqual({
    kind: 'parsed',
    requirement: {
      mode: 'all',
      evidenceKinds: [
        AUTHORIZATION_EVIDENCE_KINDS.emailOtp,
        AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion,
      ],
    },
  });
});

test('raw policies fail closed for MPC signer proof and recursive shapes', () => {
  expect(
    parseAuthorizationEvidenceRequirement({
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
    parseAuthorizationEvidenceRequirement({
      mode: 'all',
      evidenceKinds: [AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion],
      nested: {
        mode: 'any',
        evidenceKinds: [AUTHORIZATION_EVIDENCE_KINDS.emailOtp],
      },
    }),
  ).toEqual({
    kind: 'rejected',
    reason: {
      kind: 'invalid_requirement',
      message:
        'authorization evidence requirement must contain exact mode and evidenceKinds fields',
    },
  });
});

test('all requires every kind and any accepts one kind', async () => {
  const { evidenceSet } = await buildReusableAuthorizationCoreFixture();

  expect(
    evaluateAuthorizationEvidenceRequirement(
      buildAuthorizationEvidenceRequirement({
        mode: 'all',
        evidenceKinds: [
          AUTHORIZATION_EVIDENCE_KINDS.seamsSession,
          AUTHORIZATION_EVIDENCE_KINDS.emailOtp,
        ],
      }),
      evidenceSet,
    ),
  ).toEqual({
    kind: 'unsatisfied',
    mode: 'all',
    missingEvidenceKinds: [AUTHORIZATION_EVIDENCE_KINDS.emailOtp],
  });

  expect(
    evaluateAuthorizationEvidenceRequirement(
      buildAuthorizationEvidenceRequirement({
        mode: 'any',
        evidenceKinds: [
          AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion,
          AUTHORIZATION_EVIDENCE_KINDS.seamsSession,
        ],
      }),
      evidenceSet,
    ),
  ).toEqual({
    kind: 'satisfied',
    mode: 'any',
    matchedEvidenceKinds: [AUTHORIZATION_EVIDENCE_KINDS.seamsSession],
  });
});
