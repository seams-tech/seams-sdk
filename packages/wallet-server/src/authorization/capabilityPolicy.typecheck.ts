import {
  AUTHORIZATION_EVIDENCE_KINDS,
  type AuthorizationEvidenceRequirement,
} from '@shared/authorization/capabilityKinds';
import type { VerifiedAuthorizationEvidenceSet } from './domain';
import { evaluateAuthorizationEvidenceRequirement } from './capabilityPolicy';

declare const evidenceSet: VerifiedAuthorizationEvidenceSet;

evaluateAuthorizationEvidenceRequirement(
  {
    mode: 'any',
    evidenceKinds: [
      AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion,
      AUTHORIZATION_EVIDENCE_KINDS.emailOtp,
    ],
  },
  evidenceSet,
);

const recursiveRequirement = {
  mode: 'all',
  evidenceKinds: [AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion],
  nested: {
    mode: 'any',
    evidenceKinds: [AUTHORIZATION_EVIDENCE_KINDS.emailOtp],
  },
};

// @ts-expect-error Recursive policy nodes are outside the flat requirement type.
recursiveRequirement satisfies AuthorizationEvidenceRequirement;

const unsupportedSignerProof = {
  mode: 'all',
  evidenceKinds: ['mpc_signer_proof'],
} as const;

// @ts-expect-error MPC signer proof remains outside the closed evidence union.
unsupportedSignerProof satisfies AuthorizationEvidenceRequirement;

evaluateAuthorizationEvidenceRequirement(
  {
    mode: 'all',
    evidenceKinds: [AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion],
  },
  // @ts-expect-error Policy evaluation requires the normalized evidence-set record.
  [{ evidenceKind: AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion }],
);
