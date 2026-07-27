import {
  GRANT_EVIDENCE_KINDS,
  type GrantEvidenceRequirement,
} from '@shared/authorization/capabilityKinds';
import type { VerifiedGrantEvidenceSet } from './domain';
import { evaluateGrantEvidenceRequirement } from './capabilityPolicy';

declare const evidenceSet: VerifiedGrantEvidenceSet;

evaluateGrantEvidenceRequirement(
  {
    mode: 'any',
    evidenceKinds: [GRANT_EVIDENCE_KINDS.passkeyAssertion, GRANT_EVIDENCE_KINDS.emailOtp],
  },
  evidenceSet,
);

const recursiveRequirement = {
  mode: 'all',
  evidenceKinds: [GRANT_EVIDENCE_KINDS.passkeyAssertion],
  nested: {
    mode: 'any',
    evidenceKinds: [GRANT_EVIDENCE_KINDS.emailOtp],
  },
};

// @ts-expect-error Recursive policy nodes are outside the flat requirement type.
recursiveRequirement satisfies GrantEvidenceRequirement;

const unsupportedSignerProof = {
  mode: 'all',
  evidenceKinds: ['mpc_signer_proof'],
} as const;

// @ts-expect-error MPC signer proof remains outside the closed evidence union.
unsupportedSignerProof satisfies GrantEvidenceRequirement;

evaluateGrantEvidenceRequirement(
  {
    mode: 'all',
    evidenceKinds: [GRANT_EVIDENCE_KINDS.passkeyAssertion],
  },
  // @ts-expect-error Policy evaluation requires the normalized evidence-set record.
  [{ evidenceKind: GRANT_EVIDENCE_KINDS.passkeyAssertion }],
);
