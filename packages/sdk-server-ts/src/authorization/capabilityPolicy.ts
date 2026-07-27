import {
  buildGrantEvidenceRequirement,
  isGrantEvidenceKind,
  type GrantEvidenceKind,
  type GrantEvidenceRequirement,
} from '@shared/authorization/capabilityKinds';
import type { VerifiedGrantEvidenceSet } from './domain';

export type ParseGrantEvidenceRequirementResult =
  | {
      readonly kind: 'parsed';
      readonly requirement: GrantEvidenceRequirement;
    }
  | {
      readonly kind: 'rejected';
      readonly reason:
        | {
            readonly kind: 'invalid_requirement';
            readonly message: string;
          }
        | {
            readonly kind: 'unsupported_evidence_kind';
            readonly evidenceKind: string;
          };
    };

export type GrantEvidenceRequirementEvaluation =
  | {
      readonly kind: 'satisfied';
      readonly mode: GrantEvidenceRequirement['mode'];
      readonly matchedEvidenceKinds: readonly [GrantEvidenceKind, ...GrantEvidenceKind[]];
    }
  | {
      readonly kind: 'unsatisfied';
      readonly mode: 'all';
      readonly missingEvidenceKinds: readonly [GrantEvidenceKind, ...GrantEvidenceKind[]];
    }
  | {
      readonly kind: 'unsatisfied';
      readonly mode: 'any';
      readonly acceptableEvidenceKinds: readonly [GrantEvidenceKind, ...GrantEvidenceKind[]];
    };

export interface CapabilityPolicyPort {
  parseEvidenceRequirement(value: unknown): ParseGrantEvidenceRequirementResult;
  evaluateEvidenceRequirement(
    requirement: GrantEvidenceRequirement,
    evidenceSet: VerifiedGrantEvidenceSet,
  ): GrantEvidenceRequirementEvaluation;
}

export function parseGrantEvidenceRequirement(value: unknown): ParseGrantEvidenceRequirementResult {
  if (!isExactRequirementRecord(value)) {
    return rejectInvalidRequirement(
      'grant evidence requirement must contain exact mode and evidenceKinds fields',
    );
  }
  if (value.mode !== 'all' && value.mode !== 'any') {
    return rejectInvalidRequirement('grant evidence requirement mode must be all or any');
  }
  if (!Array.isArray(value.evidenceKinds) || value.evidenceKinds.length === 0) {
    return rejectInvalidRequirement('grant evidence requirement must contain evidence kinds');
  }

  const evidenceKinds: GrantEvidenceKind[] = [];
  for (const evidenceKind of value.evidenceKinds) {
    if (typeof evidenceKind !== 'string') {
      return rejectInvalidRequirement('grant evidence kinds must be strings');
    }
    if (!isGrantEvidenceKind(evidenceKind)) {
      return {
        kind: 'rejected',
        reason: {
          kind: 'unsupported_evidence_kind',
          evidenceKind,
        },
      };
    }
    evidenceKinds.push(evidenceKind);
  }

  const [firstEvidenceKind, ...remainingEvidenceKinds] = evidenceKinds;
  if (!firstEvidenceKind) {
    return rejectInvalidRequirement('grant evidence requirement must contain evidence kinds');
  }
  return {
    kind: 'parsed',
    requirement: buildGrantEvidenceRequirement({
      mode: value.mode,
      evidenceKinds: [firstEvidenceKind, ...remainingEvidenceKinds],
    }),
  };
}

export function evaluateGrantEvidenceRequirement(
  requirement: GrantEvidenceRequirement,
  evidenceSet: VerifiedGrantEvidenceSet,
): GrantEvidenceRequirementEvaluation {
  const availableKinds = collectEvidenceKinds(evidenceSet);
  switch (requirement.mode) {
    case 'all':
      return evaluateAllEvidenceRequirement(requirement.evidenceKinds, availableKinds);
    case 'any':
      return evaluateAnyEvidenceRequirement(requirement.evidenceKinds, availableKinds);
    default:
      return assertNeverRequirementMode(requirement.mode);
  }
}

export const capabilityPolicyPort: CapabilityPolicyPort = {
  parseEvidenceRequirement: parseGrantEvidenceRequirement,
  evaluateEvidenceRequirement: evaluateGrantEvidenceRequirement,
};

function evaluateAllEvidenceRequirement(
  requiredKinds: readonly [GrantEvidenceKind, ...GrantEvidenceKind[]],
  availableKinds: ReadonlySet<GrantEvidenceKind>,
): GrantEvidenceRequirementEvaluation {
  const missingKinds: GrantEvidenceKind[] = [];
  for (const evidenceKind of requiredKinds) {
    if (!availableKinds.has(evidenceKind)) {
      missingKinds.push(evidenceKind);
    }
  }
  const [firstMissingKind, ...remainingMissingKinds] = missingKinds;
  if (firstMissingKind) {
    return {
      kind: 'unsatisfied',
      mode: 'all',
      missingEvidenceKinds: [firstMissingKind, ...remainingMissingKinds],
    };
  }
  return {
    kind: 'satisfied',
    mode: 'all',
    matchedEvidenceKinds: requiredKinds,
  };
}

function evaluateAnyEvidenceRequirement(
  acceptableKinds: readonly [GrantEvidenceKind, ...GrantEvidenceKind[]],
  availableKinds: ReadonlySet<GrantEvidenceKind>,
): GrantEvidenceRequirementEvaluation {
  const matchedKinds: GrantEvidenceKind[] = [];
  for (const evidenceKind of acceptableKinds) {
    if (availableKinds.has(evidenceKind)) {
      matchedKinds.push(evidenceKind);
    }
  }
  const [firstMatchedKind, ...remainingMatchedKinds] = matchedKinds;
  if (firstMatchedKind) {
    return {
      kind: 'satisfied',
      mode: 'any',
      matchedEvidenceKinds: [firstMatchedKind, ...remainingMatchedKinds],
    };
  }
  return {
    kind: 'unsatisfied',
    mode: 'any',
    acceptableEvidenceKinds: acceptableKinds,
  };
}

function collectEvidenceKinds(
  evidenceSet: VerifiedGrantEvidenceSet,
): ReadonlySet<GrantEvidenceKind> {
  const evidenceKinds = new Set<GrantEvidenceKind>();
  for (const evidence of evidenceSet.evidence) {
    evidenceKinds.add(evidence.evidenceKind);
  }
  return evidenceKinds;
}

function isExactRequirementRecord(value: unknown): value is {
  readonly mode: unknown;
  readonly evidenceKinds: unknown;
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === 2 && keys.includes('mode') && keys.includes('evidenceKinds');
}

function rejectInvalidRequirement(message: string): ParseGrantEvidenceRequirementResult {
  return {
    kind: 'rejected',
    reason: {
      kind: 'invalid_requirement',
      message,
    },
  };
}

function assertNeverRequirementMode(value: never): never {
  throw new Error(`unsupported grant evidence requirement mode: ${String(value)}`);
}
