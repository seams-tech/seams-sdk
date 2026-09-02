import {
  buildAuthorizationEvidenceRequirement,
  isAuthorizationEvidenceKind,
  type AuthorizationEvidenceKind,
  type AuthorizationEvidenceRequirement,
} from '@shared/authorization/capabilityKinds';
import type { VerifiedAuthorizationEvidenceSet } from './domain';

export type ParseAuthorizationEvidenceRequirementResult =
  | {
      readonly kind: 'parsed';
      readonly requirement: AuthorizationEvidenceRequirement;
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

export type AuthorizationEvidenceRequirementEvaluation =
  | {
      readonly kind: 'satisfied';
      readonly mode: AuthorizationEvidenceRequirement['mode'];
      readonly matchedEvidenceKinds: readonly [
        AuthorizationEvidenceKind,
        ...AuthorizationEvidenceKind[],
      ];
    }
  | {
      readonly kind: 'unsatisfied';
      readonly mode: 'all';
      readonly missingEvidenceKinds: readonly [
        AuthorizationEvidenceKind,
        ...AuthorizationEvidenceKind[],
      ];
    }
  | {
      readonly kind: 'unsatisfied';
      readonly mode: 'any';
      readonly acceptableEvidenceKinds: readonly [
        AuthorizationEvidenceKind,
        ...AuthorizationEvidenceKind[],
      ];
    };

export interface CapabilityPolicyPort {
  parseEvidenceRequirement(value: unknown): ParseAuthorizationEvidenceRequirementResult;
  evaluateEvidenceRequirement(
    requirement: AuthorizationEvidenceRequirement,
    evidenceSet: VerifiedAuthorizationEvidenceSet,
  ): AuthorizationEvidenceRequirementEvaluation;
}

export function parseAuthorizationEvidenceRequirement(
  value: unknown,
): ParseAuthorizationEvidenceRequirementResult {
  if (!isExactRequirementRecord(value)) {
    return rejectInvalidRequirement(
      'authorization evidence requirement must contain exact mode and evidenceKinds fields',
    );
  }
  if (value.mode !== 'all' && value.mode !== 'any') {
    return rejectInvalidRequirement('authorization evidence requirement mode must be all or any');
  }
  if (!Array.isArray(value.evidenceKinds) || value.evidenceKinds.length === 0) {
    return rejectInvalidRequirement('authorization evidence requirement must contain evidence kinds');
  }

  const evidenceKinds: AuthorizationEvidenceKind[] = [];
  for (const evidenceKind of value.evidenceKinds) {
    if (typeof evidenceKind !== 'string') {
      return rejectInvalidRequirement('authorization evidence kinds must be strings');
    }
    if (!isAuthorizationEvidenceKind(evidenceKind)) {
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
    return rejectInvalidRequirement('authorization evidence requirement must contain evidence kinds');
  }
  return {
    kind: 'parsed',
    requirement: buildAuthorizationEvidenceRequirement({
      mode: value.mode,
      evidenceKinds: [firstEvidenceKind, ...remainingEvidenceKinds],
    }),
  };
}

export function evaluateAuthorizationEvidenceRequirement(
  requirement: AuthorizationEvidenceRequirement,
  evidenceSet: VerifiedAuthorizationEvidenceSet,
): AuthorizationEvidenceRequirementEvaluation {
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
  parseEvidenceRequirement: parseAuthorizationEvidenceRequirement,
  evaluateEvidenceRequirement: evaluateAuthorizationEvidenceRequirement,
};

function evaluateAllEvidenceRequirement(
  requiredKinds: readonly [AuthorizationEvidenceKind, ...AuthorizationEvidenceKind[]],
  availableKinds: ReadonlySet<AuthorizationEvidenceKind>,
): AuthorizationEvidenceRequirementEvaluation {
  const missingKinds: AuthorizationEvidenceKind[] = [];
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
  acceptableKinds: readonly [AuthorizationEvidenceKind, ...AuthorizationEvidenceKind[]],
  availableKinds: ReadonlySet<AuthorizationEvidenceKind>,
): AuthorizationEvidenceRequirementEvaluation {
  const matchedKinds: AuthorizationEvidenceKind[] = [];
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
  evidenceSet: VerifiedAuthorizationEvidenceSet,
): ReadonlySet<AuthorizationEvidenceKind> {
  const evidenceKinds = new Set<AuthorizationEvidenceKind>();
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

function rejectInvalidRequirement(
  message: string,
): ParseAuthorizationEvidenceRequirementResult {
  return {
    kind: 'rejected',
    reason: {
      kind: 'invalid_requirement',
      message,
    },
  };
}

function assertNeverRequirementMode(value: never): never {
  throw new Error(`unsupported authorization evidence requirement mode: ${String(value)}`);
}
