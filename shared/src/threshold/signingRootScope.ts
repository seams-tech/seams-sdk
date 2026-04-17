import { toOptionalTrimmedString } from '../utils/validation';

export type RuntimePolicyScope = {
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

export type SigningRootScope = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
};

function requireScopeField(label: string, value: unknown): string {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

export function deriveSigningRootId(input: {
  readonly projectId: unknown;
  readonly envId: unknown;
}): string {
  const projectId = requireScopeField('projectId', input.projectId);
  const envId = requireScopeField('envId', input.envId);
  return `${projectId}:${envId}`;
}

export function normalizeRuntimePolicyScope(input: unknown): RuntimePolicyScope {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('runtimePolicyScope must be an object');
  }
  const scope = input as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(scope, 'environmentId')) {
    throw new Error('runtimePolicyScope.environmentId is stale; use envId');
  }
  if (Object.prototype.hasOwnProperty.call(scope, 'runtimeSnapshotScope')) {
    throw new Error('runtimePolicyScope.runtimeSnapshotScope is stale; use runtimePolicyScope');
  }
  return {
    orgId: requireScopeField('orgId', scope.orgId),
    projectId: requireScopeField('projectId', scope.projectId),
    envId: requireScopeField('envId', scope.envId),
  };
}

export function signingRootScopeFromRuntimePolicyScope(
  scope: RuntimePolicyScope,
): SigningRootScope {
  return {
    signingRootId: deriveSigningRootId(scope),
  };
}

export function normalizeSigningRootScope(input: {
  readonly signingRootId: unknown;
  readonly signingRootVersion?: unknown;
}): SigningRootScope {
  const signingRootId = requireScopeField('signingRootId', input.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
  return {
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
  };
}
