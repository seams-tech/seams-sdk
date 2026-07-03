import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { ThresholdRuntimePolicyScope } from '../types';

export function normalizeThresholdRuntimePolicyScope(
  raw: unknown,
): ThresholdRuntimePolicyScope | undefined {
  try {
    return normalizeRuntimePolicyScope(raw);
  } catch {
    return undefined;
  }
}

export function thresholdRuntimePolicyScopesEqual(leftRaw: unknown, rightRaw: unknown): boolean {
  const left = normalizeThresholdRuntimePolicyScope(leftRaw);
  const right = normalizeThresholdRuntimePolicyScope(rightRaw);
  if (!left || !right) return !left && !right;
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}
