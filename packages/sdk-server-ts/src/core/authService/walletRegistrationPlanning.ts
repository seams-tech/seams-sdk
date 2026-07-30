import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  thresholdEcdsaChainTargetFromValue,
  type ThresholdEcdsaChainTarget,
} from '../thresholdEcdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../types';
import { isObject } from './record';
import { normalizeThresholdRuntimePolicyScope } from './thresholdRuntimePolicy';

type AdjacentFlowEcdsaPrepareSpec = {
  chainTargets: ThresholdEcdsaChainTarget[];
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  signingRootId?: string;
  signingRootVersion?: string;
};

export function normalizeAdjacentFlowEcdsaPrepareSpec(
  raw: unknown,
):
  | { ok: true; value: AdjacentFlowEcdsaPrepareSpec | null }
  | { ok: false; code: string; message: string } {
  if (raw == null) return { ok: true, value: null };
  if (!isObject(raw)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'threshold_ecdsa_prepare must be an object',
    };
  }
  const chainTargetRaw = raw.chainTargets ?? raw.chain_targets;
  const participantIdRaw = raw.participantIds ?? raw.participant_ids;
  const chainTargets = Array.isArray(chainTargetRaw)
    ? chainTargetRaw.map((target) => thresholdEcdsaChainTargetFromValue(target))
    : [];
  const normalizedChainTargets = chainTargets.filter(
    (target): target is ThresholdEcdsaChainTarget => Boolean(target),
  );
  if (
    normalizedChainTargets.length === 0 ||
    normalizedChainTargets.length !== chainTargets.length
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'threshold_ecdsa_prepare.chainTargets must contain valid chain targets',
    };
  }
  const participantIds = Array.isArray(participantIdRaw)
    ? participantIdRaw.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)
    : [];
  if (participantIds.length === 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'threshold_ecdsa_prepare.participantIds must contain positive integers',
    };
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
    raw.runtimePolicyScope ?? raw.runtime_policy_scope,
  );
  const signingRootId = toOptionalTrimmedString(raw.signingRootId ?? raw.signing_root_id);
  const signingRootVersion = toOptionalTrimmedString(
    raw.signingRootVersion ?? raw.signing_root_version,
  );
  return {
    ok: true,
    value: {
      chainTargets: normalizedChainTargets,
      participantIds: Array.from(new Set(participantIds)).sort((a, b) => a - b),
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      ...(signingRootId ? { signingRootId } : {}),
      ...(signingRootVersion ? { signingRootVersion } : {}),
    },
  };
}
