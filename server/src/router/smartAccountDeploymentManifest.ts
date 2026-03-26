import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { AuthService } from '../core/AuthService';
import {
  buildCanonicalEvmSmartAccountDeploymentPlan,
  type CanonicalEvmSmartAccountDeploymentPlan,
} from '../core/evmSmartAccountDeploymentPlan';
import {
  buildCanonicalSmartAccountDeploymentManifest,
  type CanonicalSmartAccountDeploymentManifest,
} from '../core/smartAccountDeploymentManifest';

type SmartAccountDeploymentManifestAuthService = Pick<
  AuthService,
  | 'getSmartAccountRecoverySubjectByAccount'
  | 'listAccountSignersByAccount'
  | 'putSmartAccountRecoverySubject'
>;

const EVM_DEPLOYMENT_PLAN_METADATA_KEYS = [
  'evmDeploymentPlan',
  'evmDeploymentPlanUpdatedAtMs',
] as const;

function normalizeChainIdKey(value: unknown): string {
  return toOptionalTrimmedString(value)?.toLowerCase() || '';
}

function normalizeAccountAddress(value: unknown): string {
  const normalized = toOptionalTrimmedString(value) || '';
  return normalized.startsWith('0x') ? normalized.toLowerCase() : normalized;
}

function buildSyncedRecoverySubjectMetadata(input: {
  metadata?: Record<string, unknown>;
  manifest: CanonicalSmartAccountDeploymentManifest;
  evmDeploymentPlan?: CanonicalEvmSmartAccountDeploymentPlan;
}): Record<string, unknown> {
  const next: Record<string, unknown> = {
    ...(input.metadata || {}),
    deploymentManifest: input.manifest,
    deploymentManifestUpdatedAtMs: input.manifest.materializedAtMs,
  };

  if (input.evmDeploymentPlan) {
    next.evmDeploymentPlan = input.evmDeploymentPlan;
    next.evmDeploymentPlanUpdatedAtMs = input.manifest.materializedAtMs;
    return next;
  }

  for (const key of EVM_DEPLOYMENT_PLAN_METADATA_KEYS) {
    delete next[key];
  }
  return next;
}

export async function readCanonicalSmartAccountDeploymentManifest(input: {
  authService: SmartAccountDeploymentManifestAuthService;
  chainIdKey: string;
  accountAddress: string;
  expectedUserId?: string;
  materializedAtMs?: number;
}): Promise<
  | {
      ok: true;
      chainIdKey: string;
      accountAddress: string;
      manifest: CanonicalSmartAccountDeploymentManifest;
      evmDeploymentPlan?: CanonicalEvmSmartAccountDeploymentPlan;
    }
  | { ok: false; code: 'invalid_args' | 'not_found' | 'forbidden' | 'internal'; message: string }
> {
  const chainIdKey = normalizeChainIdKey(input.chainIdKey);
  const accountAddress = normalizeAccountAddress(input.accountAddress);
  const expectedUserId = toOptionalTrimmedString(input.expectedUserId);
  if (!chainIdKey || !accountAddress) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing smart-account deployment manifest key',
    };
  }

  const subject = await input.authService.getSmartAccountRecoverySubjectByAccount({
    chainIdKey,
    accountAddress,
  });
  if (!subject.ok) {
    return { ok: false, code: subject.code, message: subject.message };
  }
  if (!subject.record) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Smart-account recovery subject was not found',
    };
  }
  if (expectedUserId && subject.record.userId !== expectedUserId) {
    return {
      ok: false,
      code: 'forbidden',
      message: 'Threshold session is not authorized for this smart account',
    };
  }

  const signers = await input.authService.listAccountSignersByAccount({
    chainIdKey,
    accountAddress,
  });
  if (!signers.ok) {
    return { ok: false, code: signers.code, message: signers.message };
  }

  const manifest = buildCanonicalSmartAccountDeploymentManifest({
    recoverySubject: subject.record,
    signers: signers.records,
    materializedAtMs: input.materializedAtMs,
  });
  if (!manifest) {
    return {
      ok: false,
      code: 'internal',
      message: 'Canonical smart-account deployment manifest could not be derived',
    };
  }

  const evmDeploymentPlan = buildCanonicalEvmSmartAccountDeploymentPlan(manifest);

  return {
    ok: true,
    chainIdKey,
    accountAddress,
    manifest,
    ...(evmDeploymentPlan ? { evmDeploymentPlan } : {}),
  };
}

export async function syncCanonicalSmartAccountDeploymentManifest(input: {
  authService: SmartAccountDeploymentManifestAuthService;
  chainIdKey: string;
  accountAddress: string;
  expectedUserId?: string;
  materializedAtMs?: number;
}): Promise<
  | {
      ok: true;
      chainIdKey: string;
      accountAddress: string;
      manifest: CanonicalSmartAccountDeploymentManifest;
      evmDeploymentPlan?: CanonicalEvmSmartAccountDeploymentPlan;
    }
  | { ok: false; code: 'invalid_args' | 'not_found' | 'forbidden' | 'internal'; message: string }
> {
  const resolved = await readCanonicalSmartAccountDeploymentManifest(input);
  if (!resolved.ok) return resolved;

  const subject = await input.authService.getSmartAccountRecoverySubjectByAccount({
    chainIdKey: resolved.chainIdKey,
    accountAddress: resolved.accountAddress,
  });
  if (!subject.ok) {
    return { ok: false, code: subject.code, message: subject.message };
  }
  if (!subject.record) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Smart-account recovery subject was not found',
    };
  }

  const nowMs = Number.isFinite(Number(input.materializedAtMs))
    ? Math.floor(Number(input.materializedAtMs))
    : resolved.manifest.materializedAtMs;
  const written = await input.authService.putSmartAccountRecoverySubject({
    ...subject.record,
    updatedAtMs: nowMs,
    metadata: buildSyncedRecoverySubjectMetadata({
      metadata: subject.record.metadata,
      manifest: resolved.manifest,
      ...(resolved.evmDeploymentPlan ? { evmDeploymentPlan: resolved.evmDeploymentPlan } : {}),
    }),
  });
  if (!written.ok) {
    return { ok: false, code: written.code, message: written.message };
  }

  return resolved;
}
