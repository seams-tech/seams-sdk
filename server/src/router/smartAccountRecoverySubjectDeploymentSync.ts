import { normalizePositiveInteger } from '@shared/utils/validation';
import type { AuthService } from '../core/AuthService';
import {
  smartAccountChainTargetKey,
  type SmartAccountChainTarget,
} from '../core/smartAccountChainTarget';
import type { CreateAccountAndRegisterSmartAccountDeployment } from '../core/types';
import type { RelayRuntimePolicyScope } from './relay';
import { syncCanonicalSmartAccountDeploymentManifest } from './smartAccountDeploymentManifest';

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

export type SmartAccountRecoverySubjectDeploymentUpdate = {
  chainTarget: SmartAccountChainTarget;
  accountAddress: string;
  accountModel?: string;
  deployed: boolean;
  sponsorshipScope?: RelayRuntimePolicyScope;
  counterfactualAddress?: string;
  deploymentTxHash?: string;
  code?: string;
  message?: string;
};

export async function syncSmartAccountRecoverySubjectDeployment(input: {
  authService: AuthService;
  update: SmartAccountRecoverySubjectDeploymentUpdate;
  observedAtMs?: number;
  expectedUserId?: string;
}): Promise<
  | { ok: true; chainIdKey: string; accountAddress: string }
  | { ok: false; code: 'invalid_args' | 'not_found' | 'forbidden' | 'internal'; message: string }
> {
  const chainId = normalizePositiveInteger(input.update.chainTarget.chainId);
  const accountAddress = normalizeOptionalString(input.update.accountAddress);
  if (typeof chainId !== 'number' || !accountAddress) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing smart-account deployment observation key',
    };
  }

  const chainIdKey = smartAccountChainTargetKey(input.update.chainTarget);
  const existing = await input.authService.getSmartAccountRecoverySubjectByAccount({
    chainIdKey,
    accountAddress,
  });
  if (!existing.ok) {
    return { ok: false, code: existing.code, message: existing.message };
  }
  if (!existing.record) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Smart-account recovery subject was not found',
    };
  }
  if (
    normalizeOptionalString(input.expectedUserId) &&
    existing.record.userId !== normalizeOptionalString(input.expectedUserId)
  ) {
    return {
      ok: false,
      code: 'forbidden',
      message: 'Threshold session is not authorized for this smart account',
    };
  }

  const nowMs = Math.floor(
    typeof input.observedAtMs === 'number' && Number.isFinite(input.observedAtMs)
      ? input.observedAtMs
      : Date.now(),
  );
  const written = await input.authService.putSmartAccountRecoverySubject({
    ...existing.record,
    updatedAtMs: nowMs,
    metadata: {
      ...(existing.record.metadata || {}),
      ...(normalizeOptionalString(input.update.accountModel)
        ? { accountModel: normalizeOptionalString(input.update.accountModel) }
        : {}),
      ...(input.update.sponsorshipScope
        ? {
            sponsorshipScope: {
              orgId: input.update.sponsorshipScope.orgId,
              envId: input.update.sponsorshipScope.envId,
              signingRootVersion: input.update.sponsorshipScope.signingRootVersion,
              ...(normalizeOptionalString(input.update.sponsorshipScope.projectId)
                ? { projectId: normalizeOptionalString(input.update.sponsorshipScope.projectId) }
                : {}),
            },
          }
        : {}),
      chainTarget: input.update.chainTarget,
      deployed: input.update.deployed === true,
      deploymentStatusUpdatedAtMs: nowMs,
      ...(normalizeOptionalString(input.update.counterfactualAddress)
        ? { counterfactualAddress: normalizeOptionalString(input.update.counterfactualAddress) }
        : {}),
      ...(normalizeOptionalString(input.update.deploymentTxHash)
        ? { deploymentTxHash: normalizeOptionalString(input.update.deploymentTxHash) }
        : {}),
      ...(normalizeOptionalString(input.update.code)
        ? { lastDeploymentCode: normalizeOptionalString(input.update.code) }
        : {}),
      ...(normalizeOptionalString(input.update.message)
        ? { lastDeploymentMessage: normalizeOptionalString(input.update.message) }
        : {}),
    },
  });
  if (!written.ok) {
    return { ok: false, code: written.code, message: written.message };
  }

  const syncedManifest = await syncCanonicalSmartAccountDeploymentManifest({
    authService: input.authService,
    chainIdKey,
    accountAddress,
    ...(normalizeOptionalString(input.expectedUserId)
      ? { expectedUserId: normalizeOptionalString(input.expectedUserId) }
      : {}),
    materializedAtMs: nowMs,
  });
  if (!syncedManifest.ok) {
    return {
      ok: false,
      code: syncedManifest.code,
      message: syncedManifest.message,
    };
  }

  return { ok: true, chainIdKey, accountAddress };
}

export async function syncSmartAccountRecoverySubjectDeployments(input: {
  authService: AuthService;
  deployments: CreateAccountAndRegisterSmartAccountDeployment[];
  sponsorshipScope?: RelayRuntimePolicyScope;
  observedAtMs?: number;
}): Promise<void> {
  const observedAtMs =
    typeof input.observedAtMs === 'number' && Number.isFinite(input.observedAtMs)
      ? Math.floor(input.observedAtMs)
      : Date.now();
  for (const deployment of input.deployments) {
    const accountAddress = normalizeOptionalString(deployment.accountAddress);
    if (!accountAddress) continue;
    await syncSmartAccountRecoverySubjectDeployment({
      authService: input.authService,
      observedAtMs,
      update: {
        chainTarget: deployment.chainTarget,
        accountAddress,
        accountModel: normalizeOptionalString(deployment.accountModel),
        deployed: deployment.deployed === true,
        ...(input.sponsorshipScope ? { sponsorshipScope: input.sponsorshipScope } : {}),
        ...(normalizeOptionalString(deployment.counterfactualAddress)
          ? { counterfactualAddress: normalizeOptionalString(deployment.counterfactualAddress) }
          : {}),
        ...(normalizeOptionalString(deployment.deploymentTxHash)
          ? { deploymentTxHash: normalizeOptionalString(deployment.deploymentTxHash) }
          : {}),
        ...(normalizeOptionalString(deployment.code)
          ? { code: normalizeOptionalString(deployment.code) }
          : {}),
        ...(normalizeOptionalString(deployment.message)
          ? { message: normalizeOptionalString(deployment.message) }
          : {}),
      },
    });
  }
}
