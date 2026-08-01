import type { SigningSessionStatus } from '@/core/types/seams';
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';
import type {
  VolatileWarmMaterialPort,
  WarmSessionStatusResult,
} from '../../uiConfirm/uiConfirm.types';
import {
  listExactSealedSessionsForWallet,
  SigningSessionSealedRecordFilter,
  type updateExactSealedSessionPolicy,
} from '../persistence/sealedSessionStore';
import { createClearVolatileWarmSessionMaterialCommand } from '../warmCapabilities/volatileWarmMaterialCommands';
import { parseVolatileWarmSessionId } from '../warmCapabilities/volatileWarmSessionId';
import type { WarmSessionPrfClaim } from '../warmCapabilities/types';
import {
  ed25519SigningGrantForAuthorization,
  parseExactEd25519SealedSessionRuntime,
  type ExactEd25519SealedSessionRuntime,
} from '../warmCapabilities/ed25519SealedSessionRuntime';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  normalizeWarmSessionReadPorts,
  readWarmSessionClaim,
  readWarmSessionClaims,
  toSigningSessionStatus,
  toWarmSessionClaimFromStatusResult,
  type WarmSessionReadPortsInput,
} from '../warmCapabilities/readModel';
import { unknownSigningSessionStatus } from '../lifecycle/walletSessionStatus';
import {
  ed25519WalletSessionStatusOwner,
  normalizeSessionStatusRequired,
  walletSessionStatusOwnerKey,
  type SigningSessionStatusCheck,
  type WalletSessionStatusOwner,
} from '../lifecycle/walletSessionStatus';
import type {
  Ed25519SigningSessionReadiness,
} from '../planning/planner';
import type { ThresholdEd25519SessionId } from '../operationState/types';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import {
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type SigningSessionLane = {
  curve: 'ed25519';
  chain: 'near';
  source: SignerAuthMethod;
  thresholdSessionId: string;
  signingGrantId: string;
  backingMaterialSessionId: string;
  materialActivation: MpcMaterialActivationRef;
};

export type DiscoveredSigningSessionLane = SigningSessionLane & {
  runtime: ExactEd25519SealedSessionRuntime;
  backing: 'touch_confirm' | 'email_otp_worker' | 'record_policy';
};

export type SigningGrantStatusOverride = {
  owner: WalletSessionStatusOwner;
  signingGrantId: string;
  status: SigningSessionStatus;
  thresholdSessionIds: Set<string>;
  updatedAtMs: number;
};

export type SigningGrantReadinessDeps = {
  listExactSealedSessionsForWallet?: typeof listExactSealedSessionsForWallet;
  touchConfirm?: Partial<
    Pick<
      VolatileWarmMaterialPort,
      | 'getWarmSessionStatus'
      | 'getWarmSessionStatuses'
      | 'clearVolatileWarmSessionMaterial'
    >
  >;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  clearEmailOtpWarmSessionMaterial?: (sessionId: string) => Promise<void>;
};

export type SigningGrantClaimReaderDeps = {
  touchConfirm?: WarmSessionReadPortsInput;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
};

export type SigningSessionReadinessWithStatus = {
  readiness: Ed25519SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
};

export function normalizeNonEmpty(value: unknown): string {
  return String(value || '').trim();
}

export function warmClaimFromRecordPolicy(args: {
  sessionId: string;
  remainingUses: number;
  expiresAtMs: number;
}): WarmSessionPrfClaim {
  const sessionId = normalizeNonEmpty(args.sessionId);
  const remainingUses = Math.max(0, Math.floor(Number(args.remainingUses) || 0));
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  if (expiresAtMs <= Date.now()) return { state: 'expired', sessionId };
  if (remainingUses <= 0) return { state: 'exhausted', sessionId };
  return {
    state: 'warm',
    sessionId,
    remainingUses,
    expiresAtMs,
  };
}

export function applyWalletSessionStatusToSigningSessionReadiness(args: {
  status: Ed25519SigningSessionReadiness['status'];
  thresholdSessionId: ThresholdEd25519SessionId;
  expiresAtMs: number;
  remainingUses: number;
  walletSessionStatus?: SigningSessionStatus | null;
  usesNeeded?: number;
  nowMs?: number;
  missingWhenExpiresAtMissing?: boolean;
}): SigningSessionReadinessWithStatus {
  let status = args.status;
  let expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  let remainingUses = Math.max(0, Math.floor(Number(args.remainingUses) || 0));
  const walletSessionStatus = args.walletSessionStatus;
  if (walletSessionStatus) {
    if (walletSessionStatus.status === 'not_found') {
      status = 'missing_session';
      remainingUses = 0;
    } else if (walletSessionStatus.status === 'status_unknown' && status === 'ready') {
      status = 'status_unknown';
      remainingUses = 0;
    } else if (walletSessionStatus.status === 'unavailable') {
      status = 'status_unavailable';
      remainingUses = 0;
    } else if (walletSessionStatus.status === 'expired') {
      status = 'expired';
      remainingUses = 0;
    } else if (walletSessionStatus.status === 'exhausted') {
      status = 'exhausted';
      remainingUses = 0;
    } else if (walletSessionStatus.status === 'active') {
      const sessionRemainingUses = Math.max(
        0,
        Math.floor(Number(walletSessionStatus.remainingUses) || 0),
      );
      const sessionExpiresAtMs = Math.floor(Number(walletSessionStatus.expiresAtMs) || 0);
      // Local/session-store counters are availability hints after restore. The
      // session status service is the trusted source for terminal budget state.
      // Same-projection local availability can gate admission, but it must not
      // turn a server-active session into step-up reauth.
      remainingUses = sessionRemainingUses;
      if (sessionExpiresAtMs > 0) expiresAtMs = sessionExpiresAtMs;
      if (status === 'exhausted') {
        status = 'ready';
      }
    }
  }
  const usesNeeded = Math.max(1, Math.floor(Number(args.usesNeeded) || 1));
  if (status === 'ready' && args.missingWhenExpiresAtMissing && expiresAtMs <= 0) {
    status = 'missing_session';
  }
  if (status === 'ready' && expiresAtMs <= (args.nowMs ?? Date.now())) status = 'expired';
  if (status === 'ready' && remainingUses < usesNeeded) status = 'exhausted';
  const readiness: Ed25519SigningSessionReadiness =
    status === 'ready' || status === 'exhausted'
      ? {
          status,
          curve: 'ed25519',
          thresholdSessionId: args.thresholdSessionId,
          remainingUses,
          expiresAtMs,
        }
      : status === 'expired'
        ? { status, curve: 'ed25519', thresholdSessionId: args.thresholdSessionId, expiresAtMs }
        : { status, curve: 'ed25519', thresholdSessionId: args.thresholdSessionId };
  return {
    readiness,
    expiresAtMs,
    remainingUses,
  };
}

function toLaneSource(runtime: ExactEd25519SealedSessionRuntime): SignerAuthMethod {
  switch (runtime.factor.kind) {
    case 'email_otp':
      return SIGNER_AUTH_METHODS.emailOtp;
    case 'passkey':
      return SIGNER_AUTH_METHODS.passkey;
  }
}

function authMethodForSigningSessionLanes(
  lanes: readonly DiscoveredSigningSessionLane[],
): SignerAuthMethod | null {
  for (const lane of lanes) {
    const source = lane.source;
    switch (source) {
      case SIGNER_AUTH_METHODS.emailOtp:
        return SIGNER_AUTH_METHODS.emailOtp;
      case SIGNER_AUTH_METHODS.passkey:
        break;
      default:
        return assertNeverSigningSessionLaneAuthMethod(source);
    }
  }
  return null;
}

function assertNeverSigningSessionLaneAuthMethod(value: never): never {
  throw new Error(`Unsupported signing session lane auth method: ${String(value)}`);
}

function resolveRuntimeWalletOwnerId(
  runtime: ExactEd25519SealedSessionRuntime,
): WalletSessionStatusOwner {
  return ed25519WalletSessionStatusOwner(runtime.walletId);
}

function addLane(
  lanes: DiscoveredSigningSessionLane[],
  lane: DiscoveredSigningSessionLane | null,
): void {
  if (!lane) return;
  if (!lane.thresholdSessionId || !lane.signingGrantId || !lane.backingMaterialSessionId) {
    return;
  }
  lanes.push(lane);
}

export function buildDiscoveredLaneForRuntime(
  runtime: ExactEd25519SealedSessionRuntime,
  signingGrantId: string,
): DiscoveredSigningSessionLane {
  return {
    curve: 'ed25519',
    chain: 'near',
    source: toLaneSource(runtime),
    thresholdSessionId: runtime.thresholdSessionId,
    signingGrantId,
    backingMaterialSessionId: runtime.thresholdSessionId,
    materialActivation: runtime.sealedRecord.ed25519Restore.materialActivation,
    backing: 'record_policy',
    runtime,
  };
}

export async function discoverLanesForWallet(
  deps: SigningGrantReadinessDeps,
  walletId: WalletId,
): Promise<DiscoveredSigningSessionLane[]> {
  const listSealed = deps.listExactSealedSessionsForWallet ?? listExactSealedSessionsForWallet;
  const records = (
    await Promise.all([
      listSealed({
        walletId,
        filter: { authMethod: SIGNER_AUTH_METHODS.passkey, curve: 'ed25519' },
      }),
      listSealed({
        walletId,
        filter: { authMethod: SIGNER_AUTH_METHODS.emailOtp, curve: 'ed25519' },
      }),
    ])
  ).flat();
  const lanes: DiscoveredSigningSessionLane[] = [];
  const seenThresholdSessionIds = new Set<string>();
  for (const record of records) {
    if (record.curve !== 'ed25519') continue;
    const runtime = parseExactEd25519SealedSessionRuntime(record);
    if (!runtime || runtime.walletId !== walletId) continue;
    const authorizationRead = await walletSessionAuthorizations.readActiveForWallet(walletId);
    if (authorizationRead.kind !== 'found') continue;
    const signingGrantId = ed25519SigningGrantForAuthorization({
      runtime,
      authorization: authorizationRead.projection,
    });
    if (!signingGrantId) continue;
    if (seenThresholdSessionIds.has(runtime.thresholdSessionId)) continue;
    seenThresholdSessionIds.add(runtime.thresholdSessionId);
    addLane(lanes, buildDiscoveredLaneForRuntime(runtime, signingGrantId));
  }
  return lanes;
}

export async function getLanesForWalletSession(args: {
  deps: SigningGrantReadinessDeps;
  walletId: WalletId;
  signingGrantId: string;
}): Promise<DiscoveredSigningSessionLane[]> {
  const signingGrantId = normalizeSessionStatusRequired(args.signingGrantId, 'signingGrantId');
  return (await discoverLanesForWallet(args.deps, args.walletId)).filter(
    (lane) => lane.signingGrantId === signingGrantId,
  );
}

export function walletScopedClaimsForLanes(args: {
  lanes: DiscoveredSigningSessionLane[];
  claimsByThresholdSessionId: Map<string, WarmSessionPrfClaim | null>;
  statusOverrides?: Map<string, SigningGrantStatusOverride>;
}): Map<string, WarmSessionPrfClaim | null> {
  const grouped = new Map<string, DiscoveredSigningSessionLane[]>();
  for (const lane of args.lanes) {
    const group = grouped.get(lane.signingGrantId) || [];
    group.push(lane);
    grouped.set(lane.signingGrantId, group);
  }

  const scoped = new Map<string, WarmSessionPrfClaim | null>();
  for (const group of grouped.values()) {
    const firstLane = group[0];
    if (!firstLane) continue;
    const signingGrantId = firstLane.signingGrantId;
    const applicableOverride = resolveApplicableSigningGrantStatusOverrideForGroup({
      signingGrantId,
      lanes: group,
      claimsByThresholdSessionId: args.claimsByThresholdSessionId,
      statusOverrides: args.statusOverrides,
    });
    const entries = group.map((lane) => ({
      lane,
      claim: args.claimsByThresholdSessionId.get(lane.thresholdSessionId) || null,
    }));
    const applyRawScopedClaims = (
      rawEntries: Array<{
        lane: DiscoveredSigningSessionLane;
        claim: WarmSessionPrfClaim | null;
      }>,
    ): void => {
      if (!rawEntries.length) return;
      const terminal =
        rawEntries.find((entry) => entry.claim?.state === 'expired')?.claim ||
        rawEntries.find((entry) => entry.claim?.state === 'exhausted')?.claim ||
        null;
      const warmClaims = rawEntries
        .map((entry) => entry.claim)
        .filter(
          (claim): claim is WarmSessionPrfClaim & { state: 'warm' } => claim?.state === 'warm',
        );
      const walletRemainingUses = warmClaims.length
        ? Math.min(...warmClaims.map((claim) => Math.floor(Number(claim.remainingUses) || 0)))
        : undefined;
      const walletExpiresAtMs = warmClaims.length
        ? Math.min(...warmClaims.map((claim) => Math.floor(Number(claim.expiresAtMs) || 0)))
        : undefined;

      for (const entry of rawEntries) {
        if (terminal) {
          scoped.set(entry.lane.thresholdSessionId, {
            ...terminal,
            sessionId: entry.lane.thresholdSessionId,
          });
          continue;
        }
        if (entry.claim?.state === 'warm') {
          scoped.set(entry.lane.thresholdSessionId, {
            state: 'warm',
            sessionId: entry.lane.thresholdSessionId,
            remainingUses: walletRemainingUses ?? entry.claim.remainingUses,
            expiresAtMs: walletExpiresAtMs ?? entry.claim.expiresAtMs,
          });
          continue;
        }
        scoped.set(entry.lane.thresholdSessionId, entry.claim);
      }
    };
    if (applicableOverride) {
      const overrideClaim = claimFromSigningGrantStatusOverride(applicableOverride);
      const overrideEntries = entries.filter((entry) =>
        applicableOverride.thresholdSessionIds.has(
          normalizeNonEmpty(entry.lane.thresholdSessionId),
        ),
      );
      const rawEntries = entries.filter(
        (entry) =>
          !applicableOverride.thresholdSessionIds.has(
            normalizeNonEmpty(entry.lane.thresholdSessionId),
          ),
      );
      if (overrideEntries.length === entries.length) {
        for (const entry of entries) {
          scoped.set(
            entry.lane.thresholdSessionId,
            overrideClaim ? { ...overrideClaim, sessionId: entry.lane.thresholdSessionId } : null,
          );
        }
        continue;
      }
      for (const entry of overrideEntries) {
        scoped.set(
          entry.lane.thresholdSessionId,
          overrideClaim ? { ...overrideClaim, sessionId: entry.lane.thresholdSessionId } : null,
        );
      }
      applyRawScopedClaims(rawEntries);
      continue;
    }
    applyRawScopedClaims(entries);
  }
  return scoped;
}

function resolveApplicableSigningGrantStatusOverrideForGroup(args: {
  signingGrantId: string;
  lanes: DiscoveredSigningSessionLane[];
  claimsByThresholdSessionId: Map<string, WarmSessionPrfClaim | null>;
  statusOverrides?: Map<string, SigningGrantStatusOverride>;
}): SigningGrantStatusOverride | null {
  const statusOverrides = args.statusOverrides;
  if (!statusOverrides) return null;
  for (const owner of signingGrantStatusOverrideOwnersForLanes(args.lanes)) {
    const override = statusOverrides.get(
      walletOwnerSigningSessionStatusOverrideKey(owner, args.signingGrantId),
    );
    if (!override) continue;
    const applicable = resolveApplicableSigningGrantStatusOverride({
      override,
      lanes: args.lanes,
      claimsByThresholdSessionId: args.claimsByThresholdSessionId,
      statusOverrides,
    });
    if (applicable) return applicable;
  }
  return null;
}

function signingGrantStatusOverrideOwnersForLanes(
  lanes: DiscoveredSigningSessionLane[],
): WalletSessionStatusOwner[] {
  const ownersByKey = new Map<string, WalletSessionStatusOwner>();
  for (const lane of lanes) {
    const owner = resolveRuntimeWalletOwnerId(lane.runtime);
    ownersByKey.set(walletSessionStatusOwnerKey(owner), owner);
  }
  return [...ownersByKey.values()];
}

export function walletOwnerSigningSessionStatusOverrideKey(
  owner: WalletSessionStatusOwner,
  signingGrantId: string,
): string {
  return `${walletSessionStatusOwnerKey(owner)}:${normalizeNonEmpty(signingGrantId)}`;
}

function signingGrantStatusOverrideOwners(args: {
  owner: WalletSessionStatusOwner;
  lanes: DiscoveredSigningSessionLane[];
}): WalletSessionStatusOwner[] {
  const ownersByKey = new Map<string, WalletSessionStatusOwner>();
  ownersByKey.set(walletSessionStatusOwnerKey(args.owner), args.owner);
  for (const lane of args.lanes) {
    const owner = resolveRuntimeWalletOwnerId(lane.runtime);
    ownersByKey.set(walletSessionStatusOwnerKey(owner), owner);
  }
  return [...ownersByKey.values()];
}

export function rememberSigningGrantStatusOverride(args: {
  overrides: Map<string, SigningGrantStatusOverride>;
  owner: WalletSessionStatusOwner;
  signingGrantId: string;
  lanes: DiscoveredSigningSessionLane[];
  status: SigningSessionStatus;
}): void {
  const signingGrantId = normalizeNonEmpty(args.signingGrantId);
  if (!signingGrantId) return;
  const now = Date.now();
  const thresholdSessionIds = new Set(
    args.lanes.map((lane) => normalizeNonEmpty(lane.thresholdSessionId)).filter(Boolean),
  );
  for (const owner of signingGrantStatusOverrideOwners({
    owner: args.owner,
    lanes: args.lanes,
  })) {
    args.overrides.set(walletOwnerSigningSessionStatusOverrideKey(owner, signingGrantId), {
      owner,
      signingGrantId,
      status: {
        ...args.status,
        sessionId: signingGrantId,
      },
      thresholdSessionIds,
      updatedAtMs: now,
    });
  }
}

function resolveApplicableSigningGrantStatusOverride(args: {
  override: SigningGrantStatusOverride;
  lanes: DiscoveredSigningSessionLane[];
  claimsByThresholdSessionId: Map<string, WarmSessionPrfClaim | null>;
  statusOverrides?: Map<string, SigningGrantStatusOverride>;
}): SigningGrantStatusOverride | null {
  if (!args.lanes.length) return null;
  const freshActiveLane = args.lanes.find((lane) => {
    const thresholdSessionId = normalizeNonEmpty(lane.thresholdSessionId);
    if (args.override.thresholdSessionIds.has(thresholdSessionId)) return false;
    if (lane.runtime.sealedRecord.updatedAtMs <= args.override.updatedAtMs) return false;
    const claim = args.claimsByThresholdSessionId.get(thresholdSessionId) || null;
    return claim?.state === 'warm';
  });
  if (freshActiveLane) {
    for (const lane of args.lanes) {
      args.statusOverrides?.delete(
        walletOwnerSigningSessionStatusOverrideKey(
          resolveRuntimeWalletOwnerId(lane.runtime),
          args.override.signingGrantId,
        ),
      );
    }
    return null;
  }
  return args.override;
}

function claimFromSigningGrantStatusOverride(
  override: SigningGrantStatusOverride,
): WarmSessionPrfClaim | null {
  const status = override.status;
  if (status.status === 'active') {
    const remainingUses = Math.max(0, Math.floor(Number(status.remainingUses) || 0));
    const expiresAtMs = Math.floor(Number(status.expiresAtMs) || 0);
    if (expiresAtMs <= Date.now()) {
      return { state: 'expired', sessionId: override.signingGrantId };
    }
    if (remainingUses <= 0) {
      return { state: 'exhausted', sessionId: override.signingGrantId };
    }
    return {
      state: 'warm',
      sessionId: override.signingGrantId,
      remainingUses,
      expiresAtMs,
    };
  }
  if (status.status === 'expired') {
    return { state: 'expired', sessionId: override.signingGrantId };
  }
  if (status.status === 'exhausted') {
    return { state: 'exhausted', sessionId: override.signingGrantId };
  }
  if (status.status === 'unavailable') {
    return {
      state: 'unavailable',
      sessionId: override.signingGrantId,
      code: status.statusCode || 'wallet_budget_status_override',
    };
  }
  return null;
}

export async function readClaimsForLanes(args: {
  deps: SigningGrantClaimReaderDeps;
  lanes: DiscoveredSigningSessionLane[];
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const claims = new Map<string, WarmSessionPrfClaim | null>();
  for (const lane of args.lanes) {
    claims.set(
      lane.thresholdSessionId,
      warmClaimFromRecordPolicy({
        sessionId: lane.thresholdSessionId,
        remainingUses: lane.runtime.remainingUses,
        expiresAtMs: lane.runtime.expiresAtMs,
      }),
    );
  }
  return claims;
}

export async function readWalletScopedLaneClaimsForWallet(args: {
  deps: SigningGrantReadinessDeps;
  walletId: WalletId;
  statusOverrides?: Map<string, SigningGrantStatusOverride>;
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const lanes = await discoverLanesForWallet(args.deps, args.walletId);
  return readWalletScopedLaneClaimsForLanes({
    deps: args.deps,
    lanes,
    statusOverrides: args.statusOverrides,
  });
}

export async function readWalletScopedLaneClaimsForLanes(args: {
  deps: SigningGrantClaimReaderDeps;
  lanes: DiscoveredSigningSessionLane[];
  statusOverrides?: Map<string, SigningGrantStatusOverride>;
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const rawClaims = await readClaimsForLanes({ deps: args.deps, lanes: args.lanes });
  return walletScopedClaimsForLanes({
    lanes: args.lanes,
    claimsByThresholdSessionId: rawClaims,
    statusOverrides: args.statusOverrides,
  });
}

export async function readDirectSigningSessionStatusForTargets(args: {
  deps: SigningGrantReadinessDeps;
  signingGrantId: string;
  targetBackingMaterialSessionIds?: Iterable<string>;
  targetThresholdSessionIds?: Iterable<string>;
}): Promise<SigningSessionStatus | null> {
  const signingGrantId = normalizeNonEmpty(args.signingGrantId);
  if (!signingGrantId) return null;
  const targetSessionIds = Array.from(
    new Set(
      [...(args.targetBackingMaterialSessionIds || []), ...(args.targetThresholdSessionIds || [])]
        .map(normalizeNonEmpty)
        .filter(Boolean),
    ),
  );
  if (!targetSessionIds.length) return null;

  const touchConfirm = normalizeWarmSessionReadPorts(args.deps.touchConfirm);
  const claims = await Promise.all(
    targetSessionIds.map((sessionId) => readWarmSessionClaim(touchConfirm, sessionId)),
  );
  const claim =
    claims.find((candidate) => candidate?.state === 'expired') ||
    claims.find((candidate) => candidate?.state === 'exhausted') ||
    claims.find((candidate) => candidate?.state === 'unavailable') ||
    claims.find((candidate) => candidate?.state === 'warm') ||
    null;
  return toSigningSessionStatus({
    sessionId: signingGrantId,
    claim,
  });
}

export function statusFromClaim(args: {
  signingGrantId: string;
  lanes: DiscoveredSigningSessionLane[];
  claim: WarmSessionPrfClaim | null;
}): SigningSessionStatus {
  const hasEmailOtpLane = args.lanes.some(
    (lane) => lane.source === SIGNER_AUTH_METHODS.emailOtp,
  );
  return toSigningSessionStatus({
    sessionId: args.signingGrantId,
    claim: args.claim,
    authMethod: authMethodForSigningSessionLanes(args.lanes),
    retention: hasEmailOtpLane ? 'session' : null,
  });
}

export type SigningGrantClearFailure =
  | 'touch_confirm_material'
  | 'email_otp_material'
  | 'ecdsa_projection';

export type SigningGrantClearResult =
  | {
      readonly kind: 'cleared';
    }
  | {
      readonly kind: 'unavailable';
      readonly failures: readonly SigningGrantClearFailure[];
    };

export async function clearSigningGrant(args: {
  deps: SigningGrantReadinessDeps;
  statusOverrides: Map<string, SigningGrantStatusOverride>;
  walletId: WalletId;
  signingGrantId: string;
}): Promise<SigningGrantClearResult> {
  const lanes = await getLanesForWalletSession({
    deps: args.deps,
    walletId: args.walletId,
    signingGrantId: args.signingGrantId,
  });
  args.statusOverrides.delete(
    walletOwnerSigningSessionStatusOverrideKey(
      ed25519WalletSessionStatusOwner(args.walletId),
      args.signingGrantId,
    ),
  );
  const cleared = new Set<string>();
  const failures = new Set<SigningGrantClearFailure>();
  for (const lane of lanes) {
    if (cleared.has(lane.backingMaterialSessionId)) continue;
    cleared.add(lane.backingMaterialSessionId);
    if (lane.backing === 'record_policy') continue;
    if (lane.backing === 'email_otp_worker') {
      try {
        await args.deps.clearEmailOtpWarmSessionMaterial?.(lane.backingMaterialSessionId);
      } catch {
        failures.add('email_otp_material');
      }
      continue;
    }
    const volatileSessionId = parseVolatileWarmSessionId(lane.backingMaterialSessionId);
    if (!volatileSessionId) continue;
    try {
      await args.deps.touchConfirm?.clearVolatileWarmSessionMaterial?.(
        createClearVolatileWarmSessionMaterialCommand(volatileSessionId),
      );
    } catch {
      failures.add('touch_confirm_material');
    }
  }
  if (failures.size > 0) {
    return {
      kind: 'unavailable',
      failures: [...failures],
    };
  }
  return { kind: 'cleared' };
}

function expiredEd25519SealedPolicyExpiresAtMs(args: {
  lane: DiscoveredSigningSessionLane;
  statusExpiresAtMs: number;
  nowMs: number;
}): number {
  const laneExpiresAtMs = args.lane.runtime.expiresAtMs;
  return Math.min(
    args.nowMs,
    args.statusExpiresAtMs > 0 ? args.statusExpiresAtMs : args.nowMs,
    laneExpiresAtMs > 0 ? laneExpiresAtMs : args.nowMs,
  );
}

export async function syncSealedRefreshPolicyForLanes(args: {
  lanes: DiscoveredSigningSessionLane[];
  status: SigningSessionStatus;
  updatePolicy?: typeof updateExactSealedSessionPolicy;
}): Promise<void> {
  const seen = new Set<string>();
  const filterForLane = (
    lane: DiscoveredSigningSessionLane,
  ): SigningSessionSealedRecordFilter | null => {
    return { authMethod: lane.source, curve: 'ed25519' };
  };
  const sealedLanes = args.lanes
    .filter((lane) => lane.thresholdSessionId)
    .filter((lane) => Boolean(filterForLane(lane)))
    .filter((lane) => {
      const key = `${lane.source}:${lane.curve}:near:${lane.thresholdSessionId}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  if (!sealedLanes.length) return;
  const updatePolicy = args.updatePolicy;
  if (!updatePolicy) return;
  const remainingUses = Math.floor(Number(args.status.remainingUses) || 0);
  const expiresAtMs = Math.floor(Number(args.status.expiresAtMs) || 0);
  const nowMs = Date.now();
  const laneExpiresAtMs = Math.min(
    ...sealedLanes
      .map((lane) => lane.runtime.expiresAtMs)
      .filter((value) => value > 0),
  );
  const policyExpiresAtMs =
    expiresAtMs > 0
      ? expiresAtMs
      : Number.isFinite(laneExpiresAtMs) && laneExpiresAtMs > 0
        ? laneExpiresAtMs
        : 0;
  if (args.status.status === 'expired' || (expiresAtMs > 0 && expiresAtMs <= nowMs)) {
    await Promise.all(
      sealedLanes.map((lane) =>
        updatePolicy({
          thresholdSessionId: lane.thresholdSessionId,
          filter: filterForLane(lane)!,
          remainingUses,
          expiresAtMs: expiredEd25519SealedPolicyExpiresAtMs({
            lane,
            statusExpiresAtMs: expiresAtMs,
            nowMs,
          }),
          updatedAtMs: nowMs,
        }).catch(() => undefined),
      ),
    );
    return;
  }
  if (args.status.status !== 'active' || remainingUses <= 0) {
    if (policyExpiresAtMs <= nowMs) return;
    // Exhaustion is an authorization state, not a restore-identity lifecycle event.
    // Keep durable lane identity so the next command can select the exact
    // step-up auth lane after page reload or worker-memory loss.
    await Promise.all(
      sealedLanes.map((lane) =>
        updatePolicy({
          thresholdSessionId: lane.thresholdSessionId,
          filter: filterForLane(lane)!,
          remainingUses: 0,
          expiresAtMs: policyExpiresAtMs,
          updatedAtMs: Date.now(),
        }).catch(() => undefined),
      ),
    );
    return;
  }
  await Promise.all(
    sealedLanes.map((lane) =>
      updatePolicy({
        thresholdSessionId: lane.thresholdSessionId,
        filter: filterForLane(lane)!,
        remainingUses,
        expiresAtMs,
        updatedAtMs: Date.now(),
      }).catch(() => undefined),
    ),
  );
}
