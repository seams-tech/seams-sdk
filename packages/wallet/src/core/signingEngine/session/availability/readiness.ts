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
import { parseThresholdEd25519SessionId } from '@shared/utils/domainIds';
import type {
  WarmSessionExhaustedPrfClaim,
  WarmSessionExpiredPrfClaim,
  WarmSessionMissingPrfClaim,
  WarmSessionPrfClaim,
  WarmSessionUnavailablePrfClaim,
  WarmSessionWarmPrfClaim,
} from '../warmCapabilities/types';
import {
  parseExactEd25519SealedSessionRuntime,
  type ExactEd25519SealedSessionRuntime,
} from '../warmCapabilities/ed25519SealedSessionRuntime';
import type { ActiveWalletSessionV1 } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import { resolveWalletAuthorityOperation } from '../public.ts';
import type { ExactWalletSessionReadPorts } from '../identity/exactWalletSessionCredential';
import {
  normalizeWarmSessionReadPorts,
  readWarmSessionClaim,
  toSigningSessionStatus,
  type WarmSessionReadPortsInput,
} from '../warmCapabilities/readModel';
import {
  ed25519WalletSessionStatusOwner,
  normalizeSessionStatusRequired,
  walletSessionStatusOwnerKey,
  walletSessionStatusIdentityKey,
  type WalletSessionStatusOwner,
} from '../lifecycle/walletSessionStatus';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type {
  Ed25519SigningSessionReadiness,
} from '../planning/planner';
import type { ThresholdEd25519SessionId } from '../operationState/types';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type SigningSessionLane = {
  curve: 'ed25519';
  chain: 'near';
  source: SignerAuthMethod;
  thresholdSessionId: string;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  materialActivation: MpcMaterialActivationRef;
};

export type DiscoveredSigningSessionLane = SigningSessionLane & {
  runtime: ExactEd25519SealedSessionRuntime;
  backing: 'touch_confirm' | 'email_otp_worker' | 'record_policy';
};

export type WalletSessionStatusOverride = {
  owner: WalletSessionStatusOwner;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  status: SigningSessionStatus;
  thresholdSessionIds: Set<string>;
  updatedAtMs: number;
};

export type WalletSessionReadinessDeps = {
  exactWalletSessionReadPorts: ExactWalletSessionReadPorts;
  listExactSealedSessionsForWallet?: typeof listExactSealedSessionsForWallet;
  touchConfirm?: Partial<
    Pick<
      VolatileWarmMaterialPort,
      | 'getWarmSessionStatus'
      | 'getWarmSessionStatuses'
      | 'clearVolatileWarmSessionMaterial'
    >
  >;
  getEmailOtpWarmSessionStatus?: (thresholdSessionId: string) => Promise<WarmSessionStatusResult>;
  clearEmailOtpWarmSessionMaterial?: (thresholdSessionId: string) => Promise<void>;
};

export type WalletSessionClaimReaderDeps = {
  touchConfirm?: WarmSessionReadPortsInput;
  getEmailOtpWarmSessionStatus?: (thresholdSessionId: string) => Promise<WarmSessionStatusResult>;
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
  thresholdSessionId: string;
  remainingUses: number;
  expiresAtMs: number;
}): WarmSessionPrfClaim {
  const thresholdSessionId = normalizeNonEmpty(args.thresholdSessionId);
  const remainingUses = Math.max(0, Math.floor(Number(args.remainingUses) || 0));
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  if (expiresAtMs <= Date.now()) return { state: 'expired', thresholdSessionId };
  if (remainingUses <= 0) return { state: 'exhausted', thresholdSessionId };
  return {
    state: 'warm',
    thresholdSessionId,
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
  if (!lane.thresholdSessionId || !lane.walletSessionId) {
    return;
  }
  lanes.push(lane);
}

export function buildDiscoveredLaneForRuntime(
  runtime: ExactEd25519SealedSessionRuntime,
  walletSessionId: WalletSessionId,
  quotaId: MpcWalletSigningQuotaId,
): DiscoveredSigningSessionLane {
  return {
    curve: 'ed25519',
    chain: 'near',
    source: toLaneSource(runtime),
    thresholdSessionId: runtime.thresholdSessionId,
    walletSessionId,
    quotaId,
    materialActivation: runtime.sealedRecord.ed25519Restore.materialActivation,
    backing: 'record_policy',
    runtime,
  };
}

export async function discoverLanesForWallet(
  deps: WalletSessionReadinessDeps,
  walletId: WalletId,
): Promise<DiscoveredSigningSessionLane[]> {
  return await discoverLanesForWalletWithExactAuthorization(
    deps,
    walletId,
    deps.exactWalletSessionReadPorts,
  );
}

function exactEd25519SignSubjectMatches(
  authorization: ActiveWalletSessionV1,
  materialActivation: MpcMaterialActivationRef,
): boolean {
  return authorization.capabilitySubjects.some(
    (subject) =>
      subject.kind === 'sign' &&
      subject.keyFamily === 'ed25519' &&
      mpcMaterialActivationRefsEqual(subject.materialActivation, materialActivation),
  );
}

function selectedMethodMatchesRuntime(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  authMethod: Extract<
    ResolveSelectedWalletAuthorityResultV1,
    { readonly kind: 'resolved' }
  >['authMethod'];
}): boolean {
  switch (args.runtime.factor.kind) {
    case 'passkey':
      return (
        args.authMethod.kind === 'passkey' &&
        String(args.authMethod.rpId) === String(args.runtime.factor.rpId) &&
        String(args.authMethod.credentialIdB64u) === String(args.runtime.factor.credentialIdB64u)
      );
    case 'email_otp':
      return (
        args.authMethod.kind === 'email_otp' &&
        args.authMethod.emailHashHex === args.runtime.factor.emailHashHex
      );
  }
}

async function discoverLanesForWalletWithExactAuthorization(
  deps: WalletSessionReadinessDeps,
  walletId: WalletId,
  resolver: ExactWalletSessionReadPorts,
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
  let selected: ResolveSelectedWalletAuthorityResultV1;
  try {
    selected = await resolver.resolveSelectedWalletAuthority(String(walletId));
  } catch {
    return [];
  }
  if (selected.kind !== 'resolved') return [];
  const { selection, authMethod, authority } = selected;
  if (
    selection.lockState !== 'unlocked' ||
    selection.walletId !== walletId ||
    selection.walletAuthMethodId !== authMethod.walletAuthMethodId ||
    authMethod.status !== 'active' ||
    authMethod.walletId !== walletId ||
    authMethod.walletAuthorityId !== authority.authorityId ||
    authority.state !== 'active' ||
    authority.walletId !== walletId
  ) {
    return [];
  }
  let operation: Awaited<ReturnType<typeof resolveWalletAuthorityOperation>>;
  try {
    operation = await resolveWalletAuthorityOperation({
      selected: { authMethod, authority },
      operation: { kind: 'near_sign', operation: 'sign', keyFamily: 'ed25519' },
    });
  } catch {
    return [];
  }
  if (
    operation.kind !== 'resolved' ||
    operation.value.walletId !== walletId ||
    operation.value.authorityId !== authority.authorityId ||
    operation.value.authMethodId !== authMethod.walletAuthMethodId
  ) {
    return [];
  }
  let authorizationRead: Awaited<
    ReturnType<ExactWalletSessionReadPorts['readExactWithOperationCredential']>
  >;
  try {
    authorizationRead = await resolver.readExactWithOperationCredential({
      walletId,
      authorityId: authority.authorityId,
      authMethodId: authMethod.walletAuthMethodId,
    });
  } catch {
    return [];
  }
  if (authorizationRead.kind !== 'found') return [];
  const authorization = authorizationRead.record;
  const operationCredential = authorizationRead.operationCredential;
  if (
    authorization.walletId !== walletId ||
    authorization.authorityId !== authority.authorityId ||
    authorization.authMethodId !== authMethod.walletAuthMethodId ||
    authorization.authorityDigestB64u !== authority.authorityDigestB64u ||
    authorization.authorityRevocationEpoch !== authority.revocationEpoch ||
    authorization.expiresAtMs <= Date.now() ||
    operationCredential.walletSessionId.length === 0 ||
    operationCredential.token.trim().length === 0 ||
    !exactEd25519SignSubjectMatches(authorization, operation.value.materialActivation)
  ) {
    return [];
  }
  const lanes: DiscoveredSigningSessionLane[] = [];
  const seenThresholdSessionIds = new Set<string>();
  for (const record of records) {
    if (record.curve !== 'ed25519') continue;
    const runtime = parseExactEd25519SealedSessionRuntime(record);
    if (!runtime || runtime.walletId !== walletId) continue;
    if (
      !selectedMethodMatchesRuntime({ runtime, authMethod }) ||
      !mpcMaterialActivationRefsEqual(
        runtime.sealedRecord.ed25519Restore.materialActivation,
        operation.value.materialActivation,
      )
    ) {
      continue;
    }
    if (seenThresholdSessionIds.has(runtime.thresholdSessionId)) continue;
    seenThresholdSessionIds.add(runtime.thresholdSessionId);
    addLane(
      lanes,
      buildDiscoveredLaneForRuntime(
        runtime,
        operationCredential.walletSessionId,
        authorization.quotaId,
      ),
    );
  }
  return lanes;
}

export async function getLanesForWalletSession(args: {
  deps: WalletSessionReadinessDeps;
  walletId: WalletId;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
}): Promise<DiscoveredSigningSessionLane[]> {
  const walletSessionId = normalizeSessionStatusRequired(args.walletSessionId, 'walletSessionId');
  return (await discoverLanesForWallet(args.deps, args.walletId)).filter(
    (lane) => lane.walletSessionId === walletSessionId && lane.quotaId === args.quotaId,
  );
}

export function walletScopedClaimsForLanes(args: {
  lanes: DiscoveredSigningSessionLane[];
  claimsByThresholdSessionId: Map<string, WarmSessionPrfClaim | null>;
  statusOverrides?: Map<string, WalletSessionStatusOverride>;
}): Map<string, WarmSessionPrfClaim | null> {
  const grouped = new Map<string, DiscoveredSigningSessionLane[]>();
  for (const lane of args.lanes) {
    const groupKey = walletSessionStatusIdentityKey({
      walletSessionId: lane.walletSessionId,
      quotaId: lane.quotaId,
    });
    const group = grouped.get(groupKey) || [];
    group.push(lane);
    grouped.set(groupKey, group);
  }

  const scoped = new Map<string, WarmSessionPrfClaim | null>();
  for (const group of grouped.values()) {
    const firstLane = group[0];
    if (!firstLane) continue;
    const walletSessionId = firstLane.walletSessionId;
    const quotaId = firstLane.quotaId;
    const applicableOverride = resolveApplicableWalletSessionStatusOverrideForGroup({
      walletSessionId,
      quotaId,
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
          scoped.set(
            entry.lane.thresholdSessionId,
            attachWarmClaimToThresholdSession(terminal, entry.lane.thresholdSessionId),
          );
          continue;
        }
        if (entry.claim?.state === 'warm') {
          scoped.set(entry.lane.thresholdSessionId, {
            state: 'warm',
            thresholdSessionId: entry.lane.thresholdSessionId,
            remainingUses: walletRemainingUses ?? entry.claim.remainingUses,
            expiresAtMs: walletExpiresAtMs ?? entry.claim.expiresAtMs,
          });
          continue;
        }
        scoped.set(entry.lane.thresholdSessionId, entry.claim);
      }
    };
    if (applicableOverride) {
      const overrideClaim = claimFromWalletSessionStatusOverride(applicableOverride);
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
            overrideClaim
              ? attachWarmClaimToThresholdSession(
                  overrideClaim,
                  entry.lane.thresholdSessionId,
                )
              : null,
          );
        }
        continue;
      }
      for (const entry of overrideEntries) {
        scoped.set(
          entry.lane.thresholdSessionId,
          overrideClaim
            ? attachWarmClaimToThresholdSession(overrideClaim, entry.lane.thresholdSessionId)
            : null,
        );
      }
      applyRawScopedClaims(rawEntries);
      continue;
    }
    applyRawScopedClaims(entries);
  }
  return scoped;
}

function resolveApplicableWalletSessionStatusOverrideForGroup(args: {
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  lanes: DiscoveredSigningSessionLane[];
  claimsByThresholdSessionId: Map<string, WarmSessionPrfClaim | null>;
  statusOverrides?: Map<string, WalletSessionStatusOverride>;
}): WalletSessionStatusOverride | null {
  const statusOverrides = args.statusOverrides;
  if (!statusOverrides) return null;
  for (const owner of walletSessionStatusOverrideOwnersForLanes(args.lanes)) {
    const override = statusOverrides.get(
      walletOwnerSigningSessionStatusOverrideKey(owner, args.walletSessionId, args.quotaId),
    );
    if (!override) continue;
    const applicable = resolveApplicableWalletSessionStatusOverride({
      override,
      lanes: args.lanes,
      claimsByThresholdSessionId: args.claimsByThresholdSessionId,
      statusOverrides,
    });
    if (applicable) return applicable;
  }
  return null;
}

function walletSessionStatusOverrideOwnersForLanes(
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
  walletSessionId: WalletSessionId,
  quotaId: MpcWalletSigningQuotaId,
): string {
  return `${walletSessionStatusOwnerKey(owner)}:${walletSessionStatusIdentityKey({
    walletSessionId,
    quotaId,
  })}`;
}

function walletSessionStatusOverrideOwners(args: {
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

export function rememberWalletSessionStatusOverride(args: {
  overrides: Map<string, WalletSessionStatusOverride>;
  owner: WalletSessionStatusOwner;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  lanes: DiscoveredSigningSessionLane[];
  status: SigningSessionStatus;
}): void {
  const walletSessionId = args.walletSessionId;
  const now = Date.now();
  const thresholdSessionIds = new Set(
    args.lanes.map((lane) => normalizeNonEmpty(lane.thresholdSessionId)).filter(Boolean),
  );
  for (const owner of walletSessionStatusOverrideOwners({
    owner: args.owner,
    lanes: args.lanes,
  })) {
    args.overrides.set(
      walletOwnerSigningSessionStatusOverrideKey(owner, walletSessionId, args.quotaId),
      {
        owner,
        walletSessionId,
        quotaId: args.quotaId,
        status: {
          ...args.status,
          sessionId: walletSessionId,
        },
        thresholdSessionIds,
        updatedAtMs: now,
      },
    );
  }
}

function resolveApplicableWalletSessionStatusOverride(args: {
  override: WalletSessionStatusOverride;
  lanes: DiscoveredSigningSessionLane[];
  claimsByThresholdSessionId: Map<string, WarmSessionPrfClaim | null>;
  statusOverrides?: Map<string, WalletSessionStatusOverride>;
}): WalletSessionStatusOverride | null {
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
          args.override.walletSessionId,
          args.override.quotaId,
        ),
      );
    }
    return null;
  }
  return args.override;
}

type WarmSessionPrfClaimWithoutThresholdSessionId =
  | Omit<WarmSessionWarmPrfClaim, 'thresholdSessionId'>
  | Omit<WarmSessionUnavailablePrfClaim, 'thresholdSessionId'>
  | Omit<WarmSessionMissingPrfClaim, 'thresholdSessionId'>
  | Omit<WarmSessionExpiredPrfClaim, 'thresholdSessionId'>
  | Omit<WarmSessionExhaustedPrfClaim, 'thresholdSessionId'>;

function claimFromWalletSessionStatusOverride(
  override: WalletSessionStatusOverride,
): WarmSessionPrfClaimWithoutThresholdSessionId | null {
  const status = override.status;
  if (status.status === 'active') {
    if (
      typeof status.remainingUses !== 'number' ||
      typeof status.expiresAtMs !== 'number'
    ) {
      return { state: 'unavailable', code: 'invalid_wallet_budget_status' };
    }
    const remainingUses = Math.max(0, Math.floor(Number(status.remainingUses) || 0));
    const expiresAtMs = Math.floor(Number(status.expiresAtMs) || 0);
    if (expiresAtMs <= Date.now()) {
      return { state: 'expired' };
    }
    if (remainingUses <= 0) {
      return { state: 'exhausted' };
    }
    return {
      state: 'warm',
      remainingUses,
      expiresAtMs,
    };
  }
  if (status.status === 'expired') {
    return { state: 'expired' };
  }
  if (status.status === 'exhausted') {
    return { state: 'exhausted' };
  }
  if (status.status === 'unavailable') {
    return {
      state: 'unavailable',
      code: String(status.statusCode || 'wallet_budget_status_override'),
    };
  }
  return null;
}

export async function readClaimsForLanes(args: {
  deps: WalletSessionClaimReaderDeps;
  lanes: DiscoveredSigningSessionLane[];
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const claims = new Map<string, WarmSessionPrfClaim | null>();
  for (const lane of args.lanes) {
    claims.set(
      lane.thresholdSessionId,
      warmClaimFromRecordPolicy({
        thresholdSessionId: lane.thresholdSessionId,
        remainingUses: lane.runtime.remainingUses,
        expiresAtMs: lane.runtime.expiresAtMs,
      }),
    );
  }
  return claims;
}

function attachWarmClaimToThresholdSession(
  claim: WarmSessionPrfClaim | WarmSessionPrfClaimWithoutThresholdSessionId,
  thresholdSessionId: string,
): WarmSessionPrfClaim {
  switch (claim.state) {
    case 'warm':
      return {
        state: 'warm',
        thresholdSessionId,
        remainingUses: claim.remainingUses,
        expiresAtMs: claim.expiresAtMs,
      };
    case 'unavailable':
      return { state: 'unavailable', thresholdSessionId, code: claim.code };
    case 'missing':
      return { state: 'missing', thresholdSessionId };
    case 'expired':
      return { state: 'expired', thresholdSessionId };
    case 'exhausted':
      return { state: 'exhausted', thresholdSessionId };
  }
}

export async function readWalletScopedLaneClaimsForWallet(args: {
  deps: WalletSessionReadinessDeps;
  walletId: WalletId;
  statusOverrides?: Map<string, WalletSessionStatusOverride>;
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const lanes = await discoverLanesForWallet(args.deps, args.walletId);
  return readWalletScopedLaneClaimsForLanes({
    deps: args.deps,
    lanes,
    statusOverrides: args.statusOverrides,
  });
}

export async function readWalletScopedLaneClaimsForLanes(args: {
  deps: WalletSessionClaimReaderDeps;
  lanes: DiscoveredSigningSessionLane[];
  statusOverrides?: Map<string, WalletSessionStatusOverride>;
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const rawClaims = await readClaimsForLanes({ deps: args.deps, lanes: args.lanes });
  return walletScopedClaimsForLanes({
    lanes: args.lanes,
    claimsByThresholdSessionId: rawClaims,
    statusOverrides: args.statusOverrides,
  });
}

export async function readDirectSigningSessionStatusForTargets(args: {
  deps: WalletSessionReadinessDeps;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  targetThresholdSessionIds?: Iterable<string>;
}): Promise<SigningSessionStatus | null> {
  const walletSessionId = args.walletSessionId;
  const targetThresholdSessionIds = Array.from(
    new Set(
      [...(args.targetThresholdSessionIds || [])]
        .map(normalizeNonEmpty)
        .filter(Boolean),
    ),
  );
  if (!targetThresholdSessionIds.length) return null;

  const touchConfirm = normalizeWarmSessionReadPorts(args.deps.touchConfirm);
  const claims = await Promise.all(
    targetThresholdSessionIds.map((thresholdSessionId) =>
      readWarmSessionClaim(touchConfirm, thresholdSessionId),
    ),
  );
  const claim =
    claims.find((candidate) => candidate?.state === 'expired') ||
    claims.find((candidate) => candidate?.state === 'exhausted') ||
    claims.find((candidate) => candidate?.state === 'unavailable') ||
    claims.find((candidate) => candidate?.state === 'warm') ||
    null;
  return toSigningSessionStatus({
    sessionId: walletSessionId,
    claim,
  });
}

export function statusFromClaim(args: {
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  lanes: DiscoveredSigningSessionLane[];
  claim: WarmSessionPrfClaim | null;
}): SigningSessionStatus {
  const hasEmailOtpLane = args.lanes.some(
    (lane) => lane.source === SIGNER_AUTH_METHODS.emailOtp,
  );
  return toSigningSessionStatus({
    sessionId: args.walletSessionId,
    claim: args.claim,
    authMethod: authMethodForSigningSessionLanes(args.lanes),
    retention: hasEmailOtpLane ? 'session' : null,
  });
}

export type WalletSessionClearFailure =
  | 'touch_confirm_material'
  | 'email_otp_material'
  | 'wallet_session_authorization';

export type WalletSessionClearResult =
  | {
      readonly kind: 'cleared';
    }
  | {
      readonly kind: 'unavailable';
      readonly failures: readonly WalletSessionClearFailure[];
    };

export async function clearWalletSession(args: {
  deps: WalletSessionReadinessDeps;
  statusOverrides: Map<string, WalletSessionStatusOverride>;
  walletId: WalletId;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
}): Promise<WalletSessionClearResult> {
  const lanes = await getLanesForWalletSession({
    deps: args.deps,
    walletId: args.walletId,
    walletSessionId: args.walletSessionId,
    quotaId: args.quotaId,
  });
  args.statusOverrides.delete(
    walletOwnerSigningSessionStatusOverrideKey(
      ed25519WalletSessionStatusOwner(args.walletId),
      args.walletSessionId,
      args.quotaId,
    ),
  );
  const cleared = new Set<string>();
  const failures = new Set<WalletSessionClearFailure>();
  for (const lane of lanes) {
    if (lane.backing === 'record_policy') continue;
    const materialActivationId = String(lane.materialActivation.activationId);
    if (cleared.has(materialActivationId)) continue;
    cleared.add(materialActivationId);
    if (lane.backing === 'email_otp_worker') {
      try {
        await args.deps.clearEmailOtpWarmSessionMaterial?.(lane.thresholdSessionId);
      } catch {
        failures.add('email_otp_material');
      }
      continue;
    }
    const thresholdSessionId = parseThresholdEd25519SessionId(lane.thresholdSessionId);
    if (!thresholdSessionId.ok) continue;
    try {
      await args.deps.touchConfirm?.clearVolatileWarmSessionMaterial?.(
        createClearVolatileWarmSessionMaterialCommand(thresholdSessionId.value),
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
