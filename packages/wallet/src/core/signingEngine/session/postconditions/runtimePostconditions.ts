import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  AvailableSigningLanes,
  AvailableEd25519SigningLane,
  AvailableEcdsaSigningLane,
} from '../availability/availableSigningLanes';
import {
  availableEd25519SigningLaneAuthMethod,
  availableEcdsaSigningLaneAuthMethod,
} from '../availability/availableSigningLanes';
import { signingLaneAuthMethod, type OwnerLaneScope } from '../identity/signingLaneAuthBinding';
import type { SigningSessionSealAuthMethod } from '@shared/utils/signingSessionSeal';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { walletSessionAuthorizationIdForCurve } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';

export type RuntimePostconditionSource = 'registration_finalize' | 'wallet_unlock';

export type RuntimePostconditionTarget =
  | { curve: 'ed25519'; chainTarget?: never }
  | { curve: 'ecdsa'; chainTarget: ThresholdEcdsaChainTarget };

export type RuntimeLaneMaterial =
  | { kind: 'durable_sealed_record'; sourceChainTarget?: never }
  | { kind: 'runtime_session_record'; sourceChainTarget?: never }
  | { kind: 'public_capability_reference'; sourceChainTarget?: never }
  | { kind: 'canonical_capability'; sourceChainTarget?: never };

export type RuntimePostconditionLaneState = 'ready' | 'restorable';

export type UsableRuntimeLane =
  | {
      state: RuntimePostconditionLaneState;
      authMethod: SigningSessionSealAuthMethod;
      target: { curve: 'ed25519'; chainTarget?: never };
      walletSessionId: WalletSessionId;
      quotaId: MpcWalletSigningQuotaId;
      thresholdSessionId: string;
      remainingSignatureUses: number;
      expiresAtMs: number;
      material: RuntimeLaneMaterial;
    }
  | {
      state: RuntimePostconditionLaneState;
      authMethod: SigningSessionSealAuthMethod;
      target: { curve: 'ecdsa'; chainTarget: ThresholdEcdsaChainTarget };
      authorizationId: WalletSessionAuthorizationId;
      materialActivationId: string;
      remainingSignatureUses: number;
      expiresAtMs: number;
      material: RuntimeLaneMaterial;
    };

export type WalletRuntimeInventory = {
  walletId: string;
  authMethod: SigningSessionSealAuthMethod;
  ed25519?: UsableRuntimeLane;
  ecdsaByTarget: ReadonlyMap<string, UsableRuntimeLane>;
};

export type WalletRuntimePostconditionFailureCode =
  | 'wallet_missing'
  | 'auth_method_missing'
  | 'ed25519_lane_missing'
  | 'ecdsa_lane_missing'
  | 'lane_inventory_mismatch'
  | 'auth_method_route_mismatch'
  | 'lane_material_missing';

export type WalletRuntimePostconditionResult =
  | { ok: true; inventory: WalletRuntimeInventory }
  | {
      ok: false;
      code: WalletRuntimePostconditionFailureCode;
      details: Record<string, unknown>;
    };

/**
 * R103C: the postcondition read is owner-scoped at the source. The reader
 * already filtered to the exact owner authority and signer slot, so the
 * canonical aggregate lane IS the owner's one operational lane per curve.
 * There is nothing to search, rank, or repair here — a lane is usable,
 * missing, or evidence of a data-integrity failure.
 */
type ReadOwnerScopedSigningLanes = (args: {
  walletId: string | WalletId;
  ownerScope: OwnerLaneScope;
}) => Promise<AvailableSigningLanes>;

export class WalletRuntimePostconditionError extends Error {
  readonly code: WalletRuntimePostconditionFailureCode;
  readonly details: Record<string, unknown>;

  constructor(result: Extract<WalletRuntimePostconditionResult, { ok: false }>) {
    super(`[WalletRuntimePostcondition] ${result.code} ${JSON.stringify(result.details)}`);
    this.name = 'WalletRuntimePostconditionError';
    this.code = result.code;
    this.details = result.details;
  }
}

function positiveInteger(value: unknown): number | null {
  const normalized = Math.floor(Number(value));
  return Number.isFinite(normalized) && normalized > 0 ? normalized : null;
}

function futureEpochMs(value: unknown, nowMs: number): number | null {
  const normalized = Math.floor(Number(value));
  return Number.isFinite(normalized) && normalized > nowMs ? normalized : null;
}

function laneRemainingUses(value: {
  remainingUses?: number;
  policyHint?: { remainingUses?: number };
}): number | null {
  return positiveInteger(value.remainingUses ?? value.policyHint?.remainingUses);
}

function laneExpiresAtMs(
  value: { expiresAtMs?: number; policyHint?: { expiresAtMs?: number } },
  nowMs: number,
): number | null {
  return futureEpochMs(value.expiresAtMs ?? value.policyHint?.expiresAtMs, nowMs);
}

function ed25519LaneMaterial(lane: AvailableEd25519SigningLane): RuntimeLaneMaterial | null {
  if (lane.state === 'missing') return null;
  switch (lane.source) {
    case 'durable_sealed_record':
    case 'public_capability_reference':
      return { kind: lane.source };
    default:
      return null;
  }
}

function readReadyEd25519Lane(args: {
  lanes: AvailableSigningLanes;
  authMethod: SigningSessionSealAuthMethod;
  nowMs: number;
}): UsableRuntimeLane | WalletRuntimePostconditionFailureCode {
  const lane = args.lanes.lanes.ed25519.near;
  if (lane.state === 'missing') return 'ed25519_lane_missing';
  if (availableEd25519SigningLaneAuthMethod(lane) !== args.authMethod) {
    return 'auth_method_route_mismatch';
  }
  if (lane.state !== 'ready' && lane.state !== 'restorable') {
    return 'ed25519_lane_missing';
  }
  const remainingSignatureUses = laneRemainingUses(lane);
  const expiresAtMs = laneExpiresAtMs(lane, args.nowMs);
  if (
    lane.authorizationState !== 'authorized' ||
    !lane.authorization.walletSessionId ||
    !lane.authorization.quotaId ||
    !lane.thresholdSessionId ||
    !remainingSignatureUses ||
    !expiresAtMs
  ) {
    return 'lane_inventory_mismatch';
  }
  const material = ed25519LaneMaterial(lane);
  if (!material) return 'lane_material_missing';
  return {
    state: lane.state,
    authMethod: args.authMethod,
    target: { curve: 'ed25519' },
    walletSessionId: lane.authorization.walletSessionId,
    quotaId: lane.authorization.quotaId,
    thresholdSessionId: lane.thresholdSessionId,
    remainingSignatureUses,
    expiresAtMs,
    material,
  };
}

function readEcdsaUseCaseReadyLane(args: {
  lanes: AvailableSigningLanes;
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: SigningSessionSealAuthMethod;
  nowMs: number;
}): UsableRuntimeLane | WalletRuntimePostconditionFailureCode {
  const targetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  const lane: AvailableEcdsaSigningLane | undefined = args.lanes.ecdsa.lanesByTarget[targetKey];
  if (!lane || lane.state === 'missing') return 'ecdsa_lane_missing';
  if (availableEcdsaSigningLaneAuthMethod(lane) !== args.authMethod) {
    return 'auth_method_route_mismatch';
  }
  if (lane.state !== 'ready') return 'ecdsa_lane_missing';
  const remainingSignatureUses = laneRemainingUses(lane);
  const expiresAtMs = laneExpiresAtMs(lane, args.nowMs);
  if (!lane.authorization || !remainingSignatureUses || !expiresAtMs) {
    return 'lane_inventory_mismatch';
  }
  const authorizationId = walletSessionAuthorizationIdForCurve(
    lane.authorization.projection,
    'ecdsa',
  );
  if (!authorizationId) return 'lane_inventory_mismatch';
  return {
    state: lane.state,
    authMethod: args.authMethod,
    target: { curve: 'ecdsa', chainTarget: args.chainTarget },
    authorizationId,
    materialActivationId: String(lane.materialActivation.activationId),
    remainingSignatureUses,
    expiresAtMs,
    material: { kind: 'canonical_capability' },
  };
}

export async function readWalletRuntimePostconditions(args: {
  source: RuntimePostconditionSource;
  walletId: string | WalletId;
  ownerScope: OwnerLaneScope;
  requiredTargets: readonly RuntimePostconditionTarget[];
  readOwnerScopedSigningLanes: ReadOwnerScopedSigningLanes;
  nowMs?: number;
}): Promise<WalletRuntimePostconditionResult> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) {
    return { ok: false, code: 'wallet_missing', details: { source: args.source } };
  }
  const authMethod = signingLaneAuthMethod(args.ownerScope.auth);
  const lanes = await args.readOwnerScopedSigningLanes({
    walletId,
    ownerScope: args.ownerScope,
  });
  const nowMs = args.nowMs ?? Date.now();
  let ed25519: UsableRuntimeLane | undefined;
  const ecdsaByTarget = new Map<string, UsableRuntimeLane>();
  for (const target of args.requiredTargets) {
    if (target.curve === 'ed25519') {
      const readyLane = readReadyEd25519Lane({ lanes, authMethod, nowMs });
      if (typeof readyLane === 'string') {
        return {
          ok: false,
          code: readyLane,
          details: {
            source: args.source,
            walletId,
            authMethod,
            curve: 'ed25519',
            state: lanes.lanes.ed25519.near.state,
            candidateCount: lanes.candidates.ed25519.near.length,
          },
        };
      }
      ed25519 = readyLane;
      continue;
    }
    const readyLane = readEcdsaUseCaseReadyLane({
      lanes,
      chainTarget: target.chainTarget,
      authMethod,
      nowMs,
    });
    if (typeof readyLane === 'string') {
      const targetKey = thresholdEcdsaChainTargetKey(target.chainTarget);
      return {
        ok: false,
        code: readyLane,
        details: {
          source: args.source,
          walletId,
          authMethod,
          curve: 'ecdsa',
          targetKey,
          state: lanes.ecdsa.lanesByTarget[targetKey]?.state || 'missing',
          candidateCount: lanes.ecdsa.candidatesByTarget[targetKey]?.length || 0,
        },
      };
    }
    ecdsaByTarget.set(thresholdEcdsaChainTargetKey(target.chainTarget), readyLane);
  }
  return {
    ok: true,
    inventory: {
      walletId,
      authMethod,
      ...(ed25519 ? { ed25519 } : {}),
      ecdsaByTarget,
    },
  };
}

function laneMaterialShape(lane: UsableRuntimeLane): string {
  return lane.material.kind;
}

function compareReadyLaneShape(args: {
  left: UsableRuntimeLane | undefined;
  right: UsableRuntimeLane | undefined;
  label: string;
}): WalletRuntimePostconditionResult | null {
  if (!args.left && !args.right) return null;
  if (!args.left || !args.right) {
    return {
      ok: false,
      code: 'lane_inventory_mismatch',
      details: {
        lane: args.label,
        leftPresent: Boolean(args.left),
        rightPresent: Boolean(args.right),
      },
    };
  }
  const leftTarget =
    args.left.target.curve === 'ecdsa'
      ? thresholdEcdsaChainTargetKey(args.left.target.chainTarget)
      : 'near';
  const rightTarget =
    args.right.target.curve === 'ecdsa'
      ? thresholdEcdsaChainTargetKey(args.right.target.chainTarget)
      : 'near';
  if (
    args.left.authMethod !== args.right.authMethod ||
    args.left.target.curve !== args.right.target.curve ||
    leftTarget !== rightTarget ||
    laneMaterialShape(args.left) !== laneMaterialShape(args.right)
  ) {
    return {
      ok: false,
      code: 'lane_inventory_mismatch',
      details: {
        lane: args.label,
        leftAuthMethod: args.left.authMethod,
        rightAuthMethod: args.right.authMethod,
        leftCurve: args.left.target.curve,
        rightCurve: args.right.target.curve,
        leftTarget,
        rightTarget,
        leftMaterial: laneMaterialShape(args.left),
        rightMaterial: laneMaterialShape(args.right),
      },
    };
  }
  return null;
}

export function compareWalletRuntimeInventories(args: {
  registration: WalletRuntimeInventory;
  unlock: WalletRuntimeInventory;
}): WalletRuntimePostconditionResult {
  if (args.registration.walletId !== args.unlock.walletId) {
    return {
      ok: false,
      code: 'wallet_missing',
      details: {
        registrationWalletId: args.registration.walletId,
        unlockWalletId: args.unlock.walletId,
      },
    };
  }
  if (args.registration.authMethod !== args.unlock.authMethod) {
    return {
      ok: false,
      code: 'auth_method_route_mismatch',
      details: {
        registrationAuthMethod: args.registration.authMethod,
        unlockAuthMethod: args.unlock.authMethod,
      },
    };
  }
  const ed25519Mismatch = compareReadyLaneShape({
    left: args.registration.ed25519,
    right: args.unlock.ed25519,
    label: 'ed25519:near',
  });
  if (ed25519Mismatch) return ed25519Mismatch;

  const registrationTargets = [...args.registration.ecdsaByTarget.keys()].sort();
  const unlockTargets = [...args.unlock.ecdsaByTarget.keys()].sort();
  if (registrationTargets.join('|') !== unlockTargets.join('|')) {
    return {
      ok: false,
      code: 'lane_inventory_mismatch',
      details: { registrationTargets, unlockTargets },
    };
  }
  for (const targetKey of registrationTargets) {
    const ecdsaMismatch = compareReadyLaneShape({
      left: args.registration.ecdsaByTarget.get(targetKey),
      right: args.unlock.ecdsaByTarget.get(targetKey),
      label: `ecdsa:${targetKey}`,
    });
    if (ecdsaMismatch) return ecdsaMismatch;
  }
  return { ok: true, inventory: args.registration };
}

export async function assertWalletRuntimePostconditions(args: {
  source: RuntimePostconditionSource;
  walletId: string | WalletId;
  ownerScope: OwnerLaneScope;
  requiredTargets: readonly RuntimePostconditionTarget[];
  readOwnerScopedSigningLanes: ReadOwnerScopedSigningLanes;
  nowMs?: number;
}): Promise<WalletRuntimeInventory> {
  const result = await readWalletRuntimePostconditions(args);
  if (!result.ok) throw new WalletRuntimePostconditionError(result);
  return result.inventory;
}
