import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  AvailableSigningLanes,
  ConcreteAvailableEcdsaSigningLane,
  ConcreteAvailableEd25519SigningLane,
} from '../availability/availableSigningLanes';

export type RuntimePostconditionSource = 'registration_finalize' | 'wallet_unlock';
export type RuntimePostconditionAuthMethod = 'email_otp' | 'passkey';

export type RuntimePostconditionTarget =
  | { curve: 'ed25519'; chainTarget?: never }
  | { curve: 'ecdsa'; chainTarget: ThresholdEcdsaChainTarget };

export type RuntimeLaneMaterial =
  | { kind: 'durable_sealed_record'; sourceChainTarget?: never }
  | { kind: 'runtime_session_record'; sourceChainTarget?: never }
  | { kind: 'runtime_and_durable'; sourceChainTarget?: never }
  | { kind: 'evm_family_shared_key'; sourceChainTarget: ThresholdEcdsaChainTarget };

export type ReadyRuntimeLane =
  | {
      state: 'ready';
      authMethod: RuntimePostconditionAuthMethod;
      target: { curve: 'ed25519'; chainTarget?: never };
      walletSigningSessionId: string;
      thresholdSessionId: string;
      remainingSignatureUses: number;
      expiresAtMs: number;
      material: RuntimeLaneMaterial;
    }
  | {
      state: 'ready';
      authMethod: RuntimePostconditionAuthMethod;
      target: { curve: 'ecdsa'; chainTarget: ThresholdEcdsaChainTarget };
      walletSigningSessionId: string;
      thresholdSessionId: string;
      remainingSignatureUses: number;
      expiresAtMs: number;
      material: RuntimeLaneMaterial;
    };

export type WalletRuntimeInventory = {
  walletId: string;
  authMethod: RuntimePostconditionAuthMethod;
  ed25519?: ReadyRuntimeLane;
  ecdsaByTarget: ReadonlyMap<string, ReadyRuntimeLane>;
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

type ReadPersistedAvailableSigningLanes = (args: {
  walletId: string | WalletId;
  authMethod: RuntimePostconditionAuthMethod;
}) => Promise<AvailableSigningLanes>;

export class WalletRuntimePostconditionError extends Error {
  readonly code: WalletRuntimePostconditionFailureCode;
  readonly details: Record<string, unknown>;

  constructor(result: Extract<WalletRuntimePostconditionResult, { ok: false }>) {
    super(`[WalletRuntimePostcondition] ${result.code}`);
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

function ecdsaMaterialForLane(lane: ConcreteAvailableEcdsaSigningLane): RuntimeLaneMaterial | null {
  if (lane.source === 'evm_family_shared_key') {
    return { kind: 'evm_family_shared_key', sourceChainTarget: lane.sourceChainTarget };
  }
  if (
    lane.source === 'durable_sealed_record' ||
    lane.source === 'runtime_session_record' ||
    lane.source === 'runtime_and_durable'
  ) {
    return { kind: lane.source };
  }
  return null;
}

function ed25519MaterialForLane(
  lane: ConcreteAvailableEd25519SigningLane,
): RuntimeLaneMaterial | null {
  if (
    lane.source === 'durable_sealed_record' ||
    lane.source === 'runtime_session_record' ||
    lane.source === 'runtime_and_durable'
  ) {
    return { kind: lane.source };
  }
  return null;
}

function readReadyEd25519Lane(args: {
  lane: AvailableSigningLanes['lanes']['ed25519']['near'];
  authMethod: RuntimePostconditionAuthMethod;
  nowMs: number;
}): ReadyRuntimeLane | WalletRuntimePostconditionFailureCode {
  const lane = args.lane;
  if (lane.state === 'missing') return 'ed25519_lane_missing';
  if (lane.authMethod !== args.authMethod) return 'auth_method_route_mismatch';
  if (lane.state !== 'ready') return 'ed25519_lane_missing';
  const remainingSignatureUses = positiveInteger(lane.remainingUses);
  const expiresAtMs = futureEpochMs(lane.expiresAtMs, args.nowMs);
  if (!lane.walletSigningSessionId || !lane.thresholdSessionId || !remainingSignatureUses || !expiresAtMs) {
    return 'lane_inventory_mismatch';
  }
  const material = ed25519MaterialForLane(lane);
  if (!material) return 'lane_material_missing';
  return {
    state: 'ready',
    authMethod: args.authMethod,
    target: { curve: 'ed25519' },
    walletSigningSessionId: lane.walletSigningSessionId,
    thresholdSessionId: lane.thresholdSessionId,
    remainingSignatureUses,
    expiresAtMs,
    material,
  };
}

function readReadyEcdsaLane(args: {
  lanes: AvailableSigningLanes;
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: RuntimePostconditionAuthMethod;
  nowMs: number;
}): ReadyRuntimeLane | WalletRuntimePostconditionFailureCode {
  const targetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  const lane = args.lanes.ecdsa.lanesByTarget[targetKey];
  if (!lane || lane.state === 'missing') return 'ecdsa_lane_missing';
  if (lane.authMethod !== args.authMethod) return 'auth_method_route_mismatch';
  if (lane.state !== 'ready') return 'ecdsa_lane_missing';
  const remainingSignatureUses = positiveInteger(lane.remainingUses);
  const expiresAtMs = futureEpochMs(lane.expiresAtMs, args.nowMs);
  if (!lane.walletSigningSessionId || !lane.thresholdSessionId || !remainingSignatureUses || !expiresAtMs) {
    return 'lane_inventory_mismatch';
  }
  const material = ecdsaMaterialForLane(lane);
  if (!material) return 'lane_material_missing';
  return {
    state: 'ready',
    authMethod: args.authMethod,
    target: { curve: 'ecdsa', chainTarget: args.chainTarget },
    walletSigningSessionId: lane.walletSigningSessionId,
    thresholdSessionId: lane.thresholdSessionId,
    remainingSignatureUses,
    expiresAtMs,
    material,
  };
}

export async function readWalletRuntimePostconditions(args: {
  source: RuntimePostconditionSource;
  walletId: string | WalletId;
  authMethod: RuntimePostconditionAuthMethod;
  requiredTargets: readonly RuntimePostconditionTarget[];
  readPersistedAvailableSigningLanes: ReadPersistedAvailableSigningLanes;
  nowMs?: number;
}): Promise<WalletRuntimePostconditionResult> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) {
    return { ok: false, code: 'wallet_missing', details: { source: args.source } };
  }
  const lanes = await args.readPersistedAvailableSigningLanes({
    walletId,
    authMethod: args.authMethod,
  });
  const nowMs = args.nowMs ?? Date.now();
  let ed25519: ReadyRuntimeLane | undefined;
  const ecdsaByTarget = new Map<string, ReadyRuntimeLane>();
  for (const target of args.requiredTargets) {
    if (target.curve === 'ed25519') {
      const readyLane = readReadyEd25519Lane({
        lane: lanes.lanes.ed25519.near,
        authMethod: args.authMethod,
        nowMs,
      });
      if (typeof readyLane === 'string') {
        return {
          ok: false,
          code: readyLane,
          details: {
            source: args.source,
            walletId,
            authMethod: args.authMethod,
            curve: 'ed25519',
            state: lanes.lanes.ed25519.near.state,
            candidateCount: lanes.candidates.ed25519.near.length,
          },
        };
      }
      ed25519 = readyLane;
      continue;
    }
    const readyLane = readReadyEcdsaLane({
      lanes,
      chainTarget: target.chainTarget,
      authMethod: args.authMethod,
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
          authMethod: args.authMethod,
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
      authMethod: args.authMethod,
      ...(ed25519 ? { ed25519 } : {}),
      ecdsaByTarget,
    },
  };
}

function laneMaterialShape(lane: ReadyRuntimeLane): string {
  if (lane.material.kind === 'evm_family_shared_key') {
    return `${lane.material.kind}:${thresholdEcdsaChainTargetKey(lane.material.sourceChainTarget)}`;
  }
  return lane.material.kind;
}

function compareReadyLaneShape(args: {
  left: ReadyRuntimeLane | undefined;
  right: ReadyRuntimeLane | undefined;
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
  authMethod: RuntimePostconditionAuthMethod;
  requiredTargets: readonly RuntimePostconditionTarget[];
  readPersistedAvailableSigningLanes: ReadPersistedAvailableSigningLanes;
  nowMs?: number;
}): Promise<WalletRuntimeInventory> {
  const result = await readWalletRuntimePostconditions(args);
  if (!result.ok) throw new WalletRuntimePostconditionError(result);
  return result.inventory;
}
