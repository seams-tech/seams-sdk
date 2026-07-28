import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import { resolveThresholdEcdsaKeyIdFromKeyRef } from '../identity/evmFamilyEcdsaIdentity';
import type { WarmSessionEcdsaCapabilityState } from './types';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';

export type EcdsaWarmCapabilityReader = {
  getEcdsaCapabilityForLane: (
    lane: ExactEcdsaSigningLaneIdentity,
  ) => Promise<WarmSessionEcdsaCapabilityState | null>;
};

/** Asserts the warm capability that came back describes the material the
 * bootstrap just created. Only material identity is compared here: the
 * authorization half is checked separately against the bootstrap's
 * authorizationSessionId, and the signing grant is authorization-owned, so it
 * takes no part in proving which material this is. */
function requireExactBootstrapCapability(args: {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  capability: WarmSessionEcdsaCapabilityState;
}): WarmSessionEcdsaCapabilityState {
  const { bootstrap, capability } = args;
  if (capability.state !== 'ready' || !capability.runtime) {
    throw new Error(
      `[SigningEngine] Email OTP bootstrap did not reach warm-session ready state for ${String(
        args.walletId,
      )} (${thresholdEcdsaChainTargetKey(args.chainTarget)}, state=${capability.state})`,
    );
  }

  const runtime = capability.runtime;
  const keyRef = bootstrap.thresholdEcdsaKeyRef;
  const participantIdsMatch =
    !keyRef.participantIds?.length ||
    runtime.participantIds.map((value) => Number(value)).join(',') ===
      keyRef.participantIds.map((value) => Number(value)).join(',');

  if (
    !thresholdEcdsaChainTargetsEqual(runtime.chainTarget, args.chainTarget) ||
    !thresholdEcdsaChainTargetsEqual(keyRef.chainTarget, args.chainTarget) ||
    String(runtime.sealedRecord.thresholdSessionId) !== bootstrapThresholdSessionId(bootstrap) ||
    String(runtime.ecdsaThresholdKeyId) !==
      String(resolveThresholdEcdsaKeyIdFromKeyRef({ keyRef })) ||
    !participantIdsMatch
  ) {
    throw new Error(
      `[SigningEngine] Email OTP bootstrap produced non-exact warm ECDSA capability for ${String(
        args.walletId,
      )} (${thresholdEcdsaChainTargetKey(args.chainTarget)})`,
    );
  }

  return capability;
}

function bootstrapThresholdSessionId(bootstrap: ThresholdEcdsaSessionBootstrapResult): string {
  return String(
    bootstrap.thresholdEcdsaKeyRef.thresholdSessionId || bootstrap.session.thresholdSessionId || '',
  ).trim();
}

export async function assertWarmThresholdEcdsaCapabilityReady(
  reader: EcdsaWarmCapabilityReader,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    lane: ExactEcdsaSigningLaneIdentity;
  },
): Promise<WarmSessionEcdsaCapabilityState> {
  const authorizationSessionId = String(
    args.bootstrap.session.authorizationSessionId,
  ).trim();
  if (!authorizationSessionId) {
    throw new Error(
      `[SigningEngine] Email OTP bootstrap did not provide authorizationSessionId for ${String(
        args.walletId,
      )} (${thresholdEcdsaChainTargetKey(args.chainTarget)})`,
    );
  }
  if (
    String(args.lane.authorization.projection.authorizationSessionId) !==
    authorizationSessionId
  ) {
    throw new Error(
      `[SigningEngine] Email OTP bootstrap authorization session mismatch for ${String(
        args.walletId,
      )} (${thresholdEcdsaChainTargetKey(args.chainTarget)})`,
    );
  }
  const capability = await reader.getEcdsaCapabilityForLane(args.lane);
  return requireExactBootstrapCapability({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    bootstrap: args.bootstrap,
    capability: capability || {
      capability: 'ecdsa',
      state: 'missing',
      manifest: null,
      runtime: null,
      key: null,
      lane: null,
      auth: null,
      prfClaim: null,
    },
  });
}
