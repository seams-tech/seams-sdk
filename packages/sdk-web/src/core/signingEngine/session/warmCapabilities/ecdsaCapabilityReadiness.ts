import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  resolveThresholdEcdsaKeyIdFromKeyRef,
  resolveThresholdEcdsaKeyIdFromRecord,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaSessionIdentity,
  ecdsaSessionIdentitiesEqual,
} from './ecdsaProvisionPlan';
import type { WarmSessionEcdsaCapabilityState, WarmSessionEnvelope } from './types';

export type EcdsaWarmCapabilityReader = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionEnvelope>;
};

function requireExactBootstrapCapability(args: {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  capability: WarmSessionEcdsaCapabilityState;
}): WarmSessionEcdsaCapabilityState {
  const { bootstrap, capability } = args;
  if (capability.state !== 'ready' || !capability.record) {
    throw new Error(
      `[SigningEngine] Email OTP bootstrap did not reach warm-session ready state for ${String(
        args.walletId,
      )} (${thresholdEcdsaChainTargetKey(args.chainTarget)}, state=${capability.state})`,
    );
  }

  const record = capability.record;
  const keyRef = bootstrap.thresholdEcdsaKeyRef;
  const recordIdentity = buildEcdsaSessionIdentity(record);
  const bootstrapIdentity = buildEcdsaSessionIdentity({
    thresholdSessionId: keyRef.thresholdSessionId || bootstrap.session.thresholdSessionId,
    signingGrantId:
      keyRef.signingGrantId || bootstrap.session.signingGrantId,
  });
  const participantIdsMatch =
    !record.participantIds?.length ||
    !keyRef.participantIds?.length ||
    record.participantIds.map((value) => Number(value)).join(',') ===
      keyRef.participantIds.map((value) => Number(value)).join(',');

  if (
    !thresholdEcdsaChainTargetsEqual(record.chainTarget, args.chainTarget) ||
    !thresholdEcdsaChainTargetsEqual(keyRef.chainTarget, args.chainTarget) ||
    !ecdsaSessionIdentitiesEqual(recordIdentity, bootstrapIdentity) ||
    String(resolveThresholdEcdsaKeyIdFromRecord({ record })) !==
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

export async function assertWarmThresholdEcdsaCapabilityReady(
  reader: EcdsaWarmCapabilityReader,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
  },
): Promise<WarmSessionEcdsaCapabilityState> {
  const warmSession = await reader.getWarmSession(args.walletId);
  const capability = warmSession.capabilities.ecdsa[args.chainTarget.kind];
  return requireExactBootstrapCapability({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    bootstrap: args.bootstrap,
    capability,
  });
}
