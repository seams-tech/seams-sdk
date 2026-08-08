import type { EvmFamilyChain } from '../../interfaces/operationDeps';
import {
  selectedEcdsaLane,
  emailOtpAuthContextReason,
  emailOtpAuthContextRetention,
  type SelectedEcdsaLane,
  type ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import { signingLaneAuthMethod } from '../../session/identity/signingLaneAuthBinding';
import { type EcdsaTransactionSigningLane } from '../../session/operationState/lanes';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { type EvmFamilyEcdsaKeyIdentity } from '../../session/identity/evmFamilyEcdsaIdentity';
import { requireEvmFamilyEcdsaSigner } from '../../session/identity/exactSigningLaneIdentity';

export type ResolvedEvmFamilyEcdsaSigningLane = EcdsaTransactionSigningLane & {
  curve: 'ecdsa';
  keyKind: 'threshold_ecdsa_secp256k1';
  chainFamily: EvmFamilyChain;
  key: EvmFamilyEcdsaKeyIdentity;
  keyHandle: ReturnType<typeof requireEvmFamilyEcdsaSigner>['keyHandle'];
  chainTarget: ThresholdEcdsaChainTarget;
};

export function summarizeEvmFamilyEcdsaLane(
  lane: EcdsaTransactionSigningLane | SelectedEcdsaLane | undefined,
): Record<string, unknown> {
  if (!lane) return { present: false };
  const signer = requireEvmFamilyEcdsaSigner(lane.identity, 'ECDSA lane summary');
  return {
    present: true,
    walletId: signer.walletId,
    authMethod: signingLaneAuthMethod(lane.auth),
    curve: lane.curve,
    chain: lane.chain,
    chainFamily: 'chainFamily' in lane ? lane.chainFamily : lane.chain,
    keyKind: 'keyKind' in lane ? lane.keyKind : 'threshold_ecdsa_secp256k1',
    sessionOrigin: 'sessionOrigin' in lane ? lane.sessionOrigin : undefined,
    storageSource: 'storageSource' in lane ? lane.storageSource : undefined,
    retention: 'retention' in lane ? lane.retention : undefined,
    walletSessionId: lane.authorization.projection.walletSessionId,
    materialActivationId: lane.materialActivation.activationId,
    chainTarget: signer.chainTarget,
    evmFamilyKeyPresent: Boolean(signer.key),
  };
}

export function logEvmFamilyEcdsaLaneDiagnostic(
  message: string,
  details: Record<string, unknown>,
): void {
  try {
    console.warn(`[SigningEngine][ecdsa] ${message}`, JSON.stringify(details, null, 2));
  } catch {}
}

export function requireResolvedEvmFamilyEcdsaSigningLane(args: {
  lane: EcdsaTransactionSigningLane | undefined;
  chain: EvmFamilyChain;
  context: string;
  diagnostics?: Record<string, unknown>;
}): ResolvedEvmFamilyEcdsaSigningLane {
  const lane = args.lane;
  if (!lane) {
    logEvmFamilyEcdsaLaneDiagnostic('missing selected signing lane', {
      context: args.context,
      chain: args.chain,
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] missing selected signing lane for ${args.context}`);
  }
  if (lane.curve !== 'ecdsa' || lane.keyKind !== 'threshold_ecdsa_secp256k1') {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane is not ECDSA', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] ${args.context} requires an ECDSA signing lane`);
  }
  const identity = lane.identity;
  const signer = requireEvmFamilyEcdsaSigner(identity, `${args.context} resolved ECDSA lane`);
  const chainTarget = signer.chainTarget;
  if (chainTarget.kind !== args.chain) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane chain mismatch', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] ${args.context} chain does not match selected lane`);
  }

  const key = signer.key;
  if (!key?.ecdsaThresholdKeyId || !key.signingRootId || !key.signingRootVersion) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane missing full ECDSA identity', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] incomplete ECDSA lane identity for ${args.context}`);
  }
  if (
    !key ||
    String(key.walletId) !== String(signer.walletId) ||
    String(signer.keyHandle || '').trim() === ''
  ) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane missing matching shared key identity', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] missing shared key identity for ${args.context}`);
  }

  const selectedLane = selectedEcdsaLane({
    key,
    materialActivation: signer.materialActivation,
    keyHandle: signer.keyHandle,
    walletId: signer.walletId,
    auth: identity.auth,
    authorization: lane.authorization,
    chainTarget,
  });

  return {
    ...lane,
    ...selectedLane,
    key,
    keyHandle: signer.keyHandle,
    chainTarget,
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: signer.chainTarget.kind,
  };
}

// `updateResolvedEvmFamilyEcdsaSigningLaneIdentity` is gone. It re-derived a
// resolved lane after a record refresh rewrote its session identity -- a
// lifecycle Refactor 90 deletes. Material is selected by manifest and sealed
// runtime now, so a lane's identity never changes underneath it and there is
// nothing to update in place. It had no production callers.
