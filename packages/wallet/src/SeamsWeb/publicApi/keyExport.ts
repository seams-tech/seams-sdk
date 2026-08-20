import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type {
  ExportKeypairInput,
  KeyExportCapability,
  KeyExportOutcome,
  ResolveExactKeyExportLaneInput,
  ResolveExactKeyExportLaneResult,
  ExportKeypairWithUIInput,
} from '@/SeamsWeb/publicApi/types';
import type { SigningEngineExportKeypairWithUIInput } from '@/core/signingEngine/flows/recovery/public';
import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
} from '@shared/authorization/capabilityKinds';
import { requireBrowserCapabilityOperation } from '@/SeamsWeb/publicApi/capabilitySelection';
import { resolveConfiguredChainTarget } from '@/SeamsWeb/publicApi/chainTargets';
import type { CurrentWalletResolver } from '@/SeamsWeb/publicApi/currentWallet';

/**
 * Domain methods sit below the public boundary: `options` has already been
 * normalized, so they take the signing-engine input shape.
 */
export type KeyExportDomainMethods = {
  resolveExactKeyExportLane(
    input: ResolveExactKeyExportLaneInput,
  ): Promise<ResolveExactKeyExportLaneResult>;
  exportKeypairWithUI(input: SigningEngineExportKeypairWithUIInput): Promise<void>;
};

type KeyExportCapabilitySelectionInput =
  | ResolveExactKeyExportLaneInput
  | ExportKeypairWithUIInput
  | SigningEngineExportKeypairWithUIInput;

export function requireKeyExportCapability(
  configs: SeamsConfigsReadonly,
  input: KeyExportCapabilitySelectionInput,
): void {
  switch (input.kind) {
    case 'ed25519':
      requireBrowserCapabilityOperation(configs, {
        capabilityKind: CAPABILITY_KINDS.nearEd25519MpcSigning,
        operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.exportKey,
      });
      return;
    case 'ecdsa':
      requireBrowserCapabilityOperation(configs, {
        capabilityKind: CAPABILITY_KINDS.evmEcdsaMpcSigning,
        operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.exportKey,
        chainTarget: input.chainTarget,
      });
      return;
  }
}

/**
 * Builds the public key-export capability.
 *
 * `exportKeypair` fuses the lane handshake: resolving the exact lane and then
 * exporting with it are not two caller decisions — the second call's input is
 * the first call's input plus the first call's output. Fusing them also keeps
 * `relink_required` a handled outcome instead of collapsing it into a generic
 * "unexpected lane kind" throw, which is what every hand-written narrow did.
 *
 * The two-step primitives stay exported for callers that want to check export
 * availability before opening the viewer.
 */
export function createKeyExportCapability(deps: {
  configs: SeamsConfigsReadonly;
  currentWallet: CurrentWalletResolver;
  domain: KeyExportDomainMethods;
}): KeyExportCapability {
  const resolveExactKeyExportLane: KeyExportCapability['resolveExactKeyExportLane'] = async (
    input,
  ) => {
    requireKeyExportCapability(deps.configs, input);
    return await deps.domain.resolveExactKeyExportLane(input);
  };
  const exportKeypairWithUI: KeyExportCapability['exportKeypairWithUI'] = async (input) => {
    requireKeyExportCapability(deps.configs, input);
    await deps.domain.exportKeypairWithUI({ ...input, options: input.options ?? {} });
  };

  const exportKeypair = async (input: ExportKeypairInput): Promise<KeyExportOutcome> => {
    const options = input.options ?? {};
    if (input.kind === 'ed25519') {
      const subject = await deps.currentWallet.nearSubject(input);
      const laneInput = { kind: 'ed25519' as const, ...subject };
      requireKeyExportCapability(deps.configs, laneInput);
      const lane = await deps.domain.resolveExactKeyExportLane(laneInput);
      if (lane.kind === 'relink_required') return lane;
      if (lane.kind !== 'ed25519') {
        throw new Error(`[key-export] expected an Ed25519 lane, received ${lane.kind}`);
      }
      await deps.domain.exportKeypairWithUI({
        ...laneInput,
        laneIdentity: lane.laneIdentity,
        materialActivation: lane.materialActivation,
        options,
      });
      return { kind: 'exported' };
    }
    const walletSession = await deps.currentWallet.walletSession(input.walletSession);
    const chainTarget = resolveConfiguredChainTarget(
      deps.configs.network.chains,
      input.chainTarget,
    );
    const laneInput = { kind: 'ecdsa' as const, walletSession, chainTarget };
    requireKeyExportCapability(deps.configs, laneInput);
    const lane = await deps.domain.resolveExactKeyExportLane(laneInput);
    if (lane.kind === 'relink_required') return lane;
    if (lane.kind !== 'ecdsa') {
      throw new Error(`[key-export] expected an ECDSA lane, received ${lane.kind}`);
    }
    await deps.domain.exportKeypairWithUI({
      ...laneInput,
      laneIdentity: lane.laneIdentity,
      options,
    });
    return { kind: 'exported' };
  };

  return { resolveExactKeyExportLane, exportKeypairWithUI, exportKeypair };
}
