import type { KeyExportFlowEvent, SeamsWeb } from '@seams/sdk';
import {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromConfig,
  walletSessionRefFromSession,
} from '@seams/sdk/advanced';

function logExportEvent(event: KeyExportFlowEvent): void {
  console.log(event.phase, event.status, event.message);
}

export async function exportNearKey(
  seams: SeamsWeb,
  walletId: string,
  nearAccountId: string,
): Promise<void> {
  const walletSession = walletSessionRefFromSession({
    walletId,
    walletSessionUserId: walletId,
  });
  const nearAccount = nearAccountRefFromAccountId(nearAccountId);
  const lane = await seams.keys.resolveExactKeyExportLane({
    kind: 'ed25519',
    walletSession,
    nearAccount,
  });
  if (lane.kind !== 'ed25519') {
    throw new Error(`Expected an Ed25519 export lane, received ${lane.kind}`);
  }
  await seams.keys.exportKeypairWithUI({
    kind: 'ed25519',
    walletSession,
    nearAccount,
    laneIdentity: lane.laneIdentity,
    materialActivation: lane.materialActivation,
    options: { onEvent: logExportEvent },
  });
}

export async function exportEvmKey(seams: SeamsWeb, walletId: string): Promise<void> {
  const walletSession = walletSessionRefFromSession({
    walletId,
    walletSessionUserId: walletId,
  });
  const chainTarget = thresholdEcdsaChainTargetFromConfig({
    network: 'tempo-testnet',
    rpcUrl: 'https://rpc.moderato.tempo.xyz',
    explorerUrl: 'https://explore.testnet.tempo.xyz',
    chainId: 42431,
  });
  const lane = await seams.keys.resolveExactKeyExportLane({
    kind: 'ecdsa',
    walletSession,
    chainTarget,
  });
  if (lane.kind !== 'ecdsa') {
    throw new Error(`Expected an ECDSA export lane, received ${lane.kind}`);
  }
  await seams.keys.exportKeypairWithUI({
    kind: 'ecdsa',
    walletSession,
    chainTarget,
    laneIdentity: lane.laneIdentity,
    options: { onEvent: logExportEvent },
  });
}
