import { logWalletEvents, type SeamsWeb } from '@seams/wallet';

export async function exportNearKey(seams: SeamsWeb): Promise<void> {
  const outcome = await seams.keys.exportKeypair({
    kind: 'ed25519',
    options: { onEvent: logWalletEvents() },
  });
  if (outcome.kind === 'relink_required') {
    // This device has no canonical owner binding: send the person through
    // device linking rather than showing a generic error.
    console.warn('Link this device again before exporting:', outcome.reason);
  }
}

export async function exportEvmKey(seams: SeamsWeb): Promise<void> {
  const outcome = await seams.keys.exportKeypair({
    kind: 'ecdsa',
    chainTarget: 'tempo-testnet',
    options: { onEvent: logWalletEvents() },
  });
  if (outcome.kind === 'relink_required') {
    console.warn('Link this device again before exporting:', outcome.reason);
  }
}
