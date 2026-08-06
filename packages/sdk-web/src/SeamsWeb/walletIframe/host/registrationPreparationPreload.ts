import { prewarmTxConfirmerUi } from '@/core/signingEngine/uiConfirm/ui/confirm-ui';
import { loadSignEvmFamilyWithUiConfirmForTempo } from '@/core/signingEngine/flows/signEvmFamily/signerLoader';

export async function preloadWalletHostRegistrationPreparation(): Promise<void> {
  await Promise.all([
    prewarmTxConfirmerUi(),
    import('./runtime-ecdsa-tempo').catch(() => undefined),
    loadSignEvmFamilyWithUiConfirmForTempo().catch(() => undefined),
  ]);
}
