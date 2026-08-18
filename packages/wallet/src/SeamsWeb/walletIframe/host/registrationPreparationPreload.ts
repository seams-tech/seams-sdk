import { prewarmTxConfirmerUi } from '@/core/signingEngine/uiConfirm/ui/confirm-ui';
import {
  loadSecp256k1EngineCtor,
  loadSignEvmFamilyWithUiConfirmForTempo,
  loadSignEvmWithUiConfirm,
  loadWebAuthnP256EngineCtor,
} from '@/core/signingEngine/flows/signEvmFamily/signerLoader';

export async function preloadWalletHostRegistrationPreparation(): Promise<void> {
  await Promise.all([
    prewarmTxConfirmerUi(),
    import('./runtime-ecdsa-tempo').catch(() => undefined),
    loadSignEvmFamilyWithUiConfirmForTempo().catch(() => undefined),
    loadSignEvmWithUiConfirm().catch(() => undefined),
    loadSecp256k1EngineCtor().catch(() => undefined),
    loadWebAuthnP256EngineCtor().catch(() => undefined),
  ]);
}
