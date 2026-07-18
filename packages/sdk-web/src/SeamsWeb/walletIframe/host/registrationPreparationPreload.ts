import { prewarmTxConfirmerUi } from '@/core/signingEngine/uiConfirm/ui/confirm-ui';
import { resolveEmbeddedBase } from '@/core/signingEngine/uiConfirm/ui/lit-components/asset-base';

const registrationStyleAssets = [
  'w3a-components.css',
  'tx-tree.css',
  'tx-confirmer.css',
  'halo-border.css',
  'passkey-halo-loading.css',
] as const;

async function preloadRegistrationStyleAsset(baseUrl: string, asset: string): Promise<void> {
  try {
    const response = await fetch(new URL(asset, baseUrl), { cache: 'force-cache' });
    if (response.ok) await response.text();
  } catch {}
}

export async function preloadWalletHostRegistrationPreparation(): Promise<void> {
  const stylePromises: Promise<void>[] = [];
  const baseUrl = resolveEmbeddedBase();
  for (const asset of registrationStyleAssets) {
    stylePromises.push(preloadRegistrationStyleAsset(baseUrl, asset));
  }
  await Promise.all([prewarmTxConfirmerUi(), ...stylePromises]);
}
