export type GasSponsorshipSpendCapNetworkClass = 'TESTNET' | 'MAINNET';

// Internal spend-cap target ids for NEAR networks. These are not on-chain chain ids.
export const NEAR_TESTNET_SPEND_CAP_CHAIN_ID = 2_147_000_001;
export const NEAR_MAINNET_SPEND_CAP_CHAIN_ID = 2_147_000_002;

export function getNearSpendCapChainId(
  networkClass: GasSponsorshipSpendCapNetworkClass,
): number {
  return networkClass === 'MAINNET'
    ? NEAR_MAINNET_SPEND_CAP_CHAIN_ID
    : NEAR_TESTNET_SPEND_CAP_CHAIN_ID;
}

export function isNearSpendCapChainId(value: number): boolean {
  return value === NEAR_TESTNET_SPEND_CAP_CHAIN_ID || value === NEAR_MAINNET_SPEND_CAP_CHAIN_ID;
}
