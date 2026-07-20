import { chainFamilyFromNetwork, findPrimaryChainByFamily } from './chains';
import type { SeamsChainFamily } from '../types/seams';

const canonicalFamilies = ['near', 'tempo', 'evm'] as const satisfies readonly SeamsChainFamily[];
const arcNetworkFamily: SeamsChainFamily = chainFamilyFromNetwork('arc-mainnet');

for (const family of canonicalFamilies) {
  findPrimaryChainByFamily([], family);
}

// @ts-expect-error Arc identifies an EVM network, never a chain-family discriminator.
const arcFamily: SeamsChainFamily = 'arc';

// @ts-expect-error Family-based APIs accept only the canonical family union.
findPrimaryChainByFamily([], 'arc');

void arcNetworkFamily;
void arcFamily;
