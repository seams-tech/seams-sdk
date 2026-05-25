import { base64UrlEncode } from './encoders';
import { alphabetizeStringify, sha256BytesUtf8 } from './digests';

type EcdsaInventoryChainTarget =
  | {
      kind: 'evm';
      namespace: 'eip155';
      chainId: number;
      networkSlug?: string;
    }
  | {
      kind: 'tempo';
      chainId: number;
      networkSlug?: string;
    };

export type WalletSubjectEcdsaKeyFactsInventoryChallengeInput = {
  walletSubjectId: string;
  rpId: string;
  keyTargets: readonly {
    keyHandle: string;
    chainTarget: EcdsaInventoryChainTarget;
  }[];
  runtimePolicyScope?: unknown;
  serverNonceB64u: string;
};

function chainTargetKey(target: EcdsaInventoryChainTarget): string {
  return target.kind === 'evm' ? `evm:eip155:${target.chainId}` : `tempo:${target.chainId}`;
}

function normalizeChainTarget(target: EcdsaInventoryChainTarget): EcdsaInventoryChainTarget {
  if (target.kind === 'evm') {
    return {
      kind: 'evm',
      namespace: 'eip155',
      chainId: target.chainId,
      ...(target.networkSlug ? { networkSlug: target.networkSlug } : {}),
    };
  }
  return {
    kind: 'tempo',
    chainId: target.chainId,
    ...(target.networkSlug ? { networkSlug: target.networkSlug } : {}),
  };
}

export function canonicalizeWalletSubjectEcdsaKeyFactsInventoryChallenge(
  input: WalletSubjectEcdsaKeyFactsInventoryChallengeInput,
): string {
  const keyTargets = input.keyTargets
    .map((target) => ({
      keyHandle: target.keyHandle,
      chainTarget: normalizeChainTarget(target.chainTarget),
      targetKey: chainTargetKey(target.chainTarget),
    }))
    .sort((left, right) => {
      const leftKey = `${left.keyHandle}:${left.targetKey}`;
      const rightKey = `${right.keyHandle}:${right.targetKey}`;
      return leftKey.localeCompare(rightKey);
    });

  return alphabetizeStringify({
    version: 'wallet-subject-ecdsa-key-facts-inventory:v1',
    walletSubjectId: input.walletSubjectId,
    rpId: input.rpId,
    keyTargets,
    ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
    serverNonceB64u: input.serverNonceB64u,
  });
}

export async function computeWalletSubjectEcdsaKeyFactsInventoryChallengeDigestB64u(
  input: WalletSubjectEcdsaKeyFactsInventoryChallengeInput,
): Promise<string> {
  return base64UrlEncode(
    await sha256BytesUtf8(canonicalizeWalletSubjectEcdsaKeyFactsInventoryChallenge(input)),
  );
}
