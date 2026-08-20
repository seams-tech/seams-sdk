import {
  configuredThresholdEcdsaChainTargets,
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmEip155ChainTarget,
  TempoChainTarget,
  ThresholdEcdsaChainTarget,
} from '@/core/platform/types';
import type {
  SeamsChainConfig,
  SeamsEvmChainNetwork,
  SeamsTempoChainNetwork,
} from '@/core/types/seams';

/**
 * Names one configured chain without naming it twice.
 *
 * A selector must resolve to exactly one configured ECDSA target. Matching more
 * than one throws and names the candidates rather than ranking them — an ECDSA
 * target is always exactly one chain, never a best guess
 * (docs/refactor-79-exact-signing-lane.md).
 */
export type EcdsaChainSelector =
  /** A configured EVM-family network slug, e.g. `'tempo-testnet'`. */
  | SeamsTempoChainNetwork
  | SeamsEvmChainNetwork
  /** A configured chain id; throws when two families share it. */
  | { chainId: number }
  /** A chain family; legal only when exactly one chain of it is configured. */
  | { family: 'tempo' | 'evm' }
  /** An already-built target, passed through unchanged. */
  | ThresholdEcdsaChainTarget;

/** Selector for a Tempo-only call site; keeps the family guarantee at compile time. */
export type TempoChainSelector =
  | SeamsTempoChainNetwork
  | { chainId: number }
  | { family: 'tempo' }
  | TempoChainTarget;

/** Selector for an EVM-eip155-only call site; keeps the family guarantee at compile time. */
export type EvmChainSelector =
  | SeamsEvmChainNetwork
  | { chainId: number }
  | { family: 'evm' }
  | EvmEip155ChainTarget;

function isBuiltTarget(selector: EcdsaChainSelector): selector is ThresholdEcdsaChainTarget {
  return typeof selector === 'object' && selector !== null && 'kind' in selector;
}

function matchesSelector(
  target: ThresholdEcdsaChainTarget,
  selector: Exclude<EcdsaChainSelector, ThresholdEcdsaChainTarget>,
): boolean {
  if (typeof selector === 'string') return target.networkSlug === selector;
  if ('chainId' in selector) return target.chainId === selector.chainId;
  return target.kind === selector.family;
}

function describeSelector(selector: EcdsaChainSelector): string {
  if (typeof selector === 'string') return selector;
  if (isBuiltTarget(selector)) return thresholdEcdsaChainTargetKey(selector);
  if ('chainId' in selector) return `chainId ${selector.chainId}`;
  return `family ${selector.family}`;
}

/**
 * Resolves a selector against the chains this client was configured with.
 *
 * Throws when the selector matches no configured chain, or more than one — the
 * error names every configured target so the caller can pick an exact one.
 */
export function resolveConfiguredChainTarget(
  chains: readonly SeamsChainConfig[],
  selector: EcdsaChainSelector,
): ThresholdEcdsaChainTarget {
  if (isBuiltTarget(selector)) return thresholdEcdsaChainTargetFromRequest(selector);
  const configured = configuredThresholdEcdsaChainTargets(chains);
  const matches = configured.filter((target) => matchesSelector(target, selector));
  const only = matches[0];
  if (matches.length === 1 && only) return only;
  if (matches.length > 1) {
    throw new Error(
      `[threshold-ecdsa] ambiguous chain selector "${describeSelector(selector)}": matched ${matches
        .map(thresholdEcdsaChainTargetKey)
        .join(', ')}. Name one exact network slug instead.`,
    );
  }
  const configuredSlugs = configured.map((target) => target.networkSlug).join(', ');
  throw new Error(
    `[threshold-ecdsa] no configured ECDSA chain matches "${describeSelector(selector)}". Configured chains: ${configuredSlugs || '(none)'}.`,
  );
}

/** Resolve a Tempo call site's selector, asserting the resolved family. */
export function resolveTempoChainTarget(
  chains: readonly SeamsChainConfig[],
  selector: TempoChainSelector,
): TempoChainTarget {
  const target = resolveConfiguredChainTarget(chains, selector);
  if (target.kind !== 'tempo') {
    throw new Error(
      `[threshold-ecdsa] expected a Tempo chain target, resolved ${thresholdEcdsaChainTargetKey(target)}`,
    );
  }
  return target;
}

/** Resolve an EVM-eip155 call site's selector, asserting the resolved family. */
export function resolveEvmChainTarget(
  chains: readonly SeamsChainConfig[],
  selector: EvmChainSelector,
): EvmEip155ChainTarget {
  const target = resolveConfiguredChainTarget(chains, selector);
  if (target.kind !== 'evm') {
    throw new Error(
      `[threshold-ecdsa] expected an EVM chain target, resolved ${thresholdEcdsaChainTargetKey(target)}`,
    );
  }
  return target;
}
