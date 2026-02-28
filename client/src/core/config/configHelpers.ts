import { coerceThemeName } from '@shared/utils/theme';
import { toTrimmedString } from '@shared/utils/validation';
import type { EcdsaSignerProvisioningDefaults } from '../types/ecdsaSignerProvisioningDefaults';
import type {
  TatchiChainConfig,
  TatchiChainConfigInput,
  TatchiChainNetwork,
  TatchiConfigsInput,
  ThemeName,
  ThemePaletteName,
} from '../types/tatchi';
import type { SignerMode } from '../types/signer-worker';
import { isSignerMode, isThresholdBehavior } from '../types/signer-worker';
import {
  isEvmChainNetwork,
  isNearChainNetwork,
  isTempoChainNetwork,
  isTatchiChainNetwork,
} from './chains';

export type IntRange = Readonly<{ min: number; max: number }>;

export function resolveIntegerInRange(args: {
  value: unknown;
  fallback: number;
  range: IntRange;
  path: string;
}): number {
  const candidate = args.value ?? args.fallback;
  if (
    typeof candidate !== 'number' ||
    !Number.isFinite(candidate) ||
    !Number.isInteger(candidate)
  ) {
    throw new Error(`[configPresets] Invalid config: ${args.path} must be an integer`);
  }
  if (candidate < args.range.min || candidate > args.range.max) {
    throw new Error(
      `[configPresets] Invalid config: ${args.path} must be in [${args.range.min}, ${args.range.max}]`,
    );
  }
  return candidate;
}

export function resolveOptionalPositiveInteger(args: {
  value: unknown;
  fallback?: number;
  path: string;
}): number | undefined {
  const candidate = args.value ?? args.fallback;
  if (candidate == null) return undefined;
  if (
    typeof candidate !== 'number' ||
    !Number.isFinite(candidate) ||
    !Number.isInteger(candidate)
  ) {
    throw new Error(`[configPresets] Invalid config: ${args.path} must be an integer`);
  }
  if (candidate <= 0) {
    throw new Error(`[configPresets] Invalid config: ${args.path} must be > 0`);
  }
  return candidate;
}

export function resolveRequiredString(args: {
  value: unknown;
  fallback?: string;
  path: string;
}): string {
  const value = toTrimmedString(args.value) || toTrimmedString(args.fallback);
  if (!value) {
    throw new Error(`[configPresets] Missing required config: ${args.path}`);
  }
  return value;
}

export function resolveBoolean(args: { value: unknown; fallback: boolean; path: string }): boolean {
  if (args.value == null) return args.fallback;
  if (typeof args.value !== 'boolean') {
    throw new Error(`[configPresets] Invalid config: ${args.path} must be boolean`);
  }
  return args.value;
}

export function toColorTokenRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

function copySignerMode(mode: SignerMode): SignerMode {
  if (mode.mode === 'threshold-signer' && isThresholdBehavior(mode.behavior)) {
    return { mode: 'threshold-signer', behavior: mode.behavior };
  }
  return { mode: mode.mode };
}

export function resolveSignerMode(
  input: TatchiConfigsInput['signerMode'],
  fallback: SignerMode,
): SignerMode {
  if (input == null) return copySignerMode(fallback);

  if (typeof input === 'string') {
    if (!isSignerMode(input)) {
      throw new Error(
        "[configPresets] Invalid config: signerMode must be 'local-signer' or 'threshold-signer'",
      );
    }
    return { mode: input };
  }

  if (typeof input !== 'object') {
    throw new Error('[configPresets] Invalid config: signerMode must be a string or object');
  }

  if (!isSignerMode(input.mode)) {
    throw new Error(
      "[configPresets] Invalid config: signerMode.mode must be 'local-signer' or 'threshold-signer'",
    );
  }

  if (input.mode === 'local-signer') {
    return { mode: 'local-signer' };
  }

  if (input.behavior == null) {
    return { mode: 'threshold-signer' };
  }

  if (!isThresholdBehavior(input.behavior)) {
    throw new Error(
      "[configPresets] Invalid config: signerMode.behavior must be 'strict' or 'fallback'",
    );
  }

  return {
    mode: 'threshold-signer',
    behavior: input.behavior,
  };
}

export function resolveTheme(args: { value: unknown; fallback: ThemeName }): ThemeName {
  if (args.value == null) return args.fallback;
  const parsed = coerceThemeName(args.value);
  if (!parsed) {
    throw new Error("[configPresets] Invalid config: appearance.theme must be 'light' or 'dark'");
  }
  return parsed;
}

export function resolveThemePalette(args: {
  value: unknown;
  fallback: ThemePaletteName;
}): ThemePaletteName {
  if (args.value == null) return args.fallback;
  if (args.value !== 'default') {
    throw new Error("[configPresets] Invalid config: appearance.palette must be 'default'");
  }
  return 'default';
}

export function resolveSmartAccountDeploymentMode(
  value: unknown,
  fallback: 'observe' | 'enforce',
): 'observe' | 'enforce' {
  if (value == null) return fallback;
  if (value === 'observe' || value === 'enforce') return value;
  throw new Error(
    "[configPresets] Invalid config: relayer.smartAccountDeploymentMode must be 'observe' or 'enforce'",
  );
}

export function copyEcdsaSignerProvisioningDefaults(
  value: EcdsaSignerProvisioningDefaults,
): EcdsaSignerProvisioningDefaults {
  return {
    tempo: {
      ...value.tempo,
      participantIds: [...value.tempo.participantIds],
      signingSession: { ...value.tempo.signingSession },
      ...(value.tempo.smartAccount ? { smartAccount: { ...value.tempo.smartAccount } } : {}),
    },
    evm: {
      ...value.evm,
      participantIds: [...value.evm.participantIds],
      signingSession: { ...value.evm.signingSession },
      ...(value.evm.smartAccount ? { smartAccount: { ...value.evm.smartAccount } } : {}),
    },
  };
}

export function resolveChainNetwork(network: unknown): TatchiChainNetwork {
  if (!isTatchiChainNetwork(network)) {
    throw new Error(`[configPresets] Invalid chain network: ${String(network || '')}`);
  }
  return network;
}

export function resolveChainConfig(args: {
  input: TatchiChainConfigInput;
  fallback?: TatchiChainConfig;
}): TatchiChainConfig {
  const network = resolveChainNetwork((args.input as { network?: unknown }).network);
  const rpcUrl = resolveRequiredString({
    value: args.input.rpcUrl,
    fallback: args.fallback?.rpcUrl,
    path: `chains.${network}.rpcUrl`,
  });
  const explorerUrl = resolveRequiredString({
    value: args.input.explorerUrl,
    fallback: args.fallback?.explorerUrl,
    path: `chains.${network}.explorerUrl`,
  });

  if (isNearChainNetwork(network)) {
    return {
      network,
      rpcUrl,
      explorerUrl,
    };
  }

  const chainId = resolveOptionalPositiveInteger({
    value: (args.input as { chainId?: unknown }).chainId,
    fallback: (args.fallback as { chainId?: number } | undefined)?.chainId,
    path: `chains.${network}.chainId`,
  });
  if (typeof chainId !== 'number') {
    throw new Error(`[configPresets] Missing required config: chains.${network}.chainId`);
  }

  if (isTempoChainNetwork(network)) {
    return {
      network,
      rpcUrl,
      explorerUrl,
      chainId,
    };
  }

  if (isEvmChainNetwork(network)) {
    return {
      network,
      rpcUrl,
      explorerUrl,
      chainId,
    };
  }

  throw new Error(`[configPresets] Unsupported chain network: ${network}`);
}

export function resolveChains(
  defaults: readonly TatchiChainConfig[],
  overrides: TatchiConfigsInput['chains'],
): TatchiChainConfig[] {
  const byNetwork = new Map<TatchiChainNetwork, TatchiChainConfig>(
    defaults.map((chain) => [chain.network, { ...chain }]),
  );
  const orderedNetworks: TatchiChainNetwork[] = [];

  if (Array.isArray(overrides)) {
    for (const override of overrides) {
      const network = resolveChainNetwork((override as { network?: unknown }).network);
      const resolved = resolveChainConfig({
        input: override as TatchiChainConfigInput,
        fallback: byNetwork.get(network),
      });
      byNetwork.set(network, resolved);
      if (!orderedNetworks.includes(network)) {
        orderedNetworks.push(network);
      }
    }
  }

  for (const chain of defaults) {
    if (!orderedNetworks.includes(chain.network)) {
      orderedNetworks.push(chain.network);
    }
  }

  const resolved = orderedNetworks
    .map((network) => byNetwork.get(network))
    .filter((chain): chain is TatchiChainConfig => !!chain);
  if (!resolved.some((chain) => isNearChainNetwork(chain.network))) {
    throw new Error(
      '[configPresets] Missing required config: chains (at least one near-* network)',
    );
  }
  return resolved;
}
