import { coerceThemeMode } from '@shared/utils/theme';
import { toTrimmedString } from '@shared/utils/validation';
import type { EcdsaSignerProvisioningDefaults } from '../types/ecdsaSignerProvisioningDefaults';
import { parseServerEnvironmentBudgetAllowance } from '../signingEngine/session/budget/policy';
import type {
  AppearanceTheme,
  SeamsChainConfig,
  SeamsChainConfigInput,
  SeamsChainNetwork,
  SeamsConfigsInput,
  ThemeMode,
  ThemePaletteName,
} from '../types/seams';
import {
  isEvmChainNetwork,
  isNearChainNetwork,
  isTempoChainNetwork,
  isSeamsChainNetwork,
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

export function resolveThemeMode(args: { value: unknown; fallback: ThemeMode }): ThemeMode {
  if (args.value == null) return args.fallback;
  const parsed = coerceThemeMode(args.value);
  if (!parsed) {
    throw new Error("[configPresets] Invalid config: appearance.theme.mode must be 'light' or 'dark'");
  }
  return parsed;
}

function resolveAppearanceThemeId(args: { value: unknown; fallback: string }): string {
  const id = toTrimmedString(args.value) || args.fallback;
  if (!id) {
    throw new Error('[configPresets] Invalid config: appearance.theme.id must be non-empty');
  }
  return id;
}

function readLegacyTokenColors(tokens: unknown, mode: ThemeMode): Record<string, string> {
  if (!tokens || typeof tokens !== 'object') return {};
  const record = tokens as Record<string, unknown>;
  const modeRecord = record[mode];
  if (!modeRecord || typeof modeRecord !== 'object') return {};
  return toColorTokenRecord((modeRecord as Record<string, unknown>).colors);
}

export function resolveAppearanceTheme(args: {
  value: unknown;
  fallback: AppearanceTheme;
  legacyTokens?: unknown;
}): AppearanceTheme {
  const fallbackMode = args.fallback.mode;
  const fallbackShape = args.fallback.shape;
  const legacyMode = coerceThemeMode(args.value);
  if (legacyMode) {
    return {
      id: args.fallback.id,
      mode: legacyMode,
      colors: {
        ...args.fallback.colors,
        ...readLegacyTokenColors(args.legacyTokens, legacyMode),
      },
      ...(fallbackShape ? { shape: fallbackShape } : {}),
    };
  }

  if (args.value == null) {
    return {
      ...args.fallback,
      colors: {
        ...args.fallback.colors,
        ...readLegacyTokenColors(args.legacyTokens, fallbackMode),
      },
    };
  }

  if (typeof args.value !== 'object' || Array.isArray(args.value)) {
    throw new Error(
      '[configPresets] Invalid config: appearance.theme must be an object with id, mode, and optional colors',
    );
  }

  const record = args.value as Record<string, unknown>;
  const rawMode = record.mode;
  const mode = rawMode == null ? fallbackMode : coerceThemeMode(rawMode);
  if (!mode) {
    throw new Error("[configPresets] Invalid config: appearance.theme.mode must be 'light' or 'dark'");
  }

  /* A different theme id is a theme switch: replace colors/shape wholesale.
     Merging across ids lets keys the new theme doesn't define (e.g.
     passkeyHaloBackground) leak from the old theme forever — only same-id
     updates are partial. */
  const id = resolveAppearanceThemeId({ value: record.id, fallback: args.fallback.id });
  const isThemeSwitch = id !== args.fallback.id;

  /* shape merges like colors (incoming keys win); toColorTokenRecord is a
     generic string-record filter despite the name */
  const shape = {
    ...(isThemeSwitch ? {} : fallbackShape || {}),
    ...toColorTokenRecord(record.shape),
  };

  return {
    id,
    mode,
    colors: {
      ...(isThemeSwitch ? {} : args.fallback.colors),
      ...readLegacyTokenColors(args.legacyTokens, mode),
      ...toColorTokenRecord(record.colors),
    },
    ...(Object.keys(shape).length > 0 ? { shape } : {}),
  };
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

export function copyEcdsaSignerProvisioningDefaults(
  value: EcdsaSignerProvisioningDefaults,
): EcdsaSignerProvisioningDefaults {
  const tempoAllowance = parseServerEnvironmentBudgetAllowance({
    remainingUses: value.tempo.signingSession.remainingUses,
    policyVersion: 'sdk_config.threshold_ecdsa_provisioning.tempo',
  });
  const evmAllowance = parseServerEnvironmentBudgetAllowance({
    remainingUses: value.evm.signingSession.remainingUses,
    policyVersion: 'sdk_config.threshold_ecdsa_provisioning.evm',
  });
  return {
    tempo: {
      ...value.tempo,
      signingSession: {
        ...value.tempo.signingSession,
        remainingUses: tempoAllowance.remainingUses,
      },
    },
    evm: {
      ...value.evm,
      signingSession: {
        ...value.evm.signingSession,
        remainingUses: evmAllowance.remainingUses,
      },
    },
  };
}

export function resolveChainNetwork(network: unknown): SeamsChainNetwork {
  if (!isSeamsChainNetwork(network)) {
    throw new Error(`[configPresets] Invalid chain network: ${String(network || '')}`);
  }
  return network;
}

export function resolveChainConfig(args: {
  input: SeamsChainConfigInput;
  fallback?: SeamsChainConfig;
}): SeamsChainConfig {
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
  defaults: readonly SeamsChainConfig[],
  overrides: SeamsConfigsInput['chains'],
): SeamsChainConfig[] {
  if (Array.isArray(overrides)) {
    const defaultsByNetwork = new Map<SeamsChainNetwork, SeamsChainConfig>(
      defaults.map((chain) => [chain.network, { ...chain }]),
    );
    const byNetwork = new Map<SeamsChainNetwork, SeamsChainConfig>();
    const orderedNetworks: SeamsChainNetwork[] = [];
    for (const override of overrides) {
      const network = resolveChainNetwork((override as { network?: unknown }).network);
      const resolved = resolveChainConfig({
        input: override as SeamsChainConfigInput,
        fallback: defaultsByNetwork.get(network),
      });
      byNetwork.set(network, resolved);
      if (!orderedNetworks.includes(network)) {
        orderedNetworks.push(network);
      }
    }
    const resolved = orderedNetworks
      .map((network) => byNetwork.get(network))
      .filter((chain): chain is SeamsChainConfig => !!chain);
    if (!resolved.some((chain) => isNearChainNetwork(chain.network))) {
      throw new Error(
        '[configPresets] Missing required config: chains (at least one near-* network)',
      );
    }
    return resolved;
  }

  const resolved = defaults.map((chain) => ({ ...chain }));
  if (!resolved.some((chain) => isNearChainNetwork(chain.network))) {
    throw new Error(
      '[configPresets] Missing required config: chains (at least one near-* network)',
    );
  }
  return resolved;
}
