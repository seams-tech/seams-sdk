import type { ConfirmationBehavior, ConfirmationConfig, ConfirmationUIMode } from './signer-worker';

export type VisibleConfirmationUIMode = Exclude<ConfirmationUIMode, 'none'>;

export type SilentConfirmationConfig = {
  kind: 'silent';
  uiMode: 'none';
  behavior?: never;
  autoProceedDelay?: never;
};

export type InteractiveConfirmationConfig = {
  kind: 'interactive';
  uiMode: VisibleConfirmationUIMode;
  behavior: Extract<ConfirmationBehavior, 'requireClick'>;
  autoProceedDelay?: never;
};

export type AutoProceedConfirmationConfig = {
  kind: 'auto_proceed';
  uiMode: VisibleConfirmationUIMode;
  behavior: Extract<ConfirmationBehavior, 'skipClick'>;
  autoProceedDelay: number;
};

export type NormalizedConfirmationConfig =
  | SilentConfirmationConfig
  | InteractiveConfirmationConfig
  | AutoProceedConfirmationConfig;

type RawConfirmationConfigInput = Partial<ConfirmationConfig> | null | undefined;

function normalizeVisibleUiMode(uiMode: unknown): VisibleConfirmationUIMode {
  return uiMode === 'drawer' ? 'drawer' : 'modal';
}

function normalizeAutoProceedDelay(delay: unknown): number {
  if (typeof delay !== 'number' || !Number.isFinite(delay)) return 0;
  return Math.max(0, Math.floor(delay));
}

export function normalizeConfirmationConfig(
  input: RawConfirmationConfigInput,
): NormalizedConfirmationConfig {
  if (input?.uiMode === 'none') {
    return {
      kind: 'silent',
      uiMode: 'none',
    };
  }

  const uiMode = normalizeVisibleUiMode(input?.uiMode);

  if (input?.behavior === 'skipClick') {
    return {
      kind: 'auto_proceed',
      uiMode,
      behavior: 'skipClick',
      autoProceedDelay: normalizeAutoProceedDelay(input.autoProceedDelay),
    };
  }

  return {
    kind: 'interactive',
    uiMode,
    behavior: 'requireClick',
  };
}

export function silentConfirmationConfig(): NormalizedConfirmationConfig {
  return {
    kind: 'silent',
    uiMode: 'none',
  };
}

export function assertNeverConfirmationConfig(value: never): never {
  throw new Error(`Unsupported confirmation config: ${String((value as { kind?: unknown }).kind)}`);
}
