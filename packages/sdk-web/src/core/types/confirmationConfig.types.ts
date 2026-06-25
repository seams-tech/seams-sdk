import type { ConfirmationBehavior, ConfirmationUIMode } from './signer-worker';

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

