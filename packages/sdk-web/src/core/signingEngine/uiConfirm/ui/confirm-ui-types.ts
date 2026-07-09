import type { UserConfirmSecurityContext } from '@/core/types';
import type { AppearanceConfig, ThemeMode } from '@/core/types/seams';
import type { TxDisplayModel } from '@/core/signingEngine/interfaces/display';
import type {
  EmailOtpConfirmPrompt,
  SigningAuthMode,
} from '@/core/signingEngine/stepUpConfirmation/types';

export type { ThemeMode } from '@/core/types/seams';

export interface ConfirmUIElement {
  /** When true, host controls element removal (two-phase close). */
  deferClose?: boolean;
  /** Optional close API for programmatic removal with a final decision state. */
  close?(confirmed: boolean): void;
}

export type ConfirmationUIMode = 'none' | 'modal' | 'drawer';

// Public handle returned by mount/await helpers

export type ConfirmUIUpdate = {
  nearAccountId?: string;
  model?: TxDisplayModel;
  intentDigest?: string;
  securityContext?: Partial<UserConfirmSecurityContext>;
  theme?: ThemeMode;
  appearance?: AppearanceConfig;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
  loading?: boolean;
  errorMessage?: string;
  confirmText?: string;
  cancelText?: string;
  title?: string;
  body?: string;
  signingAuthMode?: SigningAuthMode;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
};

export interface ConfirmUIHandle {
  close(confirmed: boolean): void;
  update(props: ConfirmUIUpdate): void;
  /**
   * Subscribe to cancel events emitted by the mounted confirmer element.
   * Returns an unsubscribe function.
   */
  onCancel?(listener: (detail: { error?: string }) => void): () => void;
}

export type ConfirmUIPromptDiagnostics = {
  kind: 'confirm_ui_prompt_diagnostics_v1';
  elementDefineMs: number;
  mountMs: number;
  hostFirstUpdateMs: number;
  hostInteractiveMs: number;
  confirmEventMs: number;
  decisionWaitMs: number;
};
