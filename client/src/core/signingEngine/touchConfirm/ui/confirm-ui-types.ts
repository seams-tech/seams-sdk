import type { UserConfirmSecurityContext } from '@/core/types';
import type { TxDisplayModel } from '@/core/signingEngine/touchConfirm/shared/displayModel';

export interface ConfirmUIElement {
  /** When true, host controls element removal (two-phase close). */
  deferClose?: boolean;
  /** Optional close API for programmatic removal with a final decision state. */
  close?(confirmed: boolean): void;
}

export type ConfirmationUIMode = 'none' | 'modal' | 'drawer';

// Theme name used across confirm UI
export type ThemeName = 'dark' | 'light';
// Public handle returned by mount/await helpers

export type ConfirmUIUpdate = {
  nearAccountId?: string;
  model?: TxDisplayModel;
  securityContext?: Partial<UserConfirmSecurityContext>;
  theme?: ThemeName;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
  loading?: boolean;
  errorMessage?: string;
  title?: string;
  body?: string;
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
