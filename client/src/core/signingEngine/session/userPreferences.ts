import { ConfirmationConfig, DEFAULT_CONFIRMATION_CONFIG } from '../../types/signer-worker';
import { IndexedDBManager, type IndexedDBEvent } from '../../indexedDB';
import { getLastSelectedNearAccount } from '../../accountData/near/accountProjection';
import { toWalletId, type WalletId } from '../interfaces/ecdsaChainTarget';

export class UserPreferencesManager {
  private confirmationConfigChangeListeners: Set<(config: ConfirmationConfig) => void> =
    new Set();
  private currentWalletChangeListeners: Set<(walletId: WalletId | null) => void> = new Set();

  private currentWalletId: WalletId | undefined;
  private confirmationConfig: ConfirmationConfig = DEFAULT_CONFIRMATION_CONFIG;
  private unsubscribeFromIndexedDB?: () => void;

  constructor() {
    this.subscribeToIndexedDBChanges();
  }

  onConfirmationConfigChange(callback: (config: ConfirmationConfig) => void): () => void {
    this.confirmationConfigChangeListeners.add(callback);
    return () => {
      this.confirmationConfigChangeListeners.delete(callback);
    };
  }

  onCurrentWalletChange(callback: (walletId: WalletId | null) => void): () => void {
    this.currentWalletChangeListeners.add(callback);
    return () => {
      this.currentWalletChangeListeners.delete(callback);
    };
  }

  private notifyConfirmationConfigChange(config: ConfirmationConfig): void {
    if (this.confirmationConfigChangeListeners.size === 0) return;
    for (const listener of this.confirmationConfigChangeListeners) {
      listener(config);
    }
  }

  private notifyCurrentWalletChange(walletId: WalletId | null): void {
    if (this.currentWalletChangeListeners.size === 0) return;
    for (const listener of this.currentWalletChangeListeners) {
      try {
        listener(walletId);
      } catch {}
    }
  }

  private sanitizeConfirmationConfig(
    config?: Partial<ConfirmationConfig> | null,
  ): Partial<ConfirmationConfig> {
    if (!config) return {};
    const { uiMode, behavior, autoProceedDelay } = config as ConfirmationConfig;
    const next: Partial<ConfirmationConfig> = {};
    if (uiMode != null) next.uiMode = uiMode;
    if (behavior != null) next.behavior = behavior;
    if (autoProceedDelay != null) next.autoProceedDelay = autoProceedDelay;
    return next;
  }

  private mergeConfirmationConfig(
    base: Partial<ConfirmationConfig>,
    patch: Partial<ConfirmationConfig>,
  ): ConfirmationConfig {
    const merged = { ...base, ...patch } as Partial<ConfirmationConfig>;
    return {
      uiMode: merged.uiMode ?? DEFAULT_CONFIRMATION_CONFIG.uiMode,
      behavior: merged.behavior ?? DEFAULT_CONFIRMATION_CONFIG.behavior,
      autoProceedDelay: merged.autoProceedDelay ?? DEFAULT_CONFIRMATION_CONFIG.autoProceedDelay,
    };
  }

  async initFromIndexedDB(): Promise<void> {
    await this.loadUserSettings().catch((error) => {
      console.warn('[SigningEngine]: Failed to initialize user settings:', error);
    });
  }

  private subscribeToIndexedDBChanges(): void {
    this.unsubscribeFromIndexedDB = IndexedDBManager.onChange((event) => {
      void this.handleIndexedDBEvent(event).catch((error) => {
        console.warn('[SigningEngine]: Error handling IndexedDB event:', error);
      });
    });
  }

  private async handleIndexedDBEvent(event: IndexedDBEvent): Promise<void> {
    switch (event.type) {
      case 'preferences-updated':
      case 'user-updated':
        if (this.currentWalletId && String(event.accountId) === String(this.currentWalletId)) {
          await this.reloadUserSettings();
        }
        break;
      case 'user-deleted':
        if (this.currentWalletId && String(event.accountId) === String(this.currentWalletId)) {
          this.currentWalletId = undefined;
          this.confirmationConfig = DEFAULT_CONFIRMATION_CONFIG;
        }
        break;
    }
  }

  destroy(): void {
    if (this.unsubscribeFromIndexedDB) {
      this.unsubscribeFromIndexedDB();
      this.unsubscribeFromIndexedDB = undefined;
    }
    this.confirmationConfigChangeListeners.clear();
    this.currentWalletChangeListeners.clear();
  }

  getCurrentWalletId(): WalletId | null {
    return this.currentWalletId ?? null;
  }

  getConfirmationConfig(): ConfirmationConfig {
    return this.confirmationConfig;
  }

  applyWalletHostConfirmationConfig(
    args:
      | {
          walletId?: WalletId | null;
          confirmationConfig: ConfirmationConfig;
        }
      | undefined,
  ): void {
    const walletId = args?.walletId;
    const confirmationConfig = args?.confirmationConfig ?? DEFAULT_CONFIRMATION_CONFIG;
    const sanitized = this.sanitizeConfirmationConfig(confirmationConfig);
    const next = this.mergeConfirmationConfig(DEFAULT_CONFIRMATION_CONFIG, sanitized);

    if (walletId) {
      const prev = this.currentWalletId;
      this.currentWalletId = walletId;
      if (!prev || String(prev) !== String(walletId)) {
        this.notifyCurrentWalletChange(walletId);
      }
    }

    this.confirmationConfig = next;
    this.notifyConfirmationConfigChange(this.confirmationConfig);
  }

  setCurrentWallet(walletId: WalletId): void {
    const prev = this.currentWalletId;
    this.currentWalletId = walletId;
    if (!prev || String(prev) !== String(walletId)) {
      this.notifyCurrentWalletChange(walletId);
    }
    if (!IndexedDBManager.isDisabled()) {
      void this.loadSettingsForWallet(walletId).catch(() => undefined);
    }
  }

  private applyStoredPreferences(
    preferences: { confirmationConfig?: ConfirmationConfig } | undefined,
  ): void {
    if (!preferences?.confirmationConfig) return;
    const sanitized = this.sanitizeConfirmationConfig(preferences.confirmationConfig);
    this.confirmationConfig = this.mergeConfirmationConfig(this.confirmationConfig, sanitized);
    this.notifyConfirmationConfigChange(this.confirmationConfig);
  }

  private async loadSettingsForWallet(walletId: WalletId): Promise<void> {
    if (IndexedDBManager.isDisabled()) return;
    const preferences = await IndexedDBManager.getWalletPreferences(walletId).catch(() => undefined);
    this.applyStoredPreferences(preferences);
  }

  async reloadUserSettings(): Promise<void> {
    const walletId = this.getCurrentWalletId();
    if (!walletId) return;
    await this.loadSettingsForWallet(walletId);
  }

  setConfirmBehavior(behavior: 'requireClick' | 'skipClick'): void {
    this.confirmationConfig = this.mergeConfirmationConfig(this.confirmationConfig, { behavior });
    this.notifyConfirmationConfigChange(this.confirmationConfig);
    void this.saveUserSettings();
  }

  setConfirmationConfig(config: Partial<ConfirmationConfig>, opts?: { persist?: boolean }): void {
    const sanitized = this.sanitizeConfirmationConfig(config);
    this.confirmationConfig = this.mergeConfirmationConfig(this.confirmationConfig, sanitized);
    this.notifyConfirmationConfigChange(this.confirmationConfig);
    if (opts?.persist !== false) {
      void this.saveUserSettings();
    }
  }

  async loadUserSettings(): Promise<void> {
    if (IndexedDBManager.isDisabled()) return;
    const last = await getLastSelectedNearAccount(IndexedDBManager).catch(() => null);
    if (!last) {
      console.debug('[SigningEngine]: No last user found, using default settings');
      return;
    }
    this.currentWalletId = toWalletId(last.profileId);
    await this.loadSettingsForWallet(this.currentWalletId);
  }

  async saveUserSettings(): Promise<void> {
    try {
      const walletId = this.currentWalletId ?? undefined;
      if (!walletId) {
        console.warn(
          '[UserPreferences]: No current wallet set; keeping confirmation config in memory only',
        );
        return;
      }

      await IndexedDBManager.updateWalletPreferences({
        walletId,
        preferences: {
          confirmationConfig: this.confirmationConfig,
        },
      });
    } catch (error) {
      console.warn('[SigningEngine]: Failed to save user settings:', error);
    }
  }
}

const UserPreferencesInstance = new UserPreferencesManager();
export default UserPreferencesInstance;
