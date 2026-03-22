import { ConfirmationConfig, DEFAULT_CONFIRMATION_CONFIG } from '../../types/signer-worker';
import type { AccountId } from '../../types/accountIds';
import { IndexedDBManager, type IndexedDBEvent } from '../../indexedDB';

export class UserPreferencesManager {
  private confirmationConfigChangeListeners: Set<(config: ConfirmationConfig) => void> =
    new Set();
  private currentUserChangeListeners: Set<(nearAccountId: AccountId | null) => void> = new Set();

  private currentUserAccountId: AccountId | undefined;
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

  onCurrentUserChange(callback: (nearAccountId: AccountId | null) => void): () => void {
    this.currentUserChangeListeners.add(callback);
    return () => {
      this.currentUserChangeListeners.delete(callback);
    };
  }

  private notifyConfirmationConfigChange(config: ConfirmationConfig): void {
    if (this.confirmationConfigChangeListeners.size === 0) return;
    for (const listener of this.confirmationConfigChangeListeners) {
      listener(config);
    }
  }

  private notifyCurrentUserChange(nearAccountId: AccountId | null): void {
    if (this.currentUserChangeListeners.size === 0) return;
    for (const listener of this.currentUserChangeListeners) {
      try {
        listener(nearAccountId);
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
    this.unsubscribeFromIndexedDB = IndexedDBManager.clientDB.onChange((event) => {
      void this.handleIndexedDBEvent(event).catch((error) => {
        console.warn('[SigningEngine]: Error handling IndexedDB event:', error);
      });
    });
  }

  private async handleIndexedDBEvent(event: IndexedDBEvent): Promise<void> {
    switch (event.type) {
      case 'preferences-updated':
      case 'user-updated':
        if (event.accountId === this.currentUserAccountId) {
          await this.reloadUserSettings();
        }
        break;
      case 'user-deleted':
        if (event.accountId === this.currentUserAccountId) {
          this.currentUserAccountId = undefined;
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
    this.currentUserChangeListeners.clear();
  }

  getCurrentUserAccountId(): AccountId {
    if (!this.currentUserAccountId) {
      console.debug(
        '[UserPreferencesManager]: getCurrentUserAccountId called with no current user; returning empty id',
      );
      return '' as AccountId;
    }
    return this.currentUserAccountId;
  }

  getConfirmationConfig(): ConfirmationConfig {
    return this.confirmationConfig;
  }

  applyWalletHostConfirmationConfig(
    args:
      | {
          nearAccountId?: AccountId | null;
          confirmationConfig: ConfirmationConfig;
        }
      | undefined,
  ): void {
    const nearAccountId = args?.nearAccountId;
    const confirmationConfig = args?.confirmationConfig ?? DEFAULT_CONFIRMATION_CONFIG;
    const sanitized = this.sanitizeConfirmationConfig(confirmationConfig);
    const next = this.mergeConfirmationConfig(DEFAULT_CONFIRMATION_CONFIG, sanitized);

    if (nearAccountId) {
      const prev = this.currentUserAccountId;
      this.currentUserAccountId = nearAccountId;
      if (!prev || String(prev) !== String(nearAccountId)) {
        this.notifyCurrentUserChange(nearAccountId);
      }
    }

    this.confirmationConfig = next;
    this.notifyConfirmationConfigChange(this.confirmationConfig);
  }

  setCurrentUser(nearAccountId: AccountId): void {
    const prev = this.currentUserAccountId;
    this.currentUserAccountId = nearAccountId;
    if (!prev || String(prev) !== String(nearAccountId)) {
      this.notifyCurrentUserChange(nearAccountId);
    }
    if (!IndexedDBManager.clientDB.isDisabled()) {
      void this.loadSettingsForUser(nearAccountId).catch(() => undefined);
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

  private async loadSettingsForUser(nearAccountId: AccountId): Promise<void> {
    if (IndexedDBManager.clientDB.isDisabled()) return;
    const context = await IndexedDBManager.clientDB
      .resolveNearAccountContext(nearAccountId)
      .catch(() => null);
    if (!context?.profileId) return;
    const profile = await IndexedDBManager.clientDB.getProfile(context.profileId).catch(() => null);
    if (!profile) return;
    this.applyStoredPreferences(profile.preferences);
  }

  async reloadUserSettings(): Promise<void> {
    await this.loadSettingsForUser(this.getCurrentUserAccountId());
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
    if (IndexedDBManager.clientDB.isDisabled()) return;
    const last = await IndexedDBManager.clientDB.getLastSelectedNearAccount().catch(() => null);
    if (!last) {
      console.debug('[SigningEngine]: No last user found, using default settings');
      return;
    }
    this.currentUserAccountId = last.nearAccountId;
    const profile = await IndexedDBManager.clientDB.getProfile(last.profileId).catch(() => null);
    if (!profile) {
      console.debug('[SigningEngine]: No profile found for last user, using default settings');
      return;
    }
    this.applyStoredPreferences(profile.preferences);
  }

  async saveUserSettings(): Promise<void> {
    try {
      const accountId: AccountId | undefined = this.currentUserAccountId ?? undefined;
      if (!accountId) {
        console.warn(
          '[UserPreferences]: No current user set; keeping confirmation config in memory only',
        );
        return;
      }

      await IndexedDBManager.clientDB.updatePreferences(accountId, {
        confirmationConfig: this.confirmationConfig,
      });
    } catch (error) {
      console.warn('[SigningEngine]: Failed to save user settings:', error);
    }
  }
}

const UserPreferencesInstance = new UserPreferencesManager();
export default UserPreferencesInstance;
