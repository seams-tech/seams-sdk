import { ConfirmationConfig, DEFAULT_CONFIRMATION_CONFIG } from '../../types/signer-worker';
import type { AccountSignerRecord, IndexedDBEvent, UserPreferences } from '../../indexedDB';
import { getLastSelectedNearAccount } from '../../accountData/near/accountProjection';
import type { ProfileLastSelectionPort } from '../../indexedDB/profileAccountProjection';
import { toWalletId, type WalletId } from '../interfaces/ecdsaChainTarget';

export type UserPreferencesStorePort = ProfileLastSelectionPort & {
  isDisabled: () => boolean;
  onChange: (callback: (event: IndexedDBEvent) => void) => () => void;
  listAccountSignersByProfile: (args: {
    profileId: string;
    status?: AccountSignerRecord['status'];
  }) => Promise<AccountSignerRecord[]>;
  getWalletPreferences: (walletId: WalletId) => Promise<Partial<UserPreferences>>;
  updateWalletPreferences: (args: {
    walletId: WalletId;
    preferences: Partial<UserPreferences>;
  }) => Promise<unknown>;
};

export type UserPreferencesManagerDeps = {
  store: UserPreferencesStorePort;
};

function accountSignerMetadataWalletId(signer: AccountSignerRecord): WalletId | null {
  const walletId = String(signer.metadata?.walletId || '').trim();
  if (!walletId) return null;
  try {
    return toWalletId(walletId);
  } catch {
    return null;
  }
}

function uniqueWalletIdsFromAccountSigners(signers: readonly AccountSignerRecord[]): WalletId[] {
  const walletIds: WalletId[] = [];
  const seen = new Set<string>();
  for (const signer of signers) {
    const walletId = accountSignerMetadataWalletId(signer);
    if (!walletId) continue;
    const key = String(walletId);
    if (seen.has(key)) continue;
    seen.add(key);
    walletIds.push(walletId);
  }
  return walletIds;
}

async function resolveWalletIdForLastSelectedProfile(args: {
  store: UserPreferencesStorePort;
  profileId: string;
}): Promise<WalletId | null> {
  const signers = await args.store
    .listAccountSignersByProfile({
      profileId: args.profileId,
      status: 'active',
    })
    .catch(() => []);
  const walletIds = uniqueWalletIdsFromAccountSigners(signers);
  return walletIds.length === 1 ? walletIds[0]! : null;
}

export class UserPreferencesManager {
  private confirmationConfigChangeListeners: Set<(config: ConfirmationConfig) => void> =
    new Set();
  private currentWalletChangeListeners: Set<(walletId: WalletId | null) => void> = new Set();

  private currentWalletId: WalletId | undefined;
  private confirmationConfig: ConfirmationConfig = DEFAULT_CONFIRMATION_CONFIG;
  private unsubscribeFromIndexedDB?: () => void;

  constructor(private readonly deps: UserPreferencesManagerDeps) {
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
    this.unsubscribeFromIndexedDB = this.deps.store.onChange((event) => {
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
    if (!this.deps.store.isDisabled()) {
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
    if (this.deps.store.isDisabled()) return;
    const preferences = await this.deps.store
      .getWalletPreferences(walletId)
      .catch(() => undefined);
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
    if (this.deps.store.isDisabled()) return;
    const last = await getLastSelectedNearAccount(this.deps.store).catch(() => null);
    if (!last) {
      console.debug('[SigningEngine]: No last user found, using default settings');
      return;
    }
    const walletId = await resolveWalletIdForLastSelectedProfile({
      store: this.deps.store,
      profileId: last.profileId,
    });
    if (!walletId) {
      console.debug('[SigningEngine]: Last profile has no wallet-bound signer metadata');
      return;
    }
    this.currentWalletId = walletId;
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

      await this.deps.store.updateWalletPreferences({
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
