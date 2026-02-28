export type ConsoleSmartWalletScopeType = 'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'POLICY' | 'WALLET_SEGMENT';

export type ConsoleSmartWalletMode = 'DISABLED' | 'OPTIONAL' | 'REQUIRED';

export type ConsoleSmartWalletAccountType = 'EOA' | 'SMART_ACCOUNT';

export type ConsoleSmartWalletPaymasterMode = 'DISABLED' | 'AUTO' | 'REQUIRED';

export type ConsoleSmartWalletFallbackBehavior = 'FAIL_CLOSED' | 'FALLBACK_TO_EOA';

export type ConsoleSmartWalletEntryPointVersion = 'v0.6' | 'v0.7';

export interface ConsoleSmartWalletBundlerConfig {
  provider: string;
  entryPointVersion: ConsoleSmartWalletEntryPointVersion;
  maxFeePerGasGwei: number;
  maxPriorityFeePerGasGwei: number;
}

export interface ConsoleSmartWalletConfig {
  id: string;
  orgId: string;
  scopeType: ConsoleSmartWalletScopeType;
  projectId: string | null;
  environmentId: string | null;
  policyId: string | null;
  walletSegmentId: string | null;
  enabled: boolean;
  mode: ConsoleSmartWalletMode;
  accountType: ConsoleSmartWalletAccountType;
  paymasterMode: ConsoleSmartWalletPaymasterMode;
  fallbackBehavior: ConsoleSmartWalletFallbackBehavior;
  bundler: ConsoleSmartWalletBundlerConfig | null;
  createdAt: string;
  updatedAt: string;
}

export interface ListConsoleSmartWalletRequest {
  scopeType?: ConsoleSmartWalletScopeType;
  projectId?: string;
  environmentId?: string;
  policyId?: string;
  walletSegmentId?: string;
}

export interface CreateConsoleSmartWalletRequest {
  id?: string;
  scopeType: ConsoleSmartWalletScopeType;
  projectId?: string;
  environmentId?: string;
  policyId?: string;
  walletSegmentId?: string;
  enabled?: boolean;
  mode?: ConsoleSmartWalletMode;
  accountType?: ConsoleSmartWalletAccountType;
  paymasterMode?: ConsoleSmartWalletPaymasterMode;
  fallbackBehavior?: ConsoleSmartWalletFallbackBehavior;
  bundler?: ConsoleSmartWalletBundlerConfig | null;
}

export interface UpdateConsoleSmartWalletRequest {
  scopeType?: ConsoleSmartWalletScopeType;
  projectId?: string;
  environmentId?: string;
  policyId?: string;
  walletSegmentId?: string;
  enabled?: boolean;
  mode?: ConsoleSmartWalletMode;
  accountType?: ConsoleSmartWalletAccountType;
  paymasterMode?: ConsoleSmartWalletPaymasterMode;
  fallbackBehavior?: ConsoleSmartWalletFallbackBehavior;
  bundler?: ConsoleSmartWalletBundlerConfig | null;
}
