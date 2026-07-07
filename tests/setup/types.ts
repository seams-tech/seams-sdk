/**
 * Shared test configuration for Passkey/threshold e2e-style tests.
 *
 * In the threshold-only architecture:
 * - These values are threaded into the SeamsWeb instance and ultimately
 *   into SigningEngine, NearClient, and the UserConfirm worker configuration.
 * - `nearRpcUrl` is used by confirmTxFlow and signing helpers
 *   to fetch NEAR context consistently.
 */
export interface PasskeyTestConfig {
  frontendUrl: string;
  nearNetwork: 'testnet' | 'mainnet';
  nearRpcUrl: string;
  relayerAccount: string;
  walletOrigin: string;
  rpId: string;
  relayer?: {
    url: string;
  };
  testReceiverAccountId: string;
}

export type PasskeyTestConfigOverrides = Partial<PasskeyTestConfig>;

export type PasskeyTestSetupOptions = PasskeyTestConfigOverrides & {
  /**
   * When true, skip dynamic loading of SeamsWeb + global fallback injection.
   * Useful for lightweight lit-component tests that only need the import map.
   */
  skipSeamsWebInit?: boolean;
  /**
   * When true, inject the test import map into wallet-service iframe documents.
   * Use only for tests that evaluate /_test-sdk/esm modules inside the wallet frame.
   */
  injectWalletServiceImportMap?: boolean;
};
