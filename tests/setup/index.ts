/**
 * E2E Test Setup Utilities
 *
 * Provides reusable browser setup functions for UI, iframe, and component tests:
 * - Chromium virtual WebAuthn
 * - import-map wiring for local SDK modules
 * - wallet iframe worker URL normalization for the generic browser suite
 *
 * Intended lifecycle coverage lives in tests/e2e/intended-behaviours/harness.ts.
 *
 * IMPORTANT: Module Loading Strategy
 * ===================================
 *
 * This file uses STATIC imports at the top for types and utilities that are safe to load early.
 * However, SeamsWeb itself is imported DYNAMICALLY inside test functions to avoid
 * module loading race conditions with WebAuthn Virtual Authenticator setup.
 *
 * Why Dynamic Imports Are Necessary:
 * 1. WebAuthn Virtual Authenticator setup modifies browser environment
 * 2. This can interfere with import map processing timing
 * 3. Early imports may fail with "base64UrlEncode is not defined" errors
 * 4. Dynamic imports after setup ensure stable environment
 *
 * Setup Process:
 * ==============
 * The setup follows a precise sequence to avoid race conditions:
 * 1. WALLET SDK ROUTES: Install local wallet-origin SDK and wallet-service routes
 * 2. ENVIRONMENT SETUP: Configure WebAuthn Virtual Authenticator
 * 3. IMPORT MAP INJECTION: Add module resolution mappings to the page
 * 4. STABILIZATION WAIT: Allow browser environment to settle
 * 5. DYNAMIC IMPORTS: Load SeamsWeb after environment setup
 * 6. GLOBAL FALLBACK: Ensure base64UrlEncode is available as safety measure
 */

// STATIC IMPORTS: Safe to load early
// ===================================
// These imports are safe to use statically because:
// - Page: Playwright type, no runtime dependencies
// - type SeamsWeb: TypeScript type only, no runtime code
// - encoders: Utility functions used in Node.js context, not browser
import { Page, test } from '@playwright/test';
import { executeSequentialSetup } from './bootstrap';
import { DEFAULT_TEST_CONFIG } from './config';
import type { PasskeyTestConfig, PasskeyTestSetupOptions } from './types';
export { SDK_ESM_BASE_PATH, SDK_ESM_PATHS, sdkEsmPath } from './sdkEsmPaths';

// =============================================================================
// MAIN SETUP FUNCTION
// =============================================================================

/**
 * Generic browser setup function using the browser setup sequence.
 *
 * This function prepares UI, iframe, and component tests following a precise
 * sequence to avoid module loading race conditions:
 *
 * UserConfirm context:
 * - The wallet iframe now loads two cooperating workers:
 *   - UserConfirm worker: owns WebAuthn PRF + UserConfirm (`awaitUserConfirmationV2`).
 *   - Signer worker: derives WrapKeySeed from prfFirstB64u + wrapKeySalt supplied in wallet-origin
 *     requests and performs NEAR signing; confirmTxFlow never carries raw PRF material.
 *
 * 1. WALLET SDK ROUTES: Install local wallet-origin SDK and wallet-service routes
 * 2. ENVIRONMENT SETUP: Configure WebAuthn Virtual Authenticator
 * 3. IMPORT MAP INJECTION: Add module resolution mappings to the page
 * 4. STABILIZATION WAIT: Allow browser environment to settle
 * 5. DYNAMIC IMPORTS: Load SeamsWeb after environment setup
 * 6. GLOBAL FALLBACK: Ensure base64UrlEncode is available as safety measure
 */
export async function setupBasicPasskeyTest(
  page: Page,
  options: PasskeyTestSetupOptions = {},
): Promise<void> {
  const config: PasskeyTestConfig = { ...DEFAULT_TEST_CONFIG, ...options };

  // Generic browser tests still run through the local app origin and need their SDK assets mirrored.
  // Intended-behaviour contracts use their own harness and never import this shimmed setup path.
  try {
    const appOrigin = new URL(config.frontendUrl).origin;
    const rpId = config.rpId || '';

    // Make rpId available in all frames (wallet iframe mocks run cross-origin).
    await page.addInitScript(
      (args: { rpId: string }) => {
        try {
          const v = String(args?.rpId || '').trim();
          if (v) (window as any).__W3A_TEST_RP_ID__ = v;
        } catch {}
      },
      { rpId },
    );

    // (1) Lock __W3A_WALLET_SDK_BASE__ to per-frame same-origin /sdk/
    await page.addInitScript(
      (args: { appOrigin: string }) => {
        const { appOrigin } = args || ({} as any);
        try {
          const frameOrigin = (() => {
            try {
              const o = window.location?.origin;
              if (o && o !== 'null') return o;
            } catch {}
            return appOrigin || '';
          })();

          const base = String(frameOrigin || '').replace(/\/$/, '') + '/sdk/';
          Object.defineProperty(window, '__W3A_WALLET_SDK_BASE__', {
            get() {
              return base;
            },
            set() {
              /* ignore test overrides */
            },
            configurable: false,
          } as any);
          try {
            window.addEventListener(
              'W3A_WALLET_SDK_BASE_CHANGED' as any,
              (e: Event) => {
                try {
                  (e as any).stopImmediatePropagation?.();
                } catch {}
                try {
                  e.stopPropagation();
                } catch {}
              },
              true,
            );
          } catch {}
        } catch {}
      },
      { appOrigin },
    );

    // (2) Patch Worker constructor to force same-origin worker URLs (per-frame)
    await page.addInitScript(
      (args: { appOrigin: string }) => {
        const { appOrigin } = args || ({} as any);
        try {
          const frameOrigin = (() => {
            try {
              const o = window.location?.origin;
              if (o && o !== 'null') return o;
            } catch {}
            return appOrigin || '';
          })();

          const OriginalWorker = window.Worker;
          // Normalize worker URLs for both signer + UserConfirm workers.
          const normalize = (url: string) => {
            try {
              const u = new URL(url, frameOrigin);
              const filename = (u.pathname.split('/').pop() || '').toLowerCase();
              if (
                filename === 'passkey-confirm.worker.js' ||
                filename === 'near-signer.worker.js' ||
                filename === 'hss-client.worker.js'
              ) {
                const patchedPath = `/sdk/workers/${filename}`;
                return new URL(patchedPath + u.search + u.hash, frameOrigin).toString();
              }
              if (u.origin !== frameOrigin) {
                // preserve path/query/hash but swap origin
                return new URL(u.pathname + u.search + u.hash, frameOrigin).toString();
              }
              return u.toString();
            } catch {
              return url;
            }
          };
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const PatchedWorker: any = function (
            this: any,
            url: string | URL,
            options?: WorkerOptions,
          ) {
            const patchedUrl = normalize(String(url));
            return new (OriginalWorker as any)(patchedUrl, options);
          };
          PatchedWorker.prototype = (OriginalWorker as any).prototype;
          Object.defineProperty(window, 'Worker', { value: PatchedWorker });
        } catch {}
      },
      { appOrigin },
    );
  } catch {}

  // Execute the generic sequential setup process.
  const authenticatorId = await executeSequentialSetup(page, config, {
    skipSeamsWebInit: options.skipSeamsWebInit,
    injectWalletServiceImportMap: options.injectWalletServiceImportMap,
  });

  // environment ready
}

// =============================================================================
// SETUP HELPER FUNCTIONS
// =============================================================================

/**
 * Step 1: ENVIRONMENT SETUP
 * Configure WebAuthn Virtual Authenticator first
 */
/**
 * Handles the retained infrastructure skip for shared testnet faucet rate limiting.
 *
 * @param result - The test result object containing success status and error message
 * @returns boolean - true if test was skipped due to infrastructure issues, false otherwise
 */
export function handleInfrastructureErrors(result: { success: boolean; error?: string }): boolean {
  if (!result.success && result.error) {
    if (result.error.includes('429') && result.error.includes('Faucet service error')) {
      console.warn('⚠️  Test skipped due to testnet faucet rate limiting (HTTP 429)');
      console.warn('   This is expected when running multiple tests quickly.');
      console.warn('   Rerun the test later - this is not a test failure.');
      console.warn(`   Error: ${result.error}`);

      // Skip this test instead of failing
      test.skip(true, 'Testnet faucet rate limited (HTTP 429) - retry later');
      return true;
    }
  }

  return false;
}

export type { PasskeyTestConfig, PasskeyTestConfigOverrides } from './types';
export { DEFAULT_TEST_CONFIG } from './config';
