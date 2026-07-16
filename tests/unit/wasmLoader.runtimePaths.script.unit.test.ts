import { expect, test } from '@playwright/test';
import { resolveWasmUrl } from '../../packages/sdk-web/src/core/walletRuntimePaths/wasm-loader';

type GlobalWithWindow = any;

const g = globalThis as GlobalWithWindow;
const originalWindow = g.window;
const originalSelf = g.self;

test.afterEach(() => {
  g.window = originalWindow;
  g.self = originalSelf;
});

test('resolveWasmUrl uses the embedded wallet SDK workers base when available', () => {
  g.window = {
    __W3A_WALLET_SDK_BASE__: 'https://wallet.example.test/sdk/',
  } as (Window & typeof globalThis) & { __W3A_WALLET_SDK_BASE__?: string };
  g.self = {
    location: {
      href: 'https://wallet.example.test/sdk/wallet-iframe-host-runtime.js?v=1',
      origin: 'https://wallet.example.test',
    } as Location,
  } as unknown as (typeof globalThis) & { location?: Location };

  expect(String(resolveWasmUrl('wasm_signer_worker_bg.wasm', 'NEAR Signer DERIVATION'))).toBe(
    'https://wallet.example.test/sdk/workers/wasm_signer_worker_bg.wasm',
  );
});
