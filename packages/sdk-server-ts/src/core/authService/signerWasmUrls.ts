import type { NormalizedLogger } from '../logger';

// Built package location for signer glue imported by AuthService.
const SIGNER_WASM_PACKAGE_DIST_PATH = '../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm';
// Source-tree location when executed directly from packages/sdk-server-ts/src/core/authService.
const SIGNER_WASM_SOURCE_PATH = '../../../../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm';

export function getSignerWasmUrls(logger: NormalizedLogger): URL[] {
  const paths = [SIGNER_WASM_PACKAGE_DIST_PATH, SIGNER_WASM_SOURCE_PATH];
  const resolved: URL[] = [];
  const baseUrl = import.meta.url;

  for (const path of paths) {
    try {
      if (!baseUrl) throw new Error('import.meta.url is undefined');
      resolved.push(new URL(path, baseUrl));
    } catch (err) {
      logger.warn(`Failed to resolve signer WASM relative URL for path "${path}":`, err);
    }
  }

  if (!resolved.length) {
    throw new Error(
      'Unable to resolve signer WASM location from import.meta.url. Provide AuthServiceConfig.signerWasm.moduleOrPath in this runtime.',
    );
  }

  return resolved;
}
