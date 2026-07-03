import { toPublicKeyStringFromSecretKey } from '../nearKeys';
import type { NormalizedLogger } from '../logger';
import type { SignerWasmModuleSupplier } from '../types';
import { ensureSignerWasmRuntime, type SignerWasmRuntimeState } from './wasm';

export type AuthServiceRuntimeState = SignerWasmRuntimeState & {
  readonly isInitialized: boolean;
  readonly relayerPublicKey: string;
};

export function createInitialAuthServiceRuntimeState(): AuthServiceRuntimeState {
  return {
    isInitialized: false,
    relayerPublicKey: '',
    signerWasmReady: false,
  };
}

export async function ensureAuthServiceSignerWasmReady(input: {
  readonly state: AuthServiceRuntimeState;
  readonly signerWasmOverride?: SignerWasmModuleSupplier;
  readonly logger: NormalizedLogger;
}): Promise<AuthServiceRuntimeState> {
  const signerState = await ensureSignerWasmRuntime({
    state: { signerWasmReady: input.state.signerWasmReady },
    override: input.signerWasmOverride,
    logger: input.logger,
  });
  return {
    ...input.state,
    signerWasmReady: signerState.signerWasmReady,
  };
}

export async function ensureAuthServiceRuntimeReady(input: {
  readonly state: AuthServiceRuntimeState;
  readonly relayerPrivateKey: string;
  readonly signerWasmOverride?: SignerWasmModuleSupplier;
  readonly logger: NormalizedLogger;
}): Promise<AuthServiceRuntimeState> {
  if (input.state.isInitialized) return input.state;

  let relayerPublicKey = '';
  try {
    relayerPublicKey = toPublicKeyStringFromSecretKey(input.relayerPrivateKey);
  } catch {
    input.logger.warn(
      'Failed to derive public key from relayerPrivateKey; ensure it is in ed25519:<base58> format',
    );
  }

  const signerReadyState = await ensureAuthServiceSignerWasmReady({
    state: {
      ...input.state,
      relayerPublicKey,
    },
    signerWasmOverride: input.signerWasmOverride,
    logger: input.logger,
  });

  return {
    ...signerReadyState,
    isInitialized: true,
  };
}
