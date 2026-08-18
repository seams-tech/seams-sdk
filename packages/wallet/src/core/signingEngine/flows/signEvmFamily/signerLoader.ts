import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';

export type Secp256k1EngineCtor = new (opts: unknown) => unknown;
export type WebAuthnP256EngineCtor = new (workerCtx: unknown) => unknown;
export type SignEvmWithUiConfirmFn = (args: unknown) => Promise<EvmSignedResult>;
export type SignEvmFamilyWithUiConfirmForTempoFn = (
  args: unknown,
) => Promise<TempoSignedResult | EvmSignedResult>;

let secp256k1EngineCtorPromise: Promise<Secp256k1EngineCtor> | null = null;
let webAuthnP256EngineCtorPromise: Promise<WebAuthnP256EngineCtor> | null = null;
let signEvmWithUiConfirmPromise: Promise<SignEvmWithUiConfirmFn> | null = null;
let signEvmFamilyWithUiConfirmForTempoPromise: Promise<SignEvmFamilyWithUiConfirmForTempoFn> | null =
  null;

export async function loadSecp256k1EngineCtor(): Promise<Secp256k1EngineCtor> {
  if (!secp256k1EngineCtorPromise) {
    secp256k1EngineCtorPromise = import('./signers/secp256k1').then(
      (mod) => mod.Secp256k1Engine as Secp256k1EngineCtor,
    );
  }
  return await secp256k1EngineCtorPromise;
}

export async function loadWebAuthnP256EngineCtor(): Promise<WebAuthnP256EngineCtor> {
  if (!webAuthnP256EngineCtorPromise) {
    webAuthnP256EngineCtorPromise = import('./signers/webauthnP256').then(
      (mod) => mod.WebAuthnP256Engine as WebAuthnP256EngineCtor,
    );
  }
  return await webAuthnP256EngineCtorPromise;
}

export async function loadSignEvmWithUiConfirm(): Promise<SignEvmWithUiConfirmFn> {
  if (!signEvmWithUiConfirmPromise) {
    signEvmWithUiConfirmPromise = import('./signEvmWithUiConfirm').then(
      (mod) => mod.signEvmWithUiConfirm as SignEvmWithUiConfirmFn,
    );
  }
  return await signEvmWithUiConfirmPromise;
}

export async function loadSignEvmFamilyWithUiConfirmForTempo(): Promise<SignEvmFamilyWithUiConfirmForTempoFn> {
  if (!signEvmFamilyWithUiConfirmForTempoPromise) {
    signEvmFamilyWithUiConfirmForTempoPromise = import('./signEvmFamilyWithUiConfirmForTempo').then(
      (mod) => mod.signEvmFamilyWithUiConfirmForTempo as SignEvmFamilyWithUiConfirmForTempoFn,
    );
  }
  return await signEvmFamilyWithUiConfirmForTempoPromise;
}
