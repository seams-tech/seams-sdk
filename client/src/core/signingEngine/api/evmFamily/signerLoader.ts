import type { EvmSignedResult } from '../../chainAdaptors/evm/evmAdapter';
import type { TempoSignedResult } from '../../chainAdaptors/tempo/tempoAdapter';

export type Secp256k1EngineCtor = new (opts: unknown) => unknown;
export type WebAuthnP256EngineCtor = new (workerCtx: unknown) => unknown;
export type SignEvmWithTouchConfirmFn = (args: unknown) => Promise<EvmSignedResult>;
export type SignTempoWithTouchConfirmFn = (args: unknown) => Promise<TempoSignedResult>;

let secp256k1EngineCtorPromise: Promise<Secp256k1EngineCtor> | null = null;
let webAuthnP256EngineCtorPromise: Promise<WebAuthnP256EngineCtor> | null = null;
let signEvmWithTouchConfirmPromise: Promise<SignEvmWithTouchConfirmFn> | null = null;
let signTempoWithTouchConfirmPromise: Promise<SignTempoWithTouchConfirmFn> | null = null;

export async function loadSecp256k1EngineCtor(): Promise<Secp256k1EngineCtor> {
  if (!secp256k1EngineCtorPromise) {
    secp256k1EngineCtorPromise = import('../../signers/algorithms/secp256k1').then(
      (mod) => mod.Secp256k1Engine as Secp256k1EngineCtor,
    );
  }
  return await secp256k1EngineCtorPromise;
}

export async function loadWebAuthnP256EngineCtor(): Promise<WebAuthnP256EngineCtor> {
  if (!webAuthnP256EngineCtorPromise) {
    webAuthnP256EngineCtorPromise = import('../../signers/algorithms/webauthnP256').then(
      (mod) => mod.WebAuthnP256Engine as WebAuthnP256EngineCtor,
    );
  }
  return await webAuthnP256EngineCtorPromise;
}

export async function loadSignEvmWithTouchConfirm(): Promise<SignEvmWithTouchConfirmFn> {
  if (!signEvmWithTouchConfirmPromise) {
    signEvmWithTouchConfirmPromise = import('../../orchestration/evm/evmSigningFlow').then(
      (mod) => mod.signEvmWithTouchConfirm as SignEvmWithTouchConfirmFn,
    );
  }
  return await signEvmWithTouchConfirmPromise;
}

export async function loadSignTempoWithTouchConfirm(): Promise<SignTempoWithTouchConfirmFn> {
  if (!signTempoWithTouchConfirmPromise) {
    signTempoWithTouchConfirmPromise = import('../../orchestration/tempo/tempoSigningFlow').then(
      (mod) => mod.signTempoWithTouchConfirm as SignTempoWithTouchConfirmFn,
    );
  }
  return await signTempoWithTouchConfirmPromise;
}
