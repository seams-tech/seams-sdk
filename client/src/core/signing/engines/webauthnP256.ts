import { buildWebauthnP256SignatureWasm } from '../chainAdaptors/evm/ethSignerWasm';
import type { KeyRef, SignRequest, SignatureBytes, SigningEngine } from '../orchestration/types';
import type { WorkerOperationContext } from '../workers/operations/executeSignerWorkerOperation';
import { base64Decode, base64UrlDecode } from '@shared/utils/base64';

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export class WebAuthnP256Engine implements SigningEngine {
  readonly algorithm = 'webauthnP256' as const;

  constructor(private readonly workerCtx?: WorkerOperationContext) {}

  private async buildWebauthnSignature(args: {
    challenge32: Uint8Array;
    authenticatorData: Uint8Array;
    clientDataJSON: Uint8Array;
    signatureDer: Uint8Array;
    pubKeyX32: Uint8Array;
    pubKeyY32: Uint8Array;
  }): Promise<SignatureBytes> {
    if (!this.workerCtx) {
      throw new Error('[WebAuthnP256Engine] workerCtx is required for wasm-backed WebAuthn signature packing');
    }
    return await buildWebauthnP256SignatureWasm({
      challenge32: args.challenge32,
      authenticatorData: args.authenticatorData,
      clientDataJSON: args.clientDataJSON,
      signatureDer: args.signatureDer,
      pubKeyX32: args.pubKeyX32,
      pubKeyY32: args.pubKeyY32,
      workerCtx: this.workerCtx,
    });
  }

  async sign(req: SignRequest, keyRef: KeyRef): Promise<SignatureBytes> {
    if (req.kind !== 'webauthn' || req.algorithm !== 'webauthnP256') {
      throw new Error('[WebAuthnP256Engine] unsupported sign request');
    }
    if (req.challenge32.length !== 32) {
      throw new Error('[WebAuthnP256Engine] challenge32 must be 32 bytes');
    }
    if (keyRef.type !== 'webauthnP256') {
      throw new Error('[WebAuthnP256Engine] keyRef must be webauthnP256');
    }

    if (keyRef.pubKeyX.length !== 32 || keyRef.pubKeyY.length !== 32) {
      throw new Error('[WebAuthnP256Engine] pubKeyX/pubKeyY must be 32 bytes each');
    }
    if (keyRef.credentialId.length === 0) {
      throw new Error('[WebAuthnP256Engine] credentialId must be non-empty');
    }

    const fromSerializedCredential = async (credential: any): Promise<SignatureBytes> => {
      const rawIdB64 = String(credential?.rawId || '').trim();
      const rawId = base64Decode(rawIdB64);
      if (!bytesEq(rawId, keyRef.credentialId)) {
        throw new Error('[WebAuthnP256Engine] WebAuthn credential rawId does not match keyRef');
      }

      const response = credential?.response;
      const authenticatorData = base64UrlDecode(String(response?.authenticatorData || ''));
      const clientDataJSON = base64UrlDecode(String(response?.clientDataJSON || ''));
      const signatureDer = base64UrlDecode(String(response?.signature || ''));
      if (authenticatorData.length === 0 || clientDataJSON.length === 0 || signatureDer.length === 0) {
        throw new Error('[WebAuthnP256Engine] missing authenticatorData/clientDataJSON/signature in credential');
      }
      return await this.buildWebauthnSignature({
        challenge32: req.challenge32,
        authenticatorData,
        clientDataJSON,
        signatureDer,
        pubKeyX32: keyRef.pubKeyX,
        pubKeyY32: keyRef.pubKeyY,
      });
    };

    if (req.credential) {
      return await fromSerializedCredential(req.credential);
    }

    if (typeof navigator === 'undefined' || !navigator.credentials || typeof navigator.credentials.get !== 'function') {
      throw new Error('[WebAuthnP256Engine] WebAuthn not available (must run in a browser context)');
    }

    // Ensure browser-facing BufferSource values are ArrayBuffer-backed (not SharedArrayBuffer-backed).
    const challenge = new Uint8Array(req.challenge32);
    const allowCredentialId = new Uint8Array(keyRef.credentialId);

    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [{ type: 'public-key', id: allowCredentialId }],
        rpId: req.rpId ?? keyRef.rpId,
        userVerification: 'preferred',
      },
    })) as PublicKeyCredential | null;

    if (!assertion) throw new Error('[WebAuthnP256Engine] user cancelled WebAuthn assertion');

    const rawId = new Uint8Array(assertion.rawId);
    if (!bytesEq(rawId, keyRef.credentialId)) {
      throw new Error('[WebAuthnP256Engine] WebAuthn assertion returned unexpected credentialId');
    }

    const resp = assertion.response as AuthenticatorAssertionResponse;
    if (!resp || !resp.authenticatorData || !resp.clientDataJSON || !resp.signature) {
      throw new Error('[WebAuthnP256Engine] invalid WebAuthn assertion response');
    }

    const authenticatorData = new Uint8Array(resp.authenticatorData);
    const clientDataJSON = new Uint8Array(resp.clientDataJSON);
    const signatureDer = new Uint8Array(resp.signature);
    return await this.buildWebauthnSignature({
      challenge32: req.challenge32,
      authenticatorData,
      clientDataJSON,
      signatureDer,
      pubKeyX32: keyRef.pubKeyX,
      pubKeyY32: keyRef.pubKeyY,
    });
  }
}
