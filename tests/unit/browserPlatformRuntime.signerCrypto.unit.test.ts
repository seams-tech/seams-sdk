import { expect, test } from '@playwright/test';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  createBrowserPlatformRuntime,
  parseEmailOtpWorkerIssuedSessionHandle,
} from '@/core/platform';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { SignerWorkerOperationError } from '@/core/signingEngine/workerManager/workerTypes';
import {
  WorkerRequestType,
  WorkerResponseType,
  type WasmFinalizeThresholdEcdsaHssRoleLocalClientBootstrapRequest,
  type WasmPrepareThresholdEcdsaHssRoleLocalClientBootstrapRequest,
} from '@/core/types/signer-worker';
import {
  buildFido2HmacSecretSource,
  buildSecureEnclaveWrappedSecretSource,
  buildWebAuthnPrfFirstSecretSource,
  type EcdsaRoleLocalPendingStateBlob,
  type PrepareEcdsaClientBootstrapInput,
  type RequiredPrfAuthenticatorSuccess,
} from '@/core/platform';
import type { EcdsaRelayerHssPublicKey33B64u } from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

function bytesB64u(length: number, fill: number): string {
  return base64UrlEncode(new Uint8Array(length).fill(fill));
}

const publicKeyA = bytesB64u(33, 2);
const publicKeyB = bytesB64u(33, 3);
const publicKeyC = bytesB64u(33, 4);
const shareA = bytesB64u(32, 5);
const shareB = bytesB64u(32, 6);
const shareC = bytesB64u(32, 7);
const pendingStateBlobB64u = bytesB64u(96, 8);
const readyStateBlobB64u = bytesB64u(160, 9);

const requiredPrfSuccess: RequiredPrfAuthenticatorSuccess = {
  ok: true,
  operation: 'get_passkey',
  requirePrfFirst: true,
  credential: {
    id: 'credential',
    rawId: 'credential',
    type: 'public-key',
    authenticatorAttachment: undefined,
    response: {
      clientDataJSON: 'client-data',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: undefined,
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: bytesB64u(32, 1),
          second: undefined,
        },
      },
    },
  },
  credentialIdB64u: 'credential',
  rawIdB64u: 'credential',
  rpId: toRpId('localhost'),
  prf: {
    kind: 'required',
    prfFirstB64u: bytesB64u(32, 1),
  },
};

const prepareInput: PrepareEcdsaClientBootstrapInput = {
  kind: 'prepare_ecdsa_client_bootstrap_v1',
  algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
  context: {
    walletId: toWalletId('wallet.testnet'),
    rpId: toRpId('localhost'),
    chainTarget: thresholdEcdsaChainTargetFromChainFamily({ chain: 'evm', chainId: 5042002 }),
    ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId('ehss-key'),
    signingRootId: toEcdsaHssSigningRootId('root'),
    signingRootVersion: toEcdsaHssSigningRootVersion('v1'),
    keyPurpose: 'evm-signing',
    keyVersion: 'v1',
  },
  participants: {
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
  },
  secretSource: buildWebAuthnPrfFirstSecretSource(requiredPrfSuccess),
};

function pendingBlob(): EcdsaRoleLocalPendingStateBlob {
  return {
    kind: 'ecdsa_role_local_pending_state_blob_v1',
    curve: 'secp256k1',
    encoding: 'base64url',
    producer: 'signer_core',
    stateBlobB64u: pendingStateBlobB64u,
  };
}

function finalizeFailureWorkerCtx(message: string): WorkerOperationContext {
  return {
    async requestWorkerOperation({ request }) {
      expect(request.type).toBe(
        WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap,
      );
      throw new SignerWorkerOperationError({
        code: 'SIGNER_CRYPTO_ERROR',
        coreCode: 'HSS_COMMAND_FAILURE',
        message,
        workerKind: 'hssClient',
      });
    },
  };
}

test.describe('browser SignerCryptoPort ECDSA bootstrap', () => {
  test('builds WebAuthn PRF secret sources only after required PRF credential parsing', () => {
    const source = buildWebAuthnPrfFirstSecretSource(requiredPrfSuccess);
    expect(source).toMatchObject({
      kind: 'webauthn_prf_first',
      prfFirstB64u: requiredPrfSuccess.prf.prfFirstB64u,
      rpId: requiredPrfSuccess.rpId,
      credentialIdB64u: requiredPrfSuccess.credentialIdB64u,
    });
  });

  test('rejects unsupported future secret-source branches at browser dispatch', async () => {
    const runtime = createBrowserPlatformRuntime({
      workerCtx: {
        async requestWorkerOperation() {
          throw new Error('worker must not be called for unsupported secret sources');
        },
      },
    });

    const secureEnclaveResult = await runtime.signerCrypto.prepareEcdsaClientBootstrap({
      ...prepareInput,
      secretSource: buildSecureEnclaveWrappedSecretSource({
        keyId: 'secure-key',
        accessGroup: 'group',
      }),
    });
    expect(secureEnclaveResult).toMatchObject({
      ok: false,
      failure: 'command',
      code: 'unsupported_secret_source',
    });

    const fido2Result = await runtime.signerCrypto.prepareEcdsaClientBootstrap({
      ...prepareInput,
      secretSource: buildFido2HmacSecretSource({
        credentialIdB64u: 'credential',
        rpId: toRpId('localhost'),
      }),
    });
    expect(fido2Result).toMatchObject({
      ok: false,
      failure: 'command',
      code: 'unsupported_secret_source',
    });
  });

  test('maps worker timeout failures to invocation failures', async () => {
    const workerCtx: WorkerOperationContext = {
      async requestWorkerOperation() {
        throw new SignerWorkerOperationError({
          code: 'TIMEOUT',
          message: 'Worker operation timed out after 1000ms',
          workerKind: 'hssClient',
        });
      },
    };
    const runtime = createBrowserPlatformRuntime({ workerCtx });
    const result = await runtime.signerCrypto.prepareEcdsaClientBootstrap(prepareInput);
    expect(result).toMatchObject({ ok: false, failure: 'invocation', code: 'timeout' });
  });

  test('maps postMessage and protocol failures to invocation failures', async () => {
    const postMessageCtx: WorkerOperationContext = {
      async requestWorkerOperation() {
        throw new SignerWorkerOperationError({
          code: 'WORKER_POSTMESSAGE_ERROR',
          message: '[hssClient] failed to postMessage',
          workerKind: 'hssClient',
        });
      },
    };
    const postMessageResult = await createBrowserPlatformRuntime({
      workerCtx: postMessageCtx,
    }).signerCrypto.prepareEcdsaClientBootstrap(prepareInput);
    expect(postMessageResult).toMatchObject({
      ok: false,
      failure: 'invocation',
      code: 'worker_transport_failure',
    });

    const protocolCtx: WorkerOperationContext = {
      async requestWorkerOperation() {
        throw new SignerWorkerOperationError({
          code: 'WORKER_PROTOCOL_ERROR',
          message: '[hssClient] malformed worker response',
          workerKind: 'hssClient',
        });
      },
    };
    const protocolResult = await createBrowserPlatformRuntime({
      workerCtx: protocolCtx,
    }).signerCrypto.prepareEcdsaClientBootstrap(prepareInput);
    expect(protocolResult).toMatchObject({
      ok: false,
      failure: 'invocation',
      code: 'worker_transport_failure',
    });

    const runtimeCtx: WorkerOperationContext = {
      async requestWorkerOperation() {
        throw new SignerWorkerOperationError({
          code: 'WORKER_RUNTIME_ERROR',
          message: '[hssClient] worker runtime error: unknown error',
          workerKind: 'hssClient',
        });
      },
    };
    const runtimeResult = await createBrowserPlatformRuntime({
      workerCtx: runtimeCtx,
    }).signerCrypto.prepareEcdsaClientBootstrap(prepareInput);
    expect(runtimeResult).toMatchObject({
      ok: false,
      failure: 'invocation',
      code: 'worker_transport_failure',
    });
  });

  test('maps WASM/native initialization failures to invocation native-binding failures', async () => {
    const workerCtx: WorkerOperationContext = {
      async requestWorkerOperation() {
        throw new SignerWorkerOperationError({
          code: 'WORKER_RUNTIME_ERROR',
          message: 'HSS client WASM initialization failed: failed to instantiate module_or_path',
          workerKind: 'hssClient',
        });
      },
    };
    const result = await createBrowserPlatformRuntime({
      workerCtx,
    }).signerCrypto.prepareEcdsaClientBootstrap(prepareInput);
    expect(result).toMatchObject({
      ok: false,
      failure: 'invocation',
      code: 'native_binding_failure',
    });
  });

  test('maps HSS command failures to signer-crypto command failures', async () => {
    const workerCtx: WorkerOperationContext = {
      async requestWorkerOperation() {
        throw new SignerWorkerOperationError({
          code: 'SIGNER_CRYPTO_ERROR',
          coreCode: 'HSS_COMMAND_FAILURE',
          message: 'ECDSA bootstrap context validation failed',
          workerKind: 'hssClient',
        });
      },
    };
    const result = await createBrowserPlatformRuntime({
      workerCtx,
    }).signerCrypto.prepareEcdsaClientBootstrap(prepareInput);
    expect(result).toMatchObject({
      ok: false,
      failure: 'command',
      code: 'crypto_failure',
    });
  });

  test('matches the current ECDSA prepare/finalize parity fixture', async () => {
    const capturedPreparePayloads: WasmPrepareThresholdEcdsaHssRoleLocalClientBootstrapRequest[] =
      [];
    const capturedFinalizePayloads: WasmFinalizeThresholdEcdsaHssRoleLocalClientBootstrapRequest[] =
      [];
    const workerCtx: WorkerOperationContext = {
      async requestWorkerOperation({ kind, request }) {
        expect(kind).toBe('hssClient');
        if (request.type === WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap) {
          const payload =
            request.payload as WasmPrepareThresholdEcdsaHssRoleLocalClientBootstrapRequest;
          capturedPreparePayloads.push(payload);
          expect(payload).toMatchObject({
            walletId: prepareInput.context.walletId,
            rpId: prepareInput.context.rpId,
            ecdsaThresholdKeyId: prepareInput.context.ecdsaThresholdKeyId,
            signingRootId: prepareInput.context.signingRootId,
            signingRootVersion: prepareInput.context.signingRootVersion,
            keyPurpose: 'evm-signing',
            keyVersion: 'v1',
          });
          expect(payload.clientRootShare32B64u).toBeTruthy();
          expect(base64UrlDecode(String(payload.clientRootShare32B64u))).toHaveLength(32);
          return {
            type: WorkerResponseType.PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
            payload: {
              walletId: prepareInput.context.walletId,
              rpId: prepareInput.context.rpId,
              ecdsaThresholdKeyId: prepareInput.context.ecdsaThresholdKeyId,
              signingRootId: prepareInput.context.signingRootId,
              signingRootVersion: prepareInput.context.signingRootVersion,
              keyPurpose: 'evm-signing',
              keyVersion: 'v1',
              pendingStateBlobB64u,
              contextBinding32B64u: shareA,
              hssClientSharePublicKey33B64u: publicKeyA,
              clientVerifyingShareB64u: publicKeyA,
              clientShareRetryCounter: 7,
              participantId: 1,
            },
          } as any;
        }
        expect(request.type).toBe(
          WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap,
        );
        const payload =
          request.payload as WasmFinalizeThresholdEcdsaHssRoleLocalClientBootstrapRequest;
        capturedFinalizePayloads.push(payload);
        expect(payload).toMatchObject({
          pendingStateBlobB64u,
          relayerKeyId: 'relayer',
          relayerPublicKey33B64u: publicKeyB,
          groupPublicKey33B64u: publicKeyC,
          ethereumAddress: '0x0000000000000000000000000000000000000001',
          relayerShareRetryCounter: 0,
        });
        return {
          type: WorkerResponseType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
          payload: {
            stateBlobB64u: readyStateBlobB64u,
            contextBinding32B64u: shareA,
            hssClientSharePublicKey33B64u: publicKeyA,
            clientVerifyingShareB64u: publicKeyA,
            relayerPublicKey33B64u: publicKeyB,
            groupPublicKey33B64u: publicKeyC,
            ethereumAddress: '0x0000000000000000000000000000000000000001',
            clientShareRetryCounter: 7,
            relayerShareRetryCounter: 0,
          },
        } as any;
      },
    };
    const runtime = createBrowserPlatformRuntime({ workerCtx });
    const prepared = await runtime.signerCrypto.prepareEcdsaClientBootstrap(prepareInput);
    expect(prepared).toMatchObject({
      ok: true,
      value: {
        clientBootstrap: {
          contextBinding32B64u: shareA,
          hssClientSharePublicKey33B64u: publicKeyA,
          clientShareRetryCounter: 7,
          participantId: 1,
        },
        publicFacts: {
          hssClientSharePublicKey33B64u: publicKeyA,
          clientVerifyingShareB64u: publicKeyA,
        },
      },
    });
    expect(capturedPreparePayloads).toHaveLength(1);
    if (!prepared.ok) throw new Error(prepared.message);

    const finalized = await runtime.signerCrypto.finalizeEcdsaClientBootstrap({
      kind: 'finalize_ecdsa_client_bootstrap_v1',
      pendingStateBlob: prepared.value.pendingStateBlob,
      relayerPublicIdentity: {
        relayerKeyId: 'relayer',
        relayerPublicKey33B64u: publicKeyB as EcdsaRelayerHssPublicKey33B64u,
        groupPublicKey33B64u: publicKeyC,
        ethereumAddress: '0x0000000000000000000000000000000000000001',
      },
    });
    expect(finalized).toMatchObject({
      ok: true,
      value: {
        publicFacts: {
          hssClientSharePublicKey33B64u: publicKeyA,
          clientVerifyingShareB64u: publicKeyA,
          relayerPublicKey33B64u: publicKeyB,
          groupPublicKey33B64u: publicKeyC,
          ethereumAddress: '0x0000000000000000000000000000000000000001',
        },
      },
    });
    if (!finalized.ok) throw new Error(finalized.message);
    expect(capturedFinalizePayloads).toHaveLength(1);
    expect(finalized.value.stateBlob).toMatchObject({
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: readyStateBlobB64u,
    });
  });

  test('rejects malformed pending blobs during finalize', async () => {
    const runtime = createBrowserPlatformRuntime({
      workerCtx: finalizeFailureWorkerCtx('pending state blob has invalid magic'),
    });
    const result = await runtime.signerCrypto.finalizeEcdsaClientBootstrap({
      kind: 'finalize_ecdsa_client_bootstrap_v1',
      pendingStateBlob: {
        ...pendingBlob(),
        stateBlobB64u: bytesB64u(12, 10),
      },
      relayerPublicIdentity: {
        relayerKeyId: 'relayer',
        relayerPublicKey33B64u: publicKeyB as EcdsaRelayerHssPublicKey33B64u,
        groupPublicKey33B64u: publicKeyC,
        ethereumAddress: '0x0000000000000000000000000000000000000001',
      },
    });
    expect(result).toMatchObject({
      ok: false,
      failure: 'command',
      code: 'invalid_pending_state',
    });
  });

  test('maps signer-core pending context failures during finalize', async () => {
    const runtime = createBrowserPlatformRuntime({
      workerCtx: finalizeFailureWorkerCtx('pending context binding does not match encoded context'),
    });
    const result = await runtime.signerCrypto.finalizeEcdsaClientBootstrap({
      kind: 'finalize_ecdsa_client_bootstrap_v1',
      pendingStateBlob: pendingBlob(),
      relayerPublicIdentity: {
        relayerKeyId: 'relayer',
        relayerPublicKey33B64u: publicKeyB as EcdsaRelayerHssPublicKey33B64u,
        groupPublicKey33B64u: publicKeyC,
        ethereumAddress: '0x0000000000000000000000000000000000000001',
      },
    });
    expect(result).toMatchObject({
      ok: false,
      failure: 'command',
      code: 'invalid_pending_state',
    });
  });

  test('maps signer-core pending parse failures during finalize', async () => {
    const runtime = createBrowserPlatformRuntime({
      workerCtx: finalizeFailureWorkerCtx('pending state blob is truncated'),
    });
    const result = await runtime.signerCrypto.finalizeEcdsaClientBootstrap({
      kind: 'finalize_ecdsa_client_bootstrap_v1',
      pendingStateBlob: pendingBlob(),
      relayerPublicIdentity: {
        relayerKeyId: 'relayer',
        relayerPublicKey33B64u: publicKeyB as EcdsaRelayerHssPublicKey33B64u,
        groupPublicKey33B64u: publicKeyC,
        ethereumAddress: '0x0000000000000000000000000000000000000001',
      },
    });
    expect(result).toMatchObject({
      ok: false,
      failure: 'command',
      code: 'invalid_pending_state',
    });
  });

  test('rejects malformed relayer identity during finalize', async () => {
    const runtime = createBrowserPlatformRuntime({
      workerCtx: {
        async requestWorkerOperation() {
          throw new Error('worker must not be called for malformed relayer identity');
        },
      },
    });
    const result = await runtime.signerCrypto.finalizeEcdsaClientBootstrap({
      kind: 'finalize_ecdsa_client_bootstrap_v1',
      pendingStateBlob: pendingBlob(),
      relayerPublicIdentity: {
        relayerKeyId: '',
        relayerPublicKey33B64u: publicKeyB as EcdsaRelayerHssPublicKey33B64u,
        groupPublicKey33B64u: publicKeyC,
        ethereumAddress: '0x0000000000000000000000000000000000000001',
      },
    });
    expect(result).toMatchObject({
      ok: false,
      failure: 'command',
      code: 'invalid_relayer_public_identity',
    });
  });

  test('rejects relayer identity that reuses the client-share public key', async () => {
    const runtime = createBrowserPlatformRuntime({
      workerCtx: finalizeFailureWorkerCtx(
        'relayer group public key does not match client and relayer HSS keys',
      ),
    });
    const result = await runtime.signerCrypto.finalizeEcdsaClientBootstrap({
      kind: 'finalize_ecdsa_client_bootstrap_v1',
      pendingStateBlob: pendingBlob(),
      relayerPublicIdentity: {
        relayerKeyId: 'relayer',
        relayerPublicKey33B64u: publicKeyA as EcdsaRelayerHssPublicKey33B64u,
        groupPublicKey33B64u: publicKeyC,
        ethereumAddress: '0x0000000000000000000000000000000000000001',
      },
    });
    expect(result).toMatchObject({
      ok: false,
      failure: 'command',
      code: 'public_identity_mismatch',
    });
  });

  test('parses worker-issued Email OTP handles with strict bindings', () => {
    const parsed = parseEmailOtpWorkerIssuedSessionHandle({
      kind: 'email_otp_worker_session_handle_v1',
      sessionId: 'otp-session',
      walletId: 'wallet.testnet',
      rpId: 'localhost',
      authSubjectId: 'google:alice',
      action: 'threshold_ecdsa_bootstrap',
      operation: 'sign',
      chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
    });
    expect(parsed.action).toBe('threshold_ecdsa_bootstrap');
    if (parsed.action === 'threshold_ecdsa_bootstrap') {
      expect(parsed.chainTarget.kind).toBe('tempo');
      expect(parsed.authSubjectId).toBe('google:alice');
    }
  });

  test('rejects worker-issued Email OTP handles missing strict bindings', () => {
    expect(() =>
      parseEmailOtpWorkerIssuedSessionHandle({
        kind: 'email_otp_worker_session_handle_v1',
        sessionId: 'otp-session',
        walletId: 'wallet.testnet',
        rpId: 'localhost',
        action: 'threshold_ecdsa_bootstrap',
        operation: 'sign',
        chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
      }),
    ).toThrow(/authSubjectId/i);
  });

  test('rejects ECDSA worker-issued Email OTP handles missing chainTarget', () => {
    expect(() =>
      parseEmailOtpWorkerIssuedSessionHandle({
        kind: 'email_otp_worker_session_handle_v1',
        sessionId: 'otp-session',
        walletId: 'wallet.testnet',
        rpId: 'localhost',
        authSubjectId: 'google:alice',
        action: 'threshold_ecdsa_bootstrap',
        operation: 'sign',
      }),
    ).toThrow(/chainTarget/i);
  });

  test('parses Ed25519 worker-issued Email OTP handles without chainTarget', () => {
    const parsed = parseEmailOtpWorkerIssuedSessionHandle({
      kind: 'email_otp_worker_session_handle_v1',
      sessionId: 'otp-session',
      walletId: 'wallet.testnet',
      rpId: 'localhost',
      authSubjectId: 'google:alice',
      action: 'threshold_ed25519_session',
      operation: 'wallet_unlock',
    });
    expect(parsed.action).toBe('threshold_ed25519_session');
    if (parsed.action === 'threshold_ed25519_session') {
      expect(parsed.authSubjectId).toBe('google:alice');
      expect('chainTarget' in parsed).toBe(false);
    }
  });

  test('rejects Ed25519 worker-issued Email OTP handles with chainTarget', () => {
    expect(() =>
      parseEmailOtpWorkerIssuedSessionHandle({
        kind: 'email_otp_worker_session_handle_v1',
        sessionId: 'otp-session',
        walletId: 'wallet.testnet',
        rpId: 'localhost',
        authSubjectId: 'google:alice',
        action: 'threshold_ed25519_session',
        operation: 'wallet_unlock',
        chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
      }),
    ).toThrow(/cannot include chainTarget/i);
  });
});
