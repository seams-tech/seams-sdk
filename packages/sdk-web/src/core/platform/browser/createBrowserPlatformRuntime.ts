import { IndexedDBManager } from '../../indexedDB';
import { base64UrlDecode } from '@shared/utils/base64';
import {
  PASSKEY_PRF_FIRST_SALT_V1,
  PASSKEY_PRF_SECOND_SALT_V1,
} from '@shared/utils/signingSessionSeal';
import { errorMessage } from '@shared/utils/errors';
import {
  finalizeEcdsaClientBootstrapCommandWasm,
  prepareEcdsaClientBootstrapCommandWasm,
  buildEcdsaRoleLocalExportArtifactCommandWasm,
  closeRouterAbEcdsaRegistrationCeremonyWasm,
  createRouterAbEcdsaRegistrationCeremonyWasm,
  finalizeRouterAbEcdsaRegistrationActivationWasm,
  verifyRouterAbEcdsaRegistrationClientProofsWasm,
  storeEcdsaRoleLocalSigningMaterialWasm,
} from '../../signingEngine/threshold/crypto/ecdsaDerivationClientWasm';
import type { WorkerOperationContext } from '../../signingEngine/workerManager/executeWorkerOperation';
import {
  getSignerWorkerOperationCoreCode,
  getSignerWorkerOperationErrorCode,
} from '../../signingEngine/workerManager/workerTypes';
import {
  serializeAuthenticationCredentialWithPRF,
  serializeRegistrationCredentialWithPRF,
} from '../../signingEngine/webauthnAuth/credentials/helpers';
import { getPrfFirstB64uFromCredential } from '../../signingEngine/webauthnAuth/credentials/credentialExtensions';
import {
  clearThresholdEcdsaSessionRecordsForWalletTargetKeyHandle,
  listThresholdEcdsaSessionRecordsForWalletTarget,
  type ThresholdEcdsaSessionStoreDeps,
} from '../../signingEngine/session/persistence/records';
import {
  ecdsaRoleLocalReadyRecordMatchesInput,
  ecdsaRoleLocalReadyRecordStorageKey,
  parseEcdsaRoleLocalReadyRecord,
  parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord,
  serializeEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalMaterialHandle,
} from '../../signingEngine/session/keyMaterialBrands';
import {
  parseGeneratedFinalizeEcdsaClientBootstrapOutput,
  parseGeneratedBuildEcdsaRoleLocalExportArtifactOutput,
  parseGeneratedPrepareEcdsaClientBootstrapOutput,
  toGeneratedBuildEcdsaRoleLocalExportArtifactCommand,
  toGeneratedFinalizeEcdsaClientBootstrapCommand,
  toGeneratedPrepareEcdsaClientBootstrapCommand,
} from '../signerCoreCommandAdapters';
import type {
  AuthenticatorOperation,
  AuthenticatorResult,
  AuthenticatorPort,
  BuildEcdsaRoleLocalExportArtifactErrorCode,
  BuildEcdsaRoleLocalExportArtifactOutput,
  ClockPort,
  CleanupMalformedEcdsaRoleLocalRecordResult,
  DurableRecordStore,
  FinalizeEcdsaClientBootstrapErrorCode,
  FinalizeEcdsaClientBootstrapOutput,
  HttpTransport,
  LoadEcdsaRoleLocalReadyRecordResult,
  PlatformResult,
  RuntimePorts,
  PrepareEcdsaClientBootstrapErrorCode,
  PrepareEcdsaClientBootstrapOutput,
  PersistEcdsaRoleLocalReadyRecordResult,
  RandomSource,
  SecureSecretStore,
  SignerCryptoPort,
  SignerCryptoInvocationErrorCode,
  SignerCryptoResult,
  StoreEcdsaRoleLocalSigningMaterialErrorCode,
  StoreEcdsaRoleLocalSigningMaterialOutput,
} from '../types';
import type { EcdsaDerivationRelayerPublicKey33B64u } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';

type BrowserRuntimePortsDeps = {
  indexedDB?: typeof IndexedDBManager;
  fetch?: typeof fetch;
  crypto?: Crypto;
  credentials?: CredentialsContainer;
  workerCtx?: WorkerOperationContext;
  ecdsaSessionStore?: ThresholdEcdsaSessionStoreDeps;
  nowMs?: () => number;
};

export type BrowserDurableRecordStore = DurableRecordStore & {
  indexedDB: typeof IndexedDBManager;
};

export type BrowserRuntimePorts = RuntimePorts & {
  kind: 'browser';
  storage: BrowserDurableRecordStore;
};

function unavailable<T>(message: string): PlatformResult<T, 'unavailable'> {
  return { ok: false, code: 'unavailable', message };
}

type BrowserRelayerPublicIdentity = {
  relayerKeyId: string;
  relayerPublicKey33B64u: EcdsaDerivationRelayerPublicKey33B64u;
  groupPublicKey33B64u: string;
  ethereumAddress: `0x${string}`;
  relayerShareRetryCounter: number;
};

type SignerCryptoInvocationFailure<CommandCode extends string> = Extract<
  SignerCryptoResult<never, CommandCode>,
  { ok: false; failure: 'invocation' }
>;

type SignerCryptoCommandFailure<CommandCode extends string> = Extract<
  SignerCryptoResult<never, CommandCode>,
  { ok: false; failure: 'command' }
>;

function signerCryptoInvocationFailure<CommandCode extends string>(
  code: SignerCryptoInvocationErrorCode,
  message: string,
): SignerCryptoInvocationFailure<CommandCode> {
  return { ok: false, failure: 'invocation', code, message };
}

function signerCryptoCommandFailure<CommandCode extends string>(
  code: CommandCode,
  message: string,
): SignerCryptoCommandFailure<CommandCode> {
  return { ok: false, failure: 'command', code, message };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function requiredStringFromRecord(record: Record<string, unknown>, field: string): string {
  const value = String(record[field] || '').trim();
  if (!value) {
    throw new Error(`ECDSA client bootstrap state is missing ${field}`);
  }
  return value;
}

function requiredNonNegativeIntegerFromRecord(
  record: Record<string, unknown>,
  field: string,
): number {
  const value = record[field];
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(`${field} must be a non-negative safe integer`);
  }
  return Number(value);
}

function requireBase64UrlBytes(value: string, field: string, byteLength: number): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`${field} is required`);
  }
  const decoded = base64UrlDecode(normalized);
  if (decoded.length !== byteLength) {
    throw new Error(`${field} must decode to ${byteLength} bytes`);
  }
  return normalized;
}

function decodeBase64UrlArrayBuffer(value: string): ArrayBuffer {
  const decoded = base64UrlDecode(value);
  const out = new ArrayBuffer(decoded.byteLength);
  new Uint8Array(out).set(decoded);
  return out;
}

function parsePublicKey33B64u(value: string, field: string): string {
  return requireBase64UrlBytes(value, field, 33);
}

function parseRelayerEcdsaDerivationPublicKey33B64u(
  value: string,
): EcdsaDerivationRelayerPublicKey33B64u {
  return parsePublicKey33B64u(
    value,
    'ECDSA relayer DERIVATION public key',
  ) as EcdsaDerivationRelayerPublicKey33B64u;
}

function parseEthereumAddress(value: unknown): `0x${string}` {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(normalized)) {
    throw new Error('ECDSA relayer public identity has invalid ethereumAddress');
  }
  return normalized as `0x${string}`;
}

function isNativeBindingFailureMessage(message: string): boolean {
  return /wasm (initialization|initialize|instantiation)|webassembly|module_or_path|failed to (load|compile|instantiate) wasm|derivation client wasm initialization failed/i.test(
    message,
  );
}

function mapSignerCryptoInvocationError<CommandCode extends string>(
  error: unknown,
): SignerCryptoInvocationFailure<CommandCode> | null {
  const code = getSignerWorkerOperationErrorCode(error);
  const coreCode = getSignerWorkerOperationCoreCode(error);
  const message = errorMessage(error);
  if (coreCode === 'ECDSA_DERIVATION_WASM_INIT_FAILURE') {
    return signerCryptoInvocationFailure('native_binding_failure', message);
  }
  if (isNativeBindingFailureMessage(message)) {
    return signerCryptoInvocationFailure('native_binding_failure', message);
  }
  switch (code) {
    case 'TIMEOUT':
      return signerCryptoInvocationFailure('timeout', message);
    case 'WORKER_POSTMESSAGE_ERROR':
    case 'WORKER_PROTOCOL_ERROR':
    case 'WORKER_RUNTIME_ERROR':
      return signerCryptoInvocationFailure('worker_transport_failure', message);
    default:
      break;
  }
  if (/timed out/i.test(message)) {
    return signerCryptoInvocationFailure('timeout', message);
  }
  if (
    /postMessage|worker runtime|worker response|worker protocol|Malformed worker|Unknown worker/i.test(
      message,
    )
  ) {
    return signerCryptoInvocationFailure('worker_transport_failure', message);
  }
  return null;
}

function mapFinalizeEcdsaCommandError(
  error: unknown,
): SignerCryptoCommandFailure<FinalizeEcdsaClientBootstrapErrorCode> {
  const message = errorMessage(error);
  if (
    /relayer|public identity|group public key|ethereum address|threshold public key/i.test(message)
  ) {
    return signerCryptoCommandFailure('public_identity_mismatch', message);
  }
  return signerCryptoCommandFailure('invalid_pending_state', message);
}

function mapBuildEcdsaRoleLocalExportCommandError(
  error: unknown,
): SignerCryptoCommandFailure<BuildEcdsaRoleLocalExportArtifactErrorCode> {
  const message = errorMessage(error);
  if (
    /public facts|public key|public identity|ethereum address|context binding|context/i.test(
      message,
    )
  ) {
    return signerCryptoCommandFailure('invalid_public_identity', message);
  }
  if (/ready state|state blob|stateBlob|blob magic|trailing bytes|decode/i.test(message)) {
    return signerCryptoCommandFailure('invalid_ready_state', message);
  }
  return signerCryptoCommandFailure('crypto_failure', message);
}

function parseRelayerPublicIdentity(input: unknown): BrowserRelayerPublicIdentity {
  if (!isRecord(input)) {
    throw new Error('ECDSA relayer public identity must be an object');
  }
  return {
    relayerKeyId: requiredStringFromRecord(input, 'relayerKeyId'),
    relayerPublicKey33B64u: parseRelayerEcdsaDerivationPublicKey33B64u(
      requiredStringFromRecord(input, 'relayerPublicKey33B64u'),
    ),
    groupPublicKey33B64u: parsePublicKey33B64u(
      requiredStringFromRecord(input, 'groupPublicKey33B64u'),
      'groupPublicKey33B64u',
    ),
    ethereumAddress: parseEthereumAddress(input.ethereumAddress),
    relayerShareRetryCounter: requiredNonNegativeIntegerFromRecord(
      input,
      'relayerShareRetryCounter',
    ),
  };
}

function createBrowserDurableRecordStore(
  indexedDB: typeof IndexedDBManager,
  ecdsaSessionStore: ThresholdEcdsaSessionStoreDeps | undefined,
): BrowserDurableRecordStore {
  return {
    kind: 'durable_record_store',
    indexedDB,
    async loadEcdsaRoleLocalReadyRecord(input): Promise<LoadEcdsaRoleLocalReadyRecordResult> {
      const storageKey = ecdsaRoleLocalReadyRecordStorageKey(input);
      try {
        const stored = await indexedDB.getAppState<unknown>(storageKey);
        if (stored !== undefined && stored !== null) {
          const parsed = parseEcdsaRoleLocalReadyRecord(stored);
          if (!ecdsaRoleLocalReadyRecordMatchesInput({ record: parsed, input })) {
            return {
              ok: true,
              value: {
                kind: 'malformed',
                cleanup: {
                  ...input,
                  reason: 'Stored ECDSA role-local record identity does not match lookup input',
                },
                message: 'Stored ECDSA role-local record identity does not match lookup input',
              },
            };
          }
          return { ok: true, value: { kind: 'found', record: parsed } };
        }
        if (!ecdsaSessionStore) return { ok: true, value: { kind: 'not_found' } };
        const candidates = listThresholdEcdsaSessionRecordsForWalletTarget(ecdsaSessionStore, {
          walletId: input.walletId,
          chainTarget: input.chainTarget,
        });
        for (const candidate of candidates) {
          let parsed = null;
          try {
            parsed = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(candidate);
          } catch {
            continue;
          }
          if (ecdsaRoleLocalReadyRecordMatchesInput({ record: parsed, input })) {
            return { ok: true, value: { kind: 'found', record: parsed } };
          }
        }
        return { ok: true, value: { kind: 'not_found' } };
      } catch (error) {
        const message = errorMessage(error);
        return {
          ok: true,
          value: {
            kind: 'malformed',
            cleanup: {
              ...input,
              reason: message,
            },
            message,
          },
        };
      }
    },
    async persistEcdsaRoleLocalReadyRecord(input): Promise<PersistEcdsaRoleLocalReadyRecordResult> {
      try {
        const record = parseEcdsaRoleLocalReadyRecord(input.record);
        if (!ecdsaRoleLocalReadyRecordMatchesInput({ record, input: input.storageKeyFacts })) {
          return {
            ok: false,
            code: 'invalid_record',
            message: 'ECDSA role-local ready record identity does not match storageKeyFacts',
          };
        }
        await indexedDB.setAppState(
          ecdsaRoleLocalReadyRecordStorageKey(input.storageKeyFacts),
          serializeEcdsaRoleLocalReadyRecord(record),
        );
        return { ok: true, value: { kind: 'persisted' } };
      } catch (error) {
        return {
          ok: false,
          code: 'invalid_record',
          message: errorMessage(error),
        };
      }
    },
    async cleanupMalformedEcdsaRoleLocalRecord(
      input,
    ): Promise<CleanupMalformedEcdsaRoleLocalRecordResult> {
      try {
        await indexedDB.setAppState(ecdsaRoleLocalReadyRecordStorageKey(input), null);
        if (ecdsaSessionStore) {
          clearThresholdEcdsaSessionRecordsForWalletTargetKeyHandle(ecdsaSessionStore, {
            walletId: input.walletId,
            chainTarget: input.chainTarget,
            keyHandle: input.keyHandle,
          });
        }
        return { ok: true, value: { kind: 'deleted' } };
      } catch (error) {
        return {
          ok: false,
          code: 'unavailable',
          message: errorMessage(error),
        };
      }
    },
  };
}

function createBrowserSecureSecretStore(): SecureSecretStore {
  return {
    kind: 'secure_secret_store',
    async seal() {
      return unavailable('Browser secure secret store is not wired yet');
    },
    async unseal() {
      return unavailable('Browser secure secret store is not wired yet');
    },
    async delete() {
      return unavailable('Browser secure secret store is not wired yet');
    },
  };
}

function authenticatorFailure(error: unknown): AuthenticatorResult {
  if (error instanceof DOMException) {
    if (error.name === 'NotAllowedError') {
      return {
        ok: false,
        code: 'not_allowed',
        message: error.message || 'Passkey operation was not allowed',
      };
    }
    return { ok: false, code: 'platform_error', message: error.message || error.name };
  }
  return {
    ok: false,
    code: 'platform_error',
    message: error instanceof Error ? error.message : String(error),
  };
}

function prfExtensionInput(): AuthenticationExtensionsClientInputs {
  return {
    prf: {
      eval: {
        first: PASSKEY_PRF_FIRST_SALT_V1,
        second: PASSKEY_PRF_SECOND_SALT_V1,
      },
    },
  } as AuthenticationExtensionsClientInputs;
}

function requiredPrfFailure(): AuthenticatorResult {
  return {
    ok: false,
    code: 'prf_unavailable',
    message: 'Required passkey PRF.first output is unavailable',
  };
}

function requiredPrfSerializationFailure(error: unknown): AuthenticatorResult | null {
  if (/Missing PRF/i.test(errorMessage(error))) return requiredPrfFailure();
  return null;
}

function isPublicKeyCredential(value: Credential | null): value is PublicKeyCredential {
  return Boolean(
    value &&
    typeof value === 'object' &&
    'rawId' in value &&
    'response' in value &&
    typeof (value as { getClientExtensionResults?: unknown }).getClientExtensionResults ===
      'function',
  );
}

function createBrowserAuthenticatorPort(
  credentials: CredentialsContainer | undefined,
): AuthenticatorPort {
  return {
    kind: 'authenticator',
    async run(operation: AuthenticatorOperation): Promise<AuthenticatorResult> {
      if (!credentials) {
        return { ok: false, code: 'unavailable', message: 'navigator.credentials is unavailable' };
      }
      try {
        switch (operation.kind) {
          case 'create_passkey': {
            const credential = await credentials.create({
              publicKey: {
                rp: { id: operation.rpId, name: operation.rpId },
                user: {
                  id: decodeBase64UrlArrayBuffer(operation.userHandleB64u),
                  name: operation.userHandleB64u,
                  displayName: operation.userHandleB64u,
                },
                challenge: decodeBase64UrlArrayBuffer(operation.challengeB64u),
                pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
                authenticatorSelection: {
                  residentKey: 'preferred',
                  userVerification: operation.authenticatorOptions?.userVerification || 'preferred',
                },
                timeout: operation.authenticatorOptions?.timeoutMs,
                extensions: prfExtensionInput(),
              },
            });
            if (!isPublicKeyCredential(credential)) {
              return {
                ok: false,
                code: 'invalid_credential',
                message: 'Passkey creation returned an invalid credential',
              };
            }
            let serialized: ReturnType<typeof serializeRegistrationCredentialWithPRF>;
            try {
              serialized = serializeRegistrationCredentialWithPRF({ credential });
            } catch (error) {
              if (operation.requirePrfFirst) {
                const prfFailure = requiredPrfSerializationFailure(error);
                if (prfFailure) return prfFailure;
              }
              throw error;
            }
            const prfFirstB64u = getPrfFirstB64uFromCredential(serialized);
            if (operation.requirePrfFirst && !prfFirstB64u) return requiredPrfFailure();
            if (operation.requirePrfFirst) {
              const requiredPrfFirstB64u = prfFirstB64u || '';
              return {
                ok: true,
                operation: 'create_passkey',
                requirePrfFirst: true,
                credential: serialized,
                credentialIdB64u: serialized.rawId,
                rawIdB64u: serialized.rawId,
                rpId: operation.rpId,
                prf: { kind: 'required', prfFirstB64u: requiredPrfFirstB64u },
              };
            }
            return {
              ok: true,
              operation: 'create_passkey',
              requirePrfFirst: false,
              credential: serialized,
              credentialIdB64u: serialized.rawId,
              rawIdB64u: serialized.rawId,
              rpId: operation.rpId,
              prf: prfFirstB64u
                ? { kind: 'available_without_requirement', prfFirstB64u }
                : { kind: 'not_requested_or_unavailable' },
            };
          }
          case 'get_passkey': {
            const credential = await credentials.get({
              publicKey: {
                rpId: operation.rpId,
                challenge: decodeBase64UrlArrayBuffer(operation.challengeB64u),
                allowCredentials: [
                  {
                    type: 'public-key',
                    id: decodeBase64UrlArrayBuffer(operation.credentialIdB64u),
                  },
                ],
                userVerification: 'preferred',
                extensions: prfExtensionInput(),
              },
            });
            if (!isPublicKeyCredential(credential)) {
              return {
                ok: false,
                code: 'invalid_credential',
                message: 'Passkey assertion returned an invalid credential',
              };
            }
            let serialized: ReturnType<typeof serializeAuthenticationCredentialWithPRF>;
            try {
              serialized = serializeAuthenticationCredentialWithPRF({ credential });
            } catch (error) {
              if (operation.requirePrfFirst) {
                const prfFailure = requiredPrfSerializationFailure(error);
                if (prfFailure) return prfFailure;
              }
              throw error;
            }
            const prfFirstB64u = getPrfFirstB64uFromCredential(serialized);
            if (operation.requirePrfFirst && !prfFirstB64u) return requiredPrfFailure();
            if (operation.requirePrfFirst) {
              const requiredPrfFirstB64u = prfFirstB64u || '';
              return {
                ok: true,
                operation: 'get_passkey',
                requirePrfFirst: true,
                credential: serialized,
                credentialIdB64u: serialized.rawId,
                rawIdB64u: serialized.rawId,
                rpId: operation.rpId,
                prf: { kind: 'required', prfFirstB64u: requiredPrfFirstB64u },
              };
            }
            return {
              ok: true,
              operation: 'get_passkey',
              requirePrfFirst: false,
              credential: serialized,
              credentialIdB64u: serialized.rawId,
              rawIdB64u: serialized.rawId,
              rpId: operation.rpId,
              prf: prfFirstB64u
                ? { kind: 'available_without_requirement', prfFirstB64u }
                : { kind: 'not_requested_or_unavailable' },
            };
          }
        }
      } catch (error) {
        return authenticatorFailure(error);
      }
    },
  };
}

function createBrowserSignerCryptoPort(
  workerCtx: WorkerOperationContext | undefined,
): SignerCryptoPort {
  return {
    kind: 'signer_crypto',
    async createRouterAbEcdsaRegistrationCeremony(input) {
      if (!workerCtx) {
        throw new Error('ECDSA derivation client worker context is unavailable');
      }
      return createRouterAbEcdsaRegistrationCeremonyWasm({
        command: input,
        workerCtx,
      });
    },
    async verifyRouterAbEcdsaRegistrationClientProofs(input) {
      if (!workerCtx) {
        throw new Error('ECDSA derivation client worker context is unavailable');
      }
      return verifyRouterAbEcdsaRegistrationClientProofsWasm({
        command: input,
        workerCtx,
      });
    },
    async finalizeRouterAbEcdsaRegistrationActivation(input) {
      if (!workerCtx) {
        throw new Error('ECDSA derivation client worker context is unavailable');
      }
      return finalizeRouterAbEcdsaRegistrationActivationWasm({
        command: input,
        workerCtx,
      });
    },
    async closeRouterAbEcdsaRegistrationCeremony(input) {
      if (!workerCtx) {
        throw new Error('ECDSA derivation client worker context is unavailable');
      }
      return closeRouterAbEcdsaRegistrationCeremonyWasm({
        command: input,
        workerCtx,
      });
    },
    async prepareEcdsaClientBootstrap(
      input,
    ): Promise<
      SignerCryptoResult<PrepareEcdsaClientBootstrapOutput, PrepareEcdsaClientBootstrapErrorCode>
    > {
      if (!workerCtx) {
        return signerCryptoInvocationFailure(
          'unavailable',
          'ECDSA client bootstrap worker context is unavailable',
        );
      }
      try {
        const generatedCommand = toGeneratedPrepareEcdsaClientBootstrapCommand(input);
        const generatedOutput = await prepareEcdsaClientBootstrapCommandWasm({
          command: generatedCommand,
          workerCtx,
        });
        return {
          ok: true,
          value: parseGeneratedPrepareEcdsaClientBootstrapOutput(generatedOutput),
        };
      } catch (error) {
        const message = errorMessage(error);
        if (message.includes('unsupported ECDSA bootstrap secret source')) {
          return signerCryptoCommandFailure('unsupported_secret_source', message);
        }
        return (
          mapSignerCryptoInvocationError(error) ||
          signerCryptoCommandFailure('crypto_failure', message)
        );
      }
    },
    async finalizeEcdsaClientBootstrap(
      input,
    ): Promise<
      SignerCryptoResult<FinalizeEcdsaClientBootstrapOutput, FinalizeEcdsaClientBootstrapErrorCode>
    > {
      if (
        input.pendingStateBlob.kind !== 'ecdsa_role_local_pending_state_blob_v1' ||
        input.pendingStateBlob.curve !== 'secp256k1' ||
        input.pendingStateBlob.encoding !== 'base64url' ||
        input.pendingStateBlob.producer !== 'signer_core'
      ) {
        return signerCryptoCommandFailure(
          'invalid_pending_state',
          'ECDSA client bootstrap pending blob envelope is invalid',
        );
      }
      let relayerPublicIdentity: BrowserRelayerPublicIdentity;
      try {
        relayerPublicIdentity = parseRelayerPublicIdentity(input.relayerPublicIdentity);
      } catch (error) {
        return signerCryptoCommandFailure('invalid_relayer_public_identity', errorMessage(error));
      }
      if (!workerCtx) {
        return signerCryptoInvocationFailure(
          'unavailable',
          'ECDSA client bootstrap worker context is unavailable',
        );
      }
      try {
        const generatedCommand = toGeneratedFinalizeEcdsaClientBootstrapCommand(input);
        const generatedOutput = await finalizeEcdsaClientBootstrapCommandWasm({
          command: generatedCommand,
          workerCtx,
        });
        return {
          ok: true,
          value: parseGeneratedFinalizeEcdsaClientBootstrapOutput(generatedOutput),
        };
      } catch (error) {
        return mapSignerCryptoInvocationError(error) || mapFinalizeEcdsaCommandError(error);
      }
    },
    async storeEcdsaRoleLocalSigningMaterial(
      input,
    ): Promise<
      SignerCryptoResult<
        StoreEcdsaRoleLocalSigningMaterialOutput,
        StoreEcdsaRoleLocalSigningMaterialErrorCode
      >
    > {
      if (
        input.stateBlob.kind !== 'ecdsa_role_local_state_blob_v1' ||
        input.stateBlob.curve !== 'secp256k1' ||
        input.stateBlob.encoding !== 'base64url' ||
        input.stateBlob.producer !== 'signer_core'
      ) {
        return signerCryptoCommandFailure(
          'invalid_ready_state',
          'ECDSA role-local ready blob envelope is invalid',
        );
      }
      if (!workerCtx) {
        return signerCryptoInvocationFailure(
          'unavailable',
          'ECDSA role-local material worker context is unavailable',
        );
      }
      try {
        const stored = await storeEcdsaRoleLocalSigningMaterialWasm({
          materialHandle: input.handle.materialHandle,
          bindingDigest: input.handle.bindingDigest,
          stateBlob: input.stateBlob,
          workerCtx,
        });
        return {
          ok: true,
          value: {
            handle: {
              kind: 'ecdsa_role_local_worker_handle_v1',
              materialHandle: parseEcdsaRoleLocalMaterialHandle(stored.materialHandle),
              durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(stored.materialHandle),
              bindingDigest: parseEcdsaRoleLocalBindingDigest(stored.bindingDigest),
            },
          },
        };
      } catch (error) {
        return (
          mapSignerCryptoInvocationError(error) ||
          signerCryptoCommandFailure('crypto_failure', errorMessage(error))
        );
      }
    },
    async buildEcdsaRoleLocalExportArtifact(
      input,
    ): Promise<
      SignerCryptoResult<
        BuildEcdsaRoleLocalExportArtifactOutput,
        BuildEcdsaRoleLocalExportArtifactErrorCode
      >
    > {
      if (
        input.stateBlob.kind !== 'ecdsa_role_local_state_blob_v1' ||
        input.stateBlob.curve !== 'secp256k1' ||
        input.stateBlob.encoding !== 'base64url' ||
        input.stateBlob.producer !== 'signer_core'
      ) {
        return signerCryptoCommandFailure(
          'invalid_ready_state',
          'ECDSA role-local ready blob envelope is invalid',
        );
      }
      if (!workerCtx) {
        return signerCryptoInvocationFailure(
          'unavailable',
          'ECDSA role-local export worker context is unavailable',
        );
      }
      try {
        const generatedCommand = toGeneratedBuildEcdsaRoleLocalExportArtifactCommand(input);
        const generatedOutput = await buildEcdsaRoleLocalExportArtifactCommandWasm({
          command: generatedCommand,
          workerCtx,
        });
        return {
          ok: true,
          value: parseGeneratedBuildEcdsaRoleLocalExportArtifactOutput(generatedOutput),
        };
      } catch (error) {
        return (
          mapSignerCryptoInvocationError(error) || mapBuildEcdsaRoleLocalExportCommandError(error)
        );
      }
    },
  };
}

function createBrowserHttpTransport(fetchImpl: typeof fetch | undefined): HttpTransport {
  return {
    kind: 'http_transport',
    async request(input) {
      if (!fetchImpl) return { ok: false, code: 'network_error', message: 'fetch is unavailable' };
      const controller = new AbortController();
      const timeout =
        input.timeoutMs && input.timeoutMs > 0
          ? setTimeout(() => controller.abort(), input.timeoutMs)
          : null;
      try {
        const response = await fetchImpl(input.url, {
          method: input.method,
          headers: input.headers,
          body: input.body == null ? undefined : JSON.stringify(input.body),
          signal: controller.signal,
        });
        const contentType = response.headers.get('content-type') || '';
        const body = contentType.includes('application/json')
          ? await response.json().catch(() => null)
          : await response.text().catch(() => '');
        return { ok: true, value: { status: response.status, body } };
      } catch (error) {
        const code = controller.signal.aborted ? 'timeout' : 'network_error';
        return { ok: false, code, message: error instanceof Error ? error.message : String(error) };
      } finally {
        if (timeout) clearTimeout(timeout);
      }
    },
  };
}

function createBrowserClock(nowMs: (() => number) | undefined): ClockPort {
  return {
    kind: 'clock',
    nowMs: nowMs || (() => Date.now()),
  };
}

function createBrowserRandomSource(cryptoImpl: Crypto | undefined): RandomSource {
  return {
    kind: 'random_source',
    randomBytes(length) {
      if (!cryptoImpl?.getRandomValues) {
        throw new Error('Browser crypto.getRandomValues is unavailable');
      }
      const bytes = new Uint8Array(length);
      cryptoImpl.getRandomValues(bytes);
      return bytes;
    },
  };
}

export function createBrowserPlatformRuntime(
  deps: BrowserRuntimePortsDeps = {},
): BrowserRuntimePorts {
  const indexedDB = deps.indexedDB || IndexedDBManager;
  return {
    kind: 'browser',
    storage: createBrowserDurableRecordStore(indexedDB, deps.ecdsaSessionStore),
    secrets: createBrowserSecureSecretStore(),
    authenticator: createBrowserAuthenticatorPort(
      deps.credentials || globalThis.navigator?.credentials,
    ),
    signerCrypto: createBrowserSignerCryptoPort(deps.workerCtx),
    http: createBrowserHttpTransport(deps.fetch || globalThis.fetch?.bind(globalThis)),
    clock: createBrowserClock(deps.nowMs),
    random: createBrowserRandomSource(deps.crypto || globalThis.crypto),
  };
}

export function getBrowserPlatformIndexedDB(runtime: RuntimePorts): typeof IndexedDBManager {
  if (runtime.kind !== 'browser' || !('indexedDB' in runtime.storage)) {
    throw new Error('Browser IndexedDB manager is unavailable for these runtime ports');
  }
  return (runtime.storage as BrowserDurableRecordStore).indexedDB;
}
