import { IndexedDBManager } from '../../indexedDB';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  PASSKEY_PRF_FIRST_SALT_V1,
  PASSKEY_PRF_SECOND_SALT_V1,
} from '@shared/utils/signingSessionSeal';
import { errorMessage } from '@shared/utils/errors';
import { derivePasskeyThresholdEcdsaClientRootShare32B64uFromPrfFirst } from '../../signingEngine/session/passkey/ecdsaClientRoot';
import { buildThresholdEcdsaHssRoleLocalClientBootstrapWasm } from '../../signingEngine/threshold/crypto/hssClientSignerWasm';
import type { WorkerOperationContext } from '../../signingEngine/workerManager/executeWorkerOperation';
import {
  getSignerWorkerOperationCoreCode,
  getSignerWorkerOperationErrorCode,
} from '../../signingEngine/workerManager/workerTypes';
import {
  serializeAuthenticationCredentialWithPRF,
  serializeRegistrationCredentialWithPRF,
} from '../../signingEngine/webauthnAuth/credentials/helpers';
import {
  getPrfFirstB64uFromCredential,
} from '../../signingEngine/webauthnAuth/credentials/credentialExtensions';
import type {
  AuthenticatorOperation,
  AuthenticatorResult,
  AuthenticatorPort,
  ClockPort,
  CleanupMalformedEcdsaRoleLocalRecordResult,
  DurableRecordStore,
  EcdsaRoleLocalPendingStateBlob,
  EcdsaRoleLocalReadyStateBlob,
  FinalizeEcdsaClientBootstrapErrorCode,
  FinalizeEcdsaClientBootstrapOutput,
  HttpTransport,
  LoadEcdsaRoleLocalReadyRecordResult,
  PlatformResult,
  PlatformRuntime,
  PrepareEcdsaClientBootstrapErrorCode,
  PrepareEcdsaClientBootstrapOutput,
  PersistEcdsaRoleLocalReadyRecordResult,
  RandomSource,
  SecureSecretStore,
  SignerCryptoPort,
  SignerCryptoInvocationErrorCode,
  SignerCryptoResult,
} from '../types';
import type {
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

type BrowserPlatformRuntimeDeps = {
  indexedDB?: typeof IndexedDBManager;
  fetch?: typeof fetch;
  crypto?: Crypto;
  credentials?: CredentialsContainer;
  workerCtx?: WorkerOperationContext;
  nowMs?: () => number;
};

export type BrowserDurableRecordStore = DurableRecordStore & {
  indexedDB: typeof IndexedDBManager;
};

export type BrowserPlatformRuntime = PlatformRuntime & {
  kind: 'browser';
  storage: BrowserDurableRecordStore;
};

function unavailable<T>(message: string): PlatformResult<T, 'unavailable'> {
  return { ok: false, code: 'unavailable', message };
}

type BrowserPendingEcdsaStateBlobPayload = {
  kind: 'browser_pending_ecdsa_role_local_state_v1';
  context: PrepareEcdsaClientBootstrapOutput['publicFacts'] & {
    walletId: string;
    rpId: string;
    ecdsaThresholdKeyId: string;
    signingRootId: string;
    signingRootVersion: string;
    keyPurpose: 'evm-signing';
    keyVersion: 'v1';
  };
  contextBinding32B64u: string;
  clientShareRetryCounter: number;
  clientShare32B64u: string;
  clientCaitSithInput: {
    participantId: 1;
    mappedPrivateShare32B64u: string;
    verifyingShare33B64u: string;
  };
};

type BrowserReadyEcdsaStateBlobPayload = {
  kind: 'browser_ready_ecdsa_role_local_state_v1';
  pending: BrowserPendingEcdsaStateBlobPayload;
  relayerPublicIdentity: {
    relayerKeyId: string;
    relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
    groupPublicKey33B64u: string;
    ethereumAddress: `0x${string}`;
  };
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

function encodeJsonBlob(value: unknown): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

function decodeJsonBlob(blobB64u: string): unknown {
  return JSON.parse(new TextDecoder().decode(base64UrlDecode(blobB64u)));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function requiredStringFromRecord(
  record: Record<string, unknown>,
  field: string,
): string {
  const value = String(record[field] || '').trim();
  if (!value) {
    throw new Error(`ECDSA client bootstrap state is missing ${field}`);
  }
  return value;
}

function requiredIntegerFromRecord(record: Record<string, unknown>, field: string): number {
  const value = Number(record[field]);
  if (!Number.isInteger(value)) {
    throw new Error(`ECDSA client bootstrap state has invalid ${field}`);
  }
  return value;
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

function parseHssClientSharePublicKey33B64u(value: string): EcdsaHssClientSharePublicKey33B64u {
  const normalized = requireBase64UrlBytes(value, 'ECDSA HSS client-share public key', 33);
  return normalized as EcdsaHssClientSharePublicKey33B64u;
}

function parsePublicKey33B64u(value: string, field: string): string {
  return requireBase64UrlBytes(value, field, 33);
}

function parseRelayerHssPublicKey33B64u(value: string): EcdsaRelayerHssPublicKey33B64u {
  return parsePublicKey33B64u(
    value,
    'ECDSA relayer HSS public key',
  ) as EcdsaRelayerHssPublicKey33B64u;
}

function parseShare32B64u(value: string, field: string): string {
  return requireBase64UrlBytes(value, field, 32);
}

function parseEthereumAddress(value: unknown): `0x${string}` {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(normalized)) {
    throw new Error('ECDSA relayer public identity has invalid ethereumAddress');
  }
  return normalized as `0x${string}`;
}

function isNativeBindingFailureMessage(message: string): boolean {
  return /wasm (initialization|initialize|instantiation)|webassembly|module_or_path|failed to (load|compile|instantiate) wasm|hss client wasm initialization failed/i.test(
    message,
  );
}

function mapSignerCryptoInvocationError<CommandCode extends string>(
  error: unknown,
): SignerCryptoInvocationFailure<CommandCode> | null {
  const code = getSignerWorkerOperationErrorCode(error);
  const coreCode = getSignerWorkerOperationCoreCode(error);
  const message = errorMessage(error);
  if (coreCode === 'HSS_WASM_INIT_FAILURE') {
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
  if (/postMessage|worker runtime|worker response|worker protocol|Malformed worker|Unknown worker/i.test(message)) {
    return signerCryptoInvocationFailure('worker_transport_failure', message);
  }
  return null;
}

function parseBrowserPendingEcdsaStateBlob(
  blob: EcdsaRoleLocalPendingStateBlob,
): BrowserPendingEcdsaStateBlobPayload {
  if (
    blob.kind !== 'ecdsa_role_local_pending_state_blob_v1' ||
    blob.curve !== 'secp256k1' ||
    blob.encoding !== 'base64url' ||
    blob.producer !== 'signer_core'
  ) {
    throw new Error('ECDSA client bootstrap pending blob envelope is invalid');
  }
  const parsed = decodeJsonBlob(blob.stateBlobB64u);
  if (!isRecord(parsed) || parsed.kind !== 'browser_pending_ecdsa_role_local_state_v1') {
    throw new Error('ECDSA client bootstrap pending state has an invalid kind');
  }
  const context = parsed.context;
  if (!isRecord(context)) {
    throw new Error('ECDSA client bootstrap pending state is missing context');
  }
  const clientCaitSithInput = parsed.clientCaitSithInput;
  if (!isRecord(clientCaitSithInput)) {
    throw new Error('ECDSA client bootstrap pending state is missing clientCaitSithInput');
  }
  const participantId = requiredIntegerFromRecord(clientCaitSithInput, 'participantId');
  if (participantId !== 1) {
    throw new Error('ECDSA client bootstrap pending state has invalid participantId');
  }
  const hssClientSharePublicKey33B64u = parseHssClientSharePublicKey33B64u(
    requiredStringFromRecord(context, 'hssClientSharePublicKey33B64u'),
  );
  const keyPurpose = requiredStringFromRecord(context, 'keyPurpose');
  if (keyPurpose !== 'evm-signing') {
    throw new Error('ECDSA client bootstrap pending state has invalid keyPurpose');
  }
  const keyVersion = requiredStringFromRecord(context, 'keyVersion');
  if (keyVersion !== 'v1') {
    throw new Error('ECDSA client bootstrap pending state has invalid keyVersion');
  }
  const clientVerifyingShareB64u = parsePublicKey33B64u(
    requiredStringFromRecord(context, 'clientVerifyingShareB64u'),
    'clientVerifyingShareB64u',
  );
  const verifyingShare33B64u = parsePublicKey33B64u(
    requiredStringFromRecord(clientCaitSithInput, 'verifyingShare33B64u'),
    'clientCaitSithInput.verifyingShare33B64u',
  );
  if (clientVerifyingShareB64u !== verifyingShare33B64u) {
    throw new Error('ECDSA pending state public facts do not match clientCaitSithInput');
  }
  return {
    kind: 'browser_pending_ecdsa_role_local_state_v1',
    context: {
      walletId: requiredStringFromRecord(context, 'walletId'),
      rpId: requiredStringFromRecord(context, 'rpId'),
      ecdsaThresholdKeyId: requiredStringFromRecord(context, 'ecdsaThresholdKeyId'),
      signingRootId: requiredStringFromRecord(context, 'signingRootId'),
      signingRootVersion: requiredStringFromRecord(context, 'signingRootVersion'),
      keyPurpose,
      keyVersion,
      hssClientSharePublicKey33B64u,
      clientVerifyingShareB64u,
    },
    contextBinding32B64u: parseShare32B64u(
      requiredStringFromRecord(parsed, 'contextBinding32B64u'),
      'contextBinding32B64u',
    ),
    clientShareRetryCounter: requiredIntegerFromRecord(parsed, 'clientShareRetryCounter'),
    clientShare32B64u: parseShare32B64u(
      requiredStringFromRecord(parsed, 'clientShare32B64u'),
      'clientShare32B64u',
    ),
    clientCaitSithInput: {
      participantId: 1,
      mappedPrivateShare32B64u: parseShare32B64u(
        requiredStringFromRecord(clientCaitSithInput, 'mappedPrivateShare32B64u'),
        'clientCaitSithInput.mappedPrivateShare32B64u',
      ),
      verifyingShare33B64u,
    },
  };
}

function parseRelayerPublicIdentity(
  input: unknown,
): BrowserReadyEcdsaStateBlobPayload['relayerPublicIdentity'] {
  if (!isRecord(input)) {
    throw new Error('ECDSA relayer public identity must be an object');
  }
  return {
    relayerKeyId: requiredStringFromRecord(input, 'relayerKeyId'),
    relayerPublicKey33B64u: parseRelayerHssPublicKey33B64u(
      requiredStringFromRecord(input, 'relayerPublicKey33B64u'),
    ),
    groupPublicKey33B64u: parsePublicKey33B64u(
      requiredStringFromRecord(input, 'groupPublicKey33B64u'),
      'groupPublicKey33B64u',
    ),
    ethereumAddress: parseEthereumAddress(input.ethereumAddress),
  };
}

function createBrowserDurableRecordStore(
  indexedDB: typeof IndexedDBManager,
): BrowserDurableRecordStore {
  return {
    kind: 'durable_record_store',
    indexedDB,
    async loadEcdsaRoleLocalReadyRecord(): Promise<LoadEcdsaRoleLocalReadyRecordResult> {
      return unavailable('Browser ECDSA role-local record loading is not wired yet');
    },
    async persistEcdsaRoleLocalReadyRecord(): Promise<PersistEcdsaRoleLocalReadyRecordResult> {
      return unavailable('Browser ECDSA role-local record persistence is not wired yet');
    },
    async cleanupMalformedEcdsaRoleLocalRecord(): Promise<
      CleanupMalformedEcdsaRoleLocalRecordResult
    > {
      return unavailable('Browser ECDSA role-local record cleanup is not wired yet');
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
                  id: base64UrlDecode(operation.userHandleB64u),
                  name: operation.userHandleB64u,
                  displayName: operation.userHandleB64u,
                },
                challenge: base64UrlDecode(operation.challengeB64u),
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
            const serialized = serializeRegistrationCredentialWithPRF({ credential });
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
                challenge: base64UrlDecode(operation.challengeB64u),
                allowCredentials: [
                  {
                    type: 'public-key',
                    id: base64UrlDecode(operation.credentialIdB64u),
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
            const serialized = serializeAuthenticationCredentialWithPRF({ credential });
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

function createBrowserSignerCryptoPort(workerCtx: WorkerOperationContext | undefined): SignerCryptoPort {
  return {
    kind: 'signer_crypto',
    async prepareEcdsaClientBootstrap(input): Promise<
      SignerCryptoResult<PrepareEcdsaClientBootstrapOutput, PrepareEcdsaClientBootstrapErrorCode>
    > {
      if (!workerCtx) {
        return signerCryptoInvocationFailure(
          'unavailable',
          'ECDSA client bootstrap worker context is unavailable',
        );
      }
      if (input.secretSource.kind !== 'webauthn_prf_first') {
        return signerCryptoCommandFailure(
          'unsupported_secret_source',
          `Browser ECDSA bootstrap does not support ${input.secretSource.kind} yet`,
        );
      }
      try {
        const clientRootShare32B64u =
          await derivePasskeyThresholdEcdsaClientRootShare32B64uFromPrfFirst(
            input.secretSource.prfFirstB64u,
          );
        const bootstrap = await buildThresholdEcdsaHssRoleLocalClientBootstrapWasm({
          context: {
            walletId: input.context.walletId,
            rpId: input.context.rpId,
            ecdsaThresholdKeyId: input.context.ecdsaThresholdKeyId,
            signingRootId: input.context.signingRootId,
            signingRootVersion: input.context.signingRootVersion,
            keyPurpose: input.context.keyPurpose,
            keyVersion: input.context.keyVersion,
          },
          clientRootShare32B64u,
          workerCtx,
        });
        const hssClientSharePublicKey33B64u = parseHssClientSharePublicKey33B64u(
          bootstrap.clientPublicKey33B64u,
        );
        const pendingStatePayload: BrowserPendingEcdsaStateBlobPayload = {
          kind: 'browser_pending_ecdsa_role_local_state_v1',
          context: {
            walletId: input.context.walletId,
            rpId: input.context.rpId,
            ecdsaThresholdKeyId: input.context.ecdsaThresholdKeyId,
            signingRootId: input.context.signingRootId,
            signingRootVersion: input.context.signingRootVersion,
            keyPurpose: input.context.keyPurpose,
            keyVersion: input.context.keyVersion,
            hssClientSharePublicKey33B64u,
            clientVerifyingShareB64u: bootstrap.clientCaitSithInput.verifyingShare33B64u,
          },
          contextBinding32B64u: bootstrap.contextBinding32B64u,
          clientShareRetryCounter: bootstrap.clientShareRetryCounter,
          clientShare32B64u: bootstrap.clientShare32B64u,
          clientCaitSithInput: bootstrap.clientCaitSithInput,
        };
        const pendingStateBlob: EcdsaRoleLocalPendingStateBlob = {
          kind: 'ecdsa_role_local_pending_state_blob_v1',
          curve: 'secp256k1',
          encoding: 'base64url',
          producer: 'signer_core',
          stateBlobB64u: encodeJsonBlob(pendingStatePayload),
        };
        return {
          ok: true,
          value: {
            pendingStateBlob,
            clientBootstrap: {
              contextBinding32B64u: bootstrap.contextBinding32B64u,
              hssClientSharePublicKey33B64u,
              clientShareRetryCounter: bootstrap.clientShareRetryCounter,
              participantId: 1,
            },
            publicFacts: {
              hssClientSharePublicKey33B64u,
              clientVerifyingShareB64u: bootstrap.clientCaitSithInput.verifyingShare33B64u,
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
    async finalizeEcdsaClientBootstrap(input): Promise<
      SignerCryptoResult<FinalizeEcdsaClientBootstrapOutput, FinalizeEcdsaClientBootstrapErrorCode>
    > {
      try {
        const pending = parseBrowserPendingEcdsaStateBlob(input.pendingStateBlob);
        let relayerPublicIdentity: BrowserReadyEcdsaStateBlobPayload['relayerPublicIdentity'];
        try {
          relayerPublicIdentity = parseRelayerPublicIdentity(input.relayerPublicIdentity);
        } catch (error) {
          return signerCryptoCommandFailure(
            'invalid_relayer_public_identity',
            errorMessage(error),
          );
        }
        if (
          String(relayerPublicIdentity.relayerPublicKey33B64u) ===
          String(pending.context.hssClientSharePublicKey33B64u)
        ) {
          return signerCryptoCommandFailure(
            'public_identity_mismatch',
            'ECDSA relayer public identity matches the HSS client-share identity',
          );
        }
        const stateBlob: EcdsaRoleLocalReadyStateBlob = {
          kind: 'ecdsa_role_local_state_blob_v1',
          curve: 'secp256k1',
          encoding: 'base64url',
          producer: 'signer_core',
          stateBlobB64u: encodeJsonBlob({
            kind: 'browser_ready_ecdsa_role_local_state_v1',
            pending,
            relayerPublicIdentity,
          }),
        };
        return {
          ok: true,
          value: {
            stateBlob,
            publicFacts: {
              hssClientSharePublicKey33B64u: pending.context.hssClientSharePublicKey33B64u,
              clientVerifyingShareB64u: pending.context.clientVerifyingShareB64u,
              relayerPublicKey33B64u: relayerPublicIdentity.relayerPublicKey33B64u,
              groupPublicKey33B64u: relayerPublicIdentity.groupPublicKey33B64u,
              ethereumAddress: relayerPublicIdentity.ethereumAddress,
            },
          },
        };
      } catch (error) {
        return signerCryptoCommandFailure('invalid_pending_state', errorMessage(error));
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
  deps: BrowserPlatformRuntimeDeps = {},
): BrowserPlatformRuntime {
  const indexedDB = deps.indexedDB || IndexedDBManager;
  return {
    kind: 'browser',
    storage: createBrowserDurableRecordStore(indexedDB),
    secrets: createBrowserSecureSecretStore(),
    authenticator: createBrowserAuthenticatorPort(deps.credentials || globalThis.navigator?.credentials),
    signerCrypto: createBrowserSignerCryptoPort(deps.workerCtx),
    http: createBrowserHttpTransport(deps.fetch || globalThis.fetch?.bind(globalThis)),
    clock: createBrowserClock(deps.nowMs),
    random: createBrowserRandomSource(deps.crypto || globalThis.crypto),
  };
}

export function getBrowserPlatformIndexedDB(runtime: PlatformRuntime): typeof IndexedDBManager {
  if (runtime.kind !== 'browser' || !('indexedDB' in runtime.storage)) {
    throw new Error('Browser IndexedDB manager is unavailable for this platform runtime');
  }
  return (runtime.storage as BrowserDurableRecordStore).indexedDB;
}
