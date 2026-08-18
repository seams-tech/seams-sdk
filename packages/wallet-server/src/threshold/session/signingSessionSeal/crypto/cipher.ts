import {
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_GROUP_ID,
  encodeSigningSessionHkdfTuple,
  type SigningSessionSealProtocol,
} from '@shared/utils/signingSessionSeal';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  parseSigningSessionSealKeyVersion,
  type SigningSessionSealKeyVersion,
} from '../../../../core/keyMaterialBrands';
import type {
  SigningSessionSealCipherAdapter,
  SigningSessionSealCipherOperationInput,
  SigningSessionSealCipherOperationResult,
} from '../signingSessionSeal.types';
import {
  addSigningSessionSealLock,
  deriveSigningSessionSealLockKeyHandle,
  destroySigningSessionSealLockKeyHandle,
  removeSigningSessionSealLock,
} from './shamir3PassWasm';

type HandlerInput = Omit<SigningSessionSealCipherOperationInput, 'operation'>;
type HandlerResult = SigningSessionSealCipherOperationResult;

export interface CreateSigningSessionSealCipherAdapterOptions {
  applyServerSeal: (input: HandlerInput) => Promise<HandlerResult> | HandlerResult;
  removeServerSeal: (input: HandlerInput) => Promise<HandlerResult> | HandlerResult;
}

export type SigningSessionSealShamir3PassRootConfig = {
  readonly kind: 'shamir3pass_root_v2';
  readonly rootSecret32: Uint8Array;
  readonly currentKeyVersion: SigningSessionSealKeyVersion;
  readonly acceptedWarmKeyVersions: readonly SigningSessionSealKeyVersion[];
  readonly protocol: SigningSessionSealProtocol;
};

export interface SigningSessionSealShamir3PassRuntime {
  deriveLockKeyHandle(input: {
    readonly groupId: string;
    readonly rootSecret32: Uint8Array;
    readonly context: Uint8Array;
  }): Promise<number>;
  addLock(input: { readonly handle: number; readonly ciphertextB64u: string }): Promise<string>;
  removeLock(input: { readonly handle: number; readonly ciphertextB64u: string }): Promise<string>;
  destroyLockKeyHandle(handle: number): boolean;
}

export interface CreateSigningSessionSealShamir3PassCipherAdapterOptions {
  readonly config: SigningSessionSealShamir3PassRootConfig;
  readonly runtime?: SigningSessionSealShamir3PassRuntime;
}

function toErrorResult(error: unknown): { ok: false; code: string; message: string } {
  if (
    error &&
    typeof error === 'object' &&
    !Array.isArray(error) &&
    (error as { code?: unknown }).code
  ) {
    const code = String((error as { code?: unknown }).code || '').trim() || 'internal';
    const message =
      String((error as { message?: unknown }).message || '').trim() ||
      'Signing-session seal cipher failed';
    return { ok: false, code, message };
  }
  const message =
    error instanceof Error ? error.message : String(error || 'Signing-session seal cipher failed');
  return { ok: false, code: 'internal', message };
}

function normalizeResult(result: HandlerResult): HandlerResult {
  if (!result.ok) {
    return {
      ok: false,
      code: String(result.code || 'internal').trim() || 'internal',
      message:
        String(result.message || 'Signing-session seal cipher failed').trim() ||
        'Signing-session seal cipher failed',
    };
  }
  const ciphertext = toOptionalTrimmedString(result.ciphertext);
  if (!ciphertext) {
    return {
      ok: false,
      code: 'invalid_ciphertext',
      message: 'Signing-session seal cipher returned empty ciphertext',
    };
  }
  return {
    ok: true,
    ciphertext,
    ...(String(result.keyVersion || '').trim()
      ? { keyVersion: String(result.keyVersion).trim() }
      : {}),
  };
}

export function createSigningSessionSealCipherAdapter(
  options: CreateSigningSessionSealCipherAdapterOptions,
): SigningSessionSealCipherAdapter {
  return {
    run: async (
      input: SigningSessionSealCipherOperationInput,
    ): Promise<SigningSessionSealCipherOperationResult> => {
      const handlerInput: HandlerInput = {
        thresholdSessionId: input.thresholdSessionId,
        ciphertext: input.ciphertext,
        ...(input.keyVersion ? { keyVersion: input.keyVersion } : {}),
        ...(input.metadata ? { metadata: input.metadata } : {}),
        auth: input.auth,
      };
      try {
        const output =
          input.operation === 'apply-server-seal'
            ? await options.applyServerSeal(handlerInput)
            : await options.removeServerSeal(handlerInput);
        return normalizeResult(output);
      } catch (error: unknown) {
        return toErrorResult(error);
      }
    },
  };
}

export function createPassthroughSigningSessionSealCipherAdapter(): SigningSessionSealCipherAdapter {
  return createSigningSessionSealCipherAdapter({
    applyServerSeal: async (input) => ({
      ok: true,
      ciphertext: input.ciphertext,
      ...(input.keyVersion ? { keyVersion: input.keyVersion } : {}),
    }),
    removeServerSeal: async (input) => ({
      ok: true,
      ciphertext: input.ciphertext,
      ...(input.keyVersion ? { keyVersion: input.keyVersion } : {}),
    }),
  });
}

function normalizeKeyVersion(value: unknown, label: string): SigningSessionSealKeyVersion {
  const keyVersion = toOptionalTrimmedString(value);
  if (!keyVersion) throw new Error(`${label} is required`);
  return parseSigningSessionSealKeyVersion(keyVersion);
}

function normalizeConfig(
  config: SigningSessionSealShamir3PassRootConfig,
): SigningSessionSealShamir3PassRootConfig {
  if (config.kind !== 'shamir3pass_root_v2') {
    throw new Error('Signing-session seal root configuration kind is invalid');
  }
  if (!(config.rootSecret32 instanceof Uint8Array) || config.rootSecret32.length !== 32) {
    throw new Error('Signing-session seal root secret must be exactly 32 bytes');
  }
  if (
    config.protocol.algorithm !== SIGNING_SESSION_SEAL_ALG ||
    config.protocol.groupId !== SIGNING_SESSION_SEAL_GROUP_ID
  ) {
    throw new Error('Signing-session seal protocol is unsupported');
  }

  const currentKeyVersion = normalizeKeyVersion(
    config.currentKeyVersion,
    'currentKeyVersion',
  );
  const acceptedWarmKeyVersions = config.acceptedWarmKeyVersions.map((keyVersion, index) =>
    normalizeKeyVersion(keyVersion, `acceptedWarmKeyVersions[${index}]`),
  );
  if (!acceptedWarmKeyVersions.includes(currentKeyVersion)) {
    throw new Error('acceptedWarmKeyVersions must include currentKeyVersion');
  }
  if (new Set(acceptedWarmKeyVersions).size !== acceptedWarmKeyVersions.length) {
    throw new Error('acceptedWarmKeyVersions must not contain duplicates');
  }

  return {
    kind: 'shamir3pass_root_v2',
    rootSecret32: config.rootSecret32.slice(),
    currentKeyVersion,
    acceptedWarmKeyVersions,
    protocol: {
      algorithm: SIGNING_SESSION_SEAL_ALG,
      groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    },
  };
}

export function encodeSigningSessionSealServerLockContext(input: {
  readonly protocol: SigningSessionSealProtocol;
  readonly keyVersion: string;
}): Uint8Array {
  return encodeSigningSessionHkdfTuple([
    'seams/router-ab/signing-session-seal',
    input.protocol.algorithm,
    input.protocol.groupId,
    input.keyVersion,
    'server-lock/v1',
  ]);
}

function defaultRuntime(): SigningSessionSealShamir3PassRuntime {
  return {
    deriveLockKeyHandle: deriveSigningSessionSealLockKeyHandle,
    addLock: addSigningSessionSealLock,
    removeLock: removeSigningSessionSealLock,
    destroyLockKeyHandle: destroySigningSessionSealLockKeyHandle,
  };
}

async function deriveAcceptedKeyHandles(input: {
  readonly config: SigningSessionSealShamir3PassRootConfig;
  readonly runtime: SigningSessionSealShamir3PassRuntime;
}): Promise<ReadonlyMap<string, number>> {
  const handles = new Map<string, number>();
  try {
    for (const keyVersion of input.config.acceptedWarmKeyVersions) {
      const handle = await input.runtime.deriveLockKeyHandle({
        groupId: input.config.protocol.groupId,
        rootSecret32: input.config.rootSecret32,
        context: encodeSigningSessionSealServerLockContext({
          protocol: input.config.protocol,
          keyVersion,
        }),
      });
      handles.set(keyVersion, handle);
    }
    return handles;
  } catch (error: unknown) {
    for (const handle of handles.values()) input.runtime.destroyLockKeyHandle(handle);
    throw error;
  } finally {
    input.config.rootSecret32.fill(0);
  }
}

class SigningSessionSealKeyHandles {
  private initialization: Promise<ReadonlyMap<string, number>> | null = null;

  constructor(
    private readonly config: SigningSessionSealShamir3PassRootConfig,
    private readonly runtime: SigningSessionSealShamir3PassRuntime,
  ) {}

  get(): Promise<ReadonlyMap<string, number>> {
    if (!this.initialization) {
      this.initialization = deriveAcceptedKeyHandles({
        config: this.config,
        runtime: this.runtime,
      });
    }
    return this.initialization;
  }
}

function cipherFailure(code: string, message: string): SigningSessionSealCipherOperationResult {
  return { ok: false, code, message };
}

function mapCipherError(
  error: unknown,
  defaultMessage: string,
): SigningSessionSealCipherOperationResult {
  const message =
    toOptionalTrimmedString(error instanceof Error ? error.message : error) || defaultMessage;
  const lowered = message.toLowerCase();
  if (lowered.includes('keyversion')) return cipherFailure('invalid_key_version', message);
  if (lowered.includes('ciphertext') || lowered.includes('base64url') || lowered.includes('group')) {
    return cipherFailure('invalid_ciphertext', message);
  }
  return cipherFailure('internal', message);
}

export function createSigningSessionSealShamir3PassCipherAdapter(
  options: CreateSigningSessionSealShamir3PassCipherAdapterOptions,
): SigningSessionSealCipherAdapter {
  const config = normalizeConfig(options.config);
  options.config.rootSecret32.fill(0);
  const runtime = options.runtime ?? defaultRuntime();
  const handles = new SigningSessionSealKeyHandles(config, runtime);

  return createSigningSessionSealCipherAdapter({
    applyServerSeal: async (input) => {
      const requestedKeyVersion = toOptionalTrimmedString(input.keyVersion);
      if (requestedKeyVersion && requestedKeyVersion !== config.currentKeyVersion) {
        return cipherFailure(
          'invalid_key_version',
          `Requested keyVersion "${requestedKeyVersion}" does not match active keyVersion "${config.currentKeyVersion}"`,
        );
      }
      try {
        const handle = (await handles.get()).get(config.currentKeyVersion);
        if (handle === undefined) throw new Error('currentKeyVersion handle is unavailable');
        return {
          ok: true,
          ciphertext: await runtime.addLock({ handle, ciphertextB64u: input.ciphertext }),
          keyVersion: config.currentKeyVersion,
        };
      } catch (error: unknown) {
        return mapCipherError(error, 'Failed to apply server seal');
      }
    },
    removeServerSeal: async (input) => {
      const keyVersion = normalizeKeyVersion(input.keyVersion, 'keyVersion');
      try {
        const handle = (await handles.get()).get(keyVersion);
        if (handle === undefined) {
          return cipherFailure('invalid_key_version', `Unknown keyVersion "${keyVersion}"`);
        }
        return {
          ok: true,
          ciphertext: await runtime.removeLock({ handle, ciphertextB64u: input.ciphertext }),
          keyVersion,
        };
      } catch (error: unknown) {
        return mapCipherError(error, 'Failed to remove server seal');
      }
    },
  });
}
