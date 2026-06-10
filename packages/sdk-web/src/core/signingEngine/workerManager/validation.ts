import { normalizeRegistrationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type { TransactionContext } from '@/core/types/rpc';
import type { RegistrationConfirmationDiagnostics } from '@/core/signingEngine/stepUpConfirmation/types';
import { isObject, assertString, ensureEd25519Prefix } from '@shared/utils/validation';
import { DelegateActionInput } from '@/core/types/delegate';
import { base58Encode } from '@shared/utils/base58';
export { ensureEd25519Prefix };

export const toPublicKeyString = (pk: DelegateActionInput['publicKey']): string => {
  if (typeof pk === 'string') {
    return pk;
  }
  return ensureEd25519Prefix(base58Encode(pk.keyData));
};

// Strongly typed payload expected from the WASM → JS boundary
export interface RegistrationCredentialConfirmationPayload {
  confirmed: boolean;
  requestId: string;
  intentDigest: string;
  credential: WebAuthnRegistrationCredential; // serialized PublicKeyCredential (no methods)
  transactionContext?: TransactionContext;
  registrationDiagnostics?: RegistrationConfirmationDiagnostics;
  error?: string;
}

function sanitizeDiagnosticDuration(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return null;
  return Math.round(value);
}

function sanitizeRegistrationConfirmationDiagnosticsMaybe(
  input: unknown,
): RegistrationConfirmationDiagnostics | undefined {
  if (input == null) return undefined;
  if (!isObject(input)) return undefined;

  const record = input as Record<keyof RegistrationConfirmationDiagnostics, unknown>;
  if (record.kind !== 'registration_confirmation_diagnostics_v1') return undefined;

  const workerReadyMs = sanitizeDiagnosticDuration(record.workerReadyMs);
  const workerRequestRoundTripMs = sanitizeDiagnosticDuration(record.workerRequestRoundTripMs);
  const workerResponseValidationMs = sanitizeDiagnosticDuration(record.workerResponseValidationMs);
  const requestSetupMs = sanitizeDiagnosticDuration(record.requestSetupMs);
  const promptUserMs = sanitizeDiagnosticDuration(record.promptUserMs);
  const promptElementDefineMs = sanitizeDiagnosticDuration(record.promptElementDefineMs);
  const promptMountMs = sanitizeDiagnosticDuration(record.promptMountMs);
  const promptHostFirstUpdateMs = sanitizeDiagnosticDuration(record.promptHostFirstUpdateMs);
  const promptHostInteractiveMs = sanitizeDiagnosticDuration(record.promptHostInteractiveMs);
  const promptConfirmEventMs = sanitizeDiagnosticDuration(record.promptConfirmEventMs);
  const promptDecisionWaitMs = sanitizeDiagnosticDuration(record.promptDecisionWaitMs);
  const credentialCreateStartMs = sanitizeDiagnosticDuration(record.credentialCreateStartMs);
  const credentialCreateMs = sanitizeDiagnosticDuration(record.credentialCreateMs);
  const credentialSerializeMs = sanitizeDiagnosticDuration(record.credentialSerializeMs);
  const duplicateRetryCount = sanitizeDiagnosticDuration(record.duplicateRetryCount);
  const mainThreadTotalMs = sanitizeDiagnosticDuration(record.mainThreadTotalMs);

  if (
    workerReadyMs == null ||
    workerRequestRoundTripMs == null ||
    workerResponseValidationMs == null ||
    requestSetupMs == null ||
    promptUserMs == null ||
    promptElementDefineMs == null ||
    promptMountMs == null ||
    promptHostFirstUpdateMs == null ||
    promptHostInteractiveMs == null ||
    promptConfirmEventMs == null ||
    promptDecisionWaitMs == null ||
    credentialCreateStartMs == null ||
    credentialCreateMs == null ||
    credentialSerializeMs == null ||
    duplicateRetryCount == null ||
    mainThreadTotalMs == null
  ) {
    return undefined;
  }

  return {
    kind: 'registration_confirmation_diagnostics_v1',
    workerReadyMs,
    workerRequestRoundTripMs,
    workerResponseValidationMs,
    requestSetupMs,
    promptUserMs,
    promptElementDefineMs,
    promptMountMs,
    promptHostFirstUpdateMs,
    promptHostInteractiveMs,
    promptConfirmEventMs,
    promptDecisionWaitMs,
    credentialCreateStartMs,
    credentialCreateMs,
    credentialSerializeMs,
    duplicateRetryCount,
    mainThreadTotalMs,
  };
}

function validateTransactionContextMaybe(input: unknown): TransactionContext | undefined {
  if (input == null) return undefined;
  if (!isObject(input)) {
    throw new Error('Invalid transactionContext: expected object');
  }

  const { nearPublicKeyStr, nextNonce, txBlockHeight, txBlockHash, accessKeyInfo } = input as {
    nearPublicKeyStr?: unknown;
    nextNonce?: unknown;
    txBlockHeight?: unknown;
    txBlockHash?: unknown;
    accessKeyInfo?: unknown;
  };

  // Minimal structural validation; AccessKeyView is complex. Be tolerant because the WASM struct omits it.
  const normalizedNearPublicKeyStr = assertString(
    nearPublicKeyStr,
    'transactionContext.nearPublicKeyStr',
  );
  const normalizedNextNonce = assertString(nextNonce, 'transactionContext.nextNonce');
  const normalizedTxBlockHeight = assertString(txBlockHeight, 'transactionContext.txBlockHeight');
  const normalizedTxBlockHash = assertString(txBlockHash, 'transactionContext.txBlockHash');

  let normalizedAccessKeyInfo = accessKeyInfo as TransactionContext['accessKeyInfo'] | undefined;
  if (normalizedAccessKeyInfo != null && !isObject(normalizedAccessKeyInfo)) {
    throw new Error('Invalid transactionContext.accessKeyInfo: expected object');
  }
  if (normalizedAccessKeyInfo == null) {
    // Synthesize a minimal placeholder; not used by registration flows consuming this payload
    normalizedAccessKeyInfo = { nonce: 0 } as unknown as TransactionContext['accessKeyInfo'];
  }

  return {
    nearPublicKeyStr: normalizedNearPublicKeyStr,
    nextNonce: normalizedNextNonce,
    txBlockHeight: normalizedTxBlockHeight,
    txBlockHash: normalizedTxBlockHash,
    accessKeyInfo: normalizedAccessKeyInfo,
  };
}

function validateCredentialMaybe(input: unknown): WebAuthnRegistrationCredential | undefined {
  if (input == null) return undefined;

  const cred = normalizeRegistrationCredential(input);
  if (cred.type !== 'public-key') {
    throw new Error('Invalid credential.type: expected "public-key"');
  }

  const { id, rawId, response, authenticatorAttachment } = cred as {
    id?: unknown;
    rawId?: unknown;
    response?: unknown;
    authenticatorAttachment?: unknown;
  };

  // Core field/type validation (serialized shapes should be base64url strings)
  assertString(id, 'credential.id');
  assertString(rawId, 'credential.rawId');

  if (!isObject(response)) {
    throw new Error('Invalid credential.response: expected object');
  }

  const { clientDataJSON, attestationObject, transports } = response as {
    clientDataJSON?: unknown;
    attestationObject?: unknown;
    transports?: unknown;
  };

  assertString(clientDataJSON, 'credential.response.clientDataJSON');
  assertString(attestationObject, 'credential.response.attestationObject');

  if (!Array.isArray(transports)) {
    throw new Error('Invalid credential.response.transports: expected string[]');
  }
  for (const t of transports) {
    if (typeof t !== 'string') {
      throw new Error('Invalid credential.response.transports item: expected string');
    }
  }

  if (authenticatorAttachment != null && typeof authenticatorAttachment !== 'string') {
    throw new Error('Invalid credential.authenticatorAttachment: expected string | undefined');
  }

  // Note: prf.results may be undefined/null here. We intentionally do NOT
  // require them at the boundary; internal callers that need PRF (e.g. key
  // derivation) will extract/compute them separately. Protocol payloads must
  // not include PRF values.
  return cred;
}

export function parseAndValidateRegistrationCredentialConfirmationPayload(
  payload: unknown,
): RegistrationCredentialConfirmationPayload {
  if (!isObject(payload)) {
    throw new Error('Invalid response payload: expected object');
  }

  const {
    confirmed,
    requestId,
    intentDigest,
    credential,
    transactionContext,
    registrationDiagnostics,
    error,
  } = payload as {
    confirmed?: unknown;
    requestId?: unknown;
    intentDigest?: unknown;
    credential?: unknown;
    transactionContext?: unknown;
    registrationDiagnostics?: unknown;
    error?: unknown;
  };

  const normalizedRequestId = assertString(requestId, 'requestId');

  // intentDigest is only used for TX signing requests, not registration or link device requests
  const normalizedIntentDigest =
    intentDigest == null ? '' : assertString(intentDigest, 'intentDigest');

  const normalizedCredential = credential != null ? validateCredentialMaybe(credential) : undefined;

  if (!normalizedCredential) {
    throw new Error('Missing registration credential');
  }

  const normalizedTransactionContext =
    transactionContext != null ? validateTransactionContextMaybe(transactionContext) : undefined;
  const normalizedRegistrationDiagnostics = sanitizeRegistrationConfirmationDiagnosticsMaybe(
    registrationDiagnostics,
  );

  const normalizedError = error == null ? undefined : assertString(error, 'error');

  return {
    confirmed: !!confirmed,
    requestId: normalizedRequestId,
    intentDigest: normalizedIntentDigest,
    credential: normalizedCredential,
    ...(normalizedTransactionContext ? { transactionContext: normalizedTransactionContext } : {}),
    ...(normalizedRegistrationDiagnostics
      ? { registrationDiagnostics: normalizedRegistrationDiagnostics }
      : {}),
    ...(normalizedError != null ? { error: normalizedError } : {}),
  };
}
