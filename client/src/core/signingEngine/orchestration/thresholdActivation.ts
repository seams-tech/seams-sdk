import { IndexedDBManager } from '@/core/indexedDB';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { toAccountId } from '@/core/types/accountIds';
import type { AccountId } from '@/core/types/accountIds';
import type { TransactionContext } from '@/core/types/rpc';
import type { onProgressEvents } from '@/core/types/sdkSentEvents';
import {
  INTERNAL_WORKER_REQUEST_TYPE_SIGN_ADD_KEY_THRESHOLD_PUBLIC_KEY_NO_PROMPT,
  isSignAddKeyThresholdPublicKeyNoPromptSuccess,
} from '@/core/types/signer-worker';
import type { SignTransactionResult } from '@/core/types/tatchi';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types/webauthn';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import { getPrfFirstB64uFromCredential } from '@/core/signingEngine/signers/webauthn/credentials/credentialExtensions';
import { getLastLoggedInDeviceNumber } from '@/core/signingEngine/signers/webauthn/device/getDeviceNumber';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  ThresholdIndexedDbPort,
  ThresholdPrfFirstCachePort,
  ThresholdWebAuthnPromptPort,
} from '@/core/signingEngine/threshold/webauthn';
import { bootstrapEcdsaSession } from '@/core/signingEngine/threshold/workflows/bootstrapEcdsaSession';
import type { connectEcdsaSession } from '@/core/signingEngine/threshold/workflows/connectEcdsaSession';
import type { keygenEcdsa } from '@/core/signingEngine/threshold/workflows/keygenEcdsa';
import type { SignerWorkerManagerContext } from '@/core/signingEngine/workerManager';
import { ensureEd25519Prefix } from '@shared/utils/validation';

export type ThresholdKeyActivationChain = 'near' | 'evm' | 'tempo';

export type ThresholdKeyActivationAdapter<Request = unknown, Result = unknown> = (
  request: Request,
) => Promise<Result>;

export type ThresholdKeyActivationAdapterMap = Partial<
  Record<ThresholdKeyActivationChain, ThresholdKeyActivationAdapter<unknown, unknown>>
>;

export type ThresholdKeyActivationAdaptersForChain<
  Chain extends ThresholdKeyActivationChain,
  Request,
  Result,
> = Record<Chain, ThresholdKeyActivationAdapter<Request, Result>>
  & Partial<
    Record<
      Exclude<ThresholdKeyActivationChain, Chain>,
      ThresholdKeyActivationAdapter<unknown, unknown>
    >
  >;

export async function activateThresholdKeyForChain<
  Chain extends ThresholdKeyActivationChain,
  Request,
  Result,
>(args: {
  chain: Chain;
  request: Request;
  adapters: ThresholdKeyActivationAdaptersForChain<Chain, Request, Result>;
}): Promise<Result> {
  const adapter = args.adapters[args.chain];
  if (typeof adapter !== 'function') {
    throw new Error(`[activation] missing threshold-key activation adapter for chain: ${args.chain}`);
  }

  return await (adapter as ThresholdKeyActivationAdapter<Request, Result>)(args.request);
}

export type ThresholdEcdsaActivationChain = 'evm' | 'tempo';

export type EcdsaKeygenResult = Awaited<ReturnType<typeof keygenEcdsa>>;
export type EcdsaSessionResult = Awaited<ReturnType<typeof connectEcdsaSession>>;
export type EcdsaKeygenSuccess = EcdsaKeygenResult & { ok: true };
export type EcdsaSessionSuccess = EcdsaSessionResult & { ok: true };

export type ThresholdEcdsaSessionBootstrapResult = {
  thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
  keygen: EcdsaKeygenSuccess;
  session: EcdsaSessionSuccess;
};

export type ActivateEcdsaSessionDeps = {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  prfFirstCache: ThresholdPrfFirstCachePort;
  workerCtx: WorkerOperationContext;
  getOrCreateActiveSigningSessionId: (nearAccountId: AccountId) => string;
};

export type ActivateEcdsaSessionRequest = {
  nearAccountId: AccountId | string;
  relayerUrl: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  ttlMs?: number;
  remainingUses?: number;
};

export async function activateEcdsaSession(
  deps: ActivateEcdsaSessionDeps,
  args: ActivateEcdsaSessionRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const nearAccountId = toAccountId(args.nearAccountId);

  const bootstrap = await bootstrapEcdsaSession({
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    prfFirstCache: deps.prfFirstCache,
    relayerUrl: args.relayerUrl,
    userId: nearAccountId,
    participantIds: args.participantIds,
    sessionKind: args.sessionKind,
    sessionId: deps.getOrCreateActiveSigningSessionId(nearAccountId),
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    workerCtx: deps.workerCtx,
  });
  if (!bootstrap.ok) {
    throw new Error(bootstrap.message || bootstrap.code || 'threshold-ecdsa bootstrap failed');
  }

  const relayerKeyId = String(bootstrap.relayerKeyId || '').trim();
  if (!relayerKeyId) {
    throw new Error('threshold-ecdsa bootstrap returned empty relayerKeyId');
  }

  const clientVerifyingShareB64u = String(bootstrap.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('threshold-ecdsa bootstrap returned empty clientVerifyingShareB64u');
  }

  const sessionId = String(bootstrap.sessionId || '').trim();
  if (!sessionId) {
    throw new Error('threshold-ecdsa bootstrap returned empty sessionId');
  }

  const keygen: EcdsaKeygenSuccess = {
    ok: true,
    keygenSessionId: bootstrap.keygenSessionId,
    rpId: bootstrap.rpId,
    clientVerifyingShareB64u,
    relayerKeyId,
    groupPublicKeyB64u: bootstrap.groupPublicKeyB64u,
    ethereumAddress: bootstrap.ethereumAddress,
    relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
    participantIds: bootstrap.participantIds,
    ...(typeof bootstrap.chainId === 'string' ? { chainId: bootstrap.chainId } : {}),
    ...(typeof bootstrap.factory === 'string' ? { factory: bootstrap.factory } : {}),
    ...(typeof bootstrap.entryPoint === 'string' ? { entryPoint: bootstrap.entryPoint } : {}),
    ...(typeof bootstrap.salt === 'string' ? { salt: bootstrap.salt } : {}),
    ...(typeof bootstrap.counterfactualAddress === 'string'
      ? { counterfactualAddress: bootstrap.counterfactualAddress }
      : {}),
    ...(bootstrap.code ? { code: bootstrap.code } : {}),
    ...(bootstrap.message ? { message: bootstrap.message } : {}),
  };

  const session: EcdsaSessionSuccess = {
    ok: true,
    sessionId,
    expiresAtMs: bootstrap.expiresAtMs,
    remainingUses: bootstrap.remainingUses,
    jwt: bootstrap.jwt,
    clientVerifyingShareB64u,
    ...(bootstrap.code ? { code: bootstrap.code } : {}),
    ...(bootstrap.message ? { message: bootstrap.message } : {}),
  };

  const thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: nearAccountId,
    relayerUrl: args.relayerUrl,
    relayerKeyId,
    clientVerifyingShareB64u,
    ...(Array.isArray(args.participantIds)
      ? { participantIds: args.participantIds }
      : Array.isArray(bootstrap.participantIds)
        ? { participantIds: bootstrap.participantIds }
        : {}),
    ...(typeof bootstrap.groupPublicKeyB64u === 'string' && bootstrap.groupPublicKeyB64u.trim()
      ? { groupPublicKeyB64u: bootstrap.groupPublicKeyB64u.trim() }
      : {}),
    ...(typeof bootstrap.relayerVerifyingShareB64u === 'string' &&
    bootstrap.relayerVerifyingShareB64u.trim()
      ? { relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u.trim() }
      : {}),
    thresholdSessionKind: args.sessionKind || 'jwt',
    thresholdSessionId: sessionId,
    ...(typeof session.jwt === 'string' && session.jwt.trim()
      ? { thresholdSessionJwt: session.jwt.trim() }
      : {}),
  };

  return {
    thresholdEcdsaKeyRef,
    keygen: keygen as EcdsaKeygenSuccess,
    session: session as EcdsaSessionSuccess,
  };
}

export async function activateEvmEcdsaSession(
  deps: ActivateEcdsaSessionDeps,
  args: ActivateEcdsaSessionRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await activateEcdsaSession(deps, args);
}

export async function activateTempoEcdsaSession(
  deps: ActivateEcdsaSessionDeps,
  args: ActivateEcdsaSessionRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await activateEcdsaSession(deps, args);
}

export type ActivateNearThresholdKeyNoPromptRequest = {
  nearAccountId: AccountId | string;
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
  wrapKeySalt: string;
  transactionContext: TransactionContext;
  thresholdPublicKey: string;
  relayerVerifyingShareB64u: string;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  deviceNumber?: number;
  onEvent?: (update: onProgressEvents) => void;
};

export type ActivateNearThresholdKeyNoPromptDeps = {
  requestWorkerOperation: SignerWorkerManagerContext['requestWorkerOperation'];
  createSessionId?: (prefix: string) => string;
};

type WorkerSignedTransaction = {
  transaction?: unknown;
  signature?: unknown;
  borshBytes?: ArrayLike<number> | null;
};

function defaultCreateSessionId(prefix: string): string {
  return typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export async function activateNearThresholdKeyNoPrompt(
  deps: ActivateNearThresholdKeyNoPromptDeps,
  args: ActivateNearThresholdKeyNoPromptRequest,
): Promise<SignTransactionResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const wrapKeySalt = args.wrapKeySalt;
  if (!wrapKeySalt) throw new Error('Missing wrapKeySalt for AddKey(thresholdPublicKey) signing');
  if (!args.credential) throw new Error('Missing credential for AddKey(thresholdPublicKey) signing');
  if (!args.transactionContext) throw new Error('Missing transactionContext for no-prompt signing');

  const thresholdPublicKey = ensureEd25519Prefix(args.thresholdPublicKey);
  if (!thresholdPublicKey) {
    throw new Error('Missing thresholdPublicKey for AddKey(thresholdPublicKey) signing');
  }

  const relayerVerifyingShareB64u = args.relayerVerifyingShareB64u;
  if (!relayerVerifyingShareB64u) {
    throw new Error('Missing relayerVerifyingShareB64u for AddKey(thresholdPublicKey) signing');
  }

  const deviceNumber = Number(args.deviceNumber);
  const resolvedDeviceNumber =
    Number.isSafeInteger(deviceNumber) && deviceNumber >= 1
      ? deviceNumber
      : await getLastLoggedInDeviceNumber(nearAccountId, IndexedDBManager.clientDB);

  const localKeyMaterial = await IndexedDBManager.getNearLocalKeyMaterial(
    nearAccountId,
    resolvedDeviceNumber,
  );
  if (!localKeyMaterial) {
    throw new Error(
      `No local key material found for account ${nearAccountId} device ${resolvedDeviceNumber}`,
    );
  }

  if (localKeyMaterial.wrapKeySalt !== wrapKeySalt) {
    throw new Error('wrapKeySalt mismatch for AddKey(thresholdPublicKey) signing');
  }

  const prfFirstB64u = getPrfFirstB64uFromCredential(args.credential);
  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output for AddKey(thresholdPublicKey) signing');
  }

  const sessionId = (deps.createSessionId || defaultCreateSessionId)('no-prompt-add-threshold-key');
  const response = await deps.requestWorkerOperation({
    kind: 'nearSigner',
    request: {
      sessionId,
      type: INTERNAL_WORKER_REQUEST_TYPE_SIGN_ADD_KEY_THRESHOLD_PUBLIC_KEY_NO_PROMPT,
      payload: {
        createdAt: Date.now(),
        decryption: {
          encryptedPrivateKeyData: localKeyMaterial.encryptedSk,
          encryptedPrivateKeyChacha20NonceB64u: localKeyMaterial.chacha20NonceB64u,
        },
        transactionContext: args.transactionContext,
        nearAccountId,
        thresholdPublicKey,
        relayerVerifyingShareB64u,
        clientParticipantId:
          typeof args.clientParticipantId === 'number' ? args.clientParticipantId : undefined,
        relayerParticipantId:
          typeof args.relayerParticipantId === 'number' ? args.relayerParticipantId : undefined,
        prfFirstB64u,
        wrapKeySalt,
      },
      onEvent: args.onEvent,
    },
  });

  if (!isSignAddKeyThresholdPublicKeyNoPromptSuccess(response)) {
    throw new Error('AddKey(thresholdPublicKey) signing failed');
  }
  if (!response.payload.success) {
    throw new Error(response.payload.error || 'AddKey(thresholdPublicKey) signing failed');
  }

  const signedTransactions = response.payload.signedTransactions || [];
  if (signedTransactions.length !== 1) {
    throw new Error(`Expected 1 signed transaction but received ${signedTransactions.length}`);
  }

  const signedTx = signedTransactions[0] as WorkerSignedTransaction | undefined;
  if (!signedTx?.transaction || !signedTx.signature) {
    throw new Error('Incomplete signed transaction data received for AddKey(thresholdPublicKey)');
  }

  return {
    signedTransaction: SignedTransaction.fromPlain({
      transaction: signedTx.transaction,
      signature: signedTx.signature,
      borsh_bytes: signedTx.borshBytes ? Array.from(signedTx.borshBytes) : [],
    }),
    nearAccountId: String(nearAccountId),
    logs: response.payload.logs || [],
  };
}
