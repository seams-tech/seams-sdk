import { buildThresholdEd25519Participants2pV1 } from '@shared/threshold/participants';
import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceManager } from '@/core/rpcClients/near/nonceManager';
import { hasAccessKey } from '@/core/rpcClients/near/rpcCalls';
import { ActionType, type ActionArgsWasm, type TransactionInputWasm } from '@/core/types/actions';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { DEFAULT_WAIT_STATUS } from '@/core/types/rpc';
import type {
  ConfirmationConfig,
  RpcCallPayload,
  SignerMode,
} from '@/core/types/signer-worker';
import type { SignTransactionResult } from '@/core/types/tatchi';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types/webauthn';
import { computeThresholdEd25519KeygenIntentDigest } from '@/utils/intentDigest';
import {
  activateNearThresholdKeyNoPrompt,
  activateThresholdKeyForChain,
} from '../../orchestration/thresholdActivation';
import { enrollEd25519KeyHandler } from '../../threshold/workflows/enrollEd25519Key';
import { rotateEd25519KeyPostRegistrationHandler } from '../../threshold/workflows/rotateEd25519KeyPostRegistration';
import { collectAuthenticationCredentialForChallengeB64u } from '../../signers/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u';
import { getPrfResultsFromCredential } from '../../signers/webauthn/credentials/credentialExtensions';
import { getLastLoggedInDeviceNumber } from '../../signers/webauthn/device/getDeviceNumber';
import type { TouchIdPrompt } from '../../signers/webauthn/prompt/touchIdPrompt';
import type { SignerWorkerManagerContext } from '../../workerManager';
import type { NearSigningKeyOps } from '../../interfaces/nearKeyOps';

const DUMMY_WRAP_KEY_SALT_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

type SignTransactionsWithActionsInput = {
  transactions: TransactionInputWasm[];
  rpcCall: RpcCallPayload;
  signerMode: SignerMode;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  deviceNumber?: number;
};

export type ThresholdEd25519LifecycleDeps = {
  indexedDB: UnifiedIndexedDBManager;
  touchIdPrompt: Pick<TouchIdPrompt, 'getRpId' | 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
  signingKeyOps: Pick<NearSigningKeyOps, 'deriveThresholdEd25519ClientVerifyingShare'>;
  getSignerWorkerRequestOperation: () => SignerWorkerManagerContext['requestWorkerOperation'];
  createSessionId: (prefix: string) => string;
  nearClient: NearClient;
  nonceManager: Pick<NonceManager, 'initializeUser' | 'getNonceBlockHashAndHeight'>;
  relayerUrl: string;
  nearRpcUrl: string;
  signTransactionsWithActions: (
    args: SignTransactionsWithActionsInput,
  ) => Promise<SignTransactionResult[]>;
};

export type DeriveThresholdEd25519ClientVerifyingShareResult = {
  success: boolean;
  nearAccountId: string;
  clientVerifyingShareB64u: string;
  error?: string;
};

export type EnrollThresholdEd25519KeyResult = {
  success: boolean;
  publicKey: string;
  relayerKeyId: string;
  error?: string;
};

export type RotateThresholdEd25519KeyPostRegistrationResult = {
  success: boolean;
  oldPublicKey: string;
  oldRelayerKeyId: string;
  publicKey: string;
  relayerKeyId: string;
  deleteOldKeyAttempted: boolean;
  deleteOldKeySuccess: boolean;
  warning?: string;
  error?: string;
};

function requirePrfFirstB64uFromCredential(
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential,
): string {
  const value = getPrfResultsFromCredential(credential).first;
  if (!value) {
    throw new Error('Missing PRF.first output from credential (requires a PRF-enabled passkey)');
  }
  return value;
}

function isWebAuthnAuthenticationCredential(
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential,
): credential is WebAuthnAuthenticationCredential {
  return !!credential && 'authenticatorData' in credential.response;
}

async function resolveDeviceNumber(args: {
  indexedDB: UnifiedIndexedDBManager;
  nearAccountId: AccountId;
  deviceNumber?: number;
}): Promise<number> {
  const numeric = Number(args.deviceNumber);
  if (Number.isSafeInteger(numeric) && numeric >= 1) {
    return numeric;
  }
  return await getLastLoggedInDeviceNumber(args.nearAccountId, args.indexedDB.clientDB);
}

export async function deriveThresholdEd25519ClientVerifyingShareFromCredential(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId | string;
  },
): Promise<DeriveThresholdEd25519ClientVerifyingShareResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  try {
    const prfFirstB64u = requirePrfFirstB64uFromCredential(args.credential);
    const sessionId = deps.createSessionId('threshold-client-share');
    return await deps.signingKeyOps.deriveThresholdEd25519ClientVerifyingShare({
      sessionId,
      nearAccountId,
      prfFirstB64u,
      wrapKeySalt: DUMMY_WRAP_KEY_SALT_B64U,
    });
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      nearAccountId,
      clientVerifyingShareB64u: '',
      error: message,
    };
  }
}

export async function enrollThresholdEd25519KeyPostRegistration(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    nearAccountId: AccountId | string;
    deviceNumber?: number;
  },
): Promise<EnrollThresholdEd25519KeyResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  try {
    const rpId = deps.touchIdPrompt.getRpId();
    if (!rpId) throw new Error('Missing rpId for WebAuthn keygen challenge');

    const keygenSessionId = deps.createSessionId('threshold-keygen');
    const challengeB64u = await computeThresholdEd25519KeygenIntentDigest({
      nearAccountId,
      rpId,
      keygenSessionId,
    });

    const authCredential = await collectAuthenticationCredentialForChallengeB64u({
      indexedDB: deps.indexedDB,
      touchIdPrompt: deps.touchIdPrompt,
      nearAccountId,
      challengeB64u,
    });

    return await enrollThresholdEd25519Key(deps, {
      credential: authCredential,
      nearAccountId,
      deviceNumber: args.deviceNumber,
      keygenSessionId,
    });
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return { success: false, publicKey: '', relayerKeyId: '', error: message };
  }
}

export async function rotateThresholdEd25519KeyPostRegistration(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    nearAccountId: AccountId | string;
    deviceNumber?: number;
  },
): Promise<RotateThresholdEd25519KeyPostRegistrationResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  let oldPublicKey = '';
  let oldRelayerKeyId = '';

  try {
    const resolvedDeviceNumber = await resolveDeviceNumber({
      indexedDB: deps.indexedDB,
      nearAccountId,
      deviceNumber: args.deviceNumber,
    });

    const existing = await deps.indexedDB.getNearThresholdKeyMaterial(
      nearAccountId,
      resolvedDeviceNumber,
    );
    if (!existing) {
      throw new Error(
        `No threshold key material found for account ${nearAccountId} device ${resolvedDeviceNumber}. Call enrollThresholdEd25519Key() first.`,
      );
    }
    oldPublicKey = existing.publicKey;
    oldRelayerKeyId = existing.relayerKeyId;

    const enrollment = await enrollThresholdEd25519KeyPostRegistration(deps, {
      nearAccountId,
      deviceNumber: resolvedDeviceNumber,
    });
    if (!enrollment.success) {
      throw new Error(enrollment.error || 'Threshold keygen/enrollment failed');
    }

    return await rotateEd25519KeyPostRegistrationHandler(
      {
        nearClient: deps.nearClient,
        nearRpcUrl: deps.nearRpcUrl,
        signTransactionsWithActions: (params) => deps.signTransactionsWithActions(params),
      },
      {
        nearAccountId,
        deviceNumber: resolvedDeviceNumber,
        oldPublicKey,
        oldRelayerKeyId,
        newPublicKey: enrollment.publicKey,
        newRelayerKeyId: enrollment.relayerKeyId,
      },
    );
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      oldPublicKey,
      oldRelayerKeyId,
      publicKey: '',
      relayerKeyId: '',
      deleteOldKeyAttempted: false,
      deleteOldKeySuccess: false,
      error: message,
    };
  }
}

export async function enrollThresholdEd25519Key(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId | string;
    deviceNumber?: number;
    keygenSessionId?: string;
  },
): Promise<EnrollThresholdEd25519KeyResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const relayerUrl = deps.relayerUrl;

  try {
    if (!relayerUrl) throw new Error('Missing relayer url (configs.relayer.url)');
    if (!args.credential) throw new Error('Missing credential');

    const resolvedDeviceNumber = await resolveDeviceNumber({
      indexedDB: deps.indexedDB,
      nearAccountId,
      deviceNumber: args.deviceNumber,
    });

    const keygenSessionId = String(args.keygenSessionId || '').trim() || undefined;
    const sessionId = keygenSessionId || deps.createSessionId('threshold-keygen');
    const prfFirstB64u = requirePrfFirstB64uFromCredential(args.credential);
    if (!isWebAuthnAuthenticationCredential(args.credential)) {
      throw new Error('Authentication credential required for threshold keygen');
    }
    const webauthnAuthentication: WebAuthnAuthenticationCredential = args.credential;
    const keygen = await enrollEd25519KeyHandler(
      {
        signingKeyOps: deps.signingKeyOps,
        touchIdPrompt: deps.touchIdPrompt,
        relayerUrl,
      },
      {
        sessionId,
        keygenSessionId,
        nearAccountId,
        prfFirstB64u,
        wrapKeySalt: DUMMY_WRAP_KEY_SALT_B64U,
        webauthnAuthentication,
      },
    );

    if (!keygen.success) {
      throw new Error(keygen.error || 'Threshold keygen failed');
    }

    const publicKey = keygen.publicKey;
    const clientVerifyingShareB64u = keygen.clientVerifyingShareB64u;
    const relayerKeyId = keygen.relayerKeyId;
    const relayerVerifyingShareB64u = keygen.relayerVerifyingShareB64u;
    if (!clientVerifyingShareB64u) {
      throw new Error('Threshold keygen returned empty clientVerifyingShareB64u');
    }

    const alreadyActive = await hasAccessKey(deps.nearClient, nearAccountId, publicKey, {
      attempts: 1,
      delayMs: 0,
    });
    if (!alreadyActive) {
      const localKeyMaterial = await deps.indexedDB.getNearLocalKeyMaterial(
        nearAccountId,
        resolvedDeviceNumber,
      );
      if (localKeyMaterial) {
        deps.nonceManager.initializeUser(nearAccountId, localKeyMaterial.publicKey);
        const txContext = await deps.nonceManager.getNonceBlockHashAndHeight(deps.nearClient, {
          force: true,
        });
        const requestWorkerOperation = deps.getSignerWorkerRequestOperation();
        const signed = await activateThresholdKeyForChain({
          chain: 'near',
          adapters: {
            near: (request) =>
              activateNearThresholdKeyNoPrompt(
                {
                  requestWorkerOperation,
                  createSessionId: deps.createSessionId,
                },
                request,
              ),
          },
          request: {
            nearAccountId,
            credential: args.credential,
            wrapKeySalt: localKeyMaterial.wrapKeySalt,
            transactionContext: txContext,
            thresholdPublicKey: publicKey,
            relayerVerifyingShareB64u,
            clientParticipantId: keygen.clientParticipantId,
            relayerParticipantId: keygen.relayerParticipantId,
            deviceNumber: resolvedDeviceNumber,
          },
        });

        const signedTx = signed?.signedTransaction;
        if (!signedTx) throw new Error('Failed to sign AddKey(thresholdPublicKey) transaction');
        await deps.nearClient.sendTransaction(signedTx, DEFAULT_WAIT_STATUS.thresholdAddKey);
      } else {
        const existingThresholdKeyMaterial = await deps.indexedDB.getNearThresholdKeyMaterial(
          nearAccountId,
          resolvedDeviceNumber,
        );
        if (!existingThresholdKeyMaterial) {
          throw new Error(
            `No local key material found for account ${nearAccountId} device ${resolvedDeviceNumber} and no existing threshold key material is available for threshold-signer activation`,
          );
        }

        const addKeyAction: ActionArgsWasm = {
          action_type: ActionType.AddKey,
          public_key: publicKey,
          access_key: JSON.stringify({
            nonce: 0,
            permission: { FullAccess: {} },
          }),
        };
        const signed = await deps.signTransactionsWithActions({
          transactions: [{ receiverId: nearAccountId, actions: [addKeyAction] }],
          rpcCall: {
            nearRpcUrl: deps.nearRpcUrl,
            nearAccountId,
          },
          deviceNumber: resolvedDeviceNumber,
          signerMode: { mode: 'threshold-signer', behavior: 'strict' },
          confirmationConfigOverride: {
            uiMode: 'none',
            behavior: 'skipClick',
            autoProceedDelay: 0,
          },
          title: 'Activate threshold key',
          body: 'Confirm adding the new threshold access key.',
        });
        const signedTx = signed?.[0]?.signedTransaction;
        if (!signedTx) throw new Error('Failed to sign AddKey(thresholdPublicKey) transaction');
        await deps.nearClient.sendTransaction(signedTx, DEFAULT_WAIT_STATUS.thresholdAddKey);
      }

      const activated = await hasAccessKey(deps.nearClient, nearAccountId, publicKey);
      if (!activated) throw new Error('Threshold access key not found on-chain after AddKey');
    }

    await deps.indexedDB.storeNearThresholdKeyMaterial({
      nearAccountId,
      deviceNumber: resolvedDeviceNumber,
      publicKey,
      relayerKeyId,
      clientShareDerivation: 'prf_first_v1',
      participants: buildThresholdEd25519Participants2pV1({
        clientParticipantId: keygen.clientParticipantId,
        relayerParticipantId: keygen.relayerParticipantId,
        relayerKeyId,
        relayerUrl,
        clientVerifyingShareB64u,
        relayerVerifyingShareB64u,
        clientShareDerivation: 'prf_first_v1',
      }),
      timestamp: Date.now(),
    });

    return {
      success: true,
      publicKey,
      relayerKeyId,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return { success: false, publicKey: '', relayerKeyId: '', error: message };
  }
}
