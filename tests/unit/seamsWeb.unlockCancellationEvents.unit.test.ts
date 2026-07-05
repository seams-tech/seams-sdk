import { expect, test } from '@playwright/test';
import { unlock } from '@/SeamsWeb/operations/auth/login';
import {
  resolveNearAccountIdForWalletAuthUnlockRecord,
  resolveNearEd25519WalletUnlockSubject,
} from '@/SeamsWeb/operations/auth/walletAuth';
import { SeamsWeb } from '@/SeamsWeb';
import { IndexedDBManager } from '@/core/indexedDB';
import { createUnlockFlowEvent, UnlockEventPhase } from '@/core/types/sdkSentEvents';
import { toAccountId } from '@/core/types/accountIds';
import {
  clearStoredThresholdEd25519SessionRecordForLaneKey,
  getStoredThresholdEd25519SessionRecordForAccount,
  thresholdEd25519SessionRecordKeyFromRecord,
  upsertThresholdEd25519SessionFact,
} from '@/core/signingEngine/session/persistence/records';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';

const UNLOCK_NEAR_ACCOUNT_ID = toAccountId('alice.testnet');
const UNLOCK_WALLET_ID = 'frost-unlock-k7p9m2';
const UNLOCK_NEAR_ED25519_SIGNING_KEY_ID = 'near-ed25519-unlock-k7p9m2';

function seedUnlockPasskeyWalletBinding(): void {
  upsertThresholdEd25519SessionFact({
    walletId: UNLOCK_WALLET_ID,
    nearAccountId: UNLOCK_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: UNLOCK_NEAR_ED25519_SIGNING_KEY_ID,
    rpId: 'localhost',
    passkeyCredentialIdB64u: 'cred-1',
    relayerUrl: 'https://relay.example',
    relayerKeyId: 'rk-1',
    participantIds: [1, 2],
    signerSlot: 1,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'tsess-unlock-binding',
    signingGrantId: 'grant-unlock-binding',
    walletSessionJwt: 'jwt-unlock-binding',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 1,
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: 'signing-worker-test',
    },
    source: 'login',
  });
}

function clearUnlockPasskeyWalletBinding(): void {
  const record = getStoredThresholdEd25519SessionRecordForAccount(UNLOCK_NEAR_ACCOUNT_ID);
  const laneKey = record ? thresholdEd25519SessionRecordKeyFromRecord(record) : null;
  if (laneKey) clearStoredThresholdEd25519SessionRecordForLaneKey(laneKey);
}

test.describe('SeamsWeb unlock cancellation events', () => {
  test('wallet-auth unlock resolves NEAR binding from stored wallet Ed25519 lane', () => {
    seedUnlockPasskeyWalletBinding();
    try {
      expect(resolveNearAccountIdForWalletAuthUnlockRecord(UNLOCK_WALLET_ID)).toBe(
        UNLOCK_NEAR_ACCOUNT_ID,
      );
    } finally {
      clearUnlockPasskeyWalletBinding();
    }
  });

  test('wallet-auth unlock resolves NEAR binding from durable wallet signer metadata', async () => {
    const originalListActiveWalletSigners = IndexedDBManager.listActiveWalletSigners;
    IndexedDBManager.listActiveWalletSigners = async (args: {
      walletId: string;
      signerFamily: 'ed25519' | 'ecdsa';
    }) => {
      if (args.signerFamily !== 'ed25519') return [];
      return [
        {
          profileId: UNLOCK_WALLET_ID,
          chainIdKey: '__wallet_subject__',
          accountAddress: UNLOCK_WALLET_ID,
          signerId: 'ed25519:unlock',
          signerSlot: 1,
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          status: 'active',
          addedAt: Date.now(),
          updatedAt: Date.now(),
          metadata: {
            walletId: UNLOCK_WALLET_ID,
            nearAccountId: UNLOCK_NEAR_ACCOUNT_ID,
            nearEd25519SigningKeyId: UNLOCK_NEAR_ED25519_SIGNING_KEY_ID,
          },
        },
      ] as any;
    };
    try {
      const subject = await resolveNearEd25519WalletUnlockSubject(UNLOCK_WALLET_ID);
      expect(subject?.nearAccountId).toBe(UNLOCK_NEAR_ACCOUNT_ID);
      expect(subject?.nearEd25519SigningKeyId).toBe(UNLOCK_NEAR_ED25519_SIGNING_KEY_ID);
      expect(subject?.signerSlot).toBe(1);
    } finally {
      IndexedDBManager.listActiveWalletSigners = originalListActiveWalletSigners;
    }
  });

  test('passkey unlock emits unlock.cancelled for WebAuthn cancellation errors', async () => {
    const events: any[] = [];
    const afterCalls: any[] = [];
    const onErrors: string[] = [];
    const cancellation = new Error('The operation either timed out or was not allowed');
    cancellation.name = 'NotAllowedError';

    seedUnlockPasskeyWalletBinding();
    try {
      const result = await unlock(
        {
          signingEngine: {
            assertSealedRefreshStartupParity: async () => undefined,
            getLastUser: async () => ({
              nearAccountId: 'alice.testnet',
              signerSlot: 1,
              operationalPublicKey: 'ed25519:alice',
              authMethod: 'passkey',
            }),
            nearAuthenticatorsByAccount: async () => [{ credentialId: 'cred-1', signerSlot: 1 }],
            getAuthenticationCredentialsSerialized: async () => {
              throw cancellation;
            },
          },
        } as any,
        UNLOCK_NEAR_ACCOUNT_ID,
        {
          onEvent: (event: any) => events.push(event),
          onError: (error: Error) => onErrors.push(error.message),
          afterCall: async (ok: boolean) => afterCalls.push(ok),
        } as any,
      );

      expect(result).toEqual({
        success: false,
        error: "Login was cancelled. Please try again when you're ready to authenticate.",
      });
      expect(events.map((event) => event.phase)).toEqual([
        UnlockEventPhase.STEP_01_STARTED,
        UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_STARTED,
        UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_SUCCEEDED,
        UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SKIPPED,
        UnlockEventPhase.STEP_03_PASSKEY_PROMPT_STARTED,
        UnlockEventPhase.CANCELLED,
      ]);
      expect(events.map((event) => event.status)).toEqual([
        'started',
        'running',
        'succeeded',
        'skipped',
        'waiting_for_user',
        'cancelled',
      ]);
      expect(events[5]).toMatchObject({
        flow: 'unlock',
        phase: 'unlock.cancelled',
        step: 0,
        message: 'Wallet unlock cancelled',
        interaction: { kind: 'passkey_assert', overlay: 'hide' },
        error: {
          message: "Login was cancelled. Please try again when you're ready to authenticate.",
        },
      });
      expect(getStoredThresholdEd25519SessionRecordForAccount(UNLOCK_NEAR_ACCOUNT_ID)).toMatchObject({
        walletId: UNLOCK_WALLET_ID,
        nearAccountId: UNLOCK_NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: UNLOCK_NEAR_ED25519_SIGNING_KEY_ID,
      });
      expect(afterCalls).toEqual([false]);
      expect(onErrors).toEqual(['The operation either timed out or was not allowed']);
    } finally {
      clearUnlockPasskeyWalletBinding();
    }
  });

  test('passkey prompt is not blocked by slow sealed-refresh parity check', async () => {
    const events: any[] = [];
    let promptStarted = false;
    seedUnlockPasskeyWalletBinding();
    try {
      const result = await unlock(
        {
          signingEngine: {
            assertSealedRefreshStartupParity: async () => {
              await new Promise(() => undefined);
            },
            getLastUser: async () => ({
              nearAccountId: 'alice.testnet',
              signerSlot: 1,
              operationalPublicKey: 'ed25519:alice',
              authMethod: 'passkey',
            }),
            nearAuthenticatorsByAccount: async () => [{ credentialId: 'cred-1', signerSlot: 1 }],
            getAuthenticationCredentialsSerialized: async () => {
              promptStarted = true;
              return {
                id: 'cred-1',
                rawId: 'cred-1',
                type: 'public-key',
                response: {
                  clientDataJSON: 'client-data-json',
                  authenticatorData: 'authenticator-data',
                  signature: 'signature',
                },
                clientExtensionResults: {},
              };
            },
            setLastUser: async () => undefined,
            updateLastLogin: async () => undefined,
            getNonceCoordinator: () => ({
              recoverDurableLeases: async () => undefined,
            }),
          },
        } as any,
        UNLOCK_NEAR_ACCOUNT_ID,
        {
          onEvent: (event: any) => events.push(event),
        } as any,
      );

      expect(promptStarted).toBe(true);
      expect(result.success).toBe(true);
      expect(events.map((event) => event.phase)).toContain(
        UnlockEventPhase.STEP_03_PASSKEY_PROMPT_STARTED,
      );
      expect(events.map((event) => event.phase)).toContain(UnlockEventPhase.STEP_07_COMPLETED);
    } finally {
      clearUnlockPasskeyWalletBinding();
    }
  });

  test('Email OTP unlock failure helper emits unlock.cancelled for cancellation errors', () => {
    const events: any[] = [];
    const cancellation = Object.assign(new Error('User cancelled Email OTP unlock'), {
      code: 'cancelled',
    });
    const harness = {
      emitEmailOtpUnlockEvent: (
        onEvent: ((event: unknown) => void) | undefined,
        input: Parameters<typeof createUnlockFlowEvent>[0],
      ) => {
        onEvent?.(createUnlockFlowEvent(input));
      },
    };

    (SeamsWeb.prototype as any).emitEmailOtpUnlockFailure.call(
      harness,
      (event: any) => events.push(event),
      {
        flowId: 'email-otp-unlock:alice.testnet:challenge-1',
        accountId: 'alice.testnet',
        authMethod: 'email_otp',
        requestId: 'challenge-1',
        error: cancellation,
      },
    );

    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      flow: 'unlock',
      phase: 'unlock.cancelled',
      status: 'cancelled',
      step: 0,
      message: 'Wallet unlock cancelled',
      authMethod: 'email_otp',
      requestId: 'challenge-1',
      interaction: { kind: 'otp_input', overlay: 'hide' },
      error: { message: 'User cancelled Email OTP unlock' },
    });
  });
});
