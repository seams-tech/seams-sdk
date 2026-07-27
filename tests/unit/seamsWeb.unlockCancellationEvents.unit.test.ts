import { expect, test } from '@playwright/test';
import {
  resolveLoginUnlockWarmupBranchPlan,
  resolveLoginWalletUnlockSelectionForSubjectSet,
  unlock,
} from '@/SeamsWeb/operations/auth/login';
import { unlockDomain, type WalletAuthDomainDeps } from '@/SeamsWeb/operations/auth/walletAuth';
import {
  resolveNearEd25519WalletUnlockSubject,
  resolveWalletUnlockSubjectSet,
} from '@/SeamsWeb/operations/auth/walletUnlockSubject';
import { resolveEvmFamilyEcdsaWalletUnlockSubjectSet } from '@/SeamsWeb/operations/auth/walletUnlockEcdsaSubject';
import { SeamsWeb } from '@/SeamsWeb';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import { IndexedDBManager } from '@/core/indexedDB';
import { MinimalNearClient } from '@/core/rpcClients/near/NearClient';
import type { LoginWebContext } from '@/SeamsWeb/signingSurface/types';
import { createUnlockFlowEvent, UnlockEventPhase } from '@/core/types/sdkSentEvents';
import { toAccountId } from '@/core/types/accountIds';
import {
  clearStoredThresholdEd25519SessionRecordForLaneKey,
  getStoredThresholdEd25519SessionRecordForAccount,
  thresholdEd25519SessionRecordKeyFromRecord,
  upsertThresholdEd25519SessionFact,
} from '@/core/signingEngine/session/persistence/records';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { seedAccountSignerRecord } from './helpers/accountSignerRecord.fixtures';
import {
  walletUnlockPasskeyAuthenticatorFixture,
  walletUnlockPasskeyAuthMethodFixture,
  walletUnlockProfileFixture,
} from './helpers/walletUnlockProfile.fixtures';
import { nearPasskeyAccountProjectionFixture } from './helpers/nearAccountProjection.fixtures';

const UNLOCK_NEAR_ACCOUNT_ID = toAccountId('alice.testnet');
const UNLOCK_WALLET_ID = 'frost-unlock-k7p9m2';
const UNLOCK_NEAR_ED25519_SIGNING_KEY_ID = 'near-ed25519-unlock-k7p9m2';
const UNLOCK_ECDSA_THRESHOLD_KEY_ID = 'ecdsa-threshold-key-unlock-k7p9m2';

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

  test('ECDSA-only subject resolution reads no NEAR runtime or signer identity', async () => {
    const originalListActiveWalletSigners = IndexedDBManager.listActiveWalletSigners;
    let nearSignerQueries = 0;
    IndexedDBManager.listActiveWalletSigners = async (args: {
      walletId: string;
      signerFamily: 'ed25519' | 'ecdsa';
    }) => {
      if (args.signerFamily === 'ed25519') {
        nearSignerQueries += 1;
        throw new Error('ECDSA-only resolution must not query NEAR signer identity');
      }
      return [
        seedAccountSignerRecord({
          profileId: UNLOCK_WALLET_ID,
          metadata: {
            walletId: UNLOCK_WALLET_ID,
            ecdsaThresholdKeyId: UNLOCK_ECDSA_THRESHOLD_KEY_ID,
          },
        }),
      ];
    };
    try {
      seedUnlockPasskeyWalletBinding();
      const resolution = await resolveEvmFamilyEcdsaWalletUnlockSubjectSet(UNLOCK_WALLET_ID);

      expect(nearSignerQueries).toBe(0);
      expect(resolution).toEqual({
        kind: 'resolved',
        subjectSet: {
          kind: 'wallet_unlock_subject_set',
          walletId: UNLOCK_WALLET_ID,
          subjects: [
            {
              kind: 'evm_family_ecdsa_wallet',
              walletId: UNLOCK_WALLET_ID,
              ecdsaThresholdKeyId: UNLOCK_ECDSA_THRESHOLD_KEY_ID,
            },
          ],
        },
      });
      if (resolution.kind !== 'resolved') {
        throw new Error('test fixture requires an ECDSA subject set');
      }
      expect(
        resolveLoginWalletUnlockSelectionForSubjectSet({
          subjectSet: resolution.subjectSet,
          selection: undefined,
        }),
      ).toEqual({ mode: 'ecdsa_only', ecdsa: true });
      expect(
        resolveLoginUnlockWarmupBranchPlan({
          subjectSet: resolution.subjectSet,
          selection: { mode: 'ecdsa_only', ecdsa: true },
          hasConfiguredEcdsaTargets: true,
        }),
      ).toEqual({
        kind: 'evm_family_ecdsa_only',
        wantsEd25519Warmup: false,
        wantsEcdsaWarmup: true,
      });
    } finally {
      clearUnlockPasskeyWalletBinding();
      IndexedDBManager.listActiveWalletSigners = originalListActiveWalletSigners;
    }
  });

  test('ECDSA-only wallet-auth unlock uses wallet identity without NEAR reads or activation', async () => {
    const walletIdValue = `frost-ecdsa-only-${crypto.randomUUID()}`;
    const credentialId = `credential-${crypto.randomUUID()}`;
    const originalListActiveWalletSigners = IndexedDBManager.listActiveWalletSigners;
    const originalGetProfile = IndexedDBManager.getProfile;
    const originalListWalletPasskeyAuthenticators =
      IndexedDBManager.listWalletPasskeyAuthenticators;
    const originalListWalletAuthMethodsForWallet = IndexedDBManager.listWalletAuthMethodsForWallet;
    let nearReads = 0;
    let nearActivations = 0;
    let selectedWalletId = '';
    let promptSubjectId = '';

    IndexedDBManager.listActiveWalletSigners = async (args: {
      walletId: string;
      signerFamily: 'ed25519' | 'ecdsa';
    }) => {
      if (args.signerFamily === 'ed25519') {
        nearReads += 1;
        throw new Error('ECDSA-only unlock must not query NEAR signer identity');
      }
      return [
        seedAccountSignerRecord({
          profileId: walletIdValue,
          metadata: {
            walletId: walletIdValue,
            ecdsaThresholdKeyId: UNLOCK_ECDSA_THRESHOLD_KEY_ID,
          },
        }),
      ];
    };
    IndexedDBManager.getProfile = async () =>
      walletUnlockProfileFixture({ walletId: walletIdValue, signerSlot: 1 });
    IndexedDBManager.listWalletPasskeyAuthenticators = async () => [
      walletUnlockPasskeyAuthenticatorFixture({
        walletId: walletIdValue,
        signerSlot: 1,
        credentialId,
      }),
    ];
    IndexedDBManager.listWalletAuthMethodsForWallet = async () => [
      walletUnlockPasskeyAuthMethodFixture({
        walletId: walletIdValue,
        credentialId,
      }),
    ];
    try {
      const signingEngine = {
        assertSealedRefreshStartupParity: async () => undefined,
        getLastUser: async () => {
          nearReads += 1;
          throw new Error('ECDSA-only unlock must not read the last NEAR user');
        },
        getUserBySignerSlot: async () => {
          nearReads += 1;
          throw new Error('ECDSA-only unlock must not read a NEAR account projection');
        },
        nearAuthenticatorsByAccount: async () => {
          nearReads += 1;
          throw new Error('ECDSA-only unlock must not read NEAR authenticators');
        },
        getAuthenticationCredentialsSerialized: async (args: { subjectId: string }) => {
          promptSubjectId = args.subjectId;
          return {
            id: credentialId,
            rawId: credentialId,
            type: 'public-key',
            response: {
              clientDataJSON: 'client-data',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: null,
            },
            clientExtensionResults: {},
          };
        },
        setLastUser: async (resolvedWalletId: string) => {
          selectedWalletId = resolvedWalletId;
        },
        getNonceCoordinator: () => ({
          recoverDurableLeases: async () => undefined,
          clearAll: () => undefined,
        }),
        clearVolatileWarmSigningMaterial: async () => undefined,
        activateAuthenticatedWalletState: async () => {
          nearActivations += 1;
          throw new Error('ECDSA-only unlock must not activate NEAR wallet state');
        },
      };
      const typedSigningEngine = signingEngine as unknown as LoginWebContext['signingEngine'] &
        WalletAuthDomainDeps['signingEngine'];
      const nearClient = new MinimalNearClient('https://rpc.testnet.near.org');
      const configs = buildConfigsFromEnv({
        relayer: { url: 'https://relay.example' },
        iframeWallet: { walletOrigin: 'https://wallet.example.test' },
        signingSessionDefaults: { ttlMs: 0, remainingUses: 0 },
      });
      const context: LoginWebContext = {
        signingEngine: typedSigningEngine,
        nearClient,
        configs,
        theme: 'dark',
      };
      const deps: WalletAuthDomainDeps = {
        getContext: () => context,
        walletIframe: {
          shouldUseWalletIframe: () => false,
          requireRouter: async () => {
            throw new Error('direct wallet-auth test must not require an iframe router');
          },
        },
        signingEngine: typedSigningEngine,
        nearClient,
        initWalletIframe: async () => ({ kind: 'wallet_locked' }),
      };
      const result = await unlockDomain(deps, walletIdValue, {
        unlockSelection: { mode: 'ecdsa_only', ecdsa: true },
        signingSession: { ttlMs: 0, remainingUses: 0 },
      });

      expect(result).toEqual({
        success: true,
        kind: 'ecdsa_wallet_unlocked',
        walletId: walletIdValue,
      });
      expect(nearReads).toBe(0);
      expect(nearActivations).toBe(0);
      expect(promptSubjectId).toBe(walletIdValue);
      expect(selectedWalletId).toBe(walletIdValue);
    } finally {
      IndexedDBManager.listActiveWalletSigners = originalListActiveWalletSigners;
      IndexedDBManager.getProfile = originalGetProfile;
      IndexedDBManager.listWalletPasskeyAuthenticators = originalListWalletPasskeyAuthenticators;
      IndexedDBManager.listWalletAuthMethodsForWallet = originalListWalletAuthMethodsForWallet;
    }
  });

  test('all-registered subject resolution returns NEAR and ECDSA branches', async () => {
    const originalListActiveWalletSigners = IndexedDBManager.listActiveWalletSigners;
    IndexedDBManager.listActiveWalletSigners = async (args: {
      walletId: string;
      signerFamily: 'ed25519' | 'ecdsa';
    }) => {
      if (args.signerFamily === 'ed25519') return [];
      return [
        seedAccountSignerRecord({
          profileId: UNLOCK_WALLET_ID,
          metadata: {
            walletId: UNLOCK_WALLET_ID,
            ecdsaThresholdKeyId: UNLOCK_ECDSA_THRESHOLD_KEY_ID,
          },
        }),
      ];
    };
    try {
      seedUnlockPasskeyWalletBinding();
      const resolution = await resolveWalletUnlockSubjectSet({
        walletId: UNLOCK_WALLET_ID,
        requestedCapabilityFamilies: { kind: 'all_registered_mpc' },
      });

      expect(resolution).toEqual({
        kind: 'resolved',
        subjectSet: {
          kind: 'wallet_unlock_subject_set',
          walletId: UNLOCK_WALLET_ID,
          subjects: [
            {
              kind: 'near_ed25519_wallet',
              walletId: UNLOCK_WALLET_ID,
              nearAccountId: UNLOCK_NEAR_ACCOUNT_ID,
              nearEd25519SigningKeyId: UNLOCK_NEAR_ED25519_SIGNING_KEY_ID,
              signerSlot: 1,
            },
            {
              kind: 'evm_family_ecdsa_wallet',
              walletId: UNLOCK_WALLET_ID,
              ecdsaThresholdKeyId: UNLOCK_ECDSA_THRESHOLD_KEY_ID,
            },
          ],
        },
      });
      if (resolution.kind !== 'resolved') {
        throw new Error('test fixture requires a combined subject set');
      }
      expect(
        resolveLoginWalletUnlockSelectionForSubjectSet({
          subjectSet: resolution.subjectSet,
          selection: undefined,
        }),
      ).toEqual({ mode: 'ed25519_and_ecdsa', ed25519: true, ecdsa: true });
      expect(
        resolveLoginUnlockWarmupBranchPlan({
          subjectSet: resolution.subjectSet,
          selection: { mode: 'ed25519_and_ecdsa', ed25519: true, ecdsa: true },
          hasConfiguredEcdsaTargets: true,
        }),
      ).toEqual({
        kind: 'near_ed25519_and_evm_family_ecdsa',
        wantsEd25519Warmup: true,
        wantsEcdsaWarmup: true,
      });
    } finally {
      clearUnlockPasskeyWalletBinding();
      IndexedDBManager.listActiveWalletSigners = originalListActiveWalletSigners;
    }
  });

  test('all-registered subject resolution fails closed on an unavailable family lookup', async () => {
    const originalListActiveWalletSigners = IndexedDBManager.listActiveWalletSigners;
    IndexedDBManager.listActiveWalletSigners = async (args: {
      walletId: string;
      signerFamily: 'ed25519' | 'ecdsa';
    }) => {
      if (args.signerFamily === 'ecdsa') {
        throw new Error('simulated ECDSA signer lookup failure');
      }
      return [];
    };
    try {
      seedUnlockPasskeyWalletBinding();
      const resolution = await resolveWalletUnlockSubjectSet({
        walletId: UNLOCK_WALLET_ID,
        requestedCapabilityFamilies: { kind: 'all_registered_mpc' },
      });

      expect(resolution).toEqual({
        kind: 'capability_subject_resolution_failed',
        walletId: UNLOCK_WALLET_ID,
        reason: 'capability_subject_lookup_failed',
      });
    } finally {
      clearUnlockPasskeyWalletBinding();
      IndexedDBManager.listActiveWalletSigners = originalListActiveWalletSigners;
    }
  });

  test('all-registered subject resolution rejects invalid persisted capability identity', async () => {
    const originalListActiveWalletSigners = IndexedDBManager.listActiveWalletSigners;
    IndexedDBManager.listActiveWalletSigners = async (args: {
      walletId: string;
      signerFamily: 'ed25519' | 'ecdsa';
    }) => {
      if (args.signerFamily === 'ed25519') return [];
      return [
        seedAccountSignerRecord({
          profileId: UNLOCK_WALLET_ID,
          metadata: {
            walletId: UNLOCK_WALLET_ID,
          },
        }),
      ];
    };
    try {
      seedUnlockPasskeyWalletBinding();
      const resolution = await resolveWalletUnlockSubjectSet({
        walletId: UNLOCK_WALLET_ID,
        requestedCapabilityFamilies: { kind: 'all_registered_mpc' },
      });

      expect(resolution).toEqual({
        kind: 'capability_subject_resolution_failed',
        walletId: UNLOCK_WALLET_ID,
        reason: 'invalid_capability_subject',
      });
    } finally {
      clearUnlockPasskeyWalletBinding();
      IndexedDBManager.listActiveWalletSigners = originalListActiveWalletSigners;
    }
  });

  test('passkey unlock emits unlock.cancelled for WebAuthn cancellation errors', async () => {
    const originalListActiveWalletSigners = IndexedDBManager.listActiveWalletSigners;
    IndexedDBManager.listActiveWalletSigners = async () => [];
    const events: any[] = [];
    const afterCalls: any[] = [];
    const onErrors: string[] = [];
    let promptedCredentialIds: string[] = [];
    const cancellation = new Error('The operation either timed out or was not allowed');
    cancellation.name = 'NotAllowedError';

    seedUnlockPasskeyWalletBinding();
    try {
      const result = await unlock(
        {
          signingEngine: {
            assertSealedRefreshStartupParity: async () => undefined,
            getLastUser: async () => ({
              walletId: UNLOCK_WALLET_ID,
              nearAccountId: 'alice.testnet',
              signerSlot: 1,
              operationalPublicKey: 'ed25519:alice',
              authMethod: 'passkey',
            }),
            nearAuthenticatorsByAccount: async () => [
              { credentialId: 'cred-1', signerSlot: 1 },
              { credentialId: 'cred-other-slot', signerSlot: 2 },
            ],
            getAuthenticationCredentialsSerialized: async (args: {
              allowCredentials: Array<{ id: string }>;
            }) => {
              promptedCredentialIds = [];
              for (const credential of args.allowCredentials) {
                promptedCredentialIds.push(credential.id);
              }
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
      expect(
        getStoredThresholdEd25519SessionRecordForAccount(UNLOCK_NEAR_ACCOUNT_ID),
      ).toMatchObject({
        walletId: UNLOCK_WALLET_ID,
        nearAccountId: UNLOCK_NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: UNLOCK_NEAR_ED25519_SIGNING_KEY_ID,
      });
      expect(afterCalls).toEqual([false]);
      expect(onErrors).toEqual(['The operation either timed out or was not allowed']);
      expect(promptedCredentialIds).toEqual(['cred-1']);
    } finally {
      clearUnlockPasskeyWalletBinding();
      IndexedDBManager.listActiveWalletSigners = originalListActiveWalletSigners;
    }
  });

  test('NEAR unlock rejects a stored signer projection without auth method', async () => {
    const originalListActiveWalletSigners = IndexedDBManager.listActiveWalletSigners;
    IndexedDBManager.listActiveWalletSigners = async () => [];
    let promptCalls = 0;
    const validProjection = nearPasskeyAccountProjectionFixture({
      walletId: UNLOCK_WALLET_ID,
      nearAccountId: UNLOCK_NEAR_ACCOUNT_ID,
      operationalPublicKey: 'ed25519:alice',
      credentialId: 'cred-1',
    });
    const corruptProjection = {
      ...validProjection,
      authMethod: undefined,
    };

    seedUnlockPasskeyWalletBinding();
    try {
      const result = await unlock(
        {
          signingEngine: {
            assertSealedRefreshStartupParity: async () => undefined,
            getLastUser: async () => corruptProjection,
            nearAuthenticatorsByAccount: async () => [{ credentialId: 'cred-1', signerSlot: 1 }],
            getAuthenticationCredentialsSerialized: async () => {
              promptCalls += 1;
              throw new Error('missing auth method must fail before prompting');
            },
          },
        } as any,
        UNLOCK_NEAR_ACCOUNT_ID,
      );

      expect(result).toEqual({
        success: false,
        error: '[login] wallet signer projection is missing a valid authMethod',
      });
      expect(promptCalls).toBe(0);
    } finally {
      clearUnlockPasskeyWalletBinding();
      IndexedDBManager.listActiveWalletSigners = originalListActiveWalletSigners;
    }
  });

  test('passkey prompt is not blocked by slow sealed-refresh parity check', async () => {
    const originalListActiveWalletSigners = IndexedDBManager.listActiveWalletSigners;
    IndexedDBManager.listActiveWalletSigners = async () => [];
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
              walletId: UNLOCK_WALLET_ID,
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
      IndexedDBManager.listActiveWalletSigners = originalListActiveWalletSigners;
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
