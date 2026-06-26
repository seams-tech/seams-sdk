import { expect, test } from '@playwright/test';
import { EmailRecoveryDomain } from '@/SeamsWeb/operations/recovery/emailRecovery';
import { IndexedDBManager } from '@/core/indexedDB';
import { EmailRecoveryFlowEventPhase } from '@/core/types/sdkSentEvents';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
} from '@/core/signingEngine/session/persistence/records';

const TEST_WALLET_ID = 'frost-vermillion-k7p9m2';
const TEST_NEAR_ACCOUNT_ID = 'c'.repeat(64);
const TEST_ED25519_KEY_SCOPE_ID = 'ed25519ks_email_recovery_scope';
const TEST_WALLET_BINDING = {
  walletId: TEST_WALLET_ID,
  nearAccountId: TEST_NEAR_ACCOUNT_ID,
  nearEd25519SigningKeyId: TEST_ED25519_KEY_SCOPE_ID,
  rpId: 'example.test',
  signerSlot: 7,
};

type PendingStoreMock = {
  getCalls: Array<{ accountId: string; nearPublicKey?: string }>;
  setCalls: any[];
  clearCalls: Array<{ accountId: string; nearPublicKey?: string }>;
  store: {
    get: (accountId: string, nearPublicKey?: string) => Promise<any>;
    set: (record: any) => Promise<void>;
    clear: (accountId: string, nearPublicKey?: string) => Promise<void>;
    touchIndex: (accountId: string, nearPublicKey: string) => Promise<void>;
  };
};

function createPendingStoreMock(initialRecord?: any): PendingStoreMock {
  let pending = initialRecord ?? null;
  const getCalls: Array<{ accountId: string; nearPublicKey?: string }> = [];
  const setCalls: any[] = [];
  const clearCalls: Array<{ accountId: string; nearPublicKey?: string }> = [];

  return {
    getCalls,
    setCalls,
    clearCalls,
    store: {
      async get(accountId: string, nearPublicKey?: string): Promise<any> {
        getCalls.push({ accountId, nearPublicKey });
        if (!pending) return null;
        if (nearPublicKey && pending.nearPublicKey !== nearPublicKey) return null;
        return pending;
      },
      async set(record: any): Promise<void> {
        pending = record;
        setCalls.push(record);
      },
      async clear(accountId: string, nearPublicKey?: string): Promise<void> {
        clearCalls.push({ accountId, nearPublicKey });
        pending = null;
      },
      async touchIndex(): Promise<void> {},
    },
  };
}

function createPendingEmailRecoveryRecord(overrides?: Record<string, unknown>) {
  return {
    accountId: TEST_WALLET_ID,
    walletId: TEST_WALLET_ID,
    nearAccountId: TEST_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: TEST_ED25519_KEY_SCOPE_ID,
    nearPublicKey: 'ed25519:recovery-key',
    newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
    recoverySessionId: 'ABC123',
    deadlineEpochSeconds: 1_893_456_000,
    recoveryEmailPayloadHash: 'sha256:payload-hash',
    recoveryEmailSubject: `recover-v1 ${TEST_NEAR_ACCOUNT_ID} ABC123`,
    recoveryEmailBody: 'tee-encrypted\nseams-recovery-v1:payload-token',
    requestId: 'ABC123',
    credential: {},
    createdAt: Date.now(),
    signerSlot: 1,
    status: 'awaiting-email',
    ...overrides,
  };
}

function createLocalDomain(options?: {
  nearAccessKeys?: Array<{ public_key: string }>;
  onViewAccessKeyList?: () => void;
}) {
  const storeUserDataCalls: any[] = [];
  const storeAuthenticatorCalls: any[] = [];
  const nearAccessKeys = options?.nearAccessKeys ?? [];
  const onViewAccessKeyList = options?.onViewAccessKeyList ?? (() => {});
  const usersByAccount = new Map<string, any>();
  const hydrateSigningSessionCalls: any[] = [];
  let lastUser: any = null;
  let warmSigningSession: { sessionId: string; expiresAtMs: number; remainingUses: number } | null =
    null;

  const context = {
    configs: {
      network: {
        chains: [
          {
            network: 'ethereum-sepolia',
            rpcUrl: 'https://ethereum-sepolia.example.test',
            chainId: 11155111,
          },
        ],
        relayer: {
          url: 'https://relay.example.test',
          emailRecovery: {
            mailtoAddress: 'recovery@example.test',
            pollingIntervalMs: 1,
            maxPollingDurationMs: 10,
          },
        },
      },
      signing: {
        mode: { mode: 'threshold-signer' },
        sessionDefaults: { ttlMs: 300_000, remainingUses: 5 },
        routerAb: {
          normalSigning: {
            mode: 'enabled',
            signingWorkerId: 'signing-worker-local',
          },
        },
        thresholdEcdsa: {
          provisioningDefaults: {
            evm: {
              enabled: true,
              signingSession: { kind: 'jwt', ttlMs: 300_000, remainingUses: 3 },
            },
            tempo: {
              enabled: false,
              signingSession: { kind: 'jwt', ttlMs: 300_000, remainingUses: 3 },
            },
          },
        },
      },
    },
    signingRuntime: {
      services: {
        ecdsaRegistrationBootstrap: {
          preparePasskeyClientBootstrap: async (input: any) => ({
            clientBootstrap: {
              ...input.prepare,
              clientPublicKey33B64u: 'client-public-key',
              clientShareRetryCounter: 0,
              contextBinding32B64u: 'context-binding',
            },
          }),
        },
        ecdsaWalletRecords: {
          storeWalletEcdsaSignerRecords: async () => undefined,
          storeWalletEmailOtpEcdsaSignerRecords: async () => undefined,
          finalizeWalletEcdsaRegistration: async () => ({ storedSigners: [] }),
          storeWalletEmailOtpEcdsaRegistrationData: async () => ({ storedSigners: [] }),
        },
        warmSessions: {
          hydrateSigningSession: async (input: any) => {
            hydrateSigningSessionCalls.push(input);
            warmSigningSession = {
              sessionId: String(input?.sessionId || ''),
              expiresAtMs: Number(input?.expiresAtMs || Date.now() + 60_000),
              remainingUses: Number(input?.remainingUses || 1),
            };
          },
        },
        registrationAccounts: {
          storeUserData: async (input: any) => {
            storeUserDataCalls.push(input);
            usersByAccount.set(String(input?.nearAccountId || ''), input);
          },
          storeAuthenticator: async (input: any) => {
            storeAuthenticatorCalls.push(input);
          },
          setLastUser: async (nearAccountId: string, signerSlot: number) => {
            const accountId = String(nearAccountId || '');
            const stored = usersByAccount.get(accountId) || {};
            lastUser = {
              nearAccountId: accountId,
              signerSlot,
              operationalPublicKey: String(stored?.operationalPublicKey || 'ed25519:recovery-key'),
            };
          },
          updateLastLogin: async () => undefined,
          activateAuthenticatedWalletState: async () => undefined,
          getLastUser: async () => lastUser,
        },
      },
    },
    signingEngine: {
      getRpId: () => 'example.test',
      preparePasskeyEcdsaBootstrap: async (input: any) => ({
        clientBootstrap: {
          ...input.prepare,
          clientPublicKey33B64u: 'client-public-key',
          clientShareRetryCounter: 0,
          contextBinding32B64u: 'context-binding',
        },
      }),
      hydrateSigningSession: async (input: any) => {
        hydrateSigningSessionCalls.push(input);
        warmSigningSession = {
          sessionId: String(input?.sessionId || ''),
          expiresAtMs: Number(input?.expiresAtMs || Date.now() + 60_000),
          remainingUses: Number(input?.remainingUses || 1),
        };
      },
      storeWalletEcdsaSignerRecords: async () => undefined,
      requestRegistrationCredentialConfirmation: async () => ({
        credential: {
          id: 'cred-1',
          type: 'public-key',
          rawId: 'raw-cred-1',
          response: {
            clientDataJSON: 'client-data',
            attestationObject: 'attestation-object',
            transports: ['internal'],
          },
          clientExtensionResults: {
            prf: { results: { first: Buffer.alloc(32, 13).toString('base64url') } },
          },
        },
        intentDigest: 'threshold:email-recovery:7',
      }),
      deriveThresholdEcdsaClientVerifyingShareFromCredential: async () => ({
        success: true,
        clientVerifyingShareB64u: 'client-ecdsa-verifying-share',
      }),
      prepareThresholdEd25519HssClientCeremonyFromCredential: async () => ({
        ok: true,
        contextBindingB64u: 'ctx-binding',
        signingRootId: 'root',
        nearAccountId: TEST_NEAR_ACCOUNT_ID,
        keyPurpose: 'near-ed25519-signing',
        keyVersion: 'v1',
        participantIds: [1, 2],
        derivationVersion: 1,
        yClientB64u: 'y-client',
        tauClientB64u: 'tau-client',
      }),
      runThresholdEd25519HssCeremonyWithSession: async () => ({
        ok: true,
        contextBindingB64u: 'ctx-binding',
        preparedSession: {
          contextBindingB64u: 'ctx-binding',
          evaluatorDriverStateB64u: 'evaluator-state',
        },
        finalizedReport: {
          contextBindingB64u: 'ctx-binding',
          clientOutputMessageB64u: 'client-output',
        },
        clientOutput: {
          contextBindingB64u: 'ctx-binding',
          xClientBaseB64u: 'x-client-base',
        },
      }),
      prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization: async (input: any) => ({
        ok: true,
        materialKeyId: 'ed25519-worker-material-key',
        sealAuthorization: {
          kind: 'passkey_prf_material_seal_authorization_handle_v1',
          handle: 'seal-authorization-handle',
          rpId: 'example.test',
          credentialIdB64u: String(input?.request?.credentialIdB64u || 'raw-cred-1'),
          materialKeyId: 'ed25519-worker-material-key',
          expiresAtMs: Date.now() + 60_000,
        },
        remainingUses: 1,
      }),
      runThresholdEd25519HssCeremonyWithMaterialHandle: async () => ({
        ok: true,
        signingMaterial: {
          materialHandle: 'ed25519-worker-material:sync-session-1',
          materialBindingDigest: 'ed25519-worker-binding-digest',
          sealedWorkerMaterialRef: 'ed25519-worker-sealed-ref',
          sealedWorkerMaterialB64u: 'ed25519-worker-sealed-material',
          clientVerifyingShareB64u: 'ed25519-client-verifying-share',
          materialFormatVersion: 'ed25519_worker_material_v1',
          materialKeyId: 'ed25519-worker-material-key',
          signerSlot: 7,
          keyVersion: 'threshold-ed25519-hss-v1',
        },
      }),
      storeUserData: async (input: any) => {
        storeUserDataCalls.push(input);
        usersByAccount.set(String(input?.nearAccountId || ''), input);
      },
      storeAuthenticator: async (input: any) => {
        storeAuthenticatorCalls.push(input);
      },
      setLastUser: async (nearAccountId: string, signerSlot: number) => {
        const accountId = String(nearAccountId || '');
        const stored = usersByAccount.get(accountId) || {};
        lastUser = {
          nearAccountId: accountId,
          signerSlot,
          operationalPublicKey: String(stored?.operationalPublicKey || 'ed25519:recovery-key'),
        };
      },
      updateLastLogin: async () => undefined,
      activateAuthenticatedWalletState: async () => undefined,
      getLastUser: async () => lastUser,
      getWarmThresholdEd25519SessionStatus: async () =>
        warmSigningSession
          ? {
              sessionId: warmSigningSession.sessionId,
              status: 'active',
              remainingUses: warmSigningSession.remainingUses,
              expiresAtMs: warmSigningSession.expiresAtMs,
            }
          : null,
    },
    nearClient: {
      viewAccessKeyList: async () => {
        onViewAccessKeyList();
        return { keys: nearAccessKeys };
      },
    },
  } as any;

  const domain = new EmailRecoveryDomain({
    getContext: () => context,
    walletIframe: {
      shouldUseWalletIframe: () => false,
      requireRouter: async () => {
        throw new Error('wallet iframe router should not be used in local mode');
      },
    } as any,
  });

  return { domain, hydrateSigningSessionCalls, storeUserDataCalls, storeAuthenticatorCalls };
}

test.describe('EmailRecoveryDomain', () => {
  test('local startEmailRecovery emits progress phases and persists pending record', async () => {
    const pendingStore = createPendingStoreMock();
    const events: any[] = [];
    const thresholdMaterialWrites: any[] = [];

    clearAllStoredThresholdEd25519SessionRecords();
    const originalFetch = globalThis.fetch;
    const clientDb = IndexedDBManager as unknown as { resolveProfileAccountContext?: unknown };
    const keyMaterialPort = IndexedDBManager as unknown as {
      storeKeyMaterial?: unknown;
    };
    const originalProfileLookup = clientDb.resolveProfileAccountContext;
    const originalStoreKeyMaterial = keyMaterialPort.storeKeyMaterial;
    try {
      globalThis.fetch = (async (input: unknown) => {
        const url = String((input as any)?.url || input);
        if (url.endsWith('/email-recovery/prepare')) {
          return new Response(
            JSON.stringify({
              ok: true,
              accountId: TEST_WALLET_ID,
              walletId: TEST_WALLET_ID,
              nearAccountId: TEST_NEAR_ACCOUNT_ID,
              nearEd25519SigningKeyId: TEST_ED25519_KEY_SCOPE_ID,
              walletBinding: TEST_WALLET_BINDING,
              thresholdEd25519: {
                keyVersion: 'threshold-ed25519-hss-v1',
                recoveryExportCapable: true,
                publicKey: 'ed25519:threshold-public-key',
                relayerKeyId: 'relayer-key-1',
                clientParticipantId: 1,
                relayerParticipantId: 2,
                participantIds: [1, 2],
                session: {
                  sessionKind: 'jwt',
                  walletId: TEST_WALLET_ID,
                  nearAccountId: TEST_NEAR_ACCOUNT_ID,
                  nearEd25519SigningKeyId: TEST_ED25519_KEY_SCOPE_ID,
                  thresholdSessionId: 'sync-session-1',
                  signingGrantId: 'signing-grant-1',
                  expiresAtMs: Date.now() + 60_000,
                  remainingUses: 5,
                  participantIds: [1, 2],
                  runtimePolicyScope: {
                    orgId: 'org-email-recovery',
                    projectId: 'proj-email-recovery',
                    envId: 'env-email-recovery',
                    signingRootVersion: 'root-email-recovery-v1',
                  },
                  routerAbNormalSigning: {
                    kind: 'router_ab_ed25519_normal_signing_v1',
                    signingWorkerId: 'signing-worker-local',
                  },
                  jwt: 'sync-jwt',
                },
              },
              ecdsa: {
                kind: 'evm_family_ecdsa_keygen',
                chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 11155111 }],
                prepare: {
                  formatVersion: 'ecdsa-hss-role-local',
                  walletId: TEST_WALLET_ID,
                  walletKeyId: 'wallet-key-email-recovery',
                  rpId: 'example.test',
                  ecdsaThresholdKeyId: 'ecdsa-threshold-key',
                  runtimePolicyScope: {
                    orgId: 'org-email-recovery',
                    projectId: 'proj-email-recovery',
                    envId: 'env-email-recovery',
                    signingRootVersion: 'root-email-recovery-v1',
                  },
                  keyScope: 'evm-family',
                  relayerKeyId: 'ecdsa-relayer-key',
                  requestId: 'ABC123:ecdsa',
                  thresholdSessionId: 'tehss_ABC123',
                  signingGrantId: 'wss_ABC123',
                  ttlMs: 60_000,
                  remainingUses: 1,
                  participantIds: [1, 2],
                },
              },
            }),
            { status: 200 },
          );
        }
        if (!url.endsWith('/email-recovery/ecdsa/respond')) {
          return new Response(JSON.stringify({ ok: false, error: 'unexpected_url' }), {
            status: 404,
          });
        }
        return new Response(
          JSON.stringify({
            ok: true,
            accountId: TEST_WALLET_ID,
            walletId: TEST_WALLET_ID,
            nearAccountId: TEST_NEAR_ACCOUNT_ID,
            nearEd25519SigningKeyId: TEST_ED25519_KEY_SCOPE_ID,
            walletBinding: TEST_WALLET_BINDING,
            credentialIdB64u: 'raw-cred-1',
            credentialPublicKeyB64u: 'AQID',
            thresholdEd25519: {
              keyVersion: 'threshold-ed25519-hss-v1',
              recoveryExportCapable: true,
              publicKey: 'ed25519:threshold-public-key',
              relayerKeyId: 'relayer-key-1',
              clientParticipantId: 1,
              relayerParticipantId: 2,
              participantIds: [1, 2],
              session: {
                sessionKind: 'jwt',
                walletId: TEST_WALLET_ID,
                nearAccountId: TEST_NEAR_ACCOUNT_ID,
                nearEd25519SigningKeyId: TEST_ED25519_KEY_SCOPE_ID,
                thresholdSessionId: 'sync-session-1',
                signingGrantId: 'signing-grant-1',
                expiresAtMs: Date.now() + 60_000,
                remainingUses: 5,
                participantIds: [1, 2],
                runtimePolicyScope: {
                  orgId: 'org-email-recovery',
                  projectId: 'proj-email-recovery',
                  envId: 'env-email-recovery',
                  signingRootVersion: 'root-email-recovery-v1',
                },
                routerAbNormalSigning: {
                  kind: 'router_ab_ed25519_normal_signing_v1',
                  signingWorkerId: 'signing-worker-local',
                },
                jwt: 'sync-jwt',
              },
            },
            ecdsa: {
              bootstrap: {
                ethereumAddress: `0x${'11'.repeat(20)}`,
              },
              walletKeys: [
                {
                  keyScope: 'evm-family',
                  chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 11155111 },
                  walletId: TEST_WALLET_ID,
                  walletKeyId: 'wallet-key-email-recovery',
                  rpId: 'example.test',
                  keyHandle: 'key-handle',
                  ecdsaThresholdKeyId: 'ecdsa-threshold-key',
                  signingRootId: 'signing-root-id',
                  signingRootVersion: 'root-email-recovery-v1',
                  thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
                  thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
                  relayerKeyId: 'ecdsa-relayer-key',
                  relayerVerifyingShareB64u: 'relayer-share',
                  participantIds: [1, 2],
                },
              ],
            },
            recoverySession: {
              sessionId: 'ABC123',
              status: 'prepared',
              expiresAtMs: Date.now() + 60_000,
              deadlineEpochSeconds: 1_893_456_000,
              payloadHash: 'sha256:payload-hash',
            },
            recoveryEmail: {
              subject: `recover-v1 ${TEST_NEAR_ACCOUNT_ID} ABC123`,
              body: 'tee-encrypted\nseams-recovery-v1:payload-token',
              payloadHash: 'sha256:payload-hash',
              deadlineEpochSeconds: 1_893_456_000,
            },
          }),
          { status: 200 },
        );
      }) as any;
      clientDb.resolveProfileAccountContext = async (accountRef: {
        chainIdKey: string;
        accountAddress: string;
      }) =>
        accountRef.chainIdKey === 'near:testnet' &&
        String(accountRef.accountAddress || '').trim() === TEST_NEAR_ACCOUNT_ID
          ? { profileId: `near-profile:${TEST_NEAR_ACCOUNT_ID}`, accountRef }
          : null;
      keyMaterialPort.storeKeyMaterial = async (input: any) => {
        thresholdMaterialWrites.push({
          publicKey: input?.publicKey,
          relayerKeyId: input?.payload?.relayerKeyId,
          keyVersion: input?.payload?.keyVersion,
        });
      };

      const {
        domain,
        hydrateSigningSessionCalls,
        storeUserDataCalls,
        storeAuthenticatorCalls,
      } = createLocalDomain();
      const result = await domain.startEmailRecovery({
        walletId: TEST_WALLET_ID,
        options: {
          pendingStore: pendingStore.store as any,
          onEvent: (ev: any) => events.push(ev),
        },
      });

      expect(result.nearPublicKey).toBe('ed25519:threshold-public-key');
      expect(result.mailtoUrl).toContain('mailto:recovery@example.test');
      expect(result.mailtoUrl).toContain(
        encodeURIComponent(`recover-v1 ${TEST_NEAR_ACCOUNT_ID} ABC123`),
      );
      expect(result.mailtoUrl).toContain(encodeURIComponent('seams-recovery-v1:payload-token'));
      expect(pendingStore.setCalls).toHaveLength(1);
      expect(pendingStore.setCalls[0]?.nearPublicKey).toBe('ed25519:threshold-public-key');
      expect(pendingStore.setCalls[0]?.walletId).toBe(TEST_WALLET_ID);
      expect(pendingStore.setCalls[0]?.nearAccountId).toBe(TEST_NEAR_ACCOUNT_ID);
      expect(pendingStore.setCalls[0]?.nearEd25519SigningKeyId).toBe(TEST_ED25519_KEY_SCOPE_ID);
      expect(
        Object.prototype.hasOwnProperty.call(pendingStore.setCalls[0] || {}, 'ecdsaThresholdKeyId'),
      ).toBe(false);
      expect(pendingStore.setCalls[0]?.newEvmOwnerAddress).toBe(`0x${'11'.repeat(20)}`);
      expect(pendingStore.setCalls[0]?.recoverySessionId).toBe('ABC123');
      expect(pendingStore.setCalls[0]?.signerSlot).toBe(7);
      expect(events.map((ev) => ev.phase)).toEqual([
        EmailRecoveryFlowEventPhase.STEP_01_STARTED,
        EmailRecoveryFlowEventPhase.STEP_03_PASSKEY_CREATE_STARTED,
        EmailRecoveryFlowEventPhase.STEP_03_PASSKEY_CREATE_SUCCEEDED,
        EmailRecoveryFlowEventPhase.STEP_04_EMAIL_LINK_SENT,
        EmailRecoveryFlowEventPhase.STEP_04_EMAIL_LINK_WAITING,
      ]);
      expect(storeUserDataCalls).toHaveLength(1);
      expect(storeUserDataCalls[0]?.nearAccountId).toBe(TEST_NEAR_ACCOUNT_ID);
      expect(storeAuthenticatorCalls).toHaveLength(1);
      expect(storeAuthenticatorCalls[0]?.nearAccountId).toBe(TEST_NEAR_ACCOUNT_ID);
      expect(hydrateSigningSessionCalls).toHaveLength(2);
      expect(hydrateSigningSessionCalls[0]?.transport).toMatchObject({
        curve: 'ed25519',
        walletId: TEST_WALLET_ID,
        signingGrantId: 'signing-grant-1',
      });
      expect(hydrateSigningSessionCalls[1]?.transport).toMatchObject({
        curve: 'ed25519',
        walletId: TEST_WALLET_ID,
        signingGrantId: 'signing-grant-1',
      });
      const persistedWarmSession =
        getStoredThresholdEd25519SessionRecordByThresholdSessionId('sync-session-1');
      expect(persistedWarmSession).toMatchObject({
        walletId: TEST_WALLET_ID,
        nearAccountId: TEST_NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: TEST_ED25519_KEY_SCOPE_ID,
      });
      expect(thresholdMaterialWrites).toHaveLength(1);
      expect(thresholdMaterialWrites[0]?.publicKey).toBe('ed25519:threshold-public-key');
      expect(thresholdMaterialWrites[0]?.relayerKeyId).toBe('relayer-key-1');
      expect(
        Object.prototype.hasOwnProperty.call(thresholdMaterialWrites[0] || {}, 'recoveryPublicKey'),
      ).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
      clientDb.resolveProfileAccountContext = originalProfileLookup;
      keyMaterialPort.storeKeyMaterial = originalStoreKeyMaterial;
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('local finalizeEmailRecovery resumes pending state, polls, and clears pending store after key appears on-chain', async () => {
    const pendingStore = createPendingStoreMock(createPendingEmailRecoveryRecord());
    const events: any[] = [];
    let listCalls = 0;

    const { domain } = createLocalDomain({
      nearAccessKeys: [{ public_key: 'ed25519:recovery-key' }],
      onViewAccessKeyList: () => {
        listCalls += 1;
      },
    });

    await domain.finalizeEmailRecovery({
      walletId: TEST_WALLET_ID,
      options: {
        pendingStore: pendingStore.store as any,
        onEvent: (ev: any) => events.push(ev),
      },
    });

    expect(listCalls).toBeGreaterThanOrEqual(1);
    expect(pendingStore.getCalls).toHaveLength(1);
    expect(pendingStore.setCalls.map((record) => record.status)).toEqual([
      'awaiting-add-key',
      'finalizing',
      'complete',
    ]);
    expect(pendingStore.clearCalls).toEqual([
      { accountId: TEST_WALLET_ID, nearPublicKey: 'ed25519:recovery-key' },
    ]);
    expect(events.map((ev) => ev.phase)).toEqual([
      EmailRecoveryFlowEventPhase.STEP_00_RESUMED_PENDING,
      EmailRecoveryFlowEventPhase.STEP_05_RECOVERY_KEY_POLL_STARTED,
      EmailRecoveryFlowEventPhase.STEP_05_RECOVERY_KEY_POLL_DETECTED,
      EmailRecoveryFlowEventPhase.STEP_06_FINALIZE_STARTED,
      EmailRecoveryFlowEventPhase.STEP_06_AUTO_UNLOCK_SKIPPED,
      EmailRecoveryFlowEventPhase.STEP_07_COMPLETED,
    ]);
    expect(events[0]).toMatchObject({
      flowId: `email-recovery:${TEST_WALLET_ID}:ABC123`,
      requestId: 'ABC123',
      interaction: { kind: 'email_recovery_link', overlay: 'hide' },
      data: {
        nearPublicKey: 'ed25519:recovery-key',
        recoverySessionId: 'ABC123',
        pendingStatus: 'awaiting-email',
      },
    });
  });

  test('local finalizeEmailRecovery failure marks pending record as error and emits failed event', async () => {
    const pendingStore = createPendingStoreMock(createPendingEmailRecoveryRecord());
    const events: any[] = [];
    const errors: Error[] = [];
    let listCalls = 0;

    const { domain } = createLocalDomain({
      onViewAccessKeyList: () => {
        listCalls += 1;
      },
    });

    await expect(
      domain.finalizeEmailRecovery({
        walletId: TEST_WALLET_ID,
        options: {
          pendingStore: pendingStore.store as any,
          onEvent: (ev: any) => events.push(ev),
          onError: (error: Error) => errors.push(error),
        },
      }),
    ).rejects.toThrow('Timed out waiting for AddKey');

    expect(listCalls).toBeGreaterThanOrEqual(1);
    expect(errors).toHaveLength(1);
    expect(errors[0]?.message).toBe('Timed out waiting for AddKey');
    expect(pendingStore.setCalls.map((record) => record.status)).toEqual([
      'awaiting-add-key',
      'error',
    ]);
    expect(pendingStore.clearCalls).toEqual([]);
    expect(events.map((ev) => ev.phase)).toEqual([
      EmailRecoveryFlowEventPhase.STEP_00_RESUMED_PENDING,
      EmailRecoveryFlowEventPhase.STEP_05_RECOVERY_KEY_POLL_STARTED,
      EmailRecoveryFlowEventPhase.FAILED,
    ]);
    expect(events.at(-1)).toMatchObject({
      flowId: `email-recovery:${TEST_WALLET_ID}:ABC123`,
      requestId: 'ABC123',
      status: 'failed',
      error: { message: 'Timed out waiting for AddKey' },
    });
  });

  test('local cancelEmailRecovery clears pending store and emits cancelled event', async () => {
    const pendingStore = createPendingStoreMock();
    const { domain } = createLocalDomain();
    const events: any[] = [];

    (domain as any).emailRecoveryOptions = {
      pendingStore: pendingStore.store,
      onEvent: (event: any) => events.push(event),
    };
    await domain.cancelEmailRecovery({
      walletId: TEST_WALLET_ID,
      nearPublicKey: 'ed25519:cancel-key',
    });

    expect(pendingStore.clearCalls).toEqual([
      { accountId: TEST_WALLET_ID, nearPublicKey: 'ed25519:cancel-key' },
    ]);
    expect(events).toEqual([
      expect.objectContaining({
        version: 2,
        flow: 'email_recovery',
        step: 0,
        phase: EmailRecoveryFlowEventPhase.CANCELLED,
        status: 'cancelled',
        message: 'Email recovery cancelled',
        flowId: `email-recovery:${TEST_WALLET_ID}:ed25519:cancel-key`,
        accountId: TEST_WALLET_ID,
        interaction: { kind: 'email_recovery_link', overlay: 'hide' },
      }),
    ]);
  });

  test('iframe mode routes email recovery calls through wallet router', async () => {
    const calls = {
      start: [] as any[],
      finalize: [] as any[],
      cancel: [] as any[],
    };
    const events: any[] = [];
    let localContextTouched = false;

    const router = {
      startEmailRecovery: async (payload: any) => {
        calls.start.push(payload);
        return { mailtoUrl: 'mailto:wallet@example.test', nearPublicKey: 'ed25519:router-key' };
      },
      finalizeEmailRecovery: async (payload: any) => {
        calls.finalize.push(payload);
      },
      stopEmailRecovery: async (payload: any) => {
        calls.cancel.push(payload);
      },
    };

    const domain = new EmailRecoveryDomain({
      getContext: () => {
        localContextTouched = true;
        return {} as any;
      },
      walletIframe: {
        shouldUseWalletIframe: () => true,
        requireRouter: async () => router as any,
      } as any,
    });

    const startResult = await domain.startEmailRecovery({
      walletId: TEST_WALLET_ID,
      options: {
        onEvent: (ev: any) => events.push(ev),
        confirmerText: { title: 'Recover', body: 'Confirm recovery' },
        confirmationConfig: { uiMode: 'modal' },
      } as any,
    });
    await domain.finalizeEmailRecovery({
      walletId: TEST_WALLET_ID,
      nearPublicKey: 'ed25519:router-key',
      options: { onEvent: (ev: any) => events.push(ev) },
    });
    await domain.cancelEmailRecovery({
      walletId: TEST_WALLET_ID,
      nearPublicKey: 'ed25519:router-key',
    });

    expect(startResult).toEqual({
      mailtoUrl: 'mailto:wallet@example.test',
      nearPublicKey: 'ed25519:router-key',
    });
    expect(calls.start).toHaveLength(1);
    expect(calls.start[0]).toMatchObject({
      walletId: TEST_WALLET_ID,
      onEvent: expect.any(Function),
      options: {
        confirmerText: { title: 'Recover', body: 'Confirm recovery' },
        confirmationConfig: { uiMode: 'modal' },
      },
    });
    expect(calls.finalize).toEqual([
      {
        walletId: TEST_WALLET_ID,
        nearPublicKey: 'ed25519:router-key',
        onEvent: expect.any(Function),
      },
    ]);
    expect(calls.cancel).toEqual([
      {
        walletId: TEST_WALLET_ID,
        nearPublicKey: 'ed25519:router-key',
      },
    ]);
    expect(events).toEqual([]);
    expect(localContextTouched).toBe(false);
  });
});
