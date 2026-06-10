import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import bs58 from 'bs58';
import { base64UrlDecode } from '@shared/utils/encoders';
import {
  ensureThresholdEd25519HssClientBase,
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from '@/core/signingEngine/threshold/ed25519/hssClientBase';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { runNearTransactionsWithActionsSigning as signTransactionsWithActions } from '@/core/signingEngine/flows/signNear/signTransactions';
import * as recoveryPublic from '@/core/signingEngine/flows/recovery/public';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  persistStoredThresholdEd25519SessionClientBase,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { ActionType, type TransactionInputWasm } from '@/core/types/actions';
import {
  NearSignerWorkerCustomRequestType,
  type PrepareThresholdEd25519PresignPoolPayload,
  WorkerRequestType,
  WorkerResponseType,
} from '@/core/types/signer-worker';
import {
  applyThresholdEd25519PresignRefillResult,
  clearAllThresholdEd25519ClientPresigns,
  scheduleThresholdEd25519ClientPresignPoolRefill,
} from '@/core/signingEngine/threshold/ed25519/presignPool';
import {
  buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm,
  deriveThresholdEd25519HssClientInputsWasm,
  openThresholdEd25519HssClientOutputWasm,
  prepareThresholdEd25519HssClientRequestWasm,
  prepareThresholdEd25519HssSessionWasm,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import {
  deriveThresholdEd25519HssClientOutputMaskB64u,
  validateThresholdEd25519HssOutputProjectionPolicy,
} from '@/core/signingEngine/threshold/ed25519/clientOutputMask';
import {
  deriveThresholdEd25519HssPublicKey,
  finalizeThresholdEd25519HssServerCeremony,
  prepareThresholdEd25519HssRoleSeparatedServerInputDelivery,
  prepareThresholdEd25519HssServerSession,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/ed25519HssWasm';
import type { ThresholdEd25519HssSessionOperation } from '../../packages/sdk-server-ts/src/core/types';
import { deriveEd25519HssServerInputsFromSigningRootSecretShares } from '../../packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm';
import {
  parseSigningRootSecretShareWireV1,
  type SigningRootSecretShareWirePair,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootSecretShareWires';
import {
  handle_signer_message,
  initSync as initNearSignerWasmSync,
} from '../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  derive_threshold_ed25519_hss_client_inputs,
  initSync as initHssClientSignerWasmSync,
  threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact,
  threshold_ed25519_hss_derive_client_output_mask,
  threshold_ed25519_hss_open_client_output,
  threshold_ed25519_hss_open_seed_output,
  threshold_ed25519_hss_prepare_client_request,
  threshold_ed25519_hss_prepare_session,
  threshold_ed25519_seed_export_artifact_from_seed,
} from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';

class MemorySessionStorage implements Pick<
  Storage,
  'getItem' | 'setItem' | 'removeItem' | 'clear'
> {
  private readonly store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.has(key) ? this.store.get(key)! : null;
  }

  setItem(key: string, value: string): void {
    this.store.set(String(key), String(value));
  }

  removeItem(key: string): void {
    this.store.delete(String(key));
  }

  clear(): void {
    this.store.clear();
  }
}

const NEAR_ACCOUNT_ID = 'single-key-hss-active.testnet';
const RELAYER_URL = 'https://relay.example.test';
const RELAYER_KEY_ID = 'ed25519:relayer-key-id';
const RP_ID = 'example.localhost';
const THRESHOLD_SESSION_ID = 'threshold-ed25519-single-key-hss-session';
const WALLET_SIGNING_SESSION_ID = 'wallet-signing-session-single-key-hss';
const THRESHOLD_SESSION_JWT = 'header.payload.signature';
const ORG_ID = 'org_single_key_hss';
const TEST_CLIENT_OUTPUT_MASK_B64U = Buffer.alloc(32, 0x5a).toString('base64url');
const RUNTIME_SCOPE = {
  orgId: ORG_ID,
  projectId: 'project_single_key_hss',
  envId: 'env_single_key_hss',
  signingRootVersion: 'default',
} as const;
const SIGNING_ROOT_ID = `${RUNTIME_SCOPE.projectId}:${RUNTIME_SCOPE.envId}`;

function buildTestWarmSigningAuth() {
  const expiresAtMs = Date.now() + 60_000;
  const activeBudgetStatus = {
    sessionId: WALLET_SIGNING_SESSION_ID,
    status: 'active' as const,
    authMethod: 'passkey' as const,
    retention: 'session' as const,
    remainingUses: 5,
    availableUses: 5,
    inFlightReservedUses: 0,
    expiresAtMs,
    projectionVersion: 'test-ed25519-budget-projection',
  };
  const signingAuthPlan = {
    kind: 'warmSession',
    method: 'passkey',
    accountId: NEAR_ACCOUNT_ID,
    intent: 'transaction_sign',
    curve: 'ed25519',
    sessionId: THRESHOLD_SESSION_ID,
    retention: 'session',
    expiresAtMs,
    remainingUses: 5,
  };
  const signingLane = {
    accountId: NEAR_ACCOUNT_ID,
    authMethod: 'passkey',
    curve: 'ed25519',
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    sessionOrigin: 'bootstrap',
    storageSource: 'bootstrap',
    retention: 'session',
    activeSignerSlot: 1,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: RUNTIME_SCOPE.signingRootVersion,
  };
  const signingSessionPlan = {
    kind: 'warm_session',
    lane: signingLane,
    keyRef: {
      kind: 'cached',
      thresholdSessionId: THRESHOLD_SESSION_ID,
    },
  };
  const transactionOperation = {
    intent: {
      walletId: NEAR_ACCOUNT_ID,
      curve: 'ed25519',
      chain: 'near',
      authSelectionPolicy: { kind: 'account_class', authMethod: 'passkey' },
      operationUsesNeeded: 1,
    },
    lane: signingLane,
    readiness: {
      status: 'ready',
      remainingUses: 5,
      expiresAtMs,
    },
  };
  return {
    signingSessionCoordinator: new SigningSessionCoordinator({
      getStatus: async () => activeBudgetStatus,
      consumeUse: async () => activeBudgetStatus,
    }),
    signingAuthPlan,
    signingLane,
    signingSessionPlan,
    transactionOperation,
    ed25519SigningBoundary: {
      sessionId: THRESHOLD_SESSION_ID,
      signingSessionPlan,
      signingAuthPlan,
      signingLane,
      initialBudgetAdmittedOperation: null,
    },
  } as any;
}
const CONTEXT = {
  signingRootId: SIGNING_ROOT_ID,
  nearAccountId: NEAR_ACCOUNT_ID,
  keyPurpose: 'near-ed25519-signing',
  keyVersion: 'root-v1',
  participantIds: [1, 2],
  derivationVersion: 1,
} as const;
const PRF_FIRST_B64U = Buffer.alloc(32, 11).toString('base64url');
const EXPECTED_CLIENT_OUTPUT_MASK_B64U = 'sE_I9hyDmS1AdAYfb4CRx_rehIb4IaF9KOoAQTX2QyQ';
const SIGNING_ROOT_SECRET_SHARE_WIRE_HEX = [
  '011ba5f9c2f4003d409a9358a20b40b37eb32a28daacc5676a468b64a203c1e303',
  '021bb9834016ae79b9a815f68d1f456b35acb1b5631dd04e1cab9f640852aaed0d',
] as const;
const NEAR_SIGNER_WASM_URL = new URL(
  '../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
  import.meta.url,
);
const HSS_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm',
  import.meta.url,
);
let nearSignerWasmInitializedForDirectWorkerTests = false;
let hssClientSignerWasmInitializedForDirectWorkerTests = false;

function fixtureSigningRootSecretShareWirePair(): SigningRootSecretShareWirePair {
  const parsed = SIGNING_ROOT_SECRET_SHARE_WIRE_HEX.map((wireHex) =>
    parseSigningRootSecretShareWireV1(new Uint8Array(Buffer.from(wireHex, 'hex'))),
  );
  if (!parsed[0].ok) throw new Error(parsed[0].message);
  if (!parsed[1].ok) throw new Error(parsed[1].message);
  return [parsed[0].value, parsed[1].value];
}

async function deriveFixtureThresholdEd25519HssServerInputs(
  context:
    | typeof CONTEXT
    | {
        signingRootId: string;
        nearAccountId: string;
        keyPurpose: string;
        keyVersion: string;
        participantIds: readonly number[];
        derivationVersion: number;
      },
) {
  const shareWires = fixtureSigningRootSecretShareWirePair();
  try {
    return await deriveEd25519HssServerInputsFromSigningRootSecretShares({
      shareWires,
      context: {
        signingRootId: context.signingRootId,
        nearAccountId: context.nearAccountId,
        keyPurpose: context.keyPurpose,
        keyVersion: context.keyVersion,
        participantIds: [...context.participantIds],
        derivationVersion: context.derivationVersion,
      },
    });
  } finally {
    shareWires[0].fill(0);
    shareWires[1].fill(0);
  }
}

function expectNoSigningRootSecretShareWire(payload: string): void {
  for (const wireHex of SIGNING_ROOT_SECRET_SHARE_WIRE_HEX) {
    expect(payload.includes(wireHex)).toBe(false);
    expect(payload.includes(Buffer.from(wireHex, 'hex').toString('base64url'))).toBe(false);
  }
}

function buildExportAuthorizationDecision(requestId: string) {
  return {
    requestId,
    confirmed: true,
    credential: {
      id: 'cred-id',
      rawId: 'cred-rawid-b64u',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: 'clientDataJSON-b64u',
        authenticatorData: 'authenticatorData-b64u',
        signature: 'signature-b64u',
        userHandle: '',
      },
      clientExtensionResults: {
        prf: { results: { first: PRF_FIRST_B64U, second: undefined } },
      },
    },
  };
}

function storedHssEvaluationResultFromClientOwned(input: {
  stagedEvaluatorArtifactB64u?: string;
}): { stagedEvaluatorArtifactBytes: Uint8Array } {
  return {
    stagedEvaluatorArtifactBytes: base64UrlDecode(String(input.stagedEvaluatorArtifactB64u || '')),
  };
}

function createStubbedThresholdEd25519HssCeremonyServer(): {
  prepare: (body: Record<string, any>) => Promise<{
    ok: true;
    ceremonyHandle: string;
    preparedSession: Record<string, any>;
    clientOtOfferMessageB64u: string;
  }>;
  respond: (body: Record<string, any>) => Promise<{
    ok: true;
    contextBindingB64u: string;
    serverInputDeliveryB64u: string;
  }>;
  finalize: (body: Record<string, any>) => Promise<{
    ok: true;
    finalizedReport: Awaited<
      ReturnType<typeof finalizeThresholdEd25519HssServerCeremony>
    >['finalizedReport'];
    serverOutput: Awaited<
      ReturnType<typeof finalizeThresholdEd25519HssServerCeremony>
    >['serverOutput'];
  }>;
} {
  const ceremoniesByHandle = new Map<
    string,
    {
      operation: string;
      preparedSession: {
        contextBindingB64u: string;
        evaluatorDriverStateB64u: string;
      };
      preparedServerSession: {
        evaluatorDriverStateBytes: Uint8Array;
        garblerDriverStateBytes: Uint8Array;
      };
      serverInputs: {
        yRelayerBytes: Uint8Array;
        tauRelayerBytes: Uint8Array;
      };
    }
  >();
  let nextCeremonyId = 0;
  return {
    async prepare(body) {
      const [preparedServerSession, serverInputs] = await Promise.all([
        prepareThresholdEd25519HssServerSession({
          context: body.context,
        }),
        deriveFixtureThresholdEd25519HssServerInputs(body.context),
      ]);
      const preparedSession = {
        contextBindingB64u: preparedServerSession.contextBindingB64u,
        evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
      };
      const ceremonyHandle = `ceremony-${++nextCeremonyId}`;
      ceremoniesByHandle.set(ceremonyHandle, {
        operation: String(body.operation || '').trim(),
        preparedSession,
        preparedServerSession: {
          evaluatorDriverStateBytes: base64UrlDecode(
            preparedServerSession.evaluatorDriverStateB64u,
          ),
          garblerDriverStateBytes: base64UrlDecode(preparedServerSession.garblerDriverStateB64u),
        },
        serverInputs: {
          yRelayerBytes: base64UrlDecode(serverInputs.yRelayerB64u),
          tauRelayerBytes: base64UrlDecode(serverInputs.tauRelayerB64u),
        },
      });
      return {
        ok: true as const,
        ceremonyHandle,
        preparedSession,
        clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
      };
    },
    async respond(body) {
      const ceremonyHandle = String(body.ceremonyHandle || '').trim();
      const ceremony = ceremoniesByHandle.get(ceremonyHandle);
      if (!ceremony) {
        throw new Error(`missing prepared session for ceremony handle: ${ceremonyHandle}`);
      }
      const prepared = await prepareThresholdEd25519HssRoleSeparatedServerInputDelivery({
        operation: (ceremony.operation || 'warm_session_reconstruction') as
          | 'registration'
          | ThresholdEd25519HssSessionOperation,
        preparedServerSession: ceremony.preparedServerSession,
        expectedContextBindingB64u: ceremony.preparedSession.contextBindingB64u,
        clientRequest: body.clientRequest,
        serverInputs: ceremony.serverInputs,
      });
      return {
        ok: true as const,
        ...prepared.serverInputDelivery,
      };
    },
    async finalize(body) {
      const ceremonyHandle = String(body.ceremonyHandle || '').trim();
      const ceremony = ceremoniesByHandle.get(ceremonyHandle);
      if (!ceremony) {
        throw new Error(`missing prepared session for ceremony handle: ${ceremonyHandle}`);
      }
      ceremoniesByHandle.delete(ceremonyHandle);
      const finalized = await finalizeThresholdEd25519HssServerCeremony({
        operation:
          ceremony.operation === 'explicit_key_export'
            ? 'explicit_key_export'
            : 'warm_session_reconstruction',
        preparedSession: ceremony.preparedSession,
        preparedServerSession: ceremony.preparedServerSession,
        evaluationResult: storedHssEvaluationResultFromClientOwned(body.evaluationResult || {}),
        expectedContextBindingB64u: ceremony.preparedSession.contextBindingB64u,
      });
      return {
        ok: true as const,
        finalizedReport: finalized.finalizedReport,
        serverOutput: finalized.serverOutput,
      };
    },
  };
}

function installMemorySessionStorage(): {
  restore: () => void;
  storage: MemorySessionStorage;
} {
  const original = (globalThis as { sessionStorage?: Storage }).sessionStorage;
  const storage = new MemorySessionStorage();
  (
    globalThis as { sessionStorage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'> }
  ).sessionStorage = storage;
  return {
    storage,
    restore: () => {
      storage.clear();
      if (original) {
        (globalThis as { sessionStorage?: Storage }).sessionStorage = original;
      } else {
        delete (globalThis as { sessionStorage?: Storage }).sessionStorage;
      }
    },
  };
}

function withoutSessionStorage<T>(fn: () => T): T {
  const original = (globalThis as { sessionStorage?: Storage }).sessionStorage;
  delete (globalThis as { sessionStorage?: Storage }).sessionStorage;
  try {
    return fn();
  } finally {
    if (original) {
      (globalThis as { sessionStorage?: Storage }).sessionStorage = original;
    }
  }
}

function seedThresholdEd25519Session(args?: { xClientBaseB64u?: string }): void {
  upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: NEAR_ACCOUNT_ID,
    rpId: RP_ID,
    relayerUrl: RELAYER_URL,
    relayerKeyId: RELAYER_KEY_ID,
    participantIds: [...CONTEXT.participantIds],
    runtimePolicyScope: { ...RUNTIME_SCOPE },
    ...(String(args?.xClientBaseB64u || '').trim()
      ? { xClientBaseB64u: String(args?.xClientBaseB64u || '').trim() }
      : {}),
    thresholdSessionKind: 'jwt',
    thresholdSessionId: THRESHOLD_SESSION_ID,
    walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
    thresholdSessionAuthToken: THRESHOLD_SESSION_JWT,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 10,
    source: 'bootstrap',
  });
}

function seedReadyThresholdEd25519ClientPresign(publicKey: string): void {
  const expiresAtMs = Date.now() + 60_000;
  const payload: PrepareThresholdEd25519PresignPoolPayload = {
    kind: 'prepare_threshold_ed25519_presign_pool_v1',
    sessionKind: 'jwt',
    thresholdSessionAuthToken: THRESHOLD_SESSION_JWT,
    relayUrl: RELAYER_URL,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
    relayerKeyId: RELAYER_KEY_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearNetworkId: 'testnet',
    signerPublicKey: publicKey,
    participantIds: [...CONTEXT.participantIds],
    runtimePolicyScope: { ...RUNTIME_SCOPE },
    policy: {
      targetDepth: 2,
      lowWatermark: 1,
      maxAcceptedRefillCount: 8,
      ttlMs: 60_000,
    },
    requestTag: 'background_presign_pool_refill',
    generation: 1,
    clientPresigns: [
      {
        clientPresignId: 'client-presign-active-path-1',
        nonceHandle: 'nonce-handle-active-path-1',
        clientVerifyingShareB64u: 'client-verifying-share-active-path',
        clientCommitments: {
          hiding: 'client-hiding-active-path',
          binding: 'client-binding-active-path',
        },
      },
    ],
  };
  scheduleThresholdEd25519ClientPresignPoolRefill(payload, 1_000);
  applyThresholdEd25519PresignRefillResult({
    payload,
    nowMs: 1_100,
    result: {
      ok: true,
      kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
      generation: 1,
      accepted: [
        {
          presignId: 'server-presign-active-path-1',
          clientPresignId: 'client-presign-active-path-1',
          relayerCommitments: {
            hiding: 'relayer-hiding-active-path',
            binding: 'relayer-binding-active-path',
          },
          relayerVerifyingShareB64u: 'relayer-verifying-share-active-path',
          expiresAtMs,
        },
      ],
      rejectedClientPresignIds: [],
      expiresAtMs,
    },
  });
}

function makeThresholdKeyMaterial(publicKey: string) {
  return {
    nearAccountId: NEAR_ACCOUNT_ID,
    signerSlot: 1,
    kind: 'threshold_ed25519_v1' as const,
    publicKey,
    relayerKeyId: RELAYER_KEY_ID,
    keyVersion: CONTEXT.keyVersion,
    timestamp: Date.now(),
    participants: [
      { id: 1, role: 'client' },
      {
        id: 2,
        role: 'relayer',
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
      },
    ],
  };
}

function makeThresholdKeyMaterialRecord(publicKey: string) {
  return {
    profileId: 'profile-1',
    signerSlot: 1,
    chainIdKey: `near:${NEAR_ACCOUNT_ID}`,
    keyKind: 'threshold_share_v1',
    algorithm: 'ed25519',
    publicKey,
    payload: {
      relayerKeyId: RELAYER_KEY_ID,
      keyVersion: CONTEXT.keyVersion,
      participants: makeThresholdKeyMaterial(publicKey).participants,
    },
    timestamp: Date.now(),
    schemaVersion: 1,
  };
}

function makeIndexedDbThresholdDeps(publicKey: string) {
  const clientDB = {
    getLastProfileState: async () => ({ profileId: 'profile-1', activeSignerSlot: 1 }),
    resolveProfileAccountContext: async (accountRef: {
      chainIdKey: string;
      accountAddress: string;
    }) => ({ profileId: 'profile-1', accountRef }),
  };
  const keyMaterialStore = {
    getKeyMaterial: async () => makeThresholdKeyMaterialRecord(publicKey),
    storeKeyMaterial: async () => undefined,
  };
  return {
    ...clientDB,
    ...keyMaterialStore,
    clientDB,
    keyMaterialStore,
  };
}

function createNearEd25519ExportAvailableLanes() {
  const stored = getStoredThresholdEd25519SessionRecordByThresholdSessionId(THRESHOLD_SESSION_ID);
  const lane = stored
    ? {
        authMethod: stored.source === 'email_otp' ? ('email_otp' as const) : ('passkey' as const),
        curve: 'ed25519' as const,
        chain: 'near' as const,
        state: 'ready' as const,
        source: 'runtime_session_record' as const,
        walletSigningSessionId: String(stored.walletSigningSessionId || ''),
        thresholdSessionId: String(stored.thresholdSessionId || ''),
        remainingUses: stored.remainingUses,
        expiresAtMs: stored.expiresAtMs,
        updatedAtMs: stored.updatedAtMs,
      }
    : null;
  return {
    walletId: NEAR_ACCOUNT_ID,
    generation: Date.now(),
    ecdsa: {
      targets: [],
      lanesByTarget: {},
      candidatesByTarget: {},
    },
    lanes: {
      ed25519: {
        near: lane || {
          curve: 'ed25519' as const,
          chain: 'near' as const,
          state: 'missing' as const,
        },
      },
    },
    candidates: {
      ed25519: {
        near: lane ? [lane] : [],
      },
    },
  };
}

function createRecoveryPublicApiForTest(args: {
  touchConfirm: any;
  expectedPublicKey: string;
  exportWorkerCalls?: Array<Record<string, unknown>>;
}) {
  const recoveryPublicDeps: recoveryPublic.RecoveryPublicDeps = {
    laneSelection: {
      readPersistedAvailableSigningLanes: async () =>
        createNearEd25519ExportAvailableLanes() as any,
      readPersistedAvailableSigningLanesForTargets: async () =>
        createNearEd25519ExportAvailableLanes() as any,
      restorePasskeyPersistedSessionForSigning: async () => ({
        attempted: 0,
        restored: 0,
        deferred: 0,
      }),
      restoreEmailOtpPersistedSessionForSigning: async () => ({
        attempted: 0,
        restored: 0,
        deferred: 0,
      }),
    },
    nearSingleKeyHss: {
      keyMaterialStore: makeIndexedDbThresholdDeps(args.expectedPublicKey) as any,
      touchConfirm: args.touchConfirm,
      emailOtpSessions: {
        requestExportChallenge: async () => ({ challengeId: 'challenge-id' }),
        exportEd25519SeedWithAuthorization: async () => ({
          publicKey: args.expectedPublicKey,
          privateKey: `ed25519:${PRF_FIRST_B64U}`,
        }),
      },
      getSignerWorkerContext: () => ({
        requestWorkerOperation: async ({ request }: any) =>
          await invokeNearSignerWorkerDirect(request),
      }),
    },
    ecdsa: {
      sessionStore: {
        get: async () => null,
        set: async () => undefined,
        delete: async () => undefined,
        list: async () => [],
      } as any,
      touchConfirm: args.touchConfirm,
      getRpId: () => RP_ID,
      emailOtp: {
        requestExportChallenge: async () => ({ challengeId: 'challenge-id' }),
        exportEcdsaKeyWithFreshEmailOtpLane: async () => {
          throw new Error('ECDSA export is outside this test');
        },
        exportEcdsaKeyWithAuthorization: async () => {
          throw new Error('ECDSA export is outside this test');
        },
      },
      warmSessionPolicy: {
        getWarmSession: async () => null,
        resolveCurrentEcdsaRecord: async () => null,
      },
      getSignerWorkerContext: () => ({
        requestWorkerOperation: async ({ request }: any) =>
          await invokeNearSignerWorkerDirect(request),
      }),
    } as any,
    touchConfirm: args.touchConfirm,
    getTheme: () => 'dark',
    getSignerWorkerContext: () => ({
      requestWorkerOperation: async ({ request }: any) =>
        await invokeNearSignerWorkerDirect(request),
    }),
    privateKeyExportRecovery: {
      keyMaterialStore: makeIndexedDbThresholdDeps(args.expectedPublicKey) as any,
      relayerUrl: RELAYER_URL,
      getRpId: () => RP_ID,
      getTheme: () => 'dark',
      requestExportPrivateKeysWithUi: async (payload: Record<string, unknown>) => {
        args.exportWorkerCalls?.push(payload);
        return {
          ok: true as const,
          accountId: String(payload.nearAccountId || ''),
          exportedSchemes: ['ed25519'] as const,
        };
      },
    },
  };
  return {
    exportKeypairWithUI: (input: recoveryPublic.SigningEngineExportKeypairWithUIInput) =>
      recoveryPublic.exportKeypairWithUI(recoveryPublicDeps, input),
  };
}

async function maybeServeLocalNearSignerWasm(url: string): Promise<Response | null> {
  if (!url.startsWith('file://') || !url.endsWith('/wasm_signer_worker_bg.wasm')) {
    return null;
  }
  const bytes = await readFile(NEAR_SIGNER_WASM_URL);
  return new Response(bytes, {
    status: 200,
    headers: { 'Content-Type': 'application/wasm' },
  });
}

async function invokeNearSignerWorkerDirect(request: {
  sessionId?: string;
  type: number | NearSignerWorkerCustomRequestType;
  payload?: Record<string, unknown>;
}): Promise<any> {
  if (request.type === NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh) {
    return [];
  }

  if (
    request.type === WorkerRequestType.DeriveThresholdEd25519HssClientInputs ||
    request.type === WorkerRequestType.PrepareThresholdEd25519HssSession ||
    request.type === WorkerRequestType.PrepareThresholdEd25519HssClientRequest ||
    request.type === WorkerRequestType.DeriveThresholdEd25519HssClientOutputMask ||
    request.type === WorkerRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact ||
    request.type === WorkerRequestType.OpenThresholdEd25519HssClientOutput ||
    request.type === WorkerRequestType.OpenThresholdEd25519HssSeedOutput ||
    request.type === WorkerRequestType.BuildThresholdEd25519SeedExportArtifact
  ) {
    if (!hssClientSignerWasmInitializedForDirectWorkerTests) {
      initHssClientSignerWasmSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
      hssClientSignerWasmInitializedForDirectWorkerTests = true;
    }
    switch (request.type) {
      case WorkerRequestType.DeriveThresholdEd25519HssClientInputs:
        return {
          type: WorkerResponseType.DeriveThresholdEd25519HssClientInputsSuccess,
          payload: derive_threshold_ed25519_hss_client_inputs(request.payload || {}),
        };
      case WorkerRequestType.PrepareThresholdEd25519HssSession:
        return {
          type: WorkerResponseType.PrepareThresholdEd25519HssSessionSuccess,
          payload: threshold_ed25519_hss_prepare_session(request.payload || {}),
        };
      case WorkerRequestType.PrepareThresholdEd25519HssClientRequest:
        return {
          type: WorkerResponseType.PrepareThresholdEd25519HssClientRequestSuccess,
          payload: threshold_ed25519_hss_prepare_client_request(request.payload || {}),
        };
      case WorkerRequestType.DeriveThresholdEd25519HssClientOutputMask:
        return {
          type: WorkerResponseType.DeriveThresholdEd25519HssClientOutputMaskSuccess,
          payload: threshold_ed25519_hss_derive_client_output_mask(request.payload || {}),
        };
      case WorkerRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact:
        return {
          type: WorkerResponseType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactSuccess,
          payload: threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact(
            request.payload || {},
          ),
        };
      case WorkerRequestType.OpenThresholdEd25519HssClientOutput:
        return {
          type: WorkerResponseType.OpenThresholdEd25519HssClientOutputSuccess,
          payload: threshold_ed25519_hss_open_client_output(request.payload || {}),
        };
      case WorkerRequestType.OpenThresholdEd25519HssSeedOutput:
        return {
          type: WorkerResponseType.OpenThresholdEd25519HssSeedOutputSuccess,
          payload: threshold_ed25519_hss_open_seed_output(request.payload || {}),
        };
      case WorkerRequestType.BuildThresholdEd25519SeedExportArtifact:
        return {
          type: WorkerResponseType.BuildThresholdEd25519SeedExportArtifactSuccess,
          payload: threshold_ed25519_seed_export_artifact_from_seed(request.payload || {}),
        };
    }
  }

  if (!nearSignerWasmInitializedForDirectWorkerTests) {
    initNearSignerWasmSync({ module: readFileSync(NEAR_SIGNER_WASM_URL) });
    nearSignerWasmInitializedForDirectWorkerTests = true;
  }
  return handle_signer_message({
    type: request.type,
    payload: {
      sessionId: String(request.sessionId || '').trim(),
      ...(request.payload || {}),
    },
  });
}

const TEST_NEAR_SIGNER_WORKER_CTX = {
  requestWorkerOperation: async ({ request }: any) => await invokeNearSignerWorkerDirect(request),
};

async function flushMicrotasks(): Promise<void> {
  for (let index = 0; index < 20; index += 1) {
    await Promise.resolve();
  }
}

test.describe('threshold Ed25519 single-key HSS active path', () => {
  test('derives the client output mask from recoverable material and transcript context', async () => {
    const context = {
      ...CONTEXT,
      participantIds: [...CONTEXT.participantIds],
      contextBindingB64u: Buffer.alloc(32, 7).toString('base64url'),
      operation: 'warm_session_reconstruction' as const,
      relayerKeyId: RELAYER_KEY_ID,
    };

    const derived = await deriveThresholdEd25519HssClientOutputMaskB64u({
      clientRecoverableSecretB64u: PRF_FIRST_B64U,
      context,
      workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
    });
    const otherContextBinding = await deriveThresholdEd25519HssClientOutputMaskB64u({
      clientRecoverableSecretB64u: PRF_FIRST_B64U,
      context: {
        ...context,
        contextBindingB64u: Buffer.alloc(32, 8).toString('base64url'),
      },
      workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
    });
    const otherOperation = await deriveThresholdEd25519HssClientOutputMaskB64u({
      clientRecoverableSecretB64u: PRF_FIRST_B64U,
      context: {
        ...context,
        operation: 'explicit_key_export',
      },
      workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
    });

    expect(derived).toBe(EXPECTED_CLIENT_OUTPUT_MASK_B64U);
    expect(base64UrlDecode(derived)).toHaveLength(32);
    expect(otherContextBinding).not.toBe(derived);
    expect(otherOperation).not.toBe(derived);
  });

  test('validates client output projection policy before ceremony start', () => {
    expect(() =>
      validateThresholdEd25519HssOutputProjectionPolicy({
        kind: 'trusted-server-projection',
      } as any),
    ).toThrow(/Unsupported Ed25519 HSS output projection policy/);
    expect(() =>
      validateThresholdEd25519HssOutputProjectionPolicy({
        kind: 'client-masked-projection',
        clientRecoverableSecretB64u: PRF_FIRST_B64U,
      }),
    ).not.toThrow();
    expect(() =>
      validateThresholdEd25519HssOutputProjectionPolicy({
        kind: 'client-masked-projection-raw-mask',
        clientOutputMaskB64u: Buffer.alloc(32, 0x5a).toString('base64url'),
      } as any),
    ).toThrow(/Unsupported Ed25519 HSS output projection policy/);

    expect(() =>
      validateThresholdEd25519HssOutputProjectionPolicy({
        kind: 'client-masked-projection',
        clientRecoverableSecretB64u: '',
      }),
    ).toThrow(/clientRecoverableSecretB64u/);
  });

  test('forwards required client output mask only through client worker calls', async () => {
    const requests: any[] = [];
    const workerCtx = {
      requestWorkerOperation: async ({ request }: any) => {
        requests.push(request);
        switch (request.type) {
          case WorkerRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact:
            return {
              type: WorkerResponseType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactSuccess,
              payload: {
                contextBindingB64u: 'ctx',
                stagedEvaluatorArtifactB64u: 'artifact',
              },
            };
          case WorkerRequestType.OpenThresholdEd25519HssClientOutput:
            return {
              type: WorkerResponseType.OpenThresholdEd25519HssClientOutputSuccess,
              payload: {
                contextBindingB64u: 'ctx',
                xClientBaseB64u: 'client-base',
              },
            };
          default:
            throw new Error(`unexpected worker request type ${request.type}`);
        }
      },
    };

    await expect(
      buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm({
        preparedSession: { evaluatorDriverStateB64u: 'evaluator-state' },
        clientRequest: {
          clientRequestMessageB64u: 'client-request',
          evaluatorOtStateB64u: 'evaluator-ot-state',
          sessionResidence: 'worker_handle',
          workerSessionHandle: 'worker-session',
        },
        serverInputDelivery: { serverInputDeliveryB64u: 'server-input-delivery' },
        clientOutputMaskB64u: Buffer.alloc(31, 0x5a).toString('base64url'),
        workerCtx: workerCtx as any,
      }),
    ).rejects.toThrow(/clientOutputMaskB64u must decode to 32 bytes/);
    await expect(
      openThresholdEd25519HssClientOutputWasm({
        preparedSession: { evaluatorDriverStateB64u: 'evaluator-state' },
        finalizedReport: { clientOutputMessageB64u: 'client-output' },
        clientOutputMaskB64u: Buffer.alloc(31, 0x5a).toString('base64url'),
        workerCtx: workerCtx as any,
      }),
    ).rejects.toThrow(/clientOutputMaskB64u must decode to 32 bytes/);

    await buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm({
      preparedSession: { evaluatorDriverStateB64u: 'evaluator-state' },
      clientRequest: {
        clientRequestMessageB64u: 'client-request',
        evaluatorOtStateB64u: 'evaluator-ot-state',
        sessionResidence: 'worker_handle',
        workerSessionHandle: 'worker-session',
      },
      serverInputDelivery: { serverInputDeliveryB64u: 'server-input-delivery' },
      clientOutputMaskB64u: TEST_CLIENT_OUTPUT_MASK_B64U,
      workerCtx: workerCtx as any,
    });
    await openThresholdEd25519HssClientOutputWasm({
      preparedSession: { evaluatorDriverStateB64u: 'evaluator-state' },
      finalizedReport: { clientOutputMessageB64u: 'client-output' },
      clientOutputMaskB64u: TEST_CLIENT_OUTPUT_MASK_B64U,
      workerCtx: workerCtx as any,
    });

    expect(requests).toHaveLength(2);
    expect(requests[0].payload).toMatchObject({
      sessionSource: 'worker_handle',
      workerSessionHandle: 'worker-session',
      clientRequestMessageB64u: 'client-request',
      evaluatorOtStateB64u: 'evaluator-ot-state',
      serverInputDeliveryB64u: 'server-input-delivery',
      clientOutputMaskB64u: TEST_CLIENT_OUTPUT_MASK_B64U,
    });
    expect(requests[1].payload).toMatchObject({
      sessionSource: 'serialized_state',
      evaluatorDriverStateB64u: 'evaluator-state',
      clientOutputMessageB64u: 'client-output',
      clientOutputMaskB64u: TEST_CLIENT_OUTPUT_MASK_B64U,
    });
  });

  test('browser HSS wasm exports do not expose clear relayer roots', async () => {
    const context = {
      signingRootId: CONTEXT.signingRootId,
      nearAccountId: NEAR_ACCOUNT_ID,
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion: CONTEXT.keyVersion,
      participantIds: [...CONTEXT.participantIds],
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
    };

    const preparedSession = await prepareThresholdEd25519HssSessionWasm({
      context,
      workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
    });
    const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
      sessionId: `${THRESHOLD_SESSION_ID}:wasm-boundary-inputs`,
      ...context,
      prfFirstB64u: PRF_FIRST_B64U,
      workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
    });
    const preparedServerSession = await prepareThresholdEd25519HssServerSession({ context });
    const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
      evaluatorDriverStateB64u: preparedSession.evaluatorDriverStateB64u,
      clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
      clientInputs,
      workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
    });
    const serverInputs = await deriveFixtureThresholdEd25519HssServerInputs(context);
    for (const payload of [
      JSON.stringify(preparedSession),
      JSON.stringify(clientInputs),
      JSON.stringify(clientRequest),
    ]) {
      expect(payload.includes(serverInputs.yRelayerB64u)).toBeFalsy();
      expect(payload.includes(serverInputs.tauRelayerB64u)).toBeFalsy();
    }
  });

  test('preserves xClientBaseB64u when rebuilding the same auth session record', async () => {
    const { restore } = installMemorySessionStorage();
    const expectedXClientBaseB64u = Buffer.alloc(32, 29).toString('base64url');

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session({ xClientBaseB64u: expectedXClientBaseB64u });

    try {
      persistWarmSessionEd25519Capability({
        kind: 'jwt_passkey',
        sessionKind: 'jwt',
        nearAccountId: NEAR_ACCOUNT_ID,
        rpId: RP_ID,
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        runtimePolicyScope: { ...RUNTIME_SCOPE },
        participantIds: [...CONTEXT.participantIds],
        sessionId: THRESHOLD_SESSION_ID,
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 5,
        xClientBaseB64u: expectedXClientBaseB64u,
        jwt: THRESHOLD_SESSION_JWT,
        source: 'bootstrap',
      });

      const stored =
        getStoredThresholdEd25519SessionRecordByThresholdSessionId(THRESHOLD_SESSION_ID);
      expect(String(stored?.xClientBaseB64u || '')).toBe(expectedXClientBaseB64u);
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('keeps threshold Ed25519 session state in memory when sessionStorage is unavailable', async () => {
    clearAllStoredThresholdEd25519SessionRecords();

    try {
      const seeded = withoutSessionStorage(() =>
        upsertStoredThresholdEd25519SessionRecord({
          nearAccountId: NEAR_ACCOUNT_ID,
          rpId: RP_ID,
          relayerUrl: RELAYER_URL,
          relayerKeyId: RELAYER_KEY_ID,
          participantIds: [...CONTEXT.participantIds],
          runtimePolicyScope: { ...RUNTIME_SCOPE },
          thresholdSessionKind: 'jwt',
          thresholdSessionId: THRESHOLD_SESSION_ID,
          thresholdSessionAuthToken: THRESHOLD_SESSION_JWT,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 10,
          source: 'bootstrap',
        }),
      );

      expect(seeded).not.toBeNull();

      const loaded = withoutSessionStorage(() =>
        getStoredThresholdEd25519SessionRecordByThresholdSessionId(THRESHOLD_SESSION_ID),
      );
      expect(loaded?.thresholdSessionId).toBe(THRESHOLD_SESSION_ID);
      expect(loaded?.runtimePolicyScope?.orgId).toBe(RUNTIME_SCOPE.orgId);

      const persisted = withoutSessionStorage(() =>
        persistStoredThresholdEd25519SessionClientBase({
          thresholdSessionId: THRESHOLD_SESSION_ID,
          xClientBaseB64u: Buffer.alloc(32, 31).toString('base64url'),
        }),
      );
      expect(String(persisted?.xClientBaseB64u || '')).toBe(
        Buffer.alloc(32, 31).toString('base64url'),
      );
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('reconstructs and persists xClientBaseB64u through the real HSS ceremony', async () => {
    const { restore } = installMemorySessionStorage();
    const originalFetch = globalThis.fetch;
    let serverOutputXRelayerBaseB64u = '';
    const hssCeremonyServer = createStubbedThresholdEd25519HssCeremonyServer();

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session();

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) {
        return wasmResponse;
      }
      const body = JSON.parse(String(init?.body || '{}')) as Record<string, any>;

      if (url.endsWith('/threshold-ed25519/hss/prepare')) {
        return new Response(JSON.stringify(await hssCeremonyServer.prepare(body)), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/respond')) {
        return new Response(JSON.stringify(await hssCeremonyServer.respond(body)), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/finalize')) {
        const finalized = await hssCeremonyServer.finalize(body);
        serverOutputXRelayerBaseB64u = String(finalized.serverOutput.xRelayerBaseB64u || '').trim();
        return new Response(
          JSON.stringify({
            ok: true,
            finalizedReport: finalized.finalizedReport,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }

      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

    try {
      const xClientBaseB64u = await ensureThresholdEd25519HssClientBase({
        ctx: {
          requestWorkerOperation: async ({ request }: any) =>
            await invokeNearSignerWorkerDirect(request),
        } as any,
        thresholdSessionId: THRESHOLD_SESSION_ID,
        thresholdSessionAuthToken: THRESHOLD_SESSION_JWT,
        signingRootId: SIGNING_ROOT_ID,
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        keyVersion: CONTEXT.keyVersion,
        participantIds: [...CONTEXT.participantIds],
        prfFirstB64u: PRF_FIRST_B64U,
        persistClientBase: (xClientBaseB64u: string) =>
          Boolean(
            persistStoredThresholdEd25519SessionClientBase({
              thresholdSessionId: THRESHOLD_SESSION_ID,
              xClientBaseB64u,
            }),
          ),
      });

      expect(String(xClientBaseB64u || '')).not.toBe('');
      expect(serverOutputXRelayerBaseB64u).not.toBe('');

      const stored =
        getStoredThresholdEd25519SessionRecordByThresholdSessionId(THRESHOLD_SESSION_ID);
      expect(String(stored?.xClientBaseB64u || '')).toBe(String(xClientBaseB64u || ''));

      const derived = await deriveThresholdEd25519HssPublicKey({
        xClientBaseB64u: String(xClientBaseB64u || ''),
        xRelayerBaseB64u: serverOutputXRelayerBaseB64u,
      });
      expect(String(derived.publicKeyB64u || '')).not.toBe('');
    } finally {
      globalThis.fetch = originalFetch;
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('forwards only xClientBaseB64u into the live signer worker payload', async () => {
    const { restore } = installMemorySessionStorage();
    const originalFetch = globalThis.fetch;
    const seededXClientBaseB64u = Buffer.alloc(32, 23).toString('base64url');

    clearAllStoredThresholdEd25519SessionRecords();
    clearAllThresholdEd25519ClientPresigns();
    seedThresholdEd25519Session({ xClientBaseB64u: seededXClientBaseB64u });

    persistWarmSessionEd25519Capability({
      kind: 'jwt_passkey',
      sessionKind: 'jwt',
      nearAccountId: NEAR_ACCOUNT_ID,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      relayerKeyId: RELAYER_KEY_ID,
      runtimePolicyScope: { ...RUNTIME_SCOPE },
      participantIds: [...CONTEXT.participantIds],
      sessionId: THRESHOLD_SESSION_ID,
      walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 5,
      xClientBaseB64u: seededXClientBaseB64u,
      jwt: THRESHOLD_SESSION_JWT,
      source: 'bootstrap',
    });

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) {
        return wasmResponse;
      }
      if (url.endsWith('/threshold-ed25519/healthz')) {
        return new Response(JSON.stringify({ ok: true, configured: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

    const dummyCredential = {
      id: 'cred-id',
      rawId: 'cred-rawid-b64u',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: 'clientDataJSON-b64u',
        authenticatorData: 'authenticatorData-b64u',
        signature: 'signature-b64u',
        userHandle: '',
      },
      clientExtensionResults: {
        prf: { results: { first: PRF_FIRST_B64U, second: undefined } },
      },
    };

    let capturedPayload: Record<string, any> | null = null;
    const workerRequestTypes: unknown[] = [];

    try {
      const result = await signTransactionsWithActions({
        ctx: {
          nearKeyMaterialStore: makeIndexedDbThresholdDeps('ed25519:threshold-public-key'),
          nearContextFixture: {
            initializeUser: () => undefined,
          },
          touchIdPrompt: {
            getRpId: () => RP_ID,
          },
          relayerUrl: RELAYER_URL,
          touchConfirm: {
            getWarmSessionStatus: async () => ({
              ok: false as const,
              code: 'not_found',
              message: 'warm-session status missing',
            }),
            claimWarmSessionMaterial: async () => ({
              ok: true as const,
              prfFirstB64u: PRF_FIRST_B64U,
              remainingUses: 4,
              expiresAtMs: Date.now() + 60_000,
            }),
            clearVolatileWarmSessionMaterial: async () => undefined,
            orchestrateSigningConfirmation: async () => ({
              intentDigest: 'intent-digest-b64u',
              transactionContext: {
                nearPublicKeyStr: 'ed25519:threshold-public-key',
                nextNonce: '1',
                txBlockHeight: '1',
                txBlockHash: 'blockhash',
                accessKeyInfo: { nonce: 0 },
              },
              credential: dummyCredential,
            }),
          },
          requestWorkerOperation: async ({ request }: any) => {
            workerRequestTypes.push(request?.type);
            if (
              request?.type ===
              NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh
            ) {
              return [];
            }
            capturedPayload = request?.payload || null;
            return {
              type: WorkerResponseType.SignTransactionsWithActionsSuccess,
              payload: {
                success: true,
                signedTransactions: [
                  { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
                ],
                logs: [],
              },
            };
          },
        } as any,
        nearAccount: { kind: 'named', accountId: NEAR_ACCOUNT_ID },
        transactions: [
          {
            receiverId: NEAR_ACCOUNT_ID,
            actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
          } as TransactionInputWasm,
        ],
        rpcCall: { nearAccountId: NEAR_ACCOUNT_ID, nearRpcUrl: 'https://rpc.testnet.test' },
        signerSlot: 1,
        sessionId: THRESHOLD_SESSION_ID,
        ...buildTestWarmSigningAuth(),
      });

      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(1);

      const thresholdPayload = (capturedPayload as Record<string, any> | null)?.threshold || {};
      expect(String(thresholdPayload.xClientBaseB64u || '')).toBe(
        Buffer.alloc(32, 23).toString('base64url'),
      );
      expect(
        Object.prototype.hasOwnProperty.call(thresholdPayload, 'clientVerifyingShareB64u'),
      ).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(thresholdPayload, 'keyVersion')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(capturedPayload || {}, 'prfFirstB64u')).toBe(
        false,
      );
      expect(Object.prototype.hasOwnProperty.call(capturedPayload || {}, 'wrapKeySalt')).toBe(
        false,
      );
      expect(workerRequestTypes).toContain(
        NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh,
      );
      expect(workerRequestTypes).toContain(WorkerRequestType.SignTransactionsWithActions);
    } finally {
      globalThis.fetch = originalFetch;
      clearAllThresholdEd25519ClientPresigns();
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('uses finalize-and-dispatch for a single transaction when the Ed25519 presign pool hits', async () => {
    const { restore } = installMemorySessionStorage();
    const originalFetch = globalThis.fetch;
    const seededXClientBaseB64u = Buffer.alloc(32, 23).toString('base64url');
    const signingDigestB64u = Buffer.alloc(32, 13).toString('base64url');
    const signerPublicKey = 'ed25519:threshold-public-key';

    clearAllStoredThresholdEd25519SessionRecords();
    clearAllThresholdEd25519ClientPresigns();
    seedThresholdEd25519Session({ xClientBaseB64u: seededXClientBaseB64u });
    seedReadyThresholdEd25519ClientPresign(signerPublicKey);

    persistWarmSessionEd25519Capability({
      kind: 'jwt_passkey',
      sessionKind: 'jwt',
      nearAccountId: NEAR_ACCOUNT_ID,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      relayerKeyId: RELAYER_KEY_ID,
      runtimePolicyScope: { ...RUNTIME_SCOPE },
      participantIds: [...CONTEXT.participantIds],
      sessionId: THRESHOLD_SESSION_ID,
      walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 5,
      xClientBaseB64u: seededXClientBaseB64u,
      jwt: THRESHOLD_SESSION_JWT,
      source: 'bootstrap',
    });

    const fetchCalls: Array<{ url: string; body: Record<string, any> }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) {
        return wasmResponse;
      }
      if (url.endsWith('/threshold-ed25519/healthz')) {
        return new Response(JSON.stringify({ ok: true, configured: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      const body = JSON.parse(String(init?.body || '{}')) as Record<string, any>;
      fetchCalls.push({ url, body });
      if (url.endsWith('/threshold-ed25519/sign/finalize-and-dispatch')) {
        return new Response(
          JSON.stringify({
            ok: true,
            kind: 'threshold_ed25519_dispatched_near_tx_result_v1',
            operationId: body.operation?.operationId,
            budgetState: 'consumed',
            remainingSigningUses: 4,
            signatureB64u: 'signature-b64u',
            signerPublicKey,
            signedTransactionBorshB64u: 'signed-tx-borsh',
            transactionHash: 'pool-hit-tx-hash',
            rpcResult: { status: 'ok' },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url.endsWith('/threshold-ed25519/presign/refill')) {
        return new Response(
          JSON.stringify({
            ok: true,
            kind: 'threshold_ed25519_presign_refill_response_v1',
            accepted: [],
            rejectedClientPresignIds: [],
            serverTimeMs: Date.now(),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

    const dummyCredential = {
      id: 'cred-id',
      rawId: 'cred-rawid-b64u',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: 'clientDataJSON-b64u',
        authenticatorData: 'authenticatorData-b64u',
        signature: 'signature-b64u',
        userHandle: '',
      },
      clientExtensionResults: {
        prf: { results: { first: PRF_FIRST_B64U, second: undefined } },
      },
    };

    const workerRequestTypes: unknown[] = [];

    try {
      const result = await signTransactionsWithActions({
        ctx: {
          nearKeyMaterialStore: makeIndexedDbThresholdDeps(signerPublicKey),
          nearContextFixture: {
            initializeUser: () => undefined,
          },
          touchIdPrompt: {
            getRpId: () => RP_ID,
          },
          relayerUrl: RELAYER_URL,
          touchConfirm: {
            getWarmSessionStatus: async () => ({
              ok: false as const,
              code: 'not_found',
              message: 'warm-session status missing',
            }),
            claimWarmSessionMaterial: async () => ({
              ok: true as const,
              prfFirstB64u: PRF_FIRST_B64U,
              remainingUses: 4,
              expiresAtMs: Date.now() + 60_000,
            }),
            clearVolatileWarmSessionMaterial: async () => undefined,
            orchestrateSigningConfirmation: async () => ({
              intentDigest: 'intent-digest-b64u',
              transactionContext: {
                nearPublicKeyStr: signerPublicKey,
                nextNonce: '1',
                txBlockHeight: '1',
                txBlockHash: 'blockhash',
                accessKeyInfo: { nonce: 0 },
              },
              credential: dummyCredential,
            }),
          },
          requestWorkerOperation: async ({ request }: any) => {
            workerRequestTypes.push(request?.type);
            if (
              request?.type ===
              NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh
            ) {
              return [
                {
                  unsignedTransactionBorshB64u: 'unsigned-tx-borsh',
                  signingDigestB64u,
                },
              ];
            }
            if (
              request?.type === NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSign
            ) {
              expect(request.payload.clientNonceHandleB64u).toBe('nonce-handle-active-path-1');
              expect(request.payload.signingDigestB64u).toBe(signingDigestB64u);
              return { clientSignatureShareB64u: 'client-share' };
            }
            if (
              request?.type ===
              NearSignerWorkerCustomRequestType.ThresholdEd25519DecodeSignedNearTxBorsh
            ) {
              return {
                signedTransaction: {
                  transaction: { signerId: NEAR_ACCOUNT_ID },
                  signature: { keyType: 0, signatureData: [1] },
                  borshBytes: [2],
                },
                transactionHash: 'pool-hit-tx-hash',
              };
            }
            if (
              request?.type ===
              NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreate
            ) {
              return {
                clientNonceHandleB64u: `refill-${workerRequestTypes.length}`,
                clientVerifyingShareB64u: 'client-verifying-share-active-path',
                clientCommitments: {
                  hiding: `refill-hiding-${workerRequestTypes.length}`,
                  binding: `refill-binding-${workerRequestTypes.length}`,
                },
              };
            }
            if (
              request?.type === NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn
            ) {
              return { burned: true };
            }
            if (request?.type === WorkerRequestType.SignTransactionsWithActions) {
              throw new Error('pool hit must not call the two-RTT worker signing path');
            }
            throw new Error(`unexpected worker request in pool-hit test: ${String(request?.type)}`);
          },
        } as any,
        nearAccount: { kind: 'named', accountId: NEAR_ACCOUNT_ID },
        transactions: [
          {
            receiverId: NEAR_ACCOUNT_ID,
            actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
          } as TransactionInputWasm,
        ],
        rpcCall: { nearAccountId: NEAR_ACCOUNT_ID, nearRpcUrl: 'https://rpc.testnet.test' },
        signerSlot: 1,
        sessionId: THRESHOLD_SESSION_ID,
        ...buildTestWarmSigningAuth(),
      });

      await flushMicrotasks();

      expect(result).toHaveLength(1);
      expect(result[0].signedTransaction.serverDispatch).toEqual({
        transactionHash: 'pool-hit-tx-hash',
        rpcResult: { status: 'ok' },
      });
      expect(workerRequestTypes).toContain(
        NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh,
      );
      expect(workerRequestTypes).toContain(
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSign,
      );
      expect(workerRequestTypes).toContain(
        NearSignerWorkerCustomRequestType.ThresholdEd25519DecodeSignedNearTxBorsh,
      );
      expect(workerRequestTypes).not.toContain(WorkerRequestType.SignTransactionsWithActions);
      const finalizeCall = fetchCalls.find((call) =>
        call.url.endsWith('/threshold-ed25519/sign/finalize-and-dispatch'),
      );
      expect(finalizeCall?.body).toMatchObject({
        kind: 'threshold_ed25519_finalize_and_dispatch_near_tx_v1',
        presignId: 'server-presign-active-path-1',
        requestIntegrityHash: expect.stringMatching(/^sha256:/),
        transactions: [
          {
            nearAccountId: NEAR_ACCOUNT_ID,
            receiverId: NEAR_ACCOUNT_ID,
            actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
          },
        ],
        unsignedTransactionBorshB64u: 'unsigned-tx-borsh',
        signingDigestB64u,
        clientSignatureShareB64u: 'client-share',
        dispatch: { kind: 'near_rpc_configured_default_v1' },
      });
    } finally {
      globalThis.fetch = originalFetch;
      clearAllThresholdEd25519ClientPresigns();
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('repairs missing relayer share state by forcing one HSS rebuild and retrying the sign', async () => {
    const { restore } = installMemorySessionStorage();
    const originalFetch = globalThis.fetch;
    let hssFinalizeCalls = 0;
    let signWorkerCalls = 0;
    const hssCeremonyServer = createStubbedThresholdEd25519HssCeremonyServer();
    const seededXClientBaseB64u = Buffer.alloc(32, 23).toString('base64url');

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session({ xClientBaseB64u: seededXClientBaseB64u });

    persistWarmSessionEd25519Capability({
      kind: 'jwt_passkey',
      sessionKind: 'jwt',
      nearAccountId: NEAR_ACCOUNT_ID,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      relayerKeyId: RELAYER_KEY_ID,
      runtimePolicyScope: { ...RUNTIME_SCOPE },
      participantIds: [...CONTEXT.participantIds],
      sessionId: THRESHOLD_SESSION_ID,
      walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 5,
      xClientBaseB64u: seededXClientBaseB64u,
      jwt: THRESHOLD_SESSION_JWT,
      source: 'bootstrap',
    });

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) {
        return wasmResponse;
      }
      if (url.endsWith('/threshold-ed25519/healthz')) {
        return new Response(JSON.stringify({ ok: true, configured: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      const body = JSON.parse(String(init?.body || '{}')) as Record<string, any>;

      if (url.endsWith('/threshold-ed25519/hss/prepare')) {
        return new Response(JSON.stringify(await hssCeremonyServer.prepare(body)), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/respond')) {
        return new Response(JSON.stringify(await hssCeremonyServer.respond(body)), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/finalize')) {
        hssFinalizeCalls += 1;
        const finalized = await hssCeremonyServer.finalize(body);
        return new Response(
          JSON.stringify({
            ok: true,
            finalizedReport: finalized.finalizedReport,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }

      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

    const dummyCredential = {
      id: 'cred-id',
      rawId: 'cred-rawid-b64u',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: 'clientDataJSON-b64u',
        authenticatorData: 'authenticatorData-b64u',
        signature: 'signature-b64u',
        userHandle: '',
      },
      clientExtensionResults: {
        prf: { results: { first: PRF_FIRST_B64U, second: undefined } },
      },
    };

    try {
      const result = await signTransactionsWithActions({
        ctx: {
          nearKeyMaterialStore: makeIndexedDbThresholdDeps('ed25519:threshold-public-key'),
          nearContextFixture: {
            initializeUser: () => undefined,
          },
          touchIdPrompt: {
            getRpId: () => RP_ID,
          },
          relayerUrl: RELAYER_URL,
          touchConfirm: {
            getWarmSessionStatus: async () => ({
              ok: false as const,
              code: 'not_found',
              message: 'warm-session status missing',
            }),
            claimWarmSessionMaterial: async () => ({
              ok: true as const,
              prfFirstB64u: PRF_FIRST_B64U,
              remainingUses: 4,
              expiresAtMs: Date.now() + 60_000,
            }),
            clearVolatileWarmSessionMaterial: async () => undefined,
            orchestrateSigningConfirmation: async () => ({
              intentDigest: 'intent-digest-b64u',
              transactionContext: {
                nearPublicKeyStr: 'ed25519:threshold-public-key',
                nextNonce: '1',
                txBlockHeight: '1',
                txBlockHash: 'blockhash',
                accessKeyInfo: { nonce: 0 },
              },
              credential: dummyCredential,
            }),
          },
          requestWorkerOperation: async ({ request }: any) => {
            if (request?.type === WorkerRequestType.SignTransactionsWithActions) {
              signWorkerCalls += 1;
              if (signWorkerCalls === 1) {
                throw new Error(
                  '{"ok":false,"code":"missing_key","message":"Unknown relayerKeyId; bootstrap Ed25519 key material must be persisted"}',
                );
              }
              return {
                type: WorkerResponseType.SignTransactionsWithActionsSuccess,
                payload: {
                  success: true,
                  signedTransactions: [
                    { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
                  ],
                  logs: [],
                },
              };
            }
            return await invokeNearSignerWorkerDirect(request);
          },
        } as any,
        nearAccount: { kind: 'named', accountId: NEAR_ACCOUNT_ID },
        transactions: [
          {
            receiverId: NEAR_ACCOUNT_ID,
            actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
          } as TransactionInputWasm,
        ],
        rpcCall: { nearAccountId: NEAR_ACCOUNT_ID, nearRpcUrl: 'https://rpc.testnet.test' },
        signerSlot: 1,
        sessionId: THRESHOLD_SESSION_ID,
        ...buildTestWarmSigningAuth(),
      });

      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(1);
      expect(signWorkerCalls).toBe(2);
      expect(hssFinalizeCalls).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('prefers single-key HSS seed export from the canonical threshold session with fresh authorization', async () => {
    const { restore } = installMemorySessionStorage();
    const originalFetch = globalThis.fetch;
    const exportWorkerCalls: Array<Record<string, unknown>> = [];
    const userConfirmationCalls: Array<Record<string, any>> = [];
    const hssCeremonyServer = createStubbedThresholdEd25519HssCeremonyServer();

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session();

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) {
        return wasmResponse;
      }
      const body = JSON.parse(String(init?.body || '{}')) as Record<string, any>;

      if (url.endsWith('/threshold-ed25519/hss/prepare')) {
        return new Response(JSON.stringify(await hssCeremonyServer.prepare(body)), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/respond')) {
        return new Response(JSON.stringify(await hssCeremonyServer.respond(body)), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/finalize')) {
        const finalized = await hssCeremonyServer.finalize(body);
        return new Response(
          JSON.stringify({
            ok: true,
            finalizedReport: finalized.finalizedReport,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }

      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

    try {
      const preparedServerSession = await prepareThresholdEd25519HssServerSession({
        context: {
          signingRootId: CONTEXT.signingRootId,
          nearAccountId: NEAR_ACCOUNT_ID,
          keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
          keyVersion: CONTEXT.keyVersion,
          participantIds: [...CONTEXT.participantIds],
          derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
        },
      });
      const preparedSession = {
        contextBindingB64u: preparedServerSession.contextBindingB64u,
        evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
      };
      const storedPreparedServerSession = {
        preparedSessionHandle: String(preparedServerSession.preparedSessionHandle || '').trim(),
        evaluatorDriverStateBytes: base64UrlDecode(preparedServerSession.evaluatorDriverStateB64u),
        garblerDriverStateBytes: base64UrlDecode(preparedServerSession.garblerDriverStateB64u),
      };
      const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
        sessionId: `${THRESHOLD_SESSION_ID}:single-key-hss-export-test-inputs`,
        signingRootId: CONTEXT.signingRootId,
        nearAccountId: NEAR_ACCOUNT_ID,
        keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
        keyVersion: CONTEXT.keyVersion,
        participantIds: [...CONTEXT.participantIds],
        derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
        prfFirstB64u: PRF_FIRST_B64U,
        workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
      });
      const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
        evaluatorDriverStateB64u: preparedSession.evaluatorDriverStateB64u,
        clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
        clientInputs,
        workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
      });
      const serverInputs = await deriveFixtureThresholdEd25519HssServerInputs({
        signingRootId: CONTEXT.signingRootId,
        nearAccountId: NEAR_ACCOUNT_ID,
        keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
        keyVersion: CONTEXT.keyVersion,
        participantIds: [...CONTEXT.participantIds],
        derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      });
      const storedServerInputs = {
        yRelayerBytes: base64UrlDecode(serverInputs.yRelayerB64u),
        tauRelayerBytes: base64UrlDecode(serverInputs.tauRelayerB64u),
      };
      const prepared = await prepareThresholdEd25519HssRoleSeparatedServerInputDelivery({
        operation: 'explicit_key_export',
        preparedServerSession: storedPreparedServerSession,
        expectedContextBindingB64u: preparedSession.contextBindingB64u,
        clientRequest: {
          clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
        },
        serverInputs: storedServerInputs,
      });
      const evaluationResult = await buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm(
        {
          preparedSession,
          clientRequest,
          serverInputDelivery: prepared.serverInputDelivery,
          clientOutputMaskB64u: TEST_CLIENT_OUTPUT_MASK_B64U,
          workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
        },
      );
      const finalized = await finalizeThresholdEd25519HssServerCeremony({
        operation: 'explicit_key_export',
        preparedSession,
        preparedServerSession: storedPreparedServerSession,
        evaluationResult: storedHssEvaluationResultFromClientOwned(evaluationResult),
        expectedContextBindingB64u: preparedSession.contextBindingB64u,
      });
      const clientOutput = await openThresholdEd25519HssClientOutputWasm({
        preparedSession,
        finalizedReport: finalized.finalizedReport,
        clientOutputMaskB64u: TEST_CLIENT_OUTPUT_MASK_B64U,
        workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
      });
      const derivedPublicKey = await deriveThresholdEd25519HssPublicKey({
        xClientBaseB64u: clientOutput.xClientBaseB64u,
        xRelayerBaseB64u: finalized.serverOutput.xRelayerBaseB64u,
      });
      const expectedPublicKey = `ed25519:${bs58.encode(
        Buffer.from(String(derivedPublicKey.publicKeyB64u || ''), 'base64url'),
      )}`;

      const touchConfirm = {
        getWarmSessionStatus: async () => {
          throw new Error('warm-session status should not be consulted during export');
        },
        claimWarmSessionMaterial: async () => {
          throw new Error('warm-session material should not be consumed during export');
        },
        requestUserConfirmation: async (request: Record<string, any>) => {
          userConfirmationCalls.push(request);
          if (request.type === 'decryptPrivateKeyWithPrf') {
            return buildExportAuthorizationDecision(String(request.requestId || ''));
          }
          request.payload?.onLifecycle?.('opened');
          return { requestId: String(request.requestId || ''), confirmed: true };
        },
      };
      const recovery = createRecoveryPublicApiForTest({
        touchConfirm,
        expectedPublicKey,
        exportWorkerCalls,
      });

      const result = await recovery.exportKeypairWithUI({
        kind: 'near',
        nearAccount: { kind: 'named', accountId: NEAR_ACCOUNT_ID },
        options: {
          chain: 'near',
          variant: 'drawer',
        },
      } as any);

      expect(result).toEqual({
        accountId: NEAR_ACCOUNT_ID,
        exportedSchemes: ['ed25519'],
      });
      expect(exportWorkerCalls).toHaveLength(0);
      expect(userConfirmationCalls[0]?.type).toBe('decryptPrivateKeyWithPrf');
      const privateKeyViewerCalls = userConfirmationCalls.filter(
        (entry) => entry.type === 'showSecurePrivateKeyUi',
      );
      expect(privateKeyViewerCalls.length).toBeGreaterThanOrEqual(1);
      expect(userConfirmationCalls[0]).toMatchObject({
        summary: {
          accountId: NEAR_ACCOUNT_ID,
          publicKey: expectedPublicKey,
        },
      });
      const finalPrivateKeyViewerCall = privateKeyViewerCalls[privateKeyViewerCalls.length - 1];
      expect(finalPrivateKeyViewerCall).toMatchObject({
        payload: {
          nearAccountId: NEAR_ACCOUNT_ID,
          publicKey: expectedPublicKey,
          variant: 'drawer',
          theme: 'dark',
        },
      });
    } finally {
      globalThis.fetch = originalFetch;
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('fails closed for NEAR export when canonical single-key HSS session prerequisites are missing', async () => {
    const { restore } = installMemorySessionStorage();

    clearAllStoredThresholdEd25519SessionRecords();

    try {
      const touchConfirm = {
        claimWarmSessionMaterial: async () => ({
          ok: false as const,
          code: 'not_found',
          message: 'missing warm PRF',
        }),
      };
      const recovery = createRecoveryPublicApiForTest({
        touchConfirm,
        expectedPublicKey: 'ed25519:unused',
      });

      await expect(
        recovery.exportKeypairWithUI({
          kind: 'near',
          nearAccount: { kind: 'named', accountId: NEAR_ACCOUNT_ID },
          options: {
            chain: 'near',
            variant: 'drawer',
          },
        } as any),
      ).rejects.toThrow(
        '[SigningEngine][ed25519-export] exact lane selection failed: no_candidate',
      );
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('binds signing and export to the same canonical public key over the route/session flow', async () => {
    const { restore } = installMemorySessionStorage();
    const originalFetch = globalThis.fetch;
    const exportWorkerCalls: Array<Record<string, unknown>> = [];
    const userConfirmationCalls: Array<Record<string, any>> = [];
    let thresholdPublicKey = 'ed25519:placeholder';
    let lastServerOutputB64u = '';
    let capturedSigningPayload: Record<string, any> | null = null;
    const hssCeremonyServer = createStubbedThresholdEd25519HssCeremonyServer();

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session();

    persistWarmSessionEd25519Capability({
      kind: 'jwt_passkey',
      sessionKind: 'jwt',
      nearAccountId: NEAR_ACCOUNT_ID,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      relayerKeyId: RELAYER_KEY_ID,
      runtimePolicyScope: { ...RUNTIME_SCOPE },
      participantIds: [...CONTEXT.participantIds],
      sessionId: THRESHOLD_SESSION_ID,
      walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 5,
      jwt: THRESHOLD_SESSION_JWT,
      source: 'bootstrap',
    });

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) return wasmResponse;
      if (url.endsWith('/threshold-ed25519/healthz')) {
        return new Response(JSON.stringify({ ok: true, configured: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const body = JSON.parse(String(init?.body || '{}')) as Record<string, any>;
      if (url.endsWith('/threshold-ed25519/hss/prepare')) {
        const prepared = await hssCeremonyServer.prepare(body);
        return new Response(JSON.stringify(prepared), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/respond')) {
        const responded = await hssCeremonyServer.respond(body);
        return new Response(JSON.stringify(responded), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/finalize')) {
        const finalized = await hssCeremonyServer.finalize(body);
        lastServerOutputB64u = String(finalized.serverOutput.xRelayerBaseB64u || '').trim();
        return new Response(
          JSON.stringify({
            ok: true,
            finalizedReport: finalized.finalizedReport,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }

      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

    const dummyCredential = {
      id: 'cred-id',
      rawId: 'cred-rawid-b64u',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: 'clientDataJSON-b64u',
        authenticatorData: 'authenticatorData-b64u',
        signature: 'signature-b64u',
        userHandle: '',
      },
      clientExtensionResults: {
        prf: { results: { first: PRF_FIRST_B64U, second: undefined } },
      },
    };

    try {
      await signTransactionsWithActions({
        ctx: {
          nearKeyMaterialStore: makeIndexedDbThresholdDeps(thresholdPublicKey),
          nearContextFixture: {
            initializeUser: () => undefined,
          },
          touchIdPrompt: {
            getRpId: () => RP_ID,
          },
          relayerUrl: RELAYER_URL,
          touchConfirm: {
            getWarmSessionStatus: async () => ({
              ok: false as const,
              code: 'not_found',
              message: 'warm-session status missing',
            }),
            claimWarmSessionMaterial: async () => ({
              ok: true as const,
              prfFirstB64u: PRF_FIRST_B64U,
              remainingUses: 4,
              expiresAtMs: Date.now() + 60_000,
            }),
            clearVolatileWarmSessionMaterial: async () => undefined,
            orchestrateSigningConfirmation: async () => ({
              intentDigest: 'intent-digest-b64u',
              transactionContext: {
                nearPublicKeyStr: thresholdPublicKey,
                nextNonce: '1',
                txBlockHeight: '1',
                txBlockHash: 'blockhash',
                accessKeyInfo: { nonce: 0 },
              },
              credential: dummyCredential,
            }),
          },
          requestWorkerOperation: async ({ request }: any) => {
            if (request?.type === WorkerRequestType.SignTransactionsWithActions) {
              capturedSigningPayload = request?.payload || null;
              return {
                type: WorkerResponseType.SignTransactionsWithActionsSuccess,
                payload: {
                  success: true,
                  signedTransactions: [
                    { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
                  ],
                  logs: [],
                },
              };
            }
            return await invokeNearSignerWorkerDirect(request);
          },
        } as any,
        nearAccount: { kind: 'named', accountId: NEAR_ACCOUNT_ID },
        transactions: [
          {
            receiverId: NEAR_ACCOUNT_ID,
            actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
          } as TransactionInputWasm,
        ],
        rpcCall: { nearAccountId: NEAR_ACCOUNT_ID, nearRpcUrl: 'https://rpc.testnet.test' },
        signerSlot: 1,
        sessionId: THRESHOLD_SESSION_ID,
        ...buildTestWarmSigningAuth(),
      });

      const stored =
        getStoredThresholdEd25519SessionRecordByThresholdSessionId(THRESHOLD_SESSION_ID);
      const xClientBaseB64u = String(stored?.xClientBaseB64u || '').trim();
      expect(xClientBaseB64u).not.toBe('');
      expect(lastServerOutputB64u).not.toBe('');
      expect(
        String(
          (capturedSigningPayload as Record<string, any> | null)?.threshold?.xClientBaseB64u || '',
        ),
      ).toBe(xClientBaseB64u);

      const derivedPublicKey = await deriveThresholdEd25519HssPublicKey({
        xClientBaseB64u,
        xRelayerBaseB64u: lastServerOutputB64u,
      });
      thresholdPublicKey = `ed25519:${bs58.encode(
        Buffer.from(String(derivedPublicKey.publicKeyB64u || ''), 'base64url'),
      )}`;

      const touchConfirm = {
        getWarmSessionStatus: async () => {
          throw new Error('warm-session status should not be consulted during export');
        },
        claimWarmSessionMaterial: async () => {
          throw new Error('warm-session material should not be consumed during export');
        },
        requestUserConfirmation: async (request: Record<string, any>) => {
          userConfirmationCalls.push(request);
          if (request.type === 'decryptPrivateKeyWithPrf') {
            return buildExportAuthorizationDecision(String(request.requestId || ''));
          }
          request.payload?.onLifecycle?.('opened');
          return { requestId: String(request.requestId || ''), confirmed: true };
        },
      };
      const recovery = createRecoveryPublicApiForTest({
        touchConfirm,
        expectedPublicKey: thresholdPublicKey,
        exportWorkerCalls,
      });

      const exportResult = await recovery.exportKeypairWithUI({
        kind: 'near',
        nearAccount: { kind: 'named', accountId: NEAR_ACCOUNT_ID },
        options: {
          chain: 'near',
          variant: 'drawer',
        },
      } as any);

      expect(exportResult).toEqual({
        accountId: NEAR_ACCOUNT_ID,
        exportedSchemes: ['ed25519'],
      });
      expect(exportWorkerCalls).toHaveLength(0);
      expect(userConfirmationCalls[0]?.type).toBe('decryptPrivateKeyWithPrf');
      const privateKeyViewerCalls = userConfirmationCalls.filter(
        (entry) => entry.type === 'showSecurePrivateKeyUi',
      );
      expect(privateKeyViewerCalls.length).toBeGreaterThanOrEqual(1);
      expect(userConfirmationCalls[0]).toMatchObject({
        summary: {
          accountId: NEAR_ACCOUNT_ID,
          publicKey: thresholdPublicKey,
        },
      });
      const finalPrivateKeyViewerCall = privateKeyViewerCalls[privateKeyViewerCalls.length - 1];
      expect(finalPrivateKeyViewerCall).toMatchObject({
        payload: {
          nearAccountId: NEAR_ACCOUNT_ID,
          publicKey: thresholdPublicKey,
          variant: 'drawer',
          theme: 'dark',
        },
      });
    } finally {
      globalThis.fetch = originalFetch;
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('keeps HSS route payloads input-segregated and free of raw cross-party secret material', async () => {
    const { restore } = installMemorySessionStorage();
    const originalFetch = globalThis.fetch;
    const prepareRequests: Array<Record<string, any>> = [];
    const respondRequests: Array<Record<string, any>> = [];
    const finalizeRequests: Array<Record<string, any>> = [];
    const prepareResponses: Array<Record<string, any>> = [];
    const respondResponses: Array<Record<string, any>> = [];
    const finalizeResponses: Array<Record<string, any>> = [];
    const hssCeremonyServer = createStubbedThresholdEd25519HssCeremonyServer();

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session();

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) {
        return wasmResponse;
      }
      const body = JSON.parse(String(init?.body || '{}')) as Record<string, any>;

      if (url.endsWith('/threshold-ed25519/hss/prepare')) {
        prepareRequests.push(body);
        const responseBody = await hssCeremonyServer.prepare(body);
        prepareResponses.push(responseBody);
        return new Response(JSON.stringify(responseBody), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/respond')) {
        respondRequests.push(body);
        const responseBody = await hssCeremonyServer.respond(body);
        respondResponses.push(responseBody);
        return new Response(JSON.stringify(responseBody), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/finalize')) {
        finalizeRequests.push(body);
        const finalized = await hssCeremonyServer.finalize(body);
        const responseBody = { ok: true, finalizedReport: finalized.finalizedReport };
        finalizeResponses.push(responseBody);
        return new Response(JSON.stringify(responseBody), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

    try {
      const xClientBaseB64u = await ensureThresholdEd25519HssClientBase({
        ctx: {
          requestWorkerOperation: async ({ request }: any) =>
            await invokeNearSignerWorkerDirect(request),
        } as any,
        thresholdSessionId: THRESHOLD_SESSION_ID,
        thresholdSessionAuthToken: THRESHOLD_SESSION_JWT,
        signingRootId: SIGNING_ROOT_ID,
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        keyVersion: CONTEXT.keyVersion,
        participantIds: [...CONTEXT.participantIds],
        prfFirstB64u: PRF_FIRST_B64U,
        persistClientBase: (xClientBaseB64u: string) =>
          Boolean(
            persistStoredThresholdEd25519SessionClientBase({
              thresholdSessionId: THRESHOLD_SESSION_ID,
              xClientBaseB64u,
            }),
          ),
      });

      expect(String(xClientBaseB64u || '')).not.toBe('');
      expect(prepareRequests).toHaveLength(1);
      expect(respondRequests).toHaveLength(1);
      expect(finalizeRequests).toHaveLength(1);
      expect(prepareResponses).toHaveLength(1);
      expect(respondResponses).toHaveLength(1);
      expect(finalizeResponses).toHaveLength(1);

      const prepareRequestJson = JSON.stringify(prepareRequests[0]);
      const respondRequestJson = JSON.stringify(respondRequests[0]);
      const finalizeRequestJson = JSON.stringify(finalizeRequests[0]);
      const prepareResponseJson = JSON.stringify(prepareResponses[0]);
      const respondResponseJson = JSON.stringify(respondResponses[0]);
      const finalizeResponseJson = JSON.stringify(finalizeResponses[0]);

      expect(prepareRequests[0]).toHaveProperty('context');
      expect(Object.prototype.hasOwnProperty.call(prepareRequests[0], 'preparedSession')).toBe(
        false,
      );
      expect(Object.prototype.hasOwnProperty.call(prepareRequests[0], 'clientRequest')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(prepareRequests[0], 'clientInputs')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(prepareRequests[0], 'prfFirstB64u')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(prepareRequests[0], 'xClientBaseB64u')).toBe(
        false,
      );
      expect(prepareRequestJson.includes(PRF_FIRST_B64U)).toBe(false);
      expectNoSigningRootSecretShareWire(prepareRequestJson);

      expect(prepareResponses[0]).toHaveProperty('ceremonyHandle');
      expect(prepareResponses[0]).toHaveProperty('clientOtOfferMessageB64u');
      expect(
        Object.prototype.hasOwnProperty.call(prepareResponses[0].preparedSession || {}, 'orgId'),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(
          prepareResponses[0].preparedSession || {},
          'nearAccountId',
        ),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(
          prepareResponses[0].preparedSession || {},
          'participantIds',
        ),
      ).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(prepareResponses[0], 'serverAssistInit')).toBe(
        false,
      );
      expect(Object.prototype.hasOwnProperty.call(prepareResponses[0], 'serverOutput')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(prepareResponses[0], 'serverInputs')).toBe(false);
      expectNoSigningRootSecretShareWire(prepareResponseJson);

      expect(respondRequests[0]).toHaveProperty('ceremonyHandle');
      expect(respondRequests[0]).toHaveProperty('clientRequest');
      expect(Object.prototype.hasOwnProperty.call(respondRequests[0], 'preparedSession')).toBe(
        false,
      );
      expect(
        Object.prototype.hasOwnProperty.call(
          respondRequests[0].clientRequest || {},
          'contextBindingB64u',
        ),
      ).toBe(false);
      expect(respondRequestJson.includes(PRF_FIRST_B64U)).toBe(false);
      expectNoSigningRootSecretShareWire(respondRequestJson);

      expect(Object.prototype.hasOwnProperty.call(respondResponses[0], 'serverAssistInit')).toBe(
        false,
      );
      expect(Object.prototype.hasOwnProperty.call(respondResponses[0], 'evaluationResult')).toBe(
        false,
      );
      expect(respondResponses[0]).toHaveProperty('serverInputDeliveryB64u');
      expect(Object.prototype.hasOwnProperty.call(respondResponses[0], 'serverOutput')).toBe(false);
      expectNoSigningRootSecretShareWire(respondResponseJson);

      expect(finalizeRequests[0]).toHaveProperty('ceremonyHandle');
      expect(finalizeRequests[0]).toHaveProperty('evaluationResult');
      expect(
        Object.prototype.hasOwnProperty.call(
          finalizeRequests[0].evaluationResult || {},
          'evaluatorOtStateB64u',
        ),
      ).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(finalizeRequests[0], 'preparedSession')).toBe(
        false,
      );
      expect(Object.prototype.hasOwnProperty.call(finalizeRequests[0], 'prfFirstB64u')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(finalizeRequests[0], 'xClientBaseB64u')).toBe(
        false,
      );
      expect(Object.prototype.hasOwnProperty.call(finalizeRequests[0], 'seedB64u')).toBe(false);
      expect(finalizeRequestJson.includes(PRF_FIRST_B64U)).toBe(false);
      expectNoSigningRootSecretShareWire(finalizeRequestJson);

      expect(finalizeResponses[0]).toHaveProperty('finalizedReport');
      expect(finalizeResponses[0].finalizedReport).toHaveProperty('clientOutputMessageB64u');
      expect(
        Object.prototype.hasOwnProperty.call(
          finalizeResponses[0].finalizedReport,
          'seedOutputMessageB64u',
        ),
      ).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(finalizeResponses[0], 'serverOutput')).toBe(
        false,
      );
      expect(finalizeResponseJson.includes('xRelayerBaseB64u')).toBe(false);
      expectNoSigningRootSecretShareWire(finalizeResponseJson);
    } finally {
      globalThis.fetch = originalFetch;
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });
});
