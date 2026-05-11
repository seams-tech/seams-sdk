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
import { SigningEngine } from '@/core/signingEngine/SigningEngine';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  persistStoredThresholdEd25519SessionClientBase,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { ActionType, type TransactionInputWasm } from '@/core/types/actions';
import { WorkerRequestType, WorkerResponseType } from '@/core/types/signer-worker';
import {
  deriveThresholdEd25519HssClientInputsWasm,
  openThresholdEd25519HssClientOutputWasm,
  prepareThresholdEd25519HssClientRequestWasm,
  prepareThresholdEd25519HssSessionWasm,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import {
  finalizeThresholdEd25519HssServerCeremonyWithRelayRegistration,
  prepareThresholdEd25519HssServerCeremonyWithRelayRegistration,
  respondThresholdEd25519HssServerCeremonyWithRelayRegistration,
} from '@/core/SeamsPasskey/faucets/createAccountRelayServer';
import {
  deriveThresholdEd25519HssPublicKey,
  finalizeThresholdEd25519HssServerCeremony,
  prepareThresholdEd25519HssServerCeremony,
  prepareThresholdEd25519HssServerSession,
} from '../../server/src/core/ThresholdService/ed25519HssWasm';
import type { ThresholdEd25519HssSessionOperation } from '../../server/src/core/types';
import { deriveEd25519HssServerInputsFromSigningRootSecretShares } from '../../server/src/core/ThresholdService/thresholdPrfWasm';
import {
  parseSigningRootSecretShareWireV1,
  type SigningRootSecretShareWirePair,
} from '../../server/src/core/ThresholdService/signingRootSecretShareWires';
import {
  handle_signer_message,
  initSync as initNearSignerWasmSync,
} from '../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  derive_threshold_ed25519_hss_client_inputs,
  initSync as initHssClientSignerWasmSync,
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

function createStubbedThresholdEd25519HssCeremonyServer(): {
  prepare: (body: Record<string, any>) => Promise<{
    ok: true;
    ceremonyHandle: string;
    preparedSession: Record<string, any>;
    clientOtOfferMessageB64u: string;
  }>;
  respond: (body: Record<string, any>) => Promise<{
    ok: true;
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
      evaluationResult?: Awaited<
        ReturnType<typeof prepareThresholdEd25519HssServerCeremony>
      >['evaluationResult'];
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
      const prepared = await prepareThresholdEd25519HssServerCeremony({
        operation: (ceremony.operation || 'warm_session_reconstruction') as
          | 'registration'
          | ThresholdEd25519HssSessionOperation,
        preparedServerSession: ceremony.preparedServerSession,
        expectedContextBindingB64u: ceremony.preparedSession.contextBindingB64u,
        clientRequest: body.clientRequest,
        serverInputs: ceremony.serverInputs,
      });
      ceremony.evaluationResult = prepared.evaluationResult;
      return {
        ok: true as const,
      };
    },
    async finalize(body) {
      const ceremonyHandle = String(body.ceremonyHandle || '').trim();
      const ceremony = ceremoniesByHandle.get(ceremonyHandle);
      if (!ceremony) {
        throw new Error(`missing prepared session for ceremony handle: ${ceremonyHandle}`);
      }
      if (!ceremony.evaluationResult) {
        throw new Error(`missing staged evaluator artifact for ceremony handle: ${ceremonyHandle}`);
      }
      ceremoniesByHandle.delete(ceremonyHandle);
      const finalized = await finalizeThresholdEd25519HssServerCeremony({
        operation:
          ceremony.operation === 'explicit_key_export'
            ? 'explicit_key_export'
            : 'warm_session_reconstruction',
        preparedSession: ceremony.preparedSession,
        preparedServerSession: ceremony.preparedServerSession,
        evaluationResult: ceremony.evaluationResult,
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
  return {
    clientDB: {
      getLastProfileState: async () => ({ profileId: 'profile-1', activeSignerSlot: 1 }),
      resolveProfileAccountContext: async (accountRef: {
        chainIdKey: string;
        accountAddress: string;
      }) => ({ profileId: 'profile-1', accountRef }),
    },
    accountKeyMaterialDB: {
      getKeyMaterial: async () => makeThresholdKeyMaterialRecord(publicKey),
      storeKeyMaterial: async () => undefined,
    },
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
  type: number;
  payload?: Record<string, unknown>;
}): Promise<any> {
  if (
    request.type === WorkerRequestType.DeriveThresholdEd25519HssClientInputs ||
    request.type === WorkerRequestType.PrepareThresholdEd25519HssSession ||
    request.type === WorkerRequestType.PrepareThresholdEd25519HssClientRequest ||
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

test.describe('threshold Ed25519 single-key HSS active path', () => {
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

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session({ xClientBaseB64u: Buffer.alloc(32, 23).toString('base64url') });

    persistWarmSessionEd25519Capability({
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

    try {
      const result = await signTransactionsWithActions({
        ctx: {
          indexedDB: makeIndexedDbThresholdDeps('ed25519:threshold-public-key'),
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
            clearWarmSessionMaterial: async () => undefined,
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
    } finally {
      globalThis.fetch = originalFetch;
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

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session({ xClientBaseB64u: Buffer.alloc(32, 23).toString('base64url') });

    persistWarmSessionEd25519Capability({
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
          indexedDB: makeIndexedDbThresholdDeps('ed25519:threshold-public-key'),
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
            clearWarmSessionMaterial: async () => undefined,
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
      const prepared = await prepareThresholdEd25519HssServerCeremony({
        operation: 'explicit_key_export',
        preparedServerSession: storedPreparedServerSession,
        expectedContextBindingB64u: preparedSession.contextBindingB64u,
        clientRequest,
        serverInputs: storedServerInputs,
      });
      const evaluationResult = prepared.evaluationResult;
      const finalized = await finalizeThresholdEd25519HssServerCeremony({
        operation: 'explicit_key_export',
        preparedSession,
        preparedServerSession: storedPreparedServerSession,
        evaluationResult,
        expectedContextBindingB64u: preparedSession.contextBindingB64u,
      });
      const clientOutput = await openThresholdEd25519HssClientOutputWasm({
        preparedSession,
        finalizedReport: finalized.finalizedReport,
        workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
      });
      const derivedPublicKey = await deriveThresholdEd25519HssPublicKey({
        xClientBaseB64u: clientOutput.xClientBaseB64u,
        xRelayerBaseB64u: finalized.serverOutput.xRelayerBaseB64u,
      });
      const expectedPublicKey = `ed25519:${bs58.encode(
        Buffer.from(String(derivedPublicKey.publicKeyB64u || ''), 'base64url'),
      )}`;

      const engine: any = Object.create(SigningEngine.prototype);
      engine.seamsPasskeyConfigs = { network: { chains: [] } };
      engine.thresholdEcdsaSessionByLane = new Map();
      engine.thresholdEcdsaExportArtifactByLane = new Map();

      engine.enginePorts = {
        privateKeyExportRecoveryDeps: {
          indexedDB: {
            ...makeIndexedDbThresholdDeps(expectedPublicKey),
          },
          relayerUrl: RELAYER_URL,
          getRpId: () => RP_ID,
          getTheme: () => 'dark',
          requestExportPrivateKeysWithUi: async (payload: Record<string, unknown>) => {
            exportWorkerCalls.push(payload);
            return {
              ok: true,
              accountId: String(payload.nearAccountId || ''),
              exportedSchemes: ['ed25519'],
            };
          },
        },
        indexedDB: {
          ...makeIndexedDbThresholdDeps(expectedPublicKey),
        },
        thresholdSessionActivationDeps: {
          getSignerWorkerContext: () => ({
            requestWorkerOperation: async ({ request }: any) =>
              await invokeNearSignerWorkerDirect(request),
          }),
        },
      };

      engine.touchConfirm = {
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

      const result = await engine.exportKeypairWithUI({
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
      const engine: any = Object.create(SigningEngine.prototype);
      engine.seamsPasskeyConfigs = { network: { chains: [] } };
      engine.thresholdEcdsaSessionByLane = new Map();
      engine.thresholdEcdsaExportArtifactByLane = new Map();

      engine.enginePorts = {
        privateKeyExportRecoveryDeps: {
          indexedDB: {
            ...makeIndexedDbThresholdDeps('ed25519:unused'),
            accountKeyMaterialDB: {
              getKeyMaterial: async () => ({
                ...makeThresholdKeyMaterialRecord('ed25519:unused'),
                payload: {
                  ...makeThresholdKeyMaterialRecord('ed25519:unused').payload,
                  participants: [],
                },
              }),
              storeKeyMaterial: async () => undefined,
            },
          },
          relayerUrl: RELAYER_URL,
          getRpId: () => RP_ID,
          getTheme: () => 'dark',
          requestExportPrivateKeysWithUi: async () => {
            throw new Error('legacy export worker path should not be reached');
          },
        },
        indexedDB: {
          clientDB: {
            ...makeIndexedDbThresholdDeps('ed25519:unused').clientDB,
          },
          accountKeyMaterialDB: {
            getKeyMaterial: async () => null,
            storeKeyMaterial: async () => undefined,
          },
        },
        thresholdSessionActivationDeps: {
          getSignerWorkerContext: () => ({
            requestWorkerOperation: async ({ request }: any) =>
              await invokeNearSignerWorkerDirect(request),
          }),
        },
      };

      engine.touchConfirm = {
        claimWarmSessionMaterial: async () => ({
          ok: false as const,
          code: 'not_found',
          message: 'missing warm PRF',
        }),
      };

      await expect(
        engine.exportKeypairWithUI({
          kind: 'near',
          nearAccount: { kind: 'named', accountId: NEAR_ACCOUNT_ID },
          options: {
            chain: 'near',
            variant: 'drawer',
          },
        } as any),
      ).rejects.toThrow('[SigningEngine][ed25519-export] exact lane selection failed: no_candidate');
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
          indexedDB: makeIndexedDbThresholdDeps(thresholdPublicKey),
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
            clearWarmSessionMaterial: async () => undefined,
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
      expect(String((capturedSigningPayload as Record<string, any> | null)?.threshold?.xClientBaseB64u || '')).toBe(
        xClientBaseB64u,
      );

      const derivedPublicKey = await deriveThresholdEd25519HssPublicKey({
        xClientBaseB64u,
        xRelayerBaseB64u: lastServerOutputB64u,
      });
      thresholdPublicKey = `ed25519:${bs58.encode(
        Buffer.from(String(derivedPublicKey.publicKeyB64u || ''), 'base64url'),
      )}`;

      const engine: any = Object.create(SigningEngine.prototype);
      engine.seamsPasskeyConfigs = { network: { chains: [] } };
      engine.thresholdEcdsaSessionByLane = new Map();
      engine.thresholdEcdsaExportArtifactByLane = new Map();
      engine.enginePorts = {
        privateKeyExportRecoveryDeps: {
          indexedDB: {
            ...makeIndexedDbThresholdDeps(thresholdPublicKey),
          },
          relayerUrl: RELAYER_URL,
          getRpId: () => RP_ID,
          getTheme: () => 'dark',
          requestExportPrivateKeysWithUi: async (payload: Record<string, unknown>) => {
            exportWorkerCalls.push(payload);
            return {
              ok: true,
              accountId: String(payload.nearAccountId || ''),
              exportedSchemes: ['ed25519'],
            };
          },
        },
        indexedDB: {
          ...makeIndexedDbThresholdDeps(thresholdPublicKey),
        },
        thresholdSessionActivationDeps: {
          getSignerWorkerContext: () => ({
            requestWorkerOperation: async ({ request }: any) =>
              await invokeNearSignerWorkerDirect(request),
          }),
        },
      };
      engine.touchConfirm = {
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

      const exportResult = await engine.exportKeypairWithUI({
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
      expect(Object.prototype.hasOwnProperty.call(respondResponses[0], 'serverOutput')).toBe(false);
      expectNoSigningRootSecretShareWire(respondResponseJson);

      expect(finalizeRequests[0]).toHaveProperty('ceremonyHandle');
      expect(Object.prototype.hasOwnProperty.call(finalizeRequests[0], 'evaluationResult')).toBe(
        false,
      );
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

  test('uses the sessionless registration HSS routes with managed registration flow grants', async () => {
    const originalFetch = globalThis.fetch;
    const bootstrapGrantBodies: Array<Record<string, any>> = [];
    const prepareBodies: Array<Record<string, any>> = [];
    const finalizeBodies: Array<Record<string, any>> = [];
    const hssCeremonyServer = createStubbedThresholdEd25519HssCeremonyServer();

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) {
        return wasmResponse;
      }
      const body = JSON.parse(String(init?.body || '{}')) as Record<string, any>;

      if (url.endsWith('/v1/registration/bootstrap-grants')) {
        bootstrapGrantBodies.push(body);
        return new Response(
          JSON.stringify({
            ok: true,
            grant: {
              token: `bootstrap-token-${bootstrapGrantBodies.length}`,
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
              signingRootId: CONTEXT.signingRootId,
              orgId: RUNTIME_SCOPE.orgId,
              projectId: RUNTIME_SCOPE.projectId,
              envId: RUNTIME_SCOPE.envId,
              signingRootVersion: RUNTIME_SCOPE.signingRootVersion,
              origin: 'https://example.localhost',
              mode: 'free',
            },
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }

      if (url.endsWith('/registration/threshold-ed25519/hss/prepare')) {
        prepareBodies.push(body);
        expect(
          String(init?.headers && (init.headers as Record<string, string>).Authorization),
        ).toBe('Bearer bootstrap-token-1');
        return new Response(JSON.stringify(await hssCeremonyServer.prepare(body)), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/registration/threshold-ed25519/hss/respond')) {
        expect(
          String(init?.headers && (init.headers as Record<string, string>).Authorization),
        ).toBe('Bearer bootstrap-token-2');
        return new Response(JSON.stringify(await hssCeremonyServer.respond(body)), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/registration/threshold-ed25519/hss/finalize')) {
        finalizeBodies.push(body);
        expect(
          String(init?.headers && (init.headers as Record<string, string>).Authorization),
        ).toBe('Bearer bootstrap-token-3');
        await hssCeremonyServer.finalize(body);
        return new Response(
          JSON.stringify({
            ok: true,
            publicKey: 'ed25519:test-registration-public-key',
            relayerKeyId: RELAYER_KEY_ID,
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
      const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
        sessionId: `${THRESHOLD_SESSION_ID}:registration-inputs`,
        signingRootId: CONTEXT.signingRootId,
        nearAccountId: NEAR_ACCOUNT_ID,
        keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
        keyVersion: CONTEXT.keyVersion,
        participantIds: [...CONTEXT.participantIds],
        derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
        prfFirstB64u: PRF_FIRST_B64U,
        workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
      });
      const hssContext = {
        signingRootId: CONTEXT.signingRootId,
        nearAccountId: NEAR_ACCOUNT_ID,
        keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
        keyVersion: CONTEXT.keyVersion,
        participantIds: [...CONTEXT.participantIds],
        derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      };

      const registrationContext = {
        configs: {
          network: {
            relayer: {
              url: RELAYER_URL,
            },
          },
          registration: {
            mode: 'managed',
            environmentId: RUNTIME_SCOPE.envId,
            publishableKey: 'pk_test_single_key_hss',
          },
        },
      } as any;

      const preparedRelayCeremony =
        await prepareThresholdEd25519HssServerCeremonyWithRelayRegistration({
          context: registrationContext,
          nearAccountId: NEAR_ACCOUNT_ID,
          rpId: RP_ID,
          hssContext,
        });
      const preparedSession = preparedRelayCeremony.preparedSession;
      const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
        evaluatorDriverStateB64u: preparedSession.evaluatorDriverStateB64u,
        clientOtOfferMessageB64u: String(preparedRelayCeremony.clientOtOfferMessageB64u || ''),
        clientInputs,
        workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
      });
      const responded = await respondThresholdEd25519HssServerCeremonyWithRelayRegistration({
        context: registrationContext,
        nearAccountId: NEAR_ACCOUNT_ID,
        rpId: RP_ID,
        ceremonyHandle: String(preparedRelayCeremony.ceremonyHandle || ''),
        clientRequest,
      });
      const finalized = await finalizeThresholdEd25519HssServerCeremonyWithRelayRegistration({
        context: registrationContext,
        nearAccountId: NEAR_ACCOUNT_ID,
        rpId: RP_ID,
        ceremonyHandle: preparedRelayCeremony.ceremonyHandle,
      });

      expect(String(preparedRelayCeremony.clientOtOfferMessageB64u || '')).not.toBe('');
      expect(finalized.publicKey).toBe('ed25519:test-registration-public-key');
      expect(finalized.relayerKeyId).toBe(RELAYER_KEY_ID);
      expect(bootstrapGrantBodies).toHaveLength(3);
      expect(prepareBodies).toHaveLength(1);
      expect(finalizeBodies).toHaveLength(1);
      expect(String(prepareBodies[0]?.new_account_id || '')).toBe(NEAR_ACCOUNT_ID);
      expect(String(prepareBodies[0]?.rp_id || '')).toBe(RP_ID);
      expect(String(finalizeBodies[0]?.new_account_id || '')).toBe(NEAR_ACCOUNT_ID);
      expect(String(finalizeBodies[0]?.rp_id || '')).toBe(RP_ID);
      expect(String(finalizeBodies[0]?.ceremonyHandle || '')).toBe(
        preparedRelayCeremony.ceremonyHandle,
      );
      expect(Object.prototype.hasOwnProperty.call(finalizeBodies[0], 'preparedSession')).toBe(
        false,
      );
      expect(JSON.stringify(prepareBodies[0]).includes(PRF_FIRST_B64U)).toBe(false);
      expectNoSigningRootSecretShareWire(JSON.stringify(prepareBodies[0]));
      expect(JSON.stringify(finalizeBodies[0]).includes(PRF_FIRST_B64U)).toBe(false);
      expectNoSigningRootSecretShareWire(JSON.stringify(finalizeBodies[0]));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
