import { expect, test } from '@playwright/test';
import type {
  OrchestrateIntentDigestSigningConfirmationParams,
  OrchestrateSigningConfirmationParams,
  SigningConfirmationResultIntentDigest,
  SigningConfirmationResultWithTxContext,
} from '../../client/src/core/signingEngine/stepUpConfirmation/confirmOperation';
import { SigningAuthPlanKind, type SigningAuthPlan } from '../../client/src/core/signingEngine/stepUpConfirmation/types';
import type {
  KeyRef,
  SignRequest,
  SignatureBytes,
  Signer,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../client/src/core/signingEngine/interfaces/signing';
import {
  toWalletId,
} from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UiConfirmContext } from '../../client/src/core/signingEngine/uiConfirm/types';
import type { WorkerOperationContext } from '../../client/src/core/signingEngine/workerManager/executeWorkerOperation';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildKnownReadyThresholdEcdsaSessionPolicy,
  buildReadyEcdsaSignerSession,
  toVerifiedEcdsaPublicFactsFromKeyRef,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { selectedEcdsaLane } from '../../client/src/core/signingEngine/session/identity/laneIdentity';
import { SigningOperationIntent } from '../../client/src/core/signingEngine/session/operationState/types';
import { signEvmFamilyWithUiConfirm } from '../../client/src/core/signingEngine/flows/signEvmFamily/signingFlow';
import type { EvmFamilyThresholdEcdsaOperation } from '../../client/src/core/signingEngine/flows/signEvmFamily/thresholdAdmission';
import {
  buildReadySecp256k1SigningMaterialFromKeyRef,
  type ReadySecp256k1Signer,
  type ReadySecp256k1SigningMaterial,
} from '../../client/src/core/signingEngine/flows/signEvmFamily/signers/secp256k1';
import {
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../../client/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';

const WALLET_ID = 'alice.testnet';
const SUBJECT_ID = toWalletId(WALLET_ID);
const RP_ID = 'localhost';
const ECDSA_THRESHOLD_KEY_ID = 'ehss-shared-key';
const SIGNING_ROOT_ID = 'project:dev';
const SIGNING_ROOT_VERSION = 'default';
const THRESHOLD_SESSION_ID = 'threshold-session-1';
const WALLET_SIGNING_SESSION_ID = 'wallet-signing-session-1';
const EXPIRES_AT_MS = 1_900_000_000_000;
const VALID_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_RELAYER_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_CONTEXT_BINDING_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const EVM_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
} as const;

const ROLE_LOCAL_READY_RECORD = buildEcdsaRoleLocalReadyRecord({
  stateBlob: {
    kind: 'ecdsa_role_local_state_blob_v1',
    curve: 'secp256k1',
    encoding: 'base64url',
    producer: 'signer_core',
    stateBlobB64u: VALID_CONTEXT_BINDING_B64U,
  },
  publicFacts: buildEcdsaRoleLocalPublicFacts({
    walletId: SUBJECT_ID,
    rpId: RP_ID,
    chainTarget: EVM_TARGET,
    keyHandle: 'key-handle-ready-flow',
    ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
    contextBinding32B64u: VALID_CONTEXT_BINDING_B64U,
    hssClientSharePublicKey33B64u: VALID_PUBLIC_KEY_B64U,
    relayerPublicKey33B64u: VALID_RELAYER_PUBLIC_KEY_B64U,
    groupPublicKey33B64u: VALID_PUBLIC_KEY_B64U,
    ethereumAddress: '0x1111111111111111111111111111111111111111',
  }),
  authMethod: buildEcdsaRoleLocalPasskeyAuthMethod({
    credentialIdB64u: 'key-handle-ready-flow',
    rpId: RP_ID,
  }),
});

async function orchestrateSigningConfirmation(
  params: OrchestrateIntentDigestSigningConfirmationParams,
): Promise<SigningConfirmationResultIntentDigest>;
async function orchestrateSigningConfirmation(
  params: Exclude<OrchestrateSigningConfirmationParams, OrchestrateIntentDigestSigningConfirmationParams>,
): Promise<SigningConfirmationResultWithTxContext>;
async function orchestrateSigningConfirmation(
  params: OrchestrateSigningConfirmationParams,
): Promise<SigningConfirmationResultIntentDigest | SigningConfirmationResultWithTxContext> {
  if (params.kind !== 'intentDigest') {
    throw new Error('transaction confirmation is not used by this test');
  }
  return {
    sessionId: params.sessionId,
    intentDigest: params.intentDigest,
  };
}

function buildUiConfirmContext(): UiConfirmContext {
  return {
    touchIdPrompt: { getRpId: () => RP_ID },
    nearClient: {},
    indexedDB: {},
    userPreferencesManager: {},
    nonceCoordinator: {
      markSigned: async () => undefined,
    },
  } as unknown as UiConfirmContext;
}

function makeThresholdKeyRef(
  overrides: Partial<ThresholdEcdsaSecp256k1KeyRef> = {},
): ThresholdEcdsaSecp256k1KeyRef {
  const base: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: WALLET_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relayer.test',
    keyHandle: 'key-handle-ready-flow',
    ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    backendBinding: {
      materialKind: 'role_local_ready_state_blob',
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'client-verifying-share',
      stateBlob: ROLE_LOCAL_READY_RECORD.stateBlob,
      ecdsaRoleLocalReadyRecord: ROLE_LOCAL_READY_RECORD,
    },
    participantIds: [1, 2],
    thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    thresholdSessionKind: 'jwt',
    thresholdSessionAuthToken: 'threshold-auth-token',
    thresholdSessionId: THRESHOLD_SESSION_ID,
    walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
  };
  return {
    ...base,
    ...overrides,
    backendBinding: overrides.backendBinding ?? base.backendBinding,
  };
}

test.describe('signEvmFamilyWithUiConfirm ready signer handoff', () => {
  test('uses admitted ready signer material before key-ref fallback', async () => {
    const key = buildBaseEvmFamilyEcdsaKeyIdentity({
      walletId: WALLET_ID,
      rpId: RP_ID,
      ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      participantIds: [1, 2],
      thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
    });
    const keyRef = makeThresholdKeyRef();
    const publicFacts = await toVerifiedEcdsaPublicFactsFromKeyRef({ keyRef });
    const signerSession = buildReadyEcdsaSignerSession({
      keyRef,
      publicFacts,
      sessionPolicy: buildKnownReadyThresholdEcdsaSessionPolicy({
        remainingUses: 1,
        expiresAtMs: 1_900_000_000_000,
      }),
      thresholdSessionKind: 'jwt',
      thresholdSessionAuthToken: 'threshold-auth-token',
    });
    const lane = selectedEcdsaLane({
      key,
      keyHandle: publicFacts.keyHandle,
      walletId: WALLET_ID,
      authMethod: 'passkey',
      walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
      thresholdSessionId: THRESHOLD_SESSION_ID,
      chainTarget: EVM_TARGET,
    });
    const signingAuthPlan = {
      kind: SigningAuthPlanKind.WarmSession,
      method: 'passkey',
      accountId: WALLET_ID,
      intent: SigningOperationIntent.TransactionSign,
      curve: 'ecdsa',
      signingRootId: SIGNING_ROOT_ID,
      sessionId: THRESHOLD_SESSION_ID,
      expiresAtMs: EXPIRES_AT_MS,
      remainingUses: 1,
    } satisfies SigningAuthPlan;
    const operation = {
      intent: {
        curve: 'ecdsa',
        chain: 'evm',
        chainTarget: EVM_TARGET,
        walletId: toWalletId(WALLET_ID),
        authSelectionPolicy: { kind: 'explicit', authMethod: 'passkey' },
        operationUsesNeeded: 1,
      },
      lane,
      readiness: { status: 'ready', remainingUses: 1, expiresAtMs: EXPIRES_AT_MS },
      budgetAdmission: {
        budgetIdentity: {
          walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
          projectionVersion: 'projection-1',
          status: {
            sessionId: WALLET_SIGNING_SESSION_ID,
            status: 'active',
            remainingUses: 1,
            expiresAtMs: EXPIRES_AT_MS,
            projectionVersion: 'projection-1',
          },
        },
      },
      authPlan: signingAuthPlan,
    } satisfies EvmFamilyThresholdEcdsaOperation;

    const signature = new Uint8Array(65).fill(7);
    let signReadyCalls = 0;
    let signCalls = 0;
    let finalizedSignature: SignatureBytes | null = null;
    const readyEngine: Signer<SignRequest, KeyRef, SignatureBytes> & ReadySecp256k1Signer = {
      algorithm: 'secp256k1',
      sign: async () => {
        signCalls += 1;
        throw new Error('key-ref fallback should not be used');
      },
      signReady: async (
        req: SignRequest,
        material: ReadySecp256k1SigningMaterial,
      ): Promise<SignatureBytes> => {
        signReadyCalls += 1;
        expect(req.algorithm).toBe('secp256k1');
        expect(material.signerSession).toBe(signerSession);
        expect(material.singleUseEmailOtpSession).toBe(false);
        return signature;
      },
    };
    const touchConfirm = {
      orchestrateSigningConfirmation,
      getWarmSessionStatus: async () => ({
        ok: true as const,
        remainingUses: 1,
        expiresAtMs: EXPIRES_AT_MS,
      }),
      requestUserConfirmation: async () => {
        throw new Error('requestUserConfirmation is not used by this test');
      },
      exportPrivateKeysWithUi: async () => {
        throw new Error('exportPrivateKeysWithUi is not used by this test');
      },
    };
    const workerCtx: WorkerOperationContext = {
      requestWorkerOperation: async () => {
        throw new Error('worker operations are not used by this test');
      },
    };

    const result = await signEvmFamilyWithUiConfirm<
      { senderSignatureAlgorithm: 'secp256k1' },
      { ok: true }
    >({
      config: {
        targetKind: 'evm',
        flowName: 'evm',
        explicitAuthErrorLabel: 'EVM',
        nonceErrorLabel: 'EVM',
        title: 'Sign',
        body: 'Confirm',
        buildIntent: async () => ({
          chain: 'evm',
          uiModel: {},
          signRequests: [
            {
              kind: 'digest',
              algorithm: 'secp256k1',
              digest32: new Uint8Array(32).fill(1),
              label: 'evm',
            },
          ],
          finalize: async (signatures) => {
            finalizedSignature = signatures[0] || null;
            return { ok: true };
          },
        }),
        buildDisplayModel: ({ signerAccount, title, subtitle, intentDigest }) => ({
          chain: 'evm',
          signerAccount,
          title,
          subtitle,
          ...(intentDigest ? { intentDigest } : {}),
          operations: [{ id: 'sign', kind: 'raw.fallback', label: 'Sign', raw: '0x' }],
        }),
        webauthn: { kind: 'not_supported' },
      },
      input: {
        ctx: buildUiConfirmContext(),
        touchConfirm,
        walletId: WALLET_ID,
        request: { senderSignatureAlgorithm: 'secp256k1' },
        engines: { secp256k1: readyEngine },
        workerCtx,
        thresholdEcdsaStepUp: {
          kind: 'required_admitted',
          authPlan: {
            kind: 'planned',
            signingAuthPlan,
          },
          operation,
          signerSession,
          singleUseEmailOtpSession: false,
          runtime: {},
        },
      },
    });

    expect(result).toEqual({ ok: true });
    expect(finalizedSignature).toBe(signature);
    expect(signReadyCalls).toBe(1);
    expect(signCalls).toBe(0);
  });

  test('normalizes key-ref fallback into ready secp256k1 material', async () => {
    const keyRef = makeThresholdKeyRef();

    const material = await buildReadySecp256k1SigningMaterialFromKeyRef({
      keyRef,
      requestLabel: 'evm',
      rpId: RP_ID,
    });

    expect(material.kind).toBe('ready_secp256k1_signing_material');
    expect(material.walletId).toBe(WALLET_ID);
    expect(material.singleUseEmailOtpSession).toBe(false);
    expect(material.signerSession.session.thresholdSessionId).toBe(THRESHOLD_SESSION_ID);
    expect(material.signerSession.session.walletSigningSessionId).toBe(
      WALLET_SIGNING_SESSION_ID,
    );
    expect(material.signerSession.session.policy).toEqual({
      kind: 'unavailable_threshold_ecdsa_session_policy',
      source: 'key_ref_fallback',
    });
    expect(material.signerSession.transport.auth).toEqual({
      kind: 'jwt_threshold_session_auth',
      thresholdSessionAuthToken: 'threshold-auth-token',
    });
    expect(material.signerSession.publicFacts.publicKeyB64u).toBe(VALID_PUBLIC_KEY_B64U);
    expect('keyRef' in material.signerSession).toBe(false);
  });
});
