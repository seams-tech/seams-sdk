import { expect, test } from '@playwright/test';
import type {
  OrchestrateIntentDigestSigningConfirmationParams,
  OrchestrateSigningConfirmationParams,
  SigningConfirmationResultIntentDigest,
  SigningConfirmationResultWithTxContext,
} from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/confirmOperation';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types';
import type {
  KeyRef,
  SignRequest,
  SignatureBytes,
  Signer,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/signing';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from '../../packages/shared-ts/src/utils/routerAbEcdsaHss';
import { toWalletId } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UiConfirmContext } from '../../packages/sdk-web/src/core/signingEngine/uiConfirm/uiConfirm.types';
import type { WorkerOperationContext } from '../../packages/sdk-web/src/core/signingEngine/workerManager/executeWorkerOperation';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildKnownReadyThresholdEcdsaSessionPolicy,
  buildReadyEcdsaSignerSession,
  toRpId,
  toVerifiedEcdsaPublicFactsFromKeyRef,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { selectedEcdsaLane } from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import { SigningOperationIntent } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import { signEvmFamilyWithUiConfirm } from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlow';
import type { EvmFamilyThresholdEcdsaOperation } from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/thresholdAdmission';
import {
  type ReadySecp256k1Signer,
  type ReadySecp256k1SigningMaterial,
} from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/secp256k1';
import {
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import { parseEcdsaThresholdKeyId } from '../../packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands';

const WALLET_ID = 'alice.testnet';
const SUBJECT_ID = toWalletId(WALLET_ID);
const RP_ID = 'localhost';
const WALLET_KEY_ID = 'wallet-key-ready-flow';
const PASSKEY_AUTH = {
  kind: 'passkey' as const,
  rpId: toRpId(RP_ID),
  credentialIdB64u: 'key-handle-ready-flow',
};
const ECDSA_THRESHOLD_KEY_ID = parseEcdsaThresholdKeyId('ehss-shared-key');
const SIGNING_ROOT_ID = 'project:dev';
const SIGNING_ROOT_VERSION = 'default';
const THRESHOLD_SESSION_ID = 'threshold-session-1';
const WALLET_SIGNING_SESSION_ID = 'signing-grant-1';
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
    walletKeyId: WALLET_KEY_ID,
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

function ethereumAddress20B64u(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

function makeRouterAbEcdsaHssNormalSigningState(): RouterAbEcdsaHssNormalSigningStateV1 {
  return {
    kind: 'router_ab_ecdsa_hss_normal_signing_v1',
    scope: {
      wallet_key_id: WALLET_KEY_ID,
      wallet_id: WALLET_ID,
      ecdsa_threshold_key_id: ECDSA_THRESHOLD_KEY_ID,
      signing_root_id: SIGNING_ROOT_ID,
      signing_root_version: SIGNING_ROOT_VERSION,
      context: {
        application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      },
      public_identity: {
        context_binding_b64u: VALID_CONTEXT_BINDING_B64U,
        client_public_key33_b64u: VALID_PUBLIC_KEY_B64U,
        server_public_key33_b64u: VALID_RELAYER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: VALID_PUBLIC_KEY_B64U,
        ethereum_address20_b64u: ethereumAddress20B64u(
          '0x1111111111111111111111111111111111111111',
        ),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-1',
        key_epoch: 'worker-epoch-1',
        recipient_encryption_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      activation_epoch: 'activation-1',
    },
  };
}

async function orchestrateSigningConfirmation(
  params: OrchestrateIntentDigestSigningConfirmationParams,
): Promise<SigningConfirmationResultIntentDigest>;
async function orchestrateSigningConfirmation(
  params: Exclude<
    OrchestrateSigningConfirmationParams,
    OrchestrateIntentDigestSigningConfirmationParams
  >,
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
    backendBinding: {
      materialKind: 'role_local_ready_state_blob',
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: VALID_PUBLIC_KEY_B64U,
      stateBlob: ROLE_LOCAL_READY_RECORD.stateBlob,
      ecdsaRoleLocalReadyRecord: ROLE_LOCAL_READY_RECORD,
    },
    participantIds: [1, 2],
    thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    routerAbEcdsaHssNormalSigning: makeRouterAbEcdsaHssNormalSigningState(),
    thresholdSessionKind: 'jwt',
    walletSessionJwt: 'threshold-auth-token',
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId: WALLET_SIGNING_SESSION_ID,
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
      walletId: SUBJECT_ID,
      walletKeyId: WALLET_KEY_ID,
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
      walletSessionJwt: 'threshold-auth-token',
    });
    const lane = selectedEcdsaLane({
      key,
      keyHandle: publicFacts.keyHandle,
      walletId: SUBJECT_ID,
      auth: PASSKEY_AUTH,
      signingGrantId: WALLET_SIGNING_SESSION_ID,
      thresholdSessionId: THRESHOLD_SESSION_ID,
      chainTarget: EVM_TARGET,
    });
    const signingAuthPlan = {
      kind: SigningAuthPlanKind.WarmSession,
      method: 'passkey',
      accountId: WALLET_ID,
      intent: SigningOperationIntent.TransactionSign,
      curve: 'ecdsa',
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
          signingGrantId: WALLET_SIGNING_SESSION_ID,
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

});
