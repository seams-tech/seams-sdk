import { expect, test } from '@playwright/test';
import { base58Encode } from '../../packages/shared-ts/src/utils/base58';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import {
  parseThresholdEd25519SessionId,
  type DomainIdParseResult,
} from '../../packages/shared-ts/src/utils/domainIds';
import { routerAbMpcMaterialActivationRefToWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import {
  buildRouterAbEd25519NearTransactionPrepareRequestV2,
  type RouterAbNormalSigningPrepareRequestV2Wire,
} from '../../packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning';
import {
  EmailOtpEd25519YaoWorkerActiveClientV1,
  rehydrateEmailOtpEd25519YaoOperationMaterialV1,
} from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoWorkerClient';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../../packages/sdk-web/src/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import type { WorkerOperationContext } from '../../packages/sdk-web/src/core/signingEngine/workerManager/executeWorkerOperation';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoClient';
import { buildWalletAuthAuthorityRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import {
  nearEd25519OperationMaterialFixture,
  sealedEmailOtpNearOperationMaterialFixture,
} from './helpers/nearEd25519OperationMaterial.fixtures';
import { resolveNearOperationStepUpMaterial } from '../../packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519YaoCapabilityResolution';

const WALLET_ID = 'email-otp-operation-material.testnet';
const NEAR_ACCOUNT_ID = 'email-otp-operation-material.near';
const PROVIDER_SUBJECT_ID = 'google:email-otp-operation-material';
const THRESHOLD_SESSION_ID = unwrapDomainId(
  parseThresholdEd25519SessionId('email-otp-operation-threshold-session'),
);
const OPERATION_GRANT_ID = 'email-otp-operation-grant';

function unwrapDomainId<T>(result: DomainIdParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function activeMetadata(): RouterAbEd25519YaoActiveClientMetadataV1 {
  return {
    kind: 'router_ab_ed25519_yao_active_client_v1',
    scope: {
      lifecycle_id: 'email-otp-operation-lifecycle',
      root_share_epoch: 'root-v1',
      account_id: WALLET_ID,
      threshold_session_id: THRESHOLD_SESSION_ID,
      signer_set_id: 'near_ed25519:slot:1',
      signing_worker_id: 'email-otp-operation-signing-worker',
      material_activation: {
        kind: 'mpc_material_activation_ref',
        activation_id: 'email-otp-operation-activation',
        capability: 'email-otp-operation-capability',
        material_owner: WALLET_ID,
        key_binding: 'email-otp-operation-key',
        lifecycle_binding: 'email-otp-operation-lifecycle-binding',
        signing_worker: 'email-otp-operation-signing-worker',
      },
    },
    applicationBinding: {
      wallet_id: WALLET_ID,
      near_ed25519_signing_key_id: 'near-ed25519-key-1',
      signing_root_id: 'email-otp-operation-root',
      key_creation_signer_slot: 1,
    },
    participantIds: [1, 2],
    registeredPublicKey: new Uint8Array(32).fill(7),
    signingWorkerVerifyingShare: new Uint8Array(32).fill(8),
    stateEpoch: 1n,
    transcript: new Uint8Array(32).fill(9),
    activeCapabilityBinding: new Array<number>(32).fill(10),
    materialActivation: {
      kind: 'mpc_material_activation_ref',
      activationId: 'email-otp-operation-activation',
      capability: 'email-otp-operation-capability',
      materialOwner: WALLET_ID,
      keyBinding: 'email-otp-operation-key',
      lifecycleBinding: 'email-otp-operation-lifecycle-binding',
      signingWorker: 'email-otp-operation-signing-worker',
    },
  };
}

async function normalSigningRequest(
  metadata: RouterAbEd25519YaoActiveClientMetadataV1,
): Promise<RouterAbNormalSigningPrepareRequestV2Wire> {
  const activation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
  return (
    await buildRouterAbEd25519NearTransactionPrepareRequestV2({
      scope: {
        request_id: 'email-otp-operation-request',
        account_id: WALLET_ID,
        authorization: { kind: 'operation_step_up', grant_id: OPERATION_GRANT_ID },
        material_activation: routerAbMpcMaterialActivationRefToWire(activation),
        signing_worker_id: metadata.scope.signing_worker_id,
      },
      expiresAtMs: Date.now() + 60_000,
      operationId: 'email-otp-operation-id',
      operationFingerprint: 'email-otp-operation-fingerprint',
      displayDigestB64u: base64UrlEncode(new Uint8Array(32).fill(1)),
      nearAccountId: NEAR_ACCOUNT_ID,
      nearNetworkId: 'testnet',
      transactions: [{ receiverId: 'receiver.testnet', actionFingerprint: 'actions' }],
      unsignedTransactionBorshB64u: 'AQID',
      expectedSigningDigestB64u: 'A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc-4E',
    })
  ).request;
}

class OperationMaterialWorkerFixture {
  readonly operations: Array<{ type: string; payload: Record<string, unknown> }> = [];

  constructor(private readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1) {}

  async requestWorkerOperation(args: any): Promise<any> {
    const request = args.request as { type: string; payload: Record<string, unknown> };
    this.operations.push(request);
    switch (request.type) {
      case 'rehydrateEmailOtpEd25519YaoOperationMaterial':
        return {
          activeClientHandle: 'email-otp-operation-active-client',
          metadata: this.metadata,
          issuedGrant: {
            kind: 'operation_step_up',
            grantId: OPERATION_GRANT_ID,
            authorizationSessionId: 'email-otp-operation-authorization',
            expiresAtMs: Date.now() + 30_000,
          },
        };
      case 'disposeEmailOtpEd25519YaoActiveClient':
        return { removed: true };
      default:
        throw new Error(`Unexpected worker operation: ${request.type}`);
    }
  }

  context(): WorkerOperationContext {
    return this;
  }
}

test('Email OTP operation material client carries exact material identity without Wallet Session state', async () => {
  const metadata = activeMetadata();
  const activation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
  const worker = new OperationMaterialWorkerFixture(metadata);
  const request = await normalSigningRequest(metadata);
  const result = await rehydrateEmailOtpEd25519YaoOperationMaterialV1({
    workerContext: worker.context(),
    relayUrl: 'https://relay.example.test',
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    signerSlot: 1,
    providerSubjectId: PROVIDER_SUBJECT_ID,
    expectedOperationalPublicKey: `ed25519:${base58Encode(metadata.registeredPublicKey)}`,
    expectedThresholdSessionId: THRESHOLD_SESSION_ID,
    expectedMaterialActivation: activation,
    normalSigningRequest: request,
    displayDigest: 'display-digest',
    proof: {
      kind: 'email_otp',
      authorityRef: buildWalletAuthAuthorityRefFixture({ walletId: WALLET_ID }),
      providerSubjectId: PROVIDER_SUBJECT_ID,
      challengeId: 'email-otp-operation-challenge',
      otpCode: '123456',
    },
  });

  expect(result.activeClient).toBeInstanceOf(EmailOtpEd25519YaoWorkerActiveClientV1);
  expect(result.issuedGrant.grantId).toBe(OPERATION_GRANT_ID);
  expect(worker.operations).toHaveLength(1);
  expect(worker.operations[0]?.type).toBe('rehydrateEmailOtpEd25519YaoOperationMaterial');
  expect(worker.operations[0]?.payload).not.toHaveProperty('walletSessionJwt');
  expect(worker.operations[0]?.payload).not.toHaveProperty('walletSessionId');
  expect(worker.operations[0]?.payload).not.toHaveProperty('remainingUses');
});

test('sealed Email OTP material authorizes and rehydrates only after operation confirmation', async () => {
  const metadata = activeMetadata();
  const activation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
  const worker = new OperationMaterialWorkerFixture(metadata);
  const activeClient = new EmailOtpEd25519YaoWorkerActiveClientV1(
    worker.context(),
    'email-otp-operation-resolver-client',
    metadata,
  );
  const material = nearEd25519OperationMaterialFixture({
    activeClient,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    signerSlot: 1,
  });
  const issuedGrant = {
    kind: 'operation_step_up' as const,
    grantId: OPERATION_GRANT_ID,
    authorizationSessionId: 'email-otp-operation-authorization',
    expiresAtMs: Date.now() + 30_000,
  };
  const request = await normalSigningRequest(metadata);
  const proof = {
    kind: 'email_otp' as const,
    authorityRef: buildWalletAuthAuthorityRefFixture({ walletId: WALLET_ID }),
    providerSubjectId: PROVIDER_SUBJECT_ID,
    challengeId: 'email-otp-operation-challenge',
    otpCode: '123456',
  };
  const observed: Array<{
    request: RouterAbNormalSigningPrepareRequestV2Wire;
    displayDigest: string;
    proof: typeof proof;
  }> = [];
  const sealed = sealedEmailOtpNearOperationMaterialFixture({
    materialActivation: activation,
    material,
    issuedGrant,
    onAuthorize: (authorization) => {
      observed.push({
        request: authorization.normalSigningRequest,
        displayDigest: authorization.displayDigest,
        proof: authorization.proof,
      });
    },
  });

  expect(observed).toHaveLength(0);
  const resolved = await resolveNearOperationStepUpMaterial({
    kind: 'email_otp_sealed',
    material: sealed,
    expectedActivation: activation,
    normalSigningRequest: request,
    displayDigest: 'confirmed-display-digest',
    proof,
  });

  expect(observed).toEqual([
    {
      request,
      displayDigest: 'confirmed-display-digest',
      proof,
    },
  ]);
  expect(resolved.material).toBe(material);
  expect(resolved.issuedGrant).toEqual(issuedGrant);
  activeClient.dispose();
});
