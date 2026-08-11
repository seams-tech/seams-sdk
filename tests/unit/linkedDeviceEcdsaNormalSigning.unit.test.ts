import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  buildActiveWalletKeyLifecycle,
  buildEvmFamilyWalletKeyRecord,
  parseWalletKeyVersion,
} from '../../packages/shared-ts/src/signing-lanes/recordParsers';
import { parseRotatableSigningLaneJobV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { parseSecp256k1CompressedPublicKeyB64u } from '../../packages/shared-ts/src/passkey-custody/primitives';
import { buildActiveLinkedDeviceExecutionBundleV1 } from '../../packages/sdk-web/src/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import {
  EcdsaOnlineClientRequestType,
  EcdsaOnlineClientResponseType,
  EcdsaPresignClientRequestType,
  EcdsaPresignClientResponseType,
  type WorkerOperationContext,
} from '../../packages/sdk-web/src/core/signingEngine/workerManager/workerTypes';
import {
  executeLinkedDeviceEcdsaNormalSigningV1,
  type LinkedDeviceEcdsaNormalSigningTransportV1,
} from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/shared/linkedDeviceEcdsaNormalSigning';
import { requireEvmFamilySigningKeySlotId } from '../../packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId';
import { buildR103ActiveExecutionFixture } from './helpers/deviceLinkContracts.fixtures';
import {
  buildR102EcdsaLaneJob,
  buildR102ProtocolCommitReceipt,
  buildR103SealedHolderRecord,
} from './helpers/r102LaneGateway.fixtures';

const R33 = Uint8Array.from(
  Buffer.from('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex'),
);
const VALID_SIGNATURE65_B64U =
  '9Vht2lMjQxvAZF7DYGZeNFEAl7O1sieic2Hn9tnDPKBgsUDMZksYnSG9PCGlRkS09MOQCxzBiMx6a9Z25HjngwA';

async function fixture() {
  const source = await buildR103ActiveExecutionFixture();
  const base = await buildActiveLinkedDeviceExecutionBundleV1({
    approval: source.deviceLink.approval,
    targetPreparation: source.targetCredential.preparation,
    targetCredentialRegistration: source.targetCredential.registration,
    provisioningDeliveries: source.provisioning.deliveries,
    enrollmentReceipt: source.deviceLink.receipt,
    walletSessionDelivery: source.walletSession,
  });
  const edChild = base.orderedExecutions[0];
  if (edChild?.keyFamily !== 'ed25519') throw new Error('fixture child must be Ed25519');
  const template = buildR102EcdsaLaneJob('linked-device-test');
  const job = parseRotatableSigningLaneJobV1({
    ...template,
    operationId: String(edChild.job.operationId),
    enrollmentId: String(edChild.job.enrollmentId),
    idempotencyKey: String(edChild.job.idempotencyKey),
    walletId: String(edChild.job.walletId),
    walletKeyId: String(edChild.job.walletKeyId),
    source: {
      ...template.source,
      laneId: String(edChild.job.source.laneId),
      laneShareEpoch: String(edChild.job.source.laneShareEpoch),
      revocationEpoch: edChild.job.source.revocationEpoch,
      holderParticipantId: String(edChild.job.source.holderParticipantId),
      signingWorkerParticipantId: String(edChild.job.source.signingWorkerParticipantId),
      signingWorkerRecipientKeyId: String(edChild.job.source.signingWorkerRecipientKeyId),
    },
    targetHolder: edChild.job.targetHolder,
    targetSigningWorker: edChild.job.targetSigningWorker,
    targetMaterialActivationId: String(edChild.materialActivation.activationId),
    target: {
      ...template.target,
      laneId: String(edChild.laneId),
      laneShareEpoch: String(edChild.laneShareEpoch),
    },
  });
  const protocolCommitReceipt = buildR102ProtocolCommitReceipt(job);
  const walletKey = buildEvmFamilyWalletKeyRecord({
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    walletKeyVersion: parseWalletKeyVersion(
      `wallet-key-version:${String(job.target.laneShareEpoch)}`,
    ),
    evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
      String(job.evmFamilySigningKeySlotId),
    ),
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(job.thresholdPublicKey33B64u),
    evmAddress: job.evmAddress,
    lifecycle: buildActiveWalletKeyLifecycle({ activatedAtMs: base.activatedAtMs }),
  });
  const { kind: _kind, keyFamily: _family, walletKey: _oldKey, job: _oldJob, ...common } = edChild;
  const child = {
    ...common,
    kind: 'active_linked_device_ecdsa_execution_v1' as const,
    keyFamily: 'ecdsa_secp256k1' as const,
    walletKey,
    job,
    protocolCommitReceipt,
  };
  const now = Date.now();
  const bundle = {
    ...base,
    issuedAtMs: now - 1_000,
    expiresAtMs: now + 30_000,
    orderedExecutions: [child],
  };
  const token = { ...source.walletSession.orderedTokens[0], keyFamily: 'ecdsa_secp256k1' as const };
  const walletSession = {
    kind: 'found' as const,
    delivery: {
      ...source.walletSession,
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 30_000,
      orderedTokens: [token],
    },
    token,
  };
  const holderRecord = buildR103SealedHolderRecord(job, protocolCommitReceipt);
  return { bundle, child, walletSession, holderRecord, credentialIdB64u: token.walletKeyId, now };
}

test('claims before holder open, completes linked presign, finalizes once, and discards holder', async () => {
  const value = await fixture();
  const events: string[] = [];
  const credentialIdB64u =
    value.bundle.targetCredentialRegistration.webauthnRegistration.credentialIdB64u;
  const transport: LinkedDeviceEcdsaNormalSigningTransportV1 = {
    presignInit: async ({ request }) => {
      events.push('presign-init');
      return {
        kind: 'continue',
        presignSessionId: request.presign_session_id ?? 'missing',
        stage: 'presign',
        event: 'none',
        outgoingMessagesB64u: [],
      };
    },
    presignStep: async ({ request }) => {
      events.push('presign-step');
      return {
        kind: 'complete',
        presignSessionId: request.presign_session_id,
        stage: 'done',
        event: 'presign_done',
        outgoingMessagesB64u: [],
        serverPresignatureId: request.client_presignature_id,
        serverBigR33B64u: base64UrlEncode(R33),
        signingWorkerRerandomizationContribution32B64u: base64UrlEncode(new Uint8Array(32).fill(4)),
      };
    },
    finalize: async ({ request }) => {
      events.push('finalize');
      return {
        scope: request.scope,
        request_id: request.request_id,
        request_digest: { bytes: [] },
        signing_digest: { bytes: Array.from(new Uint8Array(32).fill(6)) },
        signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
        signature65_b64u: VALID_SIGNATURE65_B64U,
      };
    },
  };
  const workerCtx = {
    requestWorkerOperation: async (args: {
      kind: string;
      request: { type: number; payload?: Record<string, unknown> };
    }) => {
      if (
        args.kind === 'ecdsaPresignClient' &&
        args.request.type === EcdsaPresignClientRequestType.SessionInit
      ) {
        events.push('source-init');
        return {
          type: EcdsaPresignClientResponseType.SessionInitSuccess,
          payload: {
            authority: { kind: 'linked_holder_signing_material' },
            progress: {
              stage: 'done',
              event: 'presign_done',
              outgoingMessages: [],
              presignatureHandle: 'client-handle',
              presignatureBigR33: R33.buffer,
            },
          },
        };
      }
      if (
        args.kind === 'ecdsaPresignClient' &&
        args.request.type === EcdsaPresignClientRequestType.Admit
      ) {
        events.push('source-admit');
        return {
          type: EcdsaPresignClientResponseType.AdmitSuccess,
          payload: {
            kind: 'ecdsa_client_presignature_admitted_v1',
            materialHandle: 'client-handle',
            presignatureId: String(args.request.payload?.expectedPresignatureId),
          },
        };
      }
      if (
        args.kind === 'ecdsaPresignClient' &&
        args.request.type === EcdsaPresignClientRequestType.Reserve
      ) {
        events.push('source-reserve');
        return {
          type: EcdsaPresignClientResponseType.ReserveSuccess,
          payload: {
            kind: 'ecdsa_client_presignature_lifecycle_advanced_v1',
            materialHandle: 'client-handle',
          },
        };
      }
      if (
        args.kind === 'ecdsaPresignClient' &&
        args.request.type === EcdsaPresignClientRequestType.Commit
      ) {
        events.push('source-commit');
        return {
          type: EcdsaPresignClientResponseType.CommitSuccess,
          payload: {
            kind: 'ecdsa_client_presignature_lifecycle_advanced_v1',
            materialHandle: 'client-handle',
          },
        };
      }
      if (
        args.kind === 'ecdsaOnlineClient' &&
        args.request.type === EcdsaOnlineClientRequestType.ComputeSignatureShare
      ) {
        events.push('source-compute');
        return {
          type: EcdsaOnlineClientResponseType.ComputeSignatureShareSuccess,
          payload: new Uint8Array(32).fill(3).buffer,
        };
      }
      if (
        args.kind === 'evmCrypto' &&
        args.request.type === 'verifySecp256k1RecoverableSignatureAgainstPublicKey33'
      )
        return R33.buffer;
      throw new Error(`unexpected worker request ${args.kind}/${args.request.type}`);
    },
  } as WorkerOperationContext;
  const result = await executeLinkedDeviceEcdsaNormalSigningV1({
    relayServerUrl: 'https://router.example',
    workerCtx,
    bundle: value.bundle,
    child: value.child,
    walletSession: value.walletSession,
    issuedAtMs: value.now,
    request: {
      requestId: 'request:r103-ecdsa',
      operationId: 'operation:r103-ecdsa',
      operationDigests: {
        laneDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(5))),
        intentDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(6))),
        displayDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7))),
      },
      signingDigest32: new Uint8Array(32).fill(6),
      expiresAtMs: value.now + 20_000,
    },
    authenticator: {
      kind: 'authenticator',
      async run(operation) {
        events.push('webauthn');
        const prfFirstB64u = base64UrlEncode(new Uint8Array(32).fill(7));
        return {
          ok: true,
          operation: 'get_passkey',
          requirePrfFirst: true,
          credential: {
            id: credentialIdB64u,
            rawId: credentialIdB64u,
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
              clientDataJSON: 'AQ',
              authenticatorData: 'Ag',
              signature: base64UrlEncode(new Uint8Array(64).fill(3)),
              userHandle: undefined,
            },
            clientExtensionResults: { prf: { enabled: true, results: { first: prfFirstB64u } } },
          },
          credentialIdB64u,
          rawIdB64u: credentialIdB64u,
          rpId: operation.rpId,
          prf: { kind: 'required', prfFirstB64u },
        };
      },
    },
    holderRepository: {
      async get() {
        return value.holderRecord;
      },
      async put() {},
      async delete() {},
      async listForEnrollmentV1() {
        return [value.holderRecord];
      },
    },
    holderMaterial: {
      async openPersistedHolderSigningMaterialV1() {
        events.push('holder-open');
        return {
          kind: 'device_linking_holder_signing_material_handle_v1',
          handleId: 'holder:test',
          keyFamily: 'ecdsa_secp256k1',
        };
      },
      async createEd25519HolderSigningShareV1() {
        throw new Error('ECDSA test must not call Ed25519 share');
      },
      async discardHolderSigningMaterialV1() {
        events.push('discard');
      },
    },
    transport,
  });
  expect(result.signature65).toHaveLength(65);
  expect(events).toEqual([
    'webauthn',
    'presign-init',
    'holder-open',
    'source-init',
    'presign-step',
    'source-admit',
    'source-reserve',
    'source-commit',
    'source-compute',
    'finalize',
    'discard',
  ]);
});
