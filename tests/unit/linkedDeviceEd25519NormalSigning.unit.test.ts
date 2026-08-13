import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { parseLinkedDeviceId } from '../../packages/shared-ts/src/signing-lanes/ids';
import { buildActiveLinkedDeviceExecutionBundleV1 } from '../../packages/sdk-web/src/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import { SigningSessionIds } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import {
  deriveRouterAbNormalSigningAdmissionMaterialV2,
  type RouterAbNormalSigningPrepareResponseV1Wire,
  type RouterAbNormalSigningResponseV1Wire,
} from '../../packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning';
import {
  executeLinkedDeviceEd25519NormalSigningV1,
  type LinkedDeviceEd25519NormalSigningFinalizeRequestV1,
  type LinkedDeviceEd25519NormalSigningPrepareRequestV1,
  type LinkedDeviceEd25519NormalSigningTransportV1,
} from '../../packages/sdk-web/src/core/signingEngine/flows/signNear/shared/linkedDeviceEd25519NormalSigning';
import { buildR103ActiveExecutionFixture } from './helpers/deviceLinkContracts.fixtures';
import { buildR103SealedHolderRecord } from './helpers/r102LaneGateway.fixtures';

const DIGEST = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(11)));
const SIGNING_DIGEST = parseDigestB64u('JZuedIKlTa9uFN6iEy_oaKKD-QYl7Yh3EeinIINM8FA');

function requiredLinkedDeviceId(value: string) {
  const parsed = parseLinkedDeviceId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function digestWire(value: readonly number[]): { readonly bytes: readonly number[] } {
  return { bytes: [...value] };
}

class LinkedSigningTransportFixture implements LinkedDeviceEd25519NormalSigningTransportV1 {
  prepareRequest: LinkedDeviceEd25519NormalSigningPrepareRequestV1 | null = null;
  finalizeRequest: LinkedDeviceEd25519NormalSigningFinalizeRequestV1 | null = null;
  walletSessionJwt = '';

  async prepare(
    input: Parameters<LinkedDeviceEd25519NormalSigningTransportV1['prepare']>[0],
  ): Promise<RouterAbNormalSigningPrepareResponseV1Wire> {
    this.prepareRequest = input.request;
    this.walletSessionJwt =
      input.credential.kind === 'wallet_session_jwt' ? input.credential.walletSessionJwt : '';
    const admission = await deriveRouterAbNormalSigningAdmissionMaterialV2(input.request);
    const intentDigestB64u = base64UrlEncode(Uint8Array.from(admission.intentDigest.bytes));
    return {
      scope: input.request.scope,
      authorized_operation: {
        kind: 'reusable_wallet_session_authorized_operation_v1',
        authorized_operation_id: `linked-ed25519-authorized-operation:${input.request.scope.request_id}`,
        operation_id: input.request.intent.operation_id,
        capability_kind: 'near_ed25519_mpc_signing',
        operation_kind:
          input.request.intent.kind === 'near_transaction_v1'
            ? 'near.sign_transaction'
            : 'near.sign_nep413_message',
        lane_digest_b64u: DIGEST,
        intent_digest_b64u: intentDigestB64u,
        display_digest_b64u: DIGEST,
        operation_fingerprint_digest: DIGEST,
      },
      signing_payload_digest: admission.signingPayloadDigest,
      round1_binding_digest: digestWire(new Uint8Array(32).fill(12)),
      signing_worker: {
        server_id: input.request.scope.signing_worker_id,
        key_epoch: 'worker-epoch:test',
        recipient_encryption_key: 'recipient-key:test',
      },
      server_round1_handle: 'round1:test',
      server_commitments: { hiding: DIGEST, binding: DIGEST },
      server_verifying_share_b64u: DIGEST,
      signature_scheme: 'ed25519_v1',
      prepared_at_ms: 4_000,
      expires_at_ms: input.request.expires_at_ms,
    };
  }

  async finalize(
    input: Parameters<LinkedDeviceEd25519NormalSigningTransportV1['finalize']>[0],
  ): Promise<RouterAbNormalSigningResponseV1Wire> {
    this.finalizeRequest = input.request;
    return {
      scope: input.request.scope,
      signing_payload_digest: input.request.prepare_binding.signing_payload_digest,
      signing_worker: {
        server_id: input.request.scope.signing_worker_id,
        key_epoch: 'worker-epoch:test',
        recipient_encryption_key: 'recipient-key:test',
      },
      signature_scheme: 'ed25519_v1',
      signature: { bytes: Array.from(new Uint8Array(64).fill(13)) },
      signed_at_ms: 4_001,
    };
  }
}

async function linkedSigningFixture() {
  const fixture = await buildR103ActiveExecutionFixture();
  const bundle = await buildActiveLinkedDeviceExecutionBundleV1({
    approval: fixture.deviceLink.approval,
    targetPreparation: fixture.targetCredential.preparation,
    targetCredentialRegistration: fixture.targetCredential.registration,
    provisioningDeliveries: fixture.provisioning.deliveries,
    enrollmentReceipt: fixture.deviceLink.receipt,
    walletSessionDelivery: fixture.walletSession,
  });
  const child = bundle.orderedExecutions[0];
  if (child.kind !== 'active_linked_device_ed25519_execution_v1') {
    throw new Error('linked signing fixture requires an Ed25519 child');
  }
  const token = fixture.walletSession.orderedTokens[0];
  const holderRecord = buildR103SealedHolderRecord(child.job, child.protocolCommitReceipt);
  const state = { authentications: 0, shares: 0, discards: 0 };
  const credentialIdB64u =
    bundle.targetCredentialRegistration.webauthnRegistration.credentialIdB64u;
  const dependencies = {
    authenticator: {
      kind: 'authenticator',
      async run(operation) {
        state.authentications += 1;
        if (operation.kind !== 'get_passkey') throw new Error('expected get_passkey');
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
              clientDataJSON: base64UrlEncode(new Uint8Array([1])),
              authenticatorData: base64UrlEncode(new Uint8Array([2])),
              signature: base64UrlEncode(new Uint8Array(64).fill(3)),
              userHandle: undefined,
            },
            clientExtensionResults: {
              prf: { enabled: true, results: { first: prfFirstB64u } },
            },
          },
          credentialIdB64u,
          rawIdB64u: credentialIdB64u,
          rpId: operation.rpId,
          prf: { kind: 'required', prfFirstB64u },
        };
      },
    },
    holderRepository: {
      async put() {},
      async get() {
        return holderRecord;
      },
      async listForEnrollmentV1() {
        return [holderRecord];
      },
      async delete() {},
    },
    holderMaterial: {
      async openPersistedHolderSigningMaterialV1() {
        return {
          kind: 'device_linking_holder_signing_material_handle_v1',
          handleId: 'holder:test',
          keyFamily: 'ed25519',
        } as const;
      },
      async createEd25519HolderSigningShareV1() {
        state.shares += 1;
        return {
          clientCommitments: { hiding: DIGEST, binding: DIGEST },
          clientVerifyingShareB64u: DIGEST,
          clientSignatureShareB64u: DIGEST,
        };
      },
      async discardHolderSigningMaterialV1() {
        state.discards += 1;
      },
    },
  };
  return {
    bundle,
    child,
    state,
    dependencies,
    walletSession: { kind: 'found' as const, delivery: fixture.walletSession, token },
  };
}

function linkedRequest(expiresAtMs: number) {
  return {
    kind: 'nep413' as const,
    requestId: 'request:test',
    operationId: SigningSessionIds.signingOperation('operation:test'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(`sha256:${DIGEST}`),
    expiresAtMs,
    displayDigestB64u: DIGEST,
    nearAccountId: 'alice.testnet',
    nearNetworkId: 'testnet' as const,
    message: 'Sign in to Seams',
    recipient: 'wallet.example.near',
    nonce: 'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE',
    callbackUrl: 'https://wallet.example/callback',
    expectedSigningDigestB64u: SIGNING_DIGEST,
  };
}

async function linkedNearTransactionRequest(input: { readonly expiresAtMs: number }) {
  const unsignedTransactionBorsh = new Uint8Array([1, 2, 3]);
  return {
    kind: 'near_transaction' as const,
    requestId: 'request:near-transaction',
    operationId: SigningSessionIds.signingOperation('operation:near-transaction'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(`sha256:${DIGEST}`),
    expiresAtMs: input.expiresAtMs,
    displayDigestB64u: DIGEST,
    nearAccountId: 'alice.testnet',
    nearNetworkId: 'testnet' as const,
    transactions: [{ receiverId: 'receiver.testnet', actionFingerprint: DIGEST }],
    unsignedTransactionBorshB64u: base64UrlEncode(unsignedTransactionBorsh),
    expectedSigningDigestB64u: parseDigestB64u(
      base64UrlEncode(
        new Uint8Array(await crypto.subtle.digest('SHA-256', unsignedTransactionBorsh)),
      ),
    ),
  };
}

test('signs one linked Ed25519 operation with exact presence and holder cleanup', async () => {
  const fixture = await linkedSigningFixture();
  const transport = new LinkedSigningTransportFixture();
  const result = await executeLinkedDeviceEd25519NormalSigningV1({
    relayServerUrl: 'https://router.example',
    ...fixture.dependencies,
    bundle: fixture.bundle,
    child: fixture.child,
    walletSession: fixture.walletSession,
    issuedAtMs: fixture.bundle.issuedAtMs,
    request: linkedRequest(fixture.bundle.issuedAtMs + 500),
    transport,
  });

  expect(result.kind).toBe('linked_device_ed25519_normal_signing_result_v1');
  expect(fixture.state).toEqual({ authentications: 1, shares: 1, discards: 1 });
  expect(transport.walletSessionJwt).toBe(fixture.walletSession.token.walletSessionJwt);
  expect(transport.prepareRequest?.linkedDeviceExecution.enrollmentId).toBe(
    fixture.bundle.enrollmentId,
  );
  expect(transport.prepareRequest?.intent.kind).toBe('nep413_v1');
  expect(transport.finalizeRequest?.localPresenceAssertion).toEqual(
    transport.prepareRequest?.localPresenceAssertion,
  );
});

test('rejects a Wallet Session delivery from another linked device before presence', async () => {
  const fixture = await linkedSigningFixture();
  const otherDevice = requiredLinkedDeviceId('device:r103:substituted');
  const walletSession = {
    ...fixture.walletSession,
    delivery: { ...fixture.walletSession.delivery, deviceId: otherDevice },
  };

  await expect(
    executeLinkedDeviceEd25519NormalSigningV1({
      relayServerUrl: 'https://router.example',
      ...fixture.dependencies,
      bundle: fixture.bundle,
      child: fixture.child,
      walletSession,
      issuedAtMs: fixture.bundle.issuedAtMs,
      request: linkedRequest(fixture.bundle.issuedAtMs + 500),
      transport: new LinkedSigningTransportFixture(),
    }),
  ).rejects.toThrow('Wallet Session token does not match');
  expect(fixture.state).toEqual({ authentications: 0, shares: 0, discards: 0 });
});

test('dispatches the linked NEAR transaction discriminator to the transaction request', async () => {
  const fixture = await linkedSigningFixture();
  const transport = new LinkedSigningTransportFixture();

  await executeLinkedDeviceEd25519NormalSigningV1({
    relayServerUrl: 'https://router.example',
    ...fixture.dependencies,
    bundle: fixture.bundle,
    child: fixture.child,
    walletSession: fixture.walletSession,
    issuedAtMs: fixture.bundle.issuedAtMs,
    request: await linkedNearTransactionRequest({
      expiresAtMs: fixture.bundle.issuedAtMs + 500,
    }),
    transport,
  });

  expect(transport.prepareRequest?.intent.kind).toBe('near_transaction_v1');
  expect(fixture.state).toEqual({ authentications: 1, shares: 1, discards: 1 });
});
