import { expect, test } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { keccak256 } from 'viem';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { routerAbEcdsaDerivationContextBindingB64uV1 } from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { routerAbMpcMaterialActivationRefToWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { buildSourcePreservingEcdsaReservationRequestFixture } from './helpers/ordinarySourcePreservingReservation.fixtures';
import { FIXED_ECDSA_PRESIGN_PROTOCOL_ID } from '../../packages/wallet/src/core/signingEngine/workerManager/ecdsaPresignPoolIdentity';

const TEST_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(TEST_DIRECTORY, '../..');
const DERIVATION_WORKER_PATH = path.join(
  REPOSITORY_ROOT,
  'packages/wallet/dist/workers/ecdsa-derivation-client.worker.js',
);
const DERIVATION_WASM_PATH = path.join(
  REPOSITORY_ROOT,
  'packages/wallet/dist/workers/router_ab_ecdsa_client_bg.wasm',
);
const PAGE_URL = 'https://wallet.example.localhost/__ecdsa-holder-retention.html';
const DERIVATION_WORKER_URL =
  'https://wallet.example.localhost/sdk/workers/ecdsa-derivation-client.worker.js?holder-retention';
const DERIVATION_WASM_URL =
  'https://wallet.example.localhost/sdk/workers/router_ab_ecdsa_client_bg.wasm';

function compressedPublicKeyB64u(privateKey: bigint): string {
  return base64UrlEncode(secp256k1.getPublicKey(privateKeyBytes(privateKey), true));
}

function ethereumAddressB64u(privateKey: bigint): string {
  const publicKey = secp256k1.getPublicKey(privateKeyBytes(privateKey), false);
  const digest = keccak256(`0x${Buffer.from(publicKey.slice(1)).toString('hex')}`);
  return base64UrlEncode(Uint8Array.from(Buffer.from(digest.slice(-40), 'hex')));
}

function privateKeyBytes(privateKey: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let remaining = privateKey;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function x25519PublicKeyB64u(seed: number): string {
  return base64UrlEncode(new Uint8Array(32).fill(seed));
}

function x25519PublicKeyWire(seed: number): string {
  return `x25519:${Buffer.from(new Uint8Array(32).fill(seed)).toString('hex')}`;
}

async function holderRetentionFixture(): Promise<{
  readonly holderHandleId: string;
  readonly signingShare32: number[];
  readonly activationReceiptJson: string;
  readonly ordinaryExportFacts: Record<string, unknown>;
  readonly expectedBindingBase: Record<string, unknown>;
  readonly groupPublicKey33: number[];
  readonly poolIdentity: Record<string, unknown>;
}> {
  const reservation =
    buildSourcePreservingEcdsaReservationRequestFixture('worker-holder-retention');
  const sourceContribution = reservation.preparation.sourceContribution;
  const sourceActivation = sourceContribution.binding.source.activation;
  const targetActivation = sourceContribution.binding.target.activation;
  const sourceScope = reservation.preparation.sourceDerivation.sourceNormalSigning.scope;
  const applicationBindingDigestB64u = sourceScope.context.application_binding_digest_b64u;
  const contextBindingB64u = await routerAbEcdsaDerivationContextBindingB64uV1({
    application_binding_digest_b64u: applicationBindingDigestB64u,
  });
  const clientPublicKey33B64u = compressedPublicKeyB64u(1n);
  const thresholdPublicKey33B64u = compressedPublicKeyB64u(2n);
  const thresholdEthereumAddress20B64u = ethereumAddressB64u(2n);
  const sourceRelayerPublicKey33B64u = compressedPublicKeyB64u(1n);
  const sourceSigningWorkerRecipientPublicKeyB64u = x25519PublicKeyB64u(17);
  const targetSigningWorkerRecipientPublicKeyB64u = x25519PublicKeyB64u(19);
  const sourceNormalSigning = {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      ...sourceScope,
      public_identity: {
        ...sourceScope.public_identity,
        context_binding_b64u: contextBindingB64u,
        derivation_client_share_public_key33_b64u: clientPublicKey33B64u,
        server_public_key33_b64u: sourceRelayerPublicKey33B64u,
        threshold_public_key33_b64u: thresholdPublicKey33B64u,
        ethereum_address20_b64u: thresholdEthereumAddress20B64u,
      },
      material_activation: routerAbMpcMaterialActivationRefToWire(sourceActivation),
      signing_worker: {
        ...sourceScope.signing_worker,
        server_id: sourceActivation.signingWorker,
        recipient_encryption_key: x25519PublicKeyWire(17),
      },
    },
  };
  const targetNormalSigning = {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      ...sourceScope,
      public_identity: {
        ...sourceScope.public_identity,
        context_binding_b64u: contextBindingB64u,
        derivation_client_share_public_key33_b64u: clientPublicKey33B64u,
        server_public_key33_b64u: sourceRelayerPublicKey33B64u,
        threshold_public_key33_b64u: thresholdPublicKey33B64u,
        ethereum_address20_b64u: thresholdEthereumAddress20B64u,
      },
      material_activation: routerAbMpcMaterialActivationRefToWire(targetActivation),
      signing_worker: {
        ...sourceScope.signing_worker,
        server_id: targetActivation.signingWorker,
        recipient_encryption_key: x25519PublicKeyWire(19),
      },
    },
  };
  const binding = {
    ...sourceContribution.binding,
    source: {
      ...sourceContribution.binding.source,
      clientPublicKey33B64u: clientPublicKey33B64u,
      relayerPublicKey33B64u: sourceRelayerPublicKey33B64u,
      thresholdPublicKey33B64u,
      thresholdEthereumAddress20B64u,
    },
    target: {
      ...sourceContribution.binding.target,
      clientRecipientPublicKeyB64u: x25519PublicKeyB64u(23),
      signingWorkerRecipientPublicKeyB64u: targetSigningWorkerRecipientPublicKeyB64u,
    },
    targetClientPublicKey33B64u: clientPublicKey33B64u,
  };
  const activationReceipt = {
    state: 'inactive',
    binding,
    sourceDerivation: {
      applicationBindingDigestB64u,
      clientShareRetryCounter: sourceScope.public_identity.client_share_retry_counter,
      ecdsaThresholdKeyId: sourceScope.ecdsa_threshold_key_id,
      sourceNormalSigning,
    },
    targetRelayerPublicKey33B64u: sourceRelayerPublicKey33B64u,
    thresholdPublicKey33B64u,
    thresholdEthereumAddress20B64u,
    normalSigning: targetNormalSigning,
  };
  const ordinaryExportFacts = {
    context: sourceScope.context,
    lifecycle: {
      lifecycle_id: 'lifecycle-worker-holder-retention',
      work_kind: 'key_export',
      primitive_request_kind: 'export',
      root_share_epoch: sourceScope.activation_epoch,
      account_id: sourceScope.wallet_id,
      session_id: 'session-worker-holder-retention',
      signer_set_id: 'signer-set-worker-holder-retention',
      selected_server_id: targetActivation.signingWorker,
    },
    public_identity: targetNormalSigning.scope.public_identity,
    signer_set: {
      signer_set_id: 'signer-set-worker-holder-retention',
      policy: 'all_2',
      signer_a: { role: 'signer_a', signer_id: 'signer-a-holder-retention', key_epoch: 'epoch-a' },
      signer_b: { role: 'signer_b', signer_id: 'signer-b-holder-retention', key_epoch: 'epoch-b' },
      selected_server: targetNormalSigning.scope.signing_worker,
    },
    router_id: 'router-worker-holder-retention',
    client_id: sourceScope.wallet_id,
    authorization: {
      kind: 'reusable_wallet_session',
      wallet_session_id: 'wallet-session-worker-holder-retention',
    },
    material_activation: routerAbMpcMaterialActivationRefToWire(targetActivation),
    export_authorization_digest_b64u: base64UrlEncode(new Uint8Array(32).fill(41)),
    export_nonce: 'export-nonce-worker-holder-retention',
    expires_at_ms: Date.now() + 60_000,
    deriver_recipient_keys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-a',
        public_key: x25519PublicKeyWire(31),
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-b',
        public_key: x25519PublicKeyWire(37),
      },
    },
  };
  return {
    holderHandleId: 'holder-worker-retention',
    signingShare32: Array.from(new Uint8Array(31).fill(0)).concat(1),
    activationReceiptJson: JSON.stringify(activationReceipt),
    ordinaryExportFacts,
    expectedBindingBase: {
      wallet_id: sourceScope.wallet_id,
      key_handle: 'key-handle-worker-holder-retention',
      ecdsa_threshold_key_id: sourceScope.ecdsa_threshold_key_id,
      signing_root_id: sourceScope.signing_root_id,
      signing_root_version: sourceScope.signing_root_version,
      activation_epoch: sourceScope.activation_epoch,
      signing_worker_id: targetActivation.signingWorker,
      context_binding_b64u: contextBindingB64u,
      threshold_public_key33_b64u: thresholdPublicKey33B64u,
      export_authorization_digest_b64u: ordinaryExportFacts.export_authorization_digest_b64u,
      export_nonce: ordinaryExportFacts.export_nonce,
      authorization_kind: 'reusable_wallet_session',
      authorization_id: 'wallet-session-worker-holder-retention',
      material_activation: routerAbMpcMaterialActivationRefToWire(targetActivation),
      lifecycle_id: 'lifecycle-worker-holder-retention',
      recipient_identity: sourceScope.wallet_id,
      expires_at_ms: ordinaryExportFacts.expires_at_ms,
    },
    groupPublicKey33: Array.from(Buffer.from(thresholdPublicKey33B64u, 'base64url')),
    poolIdentity: {
      poolKey: 'pool-worker-holder-retention',
      materialActivationId: targetActivation.activationId,
      capability: targetActivation.capability,
      keyBinding: targetActivation.keyBinding,
      walletId: targetActivation.materialOwner,
      signingScopeB64u: 'scope-worker-holder-retention',
      pairRole: 'client',
      keyEpoch: 'key-epoch-worker-holder-retention',
      activationEpoch: sourceScope.activation_epoch,
      protocolId: FIXED_ECDSA_PRESIGN_PROTOCOL_ID,
    },
  };
}

type WorkerRpcResult =
  | { readonly ok: true; readonly result: Record<string, unknown> }
  | { readonly ok: false; readonly error: string };

async function runHolderRetentionScenario(input: {
  readonly workerUrl: string;
  readonly holderHandleId: string;
  readonly signingShare32: number[];
  readonly activationReceiptJson: string;
  readonly ordinaryExportFacts: Record<string, unknown>;
  readonly expectedBindingBase: Record<string, unknown>;
  readonly groupPublicKey33: number[];
  readonly poolIdentity: Record<string, unknown>;
}): Promise<{
  readonly ordinaryExportFinalization: WorkerRpcResult;
  readonly secondExportRequest: WorkerRpcResult;
  readonly presignInit: WorkerRpcResult;
}> {
  const worker = new Worker(input.workerUrl, { type: 'module' });
  const request = async (
    id: string,
    type: number,
    payload: Record<string, unknown>,
  ): Promise<WorkerRpcResult> =>
    await new Promise<WorkerRpcResult>((resolve, reject) => {
      const timeout = window.setTimeout(() => reject(new Error(`${id} timed out`)), 20_000);
      const onMessage = (event: MessageEvent): void => {
        const value = event.data as {
          readonly id?: unknown;
          readonly ok?: unknown;
          readonly error?: unknown;
          readonly result?: Record<string, unknown>;
        };
        if (value.id !== id) return;
        window.clearTimeout(timeout);
        worker.removeEventListener('message', onMessage);
        if (value.ok === true && value.result) {
          resolve({ ok: true, result: value.result });
        } else {
          resolve({ ok: false, error: String(value.error || `${id} failed`) });
        }
      };
      worker.addEventListener('message', onMessage);
      worker.postMessage({ id, type, payload });
    });

  try {
    await new Promise<void>((resolve, reject) => {
      const timeout = window.setTimeout(
        () => reject(new Error('ECDSA holder worker ready timeout')),
        20_000,
      );
      const onMessage = (event: MessageEvent): void => {
        const value = event.data as { readonly type?: unknown; readonly ready?: unknown };
        if (value.type !== 'WORKER_READY' && value.ready !== true) return;
        window.clearTimeout(timeout);
        worker.removeEventListener('message', onMessage);
        resolve();
      };
      worker.addEventListener('message', onMessage);
    });

    const signingShare = Uint8Array.from(input.signingShare32);
    const stored = await request('holder-store', 70_023, {
      holderHandleId: input.holderHandleId,
      ownedSigningShare32: signingShare.buffer,
      activationReceiptJson: input.activationReceiptJson,
    });
    if (!stored.ok) throw new Error(stored.error);

    const created = await request('holder-export-request', 70_027, {
      kind: 'create_ecdsa_holder_ordinary_export_request_v1',
      holderHandleId: input.holderHandleId,
      request: input.ordinaryExportFacts,
    });
    if (!created.ok) throw new Error(created.error);
    const createdPayload = created.result.payload as Record<string, unknown>;
    const createdRequest = createdPayload.request as Record<string, unknown>;
    const requestDigestB64u = String(createdPayload.requestDigestB64u);
    const expectedBinding = {
      ...input.expectedBindingBase,
      export_request_digest_b64u: requestDigestB64u,
      recipient_public_key: String(createdRequest.client_ephemeral_public_key),
    };
    const invalidForwardedResponse = {
      result: 'forwarded',
      response: {
        bundles: {
          signerA: {
            kind: 'recipient_proof_bundle',
            transcriptDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            payloadB64u: 'AQ',
          },
          signerB: {
            kind: 'recipient_proof_bundle',
            transcriptDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            payloadB64u: 'Ag',
          },
        },
      },
      signing_worker_export: {
        version: 'router-ab-ecdsa-derivation/signing-worker-export-share-envelope/v1',
        algorithm: 'hpke_x25519_hkdf_sha256_aes256gcm_v1',
        binding: expectedBinding,
        ciphertext_and_tag: new Array(49).fill(1),
      },
    };
    const ordinaryExportFinalization = await request('holder-export-finalize', 70_028, {
      kind: 'finalize_ecdsa_holder_ordinary_export_v1',
      holderHandleId: input.holderHandleId,
      requestDigestB64u,
      expectedBinding,
      forwardedResponse: invalidForwardedResponse,
    });
    if (ordinaryExportFinalization.ok) {
      throw new Error('invalid export proof unexpectedly finalized');
    }
    const secondExportRequest = await request('holder-export-request-retry', 70_027, {
      kind: 'create_ecdsa_holder_ordinary_export_request_v1',
      holderHandleId: input.holderHandleId,
      request: input.ordinaryExportFacts,
    });

    const channel = new MessageChannel();
    worker.postMessage({ kind: 'attach_linked_holder_to_ecdsa_presign_v1', port: channel.port2 }, [
      channel.port2,
    ]);
    const presignInit = await new Promise<WorkerRpcResult>((resolve, reject) => {
      const timeout = window.setTimeout(
        () => reject(new Error('holder presign init timeout')),
        20_000,
      );
      channel.port1.addEventListener('message', (event: MessageEvent): void => {
        const value = event.data as {
          readonly requestId?: unknown;
          readonly ok?: unknown;
          readonly error?: unknown;
          readonly result?: Record<string, unknown>;
        };
        if (value.requestId !== 'holder-presign-init') return;
        window.clearTimeout(timeout);
        if (value.ok === true && value.result) {
          resolve({ ok: true, result: value.result });
        } else {
          resolve({ ok: false, error: String(value.error || 'holder presign init failed') });
        }
      });
      channel.port1.start();
      const groupPublicKey33 = Uint8Array.from(input.groupPublicKey33);
      channel.port1.postMessage(
        {
          kind: 'opaque_ecdsa_presign_session_init_v1',
          requestId: 'holder-presign-init',
          authority: {
            kind: 'linked_holder_signing_material',
            holderHandleId: input.holderHandleId,
          },
          sessionId: 'holder-presign-session',
          groupPublicKey33: groupPublicKey33.buffer,
          materialExpiresAtMs: Date.now() + 60_000,
          poolIdentity: input.poolIdentity,
        },
        [groupPublicKey33.buffer],
      );
    });
    channel.port1.close();
    return { ordinaryExportFinalization, secondExportRequest, presignInit };
  } finally {
    worker.terminate();
  }
}

test('keeps a linked ECDSA holder after rejected ordinary-export finalization for subsequent presign', async ({
  page,
}) => {
  await page.route(PAGE_URL, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<!doctype html><meta charset="utf-8"><title>ECDSA holder retention</title>',
    });
  });
  await page.route(DERIVATION_WORKER_URL, async (route) => {
    await route.fulfill({ path: DERIVATION_WORKER_PATH, contentType: 'application/javascript' });
  });
  await page.route(`${DERIVATION_WASM_URL}*`, async (route) => {
    await route.fulfill({ path: DERIVATION_WASM_PATH, contentType: 'application/wasm' });
  });
  await page.goto(PAGE_URL, { waitUntil: 'domcontentloaded' });

  const fixture = await holderRetentionFixture();
  const result = await page.evaluate(runHolderRetentionScenario, {
    workerUrl: DERIVATION_WORKER_URL,
    ...fixture,
  });

  expect(result.ordinaryExportFinalization.ok).toBe(false);
  expect(result.secondExportRequest.ok).toBe(true);
  expect(result.presignInit.ok).toBe(true);
  if (result.presignInit.ok) {
    expect(result.presignInit.result.kind).toBe('progress');
  }
});
