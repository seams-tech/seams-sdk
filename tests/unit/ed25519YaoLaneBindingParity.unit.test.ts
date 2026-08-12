import { expect, test } from '@playwright/test';
import {
  computeEd25519YaoLaneSessionDigestV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationDigests';
import { parseRotatableSigningLaneJobV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import {
  deriveRouterAbEd25519YaoApplicationBindingDigestV1,
  deriveRouterAbEd25519YaoStableContextBindingV1,
  type RouterAbEd25519YaoApplicationBindingFactsV1,
  type RouterAbEd25519YaoCeremonyBindingV1,
} from '../../packages/shared-ts/src/utils/routerAbEd25519Yao';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { routerAbMpcMaterialActivationRefToWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { assertEd25519YaoLaneCeremonyBindingParityV1 } from '../../packages/sdk-web/src/core/signingEngine/threshold/crypto/ed25519YaoLaneWasm';
import { buildR102LaneJob } from './helpers/r102LaneGateway.fixtures';

const RECIPIENT_KEY_B64U = base64UrlEncode(new Uint8Array(32).fill(7));

const applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1 = {
  wallet_id: 'wallet-r102-lifecycle',
  near_ed25519_signing_key_id: 'near-key-r102-worker-source',
  signing_root_id: 'signing-root-r102-worker-source',
  key_creation_signer_slot: 1,
};

async function boundInputs(): Promise<{
  job: ReturnType<typeof buildR102LaneJob>;
  ceremonyBinding: RouterAbEd25519YaoCeremonyBindingV1;
  applicationBindingDigestB64u: string;
}> {
  const sourceJob = buildR102LaneJob('worker-source');
  if (sourceJob.keyFamily !== 'ed25519') throw new Error('fixture changed key family');
  const stableContextBindingB64u = base64UrlEncode(
    Uint8Array.from(
      await deriveRouterAbEd25519YaoStableContextBindingV1(applicationBinding, [1, 2]),
    ),
  );
  const job = parseRotatableSigningLaneJobV1({
    ...sourceJob,
    targetHolder: {
      ...sourceJob.targetHolder,
      hpkePublicKeyB64u: RECIPIENT_KEY_B64U,
    },
    targetSigningWorker: {
      ...sourceJob.targetSigningWorker,
      hpkePublicKeyB64u: RECIPIENT_KEY_B64U,
    },
    stableContextBindingB64u,
  });
  const ceremonyBinding: RouterAbEd25519YaoCeremonyBindingV1 = {
    lifecycle: {
      lifecycle_id: String(job.operationId),
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: String(job.source.laneShareEpoch),
      account_id: String(job.walletId),
      session_id: String(job.operationId),
      signer_set_id: String(job.source.participantBindingDigestB64u),
      selected_server_id: String(job.source.materialActivation.signingWorker),
    },
    operation: job.yaoRequestKind,
    session_id: Array.from(
      base64UrlDecode(await computeEd25519YaoLaneSessionDigestV1(job)),
    ),
    stable_key_context_binding: Array.from(base64UrlDecode(stableContextBindingB64u)),
    material_activation: routerAbMpcMaterialActivationRefToWire(job.source.materialActivation),
  };
  return {
    job,
    ceremonyBinding,
    applicationBindingDigestB64u: base64UrlEncode(
      Uint8Array.from(
        await deriveRouterAbEd25519YaoApplicationBindingDigestV1(applicationBinding),
      ),
    ),
  };
}

test('accepts exact Ed25519 Yao lane public binding parity', async () => {
  const input = await boundInputs();
  await expect(
    assertEd25519YaoLaneCeremonyBindingParityV1({
      ...input,
      applicationBinding,
      participantIds: [1, 2],
    }),
  ).resolves.toBeUndefined();
});

test('reports the first exact binding mismatch before WASM', async () => {
  const input = await boundInputs();
  await expect(
    assertEd25519YaoLaneCeremonyBindingParityV1({
      ...input,
      applicationBinding: {
        ...applicationBinding,
        signing_root_id: 'signing-root-r102-substituted',
      },
      participantIds: [1, 2],
    }),
  ).rejects.toThrow('application binding digest mismatch');
});
