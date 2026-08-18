import { expect, test } from '@playwright/test';
import { LaneAggregateRevocationApplicationService } from '../../packages/wallet-server/src/core/signingLanes/LaneAggregateRevocationApplicationService';
import type { LaneEnrollmentRevocationResultV1 } from '../../packages/shared-ts/src/signing-lanes';
import {
  buildRevokeLaneEnrollmentV1,
  buildRevokeSigningLaneV1,
  parseRotatableSigningLaneJobV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import {
  parseCorrelationId,
  parseDigestB64u,
} from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  buildR102ActiveProductEpoch,
  buildR102EnrollmentAdmissionRecordFixture,
  buildR102LaneJob,
  buildR102MixedLaneEnrollmentFixture,
  buildR102RevokedProductEpoch,
} from './helpers/r102LaneGateway.fixtures';
import { resolveActiveOwnerWalletExecutionLane } from '../../packages/wallet-server/src/core/signingLanes/WalletExecutionLaneProjection';
import { normalizeWalletAuthMethod } from '../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';
import { walletAuthMethodRecordId } from '../../packages/shared-ts/src/utils/registrationIntent';
import { routerAbMpcMaterialActivationRefFromWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';

const REQUEST_DIGEST = parseDigestB64u(Buffer.alloc(32, 2).toString('base64url'));
const EFFECT_DIGEST = parseDigestB64u(Buffer.alloc(32, 3).toString('base64url'));

test('aggregate revocation retires every manifest child before parent completion', async () => {
  const fixture = buildR102MixedLaneEnrollmentFixture();
  const admission = await buildR102EnrollmentAdmissionRecordFixture(fixture);
  const command = buildRevokeLaneEnrollmentV1({
    enrollmentId: fixture.manifest.enrollmentId,
    walletId: fixture.manifest.walletId,
    manifestDigestB64u: admission.value.lifecycle.manifestDigestB64u,
    reason: 'device_compromise',
    requestedAtMs: 8_000,
  });
  const activeProducts = await Promise.all([
    buildR102ActiveProductEpoch(fixture.children[0]),
    buildR102ActiveProductEpoch(fixture.children[1]),
  ]);
  const childRequests = [
    {
      curve: 'ed25519_yao' as const,
      command: buildChildCommand(fixture.children[0], command, 'one'),
    },
    {
      curve: 'ecdsa_additive' as const,
      command: buildChildCommand(fixture.children[1], command, 'two'),
    },
  ] as const;
  let products = [
    buildR102RevokedProductEpoch(activeProducts[0], childRequests[0].command),
    activeProducts[1],
  ];
  const order: string[] = [];
  const service = new LaneAggregateRevocationApplicationService({
    lifecycleStore: {
      getEnrollment: async () => admission,
      fenceEnrollmentRevocation: async () => ({
        outcome: 'applied',
        version: 2,
        commandDigestB64u: REQUEST_DIGEST,
        value: admission.value,
      }),
      listEnrollmentProductEpochs: async () => products,
    },
    laneLifecycle: {
      revokeSigningLaneV1: async (request) => {
        order.push(String(request.command.walletKeyId));
        const current = products.find(
          (product) => product.walletKeyId === request.command.walletKeyId,
        );
        if (current?.state === 'revoked') return { outcome: 'replayed' };
        products = replaceRevokedProduct(products, request.command);
        return { outcome: 'applied' };
      },
    },
    enrollmentRevocation: {
      completeLaneEnrollmentRevocationV1: async ({ expectedVersion }) => {
        order.push(`complete:${expectedVersion}`);
        return aggregateConflict(command);
      },
    },
  });

  const result = await service.revokeLaneEnrollmentV1({
    command,
    orderedChildren: childRequests,
  });

  expect(result.outcome).toBe('conflict');
  expect(order).toEqual([
    String(fixture.children[0].walletKeyId),
    String(fixture.children[1].walletKeyId),
    'complete:2',
  ]);
  expect(products.every((product) => product.state === 'revoked')).toBe(true);
});

test('aggregate revocation fails closed on a substituted child before retirement', async () => {
  const fixture = buildR102MixedLaneEnrollmentFixture();
  const admission = await buildR102EnrollmentAdmissionRecordFixture(fixture);
  const command = buildRevokeLaneEnrollmentV1({
    enrollmentId: fixture.manifest.enrollmentId,
    walletId: fixture.manifest.walletId,
    manifestDigestB64u: admission.value.lifecycle.manifestDigestB64u,
    reason: 'device_compromise',
    requestedAtMs: 8_000,
  });
  const products = await Promise.all([
    buildR102ActiveProductEpoch(fixture.children[0]),
    buildR102ActiveProductEpoch(fixture.children[1]),
  ]);
  const first = buildChildCommand(fixture.children[0], command, 'one');
  const substituted = buildRevokeSigningLaneV1({
    ...buildChildCommand(fixture.children[1], command, 'two'),
    retirementEffectBindingDigestB64u: parseDigestB64u(Buffer.alloc(32, 9).toString('base64url')),
  });
  let calls = 0;
  const service = new LaneAggregateRevocationApplicationService({
    lifecycleStore: {
      getEnrollment: async () => admission,
      fenceEnrollmentRevocation: async () => ({
        outcome: 'applied',
        version: 2,
        commandDigestB64u: REQUEST_DIGEST,
        value: admission.value,
      }),
      listEnrollmentProductEpochs: async () => [
        products[0],
        buildR102RevokedProductEpoch(
          products[1],
          buildChildCommand(fixture.children[1], command, 'two'),
        ),
      ],
    },
    laneLifecycle: {
      revokeSigningLaneV1: async () => {
        calls += 1;
        return { outcome: 'applied' };
      },
    },
    enrollmentRevocation: {
      completeLaneEnrollmentRevocationV1: async () => aggregateConflict(command),
    },
  });

  await expect(
    service.revokeLaneEnrollmentV1({
      command,
      orderedChildren: [
        { curve: 'ed25519_yao', command: first },
        { curve: 'ecdsa_additive', command: substituted },
      ],
    }),
  ).rejects.toThrow('changed its authorized effect binding');
  expect(calls).toBe(1);
});

test('aggregate revocation leaves unrelated linked enrollment active and owner lane projected', async () => {
  const fixture = buildR102MixedLaneEnrollmentFixture();
  const admission = await buildR102EnrollmentAdmissionRecordFixture(fixture);
  const command = buildRevokeLaneEnrollmentV1({
    enrollmentId: fixture.manifest.enrollmentId,
    walletId: fixture.manifest.walletId,
    manifestDigestB64u: admission.value.lifecycle.manifestDigestB64u,
    reason: 'device_compromise',
    requestedAtMs: 9_000,
  });
  const activeProducts = await Promise.all([
    buildR102ActiveProductEpoch(fixture.children[0]),
    buildR102ActiveProductEpoch(fixture.children[1]),
  ]);
  const unrelatedJob = parseRotatableSigningLaneJobV1({
    ...buildR102LaneJob('unrelated'),
    enrollmentId: 'enrollment-r102-unrelated',
  });
  const unrelatedProduct = await buildR102ActiveProductEpoch(unrelatedJob);
  let targetProducts = activeProducts;
  const listCalls: string[] = [];
  const childRequests = [
    {
      curve: 'ed25519_yao' as const,
      command: buildChildCommand(fixture.children[0], command, 'scope-one'),
    },
    {
      curve: 'ecdsa_additive' as const,
      command: buildChildCommand(fixture.children[1], command, 'scope-two'),
    },
  ] as const;
  const service = new LaneAggregateRevocationApplicationService({
    lifecycleStore: {
      getEnrollment: async () => admission,
      fenceEnrollmentRevocation: async () => ({
        outcome: 'applied',
        version: 2,
        commandDigestB64u: REQUEST_DIGEST,
        value: admission.value,
      }),
      listEnrollmentProductEpochs: async (enrollmentId) => {
        listCalls.push(String(enrollmentId));
        return String(enrollmentId) === String(fixture.manifest.enrollmentId)
          ? targetProducts
          : [unrelatedProduct];
      },
    },
    laneLifecycle: {
      revokeSigningLaneV1: async (request) => {
        targetProducts = replaceRevokedProduct(targetProducts, request.command);
        return { outcome: 'applied' };
      },
    },
    enrollmentRevocation: {
      completeLaneEnrollmentRevocationV1: async () => aggregateConflict(command),
    },
  });

  await expect(
    service.revokeLaneEnrollmentV1({ command, orderedChildren: childRequests }),
  ).resolves.toMatchObject({ outcome: 'conflict' });
  expect(listCalls).toEqual([String(fixture.manifest.enrollmentId)]);
  expect(targetProducts.every((product) => product.state === 'revoked')).toBe(true);
  expect(unrelatedProduct.state).toBe('active');

  const ownerSigner = createWalletEcdsaSignerRecord({
    walletId: fixture.manifest.walletId,
    now: 9_000,
  });
  const ownerAuthMethod = normalizeWalletAuthMethod({
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status: 'active',
    walletId: fixture.manifest.walletId,
    rpId: 'wallet.example.test',
    credentialIdB64u: 'credential-r103-owner',
    credentialPublicKeyB64u: 'public-key-r103-owner',
    counter: 0,
    createdAtMs: 9_000,
    updatedAtMs: 9_000,
  });
  if (!ownerAuthMethod) throw new Error('owner auth fixture is invalid');
  const ownerProjection = await resolveActiveOwnerWalletExecutionLane({
    source: {
      listWalletAuthMethods: async () => [ownerAuthMethod],
      listWalletSigners: async () => [ownerSigner],
    },
    walletId: fixture.manifest.walletId,
    walletAuthMethodId: walletAuthMethodRecordId(ownerAuthMethod),
    expectedMaterialActivation: routerAbMpcMaterialActivationRefFromWire(
      ownerSigner.walletKey.publicCapability.material_activation,
    ),
  });
  expect(ownerProjection.kind).toBe('projected');
});

function buildChildCommand(
  job: ReturnType<typeof buildR102MixedLaneEnrollmentFixture>['children'][number],
  parent: ReturnType<typeof buildRevokeLaneEnrollmentV1>,
  suffix: string,
) {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  return buildRevokeSigningLaneV1({
    walletId: parent.walletId,
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneShareEpoch: job.target.laneShareEpoch,
    expectedRevocationEpoch: job.source.revocationEpoch,
    reason: 'device_compromise',
    retirementCorrelationId: parseCorrelationId(`aggregate-retirement-${suffix}`),
    retirementRequestDigestB64u: REQUEST_DIGEST,
    retirementEffectBindingDigestB64u: EFFECT_DIGEST,
    requestedAtMs: parent.requestedAtMs,
  });
}

function replaceRevokedProduct(
  products: Awaited<ReturnType<typeof buildR102ActiveProductEpoch>>[],
  command: ReturnType<typeof buildRevokeSigningLaneV1>,
) {
  return products.map((product) =>
    product.walletKeyId === command.walletKeyId
      ? buildR102RevokedProductEpoch(product, command)
      : product,
  );
}

function aggregateConflict(
  command: ReturnType<typeof buildRevokeLaneEnrollmentV1>,
): LaneEnrollmentRevocationResultV1 {
  return {
    kind: 'lane_enrollment_revocation_result_v1',
    outcome: 'conflict',
    enrollmentId: command.enrollmentId,
    expectedVersion: 2,
    actualVersion: 3,
    requestedCommandDigestB64u: REQUEST_DIGEST,
    storedCommandDigestB64u: EFFECT_DIGEST,
  };
}
