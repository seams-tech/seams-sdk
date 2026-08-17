import { expect, test } from '@playwright/test';
import type { Ed25519YaoLaneJobV1 } from '../../packages/shared-ts/src/signing-lanes/rotation';
import {
  createConcreteLaneHolderWorkerV1,
  loadLaneCustodySealV1,
  type LaneHolderWasmFactoryV1,
} from '../../packages/sdk-web/src/core/signingEngine/workerManager/workers/laneHolderWorkerBackend';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { passkeyCustodyEnvelope } from './helpers/passkeyCustodyEnvelope.fixtures';
import {
  buildR102LaneJob,
  buildR102ProtocolCommitReceipt,
  buildR102ServerActivationReceipt,
} from './helpers/r102LaneGateway.fixtures';

const DIGEST_B64U = base64UrlEncode(new Uint8Array(32));
const SEALED_B64U = base64UrlEncode(new Uint8Array([1, 2, 3]));

function edJob(): Ed25519YaoLaneJobV1 {
  const job = buildR102LaneJob('holder-backend');
  if (job.keyFamily !== 'ed25519') throw new Error('R102 fixture changed key family');
  return job;
}

class FakeCustodySealWasm {
  freeCalls = 0;

  free(): void {
    this.freeCalls += 1;
  }
}

class FakeRecipientWasm {
  destroyCalls = 0;
  freeCalls = 0;
  openCalls: unknown[] = [];
  failOpen = false;

  constructor(
    private readonly publicKeyB64u: string,
    private readonly publicKeyDigestB64u: string,
  ) {}

  hpke_public_key_b64u(): string {
    return this.publicKeyB64u;
  }

  hpke_public_key_digest_b64u(): string {
    return this.publicKeyDigestB64u;
  }

  open_and_seal(
    custody: FakeCustodySealWasm,
    jobJson: string,
    receiptJson: string,
    holderPackageJson: string,
    nonce12: Uint8Array,
  ): unknown {
    this.openCalls.push({ custody, jobJson, receiptJson, holderPackageJson, nonce12 });
    if (this.failOpen) throw new Error('WASM holder open failed');
    return {
      sealedHolderMaterialB64u: SEALED_B64U,
      sealedHolderRecordDigestB64u: DIGEST_B64U,
      verifiedHolderCiphertextDigestSetB64u: DIGEST_B64U,
    };
  }

  destroy(): void {
    this.destroyCalls += 1;
  }

  free(): void {
    this.freeCalls += 1;
  }
}

class FakeLaneHolderWasmFactory implements LaneHolderWasmFactoryV1 {
  readonly custody = new FakeCustodySealWasm();
  readonly recipients: FakeRecipientWasm[] = [];
  loadedFactorSecret: Uint8Array | null = null;
  loadedFactorKind: string | null = null;
  verifyCalls: unknown[] = [];

  constructor(private readonly job: Ed25519YaoLaneJobV1) {}

  loadCustodySeal(
    input: Parameters<LaneHolderWasmFactoryV1['loadCustodySeal']>[0],
  ): FakeCustodySealWasm {
    this.loadedFactorSecret = input.factorSecret.slice();
    this.loadedFactorKind = input.factorKind;
    return this.custody;
  }

  createRecipient(
    input: Parameters<LaneHolderWasmFactoryV1['createRecipient']>[0],
  ): FakeRecipientWasm {
    expect(input.keyMaterial).toHaveLength(32);
    const recipient = new FakeRecipientWasm(
      this.job.targetHolder.hpkePublicKeyB64u,
      this.job.targetHolder.hpkePublicKeyDigestB64u,
    );
    this.recipients.push(recipient);
    return recipient;
  }

  verify(input: Parameters<LaneHolderWasmFactoryV1['verify']>[0]): unknown {
    this.verifyCalls.push(input);
    return { verifiedHolderCiphertextDigestSetB64u: DIGEST_B64U };
  }
}

function loadedBackend(job: Ed25519YaoLaneJobV1, factory: FakeLaneHolderWasmFactory) {
  const factorSecret = new Uint8Array(32).fill(8);
  const envelope = passkeyCustodyEnvelope({
    envelopeId: job.targetHolder.custodyBindingId,
    walletId: job.walletId,
    binding: {
      kind: 'ed25519_lane_holder_share_v1',
      walletKeyId: job.walletKeyId,
      laneId: job.target.laneId,
      laneShareEpoch: job.target.laneShareEpoch,
      nearEd25519SigningKeyId: job.nearEd25519SigningKeyId,
      registeredPublicKeyB64u: job.registeredPublicKeyB64u,
      participantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
    },
  });
  const custodySeal = loadLaneCustodySealV1(
    {
      factorSecret: factorSecret.buffer,
      custodyBindingId: job.targetHolder.custodyBindingId,
      custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
      envelopeBinding: {
        walletId: envelope.walletId,
        envelopeId: envelope.envelopeId,
        factor: envelope.factor,
        envelopeRevision: envelope.envelopeRevision,
        binding: envelope.binding,
      },
    },
    factory,
  );
  return {
    factorSecret,
    custodySeal,
    backend: createConcreteLaneHolderWorkerV1({ custodySeal, wasmFactory: factory }),
  };
}

function createInput(job: Ed25519YaoLaneJobV1) {
  return {
    operationId: job.operationId,
    enrollmentId: job.enrollmentId,
    walletKeyId: job.walletKeyId,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivationId: job.targetMaterialActivationId,
    targetHolderParticipantId: job.targetHolder.participantId,
    custodyBindingId: job.targetHolder.custodyBindingId,
    custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
  };
}

function holderPackage() {
  return {
    kind: 'ed25519_yao_lane_holder_package_set_v1' as const,
    deriverAEncryptedPackageJson: '{"role":"a"}',
    deriverBEncryptedPackageJson: '{"role":"b"}',
  };
}

test('uses an already-loaded opaque factor handle and never adds factor material to lane calls', async () => {
  const job = edJob();
  const factory = new FakeLaneHolderWasmFactory(job);
  const runtime = loadedBackend(job, factory);
  expect(factory.loadedFactorKind).toBe('passkey');
  expect(factory.loadedFactorSecret).toEqual(new Uint8Array(32).fill(8));
  expect(runtime.factorSecret).toEqual(new Uint8Array(32));

  const descriptor = await runtime.backend.worker.createLaneHolderRecipientV1(createInput(job));
  const sealed = await runtime.backend.worker.openAndSealLaneHolderPackageV1({
    job,
    protocolCommitReceipt: buildR102ProtocolCommitReceipt(job),
    holderPackage: holderPackage(),
    recipientHandle: descriptor.recipientHandle,
  });

  expect(sealed.sealedHolderMaterialB64u).toBe(SEALED_B64U);
  const openCall = factory.recipients[0].openCalls[0];
  expect(JSON.stringify(openCall)).not.toContain('factorSecret');
  expect(JSON.stringify(openCall)).not.toContain('privateKey');
  expect(JSON.stringify(openCall)).not.toContain('holderShare');
  expect(factory.recipients[0].destroyCalls).toBe(1);
  expect(factory.recipients[0].freeCalls).toBe(1);
  runtime.backend.destroy();
  expect(factory.custody.freeCalls).toBe(1);
});

test('loads the existing Email OTP custody factor branch explicitly', () => {
  const job = edJob();
  const factory = new FakeLaneHolderWasmFactory(job);
  const factorSecret = new Uint8Array(32).fill(6);
  const envelope = passkeyCustodyEnvelope({
    envelopeId: job.targetHolder.custodyBindingId,
    walletId: job.walletId,
    factor: {
      kind: 'email_otp',
      enrollmentId: 'email-otp-enrollment-r102',
      enrollmentSealKeyVersion: 'email_otp_enrollment_seal_key_v1',
      kekVersion: 'email_otp_factor_kek_hkdf_sha256_v1',
    },
    binding: {
      kind: 'ed25519_lane_holder_share_v1',
      walletKeyId: job.walletKeyId,
      laneId: job.target.laneId,
      laneShareEpoch: job.target.laneShareEpoch,
      nearEd25519SigningKeyId: job.nearEd25519SigningKeyId,
      registeredPublicKeyB64u: job.registeredPublicKeyB64u,
      participantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
    },
  });
  const custodySeal = loadLaneCustodySealV1(
    {
      factorSecret: factorSecret.buffer,
      custodyBindingId: job.targetHolder.custodyBindingId,
      custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
      envelopeBinding: {
        walletId: envelope.walletId,
        envelopeId: envelope.envelopeId,
        factor: envelope.factor,
        envelopeRevision: envelope.envelopeRevision,
        binding: envelope.binding,
      },
    },
    factory,
  );

  expect(factory.loadedFactorKind).toBe('email_otp');
  expect(factorSecret).toEqual(new Uint8Array(32));
  custodySeal.destroy();
});

test('fails closed on unauthorized custody identity and frees recipients after WASM failure', async () => {
  const job = edJob();
  const factory = new FakeLaneHolderWasmFactory(job);
  const runtime = loadedBackend(job, factory);
  await expect(
    runtime.backend.worker.createLaneHolderRecipientV1({
      ...createInput(job),
      custodyBindingDigestB64u: base64UrlEncode(new Uint8Array(32).fill(7)),
    }),
  ).rejects.toThrow('unauthorized custody seal binding');

  const descriptor = await runtime.backend.worker.createLaneHolderRecipientV1(createInput(job));
  factory.recipients[0].failOpen = true;
  await expect(
    runtime.backend.worker.openAndSealLaneHolderPackageV1({
      job,
      protocolCommitReceipt: buildR102ProtocolCommitReceipt(job),
      holderPackage: holderPackage(),
      recipientHandle: descriptor.recipientHandle,
    }),
  ).rejects.toThrow('WASM holder open failed');
  expect(factory.recipients[0].destroyCalls).toBe(1);
  expect(factory.recipients[0].freeCalls).toBe(1);
  await expect(
    runtime.backend.worker.openAndSealLaneHolderPackageV1({
      job,
      protocolCommitReceipt: buildR102ProtocolCommitReceipt(job),
      holderPackage: holderPackage(),
      recipientHandle: descriptor.recipientHandle,
    }),
  ).rejects.toThrow('unknown or consumed');
  runtime.backend.destroy();
});

test('verify-only replay carries public protocol records and no custody handle', async () => {
  const job = edJob();
  const factory = new FakeLaneHolderWasmFactory(job);
  const runtime = loadedBackend(job, factory);
  const verified = await runtime.backend.worker.verifyLaneHolderPackageCommitmentV1({
    job,
    protocolCommitReceipt: buildR102ProtocolCommitReceipt(job),
    holderPackage: holderPackage(),
  });

  expect(verified.verifiedHolderCiphertextDigestSetB64u).toBe(DIGEST_B64U);
  expect(factory.verifyCalls).toHaveLength(1);
  expect(JSON.stringify(factory.verifyCalls[0])).not.toContain('factorSecret');
  expect(JSON.stringify(factory.verifyCalls[0])).not.toContain('envelopeBinding');
  expect(JSON.stringify(factory.verifyCalls[0])).not.toContain('custodySealHandle');
  runtime.backend.destroy();
});

test('exact invalidation destroys only the matching recipient curve state and is idempotent', async () => {
  const job = edJob();
  const unrelatedJob = buildR102LaneJob('holder-backend-unrelated');
  const factory = new FakeLaneHolderWasmFactory(job);
  const runtime = loadedBackend(job, factory);
  await runtime.backend.worker.createLaneHolderRecipientV1(createInput(job));
  await runtime.backend.worker.createLaneHolderRecipientV1({
    ...createInput(unrelatedJob),
    custodyBindingId: job.targetHolder.custodyBindingId,
    custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
  });
  const target = {
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneShareEpoch: job.target.laneShareEpoch,
    materialActivation: buildR102ServerActivationReceipt(job).targetMaterialActivation,
  };

  await runtime.backend.worker.invalidateLaneMaterialV1(target);
  await runtime.backend.worker.invalidateLaneMaterialV1(target);

  expect(factory.recipients[0].destroyCalls).toBe(1);
  expect(factory.recipients[0].freeCalls).toBe(1);
  expect(factory.recipients[1].destroyCalls).toBe(0);
  expect(factory.recipients[1].freeCalls).toBe(0);
  runtime.backend.destroy();
  expect(factory.recipients[1].destroyCalls).toBe(1);
  expect(factory.recipients[1].freeCalls).toBe(1);
});
