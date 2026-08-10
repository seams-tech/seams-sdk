import type {
  LaneHolderPackageWireV1,
  LaneHolderRecipientWorkerV1,
  RotatableSigningLaneJobV1,
  SealedLaneHolderMaterialV1,
  VerifiedLaneHolderPackageV1,
} from '@shared/signing-lanes/rotation';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import {
  parseHpkePublicKeyB64u,
  parseSigningWorkerRecipientKeyDigestB64u,
} from '@shared/signing-lanes/participants';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseLaneHolderRecipientHandleV1 } from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  verify_lane_holder_package_commitment_v1,
  WasmLaneCustodySealV1,
  WasmLaneHolderRecipientV1,
} from '../../../../../../../crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client.js';

type LaneRecipientCreationInputV1 = Parameters<
  LaneHolderRecipientWorkerV1['createLaneHolderRecipientV1']
>[0];

export type LaneCustodySealContextV1 = {
  readonly factorSecret: ArrayBuffer;
  readonly custodyBindingId: LaneRecipientCreationInputV1['custodyBindingId'];
  readonly custodyBindingDigestB64u: LaneRecipientCreationInputV1['custodyBindingDigestB64u'];
  readonly envelopeBinding: Pick<
    PasskeyCustodyEnvelopeRecord,
    'walletId' | 'envelopeId' | 'factor' | 'envelopeRevision' | 'binding'
  >;
};

type LaneHolderRecipientWasmV1 = {
  hpke_public_key_b64u(): string;
  hpke_public_key_digest_b64u(): string;
  open_and_seal(
    custody: LaneCustodySealWasmV1,
    jobJson: string,
    receiptJson: string,
    holderPackageJson: string,
    nonce12: Uint8Array,
  ): unknown;
  destroy(): void;
  free(): void;
};

type LaneCustodySealWasmV1 = {
  free(): void;
};

export type LaneHolderWasmFactoryV1 = {
  loadCustodySeal(input: {
    readonly factorKind: 'passkey' | 'email_otp';
    readonly factorSecret: Uint8Array;
    readonly envelopeBindingJson: string;
    readonly custodyBindingId: string;
    readonly custodyBindingDigestB64u: string;
  }): LaneCustodySealWasmV1;
  createRecipient(input: {
    readonly operationId: string;
    readonly keyMaterial: Uint8Array;
  }): LaneHolderRecipientWasmV1;
  verify(input: {
    readonly jobJson: string;
    readonly receiptJson: string;
    readonly holderPackageJson: string;
  }): unknown;
};

export type LoadedLaneCustodySealV1 = {
  readonly custodyBindingId: LaneRecipientCreationInputV1['custodyBindingId'];
  readonly custodyBindingDigestB64u: LaneRecipientCreationInputV1['custodyBindingDigestB64u'];
  readonly wasm: LaneCustodySealWasmV1;
  destroy(): void;
};

class LoadedLaneCustodySeal implements LoadedLaneCustodySealV1 {
  #destroyed = false;

  constructor(
    readonly custodyBindingId: LaneRecipientCreationInputV1['custodyBindingId'],
    readonly custodyBindingDigestB64u: LaneRecipientCreationInputV1['custodyBindingDigestB64u'],
    readonly wasm: LaneCustodySealWasmV1,
  ) {}

  destroy(): void {
    if (this.#destroyed) return;
    this.#destroyed = true;
    this.wasm.free();
  }
}

type RecipientSessionV1 = {
  readonly input: LaneRecipientCreationInputV1;
  readonly wasm: LaneHolderRecipientWasmV1;
};

class ProductionLaneHolderWasmFactory implements LaneHolderWasmFactoryV1 {
  loadCustodySeal(
    input: Parameters<LaneHolderWasmFactoryV1['loadCustodySeal']>[0],
  ): LaneCustodySealWasmV1 {
    return new WasmLaneCustodySealV1(
      input.factorKind,
      input.factorSecret,
      input.envelopeBindingJson,
      input.custodyBindingId,
      input.custodyBindingDigestB64u,
    );
  }

  createRecipient(
    input: Parameters<LaneHolderWasmFactoryV1['createRecipient']>[0],
  ): LaneHolderRecipientWasmV1 {
    return new WasmLaneHolderRecipientV1(input.operationId, input.keyMaterial);
  }

  verify(input: Parameters<LaneHolderWasmFactoryV1['verify']>[0]): unknown {
    return verify_lane_holder_package_commitment_v1(
      input.jobJson,
      input.receiptJson,
      input.holderPackageJson,
    );
  }
}

function productionWasmFactory(): LaneHolderWasmFactoryV1 {
  return new ProductionLaneHolderWasmFactory();
}

function envelopeBindingJson(binding: LaneCustodySealContextV1['envelopeBinding']): string {
  return JSON.stringify({
    walletId: binding.walletId,
    envelopeId: binding.envelopeId,
    factor: binding.factor,
    envelopeRevision: binding.envelopeRevision,
    binding: binding.binding,
  });
}

export function loadLaneCustodySealV1(
  context: LaneCustodySealContextV1,
  wasmFactory: LaneHolderWasmFactoryV1 = productionWasmFactory(),
): LoadedLaneCustodySealV1 {
  if (String(context.envelopeBinding.envelopeId) !== String(context.custodyBindingId)) {
    throw new Error('lane custody envelope id does not match its admitted custody binding');
  }
  const factorSecret = new Uint8Array(context.factorSecret);
  let wasm: LaneCustodySealWasmV1;
  try {
    wasm = wasmFactory.loadCustodySeal({
      factorKind: context.envelopeBinding.factor.kind,
      factorSecret,
      envelopeBindingJson: envelopeBindingJson(context.envelopeBinding),
      custodyBindingId: context.custodyBindingId,
      custodyBindingDigestB64u: context.custodyBindingDigestB64u,
    });
  } finally {
    factorSecret.fill(0);
  }
  return new LoadedLaneCustodySeal(
    context.custodyBindingId,
    context.custodyBindingDigestB64u,
    wasm,
  );
}

function randomNonzero(length: number): Uint8Array {
  const output = new Uint8Array(length);
  do {
    crypto.getRandomValues(output);
  } while (allZero(output));
  return output;
}

function allZero(value: Uint8Array): boolean {
  let aggregate = 0;
  for (const byte of value) aggregate |= byte;
  return aggregate === 0;
}

function opaqueRecipientHandle(): ReturnType<typeof requiredRecipientHandle> {
  return requiredRecipientHandle(`lane-holder-recipient-v1.${base64UrlEncode(randomNonzero(24))}`);
}

function requiredRecipientHandle(value: unknown) {
  const parsed = parseLaneHolderRecipientHandleV1(value);
  if (parsed.ok) return parsed.value;
  throw new Error(parsed.error.message);
}

function hpkePublicKey(value: unknown) {
  const parsed = parseHpkePublicKeyB64u(value);
  if (parsed.ok) return parsed.value;
  throw new Error(parsed.error.message);
}

function hpkePublicKeyDigest(value: unknown) {
  const parsed = parseSigningWorkerRecipientKeyDigestB64u(value);
  if (parsed.ok) return parsed.value;
  throw new Error(parsed.error.message);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactFields(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const fields = [...expected].sort();
  if (actual.length !== fields.length || actual.some((field, index) => field !== fields[index])) {
    throw new Error(`${label} has invalid fields`);
  }
}

function sealedOutput(value: unknown): SealedLaneHolderMaterialV1 {
  const output = record(value, 'lane holder WASM seal output');
  exactFields(
    output,
    [
      'sealedHolderMaterialB64u',
      'sealedHolderRecordDigestB64u',
      'verifiedHolderCiphertextDigestSetB64u',
    ],
    'lane holder WASM seal output',
  );
  if (typeof output.sealedHolderMaterialB64u !== 'string' || !output.sealedHolderMaterialB64u) {
    throw new Error('lane holder WASM returned no sealed material');
  }
  return {
    sealedHolderMaterialB64u: output.sealedHolderMaterialB64u,
    sealedHolderRecordDigestB64u: parseDigestB64u(output.sealedHolderRecordDigestB64u),
    verifiedHolderCiphertextDigestSetB64u: parseDigestB64u(
      output.verifiedHolderCiphertextDigestSetB64u,
    ),
  };
}

function verifiedOutput(value: unknown): VerifiedLaneHolderPackageV1 {
  const output = record(value, 'lane holder WASM verify output');
  exactFields(output, ['verifiedHolderCiphertextDigestSetB64u'], 'lane holder WASM verify output');
  return {
    verifiedHolderCiphertextDigestSetB64u: parseDigestB64u(
      output.verifiedHolderCiphertextDigestSetB64u,
    ),
  };
}

function holderPackageJson(holderPackage: LaneHolderPackageWireV1): string {
  return JSON.stringify(holderPackage);
}

function jobJson(job: RotatableSigningLaneJobV1): string {
  return JSON.stringify(job);
}

export type ConcreteLaneHolderWorkerV1 = {
  readonly worker: LaneHolderRecipientWorkerV1;
  destroy(): void;
};

class ConcreteLaneHolderWorker implements LaneHolderRecipientWorkerV1, ConcreteLaneHolderWorkerV1 {
  readonly #sessions = new Map<string, RecipientSessionV1>();
  #destroyed = false;

  constructor(
    private readonly custodySeal: LoadedLaneCustodySealV1,
    private readonly wasmFactory: LaneHolderWasmFactoryV1,
  ) {}

  get worker(): LaneHolderRecipientWorkerV1 {
    return this;
  }

  async createLaneHolderRecipientV1(input: LaneRecipientCreationInputV1) {
    this.#requireActive();
    if (
      input.custodyBindingId !== this.custodySeal.custodyBindingId ||
      input.custodyBindingDigestB64u !== this.custodySeal.custodyBindingDigestB64u
    ) {
      throw new Error('lane recipient requested an unauthorized custody seal binding');
    }
    const keyMaterial = randomNonzero(32);
    let wasm: LaneHolderRecipientWasmV1;
    try {
      wasm = this.wasmFactory.createRecipient({
        operationId: input.operationId,
        keyMaterial,
      });
    } finally {
      keyMaterial.fill(0);
    }
    try {
      const recipientHandle = opaqueRecipientHandle();
      this.#sessions.set(String(recipientHandle), { input, wasm });
      return {
        recipientHandle,
        hpkePublicKeyB64u: hpkePublicKey(wasm.hpke_public_key_b64u()),
        hpkePublicKeyDigestB64u: hpkePublicKeyDigest(wasm.hpke_public_key_digest_b64u()),
      };
    } catch (error) {
      wasm.destroy();
      wasm.free();
      throw error;
    }
  }

  async openAndSealLaneHolderPackageV1(
    input: Parameters<LaneHolderRecipientWorkerV1['openAndSealLaneHolderPackageV1']>[0],
  ): Promise<SealedLaneHolderMaterialV1> {
    this.#requireActive();
    const key = String(input.recipientHandle);
    const session = this.#sessions.get(key);
    if (!session) throw new Error('lane holder recipient is unknown or consumed');
    this.#sessions.delete(key);
    const nonce = randomNonzero(12);
    try {
      return sealedOutput(
        session.wasm.open_and_seal(
          this.custodySeal.wasm,
          jobJson(input.job),
          JSON.stringify(input.protocolCommitReceipt),
          holderPackageJson(input.holderPackage),
          nonce,
        ),
      );
    } finally {
      nonce.fill(0);
      session.wasm.destroy();
      session.wasm.free();
    }
  }

  async verifyLaneHolderPackageCommitmentV1(
    input: Parameters<LaneHolderRecipientWorkerV1['verifyLaneHolderPackageCommitmentV1']>[0],
  ): Promise<VerifiedLaneHolderPackageV1> {
    this.#requireActive();
    return verifiedOutput(
      this.wasmFactory.verify({
        jobJson: jobJson(input.job),
        receiptJson: JSON.stringify(input.protocolCommitReceipt),
        holderPackageJson: holderPackageJson(input.holderPackage),
      }),
    );
  }

  async discardLaneHolderRecipientV1(
    input: Parameters<LaneHolderRecipientWorkerV1['discardLaneHolderRecipientV1']>[0],
  ): Promise<void> {
    const key = String(input.recipientHandle);
    const session = this.#sessions.get(key);
    if (!session) return;
    if (String(session.input.operationId) !== String(input.operationId)) {
      throw new Error('lane holder recipient discard changed its operation');
    }
    this.#sessions.delete(key);
    session.wasm.destroy();
    session.wasm.free();
  }

  async invalidateLaneMaterialV1(
    input: Parameters<LaneHolderRecipientWorkerV1['invalidateLaneMaterialV1']>[0],
  ): Promise<void> {
    for (const [key, session] of this.#sessions) {
      if (
        String(session.input.walletKeyId) !== String(input.walletKeyId) ||
        String(session.input.targetLaneId) !== String(input.laneId) ||
        String(session.input.targetLaneShareEpoch) !== String(input.laneShareEpoch) ||
        String(session.input.targetMaterialActivationId) !==
          String(input.materialActivation.activationId)
      ) {
        continue;
      }
      this.#sessions.delete(key);
      session.wasm.destroy();
      session.wasm.free();
    }
  }

  destroy(): void {
    if (this.#destroyed) return;
    this.#destroyed = true;
    for (const session of this.#sessions.values()) {
      session.wasm.destroy();
      session.wasm.free();
    }
    this.#sessions.clear();
    this.custodySeal.destroy();
  }

  #requireActive(): void {
    if (this.#destroyed) throw new Error('lane holder crypto backend is destroyed');
  }
}

export function createConcreteLaneHolderWorkerV1(args: {
  readonly custodySeal: LoadedLaneCustodySealV1;
  readonly wasmFactory?: LaneHolderWasmFactoryV1;
}): ConcreteLaneHolderWorkerV1 {
  return new ConcreteLaneHolderWorker(
    args.custodySeal,
    args.wasmFactory ?? productionWasmFactory(),
  );
}
