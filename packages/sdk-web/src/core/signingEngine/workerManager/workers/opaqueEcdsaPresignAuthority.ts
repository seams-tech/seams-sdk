import type { EcdsaClientPresignPoolIdentity } from '../ecdsaPresignPoolIdentity';
import type {
  ThresholdEcdsaPresignAbortResult,
  ThresholdEcdsaPresignProgressResult,
} from '../workerTypes';

export type OpaqueEcdsaPresignSessionV1 = {
  stage(): string;
  poll(): unknown;
  message(message: Uint8Array): void;
  start_presign(): void;
  presignature_big_r_33(): Uint8Array;
  compute_signature_share(
    groupPublicKey33: Uint8Array,
    expectedPresignBigR33: Uint8Array,
    digest32: Uint8Array,
    clientRerandomizationContribution32: Uint8Array,
    signingWorkerRerandomizationContribution32: Uint8Array,
  ): Uint8Array;
  free(): void;
};

type OpaqueEcdsaPresignSessionBindingV1 = {
  readonly groupPublicKey33: Uint8Array;
  readonly expiresAtMs: number;
  readonly poolIdentity: EcdsaClientPresignPoolIdentity;
};

type OpaqueEcdsaPresignSessionEntryV1 = {
  readonly session: OpaqueEcdsaPresignSessionV1;
  readonly binding: OpaqueEcdsaPresignSessionBindingV1;
};

export type OpaqueEcdsaPresignSessionInitV1 = OpaqueEcdsaPresignSessionBindingV1 & {
  readonly presignSessionId: string;
  readonly session: OpaqueEcdsaPresignSessionV1;
};

export type OpaqueEcdsaPresignSessionStepV1 = {
  readonly presignSessionId: string;
  readonly stage: 'triples' | 'presign';
  readonly incomingMessages: readonly ArrayBuffer[];
};

export type OpaqueEcdsaOnlineComputeV1 = {
  readonly materialHandle: string;
  readonly groupPublicKey33: ArrayBuffer;
  readonly expectedPresignBigR33: ArrayBuffer;
  readonly digest32: ArrayBuffer;
  readonly clientRerandomizationContribution32: ArrayBuffer;
  readonly signingWorkerRerandomizationContribution32: ArrayBuffer;
};

type ParsedPresignPollV1 = {
  readonly stage: 'triples' | 'triples_done' | 'presign' | 'done';
  readonly event: 'none' | 'triples_done' | 'presign_done';
  readonly outgoing: readonly Uint8Array[];
};

export class OpaqueEcdsaPresignAuthorityV1 {
  private readonly sessions = new Map<string, OpaqueEcdsaPresignSessionEntryV1>();
  private readonly materials = new Map<string, OpaqueEcdsaPresignSessionEntryV1>();
  private readonly operationTails = new Map<string, Promise<void>>();
  private generation = 0;

  async initialize(
    input: OpaqueEcdsaPresignSessionInitV1,
  ): Promise<ThresholdEcdsaPresignProgressResult> {
    const generation = this.generation;
    return await this.serialize(input.presignSessionId, async () => {
      if (generation !== this.generation) {
        input.session.free();
        throw new Error('Opaque ECDSA presign authority was closed');
      }
      if (Date.now() >= input.expiresAtMs) {
        input.session.free();
        throw new Error('Opaque ECDSA presign session expired');
      }
      this.abortNow(input.presignSessionId);
      this.sessions.set(input.presignSessionId, {
        session: input.session,
        binding: {
          groupPublicKey33: input.groupPublicKey33.slice(),
          expiresAtMs: input.expiresAtMs,
          poolIdentity: input.poolIdentity,
        },
      });
      try {
        return await this.poll(input.presignSessionId);
      } catch (error) {
        this.abortNow(input.presignSessionId);
        throw error;
      }
    });
  }

  async step(input: OpaqueEcdsaPresignSessionStepV1): Promise<ThresholdEcdsaPresignProgressResult> {
    return await this.serialize(input.presignSessionId, async () => {
      const entry = this.requireSession(input.presignSessionId);
      try {
        if (input.stage === 'presign' && entry.session.stage() === 'triples_done') {
          entry.session.start_presign();
        }
        for (const incoming of input.incomingMessages) {
          entry.session.message(new Uint8Array(incoming));
        }
        return await this.poll(input.presignSessionId);
      } catch (error) {
        this.abortNow(input.presignSessionId);
        throw error;
      }
    });
  }

  async abort(sessionId: string): Promise<ThresholdEcdsaPresignAbortResult> {
    return await this.serialize(sessionId, () => this.abortNow(sessionId));
  }

  async computeSignatureShare(input: OpaqueEcdsaOnlineComputeV1): Promise<ArrayBuffer> {
    return await this.serialize(input.materialHandle, () => {
      const entry = this.materials.get(input.materialHandle);
      this.materials.delete(input.materialHandle);
      if (!entry) throw new Error('Opaque ECDSA presign material is unknown');
      try {
        if (Date.now() >= entry.binding.expiresAtMs) {
          throw new Error('Opaque ECDSA presign material expired');
        }
        if (
          !equalPublicBytes(entry.binding.groupPublicKey33, new Uint8Array(input.groupPublicKey33))
        ) {
          throw new Error('Opaque ECDSA presign group public key binding mismatch');
        }
        return copyToArrayBuffer(
          entry.session.compute_signature_share(
            new Uint8Array(input.groupPublicKey33),
            new Uint8Array(input.expectedPresignBigR33),
            new Uint8Array(input.digest32),
            new Uint8Array(input.clientRerandomizationContribution32),
            new Uint8Array(input.signingWorkerRerandomizationContribution32),
          ),
        );
      } finally {
        entry.session.free();
      }
    });
  }

  async destroyMaterial(materialHandle: string): Promise<boolean> {
    return await this.serialize(materialHandle, () => {
      const entry = this.materials.get(materialHandle);
      this.materials.delete(materialHandle);
      entry?.session.free();
      return Boolean(entry);
    });
  }

  private abortNow(sessionId: string): ThresholdEcdsaPresignAbortResult {
    const entry = this.sessions.get(sessionId);
    this.sessions.delete(sessionId);
    if (entry) entry.session.free();
    return { kind: 'threshold_ecdsa_presign_session_aborted', sessionId };
  }

  close(): void {
    this.generation += 1;
    for (const sessionId of this.sessions.keys()) this.abortNow(sessionId);
    for (const entry of this.materials.values()) entry.session.free();
    this.materials.clear();
  }

  private requireSession(sessionId: string): OpaqueEcdsaPresignSessionEntryV1 {
    const entry = this.sessions.get(sessionId);
    if (!entry) throw new Error('Opaque ECDSA presign session is unknown');
    if (Date.now() >= entry.binding.expiresAtMs) {
      this.abortNow(sessionId);
      throw new Error('Opaque ECDSA presign session expired');
    }
    return entry;
  }

  private async poll(sessionId: string): Promise<ThresholdEcdsaPresignProgressResult> {
    const entry = this.requireSession(sessionId);
    const result = parsePollResult(entry.session.poll());
    const outgoingMessages = result.outgoing.map(copyToArrayBuffer);
    if (result.event !== 'presign_done') {
      return { stage: result.stage, event: result.event, outgoingMessages };
    }
    const bigR33 = entry.session.presignature_big_r_33();
    if (bigR33.length !== 33) throw new Error('Client presignature R must contain 33 bytes');
    const materialHandle = randomHandle(`ecdsa-presign-${sessionId}`);
    this.sessions.delete(sessionId);
    this.materials.set(materialHandle, entry);
    return {
      stage: 'done',
      event: 'presign_done',
      outgoingMessages,
      presignatureHandle: materialHandle,
      presignatureBigR33: copyToArrayBuffer(bigR33),
    };
  }

  private async serialize<T>(key: string, operation: () => T | Promise<T>): Promise<T> {
    const previous = this.operationTails.get(key) ?? Promise.resolve();
    const result = previous.then(operation);
    const tail = result.then(
      () => undefined,
      () => undefined,
    );
    this.operationTails.set(key, tail);
    try {
      return await result;
    } finally {
      if (this.operationTails.get(key) === tail) this.operationTails.delete(key);
    }
  }
}

function equalPublicBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function parsePollResult(raw: unknown): ParsedPresignPollV1 {
  const record = (raw ?? {}) as Record<string, unknown>;
  const stage = parseStage(record.stage);
  const event = parseEvent(record.event);
  const outgoing = Array.isArray(record.outgoing) ? record.outgoing.map(parseOutgoingMessage) : [];
  return { stage, event, outgoing };
}

function parseStage(value: unknown): ParsedPresignPollV1['stage'] {
  switch (value) {
    case 'triples':
    case 'triples_done':
    case 'presign':
    case 'done':
      return value;
    default:
      throw new Error('Opaque ECDSA presign session returned an invalid stage');
  }
}

function parseEvent(value: unknown): ParsedPresignPollV1['event'] {
  switch (value) {
    case 'none':
    case 'triples_done':
    case 'presign_done':
      return value;
    default:
      throw new Error('Opaque ECDSA presign session returned an invalid event');
  }
}

function parseOutgoingMessage(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new Error('Opaque ECDSA presign session returned an invalid outgoing message');
}

function copyToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer;
}

function randomHandle(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let suffix = '';
  for (const byte of bytes) suffix += byte.toString(16).padStart(2, '0');
  return `${prefix}-${suffix}`;
}
