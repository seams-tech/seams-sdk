import type { Brand } from './keyMaterialBrands';

/**
 * Advance-only material writes.
 *
 * Ed25519 worker material rotates in GENERATIONS: every mint bakes a fresh
 * `createdAtMs` into the material binding, and `materialKeyId` is a hash of that
 * binding — so `materialCreatedAtMs` totally orders material generations for a
 * session. Session-record material must only ever move forward along this order;
 * a store that regresses (e.g. a durable seal republished over a newer runtime
 * record) desynchronizes every consumer that captured the newer identity.
 *
 * `Ed25519MaterialAdvance` is the write token for material fields:
 *
 * - It is mintable ONLY from a worker seal outcome
 *   (`ed25519MaterialAdvanceFromWorkerSeal`) — the one place new material
 *   generations legitimately originate. Durable-cache fields cannot be branded
 *   into an advance, so a republish path cannot forge a material write.
 * - The store (`persistStoredThresholdEd25519SessionMaterialHandle`) accepts only
 *   this brand and additionally enforces generation monotonicity against the
 *   record it is about to overwrite.
 */
export type Ed25519MaterialAdvanceFields = {
  clientVerifyingShareB64u: string;
  ed25519WorkerMaterialHandle: string;
  ed25519WorkerMaterialBindingDigest: string;
  sealedWorkerMaterialRef: string;
  sealedWorkerMaterialB64u: string;
  materialFormatVersion: string;
  materialKeyId: string;
  /** Material generation: the binding's createdAtMs. Totally orders mints. */
  materialCreatedAtMs: number;
  signerSlot: number;
};

export type Ed25519MaterialAdvance = Brand<Ed25519MaterialAdvanceFields, 'Ed25519MaterialAdvance'>;

/**
 * Mint a material-write token from a worker seal outcome. Returns null when the
 * outcome is incomplete (a partial write would strand the record between
 * generations). This is deliberately the only exported constructor: callers that
 * did not just receive material from the worker have no business writing material
 * fields.
 */
export function ed25519MaterialAdvanceFromWorkerSeal(
  fields: Ed25519MaterialAdvanceFields,
): Ed25519MaterialAdvance | null {
  const clientVerifyingShareB64u = String(fields.clientVerifyingShareB64u || '').trim();
  const ed25519WorkerMaterialHandle = String(fields.ed25519WorkerMaterialHandle || '').trim();
  const ed25519WorkerMaterialBindingDigest = String(
    fields.ed25519WorkerMaterialBindingDigest || '',
  ).trim();
  const sealedWorkerMaterialRef = String(fields.sealedWorkerMaterialRef || '').trim();
  const sealedWorkerMaterialB64u = String(fields.sealedWorkerMaterialB64u || '').trim();
  const materialFormatVersion = String(fields.materialFormatVersion || '').trim();
  const materialKeyId = String(fields.materialKeyId || '').trim();
  const materialCreatedAtMs = Math.floor(Number(fields.materialCreatedAtMs) || 0);
  const signerSlot = Math.floor(Number(fields.signerSlot) || 0);
  if (
    !clientVerifyingShareB64u ||
    !ed25519WorkerMaterialHandle ||
    !ed25519WorkerMaterialBindingDigest ||
    !sealedWorkerMaterialRef ||
    !sealedWorkerMaterialB64u ||
    !materialFormatVersion ||
    !materialKeyId ||
    materialCreatedAtMs <= 0 ||
    signerSlot <= 0
  ) {
    return null;
  }
  return {
    clientVerifyingShareB64u,
    ed25519WorkerMaterialHandle,
    ed25519WorkerMaterialBindingDigest,
    sealedWorkerMaterialRef,
    sealedWorkerMaterialB64u,
    materialFormatVersion,
    materialKeyId,
    materialCreatedAtMs,
    signerSlot,
  } as Ed25519MaterialAdvance;
}

/**
 * True when writing `advance` over a record currently at `existingGeneration`
 * (with `existingMaterialKeyId`) would move material BACKWARD in generation
 * order. Equal generations are allowed: a re-seal within one generation rotates
 * the sealed blob but keeps the same binding (and therefore the same
 * materialKeyId).
 */
export function ed25519MaterialAdvanceWouldRegress(args: {
  advance: Ed25519MaterialAdvance;
  existingMaterialKeyId: unknown;
  existingMaterialCreatedAtMs: unknown;
}): boolean {
  const existingMaterialKeyId = String(args.existingMaterialKeyId || '').trim();
  const existingGeneration = Math.floor(Number(args.existingMaterialCreatedAtMs) || 0);
  if (!existingMaterialKeyId || existingGeneration <= 0) return false;
  return args.advance.materialCreatedAtMs < existingGeneration;
}
