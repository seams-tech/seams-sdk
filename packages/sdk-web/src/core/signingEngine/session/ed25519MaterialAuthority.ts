import type {
  Brand,
  Ed25519WorkerMaterialBindingDigest,
  Ed25519WorkerMaterialKeyId,
} from './keyMaterialBrands';
import { getStoredThresholdEd25519SessionRecordByThresholdSessionId } from './persistence/records';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  routerAbEd25519WorkerMaterialIdentityFromPersistedState,
} from './routerAbSigningWalletSession';

/**
 * Ed25519 worker-material identity exists in this SDK at three epistemic strengths:
 *
 * 1. AUTHORITY — what the live in-memory session record holds right now. Only this
 *    may parameterize an unseal/restore effect.
 * 2. CACHE — what the durable sealed store recorded at seal time. Material rotates
 *    (every mint bakes a fresh createdAtMs into materialKeyId), so the cache can be
 *    generations behind the live record. Planning only.
 * 3. OBSERVATION — what an available-lanes snapshot saw at command start. Lane reads
 *    run outside the per-session commit queue, so observations are stale by
 *    construction. Planning only.
 *
 * `Ed25519RestoreMaterialIdentity` is the boundary type between planning and effect:
 * an identity resolved against the live record AT the restore boundary, or — only
 * when no live authority exists (e.g. the first restore after a page reload) — an
 * explicit fallback to the caller's planning-time hint. The brand makes
 * `resolveEd25519RestoreMaterialIdentity` the sole constructor, so a raw lane
 * snapshot or durable-cache identity can no longer flow into a restore request
 * unexamined. (Doing exactly that previously produced
 * "[SigningEngine][near] selected Ed25519 restore material identity mismatch":
 * a snapshot captured before a re-seal was hard-compared against the live record
 * instead of being re-resolved here.)
 */
export type Ed25519RestoreMaterialIdentity = Brand<
  {
    readonly bindingDigest: Ed25519WorkerMaterialBindingDigest;
    readonly materialKeyId: Ed25519WorkerMaterialKeyId;
    /** Which store answered at resolution time; diagnostic only. */
    readonly source: 'live_record' | 'caller_hint';
  },
  'Ed25519RestoreMaterialIdentity'
>;

/** Planning-time material identity offered by the caller (lane snapshot or durable cache). */
export type Ed25519RestoreMaterialHintInput = {
  bindingDigest: Ed25519WorkerMaterialBindingDigest;
  materialKeyId: Ed25519WorkerMaterialKeyId;
};

export type Ed25519RestoreMaterialResolution =
  | { kind: 'resolved'; identity: Ed25519RestoreMaterialIdentity }
  | { kind: 'unavailable'; reason: 'no_record_and_no_hint' };

// The single place a value acquires the Ed25519RestoreMaterialIdentity brand.
// Do not export; the brand is meaningful only via resolveEd25519RestoreMaterialIdentity.
function brandResolvedIdentity(args: {
  bindingDigest: Ed25519WorkerMaterialBindingDigest;
  materialKeyId: Ed25519WorkerMaterialKeyId;
  source: 'live_record' | 'caller_hint';
}): Ed25519RestoreMaterialIdentity {
  return {
    bindingDigest: args.bindingDigest,
    materialKeyId: args.materialKeyId,
    source: args.source,
  } as Ed25519RestoreMaterialIdentity;
}

/**
 * Resolve the material identity a restore request must bind to, preferring the live
 * session record over whatever the caller observed earlier.
 *
 * Resolution order:
 * - Live record holds a restorable/loaded material identity → that identity wins,
 *   unconditionally. A differing hint is logged, not thrown: lane snapshots are taken
 *   outside the commit queue and legitimately go stale whenever material re-seals
 *   between snapshot and restore (e.g. the tail of the previous transaction).
 * - No live authority (no record — fresh page load — or a record momentarily holding
 *   no material, e.g. `auth_ready_material_pending` after a reconnect provisioned the
 *   session but before material re-attached) → fall back to the caller's hint.
 *   Restoring the durable seal the hint names is precisely how the record regains
 *   its material, so the fallback is not a weakening of authority.
 * - Neither → unavailable; the caller decides how to fail.
 */
export function resolveEd25519RestoreMaterialIdentity(args: {
  thresholdSessionId: string;
  hint: Ed25519RestoreMaterialHintInput | null;
}): Ed25519RestoreMaterialResolution {
  const record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
    args.thresholdSessionId,
  );
  const recordIdentity = record
    ? routerAbEd25519WorkerMaterialIdentityFromPersistedState(
        classifyRouterAbEd25519PersistedSigningRecord(record),
      )
    : null;
  if (recordIdentity) {
    if (
      args.hint &&
      (String(args.hint.bindingDigest) !== String(recordIdentity.bindingDigest) ||
        String(args.hint.materialKeyId) !== String(recordIdentity.materialKeyId))
    ) {
      // Not an error (see resolution order above), but frequent divergence means a
      // store is not being kept in sync — surface it for diagnosis.
      console.warn(
        '[SigningEngine][ed25519] stale material hint superseded by live record at restore boundary',
        {
          thresholdSessionId: args.thresholdSessionId,
          hintMaterialKeyId: String(args.hint.materialKeyId),
          recordMaterialKeyId: String(recordIdentity.materialKeyId),
        },
      );
    }
    return {
      kind: 'resolved',
      identity: brandResolvedIdentity({
        bindingDigest: recordIdentity.bindingDigest,
        materialKeyId: recordIdentity.materialKeyId,
        source: 'live_record',
      }),
    };
  }
  if (args.hint) {
    return {
      kind: 'resolved',
      identity: brandResolvedIdentity({
        bindingDigest: args.hint.bindingDigest,
        materialKeyId: args.hint.materialKeyId,
        source: 'caller_hint',
      }),
    };
  }
  return { kind: 'unavailable', reason: 'no_record_and_no_hint' };
}
