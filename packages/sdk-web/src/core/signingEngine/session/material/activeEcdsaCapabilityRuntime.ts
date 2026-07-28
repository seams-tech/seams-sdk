import {
  IndexedDbEcdsaCapabilityManifestStore,
  type EcdsaCapabilitySelector,
} from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import {
  listExactSealedSessionsForWallet,
  type readExactSealedSession,
  type CurrentEcdsaSealedSessionRecord,
} from '../persistence/sealedSessionStore';
import {
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  resolveExactEcdsaSealedRuntime,
  type ExactEcdsaSealedRuntime,
  type ExactEcdsaSealedRuntimeResolution,
} from './ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from './ecdsaCapabilityManifest';

// Async composition over the pure correlation in ecdsaSealedRuntime: select the
// wallet's active capability for a chain target, read that wallet's exact
// sealed records, and correlate the two halves. Kept separate so the
// correlation itself stays synchronous and directly testable.

const ecdsaCapabilityManifestStore = new IndexedDbEcdsaCapabilityManifestStore();

export type ActiveEcdsaCapabilityRuntimeResolution =
  | {
      readonly kind: 'resolved';
      readonly manifest: ActiveEcdsaCapabilityManifest;
      readonly runtime: ExactEcdsaSealedRuntime;
      readonly reason?: never;
    }
  | {
      readonly kind: 'blocked';
      readonly reason:
        | Extract<ExactEcdsaSealedRuntimeResolution, { kind: 'blocked' }>['reason']
        | 'missing_capability';
      readonly manifest?: never;
      readonly runtime?: never;
    };

function manifestCoversTarget(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly chainTarget: ThresholdEcdsaChainTarget;
}): boolean {
  return args.manifest.signer.scope.targetMemberships.some((membership) =>
    thresholdEcdsaChainTargetsEqual(membership, args.chainTarget),
  );
}

async function listActiveManifestsForTarget(args: {
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
}): Promise<readonly ActiveEcdsaCapabilityManifest[]> {
  const subjects = await ecdsaCapabilityManifestStore.listActiveWalletCapabilitySubjects(
    args.walletId,
  );
  if (subjects.kind !== 'resolved') return [];
  const manifests: ActiveEcdsaCapabilityManifest[] = [];
  for (const subject of subjects.subjects) {
    const selector: EcdsaCapabilitySelector = {
      capability: subject.capability,
      authority: subject.authority,
    };
    const lookup = await ecdsaCapabilityManifestStore.lookup(selector);
    if (lookup.kind !== 'active') continue;
    if (!manifestCoversTarget({ manifest: lookup.manifest, chainTarget: args.chainTarget })) {
      continue;
    }
    manifests.push(lookup.manifest);
  }
  return manifests;
}

async function listSealedEcdsaRecordsForWallet(args: {
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
}): Promise<readonly CurrentEcdsaSealedSessionRecord[]> {
  const records: CurrentEcdsaSealedSessionRecord[] = [];
  for (const authMethod of ['passkey', 'email_otp'] as const) {
    const found = await listExactSealedSessionsForWallet({
      walletId: String(args.walletId),
      filter: { authMethod, curve: 'ecdsa', chainTarget: args.chainTarget },
    }).catch(() => []);
    for (const record of found) {
      if (record.curve === 'ecdsa') records.push(record);
    }
  }
  return records;
}

export async function resolveActiveEcdsaCapabilityRuntime(args: {
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
}): Promise<ActiveEcdsaCapabilityRuntimeResolution> {
  const manifests = await listActiveManifestsForTarget(args);
  if (manifests.length === 0) return { kind: 'blocked', reason: 'missing_capability' };
  // Two active capabilities for one wallet/target is a store conflict; the
  // caller cannot pick between them without guessing which material to use.
  if (manifests.length > 1) return { kind: 'blocked', reason: 'exact_record_conflict' };
  const manifest = manifests[0]!;
  const sealedRecords = await listSealedEcdsaRecordsForWallet(args);
  const resolution = resolveExactEcdsaSealedRuntime({
    manifest,
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    sealedRecords,
  });
  return resolution.kind === 'resolved'
    ? { kind: 'resolved', manifest, runtime: resolution.runtime }
    : { kind: 'blocked', reason: resolution.reason };
}

/** Resolve the runtime for one exact sealed record addressed by its
 * threshold-session id. The session id addresses the sealed record only --
 * session-scoped runtime state is what it legitimately names. Material identity
 * still comes from correlating that record against the active manifest by
 * material activation, so nothing here identifies material by session id. */
export async function resolveEcdsaSealedRuntimeByThresholdSessionId(args: {
  readonly thresholdSessionId: string;
  readonly authMethod: 'passkey' | 'email_otp';
  readonly readExactSealedSession: typeof readExactSealedSession;
  readonly chainTargetHint: ThresholdEcdsaChainTarget;
}): Promise<ActiveEcdsaCapabilityRuntimeResolution> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return { kind: 'blocked', reason: 'missing_material' };
  const record = await args
    .readExactSealedSession(thresholdSessionId, {
      authMethod: args.authMethod,
      curve: 'ecdsa',
      chainTarget: args.chainTargetHint,
    })
    .catch(() => null);
  if (!record || record.curve !== 'ecdsa') return { kind: 'blocked', reason: 'missing_material' };
  // The record names its own wallet and chain target, so correlation needs no
  // extra context threaded down from the caller.
  return await resolveActiveEcdsaCapabilityRuntime({
    walletId: toWalletId(String(record.walletId)),
    chainTarget: record.ecdsaRestore.chainTarget,
  });
}
