import {
  IndexedDbEcdsaCapabilityManifestStore,
  type EcdsaCapabilitySelector,
} from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import {
  listExactSealedSessionsForWallet,
  type CurrentEcdsaSealedSessionRecord,
} from '../persistence/sealedSessionStore';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  resolveExactEcdsaSealedRuntime,
  type ExactEcdsaCapabilityRuntime,
  type ExactEcdsaSealedRuntime,
  type ExactEcdsaSealedRuntimeResolution,
} from './ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from './ecdsaCapabilityManifest';
import type { SigningSessionSealAuthMethod } from '@shared/utils/signingSessionSeal';

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

export type ExactEcdsaCapabilityRuntimeResolution =
  | {
      readonly kind: 'resolved';
      readonly manifest: ActiveEcdsaCapabilityManifest;
      readonly runtime: ExactEcdsaCapabilityRuntime;
      readonly reason?: never;
    }
  | {
      readonly kind: 'blocked';
      readonly reason: 'chain_mismatch' | 'corrupt';
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
  readonly authMethod?: SigningSessionSealAuthMethod;
}): Promise<readonly CurrentEcdsaSealedSessionRecord[]> {
  const records: CurrentEcdsaSealedSessionRecord[] = [];
  const authMethods = args.authMethod
    ? ([args.authMethod] as const)
    : (['passkey', 'email_otp'] as const);
  for (const authMethod of authMethods) {
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

export async function resolveExactEcdsaCapabilityRuntime(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly relayerUrl: string;
}): Promise<ExactEcdsaCapabilityRuntimeResolution> {
  if (!manifestCoversTarget({ manifest: args.manifest, chainTarget: args.chainTarget })) {
    return { kind: 'blocked', reason: 'chain_mismatch' };
  }
  const durable = args.manifest.durableMaterial;
  const facts = durable.roleLocalPublicFacts;
  const participantIds = exactTwoPartyParticipantIds(facts.participantIds);
  const relayerUrl = String(args.relayerUrl).trim().replace(/\/+$/g, '');
  if (!participantIds || !relayerUrl) return { kind: 'blocked', reason: 'corrupt' };
  return {
    kind: 'resolved',
    manifest: args.manifest,
    runtime: {
      kind: 'exact_ecdsa_capability_runtime_v1',
      walletId: args.manifest.signer.walletId,
      chainTarget: args.chainTarget,
      materialActivation: durable.materialActivation,
      normalSigning: durable.routerAbEcdsaDerivationNormalSigning,
      relayerUrl,
      relayerKeyId: String(durable.roleLocalBinding.relayerKeyId),
      clientVerifyingPublicKey33B64u: durable.roleLocalBinding.clientVerifyingPublicKey33B64u,
      participantIds,
      ecdsaThresholdKeyId: String(facts.ecdsaThresholdKeyId),
      thresholdEcdsaPublicKeyB64u: facts.groupPublicKey33B64u,
      keyHandle: String(facts.keyHandle),
      runtimePolicyScope: durable.runtimePolicyScope,
      roleLocalMaterialRef: {
        kind: 'ecdsa_role_local_persisted_material_ref_v1',
        durableMaterialRef: durable.durableMaterialRef,
        bindingDigest: durable.bindingDigest,
        materialActivation: durable.materialActivation,
      },
    },
  };
}

function exactTwoPartyParticipantIds(value: readonly number[]): readonly [number, number] | null {
  if (value.length !== 2) return null;
  const first = value[0];
  const second = value[1];
  if (
    !Number.isSafeInteger(first) ||
    !Number.isSafeInteger(second) ||
    first <= 0 ||
    second <= 0 ||
    first === second
  ) {
    return null;
  }
  return [first, second];
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

/** Resolve by chain kind, taking the exact chain target from the manifest's own
 * target memberships. The warm-session envelope is keyed by kind (evm/tempo)
 * while correlation needs a full target, and the manifest is the authority on
 * which targets its capability covers. */
export async function resolveActiveEcdsaCapabilityRuntimeForChain(args: {
  readonly walletId: WalletId;
  readonly chain: ThresholdEcdsaChainTarget['kind'];
}): Promise<ActiveEcdsaCapabilityRuntimeResolution> {
  const subjects = await ecdsaCapabilityManifestStore.listActiveWalletCapabilitySubjects(
    args.walletId,
  );
  if (subjects.kind !== 'resolved') return { kind: 'blocked', reason: 'missing_capability' };
  const matches: Array<{
    manifest: ActiveEcdsaCapabilityManifest;
    chainTarget: ThresholdEcdsaChainTarget;
  }> = [];
  for (const subject of subjects.subjects) {
    const lookup = await ecdsaCapabilityManifestStore.lookup({
      capability: subject.capability,
      authority: subject.authority,
    });
    if (lookup.kind !== 'active') continue;
    // Every concrete target of this kind counts. A manifest covering two
    // concrete targets of the same kind is ambiguous, not a reason to take the
    // first one.
    for (const membership of lookup.manifest.signer.scope.targetMemberships) {
      if (membership.kind !== args.chain) continue;
      matches.push({ manifest: lookup.manifest, chainTarget: membership });
    }
  }
  if (matches.length === 0) return { kind: 'blocked', reason: 'missing_capability' };
  if (matches.length > 1) return { kind: 'blocked', reason: 'exact_record_conflict' };
  const match = matches[0]!;
  const sealedRecords = await listSealedEcdsaRecordsForWallet({
    walletId: args.walletId,
    chainTarget: match.chainTarget,
  });
  const resolution = resolveExactEcdsaSealedRuntime({
    manifest: match.manifest,
    walletId: args.walletId,
    chainTarget: match.chainTarget,
    sealedRecords,
  });
  return resolution.kind === 'resolved'
    ? { kind: 'resolved', manifest: match.manifest, runtime: resolution.runtime }
    : { kind: 'blocked', reason: resolution.reason };
}
