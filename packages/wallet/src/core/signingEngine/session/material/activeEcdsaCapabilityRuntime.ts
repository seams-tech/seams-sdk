import {
  type CurrentEcdsaSealedSessionRecord,
  type listExactSealedSessionsForWallet,
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
import type { ExactWalletSessionReadPorts } from '../identity/exactWalletSessionCredential';

// Async composition over the pure correlation in ecdsaSealedRuntime: select the
// wallet's active capability for a chain target, read that wallet's exact
// sealed records, and correlate the two halves. Kept separate so the
// correlation itself stays synchronous and directly testable.

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

export type ActiveEcdsaCapabilityRuntimeReadPorts = Pick<
  ExactWalletSessionReadPorts,
  'resolveSelectedWalletAuthority'
> & {
  readonly listActiveEcdsaCapabilityManifestsForWallet: (
    walletId: WalletId,
  ) => Promise<readonly ActiveEcdsaCapabilityManifest[]>;
  readonly listExactSealedSessionsForWallet: typeof listExactSealedSessionsForWallet;
};

export type ResolveActiveEcdsaCapabilityRuntimeInput = {
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
};

export type ActiveEcdsaCapabilityRuntimeResolver = (
  args: ResolveActiveEcdsaCapabilityRuntimeInput,
) => Promise<ActiveEcdsaCapabilityRuntimeResolution>;

export type ResolveActiveEcdsaCapabilityRuntimeForChainInput = {
  readonly walletId: WalletId;
  readonly chain: ThresholdEcdsaChainTarget['kind'];
};

export type ActiveEcdsaCapabilityRuntimeForChainResolver = (
  args: ResolveActiveEcdsaCapabilityRuntimeForChainInput,
) => Promise<ActiveEcdsaCapabilityRuntimeResolution>;

function manifestCoversTarget(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly chainTarget: ThresholdEcdsaChainTarget;
}): boolean {
  return args.manifest.signer.scope.targetMemberships.some((membership) =>
    thresholdEcdsaChainTargetsEqual(membership, args.chainTarget),
  );
}

async function listActiveManifestsForTarget(args: {
  readonly ports: ActiveEcdsaCapabilityRuntimeReadPorts;
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
}): Promise<readonly ActiveEcdsaCapabilityManifest[]> {
  const manifests = await args.ports.listActiveEcdsaCapabilityManifestsForWallet(args.walletId);
  return manifests.filter((manifest) =>
    manifestCoversTarget({ manifest, chainTarget: args.chainTarget }),
  );
}

async function listSealedEcdsaRecordsForWallet(args: {
  readonly ports: ActiveEcdsaCapabilityRuntimeReadPorts;
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly authMethod?: SigningSessionSealAuthMethod;
}): Promise<readonly CurrentEcdsaSealedSessionRecord[]> {
  const records: CurrentEcdsaSealedSessionRecord[] = [];
  const authMethods = args.authMethod
    ? ([args.authMethod] as const)
    : (['passkey', 'email_otp'] as const);
  for (const authMethod of authMethods) {
    const found = await args.ports.listExactSealedSessionsForWallet({
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

async function narrowToSelectedMethod(
  ports: ActiveEcdsaCapabilityRuntimeReadPorts,
  walletId: WalletId,
  manifests: readonly ActiveEcdsaCapabilityManifest[],
): Promise<readonly ActiveEcdsaCapabilityManifest[]> {
  const selected = await ports.resolveSelectedWalletAuthority(String(walletId));
  if (selected.kind !== 'resolved') return manifests;
  const selectedMethodId = String(selected.authMethod.walletAuthMethodId);
  const matching = manifests.filter(
    (manifest) => String(manifest.signer.authority.walletAuthMethodId) === selectedMethodId,
  );
  return matching.length > 0 ? matching : manifests;
}

export async function resolveActiveEcdsaCapabilityRuntime(
  ports: ActiveEcdsaCapabilityRuntimeReadPorts,
  args: ResolveActiveEcdsaCapabilityRuntimeInput,
): Promise<ActiveEcdsaCapabilityRuntimeResolution> {
  const all = await listActiveManifestsForTarget({ ports, ...args });
  if (all.length === 0) return { kind: 'blocked', reason: 'missing_capability' };
  /* R109C: several capabilities for one wallet and target used to mean the
     store had conflicting records, because a wallet had one auth method. Now
     each method on an authority holds its own access projection over the same
     activation, so the caller is not guessing - it is operating as the selected
     method, and that is the one whose projection to use. Two projections for
     the SAME method is still a conflict. */
  const manifests = all.length > 1 ? await narrowToSelectedMethod(ports, args.walletId, all) : all;
  if (manifests.length !== 1) return { kind: 'blocked', reason: 'exact_record_conflict' };
  const manifest = manifests[0]!;
  const sealedRecords = await listSealedEcdsaRecordsForWallet({ ports, ...args });
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

export function createActiveEcdsaCapabilityRuntimeResolver(
  ports: ActiveEcdsaCapabilityRuntimeReadPorts,
): ActiveEcdsaCapabilityRuntimeResolver {
  return resolveActiveEcdsaCapabilityRuntime.bind(null, ports);
}

/** Resolve by chain kind, taking the exact chain target from the manifest's own
 * target memberships. The warm-session envelope is keyed by kind (evm/tempo)
 * while correlation needs a full target, and the manifest is the authority on
 * which targets its capability covers. */
export async function resolveActiveEcdsaCapabilityRuntimeForChain(
  ports: ActiveEcdsaCapabilityRuntimeReadPorts,
  args: ResolveActiveEcdsaCapabilityRuntimeForChainInput,
): Promise<ActiveEcdsaCapabilityRuntimeResolution> {
  const manifests = await ports.listActiveEcdsaCapabilityManifestsForWallet(args.walletId);
  const matches: Array<{
    manifest: ActiveEcdsaCapabilityManifest;
    chainTarget: ThresholdEcdsaChainTarget;
  }> = [];
  for (const manifest of manifests) {
    // Every concrete target of this kind counts. A manifest covering two
    // concrete targets of the same kind is ambiguous, not a reason to take the
    // first one.
    for (const membership of manifest.signer.scope.targetMemberships) {
      if (membership.kind !== args.chain) continue;
      matches.push({ manifest, chainTarget: membership });
    }
  }
  if (matches.length === 0) return { kind: 'blocked', reason: 'missing_capability' };
  if (matches.length > 1) return { kind: 'blocked', reason: 'exact_record_conflict' };
  const match = matches[0]!;
  const sealedRecords = await listSealedEcdsaRecordsForWallet({
    ports,
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

export function createActiveEcdsaCapabilityRuntimeForChainResolver(
  ports: ActiveEcdsaCapabilityRuntimeReadPorts,
): ActiveEcdsaCapabilityRuntimeForChainResolver {
  return resolveActiveEcdsaCapabilityRuntimeForChain.bind(null, ports);
}
