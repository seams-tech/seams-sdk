import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  listEcdsaSealedSessionsForWallet,
  listExactSealedSessionsForWallet,
  type EcdsaDurableLaneRecord,
  type SigningSessionSealedStoreRecord,
} from '../persistence/sealedSessionStore';
import {
  ed25519AvailableLaneIdentityKey,
  ecdsaAvailableLaneIdentityKey,
  readAvailableSigningLanes,
  type ReadAvailableSigningLanesForSigningInput,
  type ReadAvailableSigningLanesInput,
  type AvailableSigningLanes,
  type ConcreteAvailableEcdsaSigningLane,
} from './availableSigningLanes';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { EvmFamilyEcdsaSigningCapabilityAvailability } from '../material/ecdsaSigningCapability';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildPasskeyEcdsaAuthBinding,
  buildResolvedEvmFamilyEcdsaKey,
  toRpId,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';

export type PersistedAvailableSigningLanesDeps = {
  readActiveWalletSessionAuthorization?: (
    walletId: WalletId,
  ) => Promise<ActiveWalletSessionAuthorizationProjection | null>;
  listEcdsaSigningCapabilitiesForWallet: (args: {
    walletId: string;
    chainTargets: readonly ThresholdEcdsaChainTarget[];
    authMethod?: SignerAuthMethod;
  }) => Promise<readonly EvmFamilyEcdsaSigningCapabilityAvailability[]>;
};

function canonicalEcdsaLaneFromCapability(args: {
  available: EvmFamilyEcdsaSigningCapabilityAvailability;
  chainTarget: ThresholdEcdsaChainTarget;
}): ConcreteAvailableEcdsaSigningLane | null {
  const capability = args.available.capability;
  const signer = capability.manifest.signer;
  if (
    !signer.scope.targetMemberships.some(
      (membership) =>
        thresholdEcdsaChainTargetKey(membership) === thresholdEcdsaChainTargetKey(args.chainTarget),
    )
  ) {
    return null;
  }
  const facts = signer.registeredPublicFacts;
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: signer.walletId,
    ecdsaThresholdKeyId: capability.manifest.durableMaterial.roleLocalBinding.ecdsaThresholdKeyId,
    signingRootId: signer.signingRootId,
    signingRootVersion: signer.signingRootVersion,
    participantIds: facts.participantIds,
    thresholdOwnerAddress: facts.thresholdOwnerAddress,
  });
  const base = {
    capability,
    key,
    materialActivation: capability.manifest.activation.materialActivation,
    publicFacts: facts,
    curve: 'ecdsa' as const,
    chainTarget: args.chainTarget,
    source: 'canonical_capability' as const,
  };
  const authorization =
    args.available.kind === 'authorized_evm_family_ecdsa_signing_capability'
      ? args.available.authorization
      : null;
  if (isPasskeyWalletAuthAuthority(capability.authority)) {
    const auth = {
      kind: 'passkey' as const,
      rpId: toRpId(capability.authority.verifier.rpId),
      credentialIdB64u: capability.authority.factor.credentialIdB64u,
    };
    const resolvedKey = buildResolvedEvmFamilyEcdsaKey({
      walletId: signer.walletId,
      publicFacts: facts,
      authBinding: buildPasskeyEcdsaAuthBinding(auth),
    });
    return authorization
      ? {
          ...base,
          auth,
          resolvedKey,
          state: 'ready',
          authorization,
          remainingUses: authorization.status.remainingUses,
          expiresAtMs: authorization.status.expiresAtMs,
        }
      : { ...base, auth, resolvedKey, state: 'deferred' };
  }
  if (!isEmailOtpWalletAuthAuthority(capability.authority)) return null;
  const auth = {
    kind: 'email_otp' as const,
    providerSubjectId: capability.authority.factor.providerUserId,
  };
  return authorization
    ? {
        ...base,
        auth,
        state: 'ready',
        authorization,
        remainingUses: authorization.status.remainingUses,
        expiresAtMs: authorization.status.expiresAtMs,
      }
    : { ...base, auth, state: 'deferred' };
}

function assertNeverPersistedEd25519AuthMethod(value: never): never {
  throw new Error(`Unsupported persisted Ed25519 auth method: ${String(value)}`);
}

export async function readPersistedAvailableSigningLanes(
  deps: PersistedAvailableSigningLanesDeps,
  args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[],
): Promise<AvailableSigningLanes> {
  return await readPersistedAvailableSigningLanesForTargets(deps, {
    ...args,
    ecdsaChainTargets,
  });
}

export async function readPersistedAvailableSigningLanesForSigning(
  deps: PersistedAvailableSigningLanesDeps,
  args: ReadAvailableSigningLanesForSigningInput,
  defaultEcdsaChainTargets: readonly ThresholdEcdsaChainTarget[],
): Promise<AvailableSigningLanes> {
  if (args.curve === 'ecdsa') {
    const { curve, ...availableLanesArgs } = args;
    const ecdsaChainTargetsByKey = new Map<string, ThresholdEcdsaChainTarget>();
    for (const chainTarget of [...args.ecdsaChainTargets, ...defaultEcdsaChainTargets]) {
      ecdsaChainTargetsByKey.set(thresholdEcdsaChainTargetKey(chainTarget), chainTarget);
    }
    return await readPersistedAvailableSigningLanesForTargets(deps, {
      ...availableLanesArgs,
      ecdsaChainTargets: [...ecdsaChainTargetsByKey.values()],
    });
  }
  const { curve, ...availableLanesArgs } = args;
  return await readPersistedAvailableSigningLanes(deps, availableLanesArgs, []);
}

function sealedRecordHasEd25519ThresholdSession(record: SigningSessionSealedStoreRecord): boolean {
  return String(record.thresholdSessionIds?.ed25519 || '').trim().length > 0;
}

function sealedEcdsaRecordMatchesAnyChainTarget(
  record: SigningSessionSealedStoreRecord,
  chainTargets: readonly ThresholdEcdsaChainTarget[],
): boolean {
  const recordChainTarget = record.ecdsaRestore?.chainTarget;
  if (!recordChainTarget) return false;
  const recordChainTargetKey = thresholdEcdsaChainTargetKey(recordChainTarget);
  for (const chainTarget of chainTargets) {
    if (recordChainTargetKey === thresholdEcdsaChainTargetKey(chainTarget)) return true;
  }
  return false;
}

function filterEmailOtpCompanionEcdsaRecords(
  records: readonly EcdsaDurableLaneRecord[],
  chainTargets: readonly ThresholdEcdsaChainTarget[],
): SigningSessionSealedStoreRecord[] {
  const matchingRecords: SigningSessionSealedStoreRecord[] = [];
  for (const record of records) {
    if ('recordKind' in record) continue;
    if (!sealedRecordHasEd25519ThresholdSession(record)) continue;
    if (chainTargets.length > 0 && !sealedEcdsaRecordMatchesAnyChainTarget(record, chainTargets)) {
      continue;
    }
    matchingRecords.push(record);
  }
  return matchingRecords;
}

export async function readPersistedAvailableSigningLanesForTargets(
  deps: PersistedAvailableSigningLanesDeps,
  args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'> & {
    ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
  },
): Promise<AvailableSigningLanes> {
  const walletId = String(toWalletId(args.walletId)).trim();
  return await readAvailableSigningLanes(
    {
      ...args,
      walletId,
      ecdsaChainTargets: args.ecdsaChainTargets,
    },
    {
      readActiveWalletSessionAuthorization: deps.readActiveWalletSessionAuthorization,
      listSealedRecordsForWallet: async ({ walletId: recordWalletId, filter }) => {
        const listByAuthMethod = async (
          authMethod: SignerAuthMethod,
        ): Promise<SigningSessionSealedStoreRecord[]> => {
          const ed25519Records = await listExactSealedSessionsForWallet({
            walletId: recordWalletId,
            filter: { authMethod, curve: 'ed25519' },
          });
          switch (authMethod) {
            case SIGNER_AUTH_METHODS.passkey:
              return ed25519Records;
            case SIGNER_AUTH_METHODS.emailOtp: {
              const companionEcdsaRecords = filterEmailOtpCompanionEcdsaRecords(
                await listEcdsaSealedSessionsForWallet({
                  walletId: recordWalletId,
                  filter: {
                    authMethod: SIGNER_AUTH_METHODS.emailOtp,
                    curve: 'ecdsa',
                  },
                }),
                args.ecdsaChainTargets,
              );
              return [...ed25519Records, ...companionEcdsaRecords];
            }
            default:
              return assertNeverPersistedEd25519AuthMethod(authMethod);
          }
        };
        if (filter.authMethod) {
          return await listByAuthMethod(filter.authMethod);
        }
        const [emailOtpRecords, passkeyRecords] = await Promise.all([
          listByAuthMethod(SIGNER_AUTH_METHODS.emailOtp),
          listByAuthMethod(SIGNER_AUTH_METHODS.passkey),
        ]);
        return [...emailOtpRecords, ...passkeyRecords];
      },
      listCanonicalEcdsaLanesForWallet: async ({ walletId: recordWalletId }) => {
        const lanes: ConcreteAvailableEcdsaSigningLane[] = [];
        const seen = new Set<string>();
        const capabilities = await deps.listEcdsaSigningCapabilitiesForWallet({
          walletId: recordWalletId,
          chainTargets: args.ecdsaChainTargets,
          ...(args.authMethod ? { authMethod: args.authMethod } : {}),
        });
        for (const available of capabilities) {
          for (const chainTarget of args.ecdsaChainTargets) {
            const lane = canonicalEcdsaLaneFromCapability({ available, chainTarget });
            if (!lane) continue;
            const identityKey = ecdsaAvailableLaneIdentityKey(lane);
            if (!identityKey || seen.has(identityKey)) continue;
            seen.add(identityKey);
            lanes.push(lane);
          }
        }
        return lanes;
      },
    },
  );
}
