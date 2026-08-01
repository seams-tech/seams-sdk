import type { SigningSessionStatus } from '@/core/types/seams';
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import {
  buildWalletSessionStatusCheck,
  ed25519WalletSessionStatusOwner,
  type SigningSessionStatusCheck,
} from '../lifecycle/walletSessionStatus';
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
  durableRecordPolicyAdvisory,
  warmStatusToAvailableLaneStateAdvisory,
  type ReadAvailableSigningLanesForSigningInput,
  type ReadAvailableSigningLanesInput,
  type AvailableSigningLanes,
  type AvailableLaneStateAdvisory,
  type ConcreteAvailableEcdsaSigningLane,
  type AvailableSigningLanesRuntimeEd25519Record,
} from './availableSigningLanes';
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
import {
  ed25519SealedRuntimeAuthorityRef,
  ed25519SigningGrantForAuthorization,
  parseExactEd25519SealedSessionRuntime,
  type ExactEd25519SealedSessionRuntime,
} from '../warmCapabilities/ed25519SealedSessionRuntime';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { signingLaneAuthMethod } from '../identity/signingLaneAuthBinding';
import type { EmailOtpWarmMaterialTarget } from '../../workerManager/workerTypes';

export type PersistedAvailableSigningLanesDeps = {
  listEcdsaSigningCapabilitiesForWallet: (args: {
    walletId: string;
    chainTargets: readonly ThresholdEcdsaChainTarget[];
    authMethod?: SignerAuthMethod;
  }) => Promise<readonly EvmFamilyEcdsaSigningCapabilityAvailability[]>;
  statusReader: {
    getWarmSessionStatus: (args: { sessionId: string }) => Promise<WarmSessionStatusResult>;
  };
  getEmailOtpWarmSessionStatus: (
    target: EmailOtpWarmMaterialTarget,
  ) => Promise<WarmSessionStatusResult>;
  getWalletSessionStatus?: (
    args: SigningSessionStatusCheck,
  ) => Promise<SigningSessionStatus | null>;
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

function applyWalletSessionStatusToAdvisory(args: {
  localAdvisory: AvailableLaneStateAdvisory | null;
  walletSessionStatus: SigningSessionStatus | null;
}): AvailableLaneStateAdvisory | null {
  const sessionStatus = args.walletSessionStatus;
  if (!sessionStatus) return args.localAdvisory;
  if (sessionStatus.status === 'active') {
    const sessionExpiresAtMs = Math.floor(Number(sessionStatus.expiresAtMs) || 0);
    if (args.localAdvisory?.kind === 'runtime_material') {
      return {
        kind: 'runtime_material',
        remainingUses: Math.max(0, Math.floor(Number(sessionStatus.remainingUses) || 0)),
        expiresAtMs: sessionExpiresAtMs > 0 ? sessionExpiresAtMs : args.localAdvisory.expiresAtMs,
      };
    }
    if (args.localAdvisory?.kind === 'durable_policy') {
      return {
        kind: 'durable_policy',
        remainingUses: Math.max(0, Math.floor(Number(sessionStatus.remainingUses) || 0)),
        expiresAtMs: sessionExpiresAtMs > 0 ? sessionExpiresAtMs : args.localAdvisory.expiresAtMs,
        state: args.localAdvisory.state,
      };
    }
    if (args.localAdvisory?.kind !== 'warm_status' || args.localAdvisory.status !== 'active') {
      return args.localAdvisory;
    }
    return {
      kind: 'warm_status',
      status: 'active',
      remainingUses: Math.max(0, Math.floor(Number(sessionStatus.remainingUses) || 0)),
      expiresAtMs: sessionExpiresAtMs > 0 ? sessionExpiresAtMs : args.localAdvisory.expiresAtMs,
    };
  }
  if (sessionStatus.status === 'not_found') {
    return args.localAdvisory;
  }
  if (sessionStatus.status === 'expired') {
    return { kind: 'warm_status', status: 'expired' };
  }
  if (sessionStatus.status === 'exhausted') {
    return {
      kind: 'warm_status',
      status: 'exhausted',
      remainingUses: 0,
    };
  }
  return args.localAdvisory;
}

async function readSessionStatusOrNull(args: {
  reader: NonNullable<PersistedAvailableSigningLanesDeps['getWalletSessionStatus']>;
  check: SigningSessionStatusCheck;
}): Promise<SigningSessionStatus | null> {
  try {
    return await args.reader(args.check);
  } catch {
    return null;
  }
}

async function readEd25519WalletSessionStatusForRuntime(args: {
  reader: NonNullable<PersistedAvailableSigningLanesDeps['getWalletSessionStatus']>;
  runtime: ExactEd25519SealedSessionRuntime;
  walletId: string;
}): Promise<SigningSessionStatus | null> {
  const authorizationRead = await walletSessionAuthorizations.readActiveForWallet(
    args.runtime.walletId,
  );
  const expectedAuthority = await ed25519SealedRuntimeAuthorityRef(args.runtime);
  if (
    authorizationRead.kind !== 'found' ||
    authorizationRead.projection.authMethod !== signingLaneAuthMethod(args.runtime.auth) ||
    authorizationRead.projection.authority.authorityDigest !== expectedAuthority.authorityDigest ||
    authorizationRead.projection.expiresAtMs <= Date.now()
  ) {
    return null;
  }
  return await readSessionStatusOrNull({
    reader: args.reader,
    check: buildWalletSessionStatusCheck({
      owner: ed25519WalletSessionStatusOwner(args.walletId),
      authorization: {
        walletSessionId: authorizationRead.projection.walletSessionId,
        quotaId: authorizationRead.projection.quotaId,
      },
    }),
  });
}

async function readValidatedEd25519WarmClaim(args: {
  deps: Pick<PersistedAvailableSigningLanesDeps, 'statusReader' | 'getEmailOtpWarmSessionStatus'>;
  runtime: ExactEd25519SealedSessionRuntime;
  sessionId: string;
}): Promise<AvailableLaneStateAdvisory | null> {
  const status =
    args.runtime.factor.kind === SIGNER_AUTH_METHODS.emailOtp
      ? await args.deps
          .getEmailOtpWarmSessionStatus({
            kind: 'ed25519_yao',
            thresholdSessionId: args.sessionId,
            materialActivation: args.runtime.sealedRecord.ed25519Restore.materialActivation,
          })
          .catch(() => null)
      : await args.deps.statusReader
          .getWarmSessionStatus({ sessionId: args.sessionId })
          .catch(() => null);
  if (!status) return null;
  const advisory = warmStatusToAvailableLaneStateAdvisory({
    status,
  });
  return advisory.kind === 'warm_status' &&
    (advisory.status === 'cache_miss' || advisory.status === 'unavailable')
    ? null
    : advisory;
}

async function readEd25519StateAdvisoryForRuntime(args: {
  deps: Pick<PersistedAvailableSigningLanesDeps, 'statusReader' | 'getEmailOtpWarmSessionStatus'>;
  runtime: ExactEd25519SealedSessionRuntime;
  sessionId: string;
}): Promise<AvailableLaneStateAdvisory | null> {
  const ready = args.runtime.expiresAtMs > Date.now() && args.runtime.remainingUses > 0;
  if (ready) {
    const warmAdvisory = await readValidatedEd25519WarmClaim({
      deps: args.deps,
      runtime: args.runtime,
      sessionId: args.sessionId,
    });
    if (warmAdvisory) return warmAdvisory;
  }
  return durableRecordPolicyAdvisory({
    remainingUses: args.runtime.remainingUses,
    expiresAtMs: args.runtime.expiresAtMs,
    state: ready ? 'ready' : 'deferred',
  });
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
  return await readPersistedAvailableSigningLanes(
    deps,
    availableLanesArgs,
    defaultEcdsaChainTargets,
  );
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
    if (!sealedEcdsaRecordMatchesAnyChainTarget(record, chainTargets)) continue;
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
  const persistedEd25519RuntimesBySessionId = new Map<
    string,
    ExactEd25519SealedSessionRuntime
  >();
  return await readAvailableSigningLanes(
    {
      ...args,
      walletId,
      ecdsaChainTargets: args.ecdsaChainTargets,
    },
    {
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
      listRuntimeEd25519RecordsForWallet: async ({ walletId: recordWalletId }) => {
        const records: AvailableSigningLanesRuntimeEd25519Record[] = [];
        const seen = new Set<string>();
        const pushRecord = (record: AvailableSigningLanesRuntimeEd25519Record): void => {
          const identityKey = ed25519AvailableLaneIdentityKey(record);
          if (!identityKey || seen.has(identityKey)) return;
          seen.add(identityKey);
          records.push(record);
        };
        const sealedRecords = args.authMethod
          ? await listExactSealedSessionsForWallet({
              walletId: recordWalletId,
              filter: { authMethod: args.authMethod, curve: 'ed25519' },
            })
          : (
              await Promise.all([
                listExactSealedSessionsForWallet({
                  walletId: recordWalletId,
                  filter: { authMethod: SIGNER_AUTH_METHODS.emailOtp, curve: 'ed25519' },
                }),
                listExactSealedSessionsForWallet({
                  walletId: recordWalletId,
                  filter: { authMethod: SIGNER_AUTH_METHODS.passkey, curve: 'ed25519' },
                }),
              ])
            ).flat();
        for (const sealedRecord of sealedRecords) {
          if (sealedRecord.curve !== 'ed25519') continue;
          const runtime = parseExactEd25519SealedSessionRuntime(sealedRecord);
          if (!runtime) continue;
          const authorizationRead = await walletSessionAuthorizations.readActiveForWallet(
            runtime.walletId,
          );
          const authorization =
            authorizationRead.kind === 'found' ? authorizationRead.projection : null;
          const signingGrantId = authorization
            ? ed25519SigningGrantForAuthorization({ runtime, authorization })
            : null;
          persistedEd25519RuntimesBySessionId.set(runtime.thresholdSessionId, runtime);
          const base = {
            auth: runtime.auth,
            curve: 'ed25519',
            chain: 'near',
            walletId: runtime.walletId,
            nearAccountId: runtime.nearAccountId,
            nearEd25519SigningKeyId: runtime.nearEd25519SigningKeyId,
            signerSlot: runtime.signerSlot,
            materialActivation: runtime.sealedRecord.ed25519Restore.materialActivation,
            routerAbNormalSigning: runtime.routerAbNormalSigning,
            thresholdSessionId: runtime.thresholdSessionId,
            source: 'durable_sealed_record',
            remainingUses: runtime.remainingUses,
            expiresAtMs: runtime.expiresAtMs,
            updatedAtMs: runtime.sealedRecord.updatedAtMs,
          } as const;
          pushRecord(
            authorization && signingGrantId
              ? {
                  ...base,
                  authorizationState: 'authorized',
                  authorization,
                  signingGrantId,
                }
              : {
                  ...base,
                  authorizationState: 'authorization_required',
                },
          );
        }
        return records;
      },
      readWarmStatusAdvisoriesForSessions: async (sessionIds) => {
        const advisories = new Map<string, AvailableLaneStateAdvisory | null>();
        await Promise.all(
          sessionIds.map(async (sessionId) => {
            const runtime = persistedEd25519RuntimesBySessionId.get(sessionId);
            if (!runtime) {
              advisories.set(sessionId, null);
              return;
            }
            const localAdvisory = await readEd25519StateAdvisoryForRuntime({
              deps,
              runtime,
              sessionId,
            });
            const walletSessionStatus =
              deps.getWalletSessionStatus
                ? await readEd25519WalletSessionStatusForRuntime({
                    reader: deps.getWalletSessionStatus,
                    runtime,
                    walletId,
                  })
                : null;
            advisories.set(
              sessionId,
              applyWalletSessionStatusToAdvisory({
                localAdvisory,
                walletSessionStatus,
              }),
            );
          }),
        );
        return advisories;
      },
    },
  );
}
