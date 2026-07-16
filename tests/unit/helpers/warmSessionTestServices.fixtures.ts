import type {
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
  WarmSessionMaterialClaimer,
  VolatileWarmSessionMaterialClearer,
  WarmSessionSealPersister,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type {
  ThresholdEcdsaSessionBootstrapResult,
  ThresholdEcdsaActivationChain,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { ThresholdEcdsaActivationRequest } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import {
  toExactEcdsaSigningLaneIdentity,
  thresholdEcdsaSessionRecordReadModel,
  thresholdEcdsaRecordRpId,
  type ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  type ConsumeSingleUseEmailOtpEcdsaLaneResult,
  type ThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '@/core/signingEngine/session/identity/laneIdentity';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import { createWarmSessionCapabilityReader } from '@/core/signingEngine/session/warmCapabilities/capabilityReader';
import { createClearVolatileWarmSessionMaterialCommand } from '@/core/signingEngine/session/warmCapabilities/volatileWarmMaterialCommands';
import { parseVolatileWarmSessionId } from '@/core/signingEngine/session/warmCapabilities/volatileWarmSessionId';
import {
  buildEcdsaReconnectMaterial,
  buildEcdsaSessionProvisionPlan,
  buildEcdsaSessionIdentity,
  buildEcdsaSigningKeyContextFromRecord,
  buildPasskeyEcdsaProvisionSecretSource,
  type EcdsaSessionProvisionPlan,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import {
  ensureWarmEcdsaCapabilityReady,
  getPrimaryAndSecondaryEcdsaCapabilities,
  normalizeParticipantIds,
  toOptionalNonEmptyString,
  tryReuseReadyWarmEcdsaBootstrap,
} from '@/core/signingEngine/useCases/provisionEcdsaSession';
import {
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  buildEvmFamilyEcdsaSessionLanePolicy,
  resolveThresholdEcdsaKeyIdFromRecord,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { provisionWarmEd25519Capability } from '@/core/signingEngine/session/passkey/ed25519Provisioner';
import {
  applyWarmSessionEcdsaPostSignPolicy,
  assertWarmSessionEcdsaOperationAllowed,
} from '@/core/signingEngine/session/operationState/warmSessionPolicyAdapter';
import { createWarmSessionStatusReader as createCoreWarmSessionStatusReader } from '@/core/signingEngine/session/warmCapabilities/statusReader';
import type { ResolveExactEcdsaRecordResult } from '@/core/signingEngine/session/warmCapabilities/statusReader';
import { claimWarmSessionPrfFirst } from '@/core/signingEngine/session/passkey/prfClaim';
import { ensureEcdsaPrfSealPersisted } from '@/core/signingEngine/session/passkey/runtime';
import type {
  EnsureWarmEcdsaCapabilityReadyResult,
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '@/core/signingEngine/session/warmCapabilities/types';
import type { SensitiveOperationPolicy } from '@shared/utils';
import { ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { testEcdsaChainTarget } from './ecdsaChainTarget.fixtures';
import type { WarmSessionTransitionEvent } from '@/core/signingEngine/session/warmCapabilities/transitions';

function requirePasskeyCredentialIdForFixture(record: ThresholdEcdsaSessionRecord): string {
  const authMethod = record.ecdsaRoleLocalReadyRecord.authMethod;
  switch (authMethod.kind) {
    case 'passkey':
      return authMethod.credentialIdB64u;
    case 'email_otp':
      throw new Error('test passkey reconnect fixture requires passkey ECDSA auth material');
    default:
      return assertNever(authMethod);
  }
}

function assertNever(value: never): never {
  throw new Error(`Unexpected fixture branch: ${String(value)}`);
}

function exactEcdsaRecordOrNull(
  result: ResolveExactEcdsaRecordResult,
): ThresholdEcdsaSessionRecord | null {
  switch (result.kind) {
    case 'found':
      return result.record;
    case 'not_found':
      return null;
    case 'duplicate_records':
      throw new Error('duplicate exact ECDSA records in test fixture');
  }
  result satisfies never;
  throw new Error('unsupported exact ECDSA record result in test fixture');
}

function resolveFixtureExactEcdsaRecord(args: {
  statusReader: ReturnType<typeof createCoreWarmSessionStatusReader>;
  record: ThresholdEcdsaSessionRecord | null | undefined;
  source?: ThresholdEcdsaSessionStoreSource;
}): ThresholdEcdsaSessionRecord | null {
  if (!args.record) return null;
  return (
    exactEcdsaRecordOrNull(
      args.statusReader.resolveExactEcdsaRecord({
        lane: toExactEcdsaSigningLaneIdentity(args.record),
        ...(args.source ? { source: args.source } : {}),
      }),
    ) || args.record
  );
}

function chooseFixtureEcdsaRecordCandidate(args: {
  primary: ThresholdEcdsaSessionRecord | null | undefined;
  secondary: ThresholdEcdsaSessionRecord | null | undefined;
  thresholdSessionId: string;
}): ThresholdEcdsaSessionRecord | null {
  const candidates = [args.primary, args.secondary].filter(
    (record): record is ThresholdEcdsaSessionRecord => Boolean(record),
  );
  if (!args.thresholdSessionId) return candidates[0] || null;
  return (
    candidates.find(
      (record) => String(record.thresholdSessionId || '').trim() === args.thresholdSessionId,
    ) || null
  );
}

function requireFixtureEcdsaRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
  message: string,
): ThresholdEcdsaSessionRecord {
  if (record) return record;
  throw new Error(message);
}

type WarmSessionTestServicesDeps = {
  touchConfirm?: Partial<
    Pick<
      WarmSessionStatusReader &
        WarmSessionStatusBatchReader &
        WarmSessionMaterialClaimer &
        WarmSessionSealPersister &
        VolatileWarmSessionMaterialClearer,
      | 'getWarmSessionStatus'
      | 'getWarmSessionStatuses'
      | 'claimWarmSessionMaterial'
      | 'sealAndPersistWarmSessionMaterial'
      | 'clearVolatileWarmSessionMaterial'
    >
  >;
  consumeSingleUseEmailOtpEcdsaLane?: (
    command: ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  ) => ConsumeSingleUseEmailOtpEcdsaLaneResult;
  clearThresholdEcdsaSigningArtifactsForLane?: (args: {
    record: ThresholdEcdsaSessionRecord;
  }) => void | Promise<void>;
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  signingSessionSeal?: {
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  listThresholdEcdsaRecordsForWalletTarget?: (args: {
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => Array<{ source: ThresholdEcdsaSessionStoreSource; record: ThresholdEcdsaSessionRecord }>;
  provisionThresholdEcdsaSession?: (
    args: EcdsaBootstrapRequest | ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  provisionThresholdEd25519Session?: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

function resolveTestEcdsaBootstrapArgs(args: {
  request: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  };
  warmSession: Awaited<
    ReturnType<ReturnType<typeof createWarmSessionCapabilityReader>['getWarmSession']>
  >;
}): EcdsaBootstrapRequest {
  const chainTarget = testEcdsaChainTarget(args.request.chain);
  const { primary, secondary } = getPrimaryAndSecondaryEcdsaCapabilities({
    warmSession: args.warmSession,
    chainTarget,
  });
  const reusableWarmCapability = primary.prfClaim?.state === 'warm' ? primary : null;
  const preferredMetadataCapability = primary.record
    ? primary
    : secondary.record
      ? secondary
      : null;
  const participantIds =
    normalizeParticipantIds(primary.record?.participantIds) ||
    normalizeParticipantIds(secondary.record?.participantIds);
  const ecdsaThresholdKeyId = (() => {
    const candidate = primary.record || secondary.record;
    if (!candidate) return undefined;
    try {
      return String(
        resolveThresholdEcdsaKeyIdFromRecord({
          record: candidate,
        }),
      ).trim();
    } catch {
      return undefined;
    }
  })();
  const targetBaseArgs = {
    walletId: args.request.nearAccountId,
    chainTarget,
    ...(args.request.source ? { source: args.request.source } : {}),
    ...(preferredMetadataCapability?.record?.relayerUrl
      ? { relayerUrl: preferredMetadataCapability.record.relayerUrl }
      : {}),
    ...(ecdsaThresholdKeyId && participantIds
      ? {
          keyIntent: {
            kind: 'existing_ecdsa_key' as const,
            ecdsaThresholdKeyId,
            participantIds,
          },
        }
      : {}),
  };
  const reuseBaseArgs = {
    walletId: targetBaseArgs.walletId,
    chainTarget: targetBaseArgs.chainTarget,
    kind: 'reuse_warm_ecdsa_bootstrap' as const,
    ...(targetBaseArgs.source ? { source: targetBaseArgs.source } : {}),
    ...(targetBaseArgs.relayerUrl ? { relayerUrl: targetBaseArgs.relayerUrl } : {}),
    ...(targetBaseArgs.keyIntent ? { keyIntent: targetBaseArgs.keyIntent } : {}),
  };

  const sessionId = toOptionalNonEmptyString(reusableWarmCapability?.record?.thresholdSessionId);
  const signingGrantId = toOptionalNonEmptyString(reusableWarmCapability?.record?.signingGrantId);
  const walletSessionJwt = toOptionalNonEmptyString(reusableWarmCapability?.auth?.walletSessionJwt);

  if (sessionId && signingGrantId && walletSessionJwt) {
    if (!reusableWarmCapability?.record) {
      throw new Error('test threshold-session reconnect requires a reusable ECDSA record');
    }
    const readModel = thresholdEcdsaSessionRecordReadModel(reusableWarmCapability.record);
    const passkeyCredentialIdB64u = requirePasskeyCredentialIdForFixture(
      reusableWarmCapability.record,
    );
    return {
      kind: 'wallet_session_reconnect_ecdsa_bootstrap',
      source: targetBaseArgs.source,
      relayerUrl: targetBaseArgs.relayerUrl,
      keyHandle: reusableWarmCapability.record.keyHandle,
      key: readModel.key,
      lanePolicy: buildEvmFamilyEcdsaSessionLanePolicy({
        chainTarget,
        thresholdSessionId: sessionId,
        signingGrantId,
        thresholdSessionKind: 'jwt',
        ttlMs: Math.max(1, readModel.lane.expiresAtMs - Date.now()),
        remainingUses: readModel.lane.remainingUses,
      }),
      routeAuth: {
        kind: 'wallet_session',
        jwt: walletSessionJwt,
      },
      passkeyPrfFirstB64u: 'reconnect-client-root-share',
      passkeyCredentialIdB64u,
    };
  }
  return reuseBaseArgs;
}

export function createWarmSessionTestServices(deps: WarmSessionTestServicesDeps = {}) {
  const reconnectInFlightByCapability = new Map<
    string,
    Promise<EnsureWarmEcdsaCapabilityReadyResult>
  >();
  const sealPersistInFlightBySessionId = new Map<string, Promise<void>>();
  const getEmailOtpWarmSessionStatus =
    deps.getEmailOtpWarmSessionStatus ||
    (async (sessionId: string): Promise<WarmSessionStatusResult> => {
      if (typeof deps.touchConfirm?.getWarmSessionStatus === 'function') {
        return await deps.touchConfirm.getWarmSessionStatus({ sessionId });
      }
      return {
        ok: false,
        code: 'not_found',
        message: 'Email OTP warm-session status reader is unavailable',
      };
    });
  const statusReader = createCoreWarmSessionStatusReader({
    touchConfirm: deps.touchConfirm,
    getEmailOtpWarmSessionStatus,
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
  });
  const clearEcdsaEphemeralMaterial = async (args: {
    record: ThresholdEcdsaSessionRecord;
    thresholdSessionId?: string;
  }): Promise<void> => {
    const thresholdSessionId = parseVolatileWarmSessionId(args.thresholdSessionId);
    if (typeof deps.clearThresholdEcdsaSigningArtifactsForLane === 'function') {
      await Promise.resolve(
        deps.clearThresholdEcdsaSigningArtifactsForLane({
          record: args.record,
        }),
      ).catch(() => undefined);
    }
    if (
      thresholdSessionId &&
      typeof deps.touchConfirm?.clearVolatileWarmSessionMaterial === 'function'
    ) {
      await deps.touchConfirm
        .clearVolatileWarmSessionMaterial(
          createClearVolatileWarmSessionMaterialCommand(thresholdSessionId),
        )
        .catch(() => undefined);
    }
  };
  const capabilityReader = createWarmSessionCapabilityReader({
    touchConfirm: deps.touchConfirm ?? null,
    signingSessionSeal:
      deps.signingSessionSeal?.keyVersion && deps.signingSessionSeal.shamirPrimeB64u
        ? {
            signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
              deps.signingSessionSeal.keyVersion,
            ),
            shamirPrimeB64u: deps.signingSessionSeal.shamirPrimeB64u,
          }
        : null,
    getEmailOtpWarmSessionStatus,
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
  });
  const getWarmSession = (walletId: string | WalletId) =>
    capabilityReader.getWarmSession(toWalletId(walletId));
  const claimWarmSessionPrfFirstMaterial = (args: {
    thresholdSessionId: string;
    errorContext: string;
    uses?: number;
  }) =>
    claimWarmSessionPrfFirst({
      touchConfirm: deps.touchConfirm,
      thresholdSessionId: args.thresholdSessionId,
      errorContext: args.errorContext,
      uses: args.uses,
    });
  const provisionEcdsaCapability = async (args: EcdsaBootstrapRequest) => {
    const provisionThresholdEcdsaSession =
      deps.provisionThresholdEcdsaSession ||
      (async () => {
        throw new Error('provisionThresholdEcdsaSession test dependency is required');
      });
    return await provisionThresholdEcdsaSession(args);
  };

  return {
    getWarmSession,
    resolveEd25519RecordByThresholdSessionId:
      capabilityReader.resolveEd25519RecordByThresholdSessionId,
    resolveEcdsaRecordByThresholdSessionId: capabilityReader.resolveEcdsaRecordByThresholdSessionId,
    resolveEd25519AuthByThresholdSessionId: capabilityReader.resolveEd25519AuthByThresholdSessionId,
    resolveEcdsaAuthByThresholdSessionId: capabilityReader.resolveEcdsaAuthByThresholdSessionId,
    resolveEmailOtpEd25519SigningSessionAuthority:
      capabilityReader.resolveEmailOtpEd25519SigningSessionAuthority,
    resolveEmailOtpEcdsaSigningSessionAuthority:
      capabilityReader.resolveEmailOtpEcdsaSigningSessionAuthority,
    getEd25519CapabilityByThresholdSessionId:
      capabilityReader.getEd25519CapabilityByThresholdSessionId,
    getEcdsaCapabilityByThresholdSessionId: capabilityReader.getEcdsaCapabilityByThresholdSessionId,
    getEcdsaCapabilityForLane: capabilityReader.getEcdsaCapabilityForLane,
    resolveEcdsaSealTransportByThresholdSessionId:
      capabilityReader.resolveEcdsaSealTransportByThresholdSessionId,
    provisionEd25519Capability: (args: ProvisionWarmEd25519CapabilityArgs) =>
      provisionWarmEd25519Capability(
        {
          getWarmSession,
          provisionThresholdEd25519Session: deps.provisionThresholdEd25519Session,
          onTransition: deps.onTransition,
        },
        args,
      ),
    resolveEcdsaBootstrapRequest: async (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      source?: ThresholdEcdsaSessionStoreSource;
    }) =>
      resolveTestEcdsaBootstrapArgs({
        request: args,
        warmSession: await getWarmSession(args.nearAccountId),
      }),
    provisionEcdsaCapability,
    tryReuseReadyEcdsaBootstrap: (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      source?: ThresholdEcdsaSessionStoreSource;
    }) =>
      tryReuseReadyWarmEcdsaBootstrap(
        {
          getWarmSession,
          listThresholdEcdsaRecordsForWalletTarget:
            deps.listThresholdEcdsaRecordsForWalletTarget || (() => []),
        },
        {
          walletId: toWalletId(args.nearAccountId),
          ...(args.source ? { source: args.source } : {}),
          chainTarget: testEcdsaChainTarget(args.chain),
        },
      ),
    ensureEcdsaCapabilityReady: (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      source?: ThresholdEcdsaSessionStoreSource;
      usesNeeded?: number;
      requiredSignatureUses?: number;
      thresholdSessionId?: string;
      signingGrantId?: string;
      sessionBudgetUses?: number;
      passkeyPrfFirstB64u?: string;
      runtimeScopeBootstrap?: { projectEnvironmentId: string; publishableKey: string };
      keyRef?: ThresholdEcdsaSecp256k1KeyRef;
      plan?: EcdsaSessionProvisionPlan;
    }) =>
      (async () => {
        const chainTarget = testEcdsaChainTarget(args.chain);
        const walletId = toWalletId(args.nearAccountId);
        const exactThresholdSessionId = String(args.thresholdSessionId || '');
        const warmSession = await getWarmSession(args.nearAccountId);
        const { primary, secondary } = getPrimaryAndSecondaryEcdsaCapabilities({
          warmSession,
          chainTarget,
        });
        const candidateRecord = resolveFixtureExactEcdsaRecord({
          statusReader,
          record: chooseFixtureEcdsaRecordCandidate({
            primary: primary.record,
            secondary: secondary.record,
            thresholdSessionId: exactThresholdSessionId,
          }),
          ...(args.source ? { source: args.source } : {}),
        });
        const record =
          candidateRecord ||
          (args.keyRef
            ? resolveFixtureExactEcdsaRecord({
                statusReader,
                record: chooseFixtureEcdsaRecordCandidate({
                  primary: primary.record,
                  secondary: secondary.record,
                  thresholdSessionId: String(args.keyRef.thresholdSessionId || ''),
                }),
                ...(args.source ? { source: args.source } : {}),
              })
            : null);
        if (!record) {
          throw new Error('test ECDSA provision requires session record material');
        }
        const resolvedPlan =
          args.plan ||
          (async () => {
            const identity = buildEcdsaSessionIdentity({
              thresholdSessionId: exactThresholdSessionId || record.thresholdSessionId,
              signingGrantId: String(args.signingGrantId || '') || record.signingGrantId,
            });
            const signingKeyContext = buildEcdsaSigningKeyContextFromRecord(record);
            const sessionBudgetUses = Number(args.sessionBudgetUses || 1);
            if (args.passkeyPrfFirstB64u) {
              return buildEcdsaSessionProvisionPlan({
                kind: 'passkey_ecdsa_session_provision',
                key: buildEvmFamilyEcdsaKeyIdentityFromRecord({
                  record,
                }),
                chainTarget,
                sessionIdentity: identity,
                signingKeyContext,
                sessionBudgetUses,
                requestId: 'test-request-id',
                sessionKind: 'jwt',
                provisionSecretSource: buildPasskeyEcdsaProvisionSecretSource({
                  passkeyPrfFirstB64u: String(args.passkeyPrfFirstB64u || ''),
                  webauthnAuthentication: {
                    id: 'test-credential',
                    rawId: 'test-raw-id',
                    type: 'public-key',
                    authenticatorAttachment: 'platform',
                    response: {
                      clientDataJSON: 'test-client-data',
                      authenticatorData: 'test-authenticator-data',
                      signature: 'test-signature',
                      userHandle: undefined,
                    },
                    clientExtensionResults: {
                      prf: {
                        results: {
                          first: String(args.passkeyPrfFirstB64u || ''),
                          second: undefined,
                        },
                      },
                    },
                  },
                }),
                activationMaterial: { kind: 'session_record' },
                ...(record.runtimePolicyScope
                  ? { runtimePolicyScope: record.runtimePolicyScope }
                  : {}),
              });
            }
            return buildEcdsaSessionProvisionPlan({
              kind: 'ecdsa_session_reconnect',
              chainTarget,
              sessionIdentity: identity,
              sessionBudgetUses,
              reconnectMaterial: buildEcdsaReconnectMaterial({
                record,
              }),
            });
          })();

        const plan = await resolvedPlan;
        const readinessDeps = {
          getWarmSession,
          listThresholdEcdsaRecordsForWalletTarget:
            deps.listThresholdEcdsaRecordsForWalletTarget || (() => []),
          canProvisionEcdsaCapability: typeof deps.provisionThresholdEcdsaSession === 'function',
          provisionThresholdEcdsaSession:
            deps.provisionThresholdEcdsaSession ||
            (async () => {
              throw new Error('provisionThresholdEcdsaSession test dependency is required');
            }),
          touchConfirm: deps.touchConfirm || {},
          resolveExactEcdsaRecord: (
            recordArgs: Parameters<typeof statusReader.resolveExactEcdsaRecord>[0],
          ) => statusReader.resolveExactEcdsaRecord(recordArgs),
          readEcdsaCapabilityForLane: capabilityReader.getEcdsaCapabilityForLane,
          reconnectInFlightByCapability,
          onTransition: deps.onTransition,
        };
        const readinessArgsBase = {
          walletId,
          source: args.source || record.source,
          usesNeeded: args.usesNeeded ?? args.requiredSignatureUses,
          runtimeScopeBootstrap: args.runtimeScopeBootstrap,
          chainTarget,
          sessionBudgetUses: Number(args.sessionBudgetUses || 1),
        };
        switch (plan.kind) {
          case 'wallet_session_ecdsa_reconnect':
          case 'passkey_ecdsa_session_provision':
            return await ensureWarmEcdsaCapabilityReady(readinessDeps, {
              ...readinessArgsBase,
              record,
              plan,
            });
          case 'email_otp_ecdsa_session_provision':
            return await ensureWarmEcdsaCapabilityReady(readinessDeps, {
              ...readinessArgsBase,
              record,
              plan,
            });
        }
        plan satisfies never;
        throw new Error('unsupported test ECDSA provision plan');
      })(),
    assertEcdsaSigningSessionReady: (args: {
      walletId: AccountId | string;
      chainTarget: ThresholdEcdsaChainTarget;
      thresholdSessionId: unknown;
      usesNeeded?: number;
    }) =>
      statusReader.assertEcdsaSigningSessionReady({
        walletId: toWalletId(args.walletId),
        chainTarget: args.chainTarget,
        thresholdSessionId: args.thresholdSessionId,
        usesNeeded: args.usesNeeded,
      }),
    getEd25519SigningSessionStatus: statusReader.getEd25519SigningSessionStatus,
    getEd25519SigningSessionStatusForSession: statusReader.getEd25519SigningSessionStatusForSession,
    getEcdsaSigningSessionStatus: (args: {
      walletId: AccountId | string;
      chainTarget: ThresholdEcdsaChainTarget;
      thresholdSessionId: string;
    }) =>
      statusReader.getEcdsaSigningSessionStatus({
        walletId: toWalletId(args.walletId),
        chainTarget: args.chainTarget,
        thresholdSessionId: args.thresholdSessionId,
      }),
    listEcdsaSigningSessionStatuses: (args: {
      walletId: AccountId | string;
      chainTarget: ThresholdEcdsaChainTarget;
    }) =>
      statusReader.listEcdsaSigningSessionStatuses({
        walletId: toWalletId(args.walletId),
        chainTarget: args.chainTarget,
      }),
    claimWarmSessionPrfFirstMaterial,
    ensureEcdsaPrfSealPersistedByThresholdSessionId: (args: {
      chain?: ThresholdEcdsaActivationChain;
      thresholdSessionId: string;
      required?: boolean;
      errorContext?: string;
    }) =>
      ensureEcdsaPrfSealPersisted({
        touchConfirm: deps.touchConfirm,
        lane: toExactEcdsaSigningLaneIdentity(
          requireFixtureEcdsaRecord(
            resolveFixtureExactEcdsaRecord({
              statusReader,
              record: chooseFixtureEcdsaRecordCandidate({
                primary: capabilityReader.resolveEcdsaRecordByThresholdSessionId(
                  args.thresholdSessionId,
                ),
                secondary: null,
                thresholdSessionId: args.thresholdSessionId,
              }),
            }),
            'test ECDSA seal persistence requires exact session record',
          ),
        ),
        required: args.required,
        errorContext: args.errorContext,
        sealPersistInFlightBySessionId,
        resolveSealTransport: capabilityReader.resolveEcdsaSealTransportByThresholdSessionId,
      }),
    applyEcdsaPostSignPolicy: (args: {
      walletId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId?: string;
      source?: ThresholdEcdsaSessionStoreSource;
      selectedRecord: ThresholdEcdsaSessionRecord;
    }) =>
      applyWarmSessionEcdsaPostSignPolicy(
        {
          getWarmSession,
          resolveExactEcdsaRecord: (recordArgs) => statusReader.resolveExactEcdsaRecord(recordArgs),
          consumeSingleUseEmailOtpEcdsaLane: deps.consumeSingleUseEmailOtpEcdsaLane,
          clearEcdsaEphemeralMaterial,
        },
        {
          lane: toExactEcdsaSigningLaneIdentity(args.selectedRecord),
          selectedRecord: args.selectedRecord,
        },
      ),
    assertEcdsaOperationAllowed: (args: {
      walletId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId?: string;
      operationLabel: string;
      source?: ThresholdEcdsaSessionStoreSource;
      sensitivePolicy?: SensitiveOperationPolicy;
    }) =>
      assertWarmSessionEcdsaOperationAllowed(
        {
          getWarmSession,
          resolveExactEcdsaRecord: (recordArgs) => statusReader.resolveExactEcdsaRecord(recordArgs),
        },
        {
          lane: toExactEcdsaSigningLaneIdentity(
            requireFixtureEcdsaRecord(
              capabilityReader.resolveEcdsaRecordByThresholdSessionId(
                args.thresholdSessionId || '',
              ),
              'test ECDSA operation allowed requires exact session record',
            ),
          ),
          operationLabel: args.operationLabel,
          source: args.source || 'login',
          sensitivePolicy: args.sensitivePolicy,
        },
      ),
  };
}
