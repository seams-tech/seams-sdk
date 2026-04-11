import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/tatchi';
import type { SigningAuthMode } from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import type { WarmSessionStatusResult } from '../touchConfirm';
import type {
  WarmSessionSealPersister,
  WarmSessionMaterialClaimer,
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
} from '../touchConfirm';
import type {
  ThresholdEd25519SessionStoreSource,
  ThresholdEcdsaSessionStoreSource,
  ThresholdSessionSealTransportAuthMaterial,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../orchestration/thresholdActivation';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from '../api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence';
import type { ThresholdRuntimeSnapshotScope } from '../threshold/session/sessionPolicy';
import {
  readWarmSessionCapabilityRecordsForAccount,
  readWarmSessionEd25519RecordByThresholdSessionId,
  readWarmSessionEcdsaRecordByThresholdSessionId,
} from './warmSessionStore';
import type { Ed25519SessionKind } from '../threshold/session/ed25519SessionTypes';
import {
  assertWarmSessionEnvelopeInvariant,
} from './warmSessionTypes';
import type {
  WarmSessionEd25519AuthMaterial,
  WarmSessionEcdsaAuthMaterial,
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519CapabilityState,
  WarmSessionEnvelope,
} from './warmSessionTypes';
import {
  buildReusableEcdsaBootstrapResult,
  getEcdsaCapabilityCandidates,
  getMatchingReadyEcdsaCapability,
  getPrimaryAndSecondaryEcdsaCapabilities,
  normalizeParticipantIds,
  toOptionalNonEmptyString,
  type WarmSessionEcdsaCapabilityRef,
} from './warmSessionEcdsaProvisioning';
import {
  deriveEcdsaCapabilityState,
  deriveEd25519CapabilityState,
  formatMissingWarmPrfMaterialError,
  formatWarmSessionClaimUnavailableError,
  reportWarmSessionAvailabilityFailure,
  readWarmSessionClaim,
  readWarmSessionClaims,
  resolveEcdsaAuthMaterial,
  resolveEcdsaSealTransport,
  resolveEd25519AuthMaterial,
  toSigningSessionStatus,
} from './warmSessionReadModel';
import {
  emitWarmSessionTransition,
  summarizeWarmSessionTransition,
  type WarmSessionTransitionEvent,
} from './warmSessionTransitions';
import {
  claimWarmSessionPrfFirst,
  ensureEcdsaPrfSealPersisted,
} from './warmSessionRuntime';
export type {
  WarmSessionTransitionCapabilitySnapshot,
  WarmSessionTransitionEvent,
  WarmSessionTransitionSnapshot,
} from './warmSessionTransitions';
export type { WarmSessionEcdsaCapabilityRef } from './warmSessionEcdsaProvisioning';

export type WarmSessionManagerDeps = {
  touchConfirm?: Partial<
    Pick<
      WarmSessionStatusReader &
        WarmSessionStatusBatchReader &
        WarmSessionMaterialClaimer &
        WarmSessionSealPersister,
      | 'getWarmSessionStatus'
      | 'getWarmSessionStatuses'
      | 'claimWarmSessionMaterial'
      | 'sealAndPersistWarmSessionMaterial'
    >
  >;
  signingSessionSeal?: {
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
  getThresholdEcdsaKeyRefForSigning?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => ThresholdEcdsaSecp256k1KeyRef;
  provisionThresholdEcdsaSession?: (args: ProvisionWarmEcdsaCapabilityArgs) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  bootstrapThresholdEcdsaSession?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  provisionThresholdEd25519Session?: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

export type ProvisionWarmEd25519CapabilityArgs = {
  nearAccountId: AccountId | string;
  relayerKeyId: string;
  runtimeSnapshotScope?: ThresholdRuntimeSnapshotScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  participantIds?: number[];
  sessionKind?: Ed25519SessionKind;
  relayerUrl?: string;
  ttlMs?: number;
  remainingUses?: number;
  sessionId?: string;
  source?: ThresholdEd25519SessionStoreSource;
  beforeProvision?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

export type ProvisionWarmEd25519CapabilityResult = {
  ok: boolean;
  sessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  jwt?: string;
  ecdsaHssClientRootShare32B64u?: string;
  code?: string;
  message?: string;
};

export type EnsureWarmEcdsaCapabilityReadyArgs = {
  nearAccountId: AccountId | string;
  chain: ThresholdEcdsaActivationChain;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
  usesNeeded?: number;
  beforeReconnect?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

export type EnsureWarmEcdsaCapabilityReadyResult = {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  warmSession: WarmSessionEnvelope;
  capability: WarmSessionEcdsaCapabilityState;
  reconnected: boolean;
};

export type ResolveWarmEcdsaBootstrapRequestArgs = {
  nearAccountId: AccountId | string;
  chain: ThresholdEcdsaActivationChain;
  relayerUrl?: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  authorizationJwt?: string;
  clientRootShare32B64u?: string;
};

export type WarmEcdsaBootstrapRequest = {
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  relayerUrl?: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  authorizationJwt?: string;
  clientRootShare32B64u?: string;
};

export type ProvisionWarmEcdsaCapabilityArgs = ResolveWarmEcdsaBootstrapRequestArgs & {
  source?: ThresholdEcdsaSessionStoreSource;
  ttlMs?: number;
  remainingUses?: number;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  beforeProvision?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

export type ClaimWarmSessionPrfArgs = {
  thresholdSessionId: string;
  errorContext: string;
  uses?: number;
};

export type WarmSessionEd25519SigningAuthPlan = {
  sessionId: string;
  signingAuthMode: SigningAuthMode;
  warmSessionReady: boolean;
};

export const THRESHOLD_SESSION_MISSING_ERROR =
  '[chains] Missing threshold signingSessionId; reconnect threshold session before signing';
export const THRESHOLD_SESSION_EXHAUSTED_ERROR =
  '[chains] threshold signingSession is exhausted; reconnect threshold session before signing';
export const THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR =
  '[chains] threshold signingSession auth is unavailable; reconnect threshold session before signing';
export const THRESHOLD_SESSION_STATUS_UNAVAILABLE_ERROR =
  '[chains] threshold signingSession status is unavailable; retry after refreshing the signer runtime';

export function formatThresholdSigningSessionStatusError(code: string): string {
  return `[chains] threshold signingSession is ${code}; reconnect threshold session before signing`;
}

export function formatThresholdSigningSessionAvailabilityError(code?: string): string {
  const suffix = typeof code === 'string' && code.trim() ? ` (${code.trim()})` : '';
  return `${THRESHOLD_SESSION_STATUS_UNAVAILABLE_ERROR}${suffix}`;
}

export function requireThresholdSigningSessionId(sessionIdRaw: unknown): string {
  const sessionId = String(sessionIdRaw || '').trim();
  if (!sessionId) {
    throw new Error(THRESHOLD_SESSION_MISSING_ERROR);
  }
  return sessionId;
}

function normalizeUsesNeeded(usesNeededRaw: unknown): number {
  const usesNeeded = Math.floor(Number(usesNeededRaw) || 0);
  return usesNeeded > 0 ? usesNeeded : 1;
}

function assertPersistedWarmSessionRecord(args: {
  label: 'Ed25519' | 'ECDSA';
  nearAccountId: AccountId;
  expectedSessionId: string;
  persistedSessionIdRaw: unknown;
}): void {
  const persistedSessionId = String(args.persistedSessionIdRaw || '').trim();
  if (persistedSessionId === args.expectedSessionId) {
    return;
  }
  throw new Error(
    `[WarmSessionManager] provisioned ${args.label} capability was not persisted for ${args.nearAccountId} (expected sessionId=${args.expectedSessionId}, found=${persistedSessionId || 'missing'})`,
  );
}

export type WarmSessionManager = {
  getWarmSession: (nearAccountId: AccountId | string) => Promise<WarmSessionEnvelope>;
  resolveEd25519RecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => WarmSessionEd25519CapabilityState['record'];
  resolveEcdsaRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => WarmSessionEcdsaCapabilityState['record'];
  resolveEd25519AuthByThresholdSessionId: (
    thresholdSessionId: string,
  ) => WarmSessionEd25519AuthMaterial | null;
  resolveEcdsaAuthByThresholdSessionId: (
    thresholdSessionId: string,
  ) => WarmSessionEcdsaAuthMaterial | null;
  getEd25519CapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEd25519CapabilityState | null>;
  provisionEd25519Capability: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  resolveEcdsaBootstrapRequest: (
    args: ResolveWarmEcdsaBootstrapRequestArgs,
  ) => Promise<WarmEcdsaBootstrapRequest>;
  provisionEcdsaCapability: (
    args: ProvisionWarmEcdsaCapabilityArgs,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  tryReuseReadyEcdsaBootstrap: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => Promise<ThresholdEcdsaSessionBootstrapResult | null>;
  ensureEcdsaCapabilityReady: (
    args: EnsureWarmEcdsaCapabilityReadyArgs,
  ) => Promise<EnsureWarmEcdsaCapabilityReadyResult>;
  assertEcdsaSigningSessionReady: (args: WarmSessionEcdsaCapabilityRef & {
    thresholdSessionId: unknown;
    usesNeeded?: number;
  }) => Promise<Extract<WarmSessionStatusResult, { ok: true }>>;
  resolveEd25519SigningAuthPlan: (args: {
    nearAccountId: AccountId | string;
    usesNeeded?: number;
    operationLabel?: string;
  }) => Promise<WarmSessionEd25519SigningAuthPlan>;
  getEd25519SigningSessionStatus: (
    nearAccountId: AccountId | string,
  ) => Promise<SigningSessionStatus | null>;
  getEcdsaSigningSessionStatus: (
    args: WarmSessionEcdsaCapabilityRef,
  ) => Promise<SigningSessionStatus | null>;
  claimPrfFirstByThresholdSessionId: (args: ClaimWarmSessionPrfArgs) => Promise<string>;
  ensureEcdsaPrfSealPersistedByThresholdSessionId: (args: {
    chain: ThresholdEcdsaActivationChain;
    thresholdSessionId: string;
    required?: boolean;
    errorContext?: string;
  }) => Promise<void>;
  resolveEcdsaSealTransportByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdSessionSealTransportAuthMaterial | null;
};

export function createWarmSessionManager(deps: WarmSessionManagerDeps = {}): WarmSessionManager {
  const reconnectInFlightByCapability = new Map<
    string,
    Promise<EnsureWarmEcdsaCapabilityReadyResult>
  >();
  const sealPersistInFlightBySessionId = new Map<string, Promise<void>>();

  function buildEcdsaCapabilityInflightKey(args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    usesNeeded?: number;
    keyRef: ThresholdEcdsaSecp256k1KeyRef | null;
  }): string {
    const keyId = String(args.keyRef?.ecdsaThresholdKeyId || '').trim() || 'auto';
    const sessionId = String(args.keyRef?.thresholdSessionId || '').trim() || 'auto';
    return [
      String(args.nearAccountId),
      args.chain,
      String(normalizeUsesNeeded(args.usesNeeded)),
      keyId,
      sessionId,
    ].join('::');
  }

  return {
    async getWarmSession(nearAccountId: AccountId | string): Promise<WarmSessionEnvelope> {
      const accountId = toAccountId(nearAccountId);
      const records = readWarmSessionCapabilityRecordsForAccount(accountId);

      const ed25519Auth = resolveEd25519AuthMaterial(records.ed25519);
      const evmAuth = resolveEcdsaAuthMaterial(records.ecdsa.evm);
      const tempoAuth = resolveEcdsaAuthMaterial(records.ecdsa.tempo);

      const claimsBySessionId = await readWarmSessionClaims({
        touchConfirm: deps.touchConfirm,
        sessionIds: [
          records.ed25519?.thresholdSessionId || '',
          records.ecdsa.evm?.thresholdSessionId || '',
          records.ecdsa.tempo?.thresholdSessionId || '',
        ],
      });
      const ed25519Claim =
        claimsBySessionId.get(String(records.ed25519?.thresholdSessionId || '').trim()) || null;
      const evmClaim =
        claimsBySessionId.get(String(records.ecdsa.evm?.thresholdSessionId || '').trim()) || null;
      const tempoClaim =
        claimsBySessionId.get(String(records.ecdsa.tempo?.thresholdSessionId || '').trim()) || null;

      return assertWarmSessionEnvelopeInvariant({
        accountId,
        capabilities: {
          ed25519: {
            capability: 'ed25519',
            record: records.ed25519,
            auth: ed25519Auth,
            prfClaim: ed25519Claim,
            state: deriveEd25519CapabilityState({
              record: records.ed25519,
              auth: ed25519Auth,
              prfClaim: ed25519Claim,
            }),
          },
          ecdsa: {
            evm: {
              capability: 'ecdsa',
              chain: 'evm',
              record: records.ecdsa.evm,
              auth: evmAuth,
              prfClaim: evmClaim,
              state: deriveEcdsaCapabilityState({
                record: records.ecdsa.evm,
                auth: evmAuth,
                prfClaim: evmClaim,
              }),
            },
            tempo: {
              capability: 'ecdsa',
              chain: 'tempo',
              record: records.ecdsa.tempo,
              auth: tempoAuth,
              prfClaim: tempoClaim,
              state: deriveEcdsaCapabilityState({
                record: records.ecdsa.tempo,
                auth: tempoAuth,
                prfClaim: tempoClaim,
              }),
            },
          },
        },
        updatedAtMs: Date.now(),
      });
    },

    resolveEd25519RecordByThresholdSessionId(
      thresholdSessionId: string,
    ): WarmSessionEd25519CapabilityState['record'] {
      return readWarmSessionEd25519RecordByThresholdSessionId(thresholdSessionId);
    },

    resolveEcdsaRecordByThresholdSessionId(
      thresholdSessionId: string,
    ): WarmSessionEcdsaCapabilityState['record'] {
      return readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
    },

    resolveEd25519AuthByThresholdSessionId(
      thresholdSessionId: string,
    ): WarmSessionEd25519AuthMaterial | null {
      return resolveEd25519AuthMaterial(
        readWarmSessionEd25519RecordByThresholdSessionId(thresholdSessionId),
      );
    },

    resolveEcdsaAuthByThresholdSessionId(
      thresholdSessionId: string,
    ): WarmSessionEcdsaAuthMaterial | null {
      const record = readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
      return record ? resolveEcdsaAuthMaterial(record) : null;
    },

    async getEd25519CapabilityByThresholdSessionId(
      thresholdSessionId: string,
    ): Promise<WarmSessionEd25519CapabilityState | null> {
      const record = readWarmSessionEd25519RecordByThresholdSessionId(thresholdSessionId);
      if (!record) return null;
      const auth = resolveEd25519AuthMaterial(record);
      const prfClaim = await readWarmSessionClaim(deps.touchConfirm, record.thresholdSessionId);
      return {
        capability: 'ed25519',
        record,
        auth,
        prfClaim,
        state: deriveEd25519CapabilityState({
          record,
          auth,
          prfClaim,
        }),
      };
    },

    async provisionEd25519Capability(
      args: ProvisionWarmEd25519CapabilityArgs,
    ): Promise<ProvisionWarmEd25519CapabilityResult> {
      const nearAccountId = toAccountId(args.nearAccountId);
      if (typeof deps.provisionThresholdEd25519Session !== 'function') {
        throw new Error(
          '[WarmSessionManager] provisionThresholdEd25519Session is required to provision Ed25519 capability',
        );
      }
      const beforeWarmSession = await this.getWarmSession(nearAccountId);
      await args.beforeProvision?.();
      args.assertNotCancelled?.();
      const provisioned = await deps.provisionThresholdEd25519Session(args);
      args.assertNotCancelled?.();

      if (!provisioned.ok) {
        return provisioned;
      }

      const expectedSessionId = toOptionalNonEmptyString(provisioned.sessionId);
      if (!expectedSessionId) {
        throw new Error(
          `[WarmSessionManager] provisioned Ed25519 capability is missing sessionId for ${nearAccountId}`,
        );
      }

      const afterWarmSession = await this.getWarmSession(nearAccountId);
      assertPersistedWarmSessionRecord({
        label: 'Ed25519',
        nearAccountId,
        expectedSessionId,
        persistedSessionIdRaw: afterWarmSession.capabilities.ed25519.record?.thresholdSessionId,
      });
      emitWarmSessionTransition({
        onTransition: deps.onTransition,
        event: {
        type: 'ed25519_capability_provisioned',
        accountId: nearAccountId,
        thresholdSessionId: expectedSessionId,
        before: summarizeWarmSessionTransition(beforeWarmSession),
        after: summarizeWarmSessionTransition(afterWarmSession),
        },
      });
      return provisioned;
    },

    async resolveEcdsaBootstrapRequest(
      args: ResolveWarmEcdsaBootstrapRequestArgs,
    ): Promise<WarmEcdsaBootstrapRequest> {
      const nearAccountId = toAccountId(args.nearAccountId);
      const warmSession = await this.getWarmSession(nearAccountId);
      const capabilityCandidates = getEcdsaCapabilityCandidates({
        warmSession,
        chain: args.chain,
      });
      const { primary: primaryCapability, secondary: secondaryCapability } =
        getPrimaryAndSecondaryEcdsaCapabilities({
          warmSession,
          chain: args.chain,
        });
      const primaryWarmCapability =
        primaryCapability.prfClaim?.state === 'warm' ? primaryCapability : null;

      const explicitParticipantIds = normalizeParticipantIds(args.participantIds);
      const explicitRelayerUrl = toOptionalNonEmptyString(args.relayerUrl);
      const explicitAuthorizationJwt = toOptionalNonEmptyString(args.authorizationJwt);
      const explicitSessionId = toOptionalNonEmptyString(args.sessionId);
      const explicitThresholdKeyId = toOptionalNonEmptyString(args.ecdsaThresholdKeyId);
      const explicitClientRootShare32B64u = toOptionalNonEmptyString(args.clientRootShare32B64u);
      const preferredMetadataCapability = primaryCapability.record
        ? primaryCapability
        : secondaryCapability.record
          ? secondaryCapability
          : null;
      const preferredParticipantIds =
        normalizeParticipantIds(primaryCapability.record?.participantIds) ||
        normalizeParticipantIds(secondaryCapability.record?.participantIds);
      const preferredSessionKind =
        primaryCapability.record?.thresholdSessionKind ||
        secondaryCapability.record?.thresholdSessionKind ||
        'jwt';

      return {
        nearAccountId,
        chain: args.chain,
        ...(explicitRelayerUrl
          ? { relayerUrl: explicitRelayerUrl }
          : toOptionalNonEmptyString(preferredMetadataCapability?.record?.relayerUrl)
            ? {
                relayerUrl: String(
                  toOptionalNonEmptyString(preferredMetadataCapability?.record?.relayerUrl) || '',
                ).trim(),
              }
            : {}),
        ...(explicitThresholdKeyId
          ? { ecdsaThresholdKeyId: explicitThresholdKeyId }
          : toOptionalNonEmptyString(primaryCapability.record?.ecdsaThresholdKeyId)
            ? {
                ecdsaThresholdKeyId: String(
                  toOptionalNonEmptyString(primaryCapability.record?.ecdsaThresholdKeyId) || '',
                ).trim(),
              }
            : {}),
        ...(explicitParticipantIds
          ? { participantIds: explicitParticipantIds }
          : preferredParticipantIds
            ? {
                participantIds: preferredParticipantIds,
              }
            : {}),
        sessionKind: args.sessionKind || preferredSessionKind,
        ...(explicitSessionId
          ? { sessionId: explicitSessionId }
          : toOptionalNonEmptyString(primaryWarmCapability?.record?.thresholdSessionId)
            ? {
                sessionId: String(
                  toOptionalNonEmptyString(primaryWarmCapability?.record?.thresholdSessionId) || '',
                ).trim(),
              }
            : {}),
        ...(explicitAuthorizationJwt
          ? { authorizationJwt: explicitAuthorizationJwt }
          : toOptionalNonEmptyString(primaryWarmCapability?.auth?.thresholdSessionJwt)
            ? {
                authorizationJwt: String(
                  toOptionalNonEmptyString(primaryWarmCapability?.auth?.thresholdSessionJwt) || '',
                ).trim(),
              }
            : {}),
        ...(explicitClientRootShare32B64u
          ? { clientRootShare32B64u: explicitClientRootShare32B64u }
          : {}),
      };
    },

    async provisionEcdsaCapability(
      args: ProvisionWarmEcdsaCapabilityArgs,
    ): Promise<ThresholdEcdsaSessionBootstrapResult> {
      const nearAccountId = toAccountId(args.nearAccountId);
      const beforeWarmSession = await this.getWarmSession(nearAccountId);
      const normalizedAuthorizationJwt = toOptionalNonEmptyString(args.authorizationJwt);
      const normalizedClientRootShare32B64u = toOptionalNonEmptyString(args.clientRootShare32B64u);
      const normalizedSessionId = toOptionalNonEmptyString(args.sessionId);

      if (!normalizedAuthorizationJwt && !normalizedClientRootShare32B64u && !normalizedSessionId) {
        const reusableBootstrap = await this.tryReuseReadyEcdsaBootstrap({
          nearAccountId,
          chain: args.chain,
          source: args.source,
        });
        if (reusableBootstrap) {
          return reusableBootstrap;
        }
      }

      const resolvedBootstrapRequest = await this.resolveEcdsaBootstrapRequest({
        nearAccountId,
        chain: args.chain,
        relayerUrl: args.relayerUrl,
        ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
        participantIds: args.participantIds,
        sessionKind: args.sessionKind,
        sessionId: args.sessionId,
        authorizationJwt: args.authorizationJwt,
        clientRootShare32B64u: args.clientRootShare32B64u,
      });
      if (
        !resolvedBootstrapRequest.clientRootShare32B64u &&
        resolvedBootstrapRequest.authorizationJwt &&
        resolvedBootstrapRequest.sessionId
      ) {
        resolvedBootstrapRequest.clientRootShare32B64u =
          await this.claimPrfFirstByThresholdSessionId({
            thresholdSessionId: resolvedBootstrapRequest.sessionId,
            errorContext: 'threshold-ecdsa authorization bootstrap',
            uses: 1,
          });
      }

      await args.beforeProvision?.();
      args.assertNotCancelled?.();

      if (typeof deps.provisionThresholdEcdsaSession === 'function') {
        const provisioned = await deps.provisionThresholdEcdsaSession({
          ...args,
          ...resolvedBootstrapRequest,
        });
        args.assertNotCancelled?.();

        const expectedSessionId = toOptionalNonEmptyString(
          provisioned.thresholdEcdsaKeyRef?.thresholdSessionId,
        );
        if (!expectedSessionId) {
          throw new Error(
            `[WarmSessionManager] provisioned ECDSA capability is missing thresholdSessionId for ${nearAccountId}`,
          );
        }

        const afterWarmSession = await this.getWarmSession(nearAccountId);
        assertPersistedWarmSessionRecord({
          label: 'ECDSA',
          nearAccountId,
          expectedSessionId,
          persistedSessionIdRaw: afterWarmSession.capabilities.ecdsa[args.chain].record?.thresholdSessionId,
        });
        emitWarmSessionTransition({
          onTransition: deps.onTransition,
          event: {
          type: 'ecdsa_capability_provisioned',
          accountId: nearAccountId,
          chain: args.chain,
          thresholdSessionId: expectedSessionId,
          before: summarizeWarmSessionTransition(beforeWarmSession),
          after: summarizeWarmSessionTransition(afterWarmSession),
          },
        });
        return provisioned;
      }

      if (typeof deps.bootstrapThresholdEcdsaSession === 'function') {
        const provisioned = await deps.bootstrapThresholdEcdsaSession({
          nearAccountId,
          chain: args.chain,
        });
        args.assertNotCancelled?.();

        const expectedSessionId = toOptionalNonEmptyString(
          provisioned.thresholdEcdsaKeyRef?.thresholdSessionId,
        );
        if (!expectedSessionId) {
          throw new Error(
            `[WarmSessionManager] provisioned ECDSA capability is missing thresholdSessionId for ${nearAccountId}`,
          );
        }

        const afterWarmSession = await this.getWarmSession(nearAccountId);
        assertPersistedWarmSessionRecord({
          label: 'ECDSA',
          nearAccountId,
          expectedSessionId,
          persistedSessionIdRaw: afterWarmSession.capabilities.ecdsa[args.chain].record?.thresholdSessionId,
        });
        emitWarmSessionTransition({
          onTransition: deps.onTransition,
          event: {
          type: 'ecdsa_capability_provisioned',
          accountId: nearAccountId,
          chain: args.chain,
          thresholdSessionId: expectedSessionId,
          before: summarizeWarmSessionTransition(beforeWarmSession),
          after: summarizeWarmSessionTransition(afterWarmSession),
          },
        });
        return provisioned;
      }

      throw new Error(
        '[WarmSessionManager] provisionThresholdEcdsaSession is required to provision ECDSA capability',
      );
    },

    async tryReuseReadyEcdsaBootstrap(args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      source?: ThresholdEcdsaSessionStoreSource;
    }): Promise<ThresholdEcdsaSessionBootstrapResult | null> {
      if (typeof deps.getThresholdEcdsaKeyRefForSigning !== 'function') return null;
      const nearAccountId = toAccountId(args.nearAccountId);
      let keyRef: ThresholdEcdsaSecp256k1KeyRef | null = null;
      try {
        keyRef = deps.getThresholdEcdsaKeyRefForSigning({
          nearAccountId,
          chain: args.chain,
        });
      } catch {
        keyRef = null;
      }
      const warmSession = await this.getWarmSession(nearAccountId);
      const capability = getMatchingReadyEcdsaCapability({
        warmSession,
        chain: args.chain,
        keyRef,
        usesNeeded: 1,
      });
      if (!keyRef || !capability) return null;
      return (
        buildReusableEcdsaBootstrapResult({
          keyRef,
          capability,
          source: args.source || 'manual-bootstrap',
        }) || null
      );
    },

    async ensureEcdsaCapabilityReady(
      args: EnsureWarmEcdsaCapabilityReadyArgs,
    ): Promise<EnsureWarmEcdsaCapabilityReadyResult> {
      const nearAccountId = toAccountId(args.nearAccountId);
      const resolveKeyRef = (): ThresholdEcdsaSecp256k1KeyRef | null => {
        if (args.keyRef) return args.keyRef;
        if (typeof deps.getThresholdEcdsaKeyRefForSigning !== 'function') return null;
        try {
          return deps.getThresholdEcdsaKeyRefForSigning({
            nearAccountId,
            chain: args.chain,
          });
        } catch {
          return null;
        }
      };

      let keyRef = resolveKeyRef();
      let warmSession = await this.getWarmSession(nearAccountId);
      let capability = getMatchingReadyEcdsaCapability({
        warmSession,
        chain: args.chain,
        keyRef,
        usesNeeded: args.usesNeeded,
      });
      if (keyRef && capability) {
        return {
          keyRef,
          warmSession,
          capability,
          reconnected: false,
        };
      }

      if (typeof deps.bootstrapThresholdEcdsaSession !== 'function') {
        if (typeof deps.provisionThresholdEcdsaSession !== 'function') {
          throw new Error(
            '[WarmSessionManager] provisionThresholdEcdsaSession is required to reconnect ECDSA capability',
          );
        }
      }
      if (typeof deps.getThresholdEcdsaKeyRefForSigning !== 'function') {
        throw new Error(
          '[WarmSessionManager] getThresholdEcdsaKeyRefForSigning is required to resolve ECDSA capability',
        );
      }

      const inflightKey = buildEcdsaCapabilityInflightKey({
        nearAccountId,
        chain: args.chain,
        usesNeeded: args.usesNeeded,
        keyRef,
      });
      let reconnectPromise = reconnectInFlightByCapability.get(inflightKey);
      if (!reconnectPromise) {
        reconnectPromise = (async (): Promise<EnsureWarmEcdsaCapabilityReadyResult> => {
          const provisioned = await this.provisionEcdsaCapability({
            nearAccountId,
            chain: args.chain,
            source: 'manual-bootstrap',
            beforeProvision: args.beforeReconnect,
            assertNotCancelled: args.assertNotCancelled,
          });
          args.assertNotCancelled?.();

          const refreshedKeyRef = provisioned.thresholdEcdsaKeyRef;
          const refreshedWarmSession = await this.getWarmSession(nearAccountId);
          const refreshedCapability = getMatchingReadyEcdsaCapability({
            warmSession: refreshedWarmSession,
            chain: args.chain,
            keyRef: refreshedKeyRef,
            usesNeeded: args.usesNeeded,
          });
          if (!refreshedKeyRef || !refreshedCapability) {
            throw new Error(
              '[WarmSessionManager] threshold ECDSA warm capability is not ready after reconnect',
            );
          }

          emitWarmSessionTransition({
            onTransition: deps.onTransition,
            event: {
            type: 'ecdsa_capability_reconnected',
            accountId: nearAccountId,
            chain: args.chain,
            thresholdSessionId: String(refreshedKeyRef.thresholdSessionId || '').trim(),
            before: summarizeWarmSessionTransition(warmSession),
            after: summarizeWarmSessionTransition(refreshedWarmSession),
            },
          });

          return {
            keyRef: refreshedKeyRef,
            warmSession: refreshedWarmSession,
            capability: refreshedCapability,
            reconnected: true,
          };
        })();
        reconnectInFlightByCapability.set(inflightKey, reconnectPromise);
        void reconnectPromise.then(
          () => {
            if (reconnectInFlightByCapability.get(inflightKey) === reconnectPromise) {
              reconnectInFlightByCapability.delete(inflightKey);
            }
          },
          () => {
            if (reconnectInFlightByCapability.get(inflightKey) === reconnectPromise) {
              reconnectInFlightByCapability.delete(inflightKey);
            }
          },
        );
      }

      const reconnectedCapability = await reconnectPromise;
      args.assertNotCancelled?.();
      return reconnectedCapability;
    },

    async assertEcdsaSigningSessionReady(args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId: unknown;
      usesNeeded?: number;
    }): Promise<Extract<WarmSessionStatusResult, { ok: true }>> {
      const thresholdSessionId = requireThresholdSigningSessionId(args.thresholdSessionId);
      const status = await this.getEcdsaSigningSessionStatus({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        thresholdSessionId,
      });
      if (!status || status.status === 'not_found') {
        throw new Error(formatThresholdSigningSessionStatusError('not_found'));
      }
      if (status.status === 'unavailable') {
        throw new Error(formatThresholdSigningSessionAvailabilityError(status.statusCode));
      }
      if (status.status === 'expired') {
        throw new Error(formatThresholdSigningSessionStatusError('expired'));
      }
      if (status.status === 'exhausted') {
        throw new Error(THRESHOLD_SESSION_EXHAUSTED_ERROR);
      }

      const remainingUses = Math.floor(Number(status.remainingUses) || 0);
      if (remainingUses < normalizeUsesNeeded(args.usesNeeded)) {
        throw new Error(THRESHOLD_SESSION_EXHAUSTED_ERROR);
      }

      return {
        ok: true,
        remainingUses,
        expiresAtMs: Number(status.expiresAtMs) || Date.now(),
      };
    },

    async resolveEd25519SigningAuthPlan(args: {
      nearAccountId: AccountId | string;
      usesNeeded?: number;
      operationLabel?: string;
    }): Promise<WarmSessionEd25519SigningAuthPlan> {
      const warmSession = await this.getWarmSession(args.nearAccountId);
      const capability = warmSession.capabilities.ed25519;
      const sessionId = String(capability.record?.thresholdSessionId || '').trim();
      if (!sessionId) {
        throw new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
      }
      if (capability.state === 'auth_missing') {
        throw new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
      }
      if (capability.state === 'prf_unavailable') {
        throw new Error(formatThresholdSigningSessionAvailabilityError(capability.prfClaim?.code));
      }
      if (capability.state === 'ready') {
        const remainingUses = Math.floor(Number(capability.prfClaim?.remainingUses) || 0);
        if (remainingUses < normalizeUsesNeeded(args.usesNeeded)) {
          throw new Error(THRESHOLD_SESSION_EXHAUSTED_ERROR);
        }
        return {
          sessionId,
          signingAuthMode: 'warmSession',
          warmSessionReady: true,
        };
      }

      const status = await this.getEd25519SigningSessionStatus(args.nearAccountId);
      if (status?.status === 'unavailable') {
        throw new Error(formatThresholdSigningSessionAvailabilityError(status.statusCode));
      }
      if (status?.status === 'expired') {
        throw new Error(formatThresholdSigningSessionStatusError('expired'));
      }
      if (status?.status === 'exhausted') {
        throw new Error(THRESHOLD_SESSION_EXHAUSTED_ERROR);
      }
      if (status?.status === 'active') {
        return {
          sessionId,
          signingAuthMode: 'webauthn',
          warmSessionReady: false,
        };
      }
      if (capability.state === 'missing') {
        throw new Error(THRESHOLD_SESSION_MISSING_ERROR);
      }

      if (args.operationLabel) {
        console.warn(
          `[SigningEngine][near] ${args.operationLabel} warm session cache is unavailable; falling back to WebAuthn`,
          {
            nearAccountId: args.nearAccountId,
            sessionId,
            code: status?.status || 'not_found',
          },
        );
      }

      return {
        sessionId,
        signingAuthMode: 'webauthn',
        warmSessionReady: false,
      };
    },

    async getEd25519SigningSessionStatus(
      nearAccountId: AccountId | string,
    ): Promise<SigningSessionStatus | null> {
      const normalizedThresholdSessionId = String(
        readWarmSessionCapabilityRecordsForAccount(toAccountId(nearAccountId)).ed25519?.thresholdSessionId || '',
      ).trim();
      if (!normalizedThresholdSessionId) return null;
      const claim = await readWarmSessionClaim(deps.touchConfirm, normalizedThresholdSessionId);
      return toSigningSessionStatus({
        sessionId: normalizedThresholdSessionId,
        claim,
      });
    },

    async getEcdsaSigningSessionStatus(args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId?: string;
    }): Promise<SigningSessionStatus | null> {
      const expectedThresholdSessionId = String(args.thresholdSessionId || '').trim();
      const record =
        readWarmSessionCapabilityRecordsForAccount(toAccountId(args.nearAccountId)).ecdsa[args.chain];
      const normalizedThresholdSessionId = String(record?.thresholdSessionId || '').trim();
      if (!normalizedThresholdSessionId) return null;
      if (expectedThresholdSessionId && expectedThresholdSessionId !== normalizedThresholdSessionId) {
        return {
          sessionId: expectedThresholdSessionId,
          status: 'not_found',
        };
      }
      const claim = await readWarmSessionClaim(deps.touchConfirm, normalizedThresholdSessionId);
      return toSigningSessionStatus({
        sessionId: normalizedThresholdSessionId,
        claim,
      });
    },

    async claimPrfFirstByThresholdSessionId(args: ClaimWarmSessionPrfArgs): Promise<string> {
      return await claimWarmSessionPrfFirst({
        touchConfirm: deps.touchConfirm,
        thresholdSessionId: args.thresholdSessionId,
        errorContext: args.errorContext,
        uses: args.uses,
      });
    },

    async ensureEcdsaPrfSealPersistedByThresholdSessionId(args: {
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId: string;
      required?: boolean;
      errorContext?: string;
    }): Promise<void> {
      await ensureEcdsaPrfSealPersisted({
        touchConfirm: deps.touchConfirm,
        thresholdSessionId: args.thresholdSessionId,
        required: args.required,
        errorContext: args.errorContext,
        sealPersistInFlightBySessionId,
        resolveSealTransport: (thresholdSessionId) =>
          this.resolveEcdsaSealTransportByThresholdSessionId(thresholdSessionId),
      });
    },

    resolveEcdsaSealTransportByThresholdSessionId(
      thresholdSessionId: string,
    ): ThresholdSessionSealTransportAuthMaterial | null {
      const record = readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
      if (!record) return null;
      const auth = resolveEcdsaAuthMaterial(record);
      return resolveEcdsaSealTransport({
        record,
        auth,
        keyVersion: String(
        record.signingSessionSealKeyVersion || deps.signingSessionSeal?.keyVersion || '',
        ).trim(),
        shamirPrimeB64u: String(
        record.signingSessionSealShamirPrimeB64u ||
          deps.signingSessionSeal?.shamirPrimeB64u ||
          '',
        ).trim(),
      });
    },
  };
}

export function resolveExplicitEcdsaWarmSessionAuthByThresholdSessionId(
  thresholdSessionId: string,
): WarmSessionEcdsaAuthMaterial | null {
  return createWarmSessionManager().resolveEcdsaAuthByThresholdSessionId(thresholdSessionId);
}

export function resolveEcdsaWarmSessionSealTransportByThresholdSessionId(
  thresholdSessionId: string,
): ThresholdSessionSealTransportAuthMaterial | null {
  return createWarmSessionManager().resolveEcdsaSealTransportByThresholdSessionId(thresholdSessionId);
}
