import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/tatchi';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionRecord,
  ThresholdEd25519SessionStoreSource,
  ThresholdSessionSealTransportAuthMaterial,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from '../api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence';
import type { EmailOtpAuthLane } from '../emailOtp/authLane';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../orchestration/thresholdActivation';
import type { Ed25519SessionKind } from '../threshold/session/ed25519SessionTypes';
import type { ThresholdRuntimePolicyScope } from '../threshold/session/sessionPolicy';
import type { WarmSessionStatusResult } from '../touchConfirm';
import type {
  WarmSessionEd25519AuthMaterial,
  WarmSessionEcdsaAuthMaterial,
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519CapabilityState,
  WarmSessionEnvelope,
} from './warmSessionTypes';
import type { WarmSessionEcdsaCapabilityRef } from './warmSessionEcdsaProvisioning';

export type ProvisionWarmEd25519CapabilityArgs = {
  nearAccountId: AccountId | string;
  relayerKeyId: string;
  appSessionJwt?: string;
  useAppSessionCookie?: boolean;
  localPrfCredential?: WebAuthnAuthenticationCredential;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
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
  walletSigningSessionId?: string;
  source?: ThresholdEd25519SessionStoreSource;
  beforeProvision?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

export type ProvisionWarmEd25519CapabilityResult = {
  ok: boolean;
  sessionId?: string;
  walletSigningSessionId?: string;
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
  source?: ThresholdEcdsaSessionStoreSource;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
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

export type ApplyWarmEcdsaPostSignPolicyArgs = {
  nearAccountId: AccountId | string;
  chain: ThresholdEcdsaActivationChain;
  thresholdSessionId?: string;
  source?: ThresholdEcdsaSessionStoreSource;
};

export type AssertWarmEcdsaOperationAllowedArgs = {
  nearAccountId: AccountId | string;
  chain: ThresholdEcdsaActivationChain;
  operationLabel: string;
  thresholdSessionId?: string;
  source?: ThresholdEcdsaSessionStoreSource;
  sensitivePolicy?: SensitiveOperationPolicy;
};

export type ResolveWarmEcdsaBootstrapRequestArgs = {
  nearAccountId: AccountId | string;
  chain: ThresholdEcdsaActivationChain;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  relayerUrl?: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  walletSigningSessionId?: string;
  thresholdRouteAuth?: AppOrThresholdSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
};

export type WarmEcdsaBootstrapRequest = {
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  relayerUrl?: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  walletSigningSessionId?: string;
  thresholdRouteAuth?: AppOrThresholdSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  clientRootShare32?: Uint8Array;
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

export type WarmEcdsaSigningSessionStatus = SigningSessionStatus & {
  chain: ThresholdEcdsaActivationChain;
  source?: ThresholdEcdsaSessionStoreSource;
  walletSigningSessionId?: string;
};

export type GetWarmEcdsaSigningSessionStatusArgs = Omit<
  WarmSessionEcdsaCapabilityRef,
  'thresholdSessionId'
> & {
  thresholdSessionId: string;
};

export type WarmSessionCapabilityReader = {
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
  resolveEmailOtpSigningSessionAuthLane: (args: {
    thresholdSessionId: string;
    curve: 'ed25519' | 'ecdsa';
    chain?: ThresholdEcdsaActivationChain;
  }) => EmailOtpAuthLane | null;
  getEd25519CapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEd25519CapabilityState | null>;
  getEcdsaCapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEcdsaCapabilityState | null>;
  resolveEcdsaSealTransportByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdSessionSealTransportAuthMaterial | null;
};

export type ThresholdWarmSessionStatusReader = {
  getEd25519SigningSessionStatus: (
    nearAccountId: AccountId | string,
  ) => Promise<SigningSessionStatus | null>;
  getEd25519SigningSessionStatusForSession: (args: {
    nearAccountId: AccountId | string;
    thresholdSessionId: string;
  }) => Promise<SigningSessionStatus | null>;
  getEcdsaSigningSessionStatus: (
    args: GetWarmEcdsaSigningSessionStatusArgs,
  ) => Promise<WarmEcdsaSigningSessionStatus | null>;
  listEcdsaSigningSessionStatuses: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => Promise<WarmEcdsaSigningSessionStatus[]>;
  assertEcdsaSigningSessionReady: (
    args: Omit<WarmSessionEcdsaCapabilityRef, 'thresholdSessionId'> & {
      thresholdSessionId: unknown;
      usesNeeded?: number;
    },
  ) => Promise<Extract<WarmSessionStatusResult, { ok: true }>>;
};

export type WarmSessionProvisioner = {
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
  claimPrfFirstByThresholdSessionId: (args: ClaimWarmSessionPrfArgs) => Promise<string>;
  ensureEcdsaPrfSealPersistedByThresholdSessionId: (args: {
    chain: ThresholdEcdsaActivationChain;
    thresholdSessionId: string;
    required?: boolean;
    errorContext?: string;
  }) => Promise<void>;
};

export type WarmSessionPostSignPolicy = {
  applyEcdsaPostSignPolicy: (args: ApplyWarmEcdsaPostSignPolicyArgs) => Promise<void>;
  assertEcdsaOperationAllowed: (args: AssertWarmEcdsaOperationAllowedArgs) => Promise<void>;
};
