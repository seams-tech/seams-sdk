import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import { requireEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  decodeJwtPayloadRecord,
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  toWalletSessionThresholdExpiresAtMs,
  type WalletSessionThresholdExpiresAtMs,
} from '@shared/utils/sessionTokens';
import {
  buildPasskeyWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type {
  EcdsaLaneCandidate,
  ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import { laneCandidateAuthMethod } from '../../session/identity/laneIdentity';
import {
  SigningSessionIds,
  type SigningGrantId,
  type ThresholdEcdsaSessionId,
} from '../../session/operationState/types';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '../../session/operationState/lanes';
import {
  resolveEvmFamilyTransactionWalletAuth,
  type EvmFamilyAccountMetadataDeps,
} from './accountAuth';
import {
  buildEcdsaMaterialStateForCandidate,
  summarizeEcdsaMaterialState,
  summarizeVisibleEcdsaMaterial,
  type EcdsaMaterialState,
  type EcdsaMaterialSummary,
  type ReadyEcdsaMaterial,
} from './ecdsaMaterialState';
import {
  findExactEcdsaSessionRecordForSelectedLane,
  summarizeEvmFamilyEcdsaSessionRecord,
  logEvmFamilyEcdsaLaneDiagnostic,
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaLane,
  tryGetPasskeyThresholdEcdsaSessionRecordForSigning,
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from '../../session/warmCapabilities/routerAbEcdsaWalletSessionAuth';
import type {
  EmailOtpEcdsaSigningSessionAuthorityResolver,
  EvmFamilyEcdsaSessionReaderDeps,
  PasskeyEcdsaSessionStoreSource,
} from '../../interfaces/operationDeps';
import {
  resolveEmailOtpEcdsaSigningSessionAuthorityFromRecord,
  type EmailOtpEcdsaSigningSessionAuthority,
} from '../../session/emailOtp/ecdsaSigningSessionAuthority';
import { buildEcdsaSessionIdentity } from '../../session/warmCapabilities/ecdsaProvisionPlan';
import {
  exactEcdsaSigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityKey,
} from '../../session/identity/exactSigningLaneIdentity';
import {
  buildEcdsaWalletSessionTransportAuth,
  toParticipantId,
  toEvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilySigningKeySlotId,
  type ParticipantId,
  type VerifiedWalletSessionJwt,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  parseEcdsaRelayerKeyId,
  type EcdsaRelayerKeyId,
} from '../../session/keyMaterialBrands';
import type { EvmFamilyChain, EvmFamilySenderSignatureAlgorithm } from './types';
import {
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  thresholdEcdsaLaneCandidateFromSessionRecord,
  toExactEcdsaSigningLaneIdentity,
  type ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import { parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord } from '../../session/persistence/ecdsaRoleLocalRecords';
import type { WalletBudgetUnknown } from '../../session/budget/budgetProjection';
import type { ReauthAnchorIdentity } from '../../session/operationState/transactionState';
import type {
  EmailOtpSigningSessionAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';

const PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY = [
  'login',
  'manual-bootstrap',
  'registration',
] as const satisfies readonly PasskeyEcdsaSessionStoreSource[];

export type EvmFamilyEcdsaSigningSelectionDeps = EvmFamilyAccountMetadataDeps &
  EvmFamilyEcdsaSessionReaderDeps &
  EmailOtpEcdsaSigningSessionAuthorityResolver;

type EcdsaSelectionLaneCandidateDiagnosticsBase = {
  authMethod: EvmFamilyEcdsaAuthMethod;
  chain: EcdsaLaneCandidate['chain'];
  chainTarget: ThresholdEcdsaChainTarget;
  state: EcdsaLaneCandidate['state'];
  signingGrantId: string;
  thresholdSessionId: string;
  remainingUses: number | null;
  expiresAtMs: number | null;
  updatedAtMs: number | null;
};

function ecdsaLaneCandidateAuthMethod(candidate: EcdsaLaneCandidate): EvmFamilyEcdsaAuthMethod {
  const authMethod = laneCandidateAuthMethod(candidate);
  switch (authMethod) {
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
    case SIGNER_AUTH_METHODS.passkey:
      return SIGNER_AUTH_METHODS.passkey;
  }
  authMethod satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported ECDSA lane auth method');
}

type EcdsaSelectionLaneCandidateDiagnostics =
  | (EcdsaSelectionLaneCandidateDiagnosticsBase & {
      source: 'evm_family_shared_key';
      sourceChainTarget: ThresholdEcdsaChainTarget;
    })
  | (EcdsaSelectionLaneCandidateDiagnosticsBase & {
      source: Exclude<EcdsaLaneCandidate['source'], 'evm_family_shared_key'>;
      sourceChainTarget?: never;
    });

export type EcdsaSelectionDiagnostics = {
  selectedLaneCandidate: EcdsaSelectionLaneCandidateDiagnostics;
  exactCandidateMaterial: EcdsaMaterialSummary;
  visibleEmailOtpMaterial: EcdsaMaterialSummary | { present: false };
  visiblePasskeyMaterials: readonly (EcdsaMaterialSummary | { present: false })[];
  selectedPasskeyMaterial: EcdsaMaterialSummary | { present: false };
};

type ReadyEvmFamilyEcdsaSigningSelectionBase = {
  kind: 'ready';
  accountAuth: AccountAuthMetadata;
  source: ThresholdEcdsaSessionStoreSource;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: ReadyEcdsaMaterial;
  diagnostics: EcdsaSelectionDiagnostics;
};

export type ReadyEcdsaCommittedLane<A extends WalletAuthAuthority = WalletAuthAuthority> =
  EcdsaCommittedLane<A> & {
    material: ReadyEcdsaMaterial;
  };

export type ReadyEmailOtpEcdsaCommittedLane = ReadyEcdsaCommittedLane<EmailOtpWalletAuthAuthority>;

export type ReadyPasskeyEcdsaCommittedLane = ReadyEcdsaCommittedLane<PasskeyWalletAuthAuthority>;

export type ReadyRecordBackedEcdsaCommittedLane<
  A extends WalletAuthAuthority = WalletAuthAuthority,
> = RecordBackedEcdsaCommittedLane<A> & {
  material: ReadyEcdsaMaterial;
};

export type ReadyEvmFamilyEcdsaSigningSelection =
  | (ReadyEvmFamilyEcdsaSigningSelectionBase & {
      authMethod: 'passkey';
      committedLane: ReadyPasskeyEcdsaCommittedLane;
    })
  | (ReadyEvmFamilyEcdsaSigningSelectionBase & {
      authMethod: 'email_otp';
      committedLane: ReadyEmailOtpEcdsaCommittedLane;
    });

type ReauthRequiredEvmFamilyEcdsaSigningSelectionBase = {
  kind: 'reauth_required';
  accountAuth: AccountAuthMetadata;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: EcdsaMaterialState;
  reason: 'missing_hot_material' | 'expired' | 'exhausted';
  diagnostics: EcdsaSelectionDiagnostics;
};

type ReauthAnchorBackedEvmFamilyEcdsaSigningSelection = {
  reason: 'expired' | 'exhausted';
  reauthAnchor: ReauthAnchorIdentity;
};

type MaterialBackedEvmFamilyEcdsaSigningSelection = {
  reason: 'missing_hot_material';
  reauthAnchor?: never;
};

export type ReauthRequiredEvmFamilyEcdsaSigningSelection =
  | (ReauthRequiredEvmFamilyEcdsaSigningSelectionBase &
      ReauthAnchorBackedEvmFamilyEcdsaSigningSelection & {
        authMethod: 'email_otp';
        committedLane: EmailOtpEcdsaCommittedLane;
      })
  | (ReauthRequiredEvmFamilyEcdsaSigningSelectionBase &
      ReauthAnchorBackedEvmFamilyEcdsaSigningSelection & {
        authMethod: 'passkey';
        committedLane: PasskeyEcdsaCommittedLane;
      })
  | (ReauthRequiredEvmFamilyEcdsaSigningSelectionBase &
      MaterialBackedEvmFamilyEcdsaSigningSelection & {
        authMethod: 'email_otp';
        committedLane: EmailOtpEcdsaCommittedLane;
      })
  | (ReauthRequiredEvmFamilyEcdsaSigningSelectionBase &
      MaterialBackedEvmFamilyEcdsaSigningSelection & {
        authMethod: 'passkey';
        committedLane: PasskeyEcdsaCommittedLane;
      });

export type BudgetBlockedEvmFamilyEcdsaSigningSelection = {
  kind: 'budget_blocked';
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: ReadyEcdsaMaterial;
  budget: WalletBudgetUnknown;
  diagnostics: EcdsaSelectionDiagnostics;
};

export type MissingMaterialEvmFamilyEcdsaSigningSelection = {
  kind: 'missing_material';
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  candidate: EcdsaLaneCandidate;
  material: EcdsaMaterialState;
  diagnostics: EcdsaSelectionDiagnostics;
};

export type EvmFamilyEcdsaSigningSelectionResult =
  | ReadyEvmFamilyEcdsaSigningSelection
  | ReauthRequiredEvmFamilyEcdsaSigningSelection
  | BudgetBlockedEvmFamilyEcdsaSigningSelection
  | MissingMaterialEvmFamilyEcdsaSigningSelection;

export type EmailOtpEcdsaCommittedLaneStateFailure =
  | {
      kind: 'authority_missing';
    }
  | {
      kind: 'authority_not_ecdsa_signing_session';
    }
  | {
      kind: 'committed_lane_missing_for_reauth';
      reason: ReauthRequiredEvmFamilyEcdsaSigningSelection['reason'];
    }
  | {
      kind: 'committed_lane_missing_for_ready';
    };

export class EmailOtpEcdsaCommittedLaneStateError extends Error {
  readonly kind = 'email_otp_ecdsa_committed_lane_state_error';
  readonly failure: EmailOtpEcdsaCommittedLaneStateFailure;

  constructor(failure: EmailOtpEcdsaCommittedLaneStateFailure) {
    super(emailOtpEcdsaCommittedLaneStateFailureMessage(failure));
    this.name = 'EmailOtpEcdsaCommittedLaneStateError';
    this.failure = failure;
    Object.setPrototypeOf(this, EmailOtpEcdsaCommittedLaneStateError.prototype);
  }
}

function assertNeverEmailOtpEcdsaCommittedLaneFailure(value: never): never {
  throw new Error(`[SigningEngine][ecdsa] unknown Email OTP committed-lane failure: ${value}`);
}

function emailOtpEcdsaCommittedLaneStateFailureMessage(
  failure: EmailOtpEcdsaCommittedLaneStateFailure,
): string {
  switch (failure.kind) {
    case 'authority_missing':
      return 'Email OTP ECDSA committed lane is missing wallet-session authority; unlock wallet again';
    case 'authority_not_ecdsa_signing_session':
      return 'Email OTP ECDSA committed lane authority is not an ECDSA signing session; unlock wallet again';
    case 'committed_lane_missing_for_reauth':
      return `Email OTP ECDSA committed lane is unavailable for ${failure.reason} reauth; unlock wallet again`;
    case 'committed_lane_missing_for_ready':
      return 'Email OTP ECDSA committed lane is unavailable for ready signing; unlock wallet again';
  }
  return assertNeverEmailOtpEcdsaCommittedLaneFailure(failure);
}

function throwEmailOtpEcdsaCommittedLaneStateError(
  failure: EmailOtpEcdsaCommittedLaneStateFailure,
): never {
  throw new EmailOtpEcdsaCommittedLaneStateError(failure);
}

function walletAuthWithSelectedPrimary(
  accountAuth: AccountAuthMetadata,
  authMethod: EvmFamilyEcdsaAuthMethod,
): AccountAuthMetadata {
  return {
    ...accountAuth,
    primaryAuthMethod: authMethod,
    linkedAuthMethods: Array.from(new Set([...accountAuth.linkedAuthMethods, authMethod])),
  };
}

function exactEcdsaCandidateRequiresHotMaterial(candidate: EcdsaLaneCandidate): boolean {
  return candidate.state === 'ready';
}

export function ecdsaCommittedLaneAuthMethod(
  lane: PasskeyEcdsaCommittedLane,
): typeof SIGNER_AUTH_METHODS.passkey;
export function ecdsaCommittedLaneAuthMethod(
  lane: EmailOtpEcdsaCommittedLane,
): typeof SIGNER_AUTH_METHODS.emailOtp;
export function ecdsaCommittedLaneAuthMethod(
  lane: EcdsaCommittedLane,
): EvmFamilyEcdsaAuthMethod;
export function ecdsaCommittedLaneAuthMethod(
  lane: EcdsaCommittedLane,
): EvmFamilyEcdsaAuthMethod {
  const factorKind = lane.authority.factor.kind;
  switch (factorKind) {
    case 'passkey':
      return SIGNER_AUTH_METHODS.passkey;
    case 'email_otp':
      return SIGNER_AUTH_METHODS.emailOtp;
  }
  factorKind satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported committed lane authority');
}

function passkeyReauthRequiredSelection(args: {
  accountAuth: AccountAuthMetadata;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: EcdsaMaterialState;
  reason: ReauthRequiredEvmFamilyEcdsaSigningSelection['reason'];
  committedLane: PasskeyEcdsaCommittedLane;
  reauthAnchor?: ReauthAnchorIdentity;
  diagnostics: EcdsaSelectionDiagnostics;
}): Extract<ReauthRequiredEvmFamilyEcdsaSigningSelection, { authMethod: 'passkey' }> {
  const common = {
    kind: 'reauth_required' as const,
    accountAuth: args.accountAuth,
    lane: args.lane,
    material: args.material,
    diagnostics: args.diagnostics,
    committedLane: args.committedLane,
  };
  const authMethod = ecdsaCommittedLaneAuthMethod(args.committedLane);
  if (args.reason === 'expired' || args.reason === 'exhausted') {
    if (!args.reauthAnchor) {
      throw new Error('[SigningEngine][ecdsa] exhausted/expired reauth requires a reauth anchor');
    }
    const base = {
      ...common,
      reason: args.reason,
      reauthAnchor: args.reauthAnchor,
    };
    return {
      ...base,
      authMethod,
    };
  }
  const base = {
    ...common,
    reason: args.reason,
  };
  return {
    ...base,
    authMethod,
  };
}

function emailOtpReauthRequiredSelection(args: {
  accountAuth: AccountAuthMetadata;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: EcdsaMaterialState;
  reason: ReauthRequiredEvmFamilyEcdsaSigningSelection['reason'];
  committedLane: EmailOtpEcdsaCommittedLane;
  reauthAnchor?: ReauthAnchorIdentity;
  diagnostics: EcdsaSelectionDiagnostics;
}): Extract<ReauthRequiredEvmFamilyEcdsaSigningSelection, { authMethod: 'email_otp' }> {
  const authMethod = ecdsaCommittedLaneAuthMethod(args.committedLane);
  const common = {
    kind: 'reauth_required' as const,
    accountAuth: args.accountAuth,
    authMethod,
    lane: args.lane,
    material: args.material,
    diagnostics: args.diagnostics,
    committedLane: args.committedLane,
  };
  if (args.reason === 'expired' || args.reason === 'exhausted') {
    if (!args.reauthAnchor) {
      throw new Error('[SigningEngine][ecdsa] exhausted/expired reauth requires a reauth anchor');
    }
    return {
      ...common,
      reason: args.reason,
      reauthAnchor: args.reauthAnchor,
    };
  }
  return {
    ...common,
    reason: args.reason,
  };
}

export function resolvedEvmFamilyEcdsaSigningLaneFromCandidate(
  candidate: EcdsaLaneCandidate,
): ResolvedEvmFamilyEcdsaSigningLane {
  const buildLane =
    candidate.chainTarget.kind === 'tempo'
      ? buildTempoTransactionSigningLane
      : buildEvmTransactionSigningLane;
  const base = {
    key: candidate.key,
    keyHandle: candidate.keyHandle,
    walletId: candidate.walletId,
    chainTarget: candidate.chainTarget,
    signingGrantId: SigningSessionIds.signingGrant(candidate.signingGrantId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(candidate.thresholdSessionId),
  };
  const lane = buildLane(
    candidate.auth.kind === 'email_otp'
      ? {
          ...base,
          auth: candidate.auth,
          retention: 'session',
          sessionOrigin: 'per_operation',
        }
      : {
          ...base,
          auth: candidate.auth,
          storageSource: 'manual-bootstrap',
        },
  );
  return requireResolvedEvmFamilyEcdsaSigningLane({
    lane,
    chain: candidate.chain,
    context: 'build exact ECDSA candidate signing lane',
  });
}

function emailOtpAuthorityLaneFromCandidate(args: {
  candidate: EcdsaLaneCandidate;
  selectedLane: ResolvedEvmFamilyEcdsaSigningLane;
}): ResolvedEvmFamilyEcdsaSigningLane {
  if (args.candidate.source !== 'evm_family_shared_key') return args.selectedLane;
  return resolvedEvmFamilyEcdsaSigningLaneFromCandidate({
    ...args.candidate,
    chain: args.candidate.sourceChainTarget.kind,
    chainTarget: args.candidate.sourceChainTarget,
  });
}

function laneCandidateDiagnosticsBase(
  candidate: EcdsaLaneCandidate,
): EcdsaSelectionLaneCandidateDiagnosticsBase {
  return {
    authMethod: ecdsaLaneCandidateAuthMethod(candidate),
    chain: candidate.chain,
    chainTarget: candidate.chainTarget,
    state: candidate.state,
    signingGrantId: candidate.signingGrantId,
    thresholdSessionId: candidate.thresholdSessionId,
    remainingUses: candidate.remainingUses,
    expiresAtMs: candidate.expiresAtMs,
    updatedAtMs: candidate.updatedAtMs,
  };
}

function summarizeLaneCandidate(
  candidate: EcdsaLaneCandidate,
): EcdsaSelectionDiagnostics['selectedLaneCandidate'] {
  const base = laneCandidateDiagnosticsBase(candidate);
  switch (candidate.source) {
    case 'evm_family_shared_key':
      return {
        ...base,
        source: 'evm_family_shared_key',
        sourceChainTarget: candidate.sourceChainTarget,
      };
    case 'durable_sealed_record':
    case 'runtime_session_record':
    case 'unknown':
      return {
        ...base,
        source: candidate.source,
      };
  }
}

type PasskeyVisibleMaterial = {
  source: PasskeyEcdsaSessionStoreSource;
  record: ThresholdEcdsaSessionRecord;
};

type PasskeyMaterialSelectionResult =
  | {
      kind: 'selected';
      material: EcdsaMaterialState;
      selected: PasskeyVisibleMaterial;
    }
  | {
      kind: 'missing';
      material: EcdsaMaterialState;
    };

type PasskeyMaterialDiagnosticsSelection =
  | PasskeyMaterialSelectionResult
  | {
      kind: 'not_applicable';
      reason: 'email_otp_candidate';
      material?: never;
      selected?: never;
    };

type EmailOtpSelectionAuthority = {
  laneAuthority: EmailOtpEcdsaSigningSessionAuthority;
} & (
  | {
      kind: 'record_backed';
      record: ThresholdEcdsaSessionRecord;
    }
  | {
      kind: 'resolver_backed';
      record?: never;
    }
);

export type EcdsaCommittedLaneWalletSessionAuthority = {
  kind: 'wallet_session_authority';
  walletSessionJwt: VerifiedWalletSessionJwt;
  walletId: WalletId;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  relayerKeyId: EcdsaRelayerKeyId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  signingGrantId: SigningGrantId;
  thresholdExpiresAtMs: WalletSessionThresholdExpiresAtMs;
  participantIds: readonly ParticipantId[];
};

export type PasskeyEcdsaCommittedLaneAuthority =
  | EcdsaCommittedLaneWalletSessionAuthority
  | {
      kind: 'passkey_cookie_session_authority';
      thresholdSessionId: string;
      signingGrantId: string;
      walletSessionJwt?: never;
    };

type EcdsaCommittedLaneWalletSessionAuthorityFor<
  A extends WalletAuthAuthority,
> = A extends PasskeyWalletAuthAuthority
  ? PasskeyEcdsaCommittedLaneAuthority
  : A extends EmailOtpWalletAuthAuthority
    ? EcdsaCommittedLaneWalletSessionAuthority
    : never;

type EcdsaCommittedLaneAuthFacts<A extends WalletAuthAuthority> =
  A extends EmailOtpWalletAuthAuthority
    ? {
        authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ecdsa' }>;
      }
    : A extends PasskeyWalletAuthAuthority
      ? {
          authLane?: never;
        }
      : never;

type EcdsaCommittedLaneDurableRestoreFacts<A extends WalletAuthAuthority> =
  A extends EmailOtpWalletAuthAuthority
    ?
        | {
            source: 'record_backed';
            record: ThresholdEcdsaSessionRecord;
            durableRestore: 'record_restore_metadata';
          }
        | {
            source: 'resolver_backed';
            record?: never;
            durableRestore: 'resolver_restore_metadata';
          }
    : A extends PasskeyWalletAuthAuthority
      ? {
          source: PasskeyEcdsaSessionStoreSource;
          record: ThresholdEcdsaSessionRecord;
          durableRestore: 'record_restore_metadata';
        }
      : never;

export type EcdsaCommittedLane<A extends WalletAuthAuthority = WalletAuthAuthority> =
  A extends WalletAuthAuthority
    ? {
        lane: ResolvedEvmFamilyEcdsaSigningLane;
        authority: A;
        walletSessionAuthority: EcdsaCommittedLaneWalletSessionAuthorityFor<A>;
        material: EcdsaMaterialState;
      } & EcdsaCommittedLaneAuthFacts<A> &
        EcdsaCommittedLaneDurableRestoreFacts<A>
    : never;

export type EmailOtpEcdsaCommittedLane = EcdsaCommittedLane<EmailOtpWalletAuthAuthority>;

export type PasskeyEcdsaCommittedLane = EcdsaCommittedLane<PasskeyWalletAuthAuthority>;

export type RecordBackedEcdsaCommittedLane<A extends WalletAuthAuthority = WalletAuthAuthority> =
  Extract<
    EcdsaCommittedLane<A>,
    {
      record: ThresholdEcdsaSessionRecord;
      durableRestore: 'record_restore_metadata';
    }
  >;

export type RecordBacked<
  Lane,
  Record extends ThresholdEcdsaSessionRecord = ThresholdEcdsaSessionRecord,
> = Lane & {
  record: Record;
  durableRestore: 'record_restore_metadata';
};

type PasskeyEcdsaLaneCandidate = EcdsaLaneCandidate & {
  auth: Extract<EcdsaLaneCandidate['auth'], { kind: 'passkey' }>;
};


function readyEmailOtpEcdsaCommittedLane(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  committedLane: EmailOtpEcdsaCommittedLane;
  material: ReadyEcdsaMaterial;
}): ReadyEmailOtpEcdsaCommittedLane {
  const common = {
    lane: args.lane,
    authLane: args.committedLane.authLane,
    walletSessionAuthority: args.committedLane.walletSessionAuthority,
    material: args.material,
    authority: args.committedLane.authority,
  };
  switch (args.committedLane.source) {
    case 'record_backed':
      return {
        ...common,
        source: 'record_backed',
        record: args.committedLane.record,
        durableRestore: 'record_restore_metadata',
      };
    case 'resolver_backed':
      return {
        ...common,
        source: 'resolver_backed',
        durableRestore: 'resolver_restore_metadata',
      };
  }
}

function readyPasskeyEcdsaCommittedLane(args: {
  committedLane: PasskeyEcdsaCommittedLane;
  material: ReadyEcdsaMaterial;
}): ReadyPasskeyEcdsaCommittedLane {
  return {
    source: args.committedLane.source,
    lane: args.committedLane.lane,
    authority: args.committedLane.authority,
    record: args.committedLane.record,
    walletSessionAuthority: args.committedLane.walletSessionAuthority,
    material: args.material,
    durableRestore: 'record_restore_metadata',
  };
}

function passkeySessionStoreSourceFromExactSource(
  source: ThresholdEcdsaSessionStoreSource | undefined,
): PasskeyEcdsaSessionStoreSource {
  switch (source) {
    case undefined:
      return 'manual-bootstrap';
    case 'login':
    case 'manual-bootstrap':
    case 'registration':
      return source;
    case 'email_otp':
      throw new Error('[SigningEngine][ecdsa] passkey material cannot use Email OTP source');
  }
}

function requirePasskeyEcdsaLaneCandidate(
  candidate: EcdsaLaneCandidate,
): PasskeyEcdsaLaneCandidate {
  if (candidate.auth.kind !== 'passkey') {
    throw new Error('[SigningEngine][ecdsa] passkey committed lane requires passkey candidate');
  }
  const auth = candidate.auth;
  switch (candidate.source) {
    case 'evm_family_shared_key':
      return { ...candidate, auth };
    case 'durable_sealed_record':
    case 'runtime_session_record':
    case 'unknown':
      return { ...candidate, auth };
  }
  throw new Error('[SigningEngine][ecdsa] passkey committed lane requires passkey candidate');
}

function passkeyAuthorityFromRecord(record: ThresholdEcdsaSessionRecord): PasskeyWalletAuthAuthority {
  if (record.source === SIGNER_AUTH_METHODS.emailOtp) {
    throw new Error('[SigningEngine][ecdsa] passkey committed lane requires passkey record source');
  }
  const readyRecord = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(record);
  if (readyRecord.authMethod.kind !== 'passkey') {
    throw new Error('[SigningEngine][ecdsa] passkey committed lane requires passkey record auth');
  }
  return buildPasskeyWalletAuthAuthority({
    walletId: record.walletId,
    rpId: readyRecord.authMethod.rpId,
    credentialIdB64u: readyRecord.authMethod.credentialIdB64u,
  });
}

function assertEcdsaCommittedLaneAuthorityMatchesWallet(args: {
  authority: WalletAuthAuthority;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: EcdsaLaneCandidate;
  context: string;
}): void {
  const authorityWalletId = String(args.authority.walletId);
  if (
    String(args.lane.key.walletId) === authorityWalletId &&
    String(args.candidate.walletId) === authorityWalletId
  ) {
    return;
  }
  throw new Error(
    `[SigningEngine][ecdsa] ${args.context} committed lane authority wallet mismatch`,
  );
}

function requireEcdsaWalletSessionPayload(
  walletSessionJwt: VerifiedWalletSessionJwt,
): Record<string, unknown> {
  const payload = decodeJwtPayloadRecord(walletSessionJwt);
  if (payload?.kind !== ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND) {
    throw new Error('[SigningEngine][ecdsa] committed lane Wallet Session JWT kind is invalid');
  }
  return payload;
}

function requireEcdsaWalletSessionParticipantIds(value: unknown): readonly ParticipantId[] {
  const normalized = normalizeThresholdEd25519ParticipantIds(value);
  if (!normalized || normalized.length < 2) {
    throw new Error(
      '[SigningEngine][ecdsa] committed lane Wallet Session JWT participantIds are invalid',
    );
  }
  return normalized.map(toParticipantId);
}

function assertEcdsaWalletSessionClaimMatches(args: {
  field: string;
  expected: unknown;
  actual: unknown;
}): void {
  if (String(args.expected) === String(args.actual)) return;
  throw new Error(
    `[SigningEngine][ecdsa] committed lane Wallet Session JWT ${args.field} mismatch`,
  );
}

function buildEcdsaCommittedLaneWalletSessionAuthority(args: {
  walletSessionJwt: string;
  walletId: unknown;
  evmFamilySigningKeySlotId: unknown;
  keyHandle: unknown;
  thresholdSessionId: string;
  signingGrantId: string;
}): EcdsaCommittedLaneWalletSessionAuthority {
  const walletSessionAuth = buildEcdsaWalletSessionTransportAuth({
    kind: 'wallet_session_jwt',
    walletSessionJwt: args.walletSessionJwt,
  });
  const identity = buildEcdsaSessionIdentity({
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
  });
  const payload = requireEcdsaWalletSessionPayload(walletSessionAuth.walletSessionJwt);
  const walletId = toWalletId(payload.walletId);
  const evmFamilySigningKeySlotId = requireEvmFamilySigningKeySlotId(
    payload.evmFamilySigningKeySlotId,
  );
  const keyHandle = toEvmFamilyEcdsaKeyHandle(payload.keyHandle);
  const relayerKeyId = parseEcdsaRelayerKeyId(payload.relayerKeyId);
  const claimsIdentity = buildEcdsaSessionIdentity({
    thresholdSessionId: payload.thresholdSessionId,
    signingGrantId: payload.signingGrantId,
  });
  assertEcdsaWalletSessionClaimMatches({
    field: 'walletId',
    expected: args.walletId,
    actual: walletId,
  });
  assertEcdsaWalletSessionClaimMatches({
    field: 'evmFamilySigningKeySlotId',
    expected: args.evmFamilySigningKeySlotId,
    actual: evmFamilySigningKeySlotId,
  });
  assertEcdsaWalletSessionClaimMatches({
    field: 'keyHandle',
    expected: args.keyHandle,
    actual: keyHandle,
  });
  if (
    claimsIdentity.thresholdSessionId !== identity.thresholdSessionId ||
    claimsIdentity.signingGrantId !== identity.signingGrantId
  ) {
    throw new Error('[SigningEngine][ecdsa] committed lane Wallet Session JWT identity mismatch');
  }
  return {
    kind: 'wallet_session_authority',
    walletSessionJwt: walletSessionAuth.walletSessionJwt,
    walletId,
    evmFamilySigningKeySlotId,
    keyHandle,
    relayerKeyId,
    thresholdSessionId: identity.thresholdSessionId,
    signingGrantId: identity.signingGrantId,
    thresholdExpiresAtMs: toWalletSessionThresholdExpiresAtMs(payload.thresholdExpiresAtMs),
    participantIds: requireEcdsaWalletSessionParticipantIds(payload.participantIds),
  };
}

function buildPasskeyEcdsaWalletSessionAuthorityFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
}): PasskeyEcdsaCommittedLaneAuthority {
  const walletSessionAuth = resolveRouterAbEcdsaWalletSessionAuthFromRecord(args.record);
  if (walletSessionAuth.kind === 'ready') {
    return buildEcdsaCommittedLaneWalletSessionAuthority({
      walletSessionJwt: walletSessionAuth.walletSessionJwt,
      walletId: args.record.walletId,
      evmFamilySigningKeySlotId: args.record.evmFamilySigningKeySlotId,
      keyHandle: args.record.keyHandle,
      thresholdSessionId: walletSessionAuth.identity.thresholdSessionId,
      signingGrantId: walletSessionAuth.identity.signingGrantId,
    });
  }
  if (walletSessionAuth.reason === 'cookie_session') {
    return {
      kind: 'passkey_cookie_session_authority',
      thresholdSessionId: args.record.thresholdSessionId,
      signingGrantId: args.record.signingGrantId,
    };
  }
  throw new Error(
    `[SigningEngine][ecdsa] passkey committed lane wallet-session authority unavailable: ${walletSessionAuth.reason}`,
  );
}

function commitPasskeyEcdsaLaneForSelection(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: EcdsaLaneCandidate;
  selected: PasskeyVisibleMaterial;
  material: EcdsaMaterialState;
}): PasskeyEcdsaCommittedLane {
  const candidate = requirePasskeyEcdsaLaneCandidate(args.candidate);
  const authority = passkeyAuthorityFromRecord(args.selected.record);
  assertEcdsaCommittedLaneAuthorityMatchesWallet({
    authority,
    lane: args.lane,
    candidate,
    context: 'passkey selection',
  });
  return {
    source: args.selected.source,
    lane: args.lane,
    authority,
    record: args.selected.record,
    walletSessionAuthority: buildPasskeyEcdsaWalletSessionAuthorityFromRecord({
      record: args.selected.record,
    }),
    material: args.material,
    durableRestore: 'record_restore_metadata',
  };
}

export function commitPasskeyEcdsaLaneFromRecordForMaterial(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  record: ThresholdEcdsaSessionRecord;
  material: EcdsaMaterialState;
  source?: ThresholdEcdsaSessionStoreSource;
}): PasskeyEcdsaCommittedLane {
  const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({ record: args.record });
  const passkeyCandidate = requirePasskeyEcdsaLaneCandidate(candidate);
  const authority = passkeyAuthorityFromRecord(args.record);
  assertEcdsaCommittedLaneAuthorityMatchesWallet({
    authority,
    lane: args.lane,
    candidate: passkeyCandidate,
    context: 'passkey record material',
  });
  return {
    source: passkeySessionStoreSourceFromExactSource(args.source || args.record.source),
    lane: args.lane,
    authority,
    record: args.record,
    walletSessionAuthority: buildPasskeyEcdsaWalletSessionAuthorityFromRecord({
      record: args.record,
    }),
    material: args.material,
    durableRestore: 'record_restore_metadata',
  };
}

export function commitReadyPasskeyEcdsaLaneFromRecord(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  record: ThresholdEcdsaSessionRecord;
  material: ReadyEcdsaMaterial;
  source?: ThresholdEcdsaSessionStoreSource;
}): ReadyPasskeyEcdsaCommittedLane {
  return readyPasskeyEcdsaCommittedLane({
    committedLane: commitPasskeyEcdsaLaneFromRecordForMaterial(args),
    material: args.material,
  });
}

function listPasskeyVisibleMaterials(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
}): PasskeyVisibleMaterial[] {
  const candidates: PasskeyVisibleMaterial[] = [];
  for (const source of PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY) {
    const record = tryGetPasskeyThresholdEcdsaSessionRecordForSigning({
      deps: args.deps,
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      source,
    });
    if (!record) continue;
    candidates.push({
      source,
      record,
    });
  }
  return candidates;
}

function buildEcdsaSelectionDiagnostics(args: {
  candidate: EcdsaLaneCandidate;
  exactCandidateMaterial: EcdsaMaterialState;
  emailOtpRecord?: ThresholdEcdsaSessionRecord;
  passkeyVisibleMaterials: readonly PasskeyVisibleMaterial[];
  passkeySelection: PasskeyMaterialDiagnosticsSelection;
  materialChainTarget: ThresholdEcdsaChainTarget;
}): EcdsaSelectionDiagnostics {
  const selectedPasskeyMaterial =
    args.passkeySelection.kind === 'selected'
      ? summarizeVisibleEcdsaMaterial({
          authMethod: SIGNER_AUTH_METHODS.passkey,
          source: args.passkeySelection.selected.source,
          chainTarget: args.candidate.chainTarget,
          materialChainTarget: args.materialChainTarget,
          record: args.passkeySelection.selected.record,
        })
      : { present: false as const };
  return {
    selectedLaneCandidate: summarizeLaneCandidate(args.candidate),
    exactCandidateMaterial: summarizeEcdsaMaterialState(args.exactCandidateMaterial),
    visibleEmailOtpMaterial: summarizeVisibleEcdsaMaterial({
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      source: SIGNER_AUTH_METHODS.emailOtp,
      chainTarget: args.candidate.chainTarget,
      materialChainTarget: args.materialChainTarget,
      ...(args.emailOtpRecord ? { record: args.emailOtpRecord } : {}),
    }),
    visiblePasskeyMaterials: args.passkeyVisibleMaterials.map((material) =>
      summarizeVisibleEcdsaMaterial({
        authMethod: SIGNER_AUTH_METHODS.passkey,
        source: material.source,
        chainTarget: args.candidate.chainTarget,
        materialChainTarget: args.materialChainTarget,
        record: material.record,
      }),
    ),
    selectedPasskeyMaterial,
  };
}

function selectPasskeyMaterialForCandidate(args: {
  candidate: EcdsaLaneCandidate;
  exactRecord?: ThresholdEcdsaSessionRecord;
  exactSource?: ThresholdEcdsaSessionStoreSource;
  passkeyVisibleMaterials: readonly PasskeyVisibleMaterial[];
  chainTarget: ThresholdEcdsaChainTarget;
  materialChainTarget: ThresholdEcdsaChainTarget;
}): PasskeyMaterialSelectionResult {
  if (args.exactRecord) {
    const exactSource = passkeySessionStoreSourceFromExactSource(args.exactSource);
    const exactMaterial = buildEcdsaMaterialStateForCandidate({
      candidate: args.candidate,
      record: args.exactRecord,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      source: exactSource,
      chainTarget: args.chainTarget,
      materialChainTarget: args.materialChainTarget,
    });
    if (exactMaterial.kind === 'ready_to_sign') {
      return {
        kind: 'selected',
        material: exactMaterial,
        selected: {
          source: exactSource,
          record: exactMaterial.record,
        },
      };
    }
    if (exactMaterial.kind === 'reauth_required') {
      return {
        kind: 'selected',
        material: exactMaterial,
        selected: {
          source: exactSource,
          record: exactMaterial.record,
        },
      };
    }
  }
  for (const candidateMaterial of args.passkeyVisibleMaterials) {
    const material = buildEcdsaMaterialStateForCandidate({
      candidate: args.candidate,
      record: candidateMaterial.record,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      source: candidateMaterial.source,
      chainTarget: args.chainTarget,
      materialChainTarget: args.materialChainTarget,
    });
    if (material.kind === 'ready_to_sign') {
      return { kind: 'selected', material, selected: candidateMaterial };
    }
    if (material.kind === 'reauth_required') {
      return { kind: 'selected', material, selected: candidateMaterial };
    }
  }
  return {
    kind: 'missing',
    material: buildEcdsaMaterialStateForCandidate({
      candidate: args.candidate,
      record: undefined,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      source: 'manual-bootstrap',
      chainTarget: args.chainTarget,
      materialChainTarget: args.materialChainTarget,
    }),
  };
}

function selectSessionSourceForWalletAuth(args: {
  emailOtpCommittedLane?: EmailOtpEcdsaCommittedLane;
  passkeySelection: PasskeyMaterialDiagnosticsSelection;
}): { sessionSource?: string; isEmailOtpThresholdContext?: boolean } {
  const hasEmailOtpVisible = Boolean(args.emailOtpCommittedLane);
  const hasPasskeyVisible = args.passkeySelection.kind === 'selected';
  if (hasEmailOtpVisible === hasPasskeyVisible) return {};
  if (hasEmailOtpVisible) {
    return {
      sessionSource: SIGNER_AUTH_METHODS.emailOtp,
      isEmailOtpThresholdContext: true,
    };
  }
  if (args.passkeySelection.kind !== 'selected') return {};
  return {
    sessionSource:
      args.passkeySelection.selected.record.source || args.passkeySelection.selected.source,
    isEmailOtpThresholdContext: false,
  };
}

async function resolveEmailOtpAuthorityForSelection(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: EcdsaLaneCandidate;
  record: ThresholdEcdsaSessionRecord | null;
}): Promise<EmailOtpSelectionAuthority | null> {
  const exactLane = exactEcdsaSigningLaneIdentityFromSelectedLane(args.lane);
  if (args.record) {
    if (args.record.source !== SIGNER_AUTH_METHODS.emailOtp) {
      logEvmFamilyEcdsaLaneDiagnostic('Email OTP exact ECDSA record rejected for source', {
        lane: summarizeEvmFamilyEcdsaLane(args.lane),
        record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
      });
      return null;
    }
    const recordAuthority = resolveEmailOtpEcdsaSigningSessionAuthorityFromRecord(args.record);
    if (recordAuthority.kind !== 'ready') {
      logEvmFamilyEcdsaLaneDiagnostic('Email OTP exact ECDSA record rejected for authority', {
        rejection: recordAuthority,
        lane: summarizeEvmFamilyEcdsaLane(args.lane),
        record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
      });
      return null;
    }
    return {
      kind: 'record_backed',
      record: args.record,
      laneAuthority: recordAuthority.authority,
    };
  }
  logEvmFamilyEcdsaLaneDiagnostic('Email OTP exact ECDSA record-backed authority not found', {
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
  });
  const laneAuthority = await args.deps.resolveEmailOtpEcdsaSigningSessionAuthority({
    lane: exactLane,
    chain: args.lane.chainTarget.kind,
  });
  if (laneAuthority) {
    return {
      kind: 'resolver_backed',
      laneAuthority,
    };
  }
  logEvmFamilyEcdsaLaneDiagnostic('Email OTP exact ECDSA resolver authority not found', {
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
    candidate: summarizeLaneCandidate(args.candidate),
  });
  return null;
}

function exactEmailOtpEcdsaRecordForLane(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
}): ThresholdEcdsaSessionRecord | null {
  const record = findExactEcdsaSessionRecordForSelectedLane(args);
  return matchingEmailOtpRecordForLane({ record, lane: args.lane });
}

function matchingEmailOtpRecordForLane(args: {
  record: ThresholdEcdsaSessionRecord | null | undefined;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
}): ThresholdEcdsaSessionRecord | null {
  const record = args.record || null;
  if (!record || record.source !== SIGNER_AUTH_METHODS.emailOtp) return null;
  if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, args.lane.chainTarget)) {
    return null;
  }
  try {
    const matches =
      exactSigningLaneIdentityKey(toExactEcdsaSigningLaneIdentity(record)) ===
      exactSigningLaneIdentityKey(exactEcdsaSigningLaneIdentityFromSelectedLane(args.lane));
    return matches ? record : null;
  } catch {
    return null;
  }
}

function requireEmailOtpSelectionAuthority(args: {
  authority: EmailOtpSelectionAuthority | null;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: EcdsaLaneCandidate;
}): EmailOtpSelectionAuthority {
  if (args.authority) return args.authority;
  logEvmFamilyEcdsaLaneDiagnostic('Email OTP exact ECDSA signing-session authority missing', {
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
    candidate: summarizeLaneCandidate(args.candidate),
  });
  throwEmailOtpEcdsaCommittedLaneStateError({ kind: 'authority_missing' });
}

function requireEmailOtpEcdsaSigningSessionAuthLane(args: {
  authority: EmailOtpSelectionAuthority;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: EcdsaLaneCandidate;
}): Extract<EmailOtpSigningSessionAuthLane, { curve: 'ecdsa' }> {
  const authLane = args.authority.laneAuthority.authLane;
  if (
    authLane.kind === 'signing_session' &&
    authLane.curve === 'ecdsa' &&
    thresholdEcdsaChainTargetsEqual(authLane.chainTarget, args.lane.chainTarget)
  ) {
    return authLane;
  }
  logEvmFamilyEcdsaLaneDiagnostic('Email OTP ECDSA committed lane rejected for authority shape', {
    authorityKind: authLane.kind,
    authorityCurve: authLane.kind === 'signing_session' ? authLane.curve : null,
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
    candidate: summarizeLaneCandidate(args.candidate),
  });
  throwEmailOtpEcdsaCommittedLaneStateError({ kind: 'authority_not_ecdsa_signing_session' });
}

function requireEmailOtpCommittedLaneForReauth(args: {
  committedLane: EmailOtpEcdsaCommittedLane | null;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: EcdsaLaneCandidate;
  reason: ReauthRequiredEvmFamilyEcdsaSigningSelection['reason'];
}): EmailOtpEcdsaCommittedLane {
  if (args.committedLane) return args.committedLane;
  logEvmFamilyEcdsaLaneDiagnostic('Email OTP ECDSA committed lane missing for reauth', {
    reason: args.reason,
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
    candidate: summarizeLaneCandidate(args.candidate),
  });
  throwEmailOtpEcdsaCommittedLaneStateError({
    kind: 'committed_lane_missing_for_reauth',
    reason: args.reason,
  });
}

function requirePasskeyCommittedLaneForReauth(args: {
  committedLane: PasskeyEcdsaCommittedLane | null;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: EcdsaLaneCandidate;
  reason: ReauthRequiredEvmFamilyEcdsaSigningSelection['reason'];
}): PasskeyEcdsaCommittedLane {
  if (args.committedLane) return args.committedLane;
  logEvmFamilyEcdsaLaneDiagnostic('Passkey ECDSA committed lane missing for reauth', {
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
    candidate: summarizeLaneCandidate(args.candidate),
    reason: args.reason,
  });
  throw new Error(
    `Passkey ECDSA committed lane is unavailable for ${args.reason} reauth; unlock wallet again`,
  );
}

function requireEmailOtpCommittedLaneForReady(args: {
  committedLane: EmailOtpEcdsaCommittedLane | null;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: EcdsaLaneCandidate;
}): EmailOtpEcdsaCommittedLane {
  if (args.committedLane) return args.committedLane;
  logEvmFamilyEcdsaLaneDiagnostic('Email OTP ECDSA committed lane missing for ready signing', {
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
    candidate: summarizeLaneCandidate(args.candidate),
  });
  throwEmailOtpEcdsaCommittedLaneStateError({ kind: 'committed_lane_missing_for_ready' });
}

function buildEmailOtpEcdsaWalletSessionAuthority(args: {
  authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ecdsa' }>;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
}): EmailOtpEcdsaCommittedLane['walletSessionAuthority'] {
  return buildEcdsaCommittedLaneWalletSessionAuthority({
    walletSessionJwt: args.authLane.jwt,
    walletId: args.lane.key.walletId,
    evmFamilySigningKeySlotId: args.lane.key.evmFamilySigningKeySlotId,
    keyHandle: args.lane.keyHandle,
    thresholdSessionId: args.authLane.thresholdSessionId,
    signingGrantId: String(args.authLane.authorizingSigningGrantId),
  });
}

function commitEmailOtpEcdsaLaneForSelection(args: {
  authority: EmailOtpSelectionAuthority;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: EcdsaLaneCandidate;
  material: EcdsaMaterialState;
}): EmailOtpEcdsaCommittedLane {
  const authLane = requireEmailOtpEcdsaSigningSessionAuthLane({
    authority: args.authority,
    lane: args.lane,
    candidate: args.candidate,
  });
  const authority = args.authority.laneAuthority.authority;
  assertEcdsaCommittedLaneAuthorityMatchesWallet({
    authority,
    lane: args.lane,
    candidate: args.candidate,
    context: 'Email OTP',
  });
  const common = {
    lane: args.lane,
    authority,
    authLane,
    walletSessionAuthority: buildEmailOtpEcdsaWalletSessionAuthority({
      authLane,
      lane: args.lane,
    }),
    material: args.material,
  };
  switch (args.authority.kind) {
    case 'record_backed':
      return {
        ...common,
        source: 'record_backed',
        record: args.authority.record,
        durableRestore: 'record_restore_metadata',
      };
    case 'resolver_backed':
      return {
        ...common,
        source: 'resolver_backed',
        durableRestore: 'resolver_restore_metadata',
      };
  }
}

function requireEmailOtpSelectionAuthorityFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: EcdsaLaneCandidate;
}): EmailOtpSelectionAuthority {
  if (args.record.source !== SIGNER_AUTH_METHODS.emailOtp) {
    logEvmFamilyEcdsaLaneDiagnostic('Email OTP record-backed committed lane rejected for source', {
      lane: summarizeEvmFamilyEcdsaLane(args.lane),
      candidate: summarizeLaneCandidate(args.candidate),
      record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
    });
    throwEmailOtpEcdsaCommittedLaneStateError({ kind: 'authority_missing' });
  }
  const resolved = resolveEmailOtpEcdsaSigningSessionAuthorityFromRecord(args.record);
  if (resolved.kind === 'ready') {
    return {
      kind: 'record_backed',
      record: args.record,
      laneAuthority: resolved.authority,
    };
  }
  logEvmFamilyEcdsaLaneDiagnostic('Email OTP record-backed committed lane rejected', {
    rejection: resolved,
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
    candidate: summarizeLaneCandidate(args.candidate),
    record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
  });
  throwEmailOtpEcdsaCommittedLaneStateError({ kind: 'authority_missing' });
}

export function commitEmailOtpEcdsaLaneFromRecordForMaterial(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  record: ThresholdEcdsaSessionRecord;
  material: EcdsaMaterialState;
}): EmailOtpEcdsaCommittedLane {
  const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({ record: args.record });
  const authority = requireEmailOtpSelectionAuthority({
    authority: requireEmailOtpSelectionAuthorityFromRecord({
      record: args.record,
      lane: args.lane,
      candidate,
    }),
    lane: args.lane,
    candidate,
  });
  return commitEmailOtpEcdsaLaneForSelection({
    authority,
    lane: args.lane,
    candidate,
    material: args.material,
  });
}

export function commitReadyEmailOtpEcdsaLaneFromRecord(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  record: ThresholdEcdsaSessionRecord;
  material: ReadyEcdsaMaterial;
}): ReadyEmailOtpEcdsaCommittedLane {
  return readyEmailOtpEcdsaCommittedLane({
    lane: args.lane,
    committedLane: commitEmailOtpEcdsaLaneFromRecordForMaterial(args),
    material: args.material,
  });
}

export async function resolveEvmFamilyEcdsaSigningSelection(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  walletId: WalletId;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  authMethod: EvmFamilyEcdsaAuthMethod;
  laneCandidate: EcdsaLaneCandidate;
  reauthAnchor?: ReauthAnchorIdentity;
  allowMissingHotMaterial?: boolean;
}): Promise<EvmFamilyEcdsaSigningSelectionResult> {
  const lane = resolvedEvmFamilyEcdsaSigningLaneFromCandidate(args.laneCandidate);
  const emailOtpAuthorityLane = emailOtpAuthorityLaneFromCandidate({
    candidate: args.laneCandidate,
    selectedLane: lane,
  });
  const materialChainTarget =
    args.laneCandidate.source === 'evm_family_shared_key'
      ? args.laneCandidate.sourceChainTarget
      : args.chainTarget;
  const exactRecordForCandidate =
    args.laneCandidate.source === 'evm_family_shared_key'
      ? undefined
      : findExactEcdsaSessionRecordForSelectedLane({
          deps: args.deps,
          lane,
        });
  const candidateAuthMethod = ecdsaLaneCandidateAuthMethod(args.laneCandidate);
  const visibleEmailOtpRecord =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? exactEmailOtpEcdsaRecordForLane({
          deps: args.deps,
          lane: emailOtpAuthorityLane,
        })
      : null;
  const emailOtpAuthority =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? await resolveEmailOtpAuthorityForSelection({
          deps: args.deps,
          lane: emailOtpAuthorityLane,
          candidate: args.laneCandidate,
          record: visibleEmailOtpRecord,
        })
      : null;
  const requiredEmailOtpAuthority =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? requireEmailOtpSelectionAuthority({
          authority: emailOtpAuthority,
          lane: emailOtpAuthorityLane,
          candidate: args.laneCandidate,
        })
      : null;
  const emailOtpMaterialRecord =
    requiredEmailOtpAuthority?.kind === 'record_backed' ? requiredEmailOtpAuthority.record : null;
  const passkeyVisibleMaterials = listPasskeyVisibleMaterials({
    deps: args.deps,
    walletId: args.walletId,
    chainTarget: materialChainTarget,
  });
  const exactCandidateMaterial =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? buildEcdsaMaterialStateForCandidate({
          candidate: args.laneCandidate,
          record: emailOtpMaterialRecord || undefined,
          authMethod: SIGNER_AUTH_METHODS.emailOtp,
          source: SIGNER_AUTH_METHODS.emailOtp,
          chainTarget: args.chainTarget,
          materialChainTarget,
        })
      : selectPasskeyMaterialForCandidate({
          candidate: args.laneCandidate,
          exactRecord: exactRecordForCandidate,
          exactSource: exactRecordForCandidate?.source || undefined,
          passkeyVisibleMaterials,
          chainTarget: args.chainTarget,
          materialChainTarget,
        }).material;

  const selectedPasskeyMaterial: PasskeyMaterialDiagnosticsSelection =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? { kind: 'not_applicable', reason: 'email_otp_candidate' }
      : selectPasskeyMaterialForCandidate({
          candidate: args.laneCandidate,
          exactRecord: exactRecordForCandidate,
          exactSource: exactRecordForCandidate?.source || undefined,
          passkeyVisibleMaterials,
          chainTarget: args.chainTarget,
          materialChainTarget,
        });

  const committedEmailOtpLane =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp && requiredEmailOtpAuthority
      ? commitEmailOtpEcdsaLaneForSelection({
          authority: requiredEmailOtpAuthority,
          lane: emailOtpAuthorityLane,
          candidate: args.laneCandidate,
          material: exactCandidateMaterial,
        })
      : null;
  const committedPasskeyLane =
    candidateAuthMethod === SIGNER_AUTH_METHODS.passkey &&
    selectedPasskeyMaterial.kind === 'selected'
      ? commitPasskeyEcdsaLaneForSelection({
          lane,
          candidate: args.laneCandidate,
          selected: selectedPasskeyMaterial.selected,
          material: exactCandidateMaterial,
        })
      : null;
  const walletAuthInputs = selectSessionSourceForWalletAuth({
    ...(committedEmailOtpLane ? { emailOtpCommittedLane: committedEmailOtpLane } : {}),
    passkeySelection: selectedPasskeyMaterial,
  });
  const walletAuth = await resolveEvmFamilyTransactionWalletAuth({
    deps: args.deps,
    walletId: args.walletId,
    senderSignatureAlgorithm: args.senderSignatureAlgorithm,
    chainTarget: args.chainTarget,
    ...(walletAuthInputs.sessionSource ? { sessionSource: walletAuthInputs.sessionSource } : {}),
    ...(typeof walletAuthInputs.isEmailOtpThresholdContext === 'boolean'
      ? { isEmailOtpThresholdContext: walletAuthInputs.isEmailOtpThresholdContext }
      : {}),
  });
  const selectedAccountAuth = walletAuthWithSelectedPrimary(walletAuth, candidateAuthMethod);

  const diagnostics = buildEcdsaSelectionDiagnostics({
    candidate: args.laneCandidate,
    exactCandidateMaterial,
    ...(emailOtpMaterialRecord ? { emailOtpRecord: emailOtpMaterialRecord } : {}),
    passkeyVisibleMaterials,
    materialChainTarget,
    passkeySelection: selectedPasskeyMaterial,
  });

  if (
    !args.allowMissingHotMaterial &&
    exactEcdsaCandidateRequiresHotMaterial(args.laneCandidate) &&
    exactCandidateMaterial.kind !== 'ready_to_sign'
  ) {
    return {
      kind: 'missing_material',
      accountAuth: selectedAccountAuth,
      authMethod: candidateAuthMethod,
      candidate: args.laneCandidate,
      material: exactCandidateMaterial,
      diagnostics,
    };
  }

  if (args.laneCandidate.state === 'expired') {
    if (candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
      const reauthLane = requireEmailOtpCommittedLaneForReauth({
        committedLane: committedEmailOtpLane,
        lane,
        candidate: args.laneCandidate,
        reason: 'expired',
      });
      return emailOtpReauthRequiredSelection({
        accountAuth: selectedAccountAuth,
        lane,
        material: exactCandidateMaterial,
        reason: 'expired',
        committedLane: reauthLane,
        ...(args.reauthAnchor ? { reauthAnchor: args.reauthAnchor } : {}),
        diagnostics,
      });
    }
    const reauthLane = requirePasskeyCommittedLaneForReauth({
      committedLane: committedPasskeyLane,
      lane,
      candidate: args.laneCandidate,
      reason: 'expired',
    });
    return passkeyReauthRequiredSelection({
      accountAuth: selectedAccountAuth,
      lane,
      material: exactCandidateMaterial,
      reason: 'expired',
      committedLane: reauthLane,
      ...(args.reauthAnchor ? { reauthAnchor: args.reauthAnchor } : {}),
      diagnostics,
    });
  }

  if (args.laneCandidate.state === 'exhausted') {
    if (candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
      const reauthLane = requireEmailOtpCommittedLaneForReauth({
        committedLane: committedEmailOtpLane,
        lane,
        candidate: args.laneCandidate,
        reason: 'exhausted',
      });
      return emailOtpReauthRequiredSelection({
        accountAuth: selectedAccountAuth,
        lane,
        material: exactCandidateMaterial,
        reason: 'exhausted',
        committedLane: reauthLane,
        ...(args.reauthAnchor ? { reauthAnchor: args.reauthAnchor } : {}),
        diagnostics,
      });
    }
    const reauthLane = requirePasskeyCommittedLaneForReauth({
      committedLane: committedPasskeyLane,
      lane,
      candidate: args.laneCandidate,
      reason: 'exhausted',
    });
    return passkeyReauthRequiredSelection({
      accountAuth: selectedAccountAuth,
      lane,
      material: exactCandidateMaterial,
      reason: 'exhausted',
      committedLane: reauthLane,
      ...(args.reauthAnchor ? { reauthAnchor: args.reauthAnchor } : {}),
      diagnostics,
    });
  }

  if (exactCandidateMaterial.kind !== 'ready_to_sign') {
    if (candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
      const reauthLane = requireEmailOtpCommittedLaneForReauth({
        committedLane: committedEmailOtpLane,
        lane,
        candidate: args.laneCandidate,
        reason: 'missing_hot_material',
      });
      return emailOtpReauthRequiredSelection({
        accountAuth: selectedAccountAuth,
        lane,
        material: exactCandidateMaterial,
        reason: 'missing_hot_material',
        committedLane: reauthLane,
        diagnostics,
      });
    }
    if (!committedPasskeyLane) {
      logEvmFamilyEcdsaLaneDiagnostic('Passkey ECDSA material requires restore before reauth', {
        lane: summarizeEvmFamilyEcdsaLane(lane),
        candidate: summarizeLaneCandidate(args.laneCandidate),
        material: summarizeEcdsaMaterialState(exactCandidateMaterial),
      });
      return {
        kind: 'missing_material',
        accountAuth: selectedAccountAuth,
        authMethod: SIGNER_AUTH_METHODS.passkey,
        candidate: args.laneCandidate,
        material: exactCandidateMaterial,
        diagnostics,
      };
    }
    const reauthLane = requirePasskeyCommittedLaneForReauth({
      committedLane: committedPasskeyLane,
      lane,
      candidate: args.laneCandidate,
      reason: 'missing_hot_material',
    });
    return passkeyReauthRequiredSelection({
      accountAuth: selectedAccountAuth,
      lane,
      material: exactCandidateMaterial,
      reason: 'missing_hot_material',
      committedLane: reauthLane,
      diagnostics,
    });
  }

  if (candidateAuthMethod !== exactCandidateMaterial.authMethod) {
    logEvmFamilyEcdsaLaneDiagnostic('selected ECDSA material auth method mismatch', {
      lane: summarizeEvmFamilyEcdsaLane(lane),
      material: summarizeEcdsaMaterialState(exactCandidateMaterial),
    });
    throw new Error('[SigningEngine][ecdsa] selected ECDSA material auth method mismatch');
  }

  if (candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
    const committedLane = requireEmailOtpCommittedLaneForReady({
      committedLane: committedEmailOtpLane,
      lane,
      candidate: args.laneCandidate,
    });
    const readyCommittedLane = readyEmailOtpEcdsaCommittedLane({
      lane,
      committedLane,
      material: exactCandidateMaterial,
    });
    return {
      kind: 'ready',
      accountAuth: selectedAccountAuth,
      authMethod: ecdsaCommittedLaneAuthMethod(readyCommittedLane),
      source: exactCandidateMaterial.source,
      lane,
      material: exactCandidateMaterial,
      committedLane: readyCommittedLane,
      diagnostics,
    };
  }

  const readyCommittedLane = readyPasskeyEcdsaCommittedLane({
    committedLane:
      committedPasskeyLane ||
      commitPasskeyEcdsaLaneFromRecordForMaterial({
        lane,
        record: exactCandidateMaterial.record,
        material: exactCandidateMaterial,
        source: exactCandidateMaterial.source,
      }),
    material: exactCandidateMaterial,
  });
  return {
    kind: 'ready',
    accountAuth: selectedAccountAuth,
    authMethod: ecdsaCommittedLaneAuthMethod(readyCommittedLane),
    source: exactCandidateMaterial.source,
    lane,
    material: exactCandidateMaterial,
    committedLane: readyCommittedLane,
    diagnostics,
  };
}
