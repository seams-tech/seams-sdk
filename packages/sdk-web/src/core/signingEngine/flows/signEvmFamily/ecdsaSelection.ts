import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { SignerAuthMethod } from '@shared/utils/signerDomain';
import type {
  EcdsaLaneCandidate,
  ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import { laneCandidateAuthMethod } from '../../session/identity/laneIdentity';
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
  type EcdsaMaterialState,
  type EcdsaMaterialSummary,
  type MissingEcdsaMaterial,
  type ReadyEcdsaMaterial,
} from './ecdsaMaterialState';
import {
  logEvmFamilyEcdsaLaneDiagnostic,
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaLane,
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type {
  DurableEmailOtpEcdsaSigningSessionAuthorityResolver,
  EvmFamilyEcdsaSessionReaderDeps,
  PasskeyEcdsaSessionStoreSource,
} from '../../interfaces/operationDeps';
import type { EmailOtpEcdsaSigningSessionAuthority } from '../../session/emailOtp/ecdsaSigningSessionAuthority';
import {
  exactEcdsaSigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityKey,
} from '../../session/identity/exactSigningLaneIdentity';
import { toEvmFamilyEcdsaKeyHandle } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { EvmFamilyChain, EvmFamilySenderSignatureAlgorithm } from './types';
import {
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ReauthAnchorIdentity } from '../../session/operationState/transactionState';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EcdsaReauthAnchorPublicRestore } from '../../session/persistence/sealedSessionStore';
import {
  buildEcdsaWalletSessionAuthority,
  type EcdsaWalletSessionAuthority,
} from '../../session/identity/ecdsaWalletSessionAuthority';

export type EvmFamilyEcdsaSigningSelectionDeps = EvmFamilyAccountMetadataDeps &
  EvmFamilyEcdsaSessionReaderDeps &
  DurableEmailOtpEcdsaSigningSessionAuthorityResolver;

type EcdsaSelectionLaneCandidateDiagnosticsBase = {
  authMethod: EvmFamilyEcdsaAuthMethod;
  chain: EcdsaLaneCandidate['chain'];
  chainTarget: ThresholdEcdsaChainTarget;
  state: EcdsaLaneCandidate['state'];
  walletSessionId: string;
  materialActivationId: string;
  remainingUses: number;
  expiresAtMs: number;
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
  reauthLane: EcdsaPublicReauthLane;
  committedLane?: never;
};

type MaterialBackedEvmFamilyEcdsaSigningSelection = {
  reason: 'missing_hot_material';
  committedLane: EcdsaCommittedLane;
  reauthLane?: never;
};

export type ReauthRequiredEvmFamilyEcdsaSigningSelection =
  | (ReauthRequiredEvmFamilyEcdsaSigningSelectionBase &
      ReauthAnchorBackedEvmFamilyEcdsaSigningSelection & {
        authMethod: 'email_otp';
        reauthLane: EmailOtpEcdsaPublicReauthLane;
      })
  | (ReauthRequiredEvmFamilyEcdsaSigningSelectionBase &
      ReauthAnchorBackedEvmFamilyEcdsaSigningSelection & {
        authMethod: 'passkey';
        reauthLane: PasskeyEcdsaPublicReauthLane;
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

export type MissingMaterialEvmFamilyEcdsaSigningSelection = {
  kind: 'missing_material';
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  candidate: EcdsaLaneCandidate;
  material: EcdsaMaterialState;
  diagnostics: EcdsaSelectionDiagnostics;
};

type RestoreRequiredPasskeyEcdsaLaneCandidate = EcdsaLaneCandidate & {
  auth: Extract<EcdsaLaneCandidate['auth'], { kind: 'passkey' }>;
  state: 'restorable' | 'deferred';
};

export type RestoreRequiredEvmFamilyEcdsaSigningSelection = {
  kind: 'restore_required';
  accountAuth: AccountAuthMetadata;
  authMethod: 'passkey';
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: RestoreRequiredPasskeyEcdsaLaneCandidate;
  material: MissingEcdsaMaterial & { authMethod: 'passkey' };
  restoreChainTarget: ThresholdEcdsaChainTarget;
  diagnostics: EcdsaSelectionDiagnostics;
};

export type EvmFamilyEcdsaSigningSelectionResult =
  | ReadyEvmFamilyEcdsaSigningSelection
  | ReauthRequiredEvmFamilyEcdsaSigningSelection
  | RestoreRequiredEvmFamilyEcdsaSigningSelection
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
export function ecdsaCommittedLaneAuthMethod(lane: EcdsaCommittedLane): EvmFamilyEcdsaAuthMethod;
export function ecdsaCommittedLaneAuthMethod(lane: EcdsaCommittedLane): EvmFamilyEcdsaAuthMethod {
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

function buildPasskeyEcdsaPublicReauthLane(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: EcdsaMaterialState;
  reauthAnchor: ReauthAnchorIdentity;
  publicRestore: Extract<
    EcdsaReauthAnchorPublicRestore,
    { source: Exclude<EcdsaReauthAnchorPublicRestore['source'], 'email_otp'> }
  >;
}): PasskeyEcdsaPublicReauthLane {
  const laneIdentityKey = exactSigningLaneIdentityKey(
    exactEcdsaSigningLaneIdentityFromSelectedLane(args.lane),
  );
  if (laneIdentityKey !== args.reauthAnchor.laneIdentityKey) {
    throw new Error('[SigningEngine][ecdsa] passkey public reauth anchor identity mismatch');
  }
  if (!thresholdEcdsaChainTargetsEqual(args.publicRestore.chainTarget, args.lane.chainTarget)) {
    throw new Error('[SigningEngine][ecdsa] passkey public reauth anchor target mismatch');
  }
  return {
    kind: 'public_reauth_lane',
    lane: args.lane,
    authority: buildPasskeyWalletAuthAuthority({
      walletId: args.lane.key.walletId,
      rpId: args.publicRestore.rpId,
      credentialIdB64u: args.publicRestore.credentialIdB64u,
    }),
    publicRestore: args.publicRestore,
    reauthAnchor: args.reauthAnchor,
    material: args.material,
  };
}

function buildEmailOtpEcdsaPublicReauthLane(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: EcdsaMaterialState;
  reauthAnchor: ReauthAnchorIdentity;
  publicRestore: Extract<EcdsaReauthAnchorPublicRestore, { source: 'email_otp' }>;
}): EmailOtpEcdsaPublicReauthLane {
  const laneIdentityKey = exactSigningLaneIdentityKey(
    exactEcdsaSigningLaneIdentityFromSelectedLane(args.lane),
  );
  if (laneIdentityKey !== args.reauthAnchor.laneIdentityKey) {
    throw new Error('[SigningEngine][ecdsa] Email OTP public reauth anchor identity mismatch');
  }
  if (!thresholdEcdsaChainTargetsEqual(args.publicRestore.chainTarget, args.lane.chainTarget)) {
    throw new Error('[SigningEngine][ecdsa] Email OTP public reauth anchor target mismatch');
  }
  return {
    kind: 'public_reauth_lane',
    lane: args.lane,
    authority: buildEmailOtpWalletAuthAuthority({
      walletId: args.lane.key.walletId,
      provider: args.publicRestore.provider,
      providerUserId: args.publicRestore.providerSubjectId,
      emailHashHex: args.publicRestore.emailHashHex,
    }),
    publicRestore: args.publicRestore,
    reauthAnchor: args.reauthAnchor,
    material: args.material,
  };
}

type PasskeyReauthRequiredSelectionInput = {
  accountAuth: AccountAuthMetadata;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: EcdsaMaterialState;
  diagnostics: EcdsaSelectionDiagnostics;
} & (
  | {
      reason: 'expired' | 'exhausted';
      reauthLane: PasskeyEcdsaPublicReauthLane;
      committedLane?: never;
    }
  | {
      reason: 'missing_hot_material';
      committedLane: PasskeyEcdsaCommittedLane;
      reauthLane?: never;
    }
);

function passkeyReauthRequiredSelection(
  args: PasskeyReauthRequiredSelectionInput,
): Extract<ReauthRequiredEvmFamilyEcdsaSigningSelection, { authMethod: 'passkey' }> {
  switch (args.reason) {
    case 'expired':
    case 'exhausted':
      return {
        kind: 'reauth_required',
        accountAuth: args.accountAuth,
        authMethod: 'passkey',
        lane: args.lane,
        material: args.material,
        reason: args.reason,
        reauthLane: args.reauthLane,
        diagnostics: args.diagnostics,
      };
    case 'missing_hot_material':
      return {
        kind: 'reauth_required',
        accountAuth: args.accountAuth,
        authMethod: 'passkey',
        lane: args.lane,
        material: args.material,
        reason: 'missing_hot_material',
        committedLane: args.committedLane,
        diagnostics: args.diagnostics,
      };
  }
}

type EmailOtpReauthRequiredSelectionInput = {
  accountAuth: AccountAuthMetadata;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: EcdsaMaterialState;
  diagnostics: EcdsaSelectionDiagnostics;
} & (
  | {
      reason: 'expired' | 'exhausted';
      reauthLane: EmailOtpEcdsaPublicReauthLane;
      committedLane?: never;
    }
  | {
      reason: 'missing_hot_material';
      committedLane: EmailOtpEcdsaCommittedLane;
      reauthLane?: never;
    }
);

function emailOtpReauthRequiredSelection(
  args: EmailOtpReauthRequiredSelectionInput,
): Extract<ReauthRequiredEvmFamilyEcdsaSigningSelection, { authMethod: 'email_otp' }> {
  switch (args.reason) {
    case 'expired':
    case 'exhausted':
      return {
        kind: 'reauth_required',
        accountAuth: args.accountAuth,
        authMethod: 'email_otp',
        lane: args.lane,
        material: args.material,
        reason: args.reason,
        reauthLane: args.reauthLane,
        diagnostics: args.diagnostics,
      };
    case 'missing_hot_material':
      return {
        kind: 'reauth_required',
        accountAuth: args.accountAuth,
        authMethod: 'email_otp',
        lane: args.lane,
        material: args.material,
        reason: 'missing_hot_material',
        committedLane: args.committedLane,
        diagnostics: args.diagnostics,
      };
  }
}

function passkeyRestoreRequiredSelection(args: {
  accountAuth: AccountAuthMetadata;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: RestoreRequiredPasskeyEcdsaLaneCandidate;
  material: MissingEcdsaMaterial & { authMethod: 'passkey' };
  restoreChainTarget: ThresholdEcdsaChainTarget;
  diagnostics: EcdsaSelectionDiagnostics;
}): RestoreRequiredEvmFamilyEcdsaSigningSelection {
  return {
    kind: 'restore_required',
    accountAuth: args.accountAuth,
    authMethod: SIGNER_AUTH_METHODS.passkey,
    lane: args.lane,
    candidate: args.candidate,
    material: args.material,
    restoreChainTarget: args.restoreChainTarget,
    diagnostics: args.diagnostics,
  };
}

function isRestoreRequiredPasskeyEcdsaLaneCandidate(
  candidate: EcdsaLaneCandidate,
): candidate is RestoreRequiredPasskeyEcdsaLaneCandidate {
  return (
    candidate.auth.kind === SIGNER_AUTH_METHODS.passkey &&
    (candidate.state === 'restorable' || candidate.state === 'deferred')
  );
}

function isMissingPasskeyEcdsaMaterial(
  material: EcdsaMaterialState,
): material is MissingEcdsaMaterial & { authMethod: 'passkey' } {
  return (
    material.kind === 'public_identity_unavailable' &&
    material.authMethod === SIGNER_AUTH_METHODS.passkey
  );
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
    materialActivation: candidate.materialActivation,
    keyHandle: candidate.keyHandle,
    walletId: candidate.walletId,
    chainTarget: candidate.chainTarget,
    authorization: candidate.authorization,
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
    walletSessionId: candidate.authorization.projection.walletSessionId,
    materialActivationId: candidate.materialActivation.activationId,
    remainingUses: candidate.authorization.status.remainingUses,
    expiresAtMs: candidate.authorization.status.expiresAtMs,
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
    case 'canonical_capability':
    case 'unknown':
      return {
        ...base,
        source: candidate.source,
      };
  }
}

// Canonical candidate facts for an already-resolved lane. The lane identity
// carries the exact signer binding and active authorization, so no record is
// consulted; this replaces every record-derived candidate construction.
function ecdsaLaneCandidateFromResolvedLane(
  lane: ResolvedEvmFamilyEcdsaSigningLane,
): EcdsaLaneCandidate {
  const signer = requireEvmFamilyEcdsaSignerForSelection(lane, 'ECDSA lane candidate');
  return {
    kind: 'lane_candidate',
    walletId: signer.walletId,
    key: signer.key,
    materialActivation: signer.materialActivation,
    keyHandle: signer.keyHandle,
    auth: lane.auth,
    authorization: lane.authorization,
    curve: 'ecdsa',
    chain: lane.chainFamily,
    state: 'ready',
    source: 'canonical_capability',
    chainTarget: signer.chainTarget,
  };
}

function requireEvmFamilyEcdsaSignerForSelection(
  lane: ResolvedEvmFamilyEcdsaSigningLane,
  context: string,
) {
  const identity = exactEcdsaSigningLaneIdentityFromSelectedLane(lane);
  const signer = identity.signer;
  if (signer.kind !== 'evm_family_ecdsa_signer') {
    throw new Error(`[SigningEngine][ecdsa] ${context} requires an EVM-family ECDSA signer`);
  }
  return signer;
}

type PasskeyMaterialSelectionResult = {
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

// Sealed-record authority is the only form built: the durable resolver either
// finds the exact authority or the selection has none.
type EmailOtpSelectionAuthority = {
  kind: 'durable_authority_backed';
  laneAuthority: EmailOtpEcdsaSigningSessionAuthority;
};

export type PasskeyEcdsaCommittedLaneAuthority =
  | EcdsaWalletSessionAuthority
  | {
      kind: 'passkey_cookie_session_authority';
      thresholdSessionId: string;
      signingGrantId: string;
      walletSessionJwt?: never;
    };

type EcdsaWalletSessionAuthorityFor<A extends WalletAuthAuthority> =
  A extends PasskeyWalletAuthAuthority
    ? PasskeyEcdsaCommittedLaneAuthority
    : A extends EmailOtpWalletAuthAuthority
      ? EcdsaWalletSessionAuthority
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
    ? {
        source: 'durable_authority_backed';
        durableRestore: 'sealed_record_authority';
      }
    : A extends PasskeyWalletAuthAuthority
      ? {
          source: PasskeyEcdsaSessionStoreSource;
          durableRestore: 'sealed_record_authority';
        }
      : never;

export type EcdsaCommittedLane<A extends WalletAuthAuthority = WalletAuthAuthority> =
  A extends WalletAuthAuthority
    ? {
        lane: ResolvedEvmFamilyEcdsaSigningLane;
        authority: A;
        walletSessionAuthority: EcdsaWalletSessionAuthorityFor<A>;
        material: EcdsaMaterialState;
      } & EcdsaCommittedLaneAuthFacts<A> &
        EcdsaCommittedLaneDurableRestoreFacts<A>
    : never;

export type EmailOtpEcdsaCommittedLane = EcdsaCommittedLane<EmailOtpWalletAuthAuthority>;

export type PasskeyEcdsaCommittedLane = EcdsaCommittedLane<PasskeyWalletAuthAuthority>;

export type EcdsaPublicReauthLane<A extends WalletAuthAuthority = WalletAuthAuthority> = {
  kind: 'public_reauth_lane';
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  authority: A;
  publicRestore: EcdsaReauthAnchorPublicRestore;
  reauthAnchor: ReauthAnchorIdentity;
  material: EcdsaMaterialState;
  walletSessionAuthority?: never;
  authLane?: never;
  record?: never;
};

export type EmailOtpEcdsaPublicReauthLane = EcdsaPublicReauthLane<EmailOtpWalletAuthAuthority>;
export type PasskeyEcdsaPublicReauthLane = EcdsaPublicReauthLane<PasskeyWalletAuthAuthority>;

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
  return {
    ...common,
    source: 'durable_authority_backed',
    durableRestore: 'sealed_record_authority',
  };
}

function readyPasskeyEcdsaCommittedLane(args: {
  committedLane: PasskeyEcdsaCommittedLane;
  material: ReadyEcdsaMaterial;
}): ReadyPasskeyEcdsaCommittedLane {
  return {
    source: args.committedLane.source,
    lane: args.committedLane.lane,
    authority: args.committedLane.authority,
    walletSessionAuthority: args.committedLane.walletSessionAuthority,
    material: args.material,
    durableRestore: 'sealed_record_authority',
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

function buildEcdsaSelectionDiagnostics(args: {
  candidate: EcdsaLaneCandidate;
  exactCandidateMaterial: EcdsaMaterialState;
}): EcdsaSelectionDiagnostics {
  return {
    selectedLaneCandidate: summarizeLaneCandidate(args.candidate),
    exactCandidateMaterial: summarizeEcdsaMaterialState(args.exactCandidateMaterial),
  };
}

// Exact-record-only: the lane identity names one canonical material owner, so
// there is no visible-material scan and no source-priority fallback.
function selectPasskeyMaterialForCandidate(args: {
  candidate: EcdsaLaneCandidate;
  chainTarget: ThresholdEcdsaChainTarget;
  materialChainTarget: ThresholdEcdsaChainTarget;
}): PasskeyMaterialSelectionResult {
  return {
    kind: 'missing',
    material: buildEcdsaMaterialStateForCandidate({
      candidate: args.candidate,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      source: 'manual-bootstrap',
      chainTarget: args.chainTarget,
      materialChainTarget: args.materialChainTarget,
    }),
  };
}

function selectAuthMethodForWalletAuth(args: {
  emailOtpCommittedLane?: EmailOtpEcdsaCommittedLane;
  passkeySelection: PasskeyMaterialDiagnosticsSelection;
}): { authMethod?: SignerAuthMethod; isEmailOtpThresholdContext?: boolean } {
  // Passkey material selection has no canonical constructor yet, so Email OTP
  // is the only method that can be visible. The ambiguity check the two-sided
  // comparison used to perform returns with the passkey path.
  void args.passkeySelection;
  if (!args.emailOtpCommittedLane) return {};
  return {
    authMethod: SIGNER_AUTH_METHODS.emailOtp,
    isEmailOtpThresholdContext: true,
  };
}

async function resolveEmailOtpAuthorityForSelection(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: EcdsaLaneCandidate;
}): Promise<EmailOtpSelectionAuthority | null> {
  const exactLane = exactEcdsaSigningLaneIdentityFromSelectedLane(args.lane);
  const laneAuthority = await args.deps.resolveDurableEmailOtpEcdsaSigningSessionAuthority({
    lane: exactLane,
    chain: args.lane.chainTarget.kind,
  });
  if (laneAuthority) {
    return {
      kind: 'durable_authority_backed',
      laneAuthority,
    };
  }
  logEvmFamilyEcdsaLaneDiagnostic('Email OTP exact ECDSA authority not found', {
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
    candidate: summarizeLaneCandidate(args.candidate),
  });
  return null;
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
  return buildEcdsaWalletSessionAuthority({
    walletSessionJwt: args.authLane.jwt,
    walletId: args.lane.key.walletId,
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
  return {
    ...common,
    source: 'durable_authority_backed',
    durableRestore: 'sealed_record_authority',
  };
}

type EcdsaSelectionReauthInput =
  | { kind: 'not_required'; reauthAnchor?: never; publicRestore?: never }
  | {
      kind: 'public_anchor';
      reauthAnchor: ReauthAnchorIdentity;
      publicRestore: EcdsaReauthAnchorPublicRestore;
    };

function requirePublicEcdsaSelectionReauth(
  reauth: EcdsaSelectionReauthInput,
): Extract<EcdsaSelectionReauthInput, { kind: 'public_anchor' }> {
  if (reauth.kind === 'public_anchor') return reauth;
  throw new Error(
    '[SigningEngine][ecdsa] expired/exhausted selection requires public reauth facts',
  );
}

export async function resolveEvmFamilyEcdsaSigningSelection(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  walletId: WalletId;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  authMethod: EvmFamilyEcdsaAuthMethod;
  laneCandidate: EcdsaLaneCandidate;
  reauth: EcdsaSelectionReauthInput;
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
  const candidateAuthMethod = ecdsaLaneCandidateAuthMethod(args.laneCandidate);
  const isPublicReauth = args.reauth.kind === 'public_anchor';
  const emailOtpAuthority =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp && !isPublicReauth
      ? await resolveEmailOtpAuthorityForSelection({
          deps: args.deps,
          lane: emailOtpAuthorityLane,
          candidate: args.laneCandidate,
        })
      : null;
  const requiredEmailOtpAuthority =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp && !isPublicReauth
      ? requireEmailOtpSelectionAuthority({
          authority: emailOtpAuthority,
          lane: emailOtpAuthorityLane,
          candidate: args.laneCandidate,
        })
      : null;
  const selectedPasskeyMaterial: PasskeyMaterialDiagnosticsSelection =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? { kind: 'not_applicable', reason: 'email_otp_candidate' }
      : selectPasskeyMaterialForCandidate({
          candidate: args.laneCandidate,
          chainTarget: args.chainTarget,
          materialChainTarget,
        });
  const exactCandidateMaterial =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? buildEcdsaMaterialStateForCandidate({
          candidate: args.laneCandidate,
          authMethod: SIGNER_AUTH_METHODS.emailOtp,
          source: SIGNER_AUTH_METHODS.emailOtp,
          chainTarget: args.chainTarget,
          materialChainTarget,
        })
      : (selectedPasskeyMaterial.kind === 'not_applicable'
          ? undefined
          : selectedPasskeyMaterial.material) ??
        buildEcdsaMaterialStateForCandidate({
          candidate: args.laneCandidate,
          authMethod: SIGNER_AUTH_METHODS.passkey,
          source: 'manual-bootstrap',
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
  // A passkey ECDSA committed lane has no canonical constructor yet: material
  // selection reports `missing` until the passkey path is rebuilt on sealed
  // record authority the way Email OTP already is.
  const committedPasskeyLane = null;
  const walletAuthInputs = selectAuthMethodForWalletAuth({
    ...(committedEmailOtpLane ? { emailOtpCommittedLane: committedEmailOtpLane } : {}),
    passkeySelection: selectedPasskeyMaterial,
  });
  const walletAuth = await resolveEvmFamilyTransactionWalletAuth({
    deps: args.deps,
    walletId: args.walletId,
    senderSignatureAlgorithm: args.senderSignatureAlgorithm,
    chainTarget: args.chainTarget,
    ...(walletAuthInputs.authMethod ? { sessionAuthMethod: walletAuthInputs.authMethod } : {}),
    ...(typeof walletAuthInputs.isEmailOtpThresholdContext === 'boolean'
      ? { isEmailOtpThresholdContext: walletAuthInputs.isEmailOtpThresholdContext }
      : {}),
  });
  const selectedAccountAuth = walletAuthWithSelectedPrimary(walletAuth, candidateAuthMethod);

  const diagnostics = buildEcdsaSelectionDiagnostics({
    candidate: args.laneCandidate,
    exactCandidateMaterial,
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

  if (args.laneCandidate.state === 'expired' || args.laneCandidate.state === 'exhausted') {
    const reason = args.laneCandidate.state;
    const reauth = requirePublicEcdsaSelectionReauth(args.reauth);
    if (candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
      if (reauth.publicRestore.source !== 'email_otp') {
        throw new Error(
          '[SigningEngine][ecdsa] Email OTP selection requires Email OTP public reauth facts',
        );
      }
      const reauthLane = buildEmailOtpEcdsaPublicReauthLane({
        lane,
        material: exactCandidateMaterial,
        reauthAnchor: reauth.reauthAnchor,
        publicRestore: reauth.publicRestore,
      });
      return emailOtpReauthRequiredSelection({
        accountAuth: selectedAccountAuth,
        lane,
        material: exactCandidateMaterial,
        reason,
        reauthLane,
        diagnostics,
      });
    }
    if (reauth.publicRestore.source === 'email_otp') {
      throw new Error(
        '[SigningEngine][ecdsa] passkey selection requires passkey public reauth facts',
      );
    }
    const reauthLane = buildPasskeyEcdsaPublicReauthLane({
      lane,
      material: exactCandidateMaterial,
      reauthAnchor: reauth.reauthAnchor,
      publicRestore: reauth.publicRestore,
    });
    return passkeyReauthRequiredSelection({
      accountAuth: selectedAccountAuth,
      lane,
      material: exactCandidateMaterial,
      reason,
      reauthLane,
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
      if (
        isRestoreRequiredPasskeyEcdsaLaneCandidate(args.laneCandidate) &&
        isMissingPasskeyEcdsaMaterial(exactCandidateMaterial)
      ) {
        return passkeyRestoreRequiredSelection({
          accountAuth: selectedAccountAuth,
          lane,
          candidate: args.laneCandidate,
          material: exactCandidateMaterial,
          restoreChainTarget: materialChainTarget,
          diagnostics,
        });
      }
      logEvmFamilyEcdsaLaneDiagnostic('Passkey ECDSA material is unavailable', {
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
    committedLane: requirePasskeyCommittedLaneForReauth({
      committedLane: committedPasskeyLane,
      lane,
      candidate: args.laneCandidate,
      reason: 'missing_hot_material',
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
