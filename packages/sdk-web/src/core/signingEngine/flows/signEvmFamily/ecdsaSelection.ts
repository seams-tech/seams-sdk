import type { ActiveEvmFamilyWalletSessionAuthorization } from './ecdsaSigningCapability';
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
  AuthorizedEcdsaLaneCandidate,
  EcdsaLaneCandidate,
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
  logEvmFamilyEcdsaLaneDiagnostic,
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaLane,
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type {
  DurableEmailOtpEcdsaSigningSessionAuthorityResolver,
  EvmFamilyEcdsaSessionReaderDeps,
} from '../../interfaces/operationDeps';
import type { EmailOtpEcdsaSigningSessionAuthority } from '../../session/emailOtp/ecdsaSigningSessionAuthority';
import {
  exactEcdsaSigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityKey,
} from '../../session/identity/exactSigningLaneIdentity';
import type { EvmFamilySenderSignatureAlgorithm } from './types';
import {
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ReauthAnchorIdentity } from '../../session/operationState/transactionState';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EcdsaReauthAnchorPublicRestore } from '../../session/persistence/sealedSessionStore';

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
};

type ReadyEvmFamilyEcdsaSigningSelectionBase = {
  kind: 'ready';
  accountAuth: AccountAuthMetadata;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  diagnostics: EcdsaSelectionDiagnostics;
};

export type ReadyEcdsaCommittedLane<A extends WalletAuthAuthority = WalletAuthAuthority> =
  EcdsaCommittedLane<A>;

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
  reason: 'expired' | 'exhausted';
  diagnostics: EcdsaSelectionDiagnostics;
};

type ReauthAnchorBackedEvmFamilyEcdsaSigningSelection = {
  reason: 'expired' | 'exhausted';
  reauthLane: EcdsaPublicReauthLane;
  committedLane?: never;
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
      });

export type EvmFamilyEcdsaSigningSelectionResult =
  | ReadyEvmFamilyEcdsaSigningSelection
  | ReauthRequiredEvmFamilyEcdsaSigningSelection;

export type EmailOtpEcdsaCommittedLaneStateFailure =
  | {
      kind: 'authority_missing';
    }
  | {
      kind: 'authority_not_ecdsa_signing_session';
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
  };
}

function buildEmailOtpEcdsaPublicReauthLane(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
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
  };
}

type PasskeyReauthRequiredSelectionInput = {
  accountAuth: AccountAuthMetadata;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  diagnostics: EcdsaSelectionDiagnostics;
} & {
  reason: 'expired' | 'exhausted';
  reauthLane: PasskeyEcdsaPublicReauthLane;
};

function passkeyReauthRequiredSelection(
  args: PasskeyReauthRequiredSelectionInput,
): Extract<ReauthRequiredEvmFamilyEcdsaSigningSelection, { authMethod: 'passkey' }> {
  return {
    kind: 'reauth_required',
    accountAuth: args.accountAuth,
    authMethod: 'passkey',
    lane: args.lane,
    reason: args.reason,
    reauthLane: args.reauthLane,
    diagnostics: args.diagnostics,
  };
}

type EmailOtpReauthRequiredSelectionInput = {
  accountAuth: AccountAuthMetadata;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  diagnostics: EcdsaSelectionDiagnostics;
} & {
  reason: 'expired' | 'exhausted';
  reauthLane: EmailOtpEcdsaPublicReauthLane;
};

function emailOtpReauthRequiredSelection(
  args: EmailOtpReauthRequiredSelectionInput,
): Extract<ReauthRequiredEvmFamilyEcdsaSigningSelection, { authMethod: 'email_otp' }> {
  return {
    kind: 'reauth_required',
    accountAuth: args.accountAuth,
    authMethod: 'email_otp',
    lane: args.lane,
    reason: args.reason,
    reauthLane: args.reauthLane,
    diagnostics: args.diagnostics,
  };
}

export function resolvedEvmFamilyEcdsaSigningLaneFromCandidate(
  candidate: AuthorizedEcdsaLaneCandidate,
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
  candidate: AuthorizedEcdsaLaneCandidate;
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
  candidate: AuthorizedEcdsaLaneCandidate,
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
  candidate: AuthorizedEcdsaLaneCandidate,
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

// Sealed-record authority is the only form built: the durable resolver either
// finds the exact authority or the selection has none.
type EmailOtpSelectionAuthority = {
  kind: 'durable_authority_backed';
  laneAuthority: EmailOtpEcdsaSigningSessionAuthority;
};

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

export type EcdsaCommittedLane<A extends WalletAuthAuthority = WalletAuthAuthority> =
  A extends WalletAuthAuthority
    ? {
        lane: ResolvedEvmFamilyEcdsaSigningLane;
        authority: A;
        authorization: ActiveEvmFamilyWalletSessionAuthorization;
      } & EcdsaCommittedLaneAuthFacts<A>
    : never;

export type EmailOtpEcdsaCommittedLane = EcdsaCommittedLane<EmailOtpWalletAuthAuthority>;

export type PasskeyEcdsaCommittedLane = EcdsaCommittedLane<PasskeyWalletAuthAuthority>;

export type EcdsaPublicReauthLane<A extends WalletAuthAuthority = WalletAuthAuthority> = {
  kind: 'public_reauth_lane';
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  authority: A;
  publicRestore: EcdsaReauthAnchorPublicRestore;
  reauthAnchor: ReauthAnchorIdentity;
  authorization?: never;
  authLane?: never;
  record?: never;
};

export type EmailOtpEcdsaPublicReauthLane = EcdsaPublicReauthLane<EmailOtpWalletAuthAuthority>;
export type PasskeyEcdsaPublicReauthLane = EcdsaPublicReauthLane<PasskeyWalletAuthAuthority>;

type PasskeyEcdsaLaneCandidate = AuthorizedEcdsaLaneCandidate & {
  auth: Extract<EcdsaLaneCandidate['auth'], { kind: 'passkey' }>;
};

function readyEmailOtpEcdsaCommittedLane(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  committedLane: EmailOtpEcdsaCommittedLane;
}): ReadyEmailOtpEcdsaCommittedLane {
  const common = {
    lane: args.lane,
    authLane: args.committedLane.authLane,
    authorization: args.committedLane.authorization,
    authority: args.committedLane.authority,
  };
  return {
    ...common,
  };
}

function readyPasskeyEcdsaCommittedLane(args: {
  committedLane: PasskeyEcdsaCommittedLane;
}): ReadyPasskeyEcdsaCommittedLane {
  return {
    lane: args.committedLane.lane,
    authority: args.committedLane.authority,
    authorization: args.committedLane.authorization,
  };
}

function requirePasskeyEcdsaLaneCandidate(
  candidate: AuthorizedEcdsaLaneCandidate,
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
  candidate: AuthorizedEcdsaLaneCandidate;
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
  candidate: AuthorizedEcdsaLaneCandidate;
}): EcdsaSelectionDiagnostics {
  return { selectedLaneCandidate: summarizeLaneCandidate(args.candidate) };
}

function selectAuthMethodForWalletAuth(args: {
  emailOtpCommittedLane?: EmailOtpEcdsaCommittedLane;
  passkeyCommittedLane?: PasskeyEcdsaCommittedLane;
}): { authMethod?: SignerAuthMethod; isEmailOtpThresholdContext?: boolean } {
  const hasEmailOtp = Boolean(args.emailOtpCommittedLane);
  const hasPasskey = Boolean(args.passkeyCommittedLane);
  if (hasEmailOtp === hasPasskey) return {};
  return hasEmailOtp
    ? { authMethod: SIGNER_AUTH_METHODS.emailOtp, isEmailOtpThresholdContext: true }
    : { authMethod: SIGNER_AUTH_METHODS.passkey, isEmailOtpThresholdContext: false };
}

function commitPasskeyEcdsaLaneForSelection(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: AuthorizedEcdsaLaneCandidate;
}): PasskeyEcdsaCommittedLane {
  const candidate = requirePasskeyEcdsaLaneCandidate(args.candidate);
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: candidate.walletId,
    rpId: candidate.auth.rpId,
    credentialIdB64u: candidate.auth.credentialIdB64u,
  });
  assertEcdsaCommittedLaneAuthorityMatchesWallet({
    authority,
    lane: args.lane,
    candidate,
    context: 'Passkey',
  });
  return {
    lane: args.lane,
    authority,
    authorization: args.lane.authorization,
  };
}

async function resolveEmailOtpAuthorityForSelection(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: AuthorizedEcdsaLaneCandidate;
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
  candidate: AuthorizedEcdsaLaneCandidate;
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
  candidate: AuthorizedEcdsaLaneCandidate;
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

function requireEmailOtpCommittedLaneForReady(args: {
  committedLane: EmailOtpEcdsaCommittedLane | null;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: AuthorizedEcdsaLaneCandidate;
}): EmailOtpEcdsaCommittedLane {
  if (args.committedLane) return args.committedLane;
  logEvmFamilyEcdsaLaneDiagnostic('Email OTP ECDSA committed lane missing for ready signing', {
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
    candidate: summarizeLaneCandidate(args.candidate),
  });
  throwEmailOtpEcdsaCommittedLaneStateError({ kind: 'committed_lane_missing_for_ready' });
}

function requirePasskeyCommittedLaneForReady(args: {
  committedLane: PasskeyEcdsaCommittedLane | null;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: AuthorizedEcdsaLaneCandidate;
}): PasskeyEcdsaCommittedLane {
  if (args.committedLane) return args.committedLane;
  logEvmFamilyEcdsaLaneDiagnostic('passkey ECDSA committed lane missing for ready signing', {
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
    candidate: summarizeLaneCandidate(args.candidate),
  });
  throw new Error('[SigningEngine][ecdsa] passkey ECDSA committed lane missing for ready signing');
}

function commitEmailOtpEcdsaLaneForSelection(args: {
  authority: EmailOtpSelectionAuthority;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: AuthorizedEcdsaLaneCandidate;
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
    authorization: args.lane.authorization,
  };
  return {
    ...common,
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
  chainTarget: ThresholdEcdsaChainTarget;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  laneCandidate: AuthorizedEcdsaLaneCandidate;
  reauth: EcdsaSelectionReauthInput;
}): Promise<EvmFamilyEcdsaSigningSelectionResult> {
  const lane = resolvedEvmFamilyEcdsaSigningLaneFromCandidate(args.laneCandidate);
  const emailOtpAuthorityLane = emailOtpAuthorityLaneFromCandidate({
    candidate: args.laneCandidate,
    selectedLane: lane,
  });
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
  const committedEmailOtpLane =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp && requiredEmailOtpAuthority
      ? commitEmailOtpEcdsaLaneForSelection({
          authority: requiredEmailOtpAuthority,
          lane: emailOtpAuthorityLane,
          candidate: args.laneCandidate,
        })
      : null;
  const committedPasskeyLane =
    candidateAuthMethod === SIGNER_AUTH_METHODS.passkey && !isPublicReauth
      ? commitPasskeyEcdsaLaneForSelection({
          lane,
          candidate: args.laneCandidate,
        })
      : null;
  const walletAuthInputs = selectAuthMethodForWalletAuth({
    ...(committedEmailOtpLane ? { emailOtpCommittedLane: committedEmailOtpLane } : {}),
    ...(committedPasskeyLane ? { passkeyCommittedLane: committedPasskeyLane } : {}),
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
  });


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
        reauthAnchor: reauth.reauthAnchor,
        publicRestore: reauth.publicRestore,
      });
      return emailOtpReauthRequiredSelection({
        accountAuth: selectedAccountAuth,
        lane,
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
      reauthAnchor: reauth.reauthAnchor,
      publicRestore: reauth.publicRestore,
    });
    return passkeyReauthRequiredSelection({
      accountAuth: selectedAccountAuth,
      lane,
      reason,
      reauthLane,
      diagnostics,
    });
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
    });
    return {
      kind: 'ready',
      accountAuth: selectedAccountAuth,
      authMethod: ecdsaCommittedLaneAuthMethod(readyCommittedLane),
      lane,
      committedLane: readyCommittedLane,
      diagnostics,
    };
  }

  const readyCommittedLane = readyPasskeyEcdsaCommittedLane({
    committedLane: requirePasskeyCommittedLaneForReady({
      committedLane: committedPasskeyLane,
      lane,
      candidate: args.laneCandidate,
    }),
  });
  return {
    kind: 'ready',
    accountAuth: selectedAccountAuth,
    authMethod: ecdsaCommittedLaneAuthMethod(readyCommittedLane),
    lane,
    committedLane: readyCommittedLane,
    diagnostics,
  };
}
