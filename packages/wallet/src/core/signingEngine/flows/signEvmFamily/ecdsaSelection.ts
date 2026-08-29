import type { ExactEvmFamilyWalletSessionAuthorization } from '../../session/material/ecdsaSigningCapability';
import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  isPasskeyWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
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
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type { DurableEmailOtpEcdsaSigningSessionAuthorityResolver } from '../../interfaces/operationDeps';
import type { EmailOtpEcdsaSigningSessionAuthority } from '../../session/emailOtp/ecdsaSigningSessionAuthority';
import { exactEcdsaSigningLaneIdentityFromSelectedLane } from '../../session/identity/exactSigningLaneIdentity';
import type { EvmFamilySenderSignatureAlgorithm } from './types';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { CanonicalEvmFamilyEcdsaSigningCapability } from '../../session/material/ecdsaSigningCapability';

export type EvmFamilyEcdsaSigningSelectionDeps = EvmFamilyAccountMetadataDeps &
  DurableEmailOtpEcdsaSigningSessionAuthorityResolver & {
    resolveCanonicalEcdsaSigningCapability: (args: {
      walletId: WalletId;
      chainTarget: ThresholdEcdsaChainTarget;
      materialActivation: AuthorizedEcdsaLaneCandidate['materialActivation'];
    }) => Promise<CanonicalEvmFamilyEcdsaSigningCapability>;
  };

type EcdsaSelectionLaneCandidateDiagnosticsBase = {
  authMethod: WalletAuthAuthority['factor']['kind'];
  chain: EcdsaLaneCandidate['chain'];
  chainTarget: ThresholdEcdsaChainTarget;
  state: EcdsaLaneCandidate['state'];
  walletSessionId: string;
  materialActivationId: string;
  remainingUses: number;
  expiresAtMs: number;
};

function ecdsaLaneCandidateAuthMethod(
  candidate: EcdsaLaneCandidate,
): WalletAuthAuthority['factor']['kind'] {
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

type EcdsaSelectionLaneCandidateDiagnostics = EcdsaSelectionLaneCandidateDiagnosticsBase & {
  source: 'canonical_capability';
};

export type EcdsaSelectionDiagnostics = {
  selectedLaneCandidate: EcdsaSelectionLaneCandidateDiagnostics;
};

type ReadyEvmFamilyEcdsaSigningSelectionBase = {
  kind: 'ready';
  accountAuth: AccountAuthMetadata;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  diagnostics: EcdsaSelectionDiagnostics;
};

export type ReadyEvmFamilyEcdsaSigningSelection = ReadyEvmFamilyEcdsaSigningSelectionBase & {
  committedLane: EcdsaCommittedLane;
};

export type EvmFamilyEcdsaSigningSelectionResult = ReadyEvmFamilyEcdsaSigningSelection;

function walletAuthWithSelectedPrimary(
  accountAuth: AccountAuthMetadata,
  authMethod: WalletAuthAuthority['factor']['kind'],
): AccountAuthMetadata {
  return {
    ...accountAuth,
    primaryAuthMethod: authMethod,
    linkedAuthMethods: Array.from(new Set([...accountAuth.linkedAuthMethods, authMethod])),
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

function laneCandidateDiagnosticsBase(
  candidate: AuthorizedEcdsaLaneCandidate,
): EcdsaSelectionLaneCandidateDiagnosticsBase {
  return {
    authMethod: ecdsaLaneCandidateAuthMethod(candidate),
    chain: candidate.chain,
    chainTarget: candidate.chainTarget,
    state: candidate.state,
    walletSessionId: candidate.authorization.operationCredential.walletSessionId,
    materialActivationId: candidate.materialActivation.activationId,
    remainingUses: candidate.authorization.runtime.remainingUses,
    expiresAtMs: candidate.authorization.runtime.expiresAtMs,
  };
}

function summarizeLaneCandidate(
  candidate: AuthorizedEcdsaLaneCandidate,
): EcdsaSelectionDiagnostics['selectedLaneCandidate'] {
  return {
    ...laneCandidateDiagnosticsBase(candidate),
    source: 'canonical_capability',
  };
}

// Canonical candidate facts for an already-resolved lane. The lane identity
// carries the exact signer binding and active authorization, so no record is
// consulted; this replaces every record-derived candidate construction.
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
        authorization: ExactEvmFamilyWalletSessionAuthorization;
      } & EcdsaCommittedLaneAuthFacts<A>
    : never;

type PasskeyEcdsaLaneCandidate = AuthorizedEcdsaLaneCandidate & {
  auth: Extract<EcdsaLaneCandidate['auth'], { kind: 'passkey' }>;
};

function requirePasskeyEcdsaLaneCandidate(
  candidate: AuthorizedEcdsaLaneCandidate,
): PasskeyEcdsaLaneCandidate {
  if (candidate.auth.kind !== 'passkey') {
    throw new Error('[SigningEngine][ecdsa] passkey committed lane requires passkey candidate');
  }
  return { ...candidate, auth: candidate.auth };
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

async function commitPasskeyEcdsaLaneForSelection(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: AuthorizedEcdsaLaneCandidate;
}): Promise<EcdsaCommittedLane> {
  const candidate = requirePasskeyEcdsaLaneCandidate(args.candidate);
  const capability = await args.deps.resolveCanonicalEcdsaSigningCapability({
    walletId: candidate.walletId,
    chainTarget: candidate.chainTarget,
    materialActivation: candidate.materialActivation,
  });
  const authority = capability.authority;
  if (
    !isPasskeyWalletAuthAuthority(authority) ||
    String(authority.verifier.rpId) !== String(candidate.auth.rpId) ||
    authority.factor.credentialIdB64u !== candidate.auth.credentialIdB64u
  ) {
    throw new Error('[SigningEngine][ecdsa] exact Passkey capability authority changed');
  }
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
  throw new Error(
    'Email OTP ECDSA committed lane is missing wallet-session authority; unlock wallet again',
  );
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
  throw new Error(
    'Email OTP ECDSA committed lane authority is not an ECDSA signing session; unlock wallet again',
  );
}

function requireCommittedLaneForReady(args: {
  committedLane: EcdsaCommittedLane | null;
  expectedFactor: WalletAuthAuthority['factor']['kind'];
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: AuthorizedEcdsaLaneCandidate;
}): EcdsaCommittedLane {
  if (args.committedLane && args.committedLane.authority.factor.kind === args.expectedFactor) {
    return args.committedLane;
  }
  logEvmFamilyEcdsaLaneDiagnostic('ECDSA committed lane missing for ready signing', {
    expectedFactor: args.expectedFactor,
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
    candidate: summarizeLaneCandidate(args.candidate),
  });
  throw new Error('[SigningEngine][ecdsa] committed lane is unavailable for ready signing');
}

function commitEmailOtpEcdsaLaneForSelection(args: {
  authority: EmailOtpSelectionAuthority;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  candidate: AuthorizedEcdsaLaneCandidate;
}): EcdsaCommittedLane {
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

export async function resolveEvmFamilyEcdsaSigningSelection(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  laneCandidate: AuthorizedEcdsaLaneCandidate;
}): Promise<EvmFamilyEcdsaSigningSelectionResult> {
  const lane = resolvedEvmFamilyEcdsaSigningLaneFromCandidate(args.laneCandidate);
  const emailOtpAuthorityLane = lane;
  const candidateAuthMethod = ecdsaLaneCandidateAuthMethod(args.laneCandidate);
  const emailOtpAuthority =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? await resolveEmailOtpAuthorityForSelection({
          deps: args.deps,
          lane: emailOtpAuthorityLane,
          candidate: args.laneCandidate,
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
  const committedEmailOtpLane: EcdsaCommittedLane | null =
    candidateAuthMethod === SIGNER_AUTH_METHODS.emailOtp && requiredEmailOtpAuthority
      ? commitEmailOtpEcdsaLaneForSelection({
          authority: requiredEmailOtpAuthority,
          lane: emailOtpAuthorityLane,
          candidate: args.laneCandidate,
        })
      : null;
  const committedPasskeyLane: EcdsaCommittedLane | null =
    candidateAuthMethod === SIGNER_AUTH_METHODS.passkey
      ? await commitPasskeyEcdsaLaneForSelection({
          deps: args.deps,
          lane,
          candidate: args.laneCandidate,
        })
      : null;
  const committedLane = committedEmailOtpLane ?? committedPasskeyLane;
  const committedFactor = committedLane?.authority.factor.kind;
  const walletAuth = await resolveEvmFamilyTransactionWalletAuth({
    senderSignatureAlgorithm: args.senderSignatureAlgorithm,
    signerAuthMethod: committedFactor ?? candidateAuthMethod,
  });
  const selectedAccountAuth = walletAuthWithSelectedPrimary(walletAuth, candidateAuthMethod);

  const diagnostics = buildEcdsaSelectionDiagnostics({
    candidate: args.laneCandidate,
  });

  const readyCommittedLane = requireCommittedLaneForReady({
    committedLane,
    expectedFactor: candidateAuthMethod,
    lane,
    candidate: args.laneCandidate,
  });
  return {
    kind: 'ready',
    accountAuth: selectedAccountAuth,
    lane,
    committedLane: readyCommittedLane,
    diagnostics,
  };
}
