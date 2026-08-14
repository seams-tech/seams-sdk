import { fundImplicitNearAccountForTesting } from '@/core/rpcClients/relayer/walletRegistration';
import type { TransactionContext } from '@/core/types/rpc';
import type {
  NearEd25519FundingSession,
  NearEd25519StepUpAuthorization,
} from '../../interfaces/near';
import type { NearSigningRuntimeDeps } from '../../interfaces/runtime';
import type { NonceLeaseRef } from '../../interfaces/nonceLease';
import type { NearImplicitAccountFundingResult } from '../../interfaces/implicitAccountFunding';
import {
  buildNearNonceLane,
  nonceLeaseToRef,
  type NearFundingRequest,
  type NearTransactionReadiness,
  type NonceLease,
} from '../../nonce/NonceCoordinator';
import type {
  SigningOperationContext,
  SigningOperationFingerprint,
  ThresholdEd25519SessionId,
} from '../../session/operationState/types';
import type { ResolvedRouterAbEd25519WalletSessionState } from '../../session/warmCapabilities/routerAbEd25519WalletSessionState';

const ACCESS_KEY_POLL_ATTEMPTS = 12;
const ACCESS_KEY_POLL_DELAY_MS = 1_000;
/**
 * The funding transfer is broadcast with optimistic execution, so the account is
 * usually queryable within a few hundred milliseconds — the RPC node we read
 * from just has to catch up. Start well under a second and ease off, instead of
 * paying a flat second for a wait that is normally already over. Total budget
 * stays comparable to the flat schedule.
 */
const FUNDED_ACCESS_KEY_BACKOFF_MS = [
  120, 180, 250, 350, 500, 700, 1_000, 1_000, 1_500, 1_500, 2_000,
] as const;
const nearFundingAuthorityBrand = Symbol('NearWalletSessionFundingAuthority');

type FingerprintedSigningOperationContext = SigningOperationContext & {
  operationFingerprint: SigningOperationFingerprint;
};

type NearWalletSessionFundingAuthorityBase = Readonly<{
  kind: 'near_wallet_session_funding_authority';
  request: NearFundingRequest;
  thresholdSessionId: ThresholdEd25519SessionId;
  walletSessionToken: string;
  readonly [nearFundingAuthorityBrand]: true;
}>;

type EstablishedWalletSessionAuthority = NearWalletSessionFundingAuthorityBase & {
  provenance: 'warm_session';
};

export type FreshWalletSessionAuthority = NearWalletSessionFundingAuthorityBase & {
  provenance: 'passkey_reauth';
};

type FreshEmailOtpWalletSessionAuthority = NearWalletSessionFundingAuthorityBase & {
  provenance: 'email_otp_reauth';
};

type NearWalletSessionFundingAuthority =
  | EstablishedWalletSessionAuthority
  | FreshWalletSessionAuthority
  | FreshEmailOtpWalletSessionAuthority;

function delayAccessKeyPoll(delayMs = ACCESS_KEY_POLL_DELAY_MS): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMs);
  });
}

function requireWalletSessionToken(state: NearEd25519FundingSession): string {
  const walletSessionToken = String(state.walletSessionToken || '').trim();
  if (!walletSessionToken) {
    throw new Error(
      '[SigningEngine][near] authenticated Wallet Session token is required for funding',
    );
  }
  return walletSessionToken;
}

function fundingSessionFromWalletSessionState(
  state: ResolvedRouterAbEd25519WalletSessionState,
): NearEd25519FundingSession {
  return {
    kind: 'near_ed25519_funding_session',
    signer: state.signingLane.identity.signer,
    thresholdSessionId: state.thresholdSessionId,
    walletSessionToken: state.walletSessionAuth.walletSessionToken,
  };
}

/**
 * The step-up METHOD, which is known before any step-up authorization exists.
 * Confirmation-time funding runs between the user's confirm click and the
 * step-up assertion — before the proof is assembled — so it names its
 * provenance from the method rather than from a finished authorization.
 */
export type NearOperationStepUpFundingMethod = Exclude<
  NearEd25519StepUpAuthorization['kind'],
  'warm_session'
>;

function fundingAuthorityProvenance(
  authorization: NearEd25519StepUpAuthorization,
): NearWalletSessionFundingAuthority['provenance'] {
  switch (authorization.kind) {
    case 'warm_session':
      return 'warm_session';
    case 'passkey':
      return 'passkey_reauth';
    case 'email_otp':
      return 'email_otp_reauth';
    default:
      return assertNeverFundingAuthorization(authorization);
  }
}

function operationStepUpFundingProvenance(
  method: NearOperationStepUpFundingMethod,
): NearWalletSessionFundingAuthority['provenance'] {
  switch (method) {
    case 'passkey':
      return 'passkey_reauth';
    case 'email_otp':
      return 'email_otp_reauth';
    default: {
      method satisfies never;
      throw new Error('[SigningEngine][near] unsupported operation step-up funding method');
    }
  }
}

function assertNeverFundingAuthorization(value: never): never {
  throw new Error(`Unsupported NEAR funding authorization: ${String(value)}`);
}

function assertFundingRequestMatchesAuthenticatedState(args: {
  request: NearFundingRequest;
  fundingSession: NearEd25519FundingSession;
  nearPublicKeyStr: string;
  signingOperation: FingerprintedSigningOperationContext;
  signatureUses: number;
}): void {
  const walletId = String(args.fundingSession.signer.account.wallet.walletId);
  const nearAccountId = String(args.fundingSession.signer.account.nearAccountId);
  const requestOperation = args.request.operation;
  if (
    String(args.request.subject.walletId) !== walletId ||
    String(args.request.subject.nearAccountId) !== nearAccountId ||
    args.request.subject.nearPublicKeyStr !== args.nearPublicKeyStr
  ) {
    throw new Error(
      '[SigningEngine][near] funding request subject does not match authenticated lane',
    );
  }
  if (
    String(requestOperation.operationId) !== String(args.signingOperation.operationId) ||
    String(requestOperation.operationFingerprint) !==
      String(args.signingOperation.operationFingerprint) ||
    requestOperation.intent !== args.signingOperation.intent ||
    requestOperation.accountId !== nearAccountId
  ) {
    throw new Error(
      '[SigningEngine][near] funding request operation does not match signing operation',
    );
  }
  if (args.request.signatureUses !== args.signatureUses) {
    throw new Error('[SigningEngine][near] funding request signature use count mismatch');
  }
  if (String(args.fundingSession.thresholdSessionId).trim().length === 0) {
    throw new Error('[SigningEngine][near] funding authority threshold session mismatch');
  }
}

function createNearWalletSessionFundingAuthority(args: {
  request: NearFundingRequest;
  fundingSession: NearEd25519FundingSession;
  provenance: NearWalletSessionFundingAuthority['provenance'];
}): NearWalletSessionFundingAuthority {
  return {
    kind: 'near_wallet_session_funding_authority',
    provenance: args.provenance,
    request: args.request,
    thresholdSessionId: args.fundingSession.thresholdSessionId,
    walletSessionToken: requireWalletSessionToken(args.fundingSession),
    [nearFundingAuthorityBrand]: true,
  };
}

/**
 * `nonceLeases` are the wire-shaped refs the readiness carries; `reservedLeases`
 * are the full leases, which the confirmation flow needs so it can release them
 * if the confirmation fails after reservation.
 */
type FundedNearTransactionContext = {
  transactionContext: TransactionContext;
  nonceLeases: NonceLeaseRef[];
  reservedLeases: NonceLease[];
};

async function reserveFundedImplicitNearTransactionContext(args: {
  ctx: NearSigningRuntimeDeps;
  authority: NearWalletSessionFundingAuthority;
}): Promise<FundedNearTransactionContext> {
  const request = args.authority.request;
  const lane = buildNearNonceLane({
    chains: args.ctx.chains,
    walletId: String(request.subject.walletId),
    nearAccountId: String(request.subject.nearAccountId),
    nearPublicKeyStr: request.subject.nearPublicKeyStr,
  });
  let latestError: unknown;
  for (let attempt = 1; attempt <= ACCESS_KEY_POLL_ATTEMPTS; attempt += 1) {
    try {
      const reserved = await args.ctx.nonceCoordinator.reserveNearContext({
        lane,
        operation: request.operation,
        count: request.signatureUses,
        nearClient: args.ctx.nearClient,
      });
      return {
        transactionContext: reserved.context,
        nonceLeases: reserved.leases.map(nonceLeaseToRef),
        reservedLeases: reserved.leases,
      };
    } catch (error: unknown) {
      latestError = error;
      if (attempt < ACCESS_KEY_POLL_ATTEMPTS) {
        await delayAccessKeyPoll(
          FUNDED_ACCESS_KEY_BACKOFF_MS[attempt - 1] ?? ACCESS_KEY_POLL_DELAY_MS,
        );
      }
    }
  }
  throw latestError instanceof Error
    ? latestError
    : new Error('Funded NEAR account access key did not become available');
}

async function fundAndReserveNearContext(args: {
  ctx: NearSigningRuntimeDeps;
  authority: NearWalletSessionFundingAuthority;
}): Promise<FundedNearTransactionContext> {
  const request = args.authority.request;
  const funded = await fundImplicitNearAccountForTesting({
    relayerUrl: args.ctx.relayerUrl,
    walletId: String(request.subject.walletId),
    nearAccountId: String(request.subject.nearAccountId),
    nearPublicKeyStr: request.subject.nearPublicKeyStr,
    walletSessionToken: args.authority.walletSessionToken,
  });
  if (!funded.ok) {
    throw new Error(funded.message || funded.code || 'Failed to fund implicit NEAR account');
  }
  return await reserveFundedImplicitNearTransactionContext(args);
}

export async function resolveConfirmedNearTransactionContext(args: {
  confirmation: Readonly<{ readiness: NearTransactionReadiness }>;
  ctx: NearSigningRuntimeDeps;
  nearPublicKeyStr: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  authorization: NearEd25519StepUpAuthorization;
  signingOperation: FingerprintedSigningOperationContext;
  signatureUses: number;
}): Promise<Extract<NearTransactionReadiness, { kind: 'context_ready' }>> {
  switch (args.confirmation.readiness.kind) {
    case 'context_ready':
      return args.confirmation.readiness;
    case 'funding_required': {
      assertFundingRequestMatchesAuthenticatedState({
        request: args.confirmation.readiness.request,
        fundingSession: fundingSessionFromWalletSessionState(args.walletSessionState),
        nearPublicKeyStr: args.nearPublicKeyStr,
        signingOperation: args.signingOperation,
        signatureUses: args.signatureUses,
      });
      const authority = createNearWalletSessionFundingAuthority({
        request: args.confirmation.readiness.request,
        fundingSession: fundingSessionFromWalletSessionState(args.walletSessionState),
        provenance: fundingAuthorityProvenance(args.authorization),
      });
      const funded = await fundAndReserveNearContext({ ctx: args.ctx, authority });
      return {
        kind: 'context_ready',
        transactionContext: funded.transactionContext,
        nonceLeases: funded.nonceLeases,
      };
    }
    default:
      return assertNeverConfirmedNearTransactionContext(args.confirmation.readiness);
  }
}

function assertNeverConfirmedNearTransactionContext(value: never): never {
  throw new Error(`Unsupported confirmed NEAR transaction readiness: ${String(value)}`);
}

/**
 * The funder behind NearImplicitAccountFundingPort: funds an implicit NEAR
 * account and reserves the transaction context the confirmation flow needs, in
 * one pass.
 *
 * The warm-session path funds after the confirmation returns
 * (resolveConfirmedNearTransactionContext above) because its authorization is
 * not context-bound. A step-up authorization is: its challenge is the digest of
 * the prepared operation — nonce and block hash included — and the assertion
 * signs that digest, so funding must land before the assertion is collected.
 * Same authority, same subject and operation checks; only the ordering and the
 * caller differ.
 *
 * Reserving here rather than making the caller re-fetch matters for latency:
 * this runs while the user waits for the passkey prompt, and the reservation is
 * itself the retry — a not-yet-visible access key is retried inside
 * reserveFundedImplicitNearTransactionContext instead of costing a separate
 * access-key probe plus a full second of backoff before the caller tries again.
 */
export async function fundNearImplicitAccountForOperationStepUp(args: {
  request: NearFundingRequest;
  ctx: NearSigningRuntimeDeps;
  nearPublicKeyStr: string;
  fundingSession: NearEd25519FundingSession;
  method: NearOperationStepUpFundingMethod;
  signingOperation: FingerprintedSigningOperationContext;
  signatureUses: number;
}): Promise<NearImplicitAccountFundingResult> {
  assertFundingRequestMatchesAuthenticatedState({
    request: args.request,
    fundingSession: args.fundingSession,
    nearPublicKeyStr: args.nearPublicKeyStr,
    signingOperation: args.signingOperation,
    signatureUses: args.signatureUses,
  });
  const authority = createNearWalletSessionFundingAuthority({
    request: args.request,
    fundingSession: args.fundingSession,
    provenance: operationStepUpFundingProvenance(args.method),
  });
  const funded = await fundAndReserveNearContext({ ctx: args.ctx, authority });
  return {
    readiness: {
      kind: 'context_ready',
      transactionContext: funded.transactionContext,
      nonceLeases: funded.nonceLeases,
    },
    reservedNonceLeases: funded.reservedLeases,
  };
}
