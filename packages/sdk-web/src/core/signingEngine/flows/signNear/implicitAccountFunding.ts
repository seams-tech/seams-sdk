import { fundImplicitNearAccountForTesting } from '@/core/rpcClients/relayer/walletRegistration';
import type { TransactionContext } from '@/core/types/rpc';
import type { NearEd25519StepUpAuthorization } from '../../interfaces/near';
import type { NearSigningRuntimeDeps } from '../../interfaces/runtime';
import type { NonceLeaseRef } from '../../interfaces/nonceLease';
import { nonceLeaseToRef } from '../../nonce/NonceCoordinator';
import { buildNearNonceLane } from '../../nonce/nearNonceLaneIdentity';
import type {
  NearFundingRequest,
  NearTransactionReadiness,
} from '../../nonce/nearTransactionReadiness';
import type {
  SigningOperationContext,
  SigningOperationFingerprint,
  ThresholdEd25519SessionId,
} from '../../session/operationState/types';
import type { ResolvedRouterAbEd25519WalletSessionState } from '../../session/warmCapabilities/routerAbEd25519WalletSessionState';
import type { NearTransactionSigningConfirmationResult } from '../../stepUpConfirmation/confirmOperation';

const ACCESS_KEY_POLL_ATTEMPTS = 12;
const ACCESS_KEY_POLL_DELAY_MS = 1_000;
const nearFundingAuthorityBrand = Symbol('NearWalletSessionFundingAuthority');

type FingerprintedSigningOperationContext = SigningOperationContext & {
  operationFingerprint: SigningOperationFingerprint;
};

type NearWalletSessionFundingAuthorityBase = Readonly<{
  kind: 'near_wallet_session_funding_authority';
  request: NearFundingRequest;
  thresholdSessionId: ThresholdEd25519SessionId;
  walletSessionJwt: string;
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

function delayAccessKeyPoll(): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ACCESS_KEY_POLL_DELAY_MS);
  });
}

function requireWalletSessionJwt(state: ResolvedRouterAbEd25519WalletSessionState): string {
  const walletSessionJwt = String(state.walletSessionAuth.walletSessionJwt || '').trim();
  if (!walletSessionJwt) {
    throw new Error(
      '[SigningEngine][near] authenticated Wallet Session JWT is required for funding',
    );
  }
  return walletSessionJwt;
}

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

function assertNeverFundingAuthorization(value: never): never {
  throw new Error(`Unsupported NEAR funding authorization: ${String(value)}`);
}

function assertFundingRequestMatchesAuthenticatedState(args: {
  request: NearFundingRequest;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  nearPublicKeyStr: string;
  signingOperation: FingerprintedSigningOperationContext;
  signatureUses: number;
}): void {
  const lane = args.walletSessionState.signingLane;
  const walletId = String(lane.identity.signer.account.wallet.walletId);
  const nearAccountId = String(lane.identity.signer.account.nearAccountId);
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
  if (
    String(args.walletSessionState.thresholdSessionId) !== String(lane.identity.thresholdSessionId)
  ) {
    throw new Error('[SigningEngine][near] funding authority threshold session mismatch');
  }
}

function createNearWalletSessionFundingAuthority(args: {
  request: NearFundingRequest;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  authorization: NearEd25519StepUpAuthorization;
}): NearWalletSessionFundingAuthority {
  return {
    kind: 'near_wallet_session_funding_authority',
    provenance: fundingAuthorityProvenance(args.authorization),
    request: args.request,
    thresholdSessionId: args.walletSessionState.signingLane.identity.thresholdSessionId,
    walletSessionJwt: requireWalletSessionJwt(args.walletSessionState),
    [nearFundingAuthorityBrand]: true,
  };
}

async function reserveFundedImplicitNearTransactionContext(args: {
  ctx: NearSigningRuntimeDeps;
  authority: NearWalletSessionFundingAuthority;
}): Promise<{ transactionContext: TransactionContext; nonceLeases: NonceLeaseRef[] }> {
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
      };
    } catch (error: unknown) {
      latestError = error;
      if (attempt < ACCESS_KEY_POLL_ATTEMPTS) await delayAccessKeyPoll();
    }
  }
  throw latestError instanceof Error
    ? latestError
    : new Error('Funded NEAR account access key did not become available');
}

async function fundAndReserveNearContext(args: {
  ctx: NearSigningRuntimeDeps;
  authority: NearWalletSessionFundingAuthority;
}): Promise<{ transactionContext: TransactionContext; nonceLeases: NonceLeaseRef[] }> {
  const request = args.authority.request;
  const funded = await fundImplicitNearAccountForTesting({
    relayerUrl: args.ctx.relayerUrl,
    walletId: String(request.subject.walletId),
    nearAccountId: String(request.subject.nearAccountId),
    nearPublicKeyStr: request.subject.nearPublicKeyStr,
    walletSessionJwt: args.authority.walletSessionJwt,
  });
  if (!funded.ok) {
    throw new Error(funded.message || funded.code || 'Failed to fund implicit NEAR account');
  }
  return await reserveFundedImplicitNearTransactionContext(args);
}

export async function resolveConfirmedNearTransactionContext(args: {
  confirmation: NearTransactionSigningConfirmationResult;
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
        walletSessionState: args.walletSessionState,
        nearPublicKeyStr: args.nearPublicKeyStr,
        signingOperation: args.signingOperation,
        signatureUses: args.signatureUses,
      });
      const authority = createNearWalletSessionFundingAuthority({
        request: args.confirmation.readiness.request,
        walletSessionState: args.walletSessionState,
        authorization: args.authorization,
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
