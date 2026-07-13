import { fundImplicitNearAccountForTesting } from '@/core/rpcClients/relayer/walletRegistration';
import type { AccountId } from '@/core/types/accountIds';
import type { TransactionContext } from '@/core/types/rpc';
import type { NearSigningRuntimeDeps } from '../../interfaces/runtime';
import type { NonceLeaseRef } from '../../interfaces/nonceLease';
import { nonceLeaseToRef, type NearNonceLane } from '../../nonce/NonceCoordinator';
import type {
  SigningOperationContext,
  SigningOperationFingerprint,
} from '../../session/operationState/types';
import type { ResolvedRouterAbEd25519WalletSessionState } from '../../session/warmCapabilities/routerAbEd25519WalletSessionState';
import type { SigningConfirmationResultWithTxContext } from '../../stepUpConfirmation/confirmOperation';

const ACCESS_KEY_POLL_ATTEMPTS = 12;
const ACCESS_KEY_POLL_DELAY_MS = 1_000;

type FingerprintedSigningOperationContext = SigningOperationContext & {
  operationFingerprint: SigningOperationFingerprint;
};

function nearNonceNetworkKey(ctx: NearSigningRuntimeDeps): string {
  const nearChain = ctx.chains?.find((chain) => String(chain.network || '').startsWith('near-'));
  return String(nearChain?.network || 'near');
}

function nearNonceLane(args: {
  ctx: NearSigningRuntimeDeps;
  walletId: string;
  nearAccountId: AccountId;
  nearPublicKeyStr: string;
}): NearNonceLane {
  return {
    family: 'near',
    networkKey: nearNonceNetworkKey(args.ctx),
    walletId: args.walletId,
    nearAccountId: String(args.nearAccountId),
    publicKey: args.nearPublicKeyStr,
  };
}

function delayAccessKeyPoll(): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ACCESS_KEY_POLL_DELAY_MS);
  });
}

async function reserveFundedImplicitNearTransactionContext(args: {
  ctx: NearSigningRuntimeDeps;
  walletId: string;
  nearAccountId: AccountId;
  nearPublicKeyStr: string;
  signingOperation: FingerprintedSigningOperationContext;
  signatureUses: number;
}): Promise<{ transactionContext: TransactionContext; nonceLeases: NonceLeaseRef[] }> {
  const lane = nearNonceLane(args);
  const operation = {
    ...args.signingOperation,
    accountId: String(args.nearAccountId),
  };
  let latestError: unknown;
  for (let attempt = 1; attempt <= ACCESS_KEY_POLL_ATTEMPTS; attempt += 1) {
    try {
      const reserved = await args.ctx.nonceCoordinator.reserveNearContext({
        lane,
        operation,
        count: args.signatureUses,
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

export async function fundImplicitNearAccountAfterFreshAuth(args: {
  ctx: NearSigningRuntimeDeps;
  walletId: string;
  nearAccountId: AccountId;
  nearPublicKeyStr: string;
  walletSessionState: Pick<ResolvedRouterAbEd25519WalletSessionState, 'walletSessionAuth'>;
  signingOperation: FingerprintedSigningOperationContext;
  signatureUses: number;
}): Promise<{ transactionContext: TransactionContext; nonceLeases: NonceLeaseRef[] }> {
  const walletSessionJwt = String(
    args.walletSessionState.walletSessionAuth.walletSessionJwt || '',
  ).trim();
  if (!walletSessionJwt) {
    throw new Error('[SigningEngine][near] refreshed Wallet Session JWT is required for funding');
  }
  const funded = await fundImplicitNearAccountForTesting({
    relayerUrl: args.ctx.relayerUrl,
    walletId: args.walletId,
    nearAccountId: String(args.nearAccountId),
    nearPublicKeyStr: args.nearPublicKeyStr,
    walletSessionJwt,
  });
  if (!funded.ok) {
    throw new Error(funded.message || funded.code || 'Failed to fund implicit NEAR account');
  }
  return await reserveFundedImplicitNearTransactionContext(args);
}

export async function resolveConfirmedNearTransactionContext(args: {
  confirmation: SigningConfirmationResultWithTxContext;
  ctx: NearSigningRuntimeDeps;
  walletId: string;
  nearAccountId: AccountId;
  nearPublicKeyStr: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  signingOperation: FingerprintedSigningOperationContext;
  signatureUses: number;
}): Promise<{ transactionContext: TransactionContext; nonceLeases: NonceLeaseRef[] }> {
  switch (args.confirmation.kind) {
    case 'transaction_context_ready':
      return {
        transactionContext: args.confirmation.transactionContext,
        nonceLeases: args.confirmation.nonceLeases,
      };
    case 'implicit_account_funding_required':
      return await fundImplicitNearAccountAfterFreshAuth(args);
    default:
      return assertNeverConfirmedNearTransactionContext(args.confirmation);
  }
}

function assertNeverConfirmedNearTransactionContext(value: never): never {
  throw new Error(`Unsupported confirmed NEAR transaction context: ${String(value)}`);
}
