import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '../../interfaces/ecdsaChainTarget';
import type { NearFundingRequest } from '../../nonce/nearTransactionReadiness';
import { SigningOperationIntent, SigningSessionIds } from '../../session/operationState/types';
import type { FreshWalletSessionAuthority } from './implicitAccountFunding';

const nearAccountId = toAccountId('b'.repeat(64));
const walletId = toWalletId('wallet');
const request: NearFundingRequest = {
  subject: {
    walletId,
    nearAccountId,
    nearPublicKeyStr: 'ed25519:public-key',
  },
  operation: {
    operationId: SigningSessionIds.signingOperation('operation'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint'),
    intent: SigningOperationIntent.TransactionSign,
    accountId: nearAccountId,
  },
  signatureUses: 1,
};

// @ts-expect-error Fresh funding authority can only be created by the post-auth boundary.
const forgedFreshAuthority: FreshWalletSessionAuthority = {
  kind: 'near_wallet_session_funding_authority',
  provenance: 'passkey_reauth',
  request,
  thresholdSessionId: SigningSessionIds.thresholdEd25519Session('threshold-session'),
  walletSessionJwt: 'forged-wallet-session-jwt',
};

void forgedFreshAuthority;
