import type { AccountId } from '@/core/types/accountIds';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { NearEd25519YaoSigningCapability } from '@/core/signingEngine/interfaces/near';
import {
  Ed25519YaoActiveClientRegistry,
  type Ed25519YaoActiveClientIdentityV1,
} from './yaoActiveClientRegistry';

declare const walletId: WalletId;
declare const nearAccountId: AccountId;
declare const walletSessionState: NearEd25519YaoSigningCapability['walletSessionState'];

const validIdentity = {
  walletId,
  nearAccountId,
  thresholdSessionId: 'threshold-session-1',
} satisfies Ed25519YaoActiveClientIdentityV1;

const registry = new Ed25519YaoActiveClientRegistry();
void registry.resolve(validIdentity);
void registry.refreshWalletSession({
  kind: 'same_identity_wallet_session_refresh_v1',
  identity: validIdentity,
  signingGrantId: 'signing-grant-1',
  nextWalletSessionState: walletSessionState,
});
void registry.disposeWallet(walletId);

// @ts-expect-error Active Client lookup requires the wallet identity.
registry.resolve({ nearAccountId, thresholdSessionId: 'threshold-session-1' });

// @ts-expect-error Active Client lookup requires the NEAR account identity.
registry.resolve({ walletId, thresholdSessionId: 'threshold-session-1' });

// @ts-expect-error Same-identity refresh requires the exact signing grant.
registry.refreshWalletSession({
  kind: 'same_identity_wallet_session_refresh_v1',
  identity: validIdentity,
  nextWalletSessionState: walletSessionState,
});
