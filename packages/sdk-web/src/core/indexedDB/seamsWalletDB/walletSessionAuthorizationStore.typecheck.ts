import type {
  MpcWalletSigningQuotaId,
  SeamsSessionId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { WalletId } from '@shared/utils/domainIds';
import type { WalletAuthMethod } from '@shared/utils/signerDomain';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type {
  ActiveWalletSessionAuthorizationProjection,
  RetiredWalletSessionAuthorizationProjection,
  WalletSessionAuthorizationJwt,
} from './walletSessionAuthorizationStore';

declare const walletId: WalletId;
declare const authorizationSessionId: SeamsSessionId;
declare const walletSessionId: WalletSessionId;
declare const quotaId: MpcWalletSigningQuotaId;
declare const walletSessionJwt: WalletSessionAuthorizationJwt;
declare const authMethod: WalletAuthMethod;
declare const authority: WalletAuthAuthorityRef;

const active: ActiveWalletSessionAuthorizationProjection = {
  recordVersion: 'wallet_session_authorization_v1',
  status: 'active',
  walletId,
  authorizationSessionId,
  walletSessionId,
  quotaId,
  walletSessionJwt,
  authMethod,
  authority,
  expiresAtMs: 1_900_000_000_000,
};

const retired: RetiredWalletSessionAuthorizationProjection = {
  recordVersion: 'wallet_session_authorization_v1',
  status: 'retired',
  walletId,
  authorizationSessionId,
  walletSessionId,
  quotaId,
  authMethod,
  authority,
  expiresAtMs: 1_900_000_000_000,
  retirementReason: 'expired',
  retiredAtMs: 1_900_000_000_001,
};

// @ts-expect-error Exact active authorization requires its quota identity.
const activeWithoutQuota: ActiveWalletSessionAuthorizationProjection = {
  recordVersion: 'wallet_session_authorization_v1',
  status: 'active',
  walletId,
  authorizationSessionId,
  walletSessionId,
  walletSessionJwt,
  authMethod,
  authority,
  expiresAtMs: 1_900_000_000_000,
};

const retiredWithJwt: RetiredWalletSessionAuthorizationProjection = {
  ...retired,
  // @ts-expect-error Retired authorization cannot retain bearer authority.
  walletSessionJwt,
};

void active;
void retiredWithJwt;
