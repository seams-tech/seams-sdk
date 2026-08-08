import type {
  MpcWalletSigningQuotaId,
  SeamsSessionId,
  WalletSessionAuthorizationId,
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
declare const authorizationId: WalletSessionAuthorizationId;
declare const walletSessionId: WalletSessionId;
declare const quotaId: MpcWalletSigningQuotaId;
declare const walletSessionJwt: WalletSessionAuthorizationJwt;
declare const authMethod: WalletAuthMethod;
declare const authority: WalletAuthAuthorityRef;

const active: ActiveWalletSessionAuthorizationProjection = {
  recordVersion: 'wallet_session_authorization_v2',
  status: 'active',
  walletId,
  seamsSessionId: authorizationSessionId,
  authorizationId,
  walletSessionId,
  quotaId,
  walletSessionTokens: {
    kind: 'evm_family_ecdsa',
    ecdsa: { walletSessionJwt },
  },
  authMethod,
  authority,
  expiresAtMs: 1_900_000_000_000,
};

const retired: RetiredWalletSessionAuthorizationProjection = {
  recordVersion: 'wallet_session_authorization_v2',
  status: 'retired',
  walletId,
  seamsSessionId: authorizationSessionId,
  authorizationId,
  walletSessionId,
  quotaId,
  authMethod,
  authority,
  expiresAtMs: 1_900_000_000_000,
  retirementReason: 'expired',
  retiredAtMs: 1_900_000_000_001,
};

// @ts-expect-error Exact active authorization requires its curve token bundle.
const activeWithoutQuota: ActiveWalletSessionAuthorizationProjection = {
  recordVersion: 'wallet_session_authorization_v2',
  status: 'active',
  walletId,
  seamsSessionId: authorizationSessionId,
  authorizationId,
  walletSessionId,
  authMethod,
  authority,
  expiresAtMs: 1_900_000_000_000,
};

const retiredWithJwt: RetiredWalletSessionAuthorizationProjection = {
  ...retired,
  // @ts-expect-error Retired authorization cannot retain bearer authority.
  walletSessionJwt,
};

const activeWithLegacySessionField: ActiveWalletSessionAuthorizationProjection = {
  ...active,
  // @ts-expect-error App-session identity is named seamsSessionId in local projections.
  authorizationSessionId,
};

void active;
void retiredWithJwt;
void activeWithLegacySessionField;
