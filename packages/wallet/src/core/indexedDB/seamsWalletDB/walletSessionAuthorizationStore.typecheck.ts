import type {
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { ThresholdEcdsaSessionId, WalletId } from '@shared/utils/domainIds';
import type { WalletAuthMethod } from '@shared/utils/signerDomain';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type {
  ActiveWalletSessionAuthorizationProjection,
  RetiredWalletSessionAuthorizationProjection,
  WalletSessionAuthorizationToken,
} from './walletSessionAuthorizationStore';

declare const walletId: WalletId;
declare const authorizationId: WalletSessionAuthorizationId;
declare const walletSessionId: WalletSessionId;
declare const quotaId: MpcWalletSigningQuotaId;
declare const walletSessionToken: WalletSessionAuthorizationToken;
declare const thresholdSessionId: ThresholdEcdsaSessionId;
declare const authMethod: WalletAuthMethod;
declare const authority: WalletAuthAuthorityRef;

const active: ActiveWalletSessionAuthorizationProjection = {
  recordVersion: 'wallet_session_authorization_v3',
  status: 'active',
  walletId,
  walletSessionId,
  quotaId,
  walletSessionTokens: {
    kind: 'evm_family_ecdsa',
    ecdsa: { authorizationId, walletSessionToken, thresholdSessionId },
  },
  authMethod,
  authority,
  expiresAtMs: 1_900_000_000_000,
};

const retired: RetiredWalletSessionAuthorizationProjection = {
  recordVersion: 'wallet_session_authorization_v3',
  status: 'retired',
  walletId,
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
  recordVersion: 'wallet_session_authorization_v3',
  status: 'active',
  walletId,
  walletSessionId,
  authMethod,
  authority,
  expiresAtMs: 1_900_000_000_000,
};

const retiredWithToken: RetiredWalletSessionAuthorizationProjection = {
  ...retired,
  // @ts-expect-error Retired authorization cannot retain bearer authority.
  walletSessionToken,
};

const activeWithLegacySessionField: ActiveWalletSessionAuthorizationProjection = {
  ...active,
  // @ts-expect-error Legacy session identity fields are rejected by local projections.
  authorizationSessionId,
};

void active;
void retiredWithToken;
void activeWithLegacySessionField;
