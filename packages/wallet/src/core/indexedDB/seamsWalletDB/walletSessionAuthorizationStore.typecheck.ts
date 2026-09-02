import type {
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { WalletAuthMethodId, WalletAuthorityId, WalletId } from '@shared/utils/domainIds';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
  WalletSessionAuthorizationExactActiveReadResult,
  WalletSessionAuthorizationExactOperationCredentialReadResult,
} from './walletSessionAuthorizationStore';

declare const walletId: WalletId;
declare const authorityId: WalletAuthorityId;
declare const authMethodId: WalletAuthMethodId;
declare const authorizationId: WalletSessionAuthorizationId;
declare const walletSessionId: WalletSessionId;
declare const record: ActiveWalletSessionV1;
declare const operationCredential: WalletSessionOperationCredentialV1;

const exactAuthorization = {
  record,
  operationCredential,
} satisfies {
  readonly record: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
};

const found: WalletSessionAuthorizationExactOperationCredentialReadResult = {
  kind: 'found',
  ...exactAuthorization,
};
const missing: WalletSessionAuthorizationExactActiveReadResult = { kind: 'missing' };
const upgradeRequired: WalletSessionAuthorizationExactActiveReadResult = {
  kind: 'upgrade_required',
};
const corrupt: WalletSessionAuthorizationExactActiveReadResult = { kind: 'corrupt' };
const unavailable: WalletSessionAuthorizationExactActiveReadResult = {
  kind: 'persistence_unavailable',
};

// A credential-free result cannot cross the exact authorization boundary.
// @ts-expect-error Exact authorization requires the paired operation credential.
const missingCredential = { record } satisfies {
  readonly record: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
};

void walletId;
void authorityId;
void authMethodId;
void authorizationId;
void walletSessionId;
void found;
void missing;
void upgradeRequired;
void corrupt;
void unavailable;
void missingCredential;
