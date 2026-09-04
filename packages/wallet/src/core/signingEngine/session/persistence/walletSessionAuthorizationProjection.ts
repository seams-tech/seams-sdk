import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking/contracts';
import type { WalletSessionAuthorizationRepository } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { RegistrationEstablishedSessionV2 } from '@shared/utils/registrationEstablishedSession';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import type { WalletAuthMethodId } from '@shared/utils/domainIds';

/** The exact authorization persisted alongside its operation credential. */
export type ExactWalletSessionAuthorization = {
  readonly record: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
};

export type ExactWalletSessionAuthorityIdentity = {
  readonly walletId: ActiveWalletAuthorityV1['walletId'];
  readonly authorityId: ActiveWalletAuthorityV1['authorityId'];
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authorityDigestB64u: ActiveWalletAuthorityV1['authorityDigestB64u'];
  readonly authorityRevocationEpoch: ActiveWalletAuthorityV1['revocationEpoch'];
};

export function exactWalletSessionAuthorityIdentity(args: {
  readonly authority: ActiveWalletAuthorityV1;
  readonly walletAuthMethodId: WalletAuthMethodId;
}): ExactWalletSessionAuthorityIdentity {
  return {
    walletId: args.authority.walletId,
    authorityId: args.authority.authorityId,
    walletAuthMethodId: args.walletAuthMethodId,
    authorityDigestB64u: args.authority.authorityDigestB64u,
    authorityRevocationEpoch: args.authority.revocationEpoch,
  };
}

type ExactWalletSessionAuthorizationWriter = Pick<
  WalletSessionAuthorizationRepository,
  'writeExactWithOperationCredential'
>;

export function validateExactWalletSessionAuthorization(args: {
  readonly walletId: WalletId;
  readonly authority: WalletAuthAuthorityRef;
  readonly walletSession: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly expectedAuthorizationId: string;
  readonly expectedWalletSessionId: string;
  readonly expectedQuotaId: string;
  readonly expectedExpiresAtMs: number;
}): ExactWalletSessionAuthorization {
  const { walletSession, operationCredential } = args;
  if (
    walletSession.walletId !== args.walletId ||
    walletSession.authMethodId !== args.authority.walletAuthMethodId ||
    walletSession.authorizationId !== args.expectedAuthorizationId ||
    walletSession.quotaId !== args.expectedQuotaId ||
    walletSession.expiresAtMs !== args.expectedExpiresAtMs ||
    operationCredential.walletSessionId !== args.expectedWalletSessionId
  ) {
    throw new Error('ECDSA bootstrap exact Wallet Session authority does not match its request');
  }
  return { record: walletSession, operationCredential };
}

export function validateExactWalletSessionAuthorityIdentity(args: {
  readonly expected: ExactWalletSessionAuthorityIdentity;
  readonly walletSession: ActiveWalletSessionV1;
}): void {
  if (
    args.walletSession.walletId !== args.expected.walletId ||
    args.walletSession.authorityId !== args.expected.authorityId ||
    args.walletSession.authMethodId !== args.expected.walletAuthMethodId ||
    args.walletSession.authorityDigestB64u !== args.expected.authorityDigestB64u ||
    args.walletSession.authorityRevocationEpoch !== args.expected.authorityRevocationEpoch
  ) {
    throw new Error('ECDSA bootstrap exact Wallet Session authority identity changed');
  }
}

export async function persistActiveWalletSessionAuthorizationFromDirectRegistration(
  writer: ExactWalletSessionAuthorizationWriter,
  session: RegistrationEstablishedSessionV2,
): Promise<ExactWalletSessionAuthorization> {
  const record = await writer.writeExactWithOperationCredential({
    record: session.walletSession,
    operationCredential: session.operationCredential,
  });
  return {
    record,
    operationCredential: session.operationCredential,
  };
}

export async function persistExactWalletSessionAuthorizationFromEcdsaBootstrap(
  writer: ExactWalletSessionAuthorizationWriter,
  args: {
    readonly walletId: WalletId;
    readonly authority: WalletAuthAuthorityRef;
    readonly bootstrap: ThresholdEcdsaSessionBootstrapResult;
  },
): Promise<ExactWalletSessionAuthorization> {
  const session = args.bootstrap.session;
  const exact = validateExactWalletSessionAuthorization({
    walletId: args.walletId,
    authority: args.authority,
    walletSession: session.walletSession,
    operationCredential: session.operationCredential,
    expectedAuthorizationId: session.authorizationId,
    expectedWalletSessionId: session.walletSessionId,
    expectedQuotaId: session.quotaId,
    expectedExpiresAtMs: session.expiresAtMs,
  });
  const record = await writer.writeExactWithOperationCredential(exact);
  return {
    record,
    operationCredential: exact.operationCredential,
  };
}
