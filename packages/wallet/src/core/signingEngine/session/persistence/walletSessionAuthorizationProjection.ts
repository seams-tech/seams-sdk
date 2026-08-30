import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking/contracts';
import type { WalletSessionAuthorizationRepository } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { RegistrationEstablishedSessionV2 } from '@shared/utils/registrationEstablishedSession';

/** The exact authorization persisted alongside its operation credential. */
export type ExactWalletSessionAuthorization = {
  readonly record: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
};

type ExactWalletSessionAuthorizationWriter = Pick<
  WalletSessionAuthorizationRepository,
  'writeExactWithOperationCredential'
>;

function validateExactWalletSessionAuthorization(args: {
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
