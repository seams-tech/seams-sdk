import {
  buildActiveWalletSessionAuthorizationProjection,
  type ActiveWalletSessionAuthorizationProjection,
  type WalletSessionAuthorizationRepository,
  type WalletSessionAuthorizationTokenBundle,
  type ActiveWalletSessionV1,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import { parseThresholdEcdsaSessionId } from '@shared/utils/domainIds';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type {
  MpcWalletSigningQuotaId,
  ReusableWalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { WalletAuthMethod } from '@shared/utils/signerDomain';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { requireOpaqueWalletSessionToken } from '@shared/utils/sessionTokens';
import type {
  RegistrationEstablishedSessionV2,
} from '@shared/utils/registrationEstablishedSession';

export type WalletSessionAuthorizationProjectionWriter = Pick<
  WalletSessionAuthorizationRepository,
  'upsertActiveWithCurveMerge' | 'writeExactWithOperationCredential'
>;

type WalletSessionAuthorizationCurvePersistenceInputBase = {
  readonly walletId: WalletId;
  readonly authorizationId: ReusableWalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly authority: WalletAuthAuthorityRef;
  readonly authMethod: WalletAuthMethod;
  readonly walletSessionToken: string;
};

export type WalletSessionAuthorizationCurvePersistenceInput =
  | (WalletSessionAuthorizationCurvePersistenceInputBase & {
      readonly curve: 'ed25519';
      readonly thresholdSessionId: ThresholdEd25519SessionId;
    })
  | (WalletSessionAuthorizationCurvePersistenceInputBase & {
      readonly curve: 'ecdsa';
      readonly thresholdSessionId: ThresholdEcdsaSessionId;
    });

function curveTokenBundle(
  input: WalletSessionAuthorizationCurvePersistenceInput,
  walletSessionToken: ReturnType<typeof requireOpaqueWalletSessionToken>,
): WalletSessionAuthorizationTokenBundle {
  return input.curve === 'ed25519'
    ? {
        kind: 'near_ed25519',
        ed25519: {
          authorizationId: input.authorizationId,
          walletSessionToken,
          thresholdSessionId: input.thresholdSessionId,
        },
      }
    : {
        kind: 'evm_family_ecdsa',
        ecdsa: {
          authorizationId: input.authorizationId,
          walletSessionToken,
          thresholdSessionId: input.thresholdSessionId,
        },
      };
}

export async function persistActiveWalletSessionAuthorizationCurve(
  writer: WalletSessionAuthorizationProjectionWriter,
  args: WalletSessionAuthorizationCurvePersistenceInput,
): Promise<ActiveWalletSessionAuthorizationProjection> {
  const walletSessionToken = requireOpaqueWalletSessionToken(
    args.walletSessionToken,
    'walletSessionToken',
  );
  const active = buildActiveWalletSessionAuthorizationProjection({
    walletId: args.walletId,
    walletSessionId: args.walletSessionId,
    quotaId: args.quotaId,
    walletSessionTokens: curveTokenBundle(args, walletSessionToken),
    authMethod: args.authMethod,
    authority: args.authority,
    expiresAtMs: args.expiresAtMs,
  });
  return writer.upsertActiveWithCurveMerge({ incoming: active, writtenAtMs: Date.now() });
}

export async function persistActiveWalletSessionAuthorizationFromDirectRegistration(
  writer: Pick<WalletSessionAuthorizationRepository, 'writeExactWithOperationCredential'>,
  session: RegistrationEstablishedSessionV2,
): Promise<ActiveWalletSessionV1> {
  return writer.writeExactWithOperationCredential({
    record: session.walletSession,
    operationCredential: session.operationCredential,
  });
}

export async function persistActiveWalletSessionAuthorizationFromEcdsaBootstrap(
  writer: WalletSessionAuthorizationProjectionWriter,
  args: {
    readonly walletId: WalletId;
    readonly authority: WalletAuthAuthorityRef;
    readonly authMethod: WalletAuthMethod;
    readonly bootstrap: ThresholdEcdsaSessionBootstrapResult;
  },
): Promise<ActiveWalletSessionAuthorizationProjection> {
  const session = args.bootstrap.session;
  if (session.walletSession.walletId !== args.walletId) {
    throw new Error('ECDSA bootstrap exact Wallet Session identifies a different wallet');
  }
  await writer.writeExactWithOperationCredential({
    record: session.walletSession,
    operationCredential: session.operationCredential,
  });
  const thresholdSessionId = parseThresholdEcdsaSessionId(session.thresholdSessionId);
  if (!thresholdSessionId.ok) {
    throw new Error('ECDSA bootstrap returned an invalid threshold session id');
  }
  const walletSessionToken = requireOpaqueWalletSessionToken(
    session.operationCredential.token,
    'operationCredential.token',
  );
  return buildActiveWalletSessionAuthorizationProjection({
    walletId: args.walletId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    walletSessionTokens: curveTokenBundle(
      {
        walletId: args.walletId,
        walletSessionId: session.walletSessionId,
        quotaId: session.quotaId,
        authorizationId: session.authorizationId,
        authMethod: args.authMethod,
        authority: args.authority,
        expiresAtMs: session.expiresAtMs,
        walletSessionToken,
        thresholdSessionId: thresholdSessionId.value,
        curve: 'ecdsa',
      },
      walletSessionToken,
    ),
    authMethod: args.authMethod,
    authority: args.authority,
    expiresAtMs: session.expiresAtMs,
  });
}
