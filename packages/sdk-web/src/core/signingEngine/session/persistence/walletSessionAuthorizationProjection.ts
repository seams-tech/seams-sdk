import {
  buildActiveWalletSessionAuthorizationProjection,
  requireWalletSessionAuthorizationJwt,
  type ActiveWalletSessionAuthorizationProjection,
  type WalletSessionAuthorizationRepository,
  type WalletSessionAuthorizationTokenBundle,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type {
  MpcWalletSigningQuotaId,
  SeamsSessionId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { WalletAuthMethod } from '@shared/utils/signerDomain';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { parseWalletSessionAuthorizationIdentityClaims } from '../identity/walletSessionAuthorizationJwt';
import type { RegistrationEstablishedSession } from '@shared/utils/registrationEstablishedSession';

export type WalletSessionAuthorizationProjectionWriter = Pick<
  WalletSessionAuthorizationRepository,
  'createOrMergeExactActive' | 'replaceActive' | 'readActiveForWallet'
>;

type WalletSessionAuthorizationCurvePersistenceInputBase = {
  readonly walletId: WalletId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly authority: WalletAuthAuthorityRef;
  readonly authMethod: WalletAuthMethod;
  readonly walletSessionJwt: string;
};

export type WalletSessionAuthorizationCurvePersistenceInput =
  | (WalletSessionAuthorizationCurvePersistenceInputBase & {
      readonly curve: 'ed25519';
      readonly authorizationSessionId?: never;
    })
  | (WalletSessionAuthorizationCurvePersistenceInputBase & {
      readonly curve: 'ecdsa';
      readonly authorizationSessionId: SeamsSessionId;
    });

function walletSessionAuthorizationIdentityMatches(
  left: ActiveWalletSessionAuthorizationProjection,
  right: ActiveWalletSessionAuthorizationProjection,
): boolean {
  return (
    left.walletId === right.walletId &&
    left.seamsSessionId === right.seamsSessionId &&
    left.authorizationId === right.authorizationId &&
    left.walletSessionId === right.walletSessionId &&
    left.quotaId === right.quotaId &&
    left.authMethod === right.authMethod &&
    left.authority.kind === right.authority.kind &&
    left.authority.walletId === right.authority.walletId &&
    left.authority.authorityDigest === right.authority.authorityDigest
  );
}

function curveTokenBundle(
  curve: WalletSessionAuthorizationCurvePersistenceInput['curve'],
  walletSessionJwt: ReturnType<typeof requireWalletSessionAuthorizationJwt>,
): WalletSessionAuthorizationTokenBundle {
  return curve === 'ed25519'
    ? { kind: 'near_ed25519', ed25519: { walletSessionJwt } }
    : { kind: 'evm_family_ecdsa', ecdsa: { walletSessionJwt } };
}

export async function persistActiveWalletSessionAuthorizationCurve(
  writer: WalletSessionAuthorizationProjectionWriter,
  args: WalletSessionAuthorizationCurvePersistenceInput,
): Promise<ActiveWalletSessionAuthorizationProjection> {
  const claims = parseWalletSessionAuthorizationIdentityClaims(args.walletSessionJwt);
  if (
    !claims ||
    claims.sessionBinding.kind !== 'seams_session' ||
    claims.walletId !== args.walletId ||
    claims.walletSessionId !== args.walletSessionId ||
    claims.quotaId !== args.quotaId ||
    claims.expiresAtMs < args.expiresAtMs ||
    (args.curve === 'ecdsa' &&
      (claims.sessionBinding.kind !== 'seams_session' ||
        claims.sessionBinding.seamsSessionId !== args.authorizationSessionId))
  ) {
    throw new Error('Wallet Session JWT identity does not match the activated session');
  }
  const active = buildActiveWalletSessionAuthorizationProjection({
    walletId: args.walletId,
    seamsSessionId: claims.sessionBinding.seamsSessionId,
    authorizationId: claims.authorizationId,
    walletSessionId: args.walletSessionId,
    quotaId: args.quotaId,
    walletSessionTokens: curveTokenBundle(
      args.curve,
      requireWalletSessionAuthorizationJwt(args.walletSessionJwt),
    ),
    authMethod: args.authMethod,
    authority: args.authority,
    expiresAtMs: args.expiresAtMs,
  });
  const current = await writer.readActiveForWallet(args.walletId);
  switch (current.kind) {
    case 'missing':
      await writer.replaceActive({ active, replacedAtMs: Date.now() });
      return active;
    case 'found':
      if (walletSessionAuthorizationIdentityMatches(current.projection, active)) {
        return writer.createOrMergeExactActive({ incoming: active, mergedAtMs: Date.now() });
      }
      await writer.replaceActive({ active, replacedAtMs: Date.now() });
      return active;
    case 'corrupt':
      throw new Error('Stored Wallet Session authorization projection is corrupt');
    case 'persistence_unavailable':
      throw new Error('Wallet Session authorization projection persistence is unavailable');
    default:
      return assertNeverWalletSessionAuthorizationReadResult(current);
  }
}

function assertNeverWalletSessionAuthorizationReadResult(value: never): never {
  throw new Error(`Unknown Wallet Session authorization read result: ${String(value)}`);
}

function registrationSessionTokenBundle(
  session: RegistrationEstablishedSession,
): WalletSessionAuthorizationTokenBundle {
  switch (session.tokens.kind) {
    case 'near_ed25519':
      return {
        kind: 'near_ed25519',
        ed25519: {
          walletSessionJwt: requireWalletSessionAuthorizationJwt(
            session.tokens.ed25519.walletSessionJwt,
          ),
        },
      };
    case 'evm_family_ecdsa':
      return {
        kind: 'evm_family_ecdsa',
        ecdsa: {
          walletSessionJwt: requireWalletSessionAuthorizationJwt(
            session.tokens.ecdsa.walletSessionJwt,
          ),
        },
      };
    case 'near_ed25519_and_evm_family_ecdsa':
      return {
        kind: 'near_ed25519_and_evm_family_ecdsa',
        ed25519: {
          walletSessionJwt: requireWalletSessionAuthorizationJwt(
            session.tokens.ed25519.walletSessionJwt,
          ),
        },
        ecdsa: {
          walletSessionJwt: requireWalletSessionAuthorizationJwt(
            session.tokens.ecdsa.walletSessionJwt,
          ),
        },
      };
    default:
      return assertNeverRegistrationSessionTokens(session.tokens);
  }
}

function assertNeverRegistrationSessionTokens(value: never): never {
  throw new Error(`Unknown registration-established token bundle: ${String(value)}`);
}

export async function persistActiveWalletSessionAuthorizationFromRegistration(
  writer: WalletSessionAuthorizationProjectionWriter,
  args: {
    readonly authority: WalletAuthAuthorityRef;
    readonly authMethod: WalletAuthMethod;
    readonly session: RegistrationEstablishedSession;
  },
): Promise<ActiveWalletSessionAuthorizationProjection> {
  const active = buildActiveWalletSessionAuthorizationProjection({
    walletId: args.session.walletId,
    seamsSessionId: args.session.seamsSessionId,
    authorizationId: args.session.authorizationId,
    walletSessionId: args.session.walletSessionId,
    quotaId: args.session.quotaId,
    walletSessionTokens: registrationSessionTokenBundle(args.session),
    authMethod: args.authMethod,
    authority: args.authority,
    expiresAtMs: args.session.expiresAtMs,
  });
  return writer.createOrMergeExactActive({ incoming: active, mergedAtMs: Date.now() });
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
  return await persistActiveWalletSessionAuthorizationCurve(writer, {
    walletId: args.walletId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    authorizationSessionId: session.authorizationSessionId,
    authMethod: args.authMethod,
    authority: args.authority,
    expiresAtMs: session.expiresAtMs,
    walletSessionJwt: session.jwt,
    curve: 'ecdsa',
  });
}
