import {
  buildActiveWalletSessionAuthorizationProjection,
  type ActiveWalletSessionAuthorizationProjection,
  type WalletSessionAuthorizationRepository,
  type WalletSessionAuthorizationTokenBundle,
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
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletSessionAuthorizationId } from '@shared/authorization/capabilityKinds';
import type { WalletAuthMethod } from '@shared/utils/signerDomain';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { requireOpaqueWalletSessionToken } from '@shared/utils/sessionTokens';
import type { RegistrationEstablishedSession } from '@shared/utils/registrationEstablishedSession';

export type WalletSessionAuthorizationProjectionWriter = Pick<
  WalletSessionAuthorizationRepository,
  'createOrMergeExactActive' | 'replaceActive' | 'readActiveForWallet'
>;

type WalletSessionAuthorizationCurvePersistenceInputBase = {
  readonly walletId: WalletId;
  readonly authorizationId: WalletSessionAuthorizationId;
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

function walletSessionAuthorizationIdentityMatches(
  left: ActiveWalletSessionAuthorizationProjection,
  right: ActiveWalletSessionAuthorizationProjection,
): boolean {
  return (
    left.walletId === right.walletId &&
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
  input: WalletSessionAuthorizationCurvePersistenceInput,
  walletSessionToken: ReturnType<typeof requireOpaqueWalletSessionToken>,
): WalletSessionAuthorizationTokenBundle {
  return input.curve === 'ed25519'
    ? {
        kind: 'near_ed25519',
        ed25519: { walletSessionToken, thresholdSessionId: input.thresholdSessionId },
      }
    : {
        kind: 'evm_family_ecdsa',
        ecdsa: { walletSessionToken, thresholdSessionId: input.thresholdSessionId },
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
    authorizationId: args.authorizationId,
    walletSessionId: args.walletSessionId,
    quotaId: args.quotaId,
    walletSessionTokens: curveTokenBundle(args, walletSessionToken),
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
          walletSessionToken: requireOpaqueWalletSessionToken(
            session.tokens.ed25519.walletSessionToken,
          ),
          thresholdSessionId: session.tokens.ed25519.thresholdSessionId,
        },
      };
    case 'evm_family_ecdsa':
      return {
        kind: 'evm_family_ecdsa',
        ecdsa: {
          walletSessionToken: requireOpaqueWalletSessionToken(
            session.tokens.ecdsa.walletSessionToken,
          ),
          thresholdSessionId: session.tokens.ecdsa.thresholdSessionId,
        },
      };
    case 'near_ed25519_and_evm_family_ecdsa':
      return {
        kind: 'near_ed25519_and_evm_family_ecdsa',
        ed25519: {
          walletSessionToken: requireOpaqueWalletSessionToken(session.tokens.ed25519.walletSessionToken),
          thresholdSessionId: session.tokens.ed25519.thresholdSessionId,
        },
        ecdsa: {
          walletSessionToken: requireOpaqueWalletSessionToken(session.tokens.ecdsa.walletSessionToken),
          thresholdSessionId: session.tokens.ecdsa.thresholdSessionId,
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
  const authorizationId = parseWalletSessionAuthorizationId(
    String(session.authorizationSessionId),
  );
  if (!authorizationId.ok) {
    throw new Error('ECDSA bootstrap returned an invalid Wallet Session authorization id');
  }
  const thresholdSessionId = parseThresholdEcdsaSessionId(session.thresholdSessionId);
  if (!thresholdSessionId.ok) {
    throw new Error('ECDSA bootstrap returned an invalid threshold session id');
  }
  return await persistActiveWalletSessionAuthorizationCurve(writer, {
    walletId: args.walletId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    authorizationId: authorizationId.value,
    authMethod: args.authMethod,
    authority: args.authority,
    expiresAtMs: session.expiresAtMs,
    walletSessionToken: session.walletSessionToken,
    thresholdSessionId: thresholdSessionId.value,
    curve: 'ecdsa',
  });
}
