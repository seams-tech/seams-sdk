import type { RouterApiEmailRecoveryAuthService, RouterApiOptions } from './routerApi';
import {
  parseRouterAbEd25519BootstrapSessionJwtSessionInfo,
  signRouterAbEd25519WalletSessionJwt,
} from './commonRouterUtils';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';

type EmailRecoveryPrepareResult = Awaited<
  ReturnType<RouterApiEmailRecoveryAuthService['prepareEmailRecovery']>
>;
type EmailRecoveryRespondResult = Awaited<
  ReturnType<RouterApiEmailRecoveryAuthService['respondEmailRecoveryEcdsa']>
>;

export type EmailRecoverySuccessResult =
  | Extract<EmailRecoveryPrepareResult, { ok: true }>
  | Extract<EmailRecoveryRespondResult, { ok: true }>;

export type EmailRecoveryThresholdSessionSignResult =
  | { ok: true }
  | {
      ok: false;
      status: number;
      body: {
        ok: false;
        code: string;
        message: string;
      };
    };

export async function signEmailRecoveryThresholdSessionJwt(input: {
  result: EmailRecoverySuccessResult;
  session: RouterApiOptions['session'];
}): Promise<EmailRecoveryThresholdSessionSignResult> {
  const thresholdSession = input.result.thresholdEd25519.session;
  if (!thresholdSession) return { ok: true };
  if (thresholdSession.sessionKind !== 'jwt') {
    return {
      ok: false,
      status: 400,
      body: {
        ok: false,
        code: 'invalid_body',
        message: 'threshold_ed25519.session_kind must be jwt',
      },
    };
  }

  const sessionInfo = parseRouterAbEd25519BootstrapSessionJwtSessionInfo(thresholdSession);
  if (!sessionInfo) {
    return {
      ok: false,
      status: 500,
      body: {
        ok: false,
        code: 'internal',
        message: 'invalid thresholdEd25519 session payload for jwt signing',
      },
    };
  }

  const signed = await signRouterAbEd25519WalletSessionJwt({
    session: input.session,
    userId: sessionInfo.walletId,
    authority: buildPasskeyWalletAuthAuthority({
      walletId: input.result.walletBinding.walletId,
      rpId: input.result.walletBinding.rpId,
      credentialIdB64u: input.result.credentialIdB64u,
    }),
    relayerKeyId: input.result.thresholdEd25519.relayerKeyId,
    sessionInfo,
    fallbackParticipantIds: input.result.thresholdEd25519.participantIds,
    requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
    invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
  });
  if (!signed.ok) {
    return {
      ok: false,
      status: signed.status,
      body: { ok: false, code: signed.code, message: signed.message },
    };
  }

  thresholdSession.jwt = signed.jwt;
  return { ok: true };
}
