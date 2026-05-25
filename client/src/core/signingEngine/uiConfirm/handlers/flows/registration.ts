import type { UiConfirmContext } from '../../types';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import { TransactionSummary, RegistrationUserConfirmRequest } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { UserConfirmSecurityContext } from '@/core/types';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import { sha256Base64UrlUtf8 } from '@/utils/intentDigest';
import { isUserCancelledUserConfirm, ERROR_MESSAGES } from '@/core/signingEngine/stepUpConfirmation/channel/confirmCommon';
import { getNearAccountId, getIntentDigest, getRegisterAccountPayload } from './adapters/request';
import {
  isSerializedRegistrationCredential,
  serializeRegistrationCredentialWithPRF,
} from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import { toError } from '@shared/utils/errors';
import { createConfirmSession, createConfirmTxFlowAdapters } from './adapters/adapters';
import type { ThemeName } from '@/core/types/seams';

export async function handleRegistrationFlow(
  ctx: UiConfirmContext,
  request: RegistrationUserConfirmRequest,
  worker: Worker,
  opts: {
    confirmationConfig: ConfirmationConfig;
    transactionSummary: TransactionSummary;
    theme: ThemeName;
  },
): Promise<void> {
  const { confirmationConfig, transactionSummary, theme } = opts;
  const adapters = createConfirmTxFlowAdapters(ctx);
  const session = createConfirmSession({
    adapters,
    worker,
    request,
    confirmationConfig,
    transactionSummary,
    theme,
  });
  const nearAccountId = getNearAccountId(request);

  try {
    const requestedChallenge = request.payload.webauthnChallenge;
    const explicitChallengeB64u =
      requestedChallenge?.kind === 'intent_digest'
        ? String(requestedChallenge.challengeB64u || '').trim()
        : '';

    const computeBoundIntentDigestB64u = async (): Promise<string> => {
      if (explicitChallengeB64u) return explicitChallengeB64u;
      const uiIntentDigest = getIntentDigest(request);
      if (!uiIntentDigest) {
        throw new Error('Missing intentDigest for registration flow');
      }
      return sha256Base64UrlUtf8(uiIntentDigest);
    };

    // 2) WebAuthn registration challenge (32 bytes, base64url)
    const rpId = adapters.security.getRpId();
    if (!rpId) throw new Error('Missing rpId for registration challenge');

    let challengeB64u = await computeBoundIntentDigestB64u();
    const securityContext: UserConfirmSecurityContext = {
      rpId,
    };

    // 3) UI confirm
    const { confirmed, error: uiError } = await session.promptUser({ securityContext });
    if (!confirmed) {
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: false,
        error: uiError,
      });
    }

    // 4) Collect registration credentials (with duplicate retry)
    let credential: PublicKeyCredential | undefined;
    let signerSlot = request.payload?.signerSlot ?? 1;

    const tryCreate = async (slot?: number): Promise<PublicKeyCredential> => {
      return await adapters.webauthn.createRegistrationCredential({
        nearAccountId,
        challengeB64u,
        signerSlot: slot,
      });
    };

    try {
      credential = await tryCreate(signerSlot);
    } catch (e: unknown) {
      const err = toError(e);
      const name = String(err?.name || '');
      const msg = String(err?.message || '');
      const isDuplicate =
        name === 'InvalidStateError' || /excluded|already\s*registered/i.test(msg);

      if (isDuplicate) {
        if (explicitChallengeB64u) {
          throw new Error(
            'Registration credential already exists for this wallet registration intent; create a fresh intent before retrying',
          );
        }
        const nextSignerSlot =
          signerSlot !== undefined && Number.isFinite(signerSlot) ? signerSlot + 1 : 2;
        // Keep request payload and intentDigest in sync with the signer-slot retry.
        signerSlot = nextSignerSlot;
        getRegisterAccountPayload(request).signerSlot = nextSignerSlot;
        request.intentDigest =
          request.type === 'registerAccount'
            ? `register:${nearAccountId}:${nextSignerSlot}`
            : `device2-register:${nearAccountId}:${nextSignerSlot}`;

        challengeB64u = await computeBoundIntentDigestB64u();

        credential = await tryCreate(nextSignerSlot);
      } else {
        console.error('[RegistrationFlow] credentials.create failed (non-duplicate)', {
          name,
          msg,
        });
        throw err;
      }
    }

    // We require registration credentials to include dual PRF outputs (first + second)
    // so wallet-origin code can pass PRF outputs directly to signer workers when deriving keys.
    const serialized: WebAuthnRegistrationCredential = isSerializedRegistrationCredential(
      credential,
    )
      ? (credential as unknown as WebAuthnRegistrationCredential)
      : serializeRegistrationCredentialWithPRF({
          credential: credential! as PublicKeyCredential,
          firstPrfOutput: true,
          secondPrfOutput: true,
        });

    // 5) Respond + close
    session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: getIntentDigest(request),
      confirmed: true,
      credential: serialized,
    });
  } catch (err: unknown) {
    const cancelled = isUserCancelledUserConfirm(err);
    const msg = String(toError(err)?.message || err || '');
    if (cancelled) {
      window.parent?.postMessage({ type: 'WALLET_UI_CLOSED' }, '*');
    }

    const isPrfBrowserUnsupported =
      /WebAuthn PRF output is missing from navigator\.credentials\.create\(\)/i.test(msg) ||
      /does not fully support the WebAuthn PRF extension during registration/i.test(msg) ||
      /roaming hardware authenticators .* not supported in this flow/i.test(msg);

    return session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: getIntentDigest(request),
      confirmed: false,
      error: cancelled
        ? ERROR_MESSAGES.cancelled
        : isPrfBrowserUnsupported
          ? msg
          : msg || ERROR_MESSAGES.collectCredentialsFailed,
    });
  }
}
