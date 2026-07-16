import type { UiConfirmContext } from '../../uiConfirm.types';
import type { NormalizedConfirmationConfig } from '@/core/types/confirmationConfig';
import {
  TransactionSummary,
  RegistrationUserConfirmRequest,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { PasskeyRegistrationConfirmDisplay, UserConfirmSecurityContext } from '@/core/types';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import { sha256Base64UrlUtf8 } from '@/utils/intentDigest';
import {
  isUserCancelledUserConfirm,
  ERROR_MESSAGES,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmCommon';
import {
  getNearAccountId,
  getWalletId,
  getIntentDigest,
  getRegisterAccountPayload,
} from './adapters/request';
import {
  isSerializedRegistrationCredential,
  serializeRegistrationCredentialWithPRF,
} from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import { toError } from '@shared/utils/errors';
import { createConfirmSession, createConfirmTxFlowAdapters } from './adapters/adapters';
import type { ThemeMode } from '@/core/types/seams';
import type { RegistrationConfirmationDiagnostics } from '@/core/signingEngine/stepUpConfirmation/types';
import type { UserConfirmResponsePort } from '@/core/signingEngine/stepUpConfirmation/channel/confirmCommon';
import {
  webAuthnPromptCoordinator,
  type RegistrationWebAuthnPromptOwner,
  type ReservedRegistrationWebAuthnPrompt,
} from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';
import type { RegistrationCredentialPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { WalletIframeRequestId } from '@/core/types/registrationActivationIdentity';

function roundDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

function buildPasskeyRegistrationConfirmDisplay(args: {
  walletId: string;
  nearAccountId?: string;
  rpId: string;
  signerSlot: number;
}): PasskeyRegistrationConfirmDisplay {
  return {
    kind: 'passkey_registration_confirm_display_v1',
    intendedUserName: args.walletId,
    accountId: args.walletId,
    rpId: args.rpId,
    signerSlot: args.signerSlot,
  };
}

function buildPasskeyRegistrationCredentialArgs(args: {
  walletId: string;
  challengeB64u: string;
  signerSlot?: number;
  prompt: RegistrationCredentialPrompt;
}): {
  walletId: string;
  challengeB64u: string;
  signerSlot?: number;
  intendedUserName: string;
  prompt: RegistrationCredentialPrompt;
} {
  return {
    walletId: args.walletId,
    challengeB64u: args.challengeB64u,
    signerSlot: args.signerSlot,
    intendedUserName: args.walletId,
    prompt: args.prompt,
  };
}

export async function handleRegistrationFlow(
  ctx: UiConfirmContext,
  request: RegistrationUserConfirmRequest,
  worker: UserConfirmResponsePort,
  opts: {
    confirmationConfig: NormalizedConfirmationConfig;
    transactionSummary: TransactionSummary;
    theme: ThemeMode;
  },
): Promise<void> {
  const { confirmationConfig, transactionSummary, theme } = opts;
  const flowStartedAt = performance.now();
  let requestSetupMs = 0;
  let promptUserMs = 0;
  let promptElementDefineMs = 0;
  let promptMountMs = 0;
  let promptHostFirstUpdateMs = 0;
  let promptHostInteractiveMs = 0;
  let promptConfirmEventMs = 0;
  let promptDecisionWaitMs = 0;
  let credentialCreateStartMs = 0;
  let credentialCreateMs = 0;
  let credentialSerializeMs = 0;
  let duplicateRetryCount = 0;
  let promptReservation: ReservedRegistrationWebAuthnPrompt | null = null;

  const buildDiagnostics = (): RegistrationConfirmationDiagnostics => ({
    kind: 'registration_confirmation_diagnostics_v1',
    workerReadyMs: 0,
    workerRequestRoundTripMs: 0,
    workerResponseValidationMs: 0,
    requestSetupMs,
    promptUserMs,
    promptElementDefineMs,
    promptMountMs,
    promptHostFirstUpdateMs,
    promptHostInteractiveMs,
    promptConfirmEventMs,
    promptDecisionWaitMs,
    credentialCreateStartMs,
    credentialCreateMs,
    credentialSerializeMs,
    duplicateRetryCount,
    mainThreadTotalMs: roundDurationMs(flowStartedAt),
  });

  const adapters = createConfirmTxFlowAdapters(ctx);
  const session = createConfirmSession({
    adapters,
    worker,
    request,
    confirmationConfig,
    transactionSummary,
    theme,
  });
  const walletId = getWalletId(request);
  const nearAccountId = getNearAccountId(request);

  try {
    const requestSetupStartedAt = performance.now();
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

    const initialSignerSlot = request.payload?.signerSlot ?? 1;
    let challengeB64u = await computeBoundIntentDigestB64u();
    const securityContext: UserConfirmSecurityContext = {
      rpId,
      passkeyRegistration: buildPasskeyRegistrationConfirmDisplay({
        walletId,
        nearAccountId,
        rpId,
        signerSlot: initialSignerSlot,
      }),
    };
    requestSetupMs = roundDurationMs(requestSetupStartedAt);

    const promptOwner: RegistrationWebAuthnPromptOwner = {
      kind: 'registration_modal',
      requestId: request.requestId as WalletIframeRequestId,
    };
    promptReservation = await webAuthnPromptCoordinator.reserveRegistrationPrompt({
      owner: promptOwner,
      expiresAtMs: Date.now() + 5 * 60 * 1000,
      cancellation: { kind: 'none' },
    });

    // 3) UI confirm
    const promptUserStartedAt = performance.now();
    const {
      confirmed,
      error: uiError,
      diagnostics: promptDiagnostics,
    } = await session.promptUser({ securityContext });
    promptUserMs = roundDurationMs(promptUserStartedAt);
    promptElementDefineMs = promptDiagnostics.elementDefineMs;
    promptMountMs = promptDiagnostics.mountMs;
    promptHostFirstUpdateMs = promptDiagnostics.hostFirstUpdateMs;
    promptHostInteractiveMs = promptDiagnostics.hostInteractiveMs;
    promptConfirmEventMs = promptDiagnostics.confirmEventMs;
    promptDecisionWaitMs = promptDiagnostics.decisionWaitMs;
    if (!confirmed) {
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: false,
        registrationDiagnostics: buildDiagnostics(),
        error: uiError,
      });
    }

    // 4) Collect registration credentials (with duplicate retry)
    let credential: PublicKeyCredential | undefined;
    let signerSlot = request.payload?.signerSlot ?? 1;

    credentialCreateStartMs = roundDurationMs(flowStartedAt);
    const credentialCreateStartedAt = performance.now();
    try {
      try {
        credential = await adapters.webauthn.createRegistrationCredential(
          buildPasskeyRegistrationCredentialArgs({
            walletId,
            challengeB64u,
            signerSlot,
            prompt: {
              kind: 'reserved',
              reservation: promptReservation,
              owner: promptOwner,
              cancellation: { kind: 'none' },
            },
          }),
        );
      } catch (e: unknown) {
        const err = toError(e);
        const name = String(err?.name || '');
        const msg = String(err?.message || '');
        const isDuplicate =
          name === 'InvalidStateError' || /excluded|already\s*registered/i.test(msg);

        if (isDuplicate) {
          duplicateRetryCount += 1;
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
              ? `register:${walletId}:${nextSignerSlot}`
              : `device2-register:${walletId}:${nextSignerSlot}`;

          challengeB64u = await computeBoundIntentDigestB64u();

          credential = await adapters.webauthn.createRegistrationCredential(
            buildPasskeyRegistrationCredentialArgs({
              walletId,
              challengeB64u,
              signerSlot: nextSignerSlot,
              prompt: {
                kind: 'immediate',
                requestId: request.requestId,
                cancellation: { kind: 'none' },
              },
            }),
          );
        } else {
          console.error('[RegistrationFlow] credentials.create failed (non-duplicate)', {
            name,
            msg,
          });
          throw err;
        }
      }
    } finally {
      credentialCreateMs = roundDurationMs(credentialCreateStartedAt);
    }

    // We require registration credentials to include dual PRF outputs (first + second)
    // so wallet-origin code can pass PRF outputs directly to signer workers when deriving keys.
    const credentialSerializeStartedAt = performance.now();
    const serialized: WebAuthnRegistrationCredential = isSerializedRegistrationCredential(
      credential,
    )
      ? (credential as unknown as WebAuthnRegistrationCredential)
      : serializeRegistrationCredentialWithPRF({
          credential: credential! as PublicKeyCredential,
          firstPrfOutput: true,
          secondPrfOutput: true,
        });
    credentialSerializeMs = roundDurationMs(credentialSerializeStartedAt);

    // 5) Respond + close
    session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: getIntentDigest(request),
      confirmed: true,
      credential: serialized,
      registrationDiagnostics: buildDiagnostics(),
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
      registrationDiagnostics: buildDiagnostics(),
      error: cancelled
        ? ERROR_MESSAGES.cancelled
        : isPrfBrowserUnsupported
          ? msg
          : msg || ERROR_MESSAGES.collectCredentialsFailed,
    });
  } finally {
    if (promptReservation) {
      webAuthnPromptCoordinator.releaseReservation(promptReservation);
    }
  }
}
