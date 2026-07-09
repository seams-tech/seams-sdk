import type { UiConfirmContext } from '../../uiConfirm.types';
import type { NormalizedConfirmationConfig } from '@/core/types/confirmationConfig';
import { silentConfirmationConfig } from '@/core/types/confirmationConfig';
import {
  UserConfirmationType,
  TransactionSummary,
  LocalOnlyUserConfirmRequest,
  type DecryptPrivateKeyWithPrfPayload,
  type LocalOnlyExportSubject,
  type ShowSecurePrivateKeyUiPayload,
  type ExportPrivateKeyDisplayEntry,
  type SerializableCredential,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { UserConfirmSecurityContext } from '@/core/types';
import { __isWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import { isUserCancelledUserConfirm, ERROR_MESSAGES } from '@/core/signingEngine/stepUpConfirmation/channel/confirmCommon';
import { getIntentDigest } from './adapters/request';
import { errorMessage } from '@shared/utils/errors';
import { base64UrlEncode } from '@shared/utils/encoders';
import { createConfirmSession, createConfirmTxFlowAdapters } from './adapters/adapters';
import type { AppearanceConfig, ThemeMode } from '@/core/types/seams';
import {
  upsertExportViewerHost,
  removeExportViewerHostIfPresent,
  type UpsertExportViewerHostArgs,
} from '../../ui/export-viewer-host';
import {
  collectAuthenticationCredentialForChallengeB64u,
  collectAuthenticationCredentialForWalletChallengeB64u,
} from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';

function createRandomChallengeB64u(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return base64UrlEncode(bytes.buffer);
}

const DEFAULT_EXPORT_APPEARANCE: AppearanceConfig = {
  theme: {
    id: 'default',
    mode: 'dark',
    colors: {},
  },
  palette: 'default',
};

function isThemeMode(value: unknown): value is ThemeMode {
  return value === 'light' || value === 'dark';
}

function resolveExportAppearance(
  ctx: UiConfirmContext,
  requestedMode?: ThemeMode,
): AppearanceConfig {
  const appearance = ctx.getAppearance?.() ?? DEFAULT_EXPORT_APPEARANCE;
  if (!isThemeMode(requestedMode) || requestedMode === appearance.theme.mode) return appearance;
  return {
    ...appearance,
    theme: {
      ...appearance.theme,
      mode: requestedMode,
    },
  };
}

function localOnlyExportSubjectId(subject: LocalOnlyExportSubject): string {
  switch (subject.kind) {
    case 'near_wallet':
      return subject.nearAccountId;
    case 'evm_wallet':
      return subject.walletId;
    default: {
      const exhaustive: never = subject;
      throw new Error(`Unsupported local key export subject: ${String(exhaustive)}`);
    }
  }
}

async function mountExportViewer(
  ctx: UiConfirmContext,
  payload: ShowSecurePrivateKeyUiPayload,
  confirmationConfig: NormalizedConfirmationConfig,
  theme: ThemeMode,
): Promise<void> {
  const hostArgs: UpsertExportViewerHostArgs = {
    theme: payload.theme || theme || 'dark',
    variant: payload.variant || (confirmationConfig.uiMode === 'drawer' ? 'drawer' : 'modal'),
    accountId: localOnlyExportSubjectId(payload.subject),
    sessionId: payload.viewerSessionId,
    publicKey: payload.publicKey,
    privateKey: payload.privateKey,
    keys: Array.isArray(payload.keys) ? payload.keys : undefined,
    guidance: payload.guidance,
    appearance: resolveExportAppearance(ctx, payload.theme),
    loading: payload.loading === true,
    errorMessage: payload.errorMessage,
    onLifecycle: payload.onLifecycle,
  };
  await upsertExportViewerHost(hostArgs);
}

type ConfirmTxFlowAdapters = ReturnType<typeof createConfirmTxFlowAdapters>;

function buildLocalOnlySecurityContext(
  adapters: ConfirmTxFlowAdapters,
): Partial<UserConfirmSecurityContext> {
  try {
    return { rpId: adapters.security.getRpId() };
  } catch {
    return {};
  }
}

async function collectLocalOnlyExportCredentialWithPRF(args: {
  ctx: UiConfirmContext;
  payload: DecryptPrivateKeyWithPrfPayload;
  challengeB64u: string;
}): Promise<SerializableCredential> {
  switch (args.payload.subject.kind) {
    case 'near_wallet':
      return await collectAuthenticationCredentialForChallengeB64u({
        credentialStore: args.ctx.webauthnCredentialStore,
        touchIdPrompt: args.ctx.touchIdPrompt,
        nearAccountId: args.payload.subject.nearAccountId,
        challengeB64u: args.challengeB64u,
        includeSecondPrfOutput: true,
      });
    case 'evm_wallet':
      return await collectAuthenticationCredentialForWalletChallengeB64u({
        credentialStore: args.ctx.webauthnCredentialStore,
        touchIdPrompt: args.ctx.touchIdPrompt,
        walletId: args.payload.subject.walletId,
        challengeB64u: args.challengeB64u,
        includeSecondPrfOutput: true,
      });
    default: {
      const exhaustive: never = args.payload.subject;
      throw new Error(`Unsupported local key export subject: ${String(exhaustive)}`);
    }
  }
}

export async function handleLocalOnlyFlow(
  ctx: UiConfirmContext,
  request: LocalOnlyUserConfirmRequest,
  worker: Worker,
  opts: {
    confirmationConfig: NormalizedConfirmationConfig;
    transactionSummary: TransactionSummary;
    theme: ThemeMode;
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

  // SHOW_SECURE_PRIVATE_KEY_UI: purely visual; keep UI open and return confirmed immediately
  if (request.type === UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI) {
    try {
      await mountExportViewer(
        ctx,
        request.payload as ShowSecurePrivateKeyUiPayload,
        confirmationConfig,
        theme,
      );
      // Keep viewer open; do not close here.
      session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: true,
      });
      return;
    } catch (err: unknown) {
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: false,
        error: errorMessage(err) || 'Failed to render export UI',
      });
    }
  }

  // DECRYPT_PRIVATE_KEY_WITH_PRF: collect an authentication credential (with PRF extension results)
  // and return it; wallet-origin code extracts PRF outputs for signer-worker requests.
  if (request.type === UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF) {
    // Fail closed on stale export UI: a new export authorization must not reuse
    // a previously mounted key viewer while Touch ID is still pending.
    removeExportViewerHostIfPresent();

    const effectiveConfirmationConfig = __isWalletIframeHostMode()
      ? silentConfirmationConfig()
      : confirmationConfig;

    const challengeB64u =
      String((request.payload as { challengeB64u?: unknown })?.challengeB64u || '').trim() ||
      createRandomChallengeB64u();
    // When this flow is initiated via worker→host messaging (wallet-iframe mode),
    // there is typically no transient user activation. If confirmationConfig chooses
    // a visible UI mode (modal/drawer), prompt first so the click lands inside the
    // wallet iframe and grants activation for the subsequent WebAuthn call.
    if (effectiveConfirmationConfig.kind !== 'silent') {
      // Provide a sensible title/body for non-transaction flows so the confirmer
      // doesn't fall back to "Register with Passkey" (txSigningRequests is empty).
      try {
        const op = transactionSummary.operation;
        const warning = transactionSummary.warning;
        if (!transactionSummary.title) transactionSummary.title = op || 'Decrypt Private Key';
        if (!transactionSummary.body) {
          transactionSummary.body = warning || 'Confirm to authenticate with your passkey.';
        }
      } catch {}

      const securityContext = buildLocalOnlySecurityContext(adapters);

      const { confirmed, error: uiError } = await session.promptUser({ securityContext });
      if (!confirmed) {
        return session.confirmAndCloseModal({
          requestId: request.requestId,
          intentDigest: getIntentDigest(request),
          confirmed: false,
          error: uiError,
        });
      }
    }
    try {
      const credential = await collectLocalOnlyExportCredentialWithPRF({
        ctx,
        payload: request.payload as DecryptPrivateKeyWithPrfPayload,
        challengeB64u,
      });
      // No modal to keep open; export viewer will be shown by a subsequent request.
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: true,
        credential,
      });
    } catch (err: unknown) {
      const cancelled = isUserCancelledUserConfirm(err);
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: false,
        error: cancelled
          ? ERROR_MESSAGES.cancelled
          : errorMessage(err) || ERROR_MESSAGES.collectCredentialsFailed,
      });
    }
  }
}
