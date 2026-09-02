import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/uiConfirm.types';
import type { ThemeMode } from '@/core/types/seams';
import { WalletAuthPolicyError } from '../../stepUpConfirmation/walletAuthPolicyError';
import {
  thresholdEcdsaChainTargetKey,
  type WalletId,
  type WalletSessionRef,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { RequestEmailOtpExportChallengeArgs } from '../../session/emailOtp/exportRecoveryRuntime';
import { requestEmailOtpExportAuthorization as requestEmailOtpExportAuthorizationValue } from '../../stepUpConfirmation/otpPrompt/exportAuthorization';
import {
  buildExportStepUpAuthorization,
  type ExportEmailOtpStepUpAuthorization,
  type Ed25519ExportEmailOtpStepUpAuthorization,
  type ExportPasskeyStepUpAuthorization,
} from './stepUpAuthorization';
import {
  isExportViewerSessionOpen,
  removeExportViewerHostIfPresent,
} from '../../uiConfirm/ui/export-viewer-host';
import {
  createExportUiRequestId,
  emitKeyExportEvent,
  type KeyExportEventCallback,
} from './keyExportFlow';
import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import { demoEmailOtpCodeFromDelivery } from '../../session/emailOtp/challengeDelivery';
import type { EmailOtpTransactionSigningChallenge } from '../../session/emailOtp/publicTypes';

export type KeyExportConfirmationDeps = {
  touchConfirm: Pick<UiConfirmRuntimeBridgePort, 'requestUserConfirmation'>;
  theme?: ThemeMode;
};

export type EmailOtpExportChallengeArgs = RequestEmailOtpExportChallengeArgs;

export type EmailOtpExportAuthorizationDeps = {
  touchConfirm: Pick<UiConfirmRuntimeBridgePort, 'requestUserConfirmation'>;
  requestExportChallenge: (
    args: EmailOtpExportChallengeArgs,
  ) => Promise<EmailOtpTransactionSigningChallenge>;
};

type WalletSessionEcdsaExportAuthorizationArgs = {
  kind: 'wallet_session_export_auth';
  walletSession: WalletSessionRef;
  chain: ThresholdEcdsaChainTarget['kind'];
  publicKey: string;
  curve: 'ecdsa';
  routeAuth?: never;
  authLane?: never;
  flowId: string;
  onEvent?: KeyExportEventCallback;
};

type EmailOtpEd25519ExportAuthorizationArgs = {
  kind: 'email_otp_ed25519_export_auth';
  walletId: WalletId;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  publicKey: string;
  curve: 'ed25519';
  chain: 'near';
  flowId: string;
  onEvent?: KeyExportEventCallback;
};

async function requestWalletSessionEcdsaExportChallenge(
  deps: EmailOtpExportAuthorizationDeps,
  args: WalletSessionEcdsaExportAuthorizationArgs,
): Promise<EmailOtpTransactionSigningChallenge> {
  return await deps.requestExportChallenge({
    kind: 'wallet_login_challenge',
    walletSession: args.walletSession,
    chain: args.chain,
  });
}

function emitEmailOtpExportChallenge(
  args: WalletSessionEcdsaExportAuthorizationArgs | EmailOtpEd25519ExportAuthorizationArgs,
  challenge: EmailOtpTransactionSigningChallenge,
): void {
  const accountId =
    args.kind === 'email_otp_ed25519_export_auth'
      ? args.walletId
      : args.walletSession.walletSessionUserId;
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_02_AUTH_EMAIL_OTP_INPUT_REQUIRED,
    status: 'waiting_for_user',
    flowId: args.flowId,
    accountId: String(accountId),
    authMethod: 'email_otp',
    interaction: { kind: 'otp_input', overlay: 'show' },
    data: {
      emailHint: challenge.emailHint,
      demoOtpCode: demoEmailOtpCodeFromDelivery(challenge.delivery),
    },
  });
}

type UiConfirmRequest = Parameters<UiConfirmRuntimeBridgePort['requestUserConfirmation']>[0];
type Secp256k1ExportPrivateKeyDisplayEntry = {
  scheme: 'secp256k1';
  label: string;
  publicKey: string;
  privateKey: string;
  address: string;
};

type Ed25519ExportPrivateKeyDisplayEntry = {
  scheme: 'ed25519';
  label: string;
  publicKey: string;
  privateKey: string;
  address?: never;
};

export type ExportPrivateKeyDisplayEntry =
  | Secp256k1ExportPrivateKeyDisplayEntry
  | Ed25519ExportPrivateKeyDisplayEntry;

type ThresholdEcdsaExportViewerBaseArgs = {
  walletId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  publicKeyHex: string;
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
  flowId: string;
  onEvent?: KeyExportEventCallback;
};

type ThresholdEcdsaExportViewerLoadingArgs = ThresholdEcdsaExportViewerBaseArgs & {
  state: 'loading';
  viewerSessionId: string;
  ethereumAddress: string;
  privateKeyHex?: never;
};

type ThresholdEcdsaExportViewerReadyArgs = ThresholdEcdsaExportViewerBaseArgs & {
  state: 'ready';
  privateKeyHex: string;
  ethereumAddress: string;
  viewerSessionId?: string;
};

type ThresholdEcdsaExportViewerArgs =
  | ThresholdEcdsaExportViewerLoadingArgs
  | ThresholdEcdsaExportViewerReadyArgs;

type Ed25519ExportViewerBaseArgs = {
  walletId: string;
  nearAccountId: string;
  publicKey: string;
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
  flowId: string;
  onEvent?: KeyExportEventCallback;
};

type Ed25519ExportViewerLoadingArgs = Ed25519ExportViewerBaseArgs & {
  state: 'loading';
  viewerSessionId: string;
  privateKey?: never;
};

type Ed25519ExportViewerReadyArgs = Ed25519ExportViewerBaseArgs & {
  state: 'ready';
  privateKey: string;
  viewerSessionId?: string;
};

type Ed25519ExportViewerArgs = Ed25519ExportViewerLoadingArgs | Ed25519ExportViewerReadyArgs;

const decryptPrivateKeyWithPrfType = 'decryptPrivateKeyWithPrf' as UiConfirmRequest['type'];
const showSecurePrivateKeyUiType = 'showSecurePrivateKeyUi' as UiConfirmRequest['type'];

export function createEmailOtpKeyExportRequiresPasskeyError(): WalletAuthPolicyError {
  return new WalletAuthPolicyError({
    code: 'passkey_step_up_required',
    policy: 'export_requires_passkey',
    message: 'Key export requires a passkey-authenticated account.',
  });
}

export function isEmailOtpPasskeyStepUpError(error: unknown): boolean {
  const message = String(error instanceof Error ? error.message : error || '');
  return (
    message.includes('requires fresh passkey authentication after Email OTP login') ||
    message.includes('requires passkey authentication after Email OTP login')
  );
}

export async function requestEmailOtpKeyExportAuthorization(
  deps: EmailOtpExportAuthorizationDeps,
  args: WalletSessionEcdsaExportAuthorizationArgs,
): Promise<ExportEmailOtpStepUpAuthorization> {
  const accountIdForUi = args.walletSession.walletSessionUserId;
  const authorization = await requestEmailOtpExportAuthorizationValue({
    identity: { kind: 'wallet_session', walletId: accountIdForUi },
    chain: args.chain,
    publicKey: args.publicKey,
    curve: args.curve,
    challengeSource: {
      requestChallenge: async () => await requestWalletSessionEcdsaExportChallenge(deps, args),
    },
    confirmer: {
      requestUserConfirmation: async (request) =>
        await deps.touchConfirm.requestUserConfirmation(request),
    },
    onChallenge: emitEmailOtpExportChallenge.bind(undefined, args),
  });
  const emailOtpPrompt = {
    challengeId: authorization.challengeId,
  };
  const decision = {
    confirmed: true as const,
    otpCode: authorization.otpCode,
    emailOtpChallengeId: authorization.challengeId,
  };
  const exportAuthorization = buildExportStepUpAuthorization({
    method: 'email_otp',
    walletSessionUserId: accountIdForUi,
    chain: args.chain,
    publicKey: args.publicKey,
    curve: 'ecdsa',
    intent: 'ecdsa_export',
    emailOtpPrompt,
    decision,
  });
  if (exportAuthorization.kind !== 'email_otp') {
    throw new Error('[SigningEngine][export] Email OTP export returned the wrong step-up method');
  }
  return exportAuthorization;
}

export async function requestEmailOtpEd25519KeyExportAuthorization(
  deps: EmailOtpExportAuthorizationDeps,
  args: EmailOtpEd25519ExportAuthorizationArgs,
): Promise<Ed25519ExportEmailOtpStepUpAuthorization> {
  const authorization = await requestEmailOtpExportAuthorizationValue({
    identity: {
      kind: 'near_account',
      walletId: args.walletId,
      nearAccountId: args.nearAccountId,
    },
    chain: 'near',
    publicKey: args.publicKey,
    curve: 'ed25519',
    challengeSource: {
      requestChallenge: async () =>
        await deps.requestExportChallenge({
          kind: 'wallet_export_challenge',
          walletId: args.walletId,
          chain: 'near',
        }),
    },
    confirmer: {
      requestUserConfirmation: async (request) =>
        await deps.touchConfirm.requestUserConfirmation(request),
    },
    onChallenge: emitEmailOtpExportChallenge.bind(undefined, args),
  });
  const exportAuthorization = buildExportStepUpAuthorization({
    method: 'email_otp',
    walletSessionUserId: args.walletId,
    publicKey: args.publicKey,
    curve: 'ed25519',
    intent: 'ed25519_export',
    chain: 'near',
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    signerSlot: args.signerSlot,
    emailOtpPrompt: { challengeId: authorization.challengeId },
    decision: {
      confirmed: true,
      otpCode: authorization.otpCode,
      emailOtpChallengeId: authorization.challengeId,
    },
  });
  if (exportAuthorization.kind !== 'email_otp' || exportAuthorization.curve !== 'ed25519') {
    throw new Error('[SigningEngine][export] Ed25519 Email OTP export authorization changed kind');
  }
  return exportAuthorization;
}

export async function showEd25519ExportViewer(
  deps: KeyExportConfirmationDeps,
  args: Ed25519ExportViewerArgs,
): Promise<void> {
  const isLoading = args.state === 'loading';
  const keys: Ed25519ExportPrivateKeyDisplayEntry[] = [
    {
      scheme: 'ed25519',
      label: 'NEAR Ed25519 private key',
      publicKey: args.publicKey,
      privateKey: isLoading ? '' : args.privateKey,
    },
  ];
  await deps.touchConfirm.requestUserConfirmation({
    requestId: createExportUiRequestId('export-ed25519-yao-view'),
    type: showSecurePrivateKeyUiType,
    summary: {
      operation: 'Export Private Key',
      accountId: args.nearAccountId,
      publicKey: args.publicKey,
      warning: 'Anyone with your private key can fully control your account. Never share it.',
    },
    payload: {
      subject: { kind: 'near_wallet', nearAccountId: args.nearAccountId },
      viewerSessionId: args.viewerSessionId,
      publicKey: args.publicKey,
      keys,
      variant: args.variant,
      theme: args.theme ?? deps.theme ?? 'dark',
      loading: isLoading,
      onLifecycle: (event) => {
        emitKeyExportEvent(args.onEvent, {
          phase:
            event === 'opened'
              ? KeyExportEventPhase.STEP_04_VIEWER_OPENED
              : KeyExportEventPhase.STEP_05_VIEWER_CLOSED,
          status: event === 'opened' ? 'waiting_for_user' : 'succeeded',
          flowId: args.flowId,
          accountId: args.nearAccountId,
          interaction: {
            kind: 'key_export_viewer',
            overlay: event === 'opened' ? 'show' : 'hide',
          },
          data: { chain: 'near', curve: 'ed25519', loading: isLoading },
        });
        if (event === 'closed') {
          emitKeyExportEvent(args.onEvent, {
            phase: KeyExportEventPhase.STEP_06_COMPLETED,
            status: 'succeeded',
            flowId: args.flowId,
            accountId: args.nearAccountId,
            interaction: { kind: 'none', overlay: 'hide' },
            data: { chain: 'near', curve: 'ed25519' },
          });
        }
      },
    },
    intentDigest: `export-keys:${args.walletId}:near:${args.nearAccountId}:ed25519`,
  });
}

export async function requestThresholdEcdsaExportAuthorization(
  deps: KeyExportConfirmationDeps,
  args: {
    walletSessionUserId: string;
    credentialIdB64u: string;
    publicKey: string;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeB64u?: string;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<ExportPasskeyStepUpAuthorization> {
  const chain = args.chainTarget.kind;
  const walletIdForUi = String(args.walletSessionUserId || '').trim();
  if (!walletIdForUi) {
    throw new Error('[SigningEngine][export] missing ECDSA export wallet session user id');
  }
  return await requestPasskeyExportAuthorization(deps, {
    walletSessionUserId: args.walletSessionUserId,
    intent: 'ecdsa_export',
    curve: 'ecdsa',
    chain,
    publicKey: args.publicKey,
    flowId: args.flowId,
    onEvent: args.onEvent,
    request: {
      requestId: createExportUiRequestId('export-threshold-ecdsa-auth'),
      type: decryptPrivateKeyWithPrfType,
      summary: {
        operation: 'Export Private Key',
        accountId: walletIdForUi,
        publicKey: args.publicKey,
        warning:
          chain === 'tempo'
            ? 'Confirm to reveal your Tempo private key export.'
            : 'Confirm to reveal your EVM private key export.',
      },
      payload: {
        subject: {
          kind: 'evm_wallet',
          walletId: walletIdForUi,
        },
        credentialIdB64u: args.credentialIdB64u,
        publicKey: args.publicKey,
        ...(args.challengeB64u ? { challengeB64u: args.challengeB64u } : {}),
      },
      intentDigest: `export-keys:${walletIdForUi}:${thresholdEcdsaChainTargetKey(args.chainTarget)}:secp256k1`,
    },
  });
}

export async function showThresholdEcdsaExportViewer(
  deps: KeyExportConfirmationDeps,
  args: ThresholdEcdsaExportViewerArgs,
): Promise<void> {
  const chain = args.chainTarget.kind;
  const label = chain === 'tempo' ? 'Tempo' : 'EVM';
  const isLoading = args.state === 'loading';
  const keys: Secp256k1ExportPrivateKeyDisplayEntry[] = isLoading
    ? [
        {
          scheme: 'secp256k1',
          label,
          publicKey: args.publicKeyHex,
          privateKey: '',
          address: args.ethereumAddress,
        },
      ]
    : [
        {
          scheme: 'secp256k1',
          label,
          publicKey: args.publicKeyHex,
          privateKey: args.privateKeyHex,
          address: args.ethereumAddress,
        },
      ];
  await deps.touchConfirm.requestUserConfirmation({
    requestId: createExportUiRequestId('export-threshold-ecdsa-view'),
    type: showSecurePrivateKeyUiType,
    summary: {
      operation: 'Export Private Key',
      accountId: args.walletId,
      publicKey: args.publicKeyHex,
      warning: 'Anyone with your private key can fully control your account. Never share it.',
    },
    payload: {
      subject: {
        kind: 'evm_wallet',
        walletId: args.walletId,
      },
      viewerSessionId: args.viewerSessionId,
      publicKey: args.publicKeyHex,
      keys,
      variant: args.variant,
      theme: args.theme ?? deps.theme ?? 'dark',
      loading: isLoading,
      onLifecycle: (event) => {
        emitKeyExportEvent(args.onEvent, {
          phase:
            event === 'opened'
              ? KeyExportEventPhase.STEP_04_VIEWER_OPENED
              : KeyExportEventPhase.STEP_05_VIEWER_CLOSED,
          status: event === 'opened' ? 'waiting_for_user' : 'succeeded',
          flowId: args.flowId,
          accountId: String(args.walletId),
          interaction: {
            kind: 'key_export_viewer',
            overlay: event === 'opened' ? 'show' : 'hide',
          },
          data: { chain, curve: 'ecdsa', loading: isLoading },
        });
        if (event === 'closed') {
          emitKeyExportEvent(args.onEvent, {
            phase: KeyExportEventPhase.STEP_06_COMPLETED,
            status: 'succeeded',
            flowId: args.flowId,
            accountId: String(args.walletId),
            interaction: { kind: 'none', overlay: 'hide' },
            data: { chain, curve: 'ecdsa' },
          });
        }
      },
    },
    intentDigest: `export-keys:${args.walletId}:${thresholdEcdsaChainTargetKey(args.chainTarget)}:secp256k1`,
  });
}

async function requestPasskeyExportAuthorization(
  deps: KeyExportConfirmationDeps,
  args: {
    walletSessionUserId: string;
    intent: 'ecdsa_export';
    curve: 'ecdsa';
    chain: ThresholdEcdsaChainTarget['kind'];
    publicKey: string;
    flowId: string;
    onEvent?: KeyExportEventCallback;
    request: Parameters<UiConfirmRuntimeBridgePort['requestUserConfirmation']>[0];
  },
): Promise<ExportPasskeyStepUpAuthorization> {
  const accountIdForUi = String(args.walletSessionUserId || '').trim();
  if (!accountIdForUi) {
    throw new Error('[SigningEngine][export] missing export account identity');
  }
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_02_AUTH_PASSKEY_PROMPT_STARTED,
    status: 'waiting_for_user',
    flowId: args.flowId,
    accountId: String(accountIdForUi),
    authMethod: 'passkey',
    interaction: { kind: 'passkey_assert', overlay: 'show' },
    data: { intent: args.intent, curve: args.curve },
  });
  removeExportViewerHostIfPresent();
  const decision = await deps.touchConfirm.requestUserConfirmation(args.request);
  const authorization = buildExportStepUpAuthorization({
    method: 'passkey',
    walletSessionUserId: args.walletSessionUserId,
    publicKey: args.publicKey,
    curve: 'ecdsa',
    intent: 'ecdsa_export',
    chain: args.chain,
    decision,
  });
  if (authorization.kind !== 'passkey') {
    throw new Error('[SigningEngine][export] passkey export returned the wrong step-up method');
  }
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_02_AUTH_PASSKEY_PROMPT_SUCCEEDED,
    status: 'succeeded',
    flowId: args.flowId,
    accountId: String(accountIdForUi),
    authMethod: 'passkey',
    interaction: { kind: 'passkey_assert', overlay: 'hide' },
    data: { intent: args.intent, curve: args.curve },
  });
  return authorization;
}

export { isExportViewerSessionOpen, removeExportViewerHostIfPresent };
