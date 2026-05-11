import type { AccountId } from '@/core/types/accountIds';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import type { ThemeName, WalletAuthCurve, WalletAuthIntent } from '@/core/types/seams';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import {
  WalletAuthPolicyError,
} from '../../walletAuth';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import { requestEmailOtpExportAuthorization as requestEmailOtpExportAuthorizationValue } from '../../stepUpConfirmation/otpPrompt/exportAuthorization';
import {
  buildExportStepUpAuthorization,
  type ExportEmailOtpStepUpAuthorization,
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

export type KeyExportConfirmationDeps = {
  touchConfirm: Pick<UiConfirmRuntimeBridgePort, 'requestUserConfirmation'>;
  theme?: ThemeName;
};

export type EmailOtpExportAuthorizationDeps = {
  touchConfirm: Pick<UiConfirmRuntimeBridgePort, 'requestUserConfirmation'>;
  requestExportChallenge: (args: {
    nearAccountId: AccountId;
    chain: 'near' | ThresholdEcdsaChainTarget['kind'];
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ challengeId: string; emailHint?: string }>;
};

type UiConfirmRequest = Parameters<UiConfirmRuntimeBridgePort['requestUserConfirmation']>[0];
type ExportPrivateKeyDisplayEntry = {
  scheme: 'ed25519' | 'secp256k1';
  label: string;
  publicKey: string;
  privateKey: string;
  address?: string;
};

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
  args: {
    nearAccountId: AccountId;
    chain: 'near' | ThresholdEcdsaChainTarget['kind'];
    publicKey: string;
    curve: WalletAuthCurve;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  },
): Promise<ExportEmailOtpStepUpAuthorization> {
  const authorization = await requestEmailOtpExportAuthorizationValue({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    publicKey: args.publicKey,
    curve: args.curve,
    challengeSource: {
      requestChallenge: async () =>
        await deps.requestExportChallenge({
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          ...(args.routeAuth ? { routeAuth: args.routeAuth } : {}),
          ...(args.authLane ? { authLane: args.authLane } : {}),
        }),
    },
    confirmer: {
      requestUserConfirmation: async (request) =>
        await deps.touchConfirm.requestUserConfirmation(request),
    },
  });
  const exportAuthorization = buildExportStepUpAuthorization({
    method: 'email_otp',
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    publicKey: args.publicKey,
    curve: args.curve,
    intent: args.curve === 'ecdsa' ? 'ecdsa_export' : 'ed25519_export',
    emailOtpPrompt: {
      challengeId: authorization.challengeId,
    },
    decision: {
      confirmed: true,
      otpCode: authorization.otpCode,
      emailOtpChallengeId: authorization.challengeId,
    },
  });
  if (exportAuthorization.kind !== 'email_otp') {
    throw new Error('[SigningEngine][export] Email OTP export returned the wrong step-up method');
  }
  return exportAuthorization;
}

export async function requestNearEd25519ExportAuthorization(
  deps: KeyExportConfirmationDeps,
  args: {
    nearAccountId: AccountId;
    expectedPublicKey: string;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<ExportPasskeyStepUpAuthorization> {
  return await requestPasskeyExportAuthorization(deps, {
    nearAccountId: args.nearAccountId,
    intent: 'ed25519_export',
    curve: 'ed25519',
    chain: 'near',
    publicKey: args.expectedPublicKey,
    flowId: args.flowId,
    onEvent: args.onEvent,
    request: {
      requestId: createExportUiRequestId('export-near-ed25519-auth'),
      type: decryptPrivateKeyWithPrfType,
      summary: {
        operation: 'Export Private Key',
        accountId: args.nearAccountId,
        publicKey: args.expectedPublicKey,
        warning: 'Confirm to reveal your NEAR private key export.',
      },
      payload: {
        nearAccountId: args.nearAccountId,
        publicKey: args.expectedPublicKey,
      },
      intentDigest: `export-keys:${args.nearAccountId}:near-ed25519`,
    },
  });
}

export async function showNearEd25519ExportViewer(
  deps: KeyExportConfirmationDeps,
  args: {
    nearAccountId: AccountId;
    expectedPublicKey: string;
    privateKey?: string;
    variant?: 'drawer' | 'modal';
    theme?: 'dark' | 'light';
    loading?: boolean;
    viewerSessionId?: string;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<void> {
  const keys: ExportPrivateKeyDisplayEntry[] = [
    {
      scheme: 'ed25519',
      label: 'NEAR private key',
      publicKey: args.expectedPublicKey,
      privateKey: String(args.privateKey || '').trim(),
    },
  ];
  await deps.touchConfirm.requestUserConfirmation({
    requestId: createExportUiRequestId('export-near-ed25519-view'),
    type: showSecurePrivateKeyUiType,
    summary: {
      operation: 'Export Private Key',
      accountId: args.nearAccountId,
      publicKey: args.expectedPublicKey,
      warning: 'Anyone with your private key can fully control your account. Never share it.',
    },
    payload: {
      nearAccountId: args.nearAccountId,
      viewerSessionId: args.viewerSessionId,
      publicKey: args.expectedPublicKey,
      keys,
      variant: args.variant,
      theme: args.theme ?? deps.theme ?? 'dark',
      loading: args.loading === true,
      onLifecycle: (event) => {
        emitKeyExportEvent(args.onEvent, {
          phase:
            event === 'opened'
              ? KeyExportEventPhase.STEP_04_VIEWER_OPENED
              : KeyExportEventPhase.STEP_05_VIEWER_CLOSED,
          status: event === 'opened' ? 'waiting_for_user' : 'succeeded',
          flowId: args.flowId,
          accountId: String(args.nearAccountId),
          interaction: {
            kind: 'key_export_viewer',
            overlay: event === 'opened' ? 'show' : 'hide',
          },
          data: { chain: 'near', loading: args.loading === true },
        });
        if (event === 'closed') {
          emitKeyExportEvent(args.onEvent, {
            phase: KeyExportEventPhase.STEP_06_COMPLETED,
            status: 'succeeded',
            flowId: args.flowId,
            accountId: String(args.nearAccountId),
            interaction: { kind: 'none', overlay: 'hide' },
            data: { chain: 'near' },
          });
        }
      },
    },
    intentDigest: `export-keys:${args.nearAccountId}:near-ed25519`,
  });
}

export async function requestThresholdEcdsaExportAuthorization(
  deps: KeyExportConfirmationDeps,
  args: {
    nearAccountId: AccountId;
    publicKey: string;
    chainTarget: ThresholdEcdsaChainTarget;
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<ExportPasskeyStepUpAuthorization> {
  const chain = args.chainTarget.kind;
  return await requestPasskeyExportAuthorization(deps, {
    nearAccountId: args.nearAccountId,
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
        accountId: args.nearAccountId,
        publicKey: args.publicKey,
        warning:
          chain === 'tempo'
            ? 'Confirm to reveal your Tempo private key export.'
            : 'Confirm to reveal your EVM private key export.',
      },
      payload: {
        nearAccountId: args.nearAccountId,
        publicKey: args.publicKey,
      },
      intentDigest: `export-keys:${args.nearAccountId}:${thresholdEcdsaChainTargetKey(args.chainTarget)}:secp256k1`,
    },
  });
}

export async function showThresholdEcdsaExportViewer(
  deps: KeyExportConfirmationDeps,
  args: {
    nearAccountId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    publicKeyHex: string;
    privateKeyHex: string;
    ethereumAddress: string;
    variant?: 'drawer' | 'modal';
    theme?: 'dark' | 'light';
    flowId: string;
    onEvent?: KeyExportEventCallback;
  },
): Promise<void> {
  const chain = args.chainTarget.kind;
  const label = chain === 'tempo' ? 'Tempo private key' : 'EVM private key';
  const keys: ExportPrivateKeyDisplayEntry[] = [
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
      accountId: args.nearAccountId,
      publicKey: args.publicKeyHex,
      warning: 'Anyone with your private key can fully control your account. Never share it.',
    },
    payload: {
      nearAccountId: args.nearAccountId,
      publicKey: args.publicKeyHex,
      keys,
      variant: args.variant,
      theme: args.theme ?? deps.theme ?? 'dark',
      onLifecycle: (event) => {
        emitKeyExportEvent(args.onEvent, {
          phase:
            event === 'opened'
              ? KeyExportEventPhase.STEP_04_VIEWER_OPENED
              : KeyExportEventPhase.STEP_05_VIEWER_CLOSED,
          status: event === 'opened' ? 'waiting_for_user' : 'succeeded',
          flowId: args.flowId,
          accountId: String(args.nearAccountId),
          interaction: {
            kind: 'key_export_viewer',
            overlay: event === 'opened' ? 'show' : 'hide',
          },
          data: { chain, curve: 'ecdsa' },
        });
        if (event === 'closed') {
          emitKeyExportEvent(args.onEvent, {
            phase: KeyExportEventPhase.STEP_06_COMPLETED,
            status: 'succeeded',
            flowId: args.flowId,
            accountId: String(args.nearAccountId),
            interaction: { kind: 'none', overlay: 'hide' },
            data: { chain, curve: 'ecdsa' },
          });
        }
      },
    },
    intentDigest: `export-keys:${args.nearAccountId}:${thresholdEcdsaChainTargetKey(args.chainTarget)}:secp256k1`,
  });
}

async function requestPasskeyExportAuthorization(
  deps: KeyExportConfirmationDeps,
  args: {
    nearAccountId: AccountId;
    intent: Extract<WalletAuthIntent, 'ed25519_export' | 'ecdsa_export'>;
    curve: WalletAuthCurve;
    chain: 'near' | ThresholdEcdsaChainTarget['kind'];
    publicKey: string;
    flowId: string;
    onEvent?: KeyExportEventCallback;
    request: Parameters<UiConfirmRuntimeBridgePort['requestUserConfirmation']>[0];
  },
): Promise<ExportPasskeyStepUpAuthorization> {
  emitKeyExportEvent(args.onEvent, {
    phase: KeyExportEventPhase.STEP_02_AUTH_PASSKEY_PROMPT_STARTED,
    status: 'waiting_for_user',
    flowId: args.flowId,
    accountId: String(args.nearAccountId),
    authMethod: 'passkey',
    interaction: { kind: 'passkey_assert', overlay: 'show' },
    data: { intent: args.intent, curve: args.curve },
  });
  removeExportViewerHostIfPresent();
  const decision = await deps.touchConfirm.requestUserConfirmation(args.request);
  const authorization = buildExportStepUpAuthorization({
    method: 'passkey',
    nearAccountId: args.nearAccountId,
    publicKey: args.publicKey,
    curve: args.curve,
    intent: args.intent,
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
    accountId: String(args.nearAccountId),
    authMethod: 'passkey',
    interaction: { kind: 'passkey_assert', overlay: 'hide' },
    data: { intent: args.intent, curve: args.curve },
  });
  return authorization;
}

export { isExportViewerSessionOpen, removeExportViewerHostIfPresent };
