import type { AppearanceConfig, GetRecentUnlocksResult } from '@/core/types/seams';
import type { SeamsWeb } from '@/SeamsWeb';
import type {
  ChildToParentEnvelope,
  HostedAuthMenuCancelPayload,
  HostedAuthMenuExternalAuthResolution,
  HostedAuthMenuOpenRequest,
} from '../../shared/messages';
import { AuthMenuSession } from './session';
import '../lit-ui/auth-menu/seams-auth-menu-surface';
import { prepareHostedPasskeyRegistration } from '@/SeamsWeb/operations/registration/registration';
import {
  buildNearWalletRegistrationSignerSetSelection,
  resolvePasskeyRegistrationAccountProvisioning,
} from '@/SeamsWeb/operations/registration/registrationSignerSet';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import {
  walletIframeRequestIdFromBoundary,
  type WalletIframeRequestId,
} from '@/core/types/walletIframeIdentity';
import type { WebAuthnPromptCancellation } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';
import {
  prepareHostedPasskeyAccountSync,
  createHostedPasskeyContext,
  prepareHostedPasskeyLogin,
  type HostedPasskeyPrepared,
} from './passkey';
import type { GoogleEmailOtpWalletAuthFlow } from '@/SeamsWeb/publicApi/types';
import {
  defaultLoginWalletId,
  loginAccountOptions,
  passkeyRecentWalletId,
} from './account-options';
import type { LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import type { StartDevice2LinkingFlowResults } from '@/core/types/linkDevice';

export type AuthMenuControllerDeps = {
  readonly getSeamsWeb: () => SeamsWeb;
  readonly getAppearance: () => AppearanceConfig;
  readonly send: (message: ChildToParentEnvelope) => void;
};

function trustedHostHostname(): string {
  try {
    const referrer = document.referrer.trim();
    if (referrer) {
      const hostname = new URL(referrer).hostname.trim();
      if (hostname) return hostname;
    }
  } catch {}
  return window.location.hostname || 'Wallet';
}

export class AuthMenuController {
  private readonly sessions = new Map<
    HostedAuthMenuOpenRequest['authMenuSessionId'],
    AuthMenuSession
  >();

  constructor(private readonly deps: AuthMenuControllerDeps) {}

  get activeSessionCount(): number {
    return this.sessions.size;
  }

  async open(args: {
    request: HostedAuthMenuOpenRequest;
    requestId: string | undefined;
  }): Promise<import('../../shared/messages').HostedAuthMenuOutcome> {
    if (!args.requestId) throw new Error('Hosted auth-menu open request requires requestId');
    const requestId = walletIframeRequestIdFromBoundary(args.requestId);
    if (this.sessions.has(args.request.authMenuSessionId)) {
      throw new Error('Hosted auth-menu session is already active');
    }
    const session = new AuthMenuSession({
      request: args.request,
      requestId,
      appearance: this.deps.getAppearance(),
      hostname: trustedHostHostname(),
      beginGoogleEmailOtp: async ({ idToken, mode, signal }) =>
        await this.beginGoogleEmailOtp({ idToken, mode, signal }),
      startDeviceLinking: this.startDeviceLinking,
      cancelDeviceLinking: this.cancelDeviceLinking,
      sendToParent: this.deps.send,
    });
    const outcomePromise = session.waitForOutcome();
    this.sessions.set(args.request.authMenuSessionId, session);
    try {
      session.mount();
      session.setRegistrationPreparation((registrationValue, cancellation) =>
        this.prepareRegistration(
          args.request,
          requestId,
          session.identity.authMenuSessionId,
          registrationValue,
          cancellation,
        ),
      );
      session.setLoginPreparation({
        accountOptions: [],
        selectedWalletId: null,
        prepare: (walletId, cancellation) =>
          this.prepareLogin(
            requestId,
            session.identity.authMenuSessionId,
            cancellation,
            walletId,
            null,
          ),
      });
      void this.bootstrapLoginAccounts(session, requestId);
      return await outcomePromise;
    } finally {
      session.cleanup();
      this.sessions.delete(args.request.authMenuSessionId);
    }
  }

  private async bootstrapLoginAccounts(
    session: AuthMenuSession,
    requestId: WalletIframeRequestId,
  ): Promise<void> {
    const recentUnlocks = await this.deps
      .getSeamsWeb()
      .auth.getRecentUnlocks()
      .catch(() => null);
    if (session.state.kind === 'complete') return;
    const accountOptions = loginAccountOptions(recentUnlocks);
    session.setLoginPreparation({
      accountOptions,
      selectedWalletId: defaultLoginWalletId(recentUnlocks, accountOptions),
      prepare: (walletId, cancellation) =>
        this.prepareLogin(
          requestId,
          session.identity.authMenuSessionId,
          cancellation,
          walletId,
          recentUnlocks,
        ),
    });
  }

  private async prepareLogin(
    requestId: WalletIframeRequestId,
    authMenuSessionId: HostedAuthMenuOpenRequest['authMenuSessionId'],
    cancellation: Extract<WebAuthnPromptCancellation, { kind: 'abort_signal' }>,
    walletId: string | null,
    recentUnlocks: GetRecentUnlocksResult | null,
  ): Promise<HostedPasskeyPrepared> {
    const context = createHostedPasskeyContext(this.deps.getSeamsWeb().getContext());
    const selectedWalletId = walletId || passkeyRecentWalletId(recentUnlocks);
    if (selectedWalletId) {
      return await prepareHostedPasskeyLogin({
        context,
        walletId: selectedWalletId,
        authMenuSessionId,
        requestId,
        cancellation,
      });
    }
    return await prepareHostedPasskeyAccountSync({
      context,
      walletId: null,
      authMenuSessionId,
      requestId,
      cancellation,
    });
  }

  private async beginGoogleEmailOtp(args: {
    idToken: string;
    mode: HostedAuthMenuOpenRequest['initialMode'];
    signal: AbortSignal;
  }): Promise<GoogleEmailOtpWalletAuthFlow> {
    if (args.signal.aborted) throw new Error('Google sign-in was cancelled');
    const result = await this.deps.getSeamsWeb().auth.beginGoogleEmailOtpWalletAuth({
      idToken: args.idToken,
      mode: args.mode,
      // The wallet host is a third-party context, so a cookie session is not
      // usable here. Without an explicit 'jwt' the session exchange returns no
      // JWT, the flow's state carries no appSessionJwt, and the ECDSA login
      // reaches resolveEmailOtpAuthLane with nothing to authenticate with —
      // surfacing as "Email OTP ECDSA login requires route auth".
      sessionKind: 'jwt',
    });
    if (!result.ok) throw new Error(result.error.message);
    const flow = result.value;
    if (args.signal.aborted) {
      await flow.cancel().catch(() => {});
      throw new Error('Google sign-in was cancelled');
    }
    return flow;
  }

  private startDeviceLinking = async (
    onEvent: (event: LinkDeviceFlowEvent) => void,
  ): Promise<StartDevice2LinkingFlowResults> =>
    await this.deps.getSeamsWeb().devices.startDevice2LinkingFlow({ options: { onEvent } });

  private cancelDeviceLinking = async (): Promise<void> =>
    await this.deps.getSeamsWeb().devices.cancelDeviceLinking();

  private async prepareRegistration(
    request: HostedAuthMenuOpenRequest,
    requestId: WalletIframeRequestId,
    authMenuSessionId: HostedAuthMenuOpenRequest['authMenuSessionId'],
    registrationValue: string,
    cancellation: Extract<WebAuthnPromptCancellation, { kind: 'abort_signal' }>,
  ): Promise<
    import('@/SeamsWeb/operations/registration/registration').HostedPasskeyRegistrationPrepared
  > {
    const context = this.deps.getSeamsWeb().getContext();
    const parsedRpId = parseWebAuthnRpId(String(context.signingEngine.getRpId() || ''));
    if (!parsedRpId.ok) throw new Error(parsedRpId.error.message);
    const wallet = { kind: 'provided' as const, walletId: walletIdFromString(registrationValue) };
    const accountProvisioning = resolvePasskeyRegistrationAccountProvisioning({
      configs: context.configs,
      wallet,
      preference:
        request.registrationAccountInput === 'sponsored_named_near_account'
          ? { kind: 'relayer_named_subaccount' }
          : { kind: 'implicit_account' },
    });
    const signerSelection = buildNearWalletRegistrationSignerSetSelection({
      configs: context.configs,
      accountProvisioning,
      options: {},
    });
    return await prepareHostedPasskeyRegistration({
      context,
      wallet,
      signerSelection,
      authMethod: { kind: 'passkey', rpId: parsedRpId.value },
      authMenuSessionId,
      requestId,
      cancellation,
      options: {},
    });
  }

  cancel(payload: HostedAuthMenuCancelPayload): boolean {
    const session = this.sessions.get(payload.authMenuSessionId);
    if (!session || session.identity.requestId !== payload.requestId) return false;
    session.cancel(payload.reason);
    return true;
  }

  resolveExternalAuth(resolution: HostedAuthMenuExternalAuthResolution): boolean {
    const session = this.sessions.get(resolution.authMenuSessionId);
    if (!session || session.identity.requestId !== resolution.requestId) return false;
    return session.acceptExternalAuthResolution(resolution);
  }

  cancelByRequestId(requestId: string, reason: 'connection_closed' | 'component_unmounted'): void {
    for (const session of this.sessions.values()) {
      if (session.identity.requestId === requestId) session.cancel(reason);
    }
  }
}
