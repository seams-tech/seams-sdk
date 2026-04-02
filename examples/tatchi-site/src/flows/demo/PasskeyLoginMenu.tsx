import {
  useTatchi,
  RegistrationPhase,
  RegistrationStatus,
  LoginPhase,
  SyncAccountPhase,
  SyncAccountStatus,
  AuthMenuMode,
  DeviceLinkingPhase,
  EmailRecoveryPhase,
  EmailRecoveryStatus,
  type RegistrationSSEEvent,
  type SyncAccountSSEEvent,
  type DeviceLinkingSSEEvent,
  type EmailRecoverySSEEvent,
  PasskeyAuthMenu,
} from '@tatchi-xyz/sdk/react';
import React from 'react';
import { toast } from 'sonner';

import './PasskeyLoginMenu.css';
import { useAuthMenuControl } from '@/context/AuthMenuControl';

type PasskeyLoginMenuTestOverrides = {
  useTatchiHook?: typeof useTatchi;
  useAuthMenuControlHook?: typeof useAuthMenuControl;
  PasskeyAuthMenuComponent?: typeof PasskeyAuthMenu;
};

type PasskeyLoginMenuProps = {
  onLoggedIn?: (nearAccountId?: string) => void;
  __testOverrides?: PasskeyLoginMenuTestOverrides;
};

export function PasskeyLoginMenu(props: PasskeyLoginMenuProps) {
  const useTatchiHook = props.__testOverrides?.useTatchiHook || useTatchi;
  const useAuthMenuControlHook =
    props.__testOverrides?.useAuthMenuControlHook || useAuthMenuControl;
  const PasskeyAuthMenuComponent =
    props.__testOverrides?.PasskeyAuthMenuComponent || PasskeyAuthMenu;

  const {
    accountInputState: { targetAccountId, accountExists },
    unlock,
    registerPasskey,
    tatchi,
  } = useTatchiHook();

  // let tutorial control the menu (programmatically open/close menus)
  const authMenuControl = useAuthMenuControlHook();

  const onRegister = async () => {
    const result = await registerPasskey(targetAccountId, {
      onEvent: (event: RegistrationSSEEvent) => {
        switch (event.phase) {
          case RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION:
            toast.loading('Starting registration...', { id: 'registration' });
            break;
          case RegistrationPhase.STEP_2_KEY_GENERATION:
            if (event.status === RegistrationStatus.SUCCESS) {
              toast.success('Keys generated...', { id: 'registration' });
            }
            break;
          case RegistrationPhase.STEP_3_CONTRACT_PRE_CHECK:
            toast.loading('Checking account availability...', { id: 'registration' });
            break;
          case RegistrationPhase.STEP_4_ACCESS_KEY_ADDITION:
            toast.loading('Creating account...', { id: 'registration' });
            break;
          case RegistrationPhase.STEP_5_CONTRACT_REGISTRATION:
            toast.loading(event.message || 'Creating account and finalizing registration...', {
              id: 'registration',
            });
            break;
          case RegistrationPhase.STEP_6_ACCOUNT_VERIFICATION:
            toast.loading(event.message, { id: 'registration' });
            break;
          case RegistrationPhase.STEP_9_REGISTRATION_COMPLETE:
            if (event.status === RegistrationStatus.SUCCESS) {
              // Final toast with tx hash will be shown after the promise resolves
              toast.success('Registration completed successfully!', { id: 'registration' });
            }
            break;
          case RegistrationPhase.REGISTRATION_ERROR:
            toast.error(event.error || 'Registration failed', { id: 'registration' });
            break;
          default:
            if (event.status === RegistrationStatus.PROGRESS) {
              toast.loading(event.message || 'Processing...', { id: 'registration' });
            }
        }
      },
    });

    if (result.success && result.nearAccountId) {
      const tx = result.transactionId ? ` tx: ${result.transactionId}` : '';
      toast.success(`Registration completed: ${tx}`, { id: 'registration' });
      props.onLoggedIn?.(result.nearAccountId);
      return result;
    } else {
      throw new Error(result.error || 'Registration failed');
    }
  };

  const loginWithSession = async (accountId: string) => {
    const loginTarget = String(accountId || '').trim();
    if (!loginTarget) {
      throw new Error('Missing accountId for login');
    }

    const result = await unlock(loginTarget, {
      // Mint a JWT session via the relay server if session.kind is provided
      // session: {
      //   kind: 'jwt',
      // },
      onEvent: (event) => {
        switch (event.phase) {
          case LoginPhase.STEP_1_PREPARATION:
            toast.loading(`Logging in as ${loginTarget}...`, { id: 'login' });
            break;
          case LoginPhase.STEP_2_WEBAUTHN_ASSERTION:
            toast.loading(event.message, { id: 'login' });
            break;
          case LoginPhase.STEP_3_SESSION_READY:
            toast.loading(event.message || 'Session ready…', { id: 'login' });
            break;
          case LoginPhase.STEP_4_LOGIN_COMPLETE:
            toast.success(`Logged in as ${event.nearAccountId}!`, { id: 'login' });
            break;
          case LoginPhase.LOGIN_ERROR:
            toast.error(event.error, { id: 'login' });
            break;
        }
      },
    });
    if (result?.success) {
      const accountId = String(result.nearAccountId || '').trim();
      if (!accountId) {
        throw new Error('Login succeeded but nearAccountId is missing');
      }
      // Surface the minted JWT via toast (truncate to 8 chars)
      if (result.jwt) {
        const short = String(result.jwt).slice(0, 16);
        toast.success(`Session JWT minted: ${short}…`, { id: 'jwt' });
        console.log('[tatchi-site] JWT returned:', result.jwt);
      }
      props.onLoggedIn?.(accountId);
    }
    return result;
  };

  const onLogin = async () => {
    return await loginWithSession(targetAccountId);
  };

  const onSyncAccount = async () => {
    const result = await tatchi.recovery.syncAccount({
      ...(targetAccountId ? { accountId: targetAccountId } : {}),
      options: {
        onEvent: (event: SyncAccountSSEEvent) => {
          switch (event.phase) {
            case SyncAccountPhase.STEP_1_PREPARATION:
              toast.loading(event.message || 'Preparing account sync…', { id: 'sync' });
              break;
            case SyncAccountPhase.STEP_2_WEBAUTHN_AUTHENTICATION:
              toast.loading(event.message || 'Authenticating with passkey…', { id: 'sync' });
              break;
            case SyncAccountPhase.STEP_4_AUTHENTICATOR_SAVED:
              if (event.status === SyncAccountStatus.SUCCESS) {
                toast.success(event.message || 'Passkey saved locally', { id: 'sync' });
              }
              break;
            case SyncAccountPhase.STEP_5_SYNC_ACCOUNT_COMPLETE:
              if (event.status === SyncAccountStatus.SUCCESS) {
                toast.success(event.message || 'Account synced', { id: 'sync' });
              }
              break;
            case SyncAccountPhase.ERROR:
              toast.error((event as any)?.error || event.message || 'Account sync failed', {
                id: 'sync',
              });
              break;
            default:
              break;
          }
        },
      } as any,
    });

    if (!result?.success) {
      throw new Error(result?.error || result?.message || 'Account sync failed');
    }

    const syncedAccountId = String(result.accountId || '').trim();
    if (!syncedAccountId) {
      throw new Error('Sync succeeded but accountId is missing');
    }

    if (result.loginState?.isLoggedIn) {
      toast.success(`Synced and logged in as ${syncedAccountId}`, { id: 'sync' });
      props.onLoggedIn?.(syncedAccountId);
      return result;
    }

    toast.success(`Synced account ${syncedAccountId}. Logging in...`, { id: 'sync' });
    await loginWithSession(syncedAccountId);
    return result;
  };

  // Only handle Device2 events here
  const onLinkDeviceEvents = async (event: DeviceLinkingSSEEvent) => {
    const toastId = 'device-linking';
    switch (event.phase) {
      case DeviceLinkingPhase.STEP_1_QR_CODE_GENERATED:
        toast.loading('QR code ready. Scan it with your other device.', { id: toastId });
        break;
      case DeviceLinkingPhase.STEP_2_SCANNING:
        toast.loading('Waiting for Device 1 to scan the QR code…', { id: toastId });
        break;
      case DeviceLinkingPhase.STEP_3_AUTHORIZATION:
        toast.loading('Authorize linking on Device 1…', { id: toastId });
        break;
      case DeviceLinkingPhase.STEP_4_POLLING:
        toast.loading('Confirming new device with the network…', { id: toastId });
        break;
      case DeviceLinkingPhase.STEP_5_ADDKEY_DETECTED:
        toast.loading('Device key detected on-chain…', { id: toastId });
        break;
      case DeviceLinkingPhase.STEP_6_REGISTRATION:
        toast.loading('Creating a passkey on this device…', { id: toastId });
        break;
      case DeviceLinkingPhase.STEP_7_LINKING_COMPLETE:
        toast.success('Device linked successfully!', { id: toastId });
        break;
      case DeviceLinkingPhase.STEP_8_AUTO_LOGIN:
        toast.loading('Login in progress…', { id: toastId });
        break;
      case DeviceLinkingPhase.DEVICE_LINKING_ERROR:
      case DeviceLinkingPhase.LOGIN_ERROR:
      case DeviceLinkingPhase.REGISTRATION_ERROR: {
        toast.error(event.error, { id: toastId });
        break;
      }
      default:
        console.warn('Unexpected Link Device event');
        break;
    }
  };

  const onEmailRecoveryEvents = (event: EmailRecoverySSEEvent) => {
    const toastId = 'email-recovery';
    if (
      event.phase === EmailRecoveryPhase.STEP_6_COMPLETE &&
      event.status === EmailRecoveryStatus.SUCCESS
    ) {
      toast.success(event.message || 'Email recovery complete', { id: toastId });
      return;
    }
    if (event.phase === EmailRecoveryPhase.ERROR || event.status === EmailRecoveryStatus.ERROR) {
      toast.error((event as any)?.error || event.message || 'Email recovery failed', {
        id: toastId,
      });
      return;
    }

    switch (event.phase) {
      case EmailRecoveryPhase.RESUMED_FROM_PENDING:
        toast.loading(event.message || 'Resuming pending email recovery…', { id: toastId });
        return;
      case EmailRecoveryPhase.STEP_1_PREPARATION:
        toast.loading(event.message || 'Preparing email recovery…', { id: toastId });
        return;
      case EmailRecoveryPhase.STEP_2_TOUCH_ID_REGISTRATION:
        toast.loading(event.message || 'Creating a passkey on this device…', {
          id: toastId,
        });
        return;
      case EmailRecoveryPhase.STEP_3_AWAIT_EMAIL:
        toast.loading(event.message || 'Waiting for the recovery email to be sent and verified…', {
          id: toastId,
        });
        return;
      case EmailRecoveryPhase.STEP_4_POLLING_ADD_KEY:
      case EmailRecoveryPhase.STEP_4_POLLING_VERIFICATION_RESULT:
        toast.loading(event.message || 'Polling for recovery verification…', { id: toastId });
        return;
      case EmailRecoveryPhase.STEP_5_FINALIZING_REGISTRATION:
        toast.loading(event.message || 'Finalizing recovery registration…', { id: toastId });
        return;
      default:
        return;
    }
  };

  const startDevice2Linking = async () => {
    const toastId = 'device-linking';
    try {
      toast.loading('Generating QR code…', { id: toastId });
      await tatchi.recovery.startDevice2LinkingFlow({
        accountId: targetAccountId,
        ui: 'inline',
        options: {
          onEvent: onLinkDeviceEvents,
          onError: (error: Error) => {
            console.error('Device linking error:', error);
            toast.error(error.message || 'Device linking failed', { id: toastId });
          },
          onCancelled: () => {
            toast.dismiss(toastId);
          },
        } as any,
      } as any);
    } catch (error: any) {
      console.error('Device linking start failed:', error);
      toast.error(error?.message || 'Failed to start device linking', { id: toastId });
    }
  };

  const stopDevice2Linking = async () => {
    const toastId = 'device-linking';
    try {
      await tatchi.recovery.stopDevice2LinkingFlow();
    } catch {}
    try {
      toast.dismiss(toastId);
    } catch {}
  };

  const startEmailRecovery = async () => {
    const toastId = 'email-recovery';
    try {
      toast.loading('Starting email recovery…', { id: toastId });
      const { mailtoUrl, nearPublicKey } = await tatchi.recovery.startEmailRecovery({
        accountId: targetAccountId,
        options: {
          onEvent: onEmailRecoveryEvents,
          onError: (error: Error) => {
            console.error('Email recovery error:', error);
            toast.error(error.message || 'Email recovery failed', { id: toastId });
          },
        } as any,
      } as any);

      // Kick the user into their mail client.
      try {
        window.location.href = mailtoUrl;
      } catch {}

      // Best-effort: start polling immediately (user can reload and resume later).
      try {
        await tatchi.recovery.finalizeEmailRecovery({
          accountId: targetAccountId,
          nearPublicKey,
          options: { onEvent: onEmailRecoveryEvents } as any,
        } as any);
      } catch {}
    } catch (error: any) {
      console.error('Email recovery start failed:', error);
      toast.error(error?.message || 'Failed to start email recovery', { id: toastId });
    }
  };

  return (
    <div className="passkey-login-container-root">
      <PasskeyAuthMenuComponent
        // Keep the key stable across accountExists changes to avoid
        // remounting the menu (which causes input focus + content flashes).
        key={`pam2-${authMenuControl.defaultModeOverride ?? 'auto'}-${authMenuControl.remountKey}`}
        defaultMode={
          authMenuControl.defaultModeOverride ??
          (accountExists ? AuthMenuMode.Login : AuthMenuMode.Register)
        }
        showSDKEvents={true}
        loadingScreenDelayMs={100}
        headings={{
          registration: {
            title: 'Register Account',
            subtitle: 'Demo: Create a wallet with Passkey',
          },
        }}
        onLogin={onLogin}
        onRegister={onRegister}
        onSyncAccount={onSyncAccount}
      />
    </div>
  );
}
