import {
  SeamsAuthMenu,
  useSeams,
  type HostedAuthMenuExternalAuthEvidence,
  type HostedAuthMenuExternalAuthRequest,
  type HostedAuthMenuOutcome,
} from '@seams/sdk/react';
import React from 'react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import { useAuthMenuControl, type AuthMenuMode } from '@/context/AuthMenuControl';
import {
  ensureGoogleIdentityScriptLoaded,
  fetchGoogleAuthOptions,
  requestGoogleIdToken,
} from '@/shared/auth/googleIdentity';

type PasskeyLoginMenuProps = {
  defaultModeWhenNoDetectedAccount?: AuthMenuMode;
};

type GoogleSsoReadiness =
  | { kind: 'checking' }
  | { kind: 'ready'; clientId: string }
  | { kind: 'unavailable'; message: string };

type ExistingAccountDetection =
  | { kind: 'checking' }
  | { kind: 'detected_existing_account' }
  | { kind: 'no_existing_account_detected' };

function normalizeBaseUrl(input: unknown): string {
  return String(input || '')
    .trim()
    .replace(/\/+$/, '');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasNonEmptyArray(value: unknown): boolean {
  return Array.isArray(value) && value.length > 0;
}

function recentUnlocksContainExistingAccount(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return (
    hasNonEmptyArray(value.walletIds) ||
    hasNonEmptyArray(value.accountIds) ||
    hasNonEmptyArray(value.accounts) ||
    isRecord(value.lastUsedAccount)
  );
}

function resolveDetectedAccountInitialMode(input: {
  controlOverride?: AuthMenuMode;
  defaultModeWhenNoDetectedAccount?: AuthMenuMode;
  detection: ExistingAccountDetection;
}): AuthMenuMode | undefined {
  if (input.controlOverride !== undefined) return input.controlOverride;
  if (input.defaultModeWhenNoDetectedAccount === undefined) return undefined;

  switch (input.detection.kind) {
    case 'checking':
    case 'detected_existing_account':
      return undefined;
    case 'no_existing_account_detected':
      return input.defaultModeWhenNoDetectedAccount;
    default: {
      const exhaustive: never = input.detection;
      throw new Error(`Unknown existing-account detection state: ${JSON.stringify(exhaustive)}`);
    }
  }
}

function shouldDelayAuthMenuForAccountDetection(input: {
  controlOverride?: AuthMenuMode;
  defaultModeWhenNoDetectedAccount?: AuthMenuMode;
  detection: ExistingAccountDetection;
}): boolean {
  return (
    input.controlOverride === undefined &&
    input.defaultModeWhenNoDetectedAccount !== undefined &&
    input.detection.kind === 'checking'
  );
}

function formatGoogleBrokerError(error: unknown): string {
  if (error instanceof Error && error.message.trim()) return error.message.trim();
  if (typeof error === 'string' && error.trim()) return error.trim();
  return 'Google SSO is unavailable. Please retry.';
}

function requirePreparedGoogleSsoClientId(readiness: GoogleSsoReadiness): string {
  switch (readiness.kind) {
    case 'ready':
      return readiness.clientId;
    case 'checking':
      throw new Error('Google SSO is still loading. Try again in a moment.');
    case 'unavailable':
      throw new Error(readiness.message);
    default: {
      const exhaustive: never = readiness;
      throw new Error(`Unknown Google SSO readiness state: ${JSON.stringify(exhaustive)}`);
    }
  }
}

async function prepareGoogleSsoReadiness(relayerBaseUrl: string): Promise<GoogleSsoReadiness> {
  if (!relayerBaseUrl) {
    return { kind: 'unavailable', message: 'Relayer base URL is not configured' };
  }

  const googleOptions = await fetchGoogleAuthOptions(relayerBaseUrl);
  if (!googleOptions.configured || !googleOptions.clientId) {
    return { kind: 'unavailable', message: 'Google SSO is not configured on the Router API server' };
  }

  await ensureGoogleIdentityScriptLoaded();
  return { kind: 'ready', clientId: googleOptions.clientId };
}

function outcomeMessage(outcome: Extract<HostedAuthMenuOutcome, { kind: 'failed' }>): string {
  return outcome.message.trim() || 'Hosted auth-menu operation failed';
}

function handleHostedAuthMenuOutcome(
  outcome: HostedAuthMenuOutcome,
  refreshLoginState: (walletId?: string) => Promise<void>,
): void {
  switch (outcome.kind) {
    case 'authenticated':
      toast.success(`Logged in as ${outcome.walletId}`, { id: 'login' });
      void refreshLoginState(String(outcome.walletId)).catch(() => {});
      return;
    case 'registered':
      toast.success(`Registration completed: ${outcome.walletId}`, { id: 'registration' });
      void refreshLoginState(String(outcome.walletId)).catch(() => {});
      return;
    case 'account_synced':
      toast.success(`Account synced: ${outcome.walletId}`, { id: 'sync' });
      void refreshLoginState(String(outcome.walletId)).catch(() => {});
      return;
    case 'cancelled':
      toast.info('Wallet authentication cancelled', { id: 'login' });
      return;
    case 'failed':
      toast.error(outcomeMessage(outcome), { id: 'login' });
      return;
    default: {
      const exhaustive: never = outcome;
      throw new Error(`Unknown hosted auth-menu outcome: ${JSON.stringify(exhaustive)}`);
    }
  }
}

function providerUnavailableEvidence(message: string): HostedAuthMenuExternalAuthEvidence {
  return { kind: 'failed', code: 'provider_unavailable', message };
}

function providerErrorEvidence(message: string): HostedAuthMenuExternalAuthEvidence {
  return { kind: 'failed', code: 'provider_error', message };
}

export function PasskeyLoginMenu(props: PasskeyLoginMenuProps) {
  const relayerBaseUrl = React.useMemo(
    () => normalizeBaseUrl(FRONTEND_CONFIG.relayerUrl || FRONTEND_CONFIG.consoleBaseUrl),
    [],
  );
  const { seams, refreshLoginState } = useSeams();
  const authMenuControl = useAuthMenuControl();
  const [googleSsoReadiness, setGoogleSsoReadiness] = React.useState<GoogleSsoReadiness>({
    kind: 'checking',
  });
  const [existingAccountDetection, setExistingAccountDetection] =
    React.useState<ExistingAccountDetection>({
      kind:
        props.defaultModeWhenNoDetectedAccount === undefined
          ? 'detected_existing_account'
          : 'checking',
    });

  React.useEffect(() => {
    let cancelled = false;
    setGoogleSsoReadiness({ kind: 'checking' });
    prepareGoogleSsoReadiness(relayerBaseUrl)
      .then((readiness) => {
        if (!cancelled) setGoogleSsoReadiness(readiness);
      })
      .catch((error: unknown) => {
        if (!cancelled) setGoogleSsoReadiness({ kind: 'unavailable', message: formatGoogleBrokerError(error) });
      });
    return () => {
      cancelled = true;
    };
  }, [relayerBaseUrl]);

  React.useEffect(() => {
    if (props.defaultModeWhenNoDetectedAccount === undefined) {
      setExistingAccountDetection({ kind: 'detected_existing_account' });
      return;
    }

    let cancelled = false;
    setExistingAccountDetection({ kind: 'checking' });
    seams.auth
      .getRecentUnlocks()
      .then((recentUnlocks: unknown) => {
        if (cancelled) return;
        setExistingAccountDetection(
          recentUnlocksContainExistingAccount(recentUnlocks)
            ? { kind: 'detected_existing_account' }
            : { kind: 'no_existing_account_detected' },
        );
      })
      .catch(() => {
        if (!cancelled) setExistingAccountDetection({ kind: 'no_existing_account_detected' });
      });

    return () => {
      cancelled = true;
    };
  }, [props.defaultModeWhenNoDetectedAccount, seams]);

  const externalAuthBroker = React.useCallback(
    async (_request: HostedAuthMenuExternalAuthRequest): Promise<HostedAuthMenuExternalAuthEvidence> => {
      if (googleSsoReadiness.kind !== 'ready') {
        return providerUnavailableEvidence(
          googleSsoReadiness.kind === 'unavailable'
            ? googleSsoReadiness.message
            : 'Google SSO is still loading. Try again in a moment.',
        );
      }
      try {
        const googleClientId = requirePreparedGoogleSsoClientId(googleSsoReadiness);
        const idToken = await requestGoogleIdToken(googleClientId);
        return { kind: 'google_id_token', idToken };
      } catch (error: unknown) {
        return providerErrorEvidence(formatGoogleBrokerError(error));
      }
    },
    [googleSsoReadiness],
  );

  const resolvedInitialMode = resolveDetectedAccountInitialMode({
    controlOverride: authMenuControl.defaultModeOverride,
    defaultModeWhenNoDetectedAccount: props.defaultModeWhenNoDetectedAccount,
    detection: existingAccountDetection,
  });
  const delayAuthMenu = shouldDelayAuthMenuForAccountDetection({
    controlOverride: authMenuControl.defaultModeOverride,
    defaultModeWhenNoDetectedAccount: props.defaultModeWhenNoDetectedAccount,
    detection: existingAccountDetection,
  });

  if (delayAuthMenu) return <div aria-hidden="true" />;

  return (
    <SeamsAuthMenu
      key={`seams-auth-menu-${resolvedInitialMode ?? 'login'}-${authMenuControl.remountKey}`}
      initialMode={resolvedInitialMode}
      registrationAccountInput="implicit_wallet"
      showRegistrationInput={false}
      showProgress
      copy={{
        login: { subtitle: 'Continue with Passkey or Google SSO' },
        register: { subtitle: 'Continue with Passkey or Google SSO' },
      }}
      externalAuthBroker={externalAuthBroker}
      onOutcome={(outcome) => handleHostedAuthMenuOutcome(outcome, refreshLoginState)}
    />
  );
}
