import type { SyncAccountHooksOptions } from '../types/sdkSentEvents';
import { SyncAccountPhase, SyncAccountStatus } from '../types/sdkSentEvents';
import type { SyncAccountSSEEvent } from '../types/sdkSentEvents';
import type { PasskeyManagerContext } from './index';
import type { AccountId, WebAuthnAuthenticationCredential } from '../types';
import { toAccountId } from '../types/accountIds';
import { redactCredentialExtensionOutputs } from '../signingEngine/signers/webauthn/credentials';
import type { WebAuthnAllowCredential } from '../signingEngine/signers/webauthn/credentials';
import { base64UrlDecode } from '@shared/utils/base64';
import { errorMessage } from '@shared/utils/errors';
import { isObject } from '@shared/utils/validation';
import { IndexedDBManager } from '../indexedDB';
import { buildThresholdEd25519Participants2pV1 } from '@shared/threshold/participants';

export interface SyncAccountResult {
  success: boolean;
  accountId: string;
  publicKey: string;
  message: string;
  error?: string;
  loginState?: {
    isLoggedIn: boolean;
  };
}

export async function syncAccount(
  context: PasskeyManagerContext,
  accountId: AccountId | null,
  options?: SyncAccountHooksOptions,
  reuseCredential?: WebAuthnAuthenticationCredential,
  allowedCredentialIds?: string[],
): Promise<SyncAccountResult> {
  const onEvent = options?.onEvent;
  const emit = (event: SyncAccountEventPayload): void => {
    try {
      onEvent?.(event as SyncAccountSSEEvent);
    } catch {}
  };

  const relayerUrl = String(context.configs.network.relayer?.url || '').trim();
  if (!relayerUrl) {
    return {
      success: false,
      accountId: accountId ? String(accountId) : '',
      publicKey: '',
      message: 'Missing relayer url (configs.network.relayer.url)',
      error: 'missing_relayer_url',
      loginState: { isLoggedIn: false },
    };
  }

  const rpId = context.signingEngine.getRpId();
  if (!rpId) {
    return {
      success: false,
      accountId: accountId ? String(accountId) : '',
      publicKey: '',
      message: 'Missing rpId for WebAuthn sync',
      error: 'missing_rp_id',
      loginState: { isLoggedIn: false },
    };
  }

  try {
    emit({
      step: 1,
      phase: SyncAccountPhase.STEP_1_PREPARATION,
      status: SyncAccountStatus.PROGRESS,
      message: 'Preparing account sync...',
    });

    // 1) Get a relay-minted challenge for discovery.
    const optionsResp = await fetch(`${relayerUrl}/sync-account/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rp_id: rpId }),
    });
    const optionsJsonUnknown: unknown = await optionsResp.json().catch(() => ({}));
    const optionsJson = isObject(optionsJsonUnknown) ? optionsJsonUnknown : {};
    const optionsOk = optionsJson.ok === true;
    const optionsMessage = typeof optionsJson.message === 'string' ? optionsJson.message : '';
    const optionsError = typeof optionsJson.error === 'string' ? optionsJson.error : '';
    if (!optionsResp.ok || !optionsOk) {
      throw new Error(
        optionsMessage ||
          optionsError ||
          `sync-account/options failed (HTTP ${optionsResp.status})`,
      );
    }

    const challengeId = String(optionsJson.challengeId || '').trim();
    const challengeB64u = String(optionsJson.challengeB64u || '').trim();
    if (!challengeId || !challengeB64u) {
      throw new Error('sync-account/options returned invalid challenge');
    }

    emit({
      step: 2,
      phase: SyncAccountPhase.STEP_2_WEBAUTHN_AUTHENTICATION,
      status: SyncAccountStatus.PROGRESS,
      message: 'Authenticating with passkey...',
    });

    const allowCredentials: WebAuthnAllowCredential[] =
      Array.isArray(allowedCredentialIds) && allowedCredentialIds.length
        ? allowedCredentialIds.map((id) => ({ id, type: 'public-key', transports: [] }))
        : [];

    // NOTE: We intentionally avoid requiring a known accountId for discovery. When `allowCredentials`
    // is empty, the browser prompts the user to select any passkey for `rpId`.
    const credential =
      reuseCredential ||
      (await context.signingEngine.getAuthenticationCredentialsSerialized({
        nearAccountId: accountId || toAccountId('dummy.testnet'),
        challengeB64u,
        allowCredentials,
        includeSecondPrfOutput: false,
      }));

    const credentialForRelay =
      redactCredentialExtensionOutputs<WebAuthnAuthenticationCredential>(credential);
    const verifyResp = await fetch(`${relayerUrl}/sync-account/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId,
        webauthn_authentication: credentialForRelay,
      }),
    });
    const verifyJsonUnknown: unknown = await verifyResp.json().catch(() => ({}));
    const verifyJson = isObject(verifyJsonUnknown) ? verifyJsonUnknown : {};
    const verifyOk = verifyJson.ok === true;
    const verified = verifyJson.verified === true;
    const verifyMessage = typeof verifyJson.message === 'string' ? verifyJson.message : '';
    const verifyError = typeof verifyJson.error === 'string' ? verifyJson.error : '';
    if (!verifyResp.ok || !verifyOk || !verified) {
      throw new Error(
        verifyMessage || verifyError || `sync-account/verify failed (HTTP ${verifyResp.status})`,
      );
    }

    const syncedAccountId = String(verifyJson.accountId || '').trim();
    if (!syncedAccountId) {
      throw new Error('sync-account/verify returned missing accountId');
    }
    if (accountId && String(accountId) !== syncedAccountId) {
      throw new Error(`Selected passkey is not registered for account ${String(accountId)}`);
    }

    const deviceNumber = (() => {
      const n = Number(verifyJson.deviceNumber);
      return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 1;
    })();
    const publicKey = String(verifyJson.publicKey || '').trim();
    if (!publicKey) {
      throw new Error('sync-account/verify returned missing publicKey');
    }

    const credentialPublicKeyB64u = String(verifyJson.credentialPublicKeyB64u || '').trim();
    if (!credentialPublicKeyB64u) {
      throw new Error('sync-account/verify returned missing credentialPublicKeyB64u');
    }
    const credentialPublicKey = base64UrlDecode(credentialPublicKeyB64u);

    // 2) Persist user + authenticator data locally.
    const normalizedAccountId = toAccountId(syncedAccountId);
    await context.signingEngine.storeUserData({
      nearAccountId: normalizedAccountId,
      deviceNumber,
      clientNearPublicKey: publicKey,
      lastUpdated: Date.now(),
      passkeyCredential: {
        id: String(credential.id || ''),
        rawId: String(credential.rawId || ''),
      },
      version: 2,
    });
    await context.signingEngine.storeAuthenticator({
      nearAccountId: normalizedAccountId,
      credentialId: String(credential.rawId || ''),
      credentialPublicKey,
      transports: [],
      name: `Passkey for ${syncedAccountId}`,
      registered: new Date().toISOString(),
      syncedAt: new Date().toISOString(),
      deviceNumber,
    });

    emit({
      step: 4,
      phase: SyncAccountPhase.STEP_4_AUTHENTICATOR_SAVED,
      status: SyncAccountStatus.SUCCESS,
      message: 'Passkey saved locally',
    });

    // 3) Persist threshold key material when available.
    const thresholdEd25519 = isObject(verifyJson.thresholdEd25519)
      ? verifyJson.thresholdEd25519
      : {};
    const relayerKeyId = String(
      (thresholdEd25519.relayerKeyId ?? verifyJson.relayerKeyId ?? '') || '',
    ).trim();
    if (relayerKeyId) {
      const relayerVerifyingShareB64u = String(
        thresholdEd25519.relayerVerifyingShareB64u || '',
      ).trim();
      const derived =
        await context.signingEngine.deriveThresholdEd25519ClientVerifyingShareFromCredential({
          credential,
          nearAccountId: normalizedAccountId,
        });
      const clientVerifyingShareB64u = derived.success
        ? String(derived.clientVerifyingShareB64u || '').trim()
        : '';

      await IndexedDBManager.storeNearThresholdKeyMaterial({
        nearAccountId: normalizedAccountId,
        deviceNumber,
        publicKey,
        relayerKeyId,
        clientShareDerivation: 'prf_first_v1',
        participants: buildThresholdEd25519Participants2pV1({
          clientParticipantId: Number.isFinite(Number(thresholdEd25519.clientParticipantId))
            ? Math.floor(Number(thresholdEd25519.clientParticipantId))
            : null,
          relayerParticipantId: Number.isFinite(Number(thresholdEd25519.relayerParticipantId))
            ? Math.floor(Number(thresholdEd25519.relayerParticipantId))
            : null,
          relayerKeyId,
          relayerUrl: context.configs?.network.relayer?.url,
          clientVerifyingShareB64u,
          relayerVerifyingShareB64u,
          clientShareDerivation: 'prf_first_v1',
        }),
        timestamp: Date.now(),
      });
    }

    emit({
      step: 5,
      phase: SyncAccountPhase.STEP_5_SYNC_ACCOUNT_COMPLETE,
      status: SyncAccountStatus.SUCCESS,
      message: 'Account synced',
    });

    return {
      success: true,
      accountId: syncedAccountId,
      publicKey,
      message: 'Account synced successfully',
      loginState: { isLoggedIn: false },
    };
  } catch (e: unknown) {
    const msg = errorMessage(e) || 'syncAccount failed';
    emit({
      step: 0,
      phase: SyncAccountPhase.ERROR,
      status: SyncAccountStatus.ERROR,
      message: 'Account sync failed',
      error: msg,
    });
    return {
      success: false,
      accountId: accountId ? String(accountId) : '',
      publicKey: '',
      message: msg,
      error: msg,
      loginState: { isLoggedIn: false },
    };
  }
}

type SyncAccountEventPayload = {
  step: number;
  phase: SyncAccountPhase;
  status: SyncAccountStatus;
  message: string;
  error?: string;
  data?: Record<string, unknown>;
  [key: string]: unknown;
};
