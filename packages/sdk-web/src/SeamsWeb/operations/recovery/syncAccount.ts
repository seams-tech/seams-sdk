import {
  AccountSyncEventPhase,
  createAccountSyncFlowEvent,
  type CreateAccountSyncFlowEventInput,
  type SyncAccountHooksOptions,
} from '@/core/types/sdkSentEvents';
import type { SyncAccountResult } from '@/core/types/sdkPublicResults';
import type { AccountSyncWebContext } from '@/SeamsWeb/signingSurface/types';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import { base64UrlDecode } from '@shared/utils/base64';
import { coerceSignerSlot } from '@shared/utils/signerSlot';
import { errorMessage } from '@shared/utils/errors';
import { isObject } from '@shared/utils/validation';
import { restoreLocalLoginState } from '@/SeamsWeb/operations/session/restoreLocalLoginState';
import {
  buildThresholdWarmSessionRequestEnvelope,
  createThresholdWarmSessionPolicyDraft,
  hydrateThresholdWarmSessionFromRelay,
  requireThresholdEd25519WarmSessionKeyVersion,
  reconstructThresholdEd25519SigningMaterialFromWarmSession,
  storeThresholdEd25519KeyMaterial,
} from '@/SeamsWeb/operations/session/thresholdWarmSessionBootstrap';
import { formatEd25519HssKeyVersionForWire } from '@/core/signingEngine/session/keyMaterialBrands';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  parseRecoveryResolvedWalletBindingFromResponse,
  type RecoveryResolvedWalletBinding,
} from './recoveryWalletBinding';

export type { SyncAccountResult };

function syncAccountFailure(error: string): SyncAccountResult {
  return {
    success: false,
    error,
  };
}

function thresholdEd25519SessionFromSyncVerifyResponse(
  thresholdEd25519: Record<string, unknown>,
): Record<string, unknown> | null {
  return isObject(thresholdEd25519.session) ? thresholdEd25519.session : null;
}

export async function syncAccount(
  context: AccountSyncWebContext,
  walletId: string | null,
  options?: SyncAccountHooksOptions,
): Promise<SyncAccountResult> {
  const onEvent = options?.onEvent;
  const flowId = `account-sync:${String(walletId || 'discovery')}`;
  const emit = (event: Omit<CreateAccountSyncFlowEventInput, 'flowId'>): void => {
    try {
      onEvent?.(createAccountSyncFlowEvent({ flowId, ...event }));
    } catch {}
  };

  const relayerUrl = String(context.configs.network.relayer?.url || '').trim();
  if (!relayerUrl) {
    emit({
      phase: AccountSyncEventPhase.FAILED,
      status: 'failed',
      ...(walletId ? { accountId: String(walletId) } : {}),
      error: { code: 'missing_relayer_url', message: 'Missing relayer url' },
    });
    return syncAccountFailure('missing_relayer_url');
  }

  const rpId = context.signingEngine.getRpId();
  if (!rpId) {
    emit({
      phase: AccountSyncEventPhase.FAILED,
      status: 'failed',
      ...(walletId ? { accountId: String(walletId) } : {}),
      error: { code: 'missing_rp_id', message: 'Missing rpId for WebAuthn sync' },
    });
    return syncAccountFailure('missing_rp_id');
  }

  try {
    const requestedWalletId = walletId ? walletIdFromString(String(walletId)) : null;

    emit({
      phase: AccountSyncEventPhase.STEP_01_STARTED,
      status: 'started',
      ...(requestedWalletId ? { accountId: String(requestedWalletId) } : {}),
    });

    // 1) Get a relay-minted challenge for discovery.
    const optionsResp = await fetch(`${relayerUrl}/sync-account/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        rp_id: rpId,
        ...(requestedWalletId ? { account_id: String(requestedWalletId) } : {}),
      }),
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
    const optionsWalletBinding: RecoveryResolvedWalletBinding | null = isObject(
      optionsJson.walletBinding,
    )
      ? parseRecoveryResolvedWalletBindingFromResponse(
          optionsJson as Record<string, unknown>,
          'sync-account/options',
        )
      : null;
    if (requestedWalletId && !optionsWalletBinding) {
      throw new Error(`No wallet binding found for account ${String(requestedWalletId)}`);
    }

    const credentialIdsFromOptions = Array.isArray(
      (optionsJson as { credentialIds?: unknown }).credentialIds,
    )
      ? (optionsJson as { credentialIds: unknown[] }).credentialIds
          .map((id) => String(id || '').trim())
          .filter((id) => id.length > 0)
      : [];
    if (requestedWalletId && credentialIdsFromOptions.length === 0) {
      throw new Error(`No passkeys found for account ${String(requestedWalletId)} on this relay`);
    }

    emit({
      phase: AccountSyncEventPhase.STEP_02_PASSKEY_PROMPT_STARTED,
      status: 'waiting_for_user',
      ...(requestedWalletId ? { accountId: String(requestedWalletId) } : {}),
      interaction: { kind: 'passkey_assert', overlay: 'show' },
    });

    const allowCredentials: WebAuthnAllowCredential[] = requestedWalletId
      ? credentialIdsFromOptions.map((id) => ({ id, type: 'public-key', transports: [] }))
      : [];

    // Discovery mode intentionally uses an empty `allowCredentials`, letting the browser ask
    // the user to choose any passkey for this `rpId`.
    const credential = await context.signingEngine.getAuthenticationCredentialsSerialized({
      subjectId: String(requestedWalletId || 'account-sync'),
      challengeB64u,
      allowCredentials,
      includeSecondPrfOutput: false,
    });
    emit({
      phase: AccountSyncEventPhase.STEP_02_PASSKEY_PROMPT_SUCCEEDED,
      status: 'succeeded',
      ...(requestedWalletId ? { accountId: String(requestedWalletId) } : {}),
      interaction: { kind: 'passkey_assert', overlay: 'hide' },
    });
    let thresholdWarmPolicyDraft: ReturnType<typeof createThresholdWarmSessionPolicyDraft> = null;
    let thresholdEd25519SessionRequest: ReturnType<
      typeof buildThresholdWarmSessionRequestEnvelope
    > | null = null;
    if (optionsWalletBinding) {
      thresholdWarmPolicyDraft = createThresholdWarmSessionPolicyDraft(context, {
        kind: 'generated_signing_grant',
      });
      if (!thresholdWarmPolicyDraft) {
        throw new Error('Threshold warm-session defaults are disabled for sync bootstrap');
      }
      thresholdEd25519SessionRequest = buildThresholdWarmSessionRequestEnvelope({
        walletId: String(optionsWalletBinding.walletId),
        nearAccountId: String(optionsWalletBinding.nearAccountId),
        nearEd25519SigningKeyId: String(optionsWalletBinding.nearEd25519SigningKeyId),
        rpId,
        requestedPolicy: thresholdWarmPolicyDraft,
      });
    }

    const credentialForRelay =
      redactCredentialExtensionOutputs<WebAuthnAuthenticationCredential>(credential);
    const verifyRequestBody: Record<string, unknown> = {
      challengeId,
      webauthn_authentication: credentialForRelay,
    };
    if (thresholdEd25519SessionRequest) {
      verifyRequestBody.threshold_ed25519 = thresholdEd25519SessionRequest;
    }

    emit({
      phase: AccountSyncEventPhase.STEP_03_RELAY_VERIFY_STARTED,
      status: 'running',
      ...(requestedWalletId ? { accountId: String(requestedWalletId) } : {}),
    });
    const verifyResp = await fetch(`${relayerUrl}/sync-account/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(verifyRequestBody),
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
    emit({
      phase: AccountSyncEventPhase.STEP_03_RELAY_VERIFY_SUCCEEDED,
      status: 'succeeded',
      ...(requestedWalletId ? { accountId: String(requestedWalletId) } : {}),
    });

    const resolvedWalletBinding = parseRecoveryResolvedWalletBindingFromResponse(
      verifyJson as Record<string, unknown>,
      'sync-account/verify',
    );
    if (requestedWalletId && String(requestedWalletId) !== String(resolvedWalletBinding.walletId)) {
      throw new Error(`Selected passkey is not registered for account ${String(requestedWalletId)}`);
    }

    const signerSlot = coerceSignerSlot(resolvedWalletBinding.signerSlot, {
      min: 1,
      fallback: 1,
    });
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
    const normalizedNearAccountId = resolvedWalletBinding.nearAccountId;
    await context.signingEngine.storeUserData({
      walletId: String(resolvedWalletBinding.walletId),
      nearAccountId: normalizedNearAccountId,
      signerSlot,
      operationalPublicKey: publicKey,
      lastUpdated: Date.now(),
      passkeyCredential: {
        id: String(credential.id || ''),
        rawId: String(credential.rawId || ''),
      },
      version: 2,
    });
    await context.signingEngine.storeAuthenticator({
      nearAccountId: normalizedNearAccountId,
      credentialId: String(credential.rawId || ''),
      credentialPublicKey,
      transports: [],
      name: `Passkey for ${String(resolvedWalletBinding.walletId)}`,
      registered: new Date().toISOString(),
      syncedAt: new Date().toISOString(),
      signerSlot,
    });

    emit({
      phase: AccountSyncEventPhase.STEP_04_AUTHENTICATOR_SAVED,
      status: 'succeeded',
      accountId: String(resolvedWalletBinding.walletId),
      data: { signerSlot },
    });

    // 3) Persist threshold key material when available.
    const thresholdEd25519 = isObject(verifyJson.thresholdEd25519)
      ? verifyJson.thresholdEd25519
      : {};
    const relayerKeyId = String(
      (thresholdEd25519.relayerKeyId ?? verifyJson.relayerKeyId ?? '') || '',
    ).trim();
    if (relayerKeyId) {
      const { ed25519HssKeyVersion } = requireThresholdEd25519WarmSessionKeyVersion(
        thresholdEd25519,
        'sync-account/verify',
      );
      const thresholdKeyVersion = formatEd25519HssKeyVersionForWire(ed25519HssKeyVersion);
      const thresholdKeyMaterialCreatedAtMs = Date.now();

      await storeThresholdEd25519KeyMaterial({
        nearAccountId: normalizedNearAccountId,
        signerSlot,
        signerId: publicKey,
        publicKey,
        relayerKeyId,
        keyVersion: thresholdKeyVersion,
        clientParticipantId: Number.isFinite(Number(thresholdEd25519.clientParticipantId))
          ? Math.floor(Number(thresholdEd25519.clientParticipantId))
          : null,
        relayerParticipantId: Number.isFinite(Number(thresholdEd25519.relayerParticipantId))
          ? Math.floor(Number(thresholdEd25519.relayerParticipantId))
          : null,
        relayerUrl: context.configs?.network.relayer?.url,
        timestamp: thresholdKeyMaterialCreatedAtMs,
      });

      if (thresholdWarmPolicyDraft && optionsWalletBinding) {
        const thresholdSession = thresholdEd25519SessionFromSyncVerifyResponse(thresholdEd25519);
        if (!thresholdSession) {
          throw new Error('sync-account/verify did not return threshold session bootstrap data');
        }
        await hydrateThresholdWarmSessionFromRelay({
          context,
          walletId: String(resolvedWalletBinding.walletId),
          nearAccountId: normalizedNearAccountId,
          nearEd25519SigningKeyId: String(resolvedWalletBinding.nearEd25519SigningKeyId),
          relayerUrl,
          rpId,
          relayerKeyId,
          credential,
          signerSlot,
          requestedPolicy: thresholdWarmPolicyDraft,
          session: thresholdSession,
          participantIdsHint: Array.isArray(thresholdEd25519.participantIds)
            ? thresholdEd25519.participantIds
            : undefined,
        });
        await reconstructThresholdEd25519SigningMaterialFromWarmSession({
          context,
          credential,
          walletId: String(resolvedWalletBinding.walletId),
          nearAccountId: normalizedNearAccountId,
          nearEd25519SigningKeyId: resolvedWalletBinding.nearEd25519SigningKeyId,
          rpId,
          relayerUrl,
          relayerKeyId,
          session: thresholdSession,
          signerSlot,
          materialCreatedAtMs: thresholdKeyMaterialCreatedAtMs,
          participantIdsHint: Array.isArray(thresholdEd25519.participantIds)
            ? thresholdEd25519.participantIds
            : undefined,
        });
        emit({
          phase: AccountSyncEventPhase.STEP_05_THRESHOLD_SESSION_READY,
          status: 'succeeded',
          accountId: String(resolvedWalletBinding.walletId),
          authMethod: 'warm_session',
        });
      }
    }

    const restoredLogin = await restoreLocalLoginState({
      context,
      walletId: resolvedWalletBinding.walletId,
      nearAccountId: normalizedNearAccountId,
      nearEd25519SigningKeyId: resolvedWalletBinding.nearEd25519SigningKeyId,
      signerSlot,
    });
    const isLoggedIn = restoredLogin.isLoggedIn;

    emit({
      phase: AccountSyncEventPhase.STEP_06_COMPLETED,
      status: 'succeeded',
      accountId: String(resolvedWalletBinding.walletId),
    });

    return {
      success: true,
      accountId: String(resolvedWalletBinding.walletId),
      walletId: String(resolvedWalletBinding.walletId),
      nearAccountId: String(resolvedWalletBinding.nearAccountId),
      nearEd25519SigningKeyId: String(resolvedWalletBinding.nearEd25519SigningKeyId),
      publicKey,
      message: 'Account synced successfully',
      loginState: { isLoggedIn },
    };
  } catch (e: unknown) {
    const msg = errorMessage(e) || 'syncAccount failed';
    emit({
      phase: AccountSyncEventPhase.FAILED,
      status: 'failed',
      ...(walletId ? { accountId: String(walletId) } : {}),
      error: { message: msg },
    });
    return syncAccountFailure(msg);
  }
}
