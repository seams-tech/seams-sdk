import {
  AccountSyncEventPhase,
  createAccountSyncFlowEvent,
  type AccountSyncFlowEvent,
  type CreateAccountSyncFlowEventInput,
  type SyncAccountHooksOptions,
} from '../types/sdkSentEvents';
import type { PasskeyManagerContext } from './index';
import type { AccountId, WebAuthnAuthenticationCredential } from '../types';
import { toAccountId } from '../types/accountIds';
import { redactCredentialExtensionOutputs } from '../signingEngine/webauthnAuth/credentials/credentialExtensions';
import type { WebAuthnAllowCredential } from '../signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import { base64UrlDecode } from '@shared/utils/base64';
import { coerceSignerSlot } from '@shared/utils/signerSlot';
import { errorMessage } from '@shared/utils/errors';
import { isObject } from '@shared/utils/validation';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import { restoreLocalLoginState } from './restoreLocalLoginState';
import {
  buildThresholdWarmSessionRequestEnvelope,
  createThresholdWarmSessionPolicyDraft,
  hydrateThresholdWarmSessionFromRelay,
  requireThresholdEd25519WarmSessionKeyVersion,
  reconstructThresholdEd25519ClientBaseFromWarmSession,
  storeThresholdEd25519KeyMaterial,
} from './thresholdWarmSessionBootstrap';
import { IndexedDBManager } from '../indexedDB';
import { resolveNearAccountProfileContinuity } from '../accountData/near/accountProjection';
import {
  normalizeIndexedDbAccountAddress,
  normalizeIndexedDbChainIdKey,
  toIndexedDbChainTargetKey,
} from '../indexedDB/normalization';
import { thresholdEcdsaChainTargetFromRequest } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

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

async function persistSyncedThresholdEcdsaAccountSigners(args: {
  nearAccountId: AccountId;
  signerSlot: number;
  records: unknown[];
}): Promise<void> {
  const continuity = await resolveNearAccountProfileContinuity(
    IndexedDBManager.clientDB,
    args.nearAccountId,
  );
  const profileId = String(continuity?.profile.profileId || '').trim();
  if (!profileId) return;

  for (const rawRecord of args.records) {
    if (!isObject(rawRecord)) continue;
    if (String(rawRecord.status || '').trim() !== 'active') continue;
    if (String(rawRecord.signerType || '').trim() !== 'threshold') continue;
    const metadata = isObject(rawRecord.metadata) ? rawRecord.metadata : {};
    let chainTarget;
    try {
      chainTarget = thresholdEcdsaChainTargetFromRequest(
        isObject(metadata.chainTarget) ? metadata.chainTarget : {},
      );
    } catch {
      continue;
    }

    const ecdsaThresholdKeyId = String(metadata.ecdsaThresholdKeyId || '').trim();
    const relayerKeyId = String(metadata.relayerKeyId || '').trim();
    const thresholdEcdsaPublicKeyB64u = String(metadata.thresholdEcdsaPublicKeyB64u || '').trim();
    const signerId = normalizeIndexedDbAccountAddress(
      rawRecord.signerId || metadata.ownerAddress,
    );
    const accountAddress = normalizeIndexedDbAccountAddress(
      rawRecord.accountAddress || metadata.counterfactualAddress || metadata.ownerAddress,
    );
    if (
      !ecdsaThresholdKeyId ||
      !relayerKeyId ||
      !thresholdEcdsaPublicKeyB64u ||
      !signerId ||
      !accountAddress
    ) {
      continue;
    }

    const metadataSignerSlot = Number(metadata.signerSlot);
    const signerSlot =
      Number.isSafeInteger(metadataSignerSlot) && metadataSignerSlot >= 1
        ? metadataSignerSlot
        : args.signerSlot;
    const chainIdKey =
      normalizeIndexedDbChainIdKey(rawRecord.chainIdKey) || toIndexedDbChainTargetKey(chainTarget);
    const accountModel =
      String(metadata.accountModel || '').trim() ||
      (chainTarget.kind === 'evm' ? 'erc4337' : 'tempo-native');

    await IndexedDBManager.clientDB.upsertChainAccount({
      profileId,
      chainIdKey,
      accountAddress,
      accountModel,
      isPrimary: true,
      ...(String(metadata.factory || '').trim() ? { factory: String(metadata.factory).trim() } : {}),
      ...(String(metadata.entryPoint || '').trim()
        ? { entryPoint: String(metadata.entryPoint).trim() }
        : {}),
      ...(String(metadata.salt || '').trim() ? { salt: String(metadata.salt).trim() } : {}),
      ...(String(metadata.counterfactualAddress || '').trim()
        ? { counterfactualAddress: String(metadata.counterfactualAddress).trim() }
        : {}),
    });

    await IndexedDBManager.clientDB.upsertAccountSigner({
      profileId,
      chainIdKey,
      accountAddress,
      signerId,
      signerSlot,
      signerType: 'threshold',
      signerKind: SIGNER_KINDS.thresholdEcdsa,
      signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
      signerSource: SIGNER_SOURCES.passkeyRegistration,
      status: 'active',
      metadata: {
        ...metadata,
        accountModel,
        ownerAddress: signerId,
        ecdsaThresholdKeyId,
        relayerKeyId,
        thresholdEcdsaPublicKeyB64u,
        signerSlot,
        chainTarget,
        chainId: chainTarget.chainId,
      },
      mutation: { routeThroughOutbox: false },
    });
  }
}

export async function syncAccount(
  context: PasskeyManagerContext,
  accountId: AccountId | null,
  options?: SyncAccountHooksOptions,
): Promise<SyncAccountResult> {
  const onEvent = options?.onEvent;
  const flowId = `account-sync:${String(accountId || 'discovery')}`;
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
      ...(accountId ? { accountId: String(accountId) } : {}),
      error: { code: 'missing_relayer_url', message: 'Missing relayer url' },
    });
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
    emit({
      phase: AccountSyncEventPhase.FAILED,
      status: 'failed',
      ...(accountId ? { accountId: String(accountId) } : {}),
      error: { code: 'missing_rp_id', message: 'Missing rpId for WebAuthn sync' },
    });
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
    const normalizedRequestedAccountId = accountId ? toAccountId(String(accountId)) : null;

    emit({
      phase: AccountSyncEventPhase.STEP_01_STARTED,
      status: 'started',
      ...(normalizedRequestedAccountId ? { accountId: String(normalizedRequestedAccountId) } : {}),
    });

    // 1) Get a relay-minted challenge for discovery.
    const optionsResp = await fetch(`${relayerUrl}/sync-account/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        rp_id: rpId,
        ...(normalizedRequestedAccountId
          ? { account_id: String(normalizedRequestedAccountId) }
          : {}),
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

    const credentialIdsFromOptions = Array.isArray(
      (optionsJson as { credentialIds?: unknown }).credentialIds,
    )
      ? (optionsJson as { credentialIds: unknown[] }).credentialIds
          .map((id) => String(id || '').trim())
          .filter((id) => id.length > 0)
      : [];
    if (normalizedRequestedAccountId && credentialIdsFromOptions.length === 0) {
      throw new Error(
        `No passkeys found for account ${String(normalizedRequestedAccountId)} on this relay`,
      );
    }

    emit({
      phase: AccountSyncEventPhase.STEP_02_PASSKEY_PROMPT_STARTED,
      status: 'waiting_for_user',
      ...(normalizedRequestedAccountId ? { accountId: String(normalizedRequestedAccountId) } : {}),
      interaction: { kind: 'passkey_assert', overlay: 'show' },
    });

    const allowCredentials: WebAuthnAllowCredential[] = normalizedRequestedAccountId
      ? credentialIdsFromOptions.map((id) => ({ id, type: 'public-key', transports: [] }))
      : [];

    // Discovery mode intentionally uses an empty `allowCredentials`, letting the browser ask
    // the user to choose any passkey for this `rpId`.
    const credential = await context.signingEngine.getAuthenticationCredentialsSerialized({
      nearAccountId: accountId || toAccountId('dummy.testnet'),
      challengeB64u,
      allowCredentials,
      includeSecondPrfOutput: false,
    });
    emit({
      phase: AccountSyncEventPhase.STEP_02_PASSKEY_PROMPT_SUCCEEDED,
      status: 'succeeded',
      ...(normalizedRequestedAccountId ? { accountId: String(normalizedRequestedAccountId) } : {}),
      interaction: { kind: 'passkey_assert', overlay: 'hide' },
    });
    let thresholdWarmPolicyDraft: ReturnType<typeof createThresholdWarmSessionPolicyDraft> = null;
    let thresholdEd25519SessionRequest: ReturnType<
      typeof buildThresholdWarmSessionRequestEnvelope
    > | null = null;
    if (normalizedRequestedAccountId) {
      thresholdWarmPolicyDraft = createThresholdWarmSessionPolicyDraft(context);
      if (!thresholdWarmPolicyDraft) {
        throw new Error('Threshold warm-session defaults are disabled for sync bootstrap');
      }
      thresholdEd25519SessionRequest = buildThresholdWarmSessionRequestEnvelope({
        nearAccountId: String(normalizedRequestedAccountId),
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
      ...(normalizedRequestedAccountId ? { accountId: String(normalizedRequestedAccountId) } : {}),
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
      ...(normalizedRequestedAccountId ? { accountId: String(normalizedRequestedAccountId) } : {}),
    });

    const syncedAccountId = String(verifyJson.accountId || '').trim();
    if (!syncedAccountId) {
      throw new Error('sync-account/verify returned missing accountId');
    }
    if (normalizedRequestedAccountId && String(normalizedRequestedAccountId) !== syncedAccountId) {
      throw new Error(
        `Selected passkey is not registered for account ${String(normalizedRequestedAccountId)}`,
      );
    }

    const signerSlot = coerceSignerSlot(verifyJson.signerSlot, {
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
    const normalizedAccountId = toAccountId(syncedAccountId);
    await context.signingEngine.storeUserData({
      nearAccountId: normalizedAccountId,
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
      nearAccountId: normalizedAccountId,
      credentialId: String(credential.rawId || ''),
      credentialPublicKey,
      transports: [],
      name: `Passkey for ${syncedAccountId}`,
      registered: new Date().toISOString(),
      syncedAt: new Date().toISOString(),
      signerSlot,
    });

    emit({
      phase: AccountSyncEventPhase.STEP_04_AUTHENTICATOR_SAVED,
      status: 'succeeded',
      accountId: syncedAccountId,
      data: { signerSlot },
    });

    const syncedSmartAccountSigners = Array.isArray(verifyJson.smartAccountSigners)
      ? verifyJson.smartAccountSigners
      : [];
    if (syncedSmartAccountSigners.length) {
      await persistSyncedThresholdEcdsaAccountSigners({
        nearAccountId: normalizedAccountId,
        signerSlot,
        records: syncedSmartAccountSigners,
      });
    }

    // 3) Persist threshold key material when available.
    const thresholdEd25519 = isObject(verifyJson.thresholdEd25519)
      ? verifyJson.thresholdEd25519
      : {};
    const relayerKeyId = String(
      (thresholdEd25519.relayerKeyId ?? verifyJson.relayerKeyId ?? '') || '',
    ).trim();
    if (relayerKeyId) {
      const { keyVersion: thresholdKeyVersion } = requireThresholdEd25519WarmSessionKeyVersion(
        thresholdEd25519,
        'sync-account/verify',
      );

      await storeThresholdEd25519KeyMaterial({
        nearAccountId: normalizedAccountId,
        signerSlot,
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
        timestamp: Date.now(),
      });

      if (
        thresholdWarmPolicyDraft &&
        normalizedRequestedAccountId &&
        String(normalizedRequestedAccountId) === String(normalizedAccountId)
      ) {
        const thresholdSession = isObject((thresholdEd25519 as Record<string, unknown>).session)
          ? ((thresholdEd25519 as Record<string, unknown>).session as Record<string, unknown>)
          : null;
        if (!thresholdSession) {
          throw new Error('sync-account/verify did not return threshold session bootstrap data');
        }
        await hydrateThresholdWarmSessionFromRelay({
          context,
          nearAccountId: normalizedAccountId,
          relayerUrl,
          rpId,
          relayerKeyId,
          credential,
          requestedPolicy: thresholdWarmPolicyDraft,
          session: thresholdSession,
          participantIdsHint: Array.isArray(thresholdEd25519.participantIds)
            ? thresholdEd25519.participantIds
            : undefined,
        });
        await reconstructThresholdEd25519ClientBaseFromWarmSession({
          context,
          credential,
          nearAccountId: normalizedAccountId,
          relayerUrl,
          relayerKeyId,
          session: thresholdSession,
          keyVersion: thresholdKeyVersion,
          participantIdsHint: Array.isArray(thresholdEd25519.participantIds)
            ? thresholdEd25519.participantIds
            : undefined,
        });
        emit({
          phase: AccountSyncEventPhase.STEP_05_THRESHOLD_SESSION_READY,
          status: 'succeeded',
          accountId: syncedAccountId,
          authMethod: 'warm_session',
        });
      }
    }

    const restoredLogin = await restoreLocalLoginState({
      context,
      nearAccountId: normalizedAccountId,
      signerSlot,
    });
    const isLoggedIn = restoredLogin.isLoggedIn;

    emit({
      phase: AccountSyncEventPhase.STEP_06_COMPLETED,
      status: 'succeeded',
      accountId: syncedAccountId,
    });

    return {
      success: true,
      accountId: syncedAccountId,
      publicKey,
      message: 'Account synced successfully',
      loginState: { isLoggedIn },
    };
  } catch (e: unknown) {
    const msg = errorMessage(e) || 'syncAccount failed';
    emit({
      phase: AccountSyncEventPhase.FAILED,
      status: 'failed',
      ...(accountId ? { accountId: String(accountId) } : {}),
      error: { message: msg },
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
