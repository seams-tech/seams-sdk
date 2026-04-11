import type { PasskeyManagerContext } from '../index';
import type {
  DeviceLinkingQRData,
  LinkDeviceResult,
  DeviceLinkingSession,
  ScanAndLinkDeviceOptionsDevice1,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
} from '../../types/linkDevice';
import { DeviceLinkingPhase, DeviceLinkingStatus } from '../../types/sdkSentEvents';
import type { DeviceLinkingSSEEvent } from '../../types/sdkSentEvents';
import { toAccountId } from '../../types/accountIds';
import { coerceDeviceNumber } from '@shared/utils/deviceNumber';
import { errorMessage } from '@shared/utils/errors';
import { joinNormalizedUrl, stripTrailingSlashes } from '@shared/utils/normalize';
import { IndexedDBManager } from '../../indexedDB';
import { ensureEd25519Prefix, isObject } from '@shared/utils/validation';
import type { WalletIframeCoordinator } from '../walletIframeCoordinator';
import { restoreLocalLoginState } from '../restoreLocalLoginState';
import { linkDeviceWithScannedQRData as linkDeviceWithScannedQRDataDevice1 } from '../scanDevice';
import { DEVICE_LINKING_CONFIG } from '../../../config';
import { normalizeRegistrationCredential } from '../../signingEngine/signers/webauthn/credentials/helpers';
import { redactCredentialExtensionOutputs } from '../../signingEngine/signers/webauthn/credentials';
import { getPrfFirstB64uFromCredential } from '../../signingEngine/threshold/webauthn';
import { DEFAULT_WAIT_STATUS } from '../../types/rpc';
import { ActionType, type ActionArgsWasm } from '../../types/actions';
import type { WebAuthnRegistrationCredential } from '../../types/webauthn';
import {
  buildThresholdWarmSessionRequestEnvelope,
  createThresholdWarmSessionPolicyDraft,
  hydrateThresholdWarmSessionFromRelay,
  requireThresholdEd25519WarmSessionKeyVersion,
  reconstructThresholdEd25519ClientBaseFromWarmSession,
  storeThresholdEd25519KeyMaterial,
} from '../thresholdWarmSessionBootstrap';
import {
  THRESHOLD_SESSION_POLICY_VERSION,
  generateThresholdSessionId,
} from '../../signingEngine/threshold/session/sessionPolicy';
import { listThresholdEcdsaProvisionTargets } from '../thresholdEcdsaProvisioning';
import {
  persistLinkDeviceThresholdEcdsaBootstrap,
  type PreparedLinkDeviceLinkedAccount,
  type PreparedLinkDeviceThresholdEcdsa,
} from '../evm/linkDeviceThresholdEcdsa';

type DeterministicKeysResultLike = {
  nearPublicKey?: string;
  credential?: WebAuthnRegistrationCredential | null;
};

function nowMs(): number {
  return Date.now();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseDeviceNumberFromIntentDigest(intentDigest: string, fallback: number): number {
  const raw = String(intentDigest || '').trim();
  if (!raw) return fallback;
  const parts = raw.split(':');
  if (parts.length < 2) return fallback;
  const n = Number(parts[parts.length - 1]);
  return Number.isFinite(n) && n >= 1 ? Math.floor(n) : fallback;
}

function coercePositiveInt(value: unknown, fallback: number): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return Math.max(1, Math.floor(fallback));
  return Math.floor(n);
}

function parsePreparedLinkedAccounts(raw: unknown): PreparedLinkDeviceLinkedAccount[] {
  if (!Array.isArray(raw)) return [];
  const out: PreparedLinkDeviceLinkedAccount[] = [];
  for (const value of raw) {
    if (!isObject(value)) continue;
    const chain = String(value.chain || '')
      .trim()
      .toLowerCase();
    const chainIdKey = String(value.chainIdKey || '')
      .trim()
      .toLowerCase();
    const accountAddress = String(value.accountAddress || '').trim();
    const accountModel = String(value.accountModel || '').trim();
    const chainId = Number(value.chainId);
    if ((chain !== 'evm' && chain !== 'tempo') || !chainIdKey || !accountAddress) continue;
    if (!Number.isFinite(chainId) || chainId <= 0) continue;
    if (accountModel !== 'erc4337' && accountModel !== 'tempo-native') continue;
    out.push({
      chain,
      chainIdKey,
      accountAddress,
      chainId: Math.floor(chainId),
      accountModel,
      ...(typeof value.factory === 'string' && value.factory.trim()
        ? { factory: value.factory.trim() }
        : {}),
      ...(typeof value.entryPoint === 'string' && value.entryPoint.trim()
        ? { entryPoint: value.entryPoint.trim() }
        : {}),
      ...(typeof value.salt === 'string' && value.salt.trim() ? { salt: value.salt.trim() } : {}),
      ...(typeof value.counterfactualAddress === 'string' && value.counterfactualAddress.trim()
        ? { counterfactualAddress: value.counterfactualAddress.trim() }
        : {}),
    });
  }
  return out;
}

// Lazy-load QRCode to keep it an optional peer and reduce baseline bundle size.
async function generateQRCodeDataURL(data: string): Promise<string> {
  const mod: unknown = await import('qrcode');
  const qrcodeLike = isObject(mod) && 'default' in mod ? (mod.default as unknown) : mod;
  if (!isObject(qrcodeLike) || typeof qrcodeLike.toDataURL !== 'function') {
    throw new Error('QRCode generation unavailable (missing qrcode.toDataURL)');
  }
  return await (
    qrcodeLike.toDataURL as (input: string, opts: Record<string, unknown>) => Promise<string>
  )(data, {
    width: 256,
    margin: 2,
    color: { dark: '#000000', light: '#ffffff' },
    errorCorrectionLevel: 'M',
  });
}

/**
 * Device linking flow class.
 *
 * This implementation keeps the local persistence guarantees used by regressions/tests
 * (store authenticator + user data so the account is immediately signable on the new device).
 */
export class LinkDeviceFlow {
  private context: PasskeyManagerContext;
  private options: StartDevice2LinkingFlowArgs;
  // Keep as a normal TS-private field (not #private) so existing runtime tests can patch it.
  private session: DeviceLinkingSession | null = null;
  private error?: Error;
  private cancelled = false;
  private completionInFlight: Promise<void> | null = null;

  constructor(context: PasskeyManagerContext, options: StartDevice2LinkingFlowArgs) {
    this.context = context;
    this.options = options;
  }

  private safeOnEvent(ev: DeviceLinkingEventPayload): void {
    try {
      this.options?.options?.onEvent?.(ev as DeviceLinkingSSEEvent);
    } catch {
      // ignore
    }
  }

  private handleError(err: unknown): void {
    const e = err instanceof Error ? err : new Error(String(err || 'Unknown error'));
    this.error = e;
    this.session = this.session
      ? { ...this.session, phase: DeviceLinkingPhase.DEVICE_LINKING_ERROR }
      : null;
    this.safeOnEvent({
      step: 0,
      phase: DeviceLinkingPhase.DEVICE_LINKING_ERROR,
      status: DeviceLinkingStatus.ERROR,
      message: e.message,
      error: e.message,
    });
    try {
      this.options?.options?.onError?.(e);
    } catch {}
  }

  private async fetchClaimedSessionFromRelay(
    sessionId: string,
  ): Promise<{ accountId: string; deviceNumber?: number } | null> {
    const relayerUrl = stripTrailingSlashes(
      String(this.context?.configs?.network.relayer?.url || '').trim(),
    );
    if (!relayerUrl) {
      console.debug('[LinkDeviceFlow] relay polling skipped (missing relayer url)', { sessionId });
      return null;
    }
    const url = joinNormalizedUrl(
      relayerUrl,
      `/link-device/session/${encodeURIComponent(sessionId)}`,
    );
    const resp = await fetch(url, { method: 'GET' });
    if (!resp.ok) {
      console.debug('[LinkDeviceFlow] relay poll response not ok', {
        sessionId,
        url,
        status: resp.status,
      });
      return null;
    }
    const json: unknown = await resp.json().catch(() => ({}));
    const body = isObject(json) ? json : {};
    if (body.ok !== true) {
      console.debug('[LinkDeviceFlow] relay poll response not ok=true', { sessionId, url, body });
      return null;
    }
    const session = isObject(body.session) ? body.session : {};
    const claimedAccountId = String(session.accountId || '').trim();
    const claimedPublicKey = String(session.device2PublicKey || '').trim();
    if (
      claimedPublicKey &&
      this.session?.nearPublicKey &&
      claimedPublicKey !== this.session.nearPublicKey
    ) {
      console.debug('[LinkDeviceFlow] relay poll publicKey mismatch', {
        sessionId,
        url,
        claimedPublicKey,
        expectedPublicKey: this.session.nearPublicKey,
      });
      return null;
    }
    const deviceNumberRaw = session.deviceNumber;
    const deviceNumberParsed = Number(deviceNumberRaw);
    const deviceNumber = Number.isFinite(deviceNumberParsed)
      ? Math.floor(deviceNumberParsed)
      : undefined;
    console.debug('[LinkDeviceFlow] relay poll ok', {
      sessionId,
      url,
      claimed: !!claimedAccountId,
      ...(claimedAccountId ? { accountId: claimedAccountId } : {}),
      ...(deviceNumber ? { deviceNumber } : {}),
    });
    return claimedAccountId
      ? { accountId: claimedAccountId, ...(deviceNumber ? { deviceNumber } : {}) }
      : null;
  }

  private async registerSessionOnRelay(
    sessionId: string,
    device2PublicKey: string,
    expiresAtMs: number,
  ): Promise<void> {
    const relayerUrl = stripTrailingSlashes(
      String(this.context?.configs?.network.relayer?.url || '').trim(),
    );
    if (!relayerUrl) return;
    try {
      const resp = await fetch(joinNormalizedUrl(relayerUrl, '/link-device/session'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: sessionId,
          device2_public_key: device2PublicKey,
          expires_at_ms: expiresAtMs,
        }),
      });
      const json: unknown = await resp.json().catch(() => ({}));
      const body = isObject(json) ? json : {};
      if (!resp.ok || body.ok !== true) {
        const message = typeof body.message === 'string' ? body.message : `HTTP ${resp.status}`;
        console.warn('[link-device] session register failed:', message);
      } else {
        console.debug('[LinkDeviceFlow] session registered on relay', {
          sessionId,
          device2PublicKey,
          expiresAtMs,
        });
      }
    } catch (err) {
      console.warn('[link-device] session register error:', err);
    }
  }

  private async waitForClaimAndComplete(): Promise<void> {
    const pollMs = DEVICE_LINKING_CONFIG.TIMEOUTS.POLLING_INTERVAL_MS;
    let announced = false;
    let attempt = 0;

    while (!this.cancelled) {
      const session = this.session;
      if (!session?.sessionId) return;
      if (Date.now() > session.expiresAt) {
        throw new Error('Device linking session expired; regenerate the QR code and try again');
      }

      if (!announced) {
        announced = true;
        this.safeOnEvent({
          step: 4,
          phase: DeviceLinkingPhase.STEP_4_POLLING,
          status: DeviceLinkingStatus.PROGRESS,
          message: 'Waiting for Device1 to scan and authorize…',
        });
      }

      // Poll relay for a claimed session (Device1 posts accountId after AddKey).
      attempt++;
      if (attempt <= 3 || attempt % 10 === 0) {
        console.debug('[LinkDeviceFlow] polling relay for claim', {
          sessionId: session.sessionId,
          attempt,
          pollMs,
        });
      }
      let claimed: { accountId: string; deviceNumber?: number } | null = null;
      try {
        claimed = await this.fetchClaimedSessionFromRelay(session.sessionId);
      } catch (e) {
        console.debug('[LinkDeviceFlow] relay poll threw', {
          sessionId: session.sessionId,
          error: errorMessage(e),
        });
        claimed = null;
      }
      if (claimed?.accountId) {
        const accountId = toAccountId(claimed.accountId);
        const deviceNumber = Number.isFinite(claimed.deviceNumber)
          ? claimed.deviceNumber
          : session.deviceNumber;
        console.debug('[LinkDeviceFlow] claim detected; starting completion', {
          sessionId: session.sessionId,
          accountId: String(accountId),
          ...(deviceNumber ? { deviceNumber } : {}),
        });
        this.session = {
          ...session,
          accountId,
          ...(deviceNumber ? { deviceNumber } : {}),
          phase: DeviceLinkingPhase.STEP_5_ADDKEY_DETECTED,
        };
        this.safeOnEvent({
          step: 5,
          phase: DeviceLinkingPhase.STEP_5_ADDKEY_DETECTED,
          status: DeviceLinkingStatus.PROGRESS,
          message: `Linked to ${String(accountId)}; finishing setup…`,
        });
        // Important: don't swallow completion errors; surface them to the caller so UI can show a failure.
        await this.completeLinking();
        console.debug('[LinkDeviceFlow] completion finished', {
          sessionId: session.sessionId,
          accountId: String(accountId),
        });
        return;
      }

      await sleep(pollMs);
    }
  }

  private async completeLinking(): Promise<void> {
    if (this.cancelled) return;
    const session = this.session;
    if (!session?.accountId) throw new Error('LinkDeviceFlow: missing accountId for completion');

    console.debug('[LinkDeviceFlow] completeLinking start', {
      sessionId: session.sessionId,
      accountId: String(session.accountId),
      deviceNumber: session.deviceNumber,
    });

    const nearAccountId = toAccountId(String(session.accountId));
    const relayerUrl = String(this.context?.configs?.network.relayer?.url || '').trim();
    if (!relayerUrl) throw new Error('Missing relayer url (configs.network.relayer.url)');
    if (!session.tempPrivateKey) {
      throw new Error('LinkDeviceFlow: missing temporary private key for completion');
    }

    const rpId = this.context.signingEngine.getRpId();
    if (!rpId) throw new Error('Missing rpId for link-device flow');

    const deviceNumberHint = coerceDeviceNumber(
      session.deviceNumber ?? this.options?.deviceNumber ?? 2,
    );

    this.session = {
      ...session,
      accountId: nearAccountId,
      deviceNumber: deviceNumberHint,
      phase: DeviceLinkingPhase.STEP_6_REGISTRATION,
    };
    this.safeOnEvent({
      step: 6,
      phase: DeviceLinkingPhase.STEP_6_REGISTRATION,
      status: DeviceLinkingStatus.PROGRESS,
      message: 'Creating passkey for linked device…',
    });

    const confirm = await this.context.signingEngine.requestRegistrationCredentialConfirmation({
      nearAccountId,
      deviceNumber: deviceNumberHint,
      confirmerText: this.options?.options?.confirmerText,
      confirmationConfigOverride: this.options?.options?.confirmationConfig,
    });
    const credential = confirm.credential;
    const resolvedDeviceNumber = parseDeviceNumberFromIntentDigest(
      confirm.intentDigest,
      deviceNumberHint,
    );

    const thresholdWarmPolicy = createThresholdWarmSessionPolicyDraft(this.context);
    if (!thresholdWarmPolicy) {
      throw new Error('Threshold warm-session defaults are disabled for link-device');
    }
    const thresholdWarmSessionRequest = buildThresholdWarmSessionRequestEnvelope({
      nearAccountId: String(nearAccountId),
      rpId,
      requestedPolicy: thresholdWarmPolicy,
    });
    const thresholdEcdsaProvisionTargets = listThresholdEcdsaProvisionTargets(
      this.context.configs.signing.thresholdEcdsa.provisioningDefaults,
    );
    const thresholdEcdsaPrimaryProvisionTarget = thresholdEcdsaProvisionTargets[0] || null;
    let thresholdEcdsaClientRootShare32B64u: string | null = null;
    let thresholdEcdsaSessionPolicy: {
      version: 'threshold_session_v1';
      userId: string;
      rpId: string;
      sessionId: string;
      participantIds?: number[];
      ttlMs: number;
      remainingUses: number;
    } | null = null;
    if (thresholdEcdsaPrimaryProvisionTarget) {
      thresholdEcdsaClientRootShare32B64u = String(
        getPrfFirstB64uFromCredential(credential) || '',
      ).trim();
      if (!thresholdEcdsaClientRootShare32B64u) {
        throw new Error('Failed to derive threshold secp256k1 client root share');
      }
      if (thresholdEcdsaPrimaryProvisionTarget.options.signingSession.kind !== 'jwt') {
        throw new Error('Threshold ECDSA link-device bootstrap requires sessionKind=jwt');
      }
      thresholdEcdsaSessionPolicy = {
        version: THRESHOLD_SESSION_POLICY_VERSION,
        userId: String(nearAccountId),
        rpId,
        sessionId: generateThresholdSessionId(),
        participantIds: [...thresholdEcdsaPrimaryProvisionTarget.options.participantIds],
        ttlMs: coercePositiveInt(
          thresholdEcdsaPrimaryProvisionTarget.options.signingSession.ttlMs,
          24 * 60 * 60 * 1000,
        ),
        remainingUses: coercePositiveInt(
          thresholdEcdsaPrimaryProvisionTarget.options.signingSession.remainingUses,
          10_000,
        ),
      };
    }

    const credentialForRelay = redactCredentialExtensionOutputs(
      normalizeRegistrationCredential(credential),
    );
    const prepareResp = await fetch(joinNormalizedUrl(relayerUrl, '/link-device/prepare'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        account_id: String(nearAccountId),
        ...(this.session?.sessionId ? { session_id: this.session.sessionId } : {}),
        device_number: resolvedDeviceNumber,
        threshold_ed25519: thresholdWarmSessionRequest,
        ...(thresholdEcdsaClientRootShare32B64u && thresholdEcdsaSessionPolicy
          ? {
              threshold_ecdsa: {
                client_root_share32_b64u: thresholdEcdsaClientRootShare32B64u,
                session_policy: thresholdEcdsaSessionPolicy,
                session_kind: 'jwt',
              },
            }
          : {}),
        rp_id: rpId,
        webauthn_registration: credentialForRelay,
      }),
    });
    const prepareJson: unknown = await prepareResp.json().catch(() => ({}));
    const prepareObj = isObject(prepareJson) ? prepareJson : {};
    const prepareOk = prepareObj.ok === true;
    const prepareMessage = typeof prepareObj.message === 'string' ? prepareObj.message : '';
    const prepareError = typeof prepareObj.error === 'string' ? prepareObj.error : '';
    if (!prepareResp.ok || !prepareOk) {
      throw new Error(
        prepareMessage || prepareError || `link-device/prepare failed (HTTP ${prepareResp.status})`,
      );
    }

    const thresholdSection = isObject(prepareObj.thresholdEd25519)
      ? prepareObj.thresholdEd25519
      : {};
    const thresholdPublicKey = ensureEd25519Prefix(String(thresholdSection.publicKey || '').trim());
    const relayerKeyId = String(thresholdSection.relayerKeyId || '').trim();
    if (!thresholdPublicKey || !relayerKeyId) {
      throw new Error('link-device/prepare returned incomplete threshold key material');
    }
    const thresholdSession = isObject(thresholdSection.session) ? thresholdSection.session : null;
    if (!thresholdSession) {
      throw new Error('link-device/prepare did not return threshold session bootstrap data');
    }
    const credentialIdB64u = String(prepareObj.credentialIdB64u || '').trim();
    const linkedAccounts = parsePreparedLinkedAccounts(prepareObj.linkedAccounts);
    const thresholdEcdsaSection: PreparedLinkDeviceThresholdEcdsa | null = isObject(
      prepareObj.thresholdEcdsa,
    )
      ? {
          ecdsaThresholdKeyId: String(prepareObj.thresholdEcdsa.ecdsaThresholdKeyId || '').trim(),
          clientVerifyingShareB64u: String(
            prepareObj.thresholdEcdsa.clientVerifyingShareB64u || '',
          ).trim(),
          clientAdditiveShare32B64u: String(
            prepareObj.thresholdEcdsa.clientAdditiveShare32B64u || '',
          ).trim(),
          relayerKeyId: String(prepareObj.thresholdEcdsa.relayerKeyId || '').trim(),
          thresholdEcdsaPublicKeyB64u: String(prepareObj.thresholdEcdsa.thresholdEcdsaPublicKeyB64u || '').trim(),
          ethereumAddress: String(prepareObj.thresholdEcdsa.ethereumAddress || '').trim(),
          relayerVerifyingShareB64u: String(
            prepareObj.thresholdEcdsa.relayerVerifyingShareB64u || '',
          ).trim(),
          ...(Array.isArray(prepareObj.thresholdEcdsa.participantIds)
            ? { participantIds: prepareObj.thresholdEcdsa.participantIds as number[] }
            : {}),
          ...(isObject(prepareObj.thresholdEcdsa.session)
            ? {
                session: prepareObj.thresholdEcdsa
                  .session as PreparedLinkDeviceThresholdEcdsa['session'],
              }
            : {}),
        }
      : null;

    this.safeOnEvent({
      step: 6,
      phase: DeviceLinkingPhase.STEP_6_REGISTRATION,
      status: DeviceLinkingStatus.PROGRESS,
      message: 'Activating linked device keys on-chain…',
    });

    const ephemeralPublicKey = ensureEd25519Prefix(String(session.nearPublicKey || '').trim());
    if (!ephemeralPublicKey) throw new Error('LinkDeviceFlow: missing ephemeral public key');

    console.debug('[LinkDeviceFlow] completing on-chain key swap', {
      sessionId: session.sessionId,
      accountId: String(nearAccountId),
      ephemeralPublicKey,
      thresholdPublicKey,
    });

    const actions: ActionArgsWasm[] = [
      {
        action_type: ActionType.AddKey,
        public_key: thresholdPublicKey,
        access_key: JSON.stringify({ nonce: 0, permission: { FullAccess: {} } }),
      },
      {
        action_type: ActionType.DeleteKey,
        public_key: ephemeralPublicKey,
      },
    ];

    // The AddKey propagation can take a moment; retry longer than default to avoid flakiness.
    const txContext = await this.fetchNonceBlockHashForKey(nearAccountId, ephemeralPublicKey, {
      attempts: 24,
      delayMs: 500,
      finality: 'optimistic',
    });
    const signed = await this.context.signingEngine.signTransactionWithKeyPair({
      nearPrivateKey: session.tempPrivateKey,
      signerAccountId: String(nearAccountId),
      receiverId: String(nearAccountId),
      nonce: txContext.nextNonce,
      blockHash: txContext.blockHash,
      actions,
    });
    await this.context.nearClient.sendTransaction(
      signed.signedTransaction,
      DEFAULT_WAIT_STATUS.linkDeviceSwapKey,
    );

    this.session = {
      ...session,
      accountId: nearAccountId,
      deviceNumber: resolvedDeviceNumber,
      credential,
      phase: DeviceLinkingPhase.STEP_6_REGISTRATION,
    };

    // Store authenticator + user data first to ensure profile/account mapping exists.
    await this.storeDeviceAuthenticator({ nearPublicKey: thresholdPublicKey, credential });

    const { keyVersion: thresholdKeyVersion } = requireThresholdEd25519WarmSessionKeyVersion(
      thresholdSection,
      'link-device/prepare',
    );
    await storeThresholdEd25519KeyMaterial({
      nearAccountId,
      deviceNumber: resolvedDeviceNumber,
      publicKey: thresholdPublicKey,
      relayerKeyId,
      keyVersion: thresholdKeyVersion,
      clientParticipantId: Number.isFinite(Number(thresholdSection.clientParticipantId))
        ? Math.floor(Number(thresholdSection.clientParticipantId))
        : null,
      relayerParticipantId: Number.isFinite(Number(thresholdSection.relayerParticipantId))
        ? Math.floor(Number(thresholdSection.relayerParticipantId))
        : null,
      relayerUrl,
      timestamp: Date.now(),
    });
    await hydrateThresholdWarmSessionFromRelay({
      context: this.context,
      nearAccountId,
      relayerUrl,
      rpId,
      relayerKeyId,
      credential,
      requestedPolicy: thresholdWarmPolicy,
      session: thresholdSession,
      participantIdsHint: Array.isArray(thresholdSection.participantIds)
        ? thresholdSection.participantIds
        : undefined,
    });
    await reconstructThresholdEd25519ClientBaseFromWarmSession({
      context: this.context,
      credential,
      nearAccountId,
      relayerUrl,
      relayerKeyId,
      session: thresholdSession,
      keyVersion: thresholdKeyVersion,
      participantIdsHint: Array.isArray(thresholdSection.participantIds)
        ? thresholdSection.participantIds
        : undefined,
    });
    if (
      thresholdEcdsaSection &&
      linkedAccounts.length > 0
    ) {
      await persistLinkDeviceThresholdEcdsaBootstrap({
        indexedDB: IndexedDBManager,
        signingEngine: this.context.signingEngine,
        nearAccountId,
        relayerUrl,
        deviceNumber: resolvedDeviceNumber,
        rpId,
        credentialIdB64u,
        thresholdEcdsa: thresholdEcdsaSection,
        linkedAccounts,
      });
    }

    // Auto-login: set last-user + warm login state so the device is immediately usable.
    await this.attemptAutoLogin({ accountId: nearAccountId, deviceNumber: resolvedDeviceNumber });

    if (this.session?.tempPrivateKey) {
      this.session.tempPrivateKey = '';
    }

    if (this.cancelled) return;
    this.session = this.session
      ? { ...this.session, phase: DeviceLinkingPhase.STEP_7_LINKING_COMPLETE }
      : null;
    this.safeOnEvent({
      step: 7,
      phase: DeviceLinkingPhase.STEP_7_LINKING_COMPLETE,
      status: DeviceLinkingStatus.SUCCESS,
      message: 'Device linking completed',
    });
  }

  /**
   * Device2: Attempt auto-login after successful device linking.
   *
   * Note: In the lite-signer refactor we no longer do UserConfirm WebAuthn verification/unlocks here.
   * Auto-login is simply: set last-user pointer + initialize current user state for signing.
   */
  private async attemptAutoLogin(input: {
    accountId: string;
    deviceNumber: number;
  }): Promise<void> {
    try {
      if (this.cancelled) return;
      const nearAccountId = toAccountId(String(input.accountId));
      const deviceNumber = coerceDeviceNumber(input.deviceNumber);

      console.debug('[LinkDeviceFlow] auto-login start', {
        accountId: String(nearAccountId),
        deviceNumber,
      });
      this.safeOnEvent({
        step: 8,
        phase: DeviceLinkingPhase.STEP_8_AUTO_LOGIN,
        status: DeviceLinkingStatus.PROGRESS,
        message: 'Logging in…',
      });

      const restored = await restoreLocalLoginState({
        context: this.context,
        nearAccountId,
        deviceNumber,
      });
      if (!restored.isLoggedIn) {
        throw new Error(`Auto-login did not mark ${String(nearAccountId)} as logged in`);
      }

      this.safeOnEvent({
        step: 8,
        phase: DeviceLinkingPhase.STEP_8_AUTO_LOGIN,
        status: DeviceLinkingStatus.SUCCESS,
        message: `Welcome ${String(nearAccountId)}`,
      });
      console.debug('[LinkDeviceFlow] auto-login complete', {
        accountId: String(nearAccountId),
        deviceNumber,
      });
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Auto-login failed after device linking';
      console.warn('[LinkDeviceFlow] auto-login failed:', e);
      // Don't fail linking if auto-login fails; user can manually login.
      this.safeOnEvent({
        step: 0,
        phase: DeviceLinkingPhase.LOGIN_ERROR,
        status: DeviceLinkingStatus.ERROR,
        message: msg,
        error: msg,
      });
    }
  }

  private async fetchNonceBlockHashForKey(
    nearAccountId: string,
    publicKey: string,
    opts?: { attempts?: number; delayMs?: number; finality?: 'optimistic' | 'final' },
  ): Promise<{ nextNonce: string; blockHash: string }> {
    const attempts = Math.max(1, Math.floor(opts?.attempts ?? 6));
    const delayMs = Math.max(50, Math.floor(opts?.delayMs ?? 250));
    const finality = opts?.finality ?? 'final';

    const pk = ensureEd25519Prefix(publicKey);
    if (!pk) throw new Error('Missing publicKey for tx context fetch');

    let lastErr: unknown = null;
    for (let i = 0; i < attempts; i++) {
      try {
        const [accessKey, block] = await Promise.all([
          this.context.nearClient.viewAccessKey(String(nearAccountId), pk),
          this.context.nearClient.viewBlock({ finality }),
        ]);
        const nextNonce = (BigInt(accessKey.nonce) + 1n).toString();
        const blockHash = String(block?.header?.hash || '').trim();
        if (!blockHash) throw new Error('Missing block hash from RPC');
        return { nextNonce, blockHash };
      } catch (e: unknown) {
        lastErr = e;
      }
      if (i < attempts - 1) {
        await new Promise((res) => setTimeout(res, delayMs));
      }
    }
    throw new Error(
      `Failed to fetch nonce/blockHash for ${nearAccountId}: ${errorMessage(lastErr) || String(lastErr || '')}`,
    );
  }

  /**
   * Device2: Generate a QR payload for device1 to scan.
   *
   * Flow:
   * - Generate an ephemeral NEAR keypair (no accountId required).
   * - Render QR code for Device1 to scan + AddKey on-chain.
   * - Poll relay for mapping { sessionId -> accountId } to finish linking.
   */
  async generateQR(): Promise<{ qrData: DeviceLinkingQRData; qrCodeDataURL: string }> {
    try {
      const sessionId =
        typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
          ? `ldsess-${crypto.randomUUID()}`
          : `ldsess-${Date.now()}-${Math.random().toString(16).slice(2)}`;

      const deviceNumber = coerceDeviceNumber(this.options?.deviceNumber ?? 2);
      const tempKeypair = await this.context.signingEngine.generateEphemeralNearKeypair();

      this.session = {
        sessionId,
        accountId: null,
        deviceNumber,
        nearPublicKey: tempKeypair.publicKey,
        credential: null,
        tempPrivateKey: tempKeypair.privateKey,
        phase: DeviceLinkingPhase.STEP_1_QR_CODE_GENERATED,
        createdAt: nowMs(),
        expiresAt: nowMs() + DEVICE_LINKING_CONFIG.TIMEOUTS.SESSION_EXPIRATION_MS,
      };

      await this.registerSessionOnRelay(sessionId, tempKeypair.publicKey, this.session.expiresAt);

      const qrData: DeviceLinkingQRData = {
        sessionId,
        device2PublicKey: tempKeypair.publicKey,
        timestamp: nowMs(),
        version: 'v3',
      };

      const qrCodeDataURL = await generateQRCodeDataURL(JSON.stringify(qrData));

      this.safeOnEvent({
        step: 1,
        phase: DeviceLinkingPhase.STEP_1_QR_CODE_GENERATED,
        status: DeviceLinkingStatus.SUCCESS,
        message: 'Device linking QR generated',
      });

      if (!this.cancelled) {
        this.completionInFlight = this.waitForClaimAndComplete().catch((e) => this.handleError(e));
      }

      return { qrData, qrCodeDataURL };
    } catch (err: unknown) {
      const e = err instanceof Error ? err : new Error(String(err || 'Unknown error'));
      this.handleError(e);
      throw e;
    }
  }

  /**
   * Store authenticator + user data for the linked device so the account is immediately usable.
   *
   * This method is intentionally private in TS, but must remain callable at runtime for
   * regression tests (see `linkDevice.immediateSign.test.ts`).
   */
  private async storeDeviceAuthenticator(
    deterministicKeysResult: DeterministicKeysResultLike,
  ): Promise<void> {
    if (!this.session) {
      throw new Error('LinkDeviceFlow: missing session (cannot store device authenticator)');
    }
    const accountIdRaw = this.session.accountId;
    const deviceNumberRaw = this.session.deviceNumber;
    const credential = deterministicKeysResult.credential ?? this.session.credential;
    const nearPublicKey = String(
      deterministicKeysResult.nearPublicKey ?? this.session.nearPublicKey ?? '',
    ).trim();

    const nearAccountId = toAccountId(String(accountIdRaw || '').trim());
    const deviceNumber = coerceDeviceNumber(deviceNumberRaw);
    if (!credential) throw new Error('LinkDeviceFlow: missing credential');
    if (!nearPublicKey) throw new Error('LinkDeviceFlow: missing nearPublicKey');

    const credentialId = String(credential.rawId || credential.id || '').trim();
    const attestationObject = String(credential.response?.attestationObject || '').trim();
    if (!credentialId) throw new Error('LinkDeviceFlow: missing credential.rawId');
    if (!attestationObject)
      throw new Error('LinkDeviceFlow: missing credential.response.attestationObject');

    const credentialPublicKey =
      await this.context.signingEngine.extractCosePublicKey(attestationObject);

    // 1) Store user data first (also sets last-user/profile pointer).
    await this.context.signingEngine.storeUserData({
      nearAccountId,
      deviceNumber,
      operationalPublicKey: nearPublicKey,
      lastUpdated: nowMs(),
      passkeyCredential: {
        id: String(credential.id || credentialId),
        rawId: credentialId,
      },
      version: 2,
    });

    // 2) Store authenticator once profile/account mapping exists.
    await this.context.signingEngine.storeAuthenticator({
      nearAccountId,
      credentialId,
      credentialPublicKey,
      transports: Array.isArray(credential.response?.transports)
        ? credential.response.transports
        : [],
      name: `Passkey for ${nearAccountId}`,
      registered: new Date().toISOString(),
      syncedAt: new Date().toISOString(),
      deviceNumber,
    });
  }

  getState(): {
    phase: DeviceLinkingPhase | undefined;
    session: DeviceLinkingSession | null;
    error: Error | undefined;
  } {
    return {
      phase: this.session?.phase,
      session: this.session,
      error: this.error,
    };
  }

  cancel(): void {
    this.cancelled = true;
    this.session = this.session
      ? { ...this.session, phase: DeviceLinkingPhase.DEVICE_LINKING_ERROR }
      : null;
  }

  reset(): void {
    this.cancelled = false;
    this.error = undefined;
    this.session = null;
  }
}

export type DeviceLinkingDomainDeps = {
  getContext: () => PasskeyManagerContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
};

export class DeviceLinkingDomain {
  private readonly getContext: () => PasskeyManagerContext;
  private readonly walletIframe: Pick<
    WalletIframeCoordinator,
    'shouldUseWalletIframe' | 'requireRouter'
  >;
  private activeDeviceLinkFlow: LinkDeviceFlow | null = null;

  constructor(deps: DeviceLinkingDomainDeps) {
    this.getContext = deps.getContext;
    this.walletIframe = deps.walletIframe;
  }

  async startDevice2LinkingFlow(
    args: StartDevice2LinkingFlowArgs,
  ): Promise<StartDevice2LinkingFlowResults> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter();
      return await router.startDevice2LinkingFlow(args);
    }

    this.activeDeviceLinkFlow = new LinkDeviceFlow(this.getContext(), args);
    return await this.activeDeviceLinkFlow.generateQR();
  }

  async stopDevice2LinkingFlow(): Promise<void> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter();
      await router.stopDevice2LinkingFlow();
      return;
    }

    this.activeDeviceLinkFlow?.cancel();
    this.activeDeviceLinkFlow = null;
  }

  async linkDeviceWithScannedQRData(
    qrData: DeviceLinkingQRData,
    options: ScanAndLinkDeviceOptionsDevice1,
  ): Promise<LinkDeviceResult> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter();
      return await router.linkDeviceWithScannedQRData({
        qrData,
        fundingAmount: options.fundingAmount,
        options: {
          onEvent: options.onEvent,
          ...(options.confirmerText ? { confirmerText: options.confirmerText } : {}),
          ...(options.confirmationConfig ? { confirmationConfig: options.confirmationConfig } : {}),
        },
      });
    }

    return await linkDeviceWithScannedQRDataDevice1(this.getContext(), qrData, options);
  }
}

export async function linkDeviceErrorResult(message: string, err?: unknown): Promise<never> {
  const msg = err ? `${message}: ${errorMessage(err) || 'unknown error'}` : message;
  throw new Error(msg);
}

type DeviceLinkingEventPayload = {
  step: number;
  phase: DeviceLinkingPhase;
  status: DeviceLinkingStatus;
  message: string;
  error?: string;
  data?: Record<string, unknown>;
  [key: string]: unknown;
};
