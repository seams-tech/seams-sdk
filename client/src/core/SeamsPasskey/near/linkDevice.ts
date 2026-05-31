import type { PasskeyManagerContext } from '../index';
import type {
  DeviceLinkingQRData,
  LinkDeviceResult,
  DeviceLinkingSession,
  ScanAndLinkDeviceOptionsDevice1,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
} from '../../types/linkDevice';
import {
  createLinkDeviceFlowEvent,
  LinkDeviceEventPhase,
  type CreateLinkDeviceFlowEventInput,
} from '../../types/sdkSentEvents';
import { toAccountId } from '../../types/accountIds';
import { coerceSignerSlot } from '@shared/utils/signerSlot';
import { errorMessage } from '@shared/utils/errors';
import { joinNormalizedUrl, stripTrailingSlashes } from '@shared/utils/normalize';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { IndexedDBManager } from '../../indexedDB';
import { ensureEd25519Prefix, isObject } from '@shared/utils/validation';
import type { WalletIframeCoordinator } from '../walletIframeCoordinator';
import { restoreLocalLoginState } from '../restoreLocalLoginState';
import { linkDeviceWithScannedQRData as linkDeviceWithScannedQRDataDevice1 } from '../scanDevice';
import { DEVICE_LINKING_CONFIG } from '../../../config';
import { normalizeRegistrationCredential } from '../../signingEngine/webauthnAuth/credentials/helpers';
import { redactCredentialExtensionOutputs } from '../../signingEngine/webauthnAuth/credentials/credentialExtensions';
import { derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential } from '../../signingEngine/session/passkey/ecdsaClientRoot';
import { DEFAULT_WAIT_STATUS } from '../../types/rpc';
import { ActionType, type ActionArgsWasm } from '../../types/actions';
import type { WebAuthnRegistrationCredential } from '../../types/webauthn';
import { THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1 } from '@shared/threshold/secp256k1';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  buildThresholdWarmSessionRequestEnvelope,
  createThresholdWarmSessionPolicyDraft,
  hydrateThresholdWarmSessionFromRelay,
  requireThresholdEd25519WarmSessionKeyVersion,
  reconstructThresholdEd25519ClientBaseFromWarmSession,
  storeThresholdEd25519KeyMaterial,
} from '../thresholdWarmSessionBootstrap';
import { listThresholdEcdsaProvisionTargets } from '../thresholdEcdsaProvisioning';
import { normalizeThresholdRuntimePolicyScope } from '../../signingEngine/threshold/sessionPolicy';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPrepareContext,
  WalletRegistrationEcdsaWalletKey,
} from '../../rpcClients/relayer/walletRegistration';
import {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromRequest,
  type NearAccountRef,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

type DeterministicKeysResultLike = {
  nearPublicKey?: string;
  credential?: WebAuthnRegistrationCredential | null;
};

type EmitLinkDeviceEventInput = Omit<CreateLinkDeviceFlowEventInput, 'flowId' | 'accountId'> & {
  accountId?: string;
};

function nowMs(): number {
  return Date.now();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseSignerSlotFromIntentDigest(intentDigest: string, fallback: number): number {
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

function requireLinkDeviceString(value: unknown, field: string): string {
  const text = String(value || '').trim();
  if (!text) throw new Error(`link-device ECDSA response missing ${field}`);
  return text;
}

function parseLinkDeviceEcdsaPrepare(value: unknown): WalletRegistrationEcdsaPrepareContext {
  if (!isObject(value)) throw new Error('link-device/prepare returned invalid ECDSA prepare data');
  const participantIds = Array.isArray(value.participantIds)
    ? value.participantIds.map((participantId) => Number(participantId))
    : [];
  if (
    participantIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || participantId <= 0,
    )
  ) {
    throw new Error('link-device/prepare returned invalid ECDSA participant ids');
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(value.runtimePolicyScope);
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: requireLinkDeviceString(value.walletId, 'walletId'),
    rpId: requireLinkDeviceString(value.rpId, 'rpId'),
    ecdsaThresholdKeyId: requireLinkDeviceString(value.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
    signingRootId: requireLinkDeviceString(value.signingRootId, 'signingRootId'),
    signingRootVersion: requireLinkDeviceString(value.signingRootVersion, 'signingRootVersion'),
    keyScope: 'evm-family',
    relayerKeyId: requireLinkDeviceString(value.relayerKeyId, 'relayerKeyId'),
    requestId: requireLinkDeviceString(value.requestId, 'requestId'),
    sessionId: requireLinkDeviceString(value.sessionId, 'sessionId'),
    walletSigningSessionId: requireLinkDeviceString(
      value.walletSigningSessionId,
      'walletSigningSessionId',
    ),
    ttlMs: coercePositiveInt(value.ttlMs, 1),
    remainingUses: coercePositiveInt(value.remainingUses, 1),
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
}

function parseLinkDeviceEcdsaWalletKeys(value: unknown): WalletRegistrationEcdsaWalletKey[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('link-device/ecdsa/respond returned no ECDSA wallet keys');
  }
  return value.map((raw) => {
    if (!isObject(raw)) throw new Error('link-device/ecdsa/respond returned invalid wallet key');
    const chainTargetRaw = isObject(raw.chainTarget) ? raw.chainTarget : null;
    if (!chainTargetRaw) {
      throw new Error('link-device/ecdsa/respond returned wallet key without chain target');
    }
    const chainTarget: ThresholdEcdsaChainTarget =
      thresholdEcdsaChainTargetFromRequest(chainTargetRaw);
    const participantIds = Array.isArray(raw.participantIds)
      ? raw.participantIds.map((participantId) => Number(participantId))
      : [];
    if (
      participantIds.length === 0 ||
      participantIds.some(
        (participantId) => !Number.isSafeInteger(participantId) || participantId <= 0,
      )
    ) {
      throw new Error('link-device/ecdsa/respond returned invalid wallet key participant ids');
    }
    return {
      keyScope: 'evm-family',
      chainTarget,
      walletId: requireLinkDeviceString(raw.walletId, 'walletId'),
      rpId: requireLinkDeviceString(raw.rpId, 'rpId'),
      keyHandle: requireLinkDeviceString(raw.keyHandle, 'keyHandle'),
      ecdsaThresholdKeyId: requireLinkDeviceString(raw.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
      signingRootId: requireLinkDeviceString(raw.signingRootId, 'signingRootId'),
      signingRootVersion: requireLinkDeviceString(raw.signingRootVersion, 'signingRootVersion'),
      thresholdEcdsaPublicKeyB64u: requireLinkDeviceString(
        raw.thresholdEcdsaPublicKeyB64u,
        'thresholdEcdsaPublicKeyB64u',
      ),
      thresholdOwnerAddress: requireLinkDeviceString(
        raw.thresholdOwnerAddress,
        'thresholdOwnerAddress',
      ),
      relayerKeyId: requireLinkDeviceString(raw.relayerKeyId, 'relayerKeyId'),
      relayerVerifyingShareB64u: requireLinkDeviceString(
        raw.relayerVerifyingShareB64u,
        'relayerVerifyingShareB64u',
      ),
      participantIds,
    };
  });
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

  private flowId(): string {
    const sessionId = String(this.session?.sessionId || '').trim();
    return sessionId || `link-device:${this.session?.nearPublicKey || 'pending'}`;
  }

  private safeOnEvent(event: EmitLinkDeviceEventInput): void {
    try {
      const accountId = event.accountId ?? this.session?.accountId ?? undefined;
      this.options?.options?.onEvent?.(
        createLinkDeviceFlowEvent({
          flowId: this.flowId(),
          ...(accountId ? { accountId: String(accountId) } : {}),
          ...event,
        }),
      );
    } catch {
      // ignore
    }
  }

  private handleError(err: unknown): void {
    const e = err instanceof Error ? err : new Error(String(err || 'Unknown error'));
    this.error = e;
    this.session = this.session ? { ...this.session, phase: LinkDeviceEventPhase.FAILED } : null;
    this.safeOnEvent({
      phase: LinkDeviceEventPhase.FAILED,
      status: 'failed',
      message: e.message,
      interaction: {
        kind: 'passkey_create',
        overlay: 'hide',
      },
      error: {
        message: e.message,
      },
    });
    try {
      this.options?.options?.onError?.(e);
    } catch {}
  }

  private async fetchClaimedSessionFromRelay(
    sessionId: string,
  ): Promise<{ accountId: string; signerSlot?: number } | null> {
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
    const signerSlotRaw = session.signerSlot;
    const signerSlotParsed = Number(signerSlotRaw);
    const signerSlot = Number.isFinite(signerSlotParsed) ? Math.floor(signerSlotParsed) : undefined;
    console.debug('[LinkDeviceFlow] relay poll ok', {
      sessionId,
      url,
      claimed: !!claimedAccountId,
      ...(claimedAccountId ? { accountId: claimedAccountId } : {}),
      ...(signerSlot ? { signerSlot } : {}),
    });
    return claimedAccountId
      ? { accountId: claimedAccountId, ...(signerSlot ? { signerSlot } : {}) }
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
          phase: LinkDeviceEventPhase.STEP_01_QR_DISPLAYED,
          status: 'waiting_for_user',
          data: { role: 'display' },
          interaction: {
            kind: 'qr_display',
            overlay: 'hide',
          },
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
      let claimed: { accountId: string; signerSlot?: number } | null = null;
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
        const signerSlot = Number.isFinite(claimed.signerSlot)
          ? claimed.signerSlot
          : session.signerSlot;
        console.debug('[LinkDeviceFlow] claim detected; starting completion', {
          sessionId: session.sessionId,
          accountId: String(accountId),
          ...(signerSlot ? { signerSlot } : {}),
        });
        this.session = {
          ...session,
          accountId,
          ...(signerSlot ? { signerSlot } : {}),
          phase: LinkDeviceEventPhase.STEP_05_LINK_REQUEST_DETECTED,
        };
        this.safeOnEvent({
          phase: LinkDeviceEventPhase.STEP_05_LINK_REQUEST_DETECTED,
          status: 'succeeded',
          accountId: String(accountId),
          data: {
            role: 'display',
            signerSlot,
          },
          interaction: {
            kind: 'qr_display',
            overlay: 'hide',
          },
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
      signerSlot: session.signerSlot,
    });

    const nearAccountId = toAccountId(String(session.accountId));
    const nearAccount = nearAccountRefFromAccountId(nearAccountId);
    const relayerUrl = String(this.context?.configs?.network.relayer?.url || '').trim();
    if (!relayerUrl) throw new Error('Missing relayer url (configs.network.relayer.url)');
    if (!session.tempPrivateKey) {
      throw new Error('LinkDeviceFlow: missing temporary private key for completion');
    }

    const rpId = this.context.signingEngine.getRpId();
    if (!rpId) throw new Error('Missing rpId for link-device flow');

    const signerSlotHint = coerceSignerSlot(session.signerSlot ?? this.options?.signerSlot ?? 2);

    this.session = {
      ...session,
      accountId: nearAccountId,
      signerSlot: signerSlotHint,
      phase: LinkDeviceEventPhase.STEP_06_NEW_DEVICE_REGISTER_STARTED,
    };
    this.safeOnEvent({
      phase: LinkDeviceEventPhase.STEP_06_NEW_DEVICE_REGISTER_STARTED,
      status: 'waiting_for_user',
      accountId: String(nearAccountId),
      data: {
        role: 'display',
        signerSlot: signerSlotHint,
      },
      interaction: {
        kind: 'passkey_create',
        overlay: 'show',
      },
    });

    const confirm = await this.context.signingEngine.requestRegistrationCredentialConfirmation({
      nearAccountId,
      signerSlot: signerSlotHint,
      confirmerText: this.options?.options?.confirmerText,
      confirmationConfigOverride: this.options?.options?.confirmationConfig,
    });
    const credential = confirm.credential;
    const resolvedSignerSlot = parseSignerSlotFromIntentDigest(
      confirm.intentDigest,
      signerSlotHint,
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
    const ecdsaProvisionTargets = listThresholdEcdsaProvisionTargets({
      signerOptions: this.context.configs.signing.thresholdEcdsa.provisioningDefaults,
      chains: this.context.configs.network.chains,
    });
    const shouldPrepareEcdsa = Boolean(this.session?.sessionId && ecdsaProvisionTargets.length > 0);
    const clientRootShare32B64u = shouldPrepareEcdsa
      ? await derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential(credential)
      : '';
    if (shouldPrepareEcdsa && !clientRootShare32B64u) {
      throw new Error('Failed to derive Link Device ECDSA client root share from passkey');
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
        signer_slot: resolvedSignerSlot,
        threshold_ed25519: thresholdWarmSessionRequest,
        ...(shouldPrepareEcdsa
          ? {
              threshold_ecdsa_prepare: {
                chainTargets: ecdsaProvisionTargets.map((target) => target.chainTarget),
                participantIds: [...THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1.participantIds],
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
    const ecdsaSection = isObject(prepareObj.ecdsa) ? prepareObj.ecdsa : null;
    const ecdsaPrepare =
      shouldPrepareEcdsa && ecdsaSection ? parseLinkDeviceEcdsaPrepare(ecdsaSection.prepare) : null;
    if (shouldPrepareEcdsa && !ecdsaPrepare) {
      throw new Error('link-device/prepare did not return ECDSA prepare data');
    }
    this.safeOnEvent({
      phase: LinkDeviceEventPhase.STEP_04_LINK_REQUEST_SUBMITTED,
      status: 'running',
      accountId: String(nearAccountId),
      data: {
        role: 'display',
        signerSlot: resolvedSignerSlot,
      },
      interaction: {
        kind: 'passkey_create',
        overlay: 'hide',
      },
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
    const txContext = await this.fetchNonceBlockHashForKey({
      nearAccount,
      publicKey: ephemeralPublicKey,
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
      signerSlot: resolvedSignerSlot,
      credential,
      phase: LinkDeviceEventPhase.STEP_06_NEW_DEVICE_REGISTER_STARTED,
    };

    // Store authenticator + user data first to ensure profile/account mapping exists.
    await this.storeDeviceAuthenticator({ nearPublicKey: thresholdPublicKey, credential });

    const { keyVersion: thresholdKeyVersion } = requireThresholdEd25519WarmSessionKeyVersion(
      thresholdSection,
      'link-device/prepare',
    );
    await storeThresholdEd25519KeyMaterial({
      nearAccountId,
      signerSlot: resolvedSignerSlot,
      signerId: thresholdPublicKey,
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
    if (ecdsaPrepare && this.session?.sessionId) {
      const clientBootstrap: WalletRegistrationEcdsaClientBootstrap =
        await this.context.signingEngine.prepareWalletRegistrationEcdsaClientBootstrap({
          prepare: ecdsaPrepare,
          clientRootShare32B64u,
        });
      const ecdsaResp = await fetch(joinNormalizedUrl(relayerUrl, '/link-device/ecdsa/respond'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: this.session.sessionId,
          client_bootstrap: clientBootstrap,
        }),
      });
      const ecdsaJson: unknown = await ecdsaResp.json().catch(() => ({}));
      const ecdsaObj = isObject(ecdsaJson) ? ecdsaJson : {};
      if (!ecdsaResp.ok || ecdsaObj.ok !== true) {
        throw new Error(
          String(ecdsaObj.message || ecdsaObj.error || '') ||
            `link-device/ecdsa/respond failed (HTTP ${ecdsaResp.status})`,
        );
      }
      const ecdsaResult = isObject(ecdsaObj.ecdsa) ? ecdsaObj.ecdsa : {};
      const walletKeys = parseLinkDeviceEcdsaWalletKeys(ecdsaResult.walletKeys);
      await this.context.signingEngine.storeWalletEcdsaSignerRecords({
        walletId: walletIdFromString(String(nearAccountId)),
        walletKeys,
      });
    }
    // Auto-login: set last-user + warm login state so the device is immediately usable.
    await this.attemptAutoLogin({ nearAccount, signerSlot: resolvedSignerSlot });

    if (this.session?.tempPrivateKey) {
      this.session.tempPrivateKey = '';
    }

    if (this.cancelled) return;
    this.session = this.session
      ? { ...this.session, phase: LinkDeviceEventPhase.STEP_08_COMPLETED }
      : null;
    this.safeOnEvent({
      phase: LinkDeviceEventPhase.STEP_08_COMPLETED,
      status: 'succeeded',
      accountId: String(nearAccountId),
      data: {
        role: 'display',
        signerSlot: resolvedSignerSlot,
      },
    });
  }

  /**
   * Device2: Attempt auto-login after successful device linking.
   *
   * Note: In the lite-signer refactor we no longer do UserConfirm WebAuthn verification/unlocks here.
   * Auto-login is simply: set last-user pointer + initialize current user state for signing.
   */
  private async attemptAutoLogin(input: {
    nearAccount: NearAccountRef;
    signerSlot: number;
  }): Promise<void> {
    try {
      if (this.cancelled) return;
      const nearAccountId = input.nearAccount.accountId;
      const signerSlot = coerceSignerSlot(input.signerSlot);

      console.debug('[LinkDeviceFlow] auto-login start', {
        accountId: String(nearAccountId),
        signerSlot,
      });
      this.safeOnEvent({
        phase: LinkDeviceEventPhase.STEP_07_AUTO_UNLOCK_STARTED,
        status: 'running',
        accountId: String(nearAccountId),
        data: {
          role: 'display',
          signerSlot,
        },
      });

      const restored = await restoreLocalLoginState({
        context: this.context,
        nearAccountId,
        signerSlot,
      });
      if (!restored.isLoggedIn) {
        throw new Error(`Auto-login did not mark ${String(nearAccountId)} as logged in`);
      }

      this.safeOnEvent({
        phase: LinkDeviceEventPhase.STEP_07_AUTO_UNLOCK_SUCCEEDED,
        status: 'succeeded',
        accountId: String(nearAccountId),
        data: {
          role: 'display',
          signerSlot,
        },
      });
      console.debug('[LinkDeviceFlow] auto-login complete', {
        accountId: String(nearAccountId),
        signerSlot,
      });
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Auto-login failed after device linking';
      console.warn('[LinkDeviceFlow] auto-login failed:', e);
      // Don't fail linking if auto-login fails; user can manually login.
      this.safeOnEvent({
        phase: LinkDeviceEventPhase.STEP_07_AUTO_UNLOCK_STARTED,
        status: 'skipped',
        message: msg,
        accountId: String(input.nearAccount.accountId),
        data: {
          role: 'display',
          autoUnlockFailed: true,
          error: msg,
        },
      });
    }
  }

  private async fetchNonceBlockHashForKey(input: {
    nearAccount: NearAccountRef;
    publicKey: string;
    attempts?: number;
    delayMs?: number;
    finality?: 'optimistic' | 'final';
  }): Promise<{ nextNonce: string; blockHash: string }> {
    const nearAccountId = input.nearAccount.accountId;
    const attempts = Math.max(1, Math.floor(input.attempts ?? 6));
    const delayMs = Math.max(50, Math.floor(input.delayMs ?? 250));
    const finality = input.finality ?? 'final';

    const pk = ensureEd25519Prefix(input.publicKey);
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
      const sessionId = secureRandomId('ldsess', 32, 'link device session IDs');

      const signerSlot = coerceSignerSlot(this.options?.signerSlot ?? 2);
      const tempKeypair = await this.context.signingEngine.generateEphemeralNearKeypair();

      this.session = {
        sessionId,
        accountId: null,
        signerSlot,
        nearPublicKey: tempKeypair.publicKey,
        credential: null,
        tempPrivateKey: tempKeypair.privateKey,
        phase: LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED,
        createdAt: nowMs(),
        expiresAt: nowMs() + DEVICE_LINKING_CONFIG.TIMEOUTS.SESSION_EXPIRATION_MS,
      };

      this.safeOnEvent({
        phase: LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED,
        status: 'running',
        data: {
          role: 'display',
          signerSlot,
        },
      });

      await this.registerSessionOnRelay(sessionId, tempKeypair.publicKey, this.session.expiresAt);

      const qrData: DeviceLinkingQRData = {
        sessionId,
        device2PublicKey: tempKeypair.publicKey,
        timestamp: nowMs(),
        version: 'v3',
      };

      const qrCodeDataURL = await generateQRCodeDataURL(JSON.stringify(qrData));

      this.safeOnEvent({
        phase: LinkDeviceEventPhase.STEP_01_QR_DISPLAYED,
        status: 'waiting_for_user',
        data: {
          role: 'display',
          signerSlot,
        },
        interaction: {
          kind: 'qr_display',
          overlay: 'hide',
        },
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
    const signerSlotRaw = this.session.signerSlot;
    const credential = deterministicKeysResult.credential ?? this.session.credential;
    const nearPublicKey = String(
      deterministicKeysResult.nearPublicKey ?? this.session.nearPublicKey ?? '',
    ).trim();

    const nearAccountId = toAccountId(String(accountIdRaw || '').trim());
    const signerSlot = coerceSignerSlot(signerSlotRaw);
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
      signerSlot,
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
      signerSlot,
    });
  }

  getState(): {
    phase: LinkDeviceEventPhase | undefined;
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
    this.session = this.session ? { ...this.session, phase: LinkDeviceEventPhase.CANCELLED } : null;
    this.safeOnEvent({
      phase: LinkDeviceEventPhase.CANCELLED,
      status: 'cancelled',
      interaction: {
        kind: 'qr_display',
        overlay: 'hide',
      },
    });
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
