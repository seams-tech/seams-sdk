import type { NearClient } from '../rpcClients/near/NearClient';
import { ensureEd25519Prefix, validateNearAccountId } from '@shared/utils/validation';
import type { RegistrationHooksOptions, RegistrationSSEEvent } from '../types/sdkSentEvents';
import type { RegistrationResult, TatchiConfigsReadonly } from '../types/tatchi';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import { RegistrationPhase, RegistrationStatus } from '../types/sdkSentEvents';
import { createAccountAndRegisterWithRelayServer } from './faucets/createAccountRelayServer';
import { PasskeyManagerContext } from './index';
import type {
  SigningEnginePublic,
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../signingEngine/SigningEngine';
import { IndexedDBManager } from '../indexedDB';
import { type ConfirmationConfig, mergeSignerMode } from '../types/signer-worker';
import type { AccountId } from '../types/accountIds';
import { getUserFriendlyErrorMessage } from '@shared/utils/errors';
import { buildThresholdEd25519Participants2pV1 } from '@shared/threshold/participants';
import { THRESHOLD_ED25519_2P_PARTICIPANT_IDS } from '../config/defaultConfigs';
import { checkNearAccountExistsBestEffort } from '../rpcClients/near/rpcCalls';
import { getPrfResultsFromCredential } from '../signingEngine/signers/webauthn/credentials/credentialExtensions';
import {
  THRESHOLD_SESSION_POLICY_VERSION,
  generateThresholdSessionId,
} from '../signingEngine/threshold/session/sessionPolicy';
import {
  buildAndCacheEd25519AuthSession,
} from '../signingEngine/threshold/session/ed25519AuthSession';
import type {
  EcdsaSignerProvisioningDefaults,
  EcdsaSignerProvisioningPolicy,
} from '../types/ecdsaSignerProvisioningDefaults';
// Registration forces a visible, clickable confirmation for cross‑origin safety

type ThresholdEcdsaProvisionTarget = {
  chain: ThresholdEcdsaActivationChain;
  options: EcdsaSignerProvisioningPolicy;
};

function listThresholdEcdsaProvisionTargets(
  signerOptions: EcdsaSignerProvisioningDefaults,
): ThresholdEcdsaProvisionTarget[] {
  const targets: ThresholdEcdsaProvisionTarget[] = [];
  if (signerOptions.tempo.enabled) {
    targets.push({ chain: 'tempo', options: signerOptions.tempo });
  }
  if (signerOptions.evm.enabled) {
    targets.push({ chain: 'evm', options: signerOptions.evm });
  }
  return targets;
}

function coercePositiveInt(value: unknown, fallback: number): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return Math.max(1, Math.floor(fallback));
  return Math.floor(n);
}

function toSmartAccountBootstrapInput(
  chain: ThresholdEcdsaActivationChain,
  smartAccount: EcdsaSignerProvisioningPolicy['smartAccount'] | undefined,
):
  | {
      chainId: number;
      factory?: string;
      entryPoint?: string;
      salt?: string;
      counterfactualAddress?: string;
    }
  | undefined {
  void chain;
  if (!smartAccount) return undefined;
  return { ...smartAccount };
}

/**
 * Core registration function that handles passkey registration
 *
 * Legacy proof-derived flows have been removed from the lite threshold-signer stack. Registration is now:
 * 1) Collect a standard WebAuthn registration credential (passkey).
 * 2) Derive a deterministic threshold client verifying share from PRF.first (default registration policy).
 *    Optionally derive/store encrypted local NEAR key material (v3 vault) as backup/export data.
 * 3) Create/register the account via the relayer using threshold key enrollment.
 */
export async function registerPasskeyInternal(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  options: RegistrationHooksOptions,
  authenticatorOptions: AuthenticatorOptions,
  confirmationConfigOverride?: Partial<ConfirmationConfig>,
): Promise<RegistrationResult> {
  const { onEvent, onError, afterCall } = options;
  const { signingEngine, configs } = context;

  // Track registration progress for rollback
  const registrationState = {
    accountCreated: false,
    contractRegistered: false,
    databaseStored: false,
    contractTransactionId: null as string | null,
  };

  console.log('⚡ Registration: Passkey registration (standard WebAuthn)');
  onEvent?.({
    step: 1,
    phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
    status: RegistrationStatus.PROGRESS,
    message: `Starting registration for ${nearAccountId}`,
  } as RegistrationSSEEvent);

  try {
    await validateRegistrationInputs(context, nearAccountId, onEvent, onError);

    onEvent?.({
      step: 1,
      phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
      status: RegistrationStatus.PROGRESS,
      message: 'Generating passkey credential...',
    });

    const confirmationConfig: Partial<ConfirmationConfig> = {
      uiMode: 'modal',
      behavior: 'requireClick', // cross‑origin safari requirement: must requireClick
      ...(confirmationConfigOverride ?? options?.confirmationConfig ?? {}),
    };

    const registrationSession =
      await context.signingEngine.requestRegistrationCredentialConfirmation({
        nearAccountId: String(nearAccountId),
        deviceNumber: 1,
        confirmerText: options?.confirmerText,
        confirmationConfigOverride: confirmationConfig,
      });

    const credential = registrationSession.credential;

    onEvent?.({
      step: 1,
      phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
      status: RegistrationStatus.SUCCESS,
      message: 'WebAuthn ceremony successful',
    });

    const baseSignerMode = signingEngine.getUserPreferences().getSignerMode();
    // Registration defaults to threshold mode even when global/user defaults are local-signer.
    // Explicit per-call overrides can still force local mode for account-key registration.
    const registrationDefaultSignerMode =
      baseSignerMode.mode === 'threshold-signer'
        ? baseSignerMode
        : { mode: 'threshold-signer' as const };
    const requestedSignerMode = mergeSignerMode(registrationDefaultSignerMode, options?.signerMode);
    const requestedSignerModeStr = requestedSignerMode.mode;
    const deriveLocalBackupKey =
      requestedSignerModeStr === 'threshold-signer' ? options?.backupLocalKey !== false : true;
    const provisioningDefaults =
      requestedSignerModeStr === 'threshold-signer'
        ? options?.signerOptions || configs.signing.thresholdEcdsa.provisioningDefaults
        : null;
    const thresholdEcdsaProvisionTargets = provisioningDefaults
      ? listThresholdEcdsaProvisionTargets(provisioningDefaults)
      : [];
    const thresholdEcdsaPrimaryProvisionTarget = thresholdEcdsaProvisionTargets[0] || null;

    const deviceNumber = 1;
    let accountNearPublicKey: string | null = null;
    let thresholdClientVerifyingShareB64u: string | null = null;
    let thresholdEcdsaClientVerifyingShareB64u: string | null = null;
    let localKeyMaterialForPersist: {
      publicKey: string;
      encryptedSk: string;
      chacha20NonceB64u: string;
      wrapKeySalt: string;
      usage: 'runtime-signing' | 'export-only';
    } | null = null;
    let thresholdPrfFirstB64u: string | null = null;
    let thresholdEd25519SessionIdForRegistration: string | null = null;
    let thresholdEcdsaSessionIdForRegistration: string | null = null;
    let thresholdEd25519SessionPolicyForRegistration: {
      version: 'threshold_session_v1';
      nearAccountId: string;
      rpId: string;
      sessionId: string;
      participantIds?: number[];
      ttlMs: number;
      remainingUses: number;
    } | null = null;
    let thresholdEcdsaSessionPolicyForRegistration: {
      version: 'threshold_session_v1';
      userId: string;
      rpId: string;
      sessionId: string;
      participantIds?: number[];
      ttlMs: number;
      remainingUses: number;
    } | null = null;
    let thresholdEcdsaSessionKindForRegistration: 'jwt' | 'cookie' = 'jwt';

    // 2) Key material:
    // - threshold-signer: derive client verifying share from PRF.first (default)
    // - threshold-signer + backupLocalKey: also derive encrypted local backup key material for export
    // - local-signer: derive encrypted local key material for account key usage
    if (requestedSignerModeStr === 'threshold-signer') {
      const derived = await signingEngine.deriveThresholdEd25519ClientVerifyingShareFromCredential({
        credential,
        nearAccountId,
      });
      if (!derived.success || !derived.clientVerifyingShareB64u) {
        throw new Error(derived.error || 'Failed to derive threshold client verifying share');
      }
      thresholdClientVerifyingShareB64u = derived.clientVerifyingShareB64u;
      const derivedEcdsa =
        await signingEngine.deriveThresholdEcdsaClientVerifyingShareFromCredential({
          credential,
          nearAccountId,
        });
      if (!derivedEcdsa.success || !derivedEcdsa.clientVerifyingShareB64u) {
        throw new Error(
          derivedEcdsa.error || 'Failed to derive threshold secp256k1 client verifying share',
        );
      }
      thresholdEcdsaClientVerifyingShareB64u = derivedEcdsa.clientVerifyingShareB64u;
      thresholdPrfFirstB64u =
        String(getPrfResultsFromCredential(credential).first || '').trim() || null;
      if (!thresholdPrfFirstB64u) {
        throw new Error(
          'Missing PRF.first output from registration credential (requires a PRF-enabled passkey)',
        );
      }

      if (deriveLocalBackupKey) {
        const localKeyResult = await signingEngine.deriveNearKeypairAndEncryptFromSerialized({
          credential,
          nearAccountId,
          options: { deviceNumber, persistToDb: false },
        });
        if (!localKeyResult.success || !localKeyResult.publicKey) {
          const reason = localKeyResult?.error || 'Failed to derive local backup keypair with PRF';
          throw new Error(reason);
        }
        const localPublicKey = ensureEd25519Prefix(String(localKeyResult.publicKey || '').trim());
        if (!localPublicKey) {
          throw new Error('Missing local backup public key after key derivation');
        }
        const encryptedSk = String(localKeyResult.encryptedSk || '').trim();
        const chacha20NonceB64u = String(localKeyResult.chacha20NonceB64u || '').trim();
        const wrapKeySalt = String(localKeyResult.wrapKeySalt || '').trim();
        if (!encryptedSk || !chacha20NonceB64u || !wrapKeySalt) {
          throw new Error('Missing encrypted local backup key material after key derivation');
        }
        localKeyMaterialForPersist = {
          publicKey: localPublicKey,
          encryptedSk,
          chacha20NonceB64u,
          wrapKeySalt,
          usage: 'export-only',
        };
      }
    } else {
      const nearKeyResult = await signingEngine.deriveNearKeypairAndEncryptFromSerialized({
        credential,
        nearAccountId,
        options: { deviceNumber, persistToDb: false },
      });
      if (!nearKeyResult.success || !nearKeyResult.publicKey) {
        const reason = nearKeyResult?.error || 'Failed to generate NEAR keypair with PRF';
        throw new Error(reason);
      }
      const localPublicKey = ensureEd25519Prefix(String(nearKeyResult.publicKey || '').trim());
      if (!localPublicKey) {
        throw new Error('Missing local signer public key after key derivation');
      }
      const encryptedSk = String(nearKeyResult.encryptedSk || '').trim();
      const chacha20NonceB64u = String(nearKeyResult.chacha20NonceB64u || '').trim();
      const wrapKeySalt = String(nearKeyResult.wrapKeySalt || '').trim();
      if (!encryptedSk || !chacha20NonceB64u || !wrapKeySalt) {
        throw new Error('Missing encrypted local key material after key derivation');
      }
      localKeyMaterialForPersist = {
        publicKey: localPublicKey,
        encryptedSk,
        chacha20NonceB64u,
        wrapKeySalt,
        usage: 'runtime-signing',
      };
      accountNearPublicKey = localPublicKey;
    }

    // Step 4-5: Create account and register using the relay (atomic)
    onEvent?.({
      step: 2,
      phase: RegistrationPhase.STEP_2_KEY_GENERATION,
      status: RegistrationStatus.SUCCESS,
      message:
        requestedSignerModeStr === 'threshold-signer'
          ? deriveLocalBackupKey
            ? 'Derived threshold client share and local backup key from passkey'
            : 'Derived threshold client share from passkey'
          : 'Wallet derived successfully from passkey',
      verified: true,
      nearAccountId: nearAccountId,
      nearPublicKey: accountNearPublicKey || null,
    });

    const rpId = signingEngine.getRpId();
    if (!rpId) {
      throw new Error('Missing rpId for relay registration');
    }

    if (requestedSignerModeStr === 'threshold-signer' && thresholdClientVerifyingShareB64u) {
      thresholdEd25519SessionIdForRegistration = generateThresholdSessionId();
      thresholdEd25519SessionPolicyForRegistration = {
        version: THRESHOLD_SESSION_POLICY_VERSION,
        nearAccountId: String(nearAccountId),
        rpId,
        sessionId: thresholdEd25519SessionIdForRegistration,
        ttlMs: coercePositiveInt(configs.signing.sessionDefaults?.ttlMs, 24 * 60 * 60 * 1000),
        remainingUses: coercePositiveInt(configs.signing.sessionDefaults?.remainingUses, 10_000),
      };
    }

    if (
      requestedSignerModeStr === 'threshold-signer' &&
      thresholdEcdsaClientVerifyingShareB64u &&
      thresholdEcdsaPrimaryProvisionTarget
    ) {
      thresholdEcdsaSessionIdForRegistration = generateThresholdSessionId();
      thresholdEcdsaSessionKindForRegistration =
        thresholdEcdsaPrimaryProvisionTarget.options.signingSession.kind;
      if (thresholdEcdsaSessionKindForRegistration !== 'jwt') {
        throw new Error('Threshold ECDSA registration bootstrap requires sessionKind=jwt');
      }
      thresholdEcdsaSessionPolicyForRegistration = {
        version: THRESHOLD_SESSION_POLICY_VERSION,
        userId: String(nearAccountId),
        rpId,
        sessionId: thresholdEcdsaSessionIdForRegistration,
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

    const accountAndRegistrationResult = await createAccountAndRegisterWithRelayServer(
      context,
      nearAccountId,
      requestedSignerModeStr === 'threshold-signer' ? undefined : accountNearPublicKey || undefined,
      credential,
      rpId,
      authenticatorOptions,
      onEvent,
      {
        thresholdEd25519:
          thresholdClientVerifyingShareB64u && thresholdEd25519SessionPolicyForRegistration
            ? {
                clientVerifyingShareB64u: thresholdClientVerifyingShareB64u,
                sessionPolicy: thresholdEd25519SessionPolicyForRegistration,
                sessionKind: 'jwt',
              }
            : undefined,
        thresholdEcdsa:
          thresholdEcdsaClientVerifyingShareB64u && thresholdEcdsaSessionPolicyForRegistration
            ? {
                clientVerifyingShareB64u: thresholdEcdsaClientVerifyingShareB64u,
                sessionPolicy: thresholdEcdsaSessionPolicyForRegistration,
                sessionKind: thresholdEcdsaSessionKindForRegistration,
              }
            : undefined,
      },
    );

    if (!accountAndRegistrationResult.success) {
      throw new Error(
        accountAndRegistrationResult.error || 'Account creation and registration failed',
      );
    }

    // Update registration state based on results
    registrationState.accountCreated = true;
    registrationState.contractRegistered = true;
    registrationState.contractTransactionId = accountAndRegistrationResult.transactionId || null;

    // Step 6: Post-commit verification: ensure on-chain access key matches expected public key
    onEvent?.({
      step: 6,
      phase: RegistrationPhase.STEP_6_ACCOUNT_VERIFICATION,
      status: RegistrationStatus.PROGRESS,
      message: 'Verifying on-chain access key matches expected public key...',
    });

    const thresholdPublicKey = String(
      accountAndRegistrationResult?.thresholdEd25519?.publicKey || '',
    ).trim();
    const relayerKeyId = String(
      accountAndRegistrationResult?.thresholdEd25519?.relayerKeyId || '',
    ).trim();
    const relayerVerifyingShareB64u = String(
      accountAndRegistrationResult?.thresholdEd25519?.relayerVerifyingShareB64u || '',
    ).trim();
    const thresholdEcdsaRelayerKeyId = String(
      accountAndRegistrationResult?.thresholdEcdsa?.relayerKeyId || '',
    ).trim();
    const thresholdEcdsaGroupPublicKeyB64u = String(
      accountAndRegistrationResult?.thresholdEcdsa?.groupPublicKeyB64u || '',
    ).trim();
    const thresholdEcdsaRelayerVerifyingShareB64u = String(
      accountAndRegistrationResult?.thresholdEcdsa?.relayerVerifyingShareB64u || '',
    ).trim();
    const thresholdEd25519Session = accountAndRegistrationResult?.thresholdEd25519?.session;
    const thresholdEcdsaSession = accountAndRegistrationResult?.thresholdEcdsa?.session;
    const thresholdEcdsaEthereumAddress = String(
      accountAndRegistrationResult?.thresholdEcdsa?.ethereumAddress || '',
    ).trim();

    if (thresholdEd25519SessionPolicyForRegistration) {
      const sessionKind = String(thresholdEd25519Session?.sessionKind || '')
        .trim()
        .toLowerCase();
      const sessionId = String(thresholdEd25519Session?.sessionId || '').trim();
      const sessionJwt = String(thresholdEd25519Session?.jwt || '').trim();
      const expiresAtMs = Number(thresholdEd25519Session?.expiresAtMs);
      if (
        sessionKind !== 'jwt' ||
        !sessionId ||
        !sessionJwt ||
        !Number.isFinite(expiresAtMs) ||
        expiresAtMs <= 0
      ) {
        throw new Error('Registration did not return a valid threshold-ed25519 bootstrap session');
      }
      if (sessionId !== thresholdEd25519SessionPolicyForRegistration.sessionId) {
        throw new Error('threshold-ed25519 bootstrap sessionId mismatch');
      }
    }

    if (thresholdEcdsaSessionPolicyForRegistration) {
      const sessionKind = String(thresholdEcdsaSession?.sessionKind || '')
        .trim()
        .toLowerCase();
      const sessionId = String(thresholdEcdsaSession?.sessionId || '').trim();
      const sessionJwt = String(thresholdEcdsaSession?.jwt || '').trim();
      const expiresAtMs = Number(thresholdEcdsaSession?.expiresAtMs);
      if (
        sessionKind !== 'jwt' ||
        !sessionId ||
        !sessionJwt ||
        !Number.isFinite(expiresAtMs) ||
        expiresAtMs <= 0
      ) {
        throw new Error('Registration did not return a valid threshold-ecdsa bootstrap session');
      }
      if (sessionId !== thresholdEcdsaSessionPolicyForRegistration.sessionId) {
        throw new Error('threshold-ecdsa bootstrap sessionId mismatch');
      }
    }
    if (
      requestedSignerModeStr === 'threshold-signer' &&
      thresholdEcdsaClientVerifyingShareB64u &&
      thresholdEcdsaSessionPolicyForRegistration &&
      (!thresholdEcdsaRelayerKeyId ||
        !thresholdEcdsaGroupPublicKeyB64u ||
        !thresholdEcdsaRelayerVerifyingShareB64u)
    ) {
      console.warn(
        '[Registration] threshold ECDSA keygen result missing key material; canonical threshold session record cannot be built',
      );
    }
    const accountCreationPublicKey =
      requestedSignerModeStr === 'threshold-signer'
        ? thresholdPublicKey
        : String(accountNearPublicKey || '').trim();
    if (!accountCreationPublicKey) {
      throw new Error('Missing account public key after registration');
    }
    const expectedAccessKeys: string[] = [accountCreationPublicKey];

    const accessKeyVerified = await verifyAccountAccessKeysPresent(
      context.nearClient,
      nearAccountId,
      expectedAccessKeys,
      { attempts: 3, delayMs: 200, finality: 'optimistic' },
    );

    if (!accessKeyVerified) {
      console.warn(
        '[Registration] Access key not yet visible after atomic registration; continuing optimistically',
      );
      onEvent?.({
        step: 6,
        phase: RegistrationPhase.STEP_6_ACCOUNT_VERIFICATION,
        status: RegistrationStatus.SUCCESS,
        message: 'Access key verification pending (optimistic); continuing...',
      });
    } else {
      onEvent?.({
        step: 6,
        phase: RegistrationPhase.STEP_6_ACCOUNT_VERIFICATION,
        status: RegistrationStatus.SUCCESS,
        message: 'Access key verified on-chain',
      });
    }

    // For threshold-signer registrations, the account is created directly with the threshold key.
    // Confirm threshold key availability and continue.
    if (requestedSignerModeStr === 'threshold-signer') {
      if (
        !thresholdPublicKey ||
        !relayerKeyId ||
        !thresholdClientVerifyingShareB64u ||
        !relayerVerifyingShareB64u
      ) {
        throw new Error('Threshold registration did not return required key material');
      }

      // Step 7: ensure threshold key is available on-chain.
      onEvent?.({
        step: 7,
        phase: RegistrationPhase.STEP_7_THRESHOLD_KEY_ENROLLMENT,
        status: RegistrationStatus.PROGRESS,
        message: 'Confirming threshold key…',
        thresholdPublicKey,
        relayerKeyId,
        deviceNumber,
      });

      const thresholdConfirmed =
        accessKeyVerified ||
        (await verifyAccountAccessKeysPresent(
          context.nearClient,
          String(nearAccountId),
          [thresholdPublicKey],
          { attempts: 10, delayMs: 250, finality: 'optimistic' },
        ));
      if (!thresholdConfirmed) {
        console.warn(
          '[Registration] Threshold key not yet visible after atomic registration; continuing optimistically',
        );
      }

      onEvent?.({
        step: 7,
        phase: RegistrationPhase.STEP_7_THRESHOLD_KEY_ENROLLMENT,
        status: RegistrationStatus.SUCCESS,
        message: thresholdConfirmed
          ? 'Threshold key ready'
          : 'Threshold key verification pending (optimistic)',
        thresholdKeyReady: thresholdConfirmed,
        thresholdPublicKey,
        relayerKeyId,
        deviceNumber,
      });
    }

    const thresholdEcdsaKeyRef =
      requestedSignerModeStr === 'threshold-signer' &&
      thresholdEcdsaClientVerifyingShareB64u &&
      thresholdEcdsaRelayerKeyId &&
      context.configs.network.relayer.url
        ? {
            type: 'threshold-ecdsa-secp256k1' as const,
            userId: String(nearAccountId),
            relayerUrl: context.configs.network.relayer.url,
            relayerKeyId: thresholdEcdsaRelayerKeyId,
            clientVerifyingShareB64u: thresholdEcdsaClientVerifyingShareB64u,
            ...(Array.isArray(thresholdEcdsaSession?.participantIds)
              ? { participantIds: thresholdEcdsaSession.participantIds }
              : Array.isArray(accountAndRegistrationResult?.thresholdEcdsa?.participantIds)
                ? { participantIds: accountAndRegistrationResult.thresholdEcdsa?.participantIds }
                : {}),
            ...(String(thresholdEcdsaSession?.sessionKind || '')
              .trim()
              .toLowerCase() === 'jwt'
              ? { thresholdSessionKind: 'jwt' as const }
              : {}),
            ...(String(thresholdEcdsaSession?.sessionId || '').trim()
              ? { thresholdSessionId: String(thresholdEcdsaSession?.sessionId || '').trim() }
              : {}),
            ...(String(thresholdEcdsaSession?.jwt || '').trim()
              ? { thresholdSessionJwt: String(thresholdEcdsaSession?.jwt || '').trim() }
              : {}),
            ...(thresholdEcdsaGroupPublicKeyB64u
              ? { groupPublicKeyB64u: thresholdEcdsaGroupPublicKeyB64u }
              : {}),
            ...(thresholdEcdsaRelayerVerifyingShareB64u
              ? { relayerVerifyingShareB64u: thresholdEcdsaRelayerVerifyingShareB64u }
              : {}),
          }
        : undefined;

    // Step 8: Store user data + authenticator locally
    onEvent?.({
      step: 8,
      phase: RegistrationPhase.STEP_8_DATABASE_STORAGE,
      status: RegistrationStatus.PROGRESS,
      message: 'Storing passkey wallet metadata...',
    });

    const clientNearPublicKey =
      requestedSignerModeStr === 'threshold-signer'
        ? String(thresholdPublicKey || '').trim()
        : accountCreationPublicKey;

    await signingEngine.atomicStoreRegistrationData({
      nearAccountId,
      credential,
      publicKey: clientNearPublicKey,
    });

    // Mark database as stored for rollback tracking
    registrationState.databaseStored = true;

    if (localKeyMaterialForPersist) {
      await IndexedDBManager.storeNearLocalKeyMaterial({
        nearAccountId,
        deviceNumber,
        publicKey: localKeyMaterialForPersist.publicKey,
        encryptedSk: localKeyMaterialForPersist.encryptedSk,
        chacha20NonceB64u: localKeyMaterialForPersist.chacha20NonceB64u,
        wrapKeySalt: localKeyMaterialForPersist.wrapKeySalt,
        usage: localKeyMaterialForPersist.usage,
        timestamp: Date.now(),
      });
    }

    if (thresholdPublicKey && relayerKeyId && thresholdClientVerifyingShareB64u) {
      await IndexedDBManager.storeNearThresholdKeyMaterial({
        nearAccountId,
        deviceNumber,
        publicKey: thresholdPublicKey,
        relayerKeyId,
        clientShareDerivation: 'prf_first_v1',
        participants: buildThresholdEd25519Participants2pV1({
          clientParticipantId: accountAndRegistrationResult?.thresholdEd25519?.clientParticipantId,
          relayerParticipantId:
            accountAndRegistrationResult?.thresholdEd25519?.relayerParticipantId,
          relayerKeyId,
          relayerUrl: context.configs?.network.relayer?.url,
          clientVerifyingShareB64u: thresholdClientVerifyingShareB64u,
          relayerVerifyingShareB64u,
          clientShareDerivation: 'prf_first_v1',
        }),
        timestamp: Date.now(),
      });
    }

    onEvent?.({
      step: 8,
      phase: RegistrationPhase.STEP_8_DATABASE_STORAGE,
      status: RegistrationStatus.SUCCESS,
      message: 'Registration metadata stored successfully',
    });

    if (requestedSignerModeStr === 'threshold-signer' && thresholdPrfFirstB64u) {
      if (thresholdEd25519SessionPolicyForRegistration && thresholdEd25519Session && relayerKeyId) {
        const edSessionId = String(thresholdEd25519Session.sessionId || '').trim();
        const edSessionJwt = String(thresholdEd25519Session.jwt || '').trim();
        const edExpiresAtMs = Number(thresholdEd25519Session.expiresAtMs);
        const edRemainingUses = coercePositiveInt(
          thresholdEd25519Session.remainingUses,
          thresholdEd25519SessionPolicyForRegistration.remainingUses,
        );
        const edParticipantIds = Array.isArray(thresholdEd25519Session.participantIds)
          ? thresholdEd25519Session.participantIds
          : [...THRESHOLD_ED25519_2P_PARTICIPANT_IDS];

        await signingEngine.hydrateSigningSession({
          nearAccountId,
          sessionId: edSessionId,
          prfFirstB64u: thresholdPrfFirstB64u,
          expiresAtMs: edExpiresAtMs,
          remainingUses: edRemainingUses,
          setActiveSigningSessionId: true,
        });

        await buildAndCacheEd25519AuthSession({
          nearAccountId: String(nearAccountId),
          rpId,
          relayerUrl: context.configs.network.relayer.url,
          relayerKeyId,
          participantIds: edParticipantIds,
          sessionKind: 'jwt',
          sessionId: edSessionId,
          expiresAtMs: edExpiresAtMs,
          remainingUses: edRemainingUses,
          jwt: edSessionJwt,
          policyTtlMs: thresholdEd25519SessionPolicyForRegistration.ttlMs,
          policyRemainingUses: thresholdEd25519SessionPolicyForRegistration.remainingUses,
          source: 'registration',
        });
      }

      if (thresholdEcdsaSessionPolicyForRegistration && thresholdEcdsaProvisionTargets.length > 0) {
        if (!thresholdEcdsaKeyRef || !thresholdEcdsaSession || !thresholdEcdsaRelayerKeyId) {
          throw new Error(
            'Threshold ECDSA key/session material missing from registration response; cannot provision signers during registration',
          );
        }

        onEvent?.({
          step: 8,
          phase: RegistrationPhase.STEP_8_DATABASE_STORAGE,
          status: RegistrationStatus.PROGRESS,
          message: 'Caching threshold secp256k1 signer session...',
        });

        const ecdsaSessionId = String(thresholdEcdsaSession.sessionId || '').trim();
        const ecdsaSessionJwt = String(thresholdEcdsaSession.jwt || '').trim();
        const ecdsaExpiresAtMs = Number(thresholdEcdsaSession.expiresAtMs);
        const ecdsaRemainingUses = coercePositiveInt(
          thresholdEcdsaSession.remainingUses,
          thresholdEcdsaSessionPolicyForRegistration.remainingUses,
        );
        const ecdsaParticipantIds = Array.isArray(thresholdEcdsaSession.participantIds)
          ? thresholdEcdsaSession.participantIds
          : Array.isArray(thresholdEcdsaKeyRef.participantIds)
            ? thresholdEcdsaKeyRef.participantIds
            : thresholdEcdsaSessionPolicyForRegistration.participantIds;

        await signingEngine.hydrateSigningSession({
          nearAccountId,
          sessionId: ecdsaSessionId,
          prfFirstB64u: thresholdPrfFirstB64u,
          expiresAtMs: ecdsaExpiresAtMs,
          remainingUses: ecdsaRemainingUses,
          setActiveSigningSessionId: false,
        });

        const primarySmartAccountBootstrap = thresholdEcdsaPrimaryProvisionTarget
          ? toSmartAccountBootstrapInput(
              thresholdEcdsaPrimaryProvisionTarget.chain,
              thresholdEcdsaPrimaryProvisionTarget.options.smartAccount,
            )
          : undefined;

        const bootstrapProjection: ThresholdEcdsaSessionBootstrapResult = {
          thresholdEcdsaKeyRef,
          keygen: {
            ok: true,
            clientVerifyingShareB64u: thresholdEcdsaClientVerifyingShareB64u || undefined,
            relayerKeyId: thresholdEcdsaRelayerKeyId,
            groupPublicKeyB64u: thresholdEcdsaGroupPublicKeyB64u || undefined,
            ethereumAddress: thresholdEcdsaEthereumAddress || undefined,
            relayerVerifyingShareB64u: thresholdEcdsaRelayerVerifyingShareB64u || undefined,
            participantIds: ecdsaParticipantIds,
            ...(primarySmartAccountBootstrap
              ? { chainId: primarySmartAccountBootstrap.chainId }
              : {}),
            ...(primarySmartAccountBootstrap?.factory
              ? { factory: primarySmartAccountBootstrap.factory }
              : {}),
            ...(primarySmartAccountBootstrap?.entryPoint
              ? { entryPoint: primarySmartAccountBootstrap.entryPoint }
              : {}),
            ...(primarySmartAccountBootstrap?.salt
              ? { salt: primarySmartAccountBootstrap.salt }
              : {}),
            ...(primarySmartAccountBootstrap?.counterfactualAddress
              ? { counterfactualAddress: primarySmartAccountBootstrap.counterfactualAddress }
              : {}),
          },
          session: {
            ok: true,
            sessionId: ecdsaSessionId,
            expiresAtMs: ecdsaExpiresAtMs,
            remainingUses: ecdsaRemainingUses,
            jwt: ecdsaSessionJwt,
            clientVerifyingShareB64u: thresholdEcdsaClientVerifyingShareB64u || undefined,
          },
        };

        const canonicalChain = thresholdEcdsaPrimaryProvisionTarget?.chain || 'tempo';
        signingEngine.upsertThresholdEcdsaSessionFromBootstrap({
          nearAccountId,
          chain: canonicalChain,
          bootstrap: bootstrapProjection,
          source: 'registration',
        });

        for (const target of thresholdEcdsaProvisionTargets) {
          await signingEngine.persistThresholdEcdsaBootstrapChainAccount({
            nearAccountId,
            chain: target.chain,
            bootstrap: bootstrapProjection,
            smartAccount: toSmartAccountBootstrapInput(target.chain, target.options.smartAccount),
          });
        }
      }
    }

    // Initialize current user for immediate use (best-effort).
    try {
      await signingEngine.initializeCurrentUser(nearAccountId, context.nearClient);
    } catch (initErr) {
      console.warn('Failed to initialize current user after registration:', initErr);
    }

    onEvent?.({
      step: 9,
      phase: RegistrationPhase.STEP_9_REGISTRATION_COMPLETE,
      status: RegistrationStatus.SUCCESS,
      message: 'Registration completed!',
    });

    const successResult = {
      success: true,
      nearAccountId: nearAccountId,
      clientNearPublicKey,
      transactionId: registrationState.contractTransactionId,
      ...(thresholdEcdsaEthereumAddress ? { thresholdEcdsaEthereumAddress } : {}),
      ...(thresholdEcdsaGroupPublicKeyB64u ? { thresholdEcdsaGroupPublicKeyB64u } : {}),
    };

    afterCall?.(true, successResult);
    return successResult;
  } catch (error: unknown) {
    const message =
      error && typeof error === 'object' && 'message' in error
        ? String((error as { message?: unknown }).message || '')
        : String(error || '');
    const stack =
      error && typeof error === 'object' && 'stack' in error
        ? String((error as { stack?: unknown }).stack || '')
        : '';
    console.error('Registration failed:', message, stack);

    // Perform rollback based on registration state
    await performRegistrationRollback(registrationState, nearAccountId, signingEngine, onEvent);

    // Use centralized error handling
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', nearAccountId);

    const errorObject = new Error(errorMessage);
    onError?.(errorObject);

    onEvent?.({
      step: 0,
      phase: RegistrationPhase.REGISTRATION_ERROR,
      status: RegistrationStatus.ERROR,
      message: errorMessage,
      error: errorMessage,
    } as RegistrationSSEEvent);

    const result = { success: false, error: errorMessage };
    afterCall?.(false);
    return result;
  }
}

// Public wrapper without explicit confirmationConfig override.
export async function registerPasskey(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  options: RegistrationHooksOptions,
  authenticatorOptions: AuthenticatorOptions,
): Promise<RegistrationResult> {
  return registerPasskeyInternal(context, nearAccountId, options, authenticatorOptions, undefined);
}

//////////////////////////////////////
// HELPER FUNCTIONS
//////////////////////////////////////

/**
 * Validates registration inputs and throws errors if invalid
 * @param nearAccountId - NEAR account ID to validate
 * @param onEvent - Optional callback for registration progress events
 * @param onError - Optional callback for error handling
 */
const validateRegistrationInputs = async (
  context: {
    configs: TatchiConfigsReadonly;
    signingEngine: SigningEnginePublic;
    nearClient: NearClient;
  },
  nearAccountId: AccountId,
  onEvent?: (event: RegistrationSSEEvent) => void,
  onError?: (error: Error) => void,
) => {
  onEvent?.({
    step: 1,
    phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
    status: RegistrationStatus.PROGRESS,
    message: 'Validating registration inputs...',
  } as RegistrationSSEEvent);

  // Validation
  if (!nearAccountId) {
    const error = new Error('NEAR account ID is required for registration.');
    onError?.(error);
    throw error;
  }
  // Validate the account ID format
  const validation = validateNearAccountId(nearAccountId);
  if (!validation.valid) {
    const error = new Error(`Invalid NEAR account ID: ${validation.error}`);
    onError?.(error);
    throw error;
  }
  if (!window.isSecureContext) {
    const error = new Error('Passkey operations require a secure context (HTTPS or localhost).');
    onError?.(error);
    throw error;
  }

  // Best-effort pre-check: avoid prompting for passkey creation if the account name
  // is already taken on-chain. Final enforcement still happens in the relay + chain.
  onEvent?.({
    step: 1,
    phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
    status: RegistrationStatus.PROGRESS,
    message: `Checking if ${nearAccountId} already exists...`,
  } as RegistrationSSEEvent);

  const accountExists = await checkNearAccountExistsBestEffort(
    context.nearClient,
    String(nearAccountId),
  );
  if (accountExists) {
    const error = new Error(`Account ${nearAccountId} already exists. Please log in instead.`);
    onError?.(error);
    throw error;
  }

  onEvent?.({
    step: 1,
    phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
    status: RegistrationStatus.PROGRESS,
    message: `Account format validated, preparing confirmation`,
  } as RegistrationSSEEvent);
  return;
};

/**
 * Rollback registration data in case of errors
 */
async function performRegistrationRollback(
  registrationState: {
    accountCreated: boolean;
    contractRegistered: boolean;
    databaseStored: boolean;
    contractTransactionId: string | null;
  },
  nearAccountId: AccountId,
  signingEngine: SigningEnginePublic,
  onEvent?: (event: RegistrationSSEEvent) => void,
): Promise<void> {
  console.debug('Starting registration rollback...', registrationState);

  // Rollback in reverse order
  try {
    // 1. Rollback database storage
    if (registrationState.databaseStored) {
      console.debug('Rolling back database storage...');
      onEvent?.({
        step: 0,
        phase: RegistrationPhase.REGISTRATION_ERROR,
        status: RegistrationStatus.ERROR,
        message: 'Rolling back database storage...',
        error: 'Registration failed - rolling back database storage',
      } as RegistrationSSEEvent);

      await signingEngine.rollbackUserRegistration(nearAccountId);
      console.debug('Database rollback completed');
    }

    // 2. On-chain rollback
    // NOT POSSIBLE - account creation is an on-chain transaction and cannot be rolled back.
    if (registrationState.contractRegistered) {
      console.debug('Registration transaction cannot be rolled back (immutable blockchain state)');
      onEvent?.({
        step: 0,
        phase: RegistrationPhase.REGISTRATION_ERROR,
        status: RegistrationStatus.ERROR,
        message: `Registration transaction (tx: ${registrationState.contractTransactionId}) cannot be rolled back`,
        error: 'Registration failed - on-chain state is immutable',
      } as RegistrationSSEEvent);
    }
    console.debug('Registration rollback completed');
  } catch (rollbackError: unknown) {
    console.error('Rollback failed:', rollbackError);
    onEvent?.({
      step: 0,
      phase: RegistrationPhase.REGISTRATION_ERROR,
      status: RegistrationStatus.ERROR,
      message: `Rollback failed: ${
        rollbackError && typeof rollbackError === 'object' && 'message' in rollbackError
          ? String((rollbackError as { message?: unknown }).message || '')
          : String(rollbackError || '')
      }`,
      error: 'Both registration and rollback failed',
    } as RegistrationSSEEvent);
  }
}

async function verifyAccountAccessKeysPresent(
  nearClient: NearClient,
  nearAccountId: string,
  expectedPublicKeys: string[],
  opts?: { attempts?: number; delayMs?: number; finality?: 'optimistic' | 'final' },
): Promise<boolean> {
  const unique = Array.from(
    new Set(expectedPublicKeys.map((k) => ensureEd25519Prefix(k)).filter(Boolean)),
  );
  if (!unique.length) return false;

  const attempts = Math.max(1, Math.floor(opts?.attempts ?? 6));
  const delayMs = Math.max(50, Math.floor(opts?.delayMs ?? 750));
  const finality = opts?.finality ?? 'optimistic';

  for (let i = 0; i < attempts; i++) {
    try {
      const accessKeyList = await nearClient.viewAccessKeyList(nearAccountId, { finality });
      const keys = accessKeyList.keys.map((k) => ensureEd25519Prefix(k.public_key)).filter(Boolean);
      const allPresent = unique.every((expected) => keys.includes(expected));
      if (allPresent) return true;
    } catch {
      // tolerate transient view errors during propagation; retry
    }
    if (i < attempts - 1) {
      await new Promise((res) => setTimeout(res, delayMs));
    }
  }
  return false;
}
