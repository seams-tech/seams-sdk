import type { NearClient } from '../rpcClients/near/NearClient';
import { validateNearAccountId } from '@shared/utils/validation';
import type {
  CreateRegistrationFlowEventInput,
  RegistrationFlowEvent,
  RegistrationHooksOptions,
} from '../types/sdkSentEvents';
import type { RegistrationResult, SeamsConfigsReadonly } from '../types/seams';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import { createRegistrationFlowEvent, RegistrationEventPhase } from '../types/sdkSentEvents';
import { createAccountAndRegisterWithRelayServer } from './faucets/createAccountRelayServer';
import { PasskeyManagerContext } from './index';
import {
  type CompletedThresholdEd25519Registration,
  type ThresholdWarmSessionRequestEnvelope,
  completeRegisteredThresholdEd25519Registration,
  prewarmThresholdEd25519ClientBaseFromCredential,
  prepareThresholdEd25519RegistrationWithHss,
  persistRegisteredThresholdEd25519Session,
} from './thresholdWarmSessionBootstrap';
import type { SigningEnginePublic } from '../signingEngine/SigningEngine';
import { type ConfirmationConfig } from '../types/signer-worker';
import type { AccountId } from '../types/accountIds';
import type { WebAuthnRegistrationCredential } from '../types/webauthn';
import { getUserFriendlyErrorMessage } from '@shared/utils/errors';
import { checkNearAccountExistsBestEffort } from '../rpcClients/near/rpcCalls';
import {
  getPrfFirstB64uFromCredential,
  getPrfResultsFromCredential,
} from '../signingEngine/webauthnAuth/credentials/credentialExtensions';
import { listConfiguredThresholdEcdsaPublicationTargets } from './thresholdEcdsaProvisioning';
import { IndexedDBManager } from '../indexedDB';
import { resolveNearAccountProfileContinuity } from '../accountData/near/accountProjection';
import {
  normalizeIndexedDbAccountAddress,
  toIndexedDbChainTargetKey,
} from '../indexedDB/normalization';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
  walletSubjectIdFromWalletProfile,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '../signingEngine/threshold/ecdsa/activation';
import { buildEcdsaSessionIdentity } from '../signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import {
  generateWalletSigningSessionId,
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '../signingEngine/threshold/sessionPolicy';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaSessionLanePolicy,
  deriveEvmFamilyKeyFingerprint,
  resolveThresholdEcdsaKeyIdFromRecord,
  resolveThresholdSigningRootBindingFromRecord,
  toEvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
} from '../signingEngine/session/identity/evmFamilyEcdsaIdentity';

// Registration forces a visible, clickable confirmation for cross‑origin safety

function createThresholdRegistrationEcdsaSessionId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `threshold-ecdsa-registration-${crypto.randomUUID()}`;
  }
  return `threshold-ecdsa-registration-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function resolveRegistrationThresholdEcdsaBootstrapIdentity(
  bootstrap: ThresholdEcdsaSessionBootstrapResult,
): {
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
} {
  const keyRef = bootstrap.thresholdEcdsaKeyRef;
  const keyHandle = String(keyRef.keyHandle || '').trim();
  if (!keyHandle) {
    throw new Error('[Registration] threshold ECDSA bootstrap missing keyHandle');
  }
  const canonicalKeyHandle = toEvmFamilyEcdsaKeyHandle(keyHandle);
  const runtimePolicyScope = parseThresholdRuntimePolicyScopeFromJwt(
    String(bootstrap.session.jwt || keyRef.thresholdSessionAuthToken || '').trim(),
  );
  const signingRootBinding = resolveThresholdSigningRootBindingFromRecord({
    record: {
      keyHandle: canonicalKeyHandle,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      signingRootId: keyRef.signingRootId,
      signingRootVersion: keyRef.signingRootVersion,
    },
  });
  const ecdsaThresholdKeyId = resolveThresholdEcdsaKeyIdFromRecord({
    record: {
      ecdsaThresholdKeyId: keyRef.ecdsaThresholdKeyId,
    },
  });
  return {
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId: String(signingRootBinding.signingRootId),
    signingRootVersion: String(signingRootBinding.signingRootVersion),
  };
}

function resolveRegistrationContinuationRuntimePolicyScope(
  registrationContinuationToken: string,
): ThresholdRuntimePolicyScope {
  const runtimePolicyScope = parseThresholdRuntimePolicyScopeFromJwt(registrationContinuationToken);
  if (!runtimePolicyScope) {
    throw new Error('[Registration] ECDSA registration continuation missing runtimePolicyScope');
  }
  return runtimePolicyScope;
}

async function persistRegistrationThresholdEcdsaProfileSigner(args: {
  nearAccountId: AccountId;
  chainTarget: ThresholdEcdsaChainTarget;
  key: EvmFamilyEcdsaKeyIdentity;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  signerSlot: number;
}): Promise<void> {
  const continuity = await resolveNearAccountProfileContinuity(
    IndexedDBManager.clientDB,
    args.nearAccountId,
  );
  const profileId = String(continuity?.profile.profileId || '').trim();
  if (!profileId) {
    throw new Error(`[Registration] missing profile continuity for ${String(args.nearAccountId)}`);
  }

  const keyRef = args.bootstrap.thresholdEcdsaKeyRef;
  const identity = resolveRegistrationThresholdEcdsaBootstrapIdentity(args.bootstrap);
  const keyHandle = identity.keyHandle;
  const ecdsaThresholdKeyId = identity.ecdsaThresholdKeyId;
  const signingRootId = identity.signingRootId;
  const signingRootVersion = identity.signingRootVersion;
  if (ecdsaThresholdKeyId !== String(args.key.ecdsaThresholdKeyId)) {
    throw new Error('[Registration] threshold ECDSA profile signer key id mismatches shared key');
  }
  const ownerAddress = normalizeIndexedDbAccountAddress(
    args.bootstrap.keygen.ethereumAddress || keyRef.ethereumAddress,
  );
  const accountAddress = ownerAddress;
  const relayerKeyId = String(
    args.bootstrap.keygen.relayerKeyId || keyRef.backendBinding?.relayerKeyId || '',
  ).trim();
  const thresholdEcdsaPublicKeyB64u = String(
    args.bootstrap.keygen.thresholdEcdsaPublicKeyB64u || keyRef.thresholdEcdsaPublicKeyB64u || '',
  ).trim();
  const participantIds = Array.isArray(args.bootstrap.keygen.participantIds)
    ? args.bootstrap.keygen.participantIds
    : keyRef.participantIds;
  if (!ecdsaThresholdKeyId || !ownerAddress || !accountAddress || !relayerKeyId) {
    throw new Error('[Registration] threshold ECDSA profile signer requires exact key material');
  }

  const signerSlot = Math.max(1, Math.floor(Number(args.signerSlot) || 1));
  const accountModel = 'threshold-ecdsa';
  const evmFamilyKeyFingerprint = deriveEvmFamilyKeyFingerprint(args.key);
  await IndexedDBManager.clientDB.upsertAccountSigner({
    profileId,
    chainIdKey: toIndexedDbChainTargetKey(args.chainTarget),
    accountAddress,
    signerId: ownerAddress,
    signerSlot,
    signerType: 'threshold',
    signerKind: SIGNER_KINDS.thresholdEcdsa,
    signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
    signerSource: SIGNER_SOURCES.passkeyRegistration,
    status: 'active',
    metadata: {
      accountModel,
      accountAddress,
      ownerAddress,
      thresholdOwnerAddress: String(args.key.thresholdOwnerAddress),
      keyScope: args.key.keyScope,
      keyHandle,
      evmFamilyKeyFingerprint,
      walletId: String(args.key.walletId),
      subjectId: String(walletSubjectIdFromWalletProfile({ walletId: args.key.walletId })),
      rpId: String(args.key.rpId),
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      relayerKeyId,
      thresholdEcdsaPublicKeyB64u,
      signerSlot,
      chainTarget: args.chainTarget,
      targetMembership: {
        targetKey: thresholdEcdsaChainTargetKey(args.chainTarget),
        chainTarget: args.chainTarget,
      },
      sharedEvmFamilyKey: {
        walletId: String(args.key.walletId),
        subjectId: String(walletSubjectIdFromWalletProfile({ walletId: args.key.walletId })),
        rpId: String(args.key.rpId),
        keyScope: args.key.keyScope,
        keyHandle,
        ecdsaThresholdKeyId,
        signingRootId,
        signingRootVersion,
        participantIds: args.key.participantIds.map((participantId) => Number(participantId)),
        thresholdOwnerAddress: String(args.key.thresholdOwnerAddress),
        evmFamilyKeyFingerprint,
      },
      chainId: args.chainTarget.chainId,
      ...(Array.isArray(participantIds) && participantIds.length
        ? { participantIds: [...participantIds] }
        : {}),
    },
    mutation: { routeThroughOutbox: false },
  });
}

type EmitRegistrationEventInput = Omit<
  CreateRegistrationFlowEventInput,
  'accountId' | 'authMethod' | 'flowId'
>;

function emitRegistrationEvent(
  onEvent: RegistrationHooksOptions['onEvent'] | undefined,
  nearAccountId: AccountId,
  event: EmitRegistrationEventInput,
): void {
  onEvent?.(
    createRegistrationFlowEvent({
      flowId: `registration:passkey:${nearAccountId}`,
      accountId: String(nearAccountId),
      authMethod: 'passkey',
      ...event,
    }),
  );
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
  const registrationStartedAt = performance.now();
  const registrationTimingSummary: Record<string, number> = {};

  // Track registration progress for rollback
  const registrationState = {
    accountCreated: false,
    contractRegistered: false,
    databaseStored: false,
    contractTransactionId: null as string | null,
  };

  console.log('⚡ Registration: Passkey registration (standard WebAuthn)');
  emitRegistrationEvent(onEvent, nearAccountId, {
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });

  try {
    await validateRegistrationInputs(context, nearAccountId, onEvent, onError);

    emitRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_STARTED,
      status: 'waiting_for_user',
      interaction: {
        kind: 'passkey_create',
        overlay: 'show',
      },
    });

    const confirmationConfig: Partial<ConfirmationConfig> = {
      uiMode: 'modal',
      behavior: 'requireClick', // cross‑origin safari requirement: must requireClick
      ...(confirmationConfigOverride ?? options?.confirmationConfig ?? {}),
    };

    const registrationSession =
      await context.signingEngine.requestRegistrationCredentialConfirmation({
        nearAccountId: String(nearAccountId),
        signerSlot: 1,
        confirmerText: options?.confirmerText,
        confirmationConfigOverride: confirmationConfig,
      });

    const credential = registrationSession.credential;

    emitRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_SUCCEEDED,
      status: 'succeeded',
      interaction: {
        kind: 'passkey_create',
        overlay: 'hide',
      },
    });

    let signerSlot = 1;
    let thresholdPrfFirstB64u: string | null = null;

    const rpId = signingEngine.getRpId();
    if (!rpId) {
      throw new Error('Missing rpId for relay registration');
    }
    emitRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_STARTED,
      status: 'running',
    });
    const thresholdEd25519Registration = await prepareThresholdEd25519RegistrationWithHss({
      context,
      credential,
      nearAccountId,
      rpId,
      authenticatorOptions,
    });
    registrationTimingSummary.thresholdEd25519PrepareMs = Math.round(
      performance.now() - registrationStartedAt,
    );
    thresholdPrfFirstB64u =
      String(getPrfResultsFromCredential(credential).first || '').trim() || null;
    if (!thresholdPrfFirstB64u) {
      throw new Error(
        'Missing PRF.first output from registration credential (requires a PRF-enabled passkey)',
      );
    }

    // Step 4-5: Create account and register using the relay (atomic)
    emitRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_SUCCEEDED,
      status: 'succeeded',
      data: {
        verified: true,
        nearPublicKey: thresholdEd25519Registration.registrationInput.publicKey,
      },
    });

    const relayRegistrationStartedAt = performance.now();
    const accountAndRegistrationResult = await createAccountAndRegisterWithRelayServer(
      context,
      nearAccountId,
      credential,
      rpId,
      authenticatorOptions,
      onEvent,
      {
        thresholdEd25519: {
          ...thresholdEd25519Registration.registrationInput,
        },
      },
    );
    registrationTimingSummary.relayRegistrationMs = Math.round(
      performance.now() - relayRegistrationStartedAt,
    );

    if (!accountAndRegistrationResult.success) {
      const registrationError = new Error(
        accountAndRegistrationResult.error || 'Account creation and registration failed',
      ) as Error & { code?: string };
      const relayErrorCode = String(accountAndRegistrationResult.errorCode || '').trim();
      if (relayErrorCode) {
        registrationError.code = relayErrorCode;
      }
      throw registrationError;
    }

    // Update registration state based on results
    registrationState.accountCreated = true;
    registrationState.contractRegistered = true;
    registrationState.contractTransactionId = accountAndRegistrationResult.transactionId || null;

    // Step 6: Post-commit verification: ensure on-chain access key matches expected public key
    emitRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_07_ACCOUNT_VERIFY_STARTED,
      status: 'running',
    });

    const completedThresholdEd25519Registration = completeRegisteredThresholdEd25519Registration({
      thresholdEd25519: accountAndRegistrationResult?.thresholdEd25519,
      expectedSessionPolicy: thresholdEd25519Registration.registrationInput.sessionPolicy,
    });
    emitRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_07_ACCOUNT_VERIFY_SUCCEEDED,
      status: 'succeeded',
    });

    emitRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
      status: 'running',
    });

    // Store user data + authenticator locally.

    const localPersistenceStartedAt = performance.now();
    const storedRegistration = await signingEngine.atomicStoreRegistrationData({
      nearAccountId,
      credential,
      operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
    });
    signerSlot = storedRegistration.signerSlot;
    const persistedUser = await signingEngine.getUserBySignerSlot(nearAccountId, signerSlot);
    if (!persistedUser) {
      throw new Error(
        `[Registration] profile/account mapping was not persisted for ${String(
          nearAccountId,
        )} signer slot ${signerSlot}`,
      );
    }
    await persistRegisteredThresholdEd25519Session({
      signingEngine,
      nearAccountId,
      signerSlot,
      rpId,
      relayerUrl: context.configs.network.relayer.url,
      prfFirstB64u: thresholdPrfFirstB64u,
      registrationSessionPolicy: thresholdEd25519Registration.registrationInput.sessionPolicy,
      completedRegistration: completedThresholdEd25519Registration,
    });
    registrationTimingSummary.localPersistenceMs = Math.round(
      performance.now() - localPersistenceStartedAt,
    );

    // Mark database as stored for rollback tracking
    registrationState.databaseStored = true;

    emitRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
      status: 'succeeded',
      data: {
        thresholdPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
        relayerKeyId: completedThresholdEd25519Registration.registered.relayerKeyId,
        signerSlot,
      },
    });

    await provisionThresholdEcdsaAfterRegistration({
      context,
      signingEngine,
      credential,
      nearAccountId,
      rpId,
      signerSlot,
      registrationContinuation: accountAndRegistrationResult.registrationContinuation,
      registrationSessionPolicy: thresholdEd25519Registration.registrationInput.sessionPolicy,
      onEvent,
    });

    void prewarmThresholdEd25519ClientBaseFromCredential({
      context,
      credential,
      nearAccountId,
      signerSlot,
    }).catch(() => undefined);

    // Initialize current user for immediate use (best-effort).
    try {
      await signingEngine.initializeCurrentUser(nearAccountId, context.nearClient);
    } catch (initErr) {
      console.warn('Failed to initialize current user after registration:', initErr);
    }

    emitRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_11_COMPLETED,
      status: 'succeeded',
    });

    console.info('[Registration] flow timings', {
      nearAccountId,
      ...registrationTimingSummary,
      totalMs: Math.round(performance.now() - registrationStartedAt),
    });

    const successResult = {
      success: true,
      nearAccountId: nearAccountId,
      operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
      transactionId: registrationState.contractTransactionId,
    };

    afterCall?.(true, successResult);
    return successResult;
  } catch (error: unknown) {
    const errorCode =
      error && typeof error === 'object' && 'code' in error
        ? String((error as { code?: unknown }).code || '').trim()
        : '';
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
    const rollback = await performRegistrationRollback(registrationState, nearAccountId, signingEngine);

    // Use centralized error handling
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', nearAccountId);

    const errorObject = new Error(errorMessage);
    if (errorCode) {
      (errorObject as Error & { code?: string }).code = errorCode;
    }
    onError?.(errorObject);

    emitRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.FAILED,
      status: 'failed',
      message: errorMessage,
      interaction: {
        kind: 'passkey_create',
        overlay: 'hide',
      },
      error: {
        ...(errorCode ? { code: errorCode } : {}),
        message: errorMessage,
      },
      data: { rollback },
    });

    const result: RegistrationResult = {
      success: false,
      error: errorMessage,
      ...(errorCode ? { errorCode } : {}),
    };
    console.info('[Registration] flow timings', {
      nearAccountId,
      ...registrationTimingSummary,
      totalMs: Math.round(performance.now() - registrationStartedAt),
      failed: true,
    });
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
    configs: SeamsConfigsReadonly;
    signingEngine: SigningEnginePublic;
    nearClient: NearClient;
  },
  nearAccountId: AccountId,
  onEvent?: RegistrationHooksOptions['onEvent'],
  onError?: (error: Error) => void,
) => {
  emitRegistrationEvent(onEvent, nearAccountId, {
    phase: RegistrationEventPhase.STEP_02_ACCOUNT_PREFLIGHT_STARTED,
    status: 'running',
  });

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

  const accountExists = await checkNearAccountExistsBestEffort(
    context.nearClient,
    String(nearAccountId),
  );
  if (accountExists) {
    const error = new Error(`Account ${nearAccountId} already exists. Please log in instead.`);
    onError?.(error);
    throw error;
  }

  emitRegistrationEvent(onEvent, nearAccountId, {
    phase: RegistrationEventPhase.STEP_02_ACCOUNT_PREFLIGHT_SUCCEEDED,
    status: 'succeeded',
  });
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
): Promise<Record<string, unknown>> {
  console.debug('Starting registration rollback...', registrationState);
  const rollback: Record<string, unknown> = {
    databaseRolledBack: false,
    databasePreserved: false,
    onChainRollbackPossible: false,
    contractTransactionId: registrationState.contractTransactionId,
  };

  try {
    if (registrationState.databaseStored) {
      if (registrationState.accountCreated || registrationState.contractRegistered) {
        rollback.databasePreserved = true;
        rollback.databaseRollbackSkippedReason = 'on_chain_account_created';
        console.debug('Preserving local registration data because on-chain account state is immutable');
      } else {
        console.debug('Rolling back database storage...');
        await signingEngine.rollbackUserRegistration(nearAccountId);
        rollback.databaseRolledBack = true;
        console.debug('Database rollback completed');
      }
    }

    if (registrationState.contractRegistered) {
      console.debug('Registration transaction cannot be rolled back (immutable blockchain state)');
      rollback.onChainStateImmutable = true;
    }
    console.debug('Registration rollback completed');
  } catch (rollbackError: unknown) {
    console.error('Rollback failed:', rollbackError);
    rollback.rollbackError =
      rollbackError && typeof rollbackError === 'object' && 'message' in rollbackError
        ? String((rollbackError as { message?: unknown }).message || '')
        : String(rollbackError || '');
  }
  return rollback;
}

async function provisionThresholdEcdsaAfterRegistration(args: {
  context: PasskeyManagerContext;
  signingEngine: SigningEnginePublic;
  credential: WebAuthnRegistrationCredential;
  nearAccountId: AccountId;
  rpId: string;
  signerSlot: number;
  registrationContinuation?: Awaited<
    ReturnType<typeof createAccountAndRegisterWithRelayServer>
  >['registrationContinuation'];
  registrationSessionPolicy: ThresholdWarmSessionRequestEnvelope['session_policy'];
  onEvent?: RegistrationHooksOptions['onEvent'];
}): Promise<void> {
  const provisioningStartedAt = performance.now();
  const canonicalChain: 'tempo' | 'evm' = 'tempo';
  const timings: Record<string, number> = {};
  const logTelemetry = (payload: {
    outcome: 'success' | 'failure' | 'skipped';
    reason?: string;
    error?: string;
  }): void => {
    console.info('[registration-telemetry]', {
      event: 'post_registration_threshold_ecdsa_provisioning',
      nearAccountId: args.nearAccountId,
      chain: canonicalChain,
      ...payload,
      ...timings,
      totalMs: Math.round(performance.now() - provisioningStartedAt),
    });
  };
  const relayerUrl = String(args.context.configs.network.relayer.url || '').trim();
  const registrationContinuationToken = String(args.registrationContinuation?.token || '').trim();
  const remainingUses = Math.max(
    1,
    Math.floor(Number(args.registrationSessionPolicy.remainingUses) || 1),
  );
  const ttlMs = Math.max(1, Math.floor(Number(args.registrationSessionPolicy.ttlMs) || 1));

  if (!relayerUrl || !registrationContinuationToken) {
    emitRegistrationEvent(args.onEvent, args.nearAccountId, {
      phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SKIPPED,
      status: 'skipped',
      data: {
        reason: 'missing_registration_continuation_token',
      },
    });
    logTelemetry({
      outcome: 'skipped',
      reason: 'missing_registration_continuation_token',
    });
    return;
  }

  try {
    emitRegistrationEvent(args.onEvent, args.nearAccountId, {
      phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
      status: 'running',
    });

    const runtimePolicyScope = resolveRegistrationContinuationRuntimePolicyScope(
      registrationContinuationToken,
    );
    const clientRootShare32B64u = String(getPrfFirstB64uFromCredential(args.credential) || '').trim();
    if (!clientRootShare32B64u) {
      throw new Error('Failed to derive threshold ECDSA client root share from credential');
    }

    const configuredTargets = listConfiguredThresholdEcdsaPublicationTargets(
      args.context.configs.network.chains,
    );
    const continuationTargets = args.registrationContinuation?.thresholdEcdsaChainTargets || [];
    const continuationTargetKeys = new Set(
      continuationTargets.map((target) => thresholdEcdsaChainTargetKey(target)),
    );
    const missingContinuationTargets = configuredTargets
      .map((target) => thresholdEcdsaChainTargetKey(target.chainTarget))
      .filter((targetKey) => !continuationTargetKeys.has(targetKey));
    if (missingContinuationTargets.length > 0) {
      throw new Error(
        `[Registration] ECDSA registration continuation is missing configured targets: ${missingContinuationTargets.join(
          ', ',
        )}`,
      );
    }
    console.info('[Registration] threshold ECDSA provisioning targets', {
      nearAccountId: args.nearAccountId,
      targets: continuationTargets.map((chainTarget) => ({
        targetKey: thresholdEcdsaChainTargetKey(chainTarget),
        chainTarget,
      })),
    });

    const subjectId = walletSubjectIdFromWalletProfile({ walletId: args.nearAccountId });
    let sharedKeyIdentity: EvmFamilyEcdsaKeyIdentity | null = null;
    let sharedKeyHandle: EvmFamilyEcdsaKeyHandle | null = null;
    for (const chainTarget of continuationTargets) {
      const publicationChain = chainTarget.kind;
      const bootstrapStartedAt = performance.now();
      const thresholdSessionId = createThresholdRegistrationEcdsaSessionId();
      const walletSigningSessionId = generateWalletSigningSessionId();
      const lanePolicy = sharedKeyIdentity
        ? buildEvmFamilyEcdsaSessionLanePolicy({
            chainTarget,
            thresholdSessionId,
            walletSigningSessionId,
            thresholdSessionKind: 'jwt',
            ttlMs,
            remainingUses,
            runtimePolicyScope,
          })
        : null;
      const routeAuth = {
        kind: 'registration_continuation' as const,
        token: registrationContinuationToken,
      };
      if (sharedKeyIdentity && !sharedKeyHandle) {
        throw new Error('[Registration] threshold ECDSA shared keyHandle is missing');
      }
      const bootstrap =
        sharedKeyIdentity && sharedKeyHandle && lanePolicy
          ? await args.signingEngine.bootstrapEcdsaSession({
              kind: 'passkey_fresh_ecdsa_bootstrap',
              source: 'registration',
              relayerUrl,
              keyHandle: sharedKeyHandle,
              key: sharedKeyIdentity,
              lanePolicy,
              clientRootShare32B64u,
              routeAuth,
            })
          : await args.signingEngine.bootstrapEcdsaSession({
              kind: 'passkey_fresh_ecdsa_bootstrap',
              walletId: args.nearAccountId,
              chainTarget,
              source: 'registration',
              relayerUrl,
              sessionKind: 'jwt',
              sessionIdentity: buildEcdsaSessionIdentity({
                thresholdSessionId,
                walletSigningSessionId,
              }),
              clientRootShare32B64u,
              routeAuth,
              runtimePolicyScope,
              ttlMs,
              remainingUses,
            });
      timings[`bootstrapThresholdEcdsa${publicationChain === 'tempo' ? 'Tempo' : 'Evm'}Ms`] =
        Math.round(performance.now() - bootstrapStartedAt);

      const keyRef = bootstrap.thresholdEcdsaKeyRef;
      const identity = resolveRegistrationThresholdEcdsaBootstrapIdentity(bootstrap);
      const returnedEcdsaThresholdKeyId = identity.ecdsaThresholdKeyId;
      const ownerAddress = normalizeIndexedDbAccountAddress(
        bootstrap.keygen.ethereumAddress || keyRef.ethereumAddress,
      );
      if (!returnedEcdsaThresholdKeyId || !ownerAddress) {
        throw new Error('[Registration] threshold ECDSA bootstrap returned incomplete signer identity');
      }
      const returnedKeyIdentity = buildEvmFamilyEcdsaKeyIdentity({
        walletId: args.nearAccountId,
        subjectId,
        rpId: args.rpId,
        ecdsaThresholdKeyId: returnedEcdsaThresholdKeyId,
        signingRootId: identity.signingRootId,
        signingRootVersion: identity.signingRootVersion,
        participantIds: keyRef.participantIds || bootstrap.keygen.participantIds,
        thresholdOwnerAddress: bootstrap.keygen.ethereumAddress || keyRef.ethereumAddress,
      });
      if (!sharedKeyIdentity) {
        sharedKeyIdentity = returnedKeyIdentity;
        sharedKeyHandle = toEvmFamilyEcdsaKeyHandle(identity.keyHandle);
      } else if (
        deriveEvmFamilyKeyFingerprint(sharedKeyIdentity) !==
        deriveEvmFamilyKeyFingerprint(returnedKeyIdentity)
      ) {
        throw new Error('[Registration] threshold ECDSA bootstrap returned divergent shared key identity');
      }
      await persistRegistrationThresholdEcdsaProfileSigner({
        nearAccountId: args.nearAccountId,
        chainTarget,
        key: sharedKeyIdentity,
        bootstrap,
        signerSlot: args.signerSlot,
      });
      const thresholdSessionAuthTokenSource = String(keyRef.thresholdSessionAuthToken || '').trim()
        ? 'ecdsa'
        : 'none';
      const accountAddressForLog = ownerAddress || null;
      console.info('[Registration] threshold ECDSA background provisioned', {
        nearAccountId: args.nearAccountId,
        chain: publicationChain,
        ecdsaThresholdKeyId: returnedEcdsaThresholdKeyId,
        relayerKeyId: keyRef.backendBinding?.relayerKeyId,
        thresholdSessionId: keyRef.thresholdSessionId,
        walletSigningSessionId: keyRef.walletSigningSessionId,
        remainingUses: bootstrap.session.remainingUses,
        expiresAtMs: bootstrap.session.expiresAtMs,
        thresholdSessionAuthTokenSource,
        accountAddress: accountAddressForLog,
        durationMs:
          timings[`bootstrapThresholdEcdsa${publicationChain === 'tempo' ? 'Tempo' : 'Evm'}Ms`],
      });
    }
    emitRegistrationEvent(args.onEvent, args.nearAccountId, {
      phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED,
      status: 'succeeded',
      data: {
        chain: canonicalChain,
        ...timings,
      },
    });
    logTelemetry({
      outcome: 'success',
    });
  } catch (error: unknown) {
    logTelemetry({
      outcome: 'failure',
      error: error instanceof Error ? error.message : String(error || 'unknown error'),
    });
    throw error;
  }
}
