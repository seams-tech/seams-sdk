import type { NearClient } from '../rpcClients/near/NearClient';
import { validateNearAccountId } from '@shared/utils/validation';
import type { RegistrationHooksOptions, RegistrationSSEEvent } from '../types/sdkSentEvents';
import type { RegistrationResult, TatchiConfigsReadonly } from '../types/tatchi';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import { RegistrationPhase, RegistrationStatus } from '../types/sdkSentEvents';
import { createAccountAndRegisterWithRelayServer } from './faucets/createAccountRelayServer';
import { PasskeyManagerContext } from './index';
import {
  type CompletedThresholdEd25519Registration,
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
import { getPrfResultsFromCredential } from '../signingEngine/signers/webauthn/credentials/credentialExtensions';

// Registration forces a visible, clickable confirmation for cross‑origin safety

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

    const deviceNumber = 1;
    let thresholdPrfFirstB64u: string | null = null;

    const rpId = signingEngine.getRpId();
    if (!rpId) {
      throw new Error('Missing rpId for relay registration');
    }
    onEvent?.({
      step: 2,
      phase: RegistrationPhase.STEP_2_KEY_GENERATION,
      status: RegistrationStatus.PROGRESS,
      message: 'Preparing threshold Ed25519 registration material...',
    });
    const thresholdEd25519Registration = await prepareThresholdEd25519RegistrationWithHss({
      context,
      credential,
      nearAccountId,
      rpId,
      authenticatorOptions,
      onProgress: (message) => {
        onEvent?.({
          step: 2,
          phase: RegistrationPhase.STEP_2_KEY_GENERATION,
          status: RegistrationStatus.PROGRESS,
          message,
        });
      },
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
    onEvent?.({
      step: 2,
      phase: RegistrationPhase.STEP_2_KEY_GENERATION,
      status: RegistrationStatus.SUCCESS,
      message: 'Prepared threshold Ed25519 Option A registration material from passkey',
      verified: true,
      nearAccountId: nearAccountId,
      nearPublicKey: thresholdEd25519Registration.registrationInput.publicKey,
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
    onEvent?.({
      step: 6,
      phase: RegistrationPhase.STEP_6_ACCOUNT_VERIFICATION,
      status: RegistrationStatus.PROGRESS,
      message: 'Verifying on-chain bootstrap access keys...',
    });

    const completedThresholdEd25519Registration = completeRegisteredThresholdEd25519Registration({
      thresholdEd25519: accountAndRegistrationResult?.thresholdEd25519,
      expectedSessionPolicy: thresholdEd25519Registration.registrationInput.sessionPolicy,
    });
    onEvent?.({
      step: 6,
      phase: RegistrationPhase.STEP_6_ACCOUNT_VERIFICATION,
      status: RegistrationStatus.SUCCESS,
      message: 'Account creation accepted; final access-key visibility is reconciling on-chain',
    });

    onEvent?.({
      step: 7,
      phase: RegistrationPhase.STEP_7_THRESHOLD_KEY_ENROLLMENT,
      status: RegistrationStatus.PROGRESS,
      message: 'Confirming threshold key…',
      thresholdPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
      relayerKeyId: completedThresholdEd25519Registration.registered.relayerKeyId,
      deviceNumber,
    });

    onEvent?.({
      step: 7,
      phase: RegistrationPhase.STEP_7_THRESHOLD_KEY_ENROLLMENT,
      status: RegistrationStatus.SUCCESS,
      message: 'Threshold key ready',
      thresholdKeyReady: true,
      thresholdPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
      relayerKeyId: completedThresholdEd25519Registration.registered.relayerKeyId,
      deviceNumber,
    });

    // Step 8: Store user data + authenticator locally
    onEvent?.({
      step: 8,
      phase: RegistrationPhase.STEP_8_DATABASE_STORAGE,
      status: RegistrationStatus.PROGRESS,
      message: 'Storing passkey wallet metadata...',
    });

    const localPersistenceStartedAt = performance.now();
    await signingEngine.atomicStoreRegistrationData({
      nearAccountId,
      credential,
      operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
    });
    await persistRegisteredThresholdEd25519Session({
      signingEngine,
      nearAccountId,
      deviceNumber,
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

    onEvent?.({
      step: 8,
      phase: RegistrationPhase.STEP_8_DATABASE_STORAGE,
      status: RegistrationStatus.SUCCESS,
      message: 'Registration metadata stored successfully',
    });

    void provisionThresholdEcdsaAfterRegistration({
      context,
      signingEngine,
      credential,
      nearAccountId,
      completedThresholdEd25519Registration,
    }).catch((error: unknown) => {
      console.warn(
        '[Registration] threshold ECDSA background provisioning failed:',
        error instanceof Error ? error.message : String(error || 'unknown error'),
      );
    });

    void prewarmThresholdEd25519ClientBaseFromCredential({
      context,
      credential,
      nearAccountId,
      deviceNumber,
    }).catch(() => undefined);

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
    await performRegistrationRollback(registrationState, nearAccountId, signingEngine, onEvent);

    // Use centralized error handling
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', nearAccountId);

    const errorObject = new Error(errorMessage);
    if (errorCode) {
      (errorObject as Error & { code?: string }).code = errorCode;
    }
    onError?.(errorObject);

    onEvent?.({
      step: 0,
      phase: RegistrationPhase.REGISTRATION_ERROR,
      status: RegistrationStatus.ERROR,
      message: errorMessage,
      error: errorMessage,
    } as RegistrationSSEEvent);

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

async function provisionThresholdEcdsaAfterRegistration(args: {
  context: PasskeyManagerContext;
  signingEngine: SigningEnginePublic;
  credential: WebAuthnRegistrationCredential;
  nearAccountId: AccountId;
  completedThresholdEd25519Registration: CompletedThresholdEd25519Registration;
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
  const thresholdSessionJwt = String(
    args.completedThresholdEd25519Registration.registered.session?.jwt || '',
  ).trim();
  const thresholdSessionId = String(
    args.completedThresholdEd25519Registration.registered.session?.sessionId || '',
  ).trim();

  if (!relayerUrl || !thresholdSessionJwt || !thresholdSessionId) {
    logTelemetry({
      outcome: 'skipped',
      reason: 'missing_ed25519_session_auth',
    });
    return;
  }

  try {
    const deriveStartedAt = performance.now();
    const derived = await args.signingEngine.deriveThresholdEcdsaClientVerifyingShareFromCredential(
      {
        credential: args.credential,
        nearAccountId: args.nearAccountId,
      },
    );
    timings.deriveThresholdEcdsaClientShareMs = Math.round(performance.now() - deriveStartedAt);
    if (!derived.success || !derived.clientVerifyingShareB64u) {
      throw new Error(
        derived.error || 'Failed to derive threshold ECDSA client verifying share from credential',
      );
    }

    const bootstrapStartedAt = performance.now();
    const bootstrap = await args.signingEngine.bootstrapEcdsaSession({
      nearAccountId: args.nearAccountId,
      chain: canonicalChain,
      source: 'registration',
      relayerUrl,
      sessionKind: 'jwt',
      sessionId: thresholdSessionId,
      clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
      authorizationJwt: thresholdSessionJwt,
    });
    timings.bootstrapThresholdEcdsaMs = Math.round(performance.now() - bootstrapStartedAt);

    const keyRef = bootstrap.thresholdEcdsaKeyRef;
    const thresholdSessionJwtSource = String(keyRef.thresholdSessionJwt || '').trim()
      ? 'ecdsa'
      : 'none';
    console.info('[Registration] threshold ECDSA background provisioned', {
      nearAccountId: args.nearAccountId,
      chain: canonicalChain,
      relayerKeyId: keyRef.relayerKeyId,
      thresholdSessionId: keyRef.thresholdSessionId,
      thresholdSessionJwtSource,
      accountAddress:
        bootstrap.keygen.counterfactualAddress || bootstrap.keygen.ethereumAddress || null,
      durationMs: timings.bootstrapThresholdEcdsaMs,
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
