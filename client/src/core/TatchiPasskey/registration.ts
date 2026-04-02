import type { NearClient } from '../rpcClients/near/NearClient';
import { validateNearAccountId } from '@shared/utils/validation';
import type { RegistrationHooksOptions, RegistrationSSEEvent } from '../types/sdkSentEvents';
import type { RegistrationResult, TatchiConfigsReadonly } from '../types/tatchi';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import { RegistrationPhase, RegistrationStatus } from '../types/sdkSentEvents';
import { createAccountAndRegisterWithRelayServer } from './faucets/createAccountRelayServer';
import { PasskeyManagerContext } from './index';
import {
  completeRegisteredThresholdEd25519Registration,
  prewarmThresholdEd25519ClientBaseFromCredential,
  prepareThresholdEd25519RegistrationWithHss,
  persistRegisteredThresholdEd25519Session,
} from './thresholdWarmSessionBootstrap';
import type {
  SigningEnginePublic,
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../signingEngine/SigningEngine';
import { type ConfirmationConfig } from '../types/signer-worker';
import type { AccountId } from '../types/accountIds';
import { getUserFriendlyErrorMessage } from '@shared/utils/errors';
import { checkNearAccountExistsBestEffort } from '../rpcClients/near/rpcCalls';
import { getPrfResultsFromCredential } from '../signingEngine/signers/webauthn/credentials/credentialExtensions';
import {
  THRESHOLD_SESSION_POLICY_VERSION,
  generateThresholdSessionId,
} from '../signingEngine/threshold/session/sessionPolicy';
import {
  listThresholdEcdsaProvisionTargets,
  toRegistrationSmartAccountTarget,
  toSmartAccountBootstrapInput,
} from './thresholdEcdsaProvisioning';

// Registration forces a visible, clickable confirmation for cross‑origin safety

function coercePositiveInt(value: unknown, fallback: number): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return Math.max(1, Math.floor(fallback));
  return Math.floor(n);
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

    const provisioningDefaults =
      options?.signerOptions || configs.signing.thresholdEcdsa.provisioningDefaults;
    const thresholdEcdsaProvisionTargets = listThresholdEcdsaProvisionTargets(provisioningDefaults);
    const thresholdEcdsaPrimaryProvisionTarget = thresholdEcdsaProvisionTargets[0] || null;
    const thresholdEcdsaSmartAccountTargetsForRegistration = thresholdEcdsaProvisionTargets
      .map((target) => toRegistrationSmartAccountTarget(target.chain, target.options.smartAccount))
      .filter((target): target is NonNullable<typeof target> => Boolean(target));

    const deviceNumber = 1;
    let thresholdEcdsaClientVerifyingShareB64u: string | null = null;
    let thresholdPrfFirstB64u: string | null = null;
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
    const derivedEcdsa = await signingEngine.deriveThresholdEcdsaClientVerifyingShareFromCredential(
      {
        credential,
        nearAccountId,
      },
    );
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

    if (thresholdEcdsaClientVerifyingShareB64u && thresholdEcdsaPrimaryProvisionTarget) {
      const thresholdEcdsaSessionId = generateThresholdSessionId();
      thresholdEcdsaSessionKindForRegistration =
        thresholdEcdsaPrimaryProvisionTarget.options.signingSession.kind;
      if (thresholdEcdsaSessionKindForRegistration !== 'jwt') {
        throw new Error('Threshold ECDSA registration bootstrap requires sessionKind=jwt');
      }
      thresholdEcdsaSessionPolicyForRegistration = {
        version: THRESHOLD_SESSION_POLICY_VERSION,
        userId: String(nearAccountId),
        rpId,
        sessionId: thresholdEcdsaSessionId,
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
      credential,
      rpId,
      authenticatorOptions,
      onEvent,
      {
        thresholdEd25519: {
          ...thresholdEd25519Registration.registrationInput,
        },
        thresholdEcdsa:
          thresholdEcdsaClientVerifyingShareB64u && thresholdEcdsaSessionPolicyForRegistration
            ? {
                clientVerifyingShareB64u: thresholdEcdsaClientVerifyingShareB64u,
                sessionPolicy: thresholdEcdsaSessionPolicyForRegistration,
                sessionKind: thresholdEcdsaSessionKindForRegistration,
                ...(thresholdEcdsaSmartAccountTargetsForRegistration.length > 0
                  ? { smartAccountTargets: thresholdEcdsaSmartAccountTargetsForRegistration }
                  : {}),
              }
            : undefined,
      },
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
    const thresholdEcdsaRelayerKeyId = String(
      accountAndRegistrationResult?.thresholdEcdsa?.relayerKeyId || '',
    ).trim();
    const thresholdEcdsaGroupPublicKeyB64u = String(
      accountAndRegistrationResult?.thresholdEcdsa?.groupPublicKeyB64u || '',
    ).trim();
    const thresholdEcdsaRelayerVerifyingShareB64u = String(
      accountAndRegistrationResult?.thresholdEcdsa?.relayerVerifyingShareB64u || '',
    ).trim();
    const thresholdEcdsaSession = accountAndRegistrationResult?.thresholdEcdsa?.session;
    const thresholdEcdsaEthereumAddress = String(
      accountAndRegistrationResult?.thresholdEcdsa?.ethereumAddress || '',
    ).trim();
    const thresholdEcdsaDeployments = Array.isArray(
      accountAndRegistrationResult?.smartAccountDeployments,
    )
      ? accountAndRegistrationResult.smartAccountDeployments
      : [];

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
    onEvent?.({
      step: 6,
      phase: RegistrationPhase.STEP_6_ACCOUNT_VERIFICATION,
      status: RegistrationStatus.SUCCESS,
      message: 'Relay verified operational access key on-chain',
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

    const thresholdEcdsaKeyRef =
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

    await signingEngine.atomicStoreRegistrationData({
      nearAccountId,
      credential,
      operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
    });

    // Mark database as stored for rollback tracking
    registrationState.databaseStored = true;

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

    onEvent?.({
      step: 8,
      phase: RegistrationPhase.STEP_8_DATABASE_STORAGE,
      status: RegistrationStatus.SUCCESS,
      message: 'Registration metadata stored successfully',
    });

    void prewarmThresholdEd25519ClientBaseFromCredential({
      context,
      credential,
      nearAccountId,
      deviceNumber,
    }).catch(() => undefined);

    if (thresholdPrfFirstB64u) {
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
          signerKind:
            thresholdEcdsaPrimaryProvisionTarget?.chain === 'evm'
              ? 'threshold-ecdsa-evm'
              : 'threshold-ecdsa-tempo',
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

        const sessionProvisionChains = new Set<'tempo' | 'evm'>(
          thresholdEcdsaProvisionTargets.map((target) => target.chain),
        );
        if (sessionProvisionChains.size === 0) {
          sessionProvisionChains.add(thresholdEcdsaPrimaryProvisionTarget?.chain || 'tempo');
        }
        for (const chain of sessionProvisionChains) {
          signingEngine.upsertThresholdEcdsaSessionFromBootstrap({
            nearAccountId,
            chain,
            bootstrap: bootstrapProjection,
            source: 'registration',
          });
        }

        for (const target of thresholdEcdsaProvisionTargets) {
          const smartAccountBootstrap = toSmartAccountBootstrapInput(
            target.chain,
            target.options.smartAccount,
          );
          const smartAccountDeployment =
            smartAccountBootstrap &&
            thresholdEcdsaDeployments.find(
              (deployment) =>
                deployment.chain === target.chain &&
                Number(deployment.chainId) === Number(smartAccountBootstrap.chainId),
            );
          await signingEngine.persistThresholdEcdsaBootstrapChainAccount({
            nearAccountId,
            chain: target.chain,
            bootstrap: bootstrapProjection,
            smartAccount: smartAccountBootstrap,
            ...(smartAccountDeployment
              ? {
                  deployment: {
                    deployed: smartAccountDeployment.deployed === true,
                    ...(smartAccountDeployment.deploymentTxHash
                      ? { deploymentTxHash: smartAccountDeployment.deploymentTxHash }
                      : {}),
                  },
                }
              : {}),
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
      operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
      transactionId: registrationState.contractTransactionId,
      ...(thresholdEcdsaEthereumAddress ? { thresholdEcdsaEthereumAddress } : {}),
      ...(thresholdEcdsaGroupPublicKeyB64u ? { thresholdEcdsaGroupPublicKeyB64u } : {}),
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
