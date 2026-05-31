import type { NearClient } from '../rpcClients/near/NearClient';
import { validateNearAccountId } from '@shared/utils/validation';
import type {
  CreateRegistrationFlowEventInput,
  RegistrationHooksOptions,
} from '../types/sdkSentEvents';
import type { RegistrationResult, SeamsConfigsReadonly } from '../types/seams';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import { createRegistrationFlowEvent, RegistrationEventPhase } from '../types/sdkSentEvents';
import { createManagedRegistrationFlowGrant } from './faucets/createAccountRelayServer';
import { PasskeyManagerContext } from './index';
import {
  buildThresholdWarmSessionRequestEnvelope,
  buildThresholdEd25519RegistrationHssClientOwnedArtifact,
  completeRegisteredThresholdEd25519Registration,
  createThresholdWarmSessionPolicyDraft,
  prewarmThresholdEd25519ClientBaseFromCredential,
  prepareThresholdEd25519RegistrationHssClientMaterial,
  prepareThresholdEd25519RegistrationHssClientMaterialFromPrfFirst,
  prepareThresholdEd25519RegistrationHssClientRequest,
  persistRegisteredThresholdEd25519Session,
} from './thresholdWarmSessionBootstrap';
import type { SigningEnginePublic } from '../signingEngine/SigningEngine';
import { type ConfirmationConfig } from '../types/signer-worker';
import { toAccountId, type AccountId } from '../types/accountIds';
import { getUserFriendlyErrorMessage } from '@shared/utils/errors';
import { checkNearAccountExistsBestEffort } from '../rpcClients/near/rpcCalls';
import { redactCredentialExtensionOutputs } from '../signingEngine/webauthnAuth/credentials/credentialExtensions';
import { derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential } from '../signingEngine/session/passkey/ecdsaClientRoot';
import { normalizeRegistrationCredential } from '../signingEngine/webauthnAuth/credentials/helpers';
import { IndexedDBManager } from '../indexedDB';
import type { WebAuthnRegistrationCredential } from '../types/webauthn';
import type { ThresholdRuntimePolicyScope } from '../signingEngine/threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  AddSignerSelection,
  RegistrationAuthMethodInput,
  RegisterWalletInput,
  RegistrationSignerSelection,
  ThresholdEcdsaRegistrationSpec,
  WalletId,
} from '@shared/utils/registrationIntent';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  thresholdEcdsaChainTargetFromRequest,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../signingEngine/interfaces/ecdsaChainTarget';
import { computeRegistrationIntentDigest } from '@/utils/intentDigest';
import { computeAddSignerIntentDigest } from '@/utils/intentDigest';
import {
  createWalletAddSignerIntent,
  createWalletRegistrationIntent,
  finalizeWalletAddSigner,
  finalizeWalletRegistration,
  parseWalletRegistrationEcdsaHssRespond,
  respondWalletAddSignerHss,
  respondWalletRegistrationHss,
  startWalletAddSigner,
  startWalletRegistration,
  type WalletRegistrationEcdsaWalletKey,
} from '../rpcClients/relayer/walletRegistration';
import { buildPasskeyNearWalletRegistrationSignerSelection } from './registrationSignerSelection';
import { collectPasskeyRegistrationAuthority } from './passkeyRegistrationAuthority';
import { collectEmailOtpRegistrationAuthority } from './emailOtpRegistrationAuthority';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../signingEngine/session/identity/laneIdentity';
import { assertWalletRuntimePostconditions } from '../signingEngine/session/postconditions/runtimePostconditions';

// Registration forces a visible, clickable confirmation for cross-origin safety.

type EmitRegistrationEventInput = Omit<CreateRegistrationFlowEventInput, 'accountId' | 'flowId'>;

function emitRegistrationEvent(
  onEvent: RegistrationHooksOptions['onEvent'] | undefined,
  nearAccountId: AccountId,
  event: EmitRegistrationEventInput,
): void {
  const authMethod = event.authMethod || 'passkey';
  onEvent?.(
    createRegistrationFlowEvent({
      ...event,
      flowId: `registration:${authMethod}:${nearAccountId}`,
      accountId: String(nearAccountId),
      authMethod,
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
  const accountId = toAccountId(nearAccountId);
  const iframeRpId = String(context.configs.wallet.iframe.rpIdOverride || '').trim();
  const rpId = iframeRpId || context.signingEngine.getRpId();
  if (!rpId) {
    throw new Error('Missing rpId for relay registration');
  }
  return await registerWallet({
    context,
    wallet: {
      kind: 'provided',
      walletId: walletIdFromString(String(accountId)),
    },
    rpId,
    authMethod: { kind: 'passkey' },
    signerSelection: buildPasskeyNearWalletRegistrationSignerSelection({
      configs: context.configs,
      nearAccountId: String(accountId),
      options,
    }),
    options,
    authenticatorOptions,
    ...(confirmationConfigOverride ? { confirmationConfigOverride } : {}),
  });
}

function buildRegistrationEmailOtpAuthContext(args: {
  configs: SeamsConfigsReadonly;
  providerSubject: string;
}): ThresholdEcdsaEmailOtpAuthContext {
  const policy = args.configs.signing.emailOtp.authPolicy;
  const authSubjectId = String(args.providerSubject || '').trim();
  if (!authSubjectId) {
    throw new Error('Email OTP registration auth context requires providerSubject');
  }
  return {
    policy,
    retention: 'session',
    reason: 'login',
    authMethod: SIGNER_AUTH_METHODS.emailOtp,
    authSubjectId,
  };
}

async function assertImmediateRegistrationSigningLanes(args: {
  signingEngine: SigningEnginePublic;
  walletId: string;
  authMethod: 'passkey' | 'email_otp';
  expectEd25519: boolean;
  expectedEcdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
}): Promise<void> {
  await assertWalletRuntimePostconditions({
    source: 'registration_finalize',
    walletId: args.walletId,
    authMethod: args.authMethod,
    requiredTargets: [
      ...(args.expectEd25519 ? [{ curve: 'ed25519' as const }] : []),
      ...args.expectedEcdsaChainTargets.map((chainTarget) => ({
        curve: 'ecdsa' as const,
        chainTarget,
      })),
    ],
    readPersistedAvailableSigningLanes: async (input) =>
      await args.signingEngine.readPersistedAvailableSigningLanes(input),
  });
}

function expectedEcdsaChainTargetsFromRegistrationSpec(
  ecdsa: ThresholdEcdsaRegistrationSpec,
): ThresholdEcdsaChainTarget[] {
  return ecdsa.chainTargets.map((target) => {
    if (!target || typeof target !== 'object') {
      throw new Error('[Registration][postcondition] invalid ECDSA chain target');
    }
    return thresholdEcdsaChainTargetFromRequest(target as Record<string, unknown>);
  });
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

async function registerEcdsaWalletOnly(args: {
  context: PasskeyManagerContext;
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  rpId: string;
  signerSelection: Extract<RegistrationSignerSelection, { mode: 'ecdsa_only' }>;
  options: RegistrationHooksOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
}): Promise<RegistrationResult> {
  const { context, wallet, signerSelection } = args;
  const options = args.options || {};
  const { onEvent, onError, afterCall } = options;
  const startedAt = performance.now();
  const rpId = String(args.rpId || '').trim();
  const initialEventAccountId = String(
    wallet.kind === 'provided' ? wallet.walletId : 'wallet-registration',
  ) as AccountId;

  if (!rpId) {
    throw new Error('registerWallet requires rpId');
  }

  emitRegistrationEvent(onEvent, initialEventAccountId, {
    authMethod: args.authMethod.kind,
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });

  try {
    const relayerUrl = String(context.configs.network.relayer.url || '').trim();
    if (!relayerUrl) {
      throw new Error('registerWallet requires relayer.url');
    }

    const managedGrant = await createManagedRegistrationFlowGrant({
      context,
      ...(wallet.kind === 'provided' ? { walletId: String(wallet.walletId || '').trim() } : {}),
      rpId,
    });
    const intentResponse = await createWalletRegistrationIntent({
      relayerUrl,
      request: {
        wallet,
        rpId,
        authMethod: args.authMethod,
        signerSelection,
      },
      headers: {
        Authorization: `Bearer ${managedGrant.token}`,
      },
    });
    const localDigestB64u = await computeRegistrationIntentDigest(intentResponse.intent);
    if (localDigestB64u !== intentResponse.registrationIntentDigestB64u) {
      throw new Error('Registration intent digest mismatch');
    }

    const walletId = intentResponse.intent.walletId;
    const eventAccountId = String(walletId) as AccountId;
    let clientRootShare32B64u = '';
    let emailOtpClientRootShareHandle:
      | Awaited<
          ReturnType<SigningEnginePublic['prepareEmailOtpRegistrationEnrollmentMaterialInternal']>
        >['clientRootShareHandle']
      | null = null;
    let emailOtpChallengeId = '';
    let emailOtpEmail = '';
    let emailOtpProviderSubject = '';
    let emailOtpEnrollment:
      | Awaited<
          ReturnType<SigningEnginePublic['prepareEmailOtpRegistrationEnrollmentMaterialInternal']>
        >['emailOtpEnrollment']
      | null = null;
    let passkeyAuthority: Awaited<ReturnType<typeof collectPasskeyRegistrationAuthority>> | null =
      null;
    let startAuthority:
      | {
          kind: 'passkey';
          webauthnRegistration: unknown;
        }
      | {
          kind: 'email_otp';
          emailOtpRegistrationProof: Awaited<
            ReturnType<typeof collectEmailOtpRegistrationAuthority>
          >['proof'];
        };
    if (args.authMethod.kind === 'passkey') {
      emitRegistrationEvent(onEvent, eventAccountId, {
        authMethod: args.authMethod.kind,
        phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_STARTED,
        status: 'waiting_for_user',
        interaction: {
          kind: 'passkey_create',
          overlay: 'show',
        },
      });
      const confirmationConfig: Partial<ConfirmationConfig> = {
        uiMode: 'modal',
        behavior: 'requireClick',
        ...(args.confirmationConfigOverride ?? options?.confirmationConfig ?? {}),
      };
      passkeyAuthority = await collectPasskeyRegistrationAuthority({
        context,
        walletId: String(walletId),
        signerSlot: 1,
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
        options,
        confirmationConfigOverride: confirmationConfig,
      });
      clientRootShare32B64u = passkeyAuthority.ecdsaClientRootShare32B64u;
      startAuthority = {
        kind: 'passkey',
        webauthnRegistration: passkeyAuthority.webauthnRegistration,
      };
      emitRegistrationEvent(onEvent, eventAccountId, {
        authMethod: args.authMethod.kind,
        phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_SUCCEEDED,
        status: 'succeeded',
        interaction: {
          kind: 'passkey_create',
          overlay: 'hide',
        },
      });
    } else {
      const emailAuthority = await collectEmailOtpRegistrationAuthority({
        authMethod: args.authMethod,
        relayUrl: relayerUrl,
        walletId: String(walletId),
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
        appSessionJwt: args.authMethod.appSessionJwt,
      });
      const enrollment =
        await context.signingEngine.prepareEmailOtpRegistrationEnrollmentMaterialInternal({
          relayUrl: relayerUrl,
          walletId: toWalletId(walletId),
          userId: emailAuthority.providerSubject,
          rpId,
          appSessionJwt: args.authMethod.appSessionJwt,
        });
      emailOtpClientRootShareHandle = enrollment.clientRootShareHandle;
      emailOtpEnrollment = enrollment.emailOtpEnrollment;
      emailOtpChallengeId = emailAuthority.challengeId;
      emailOtpEmail = emailAuthority.email;
      emailOtpProviderSubject = emailAuthority.providerSubject;
      startAuthority = {
        kind: 'email_otp',
        emailOtpRegistrationProof: emailAuthority.proof,
      };
    }

    emitRegistrationEvent(onEvent, eventAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_STARTED,
      status: 'running',
    });
    const startedCeremony = await startWalletRegistration({
      relayerUrl,
      registrationIntentGrant: intentResponse.registrationIntentGrant,
      registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
      intent: intentResponse.intent,
      ...startAuthority,
    });
    if (!startedCeremony.ecdsa) {
      throw new Error('Wallet registration start did not return ECDSA HSS material');
    }
    const ecdsaPrepare = startedCeremony.ecdsa.prepare;
    const preparedClientBootstrap =
      args.authMethod.kind === 'email_otp'
        ? await (async () => {
            if (!emailOtpClientRootShareHandle) {
              throw new Error('Email OTP ECDSA registration prepare is missing worker handle');
            }
            return await context.signingEngine.prepareWalletRegistrationEcdsaPreparedClientBootstrapFromEmailOtpHandle(
              {
                prepare: ecdsaPrepare,
                clientRootShareHandle: emailOtpClientRootShareHandle,
              },
            );
          })()
        : await context.signingEngine.prepareWalletRegistrationEcdsaPreparedClientBootstrap({
            prepare: ecdsaPrepare,
            clientRootShare32B64u,
          });
    const responded = await respondWalletRegistrationHss({
      relayerUrl,
      registrationCeremonyId: startedCeremony.registrationCeremonyId,
      ecdsa: { clientBootstrap: preparedClientBootstrap.clientBootstrap },
    });
    if (!responded.ecdsa?.bootstrap) {
      throw new Error('Wallet registration HSS respond did not return ECDSA bootstrap material');
    }
    const ecdsaBootstrap = parseWalletRegistrationEcdsaHssRespond({
      localBootstrap: preparedClientBootstrap.localClientBootstrap,
      serverBootstrap: responded.ecdsa.bootstrap,
    });
    const finalized = await finalizeWalletRegistration({
      relayerUrl,
      registrationCeremonyId: startedCeremony.registrationCeremonyId,
      ecdsa: {
        expectedKeyHandles: [ecdsaBootstrap.keyHandle],
      },
      ...(emailOtpEnrollment ? { emailOtpEnrollment } : {}),
    });
    const walletKeys = finalized.ecdsa?.walletKeys || [];
    if (walletKeys.length === 0) {
      throw new Error('Wallet registration finalize did not return ECDSA wallet keys');
    }
    emitRegistrationEvent(onEvent, eventAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_SUCCEEDED,
      status: 'succeeded',
    });

    emitRegistrationEvent(onEvent, eventAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
      status: 'running',
    });
    await context.signingEngine.persistWalletRegistrationEcdsaBootstrapForWalletKeys({
      walletId: toWalletId(finalized.walletId),
      relayerUrl,
      preparedClientBootstrap,
      bootstrap: ecdsaBootstrap,
      walletKeys,
      auth:
        args.authMethod.kind === 'email_otp'
          ? {
              kind: 'email_otp',
              emailOtpAuthContext: buildRegistrationEmailOtpAuthContext({
                configs: context.configs,
                providerSubject: emailOtpProviderSubject,
              }),
            }
          : { kind: 'passkey' },
    });
    if (args.authMethod.kind === 'passkey') {
      if (!passkeyAuthority) {
        throw new Error('Passkey registration authority was not collected');
      }
      await context.signingEngine.storeWalletEcdsaRegistrationData({
        walletId: finalized.walletId,
        credential: passkeyAuthority.credential,
        walletKeys,
      });
    } else {
      await context.signingEngine.storeWalletEmailOtpEcdsaRegistrationData({
        walletId: finalized.walletId,
        email: emailOtpEmail,
        challengeId: emailOtpChallengeId,
        walletKeys,
      });
    }
    await assertImmediateRegistrationSigningLanes({
      signingEngine: context.signingEngine,
      walletId: finalized.walletId,
      authMethod: args.authMethod.kind,
      expectEd25519: false,
      expectedEcdsaChainTargets: expectedEcdsaChainTargetsFromRegistrationSpec(
        signerSelection.ecdsa,
      ),
    });
    emitRegistrationEvent(onEvent, eventAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
      status: 'succeeded',
    });
    emitRegistrationEvent(onEvent, eventAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_11_COMPLETED,
      status: 'succeeded',
    });

    const primaryKey = walletKeys[0];
    const result: RegistrationResult = {
      success: true,
      thresholdEcdsaEthereumAddress: primaryKey.thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u: primaryKey.thresholdEcdsaPublicKeyB64u,
    };
    console.info('[Registration] ECDSA wallet flow timings', {
      walletId: String(finalized.walletId),
      totalMs: Math.round(performance.now() - startedAt),
    });
    afterCall?.(true, result);
    return result;
  } catch (error: unknown) {
    const errorCode =
      error && typeof error === 'object' && 'code' in error
        ? String((error as { code?: unknown }).code || '').trim()
        : '';
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', initialEventAccountId);
    const errorObject = new Error(errorMessage);
    if (errorCode) {
      (errorObject as Error & { code?: string }).code = errorCode;
    }
    onError?.(errorObject);
    emitRegistrationEvent(onEvent, initialEventAccountId, {
      authMethod: args.authMethod.kind,
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
    });
    const result: RegistrationResult = {
      success: false,
      error: errorMessage,
      ...(errorCode ? { errorCode } : {}),
    };
    console.info('[Registration] ECDSA wallet flow timings', {
      walletId: wallet.kind === 'provided' ? String(wallet.walletId) : undefined,
      totalMs: Math.round(performance.now() - startedAt),
      failed: true,
    });
    afterCall?.(false);
    return result;
  }
}

export async function registerWallet(args: {
  context: PasskeyManagerContext;
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  rpId: string;
  signerSelection: RegistrationSignerSelection;
  options: RegistrationHooksOptions;
  authenticatorOptions: AuthenticatorOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
}): Promise<RegistrationResult> {
  const { context, wallet, signerSelection } = args;
  const options = args.options || {};
  const { onEvent, onError, afterCall } = options;
  const registrationStartedAt = performance.now();
  const registrationTimingSummary: Record<string, number> = {};
  const registrationState = {
    accountCreated: false,
    contractRegistered: false,
    databaseStored: false,
    contractTransactionId: null as string | null,
  };

  if (signerSelection.mode === 'ecdsa_only') {
    return await registerEcdsaWalletOnly({
      context,
      authMethod: args.authMethod,
      wallet,
      rpId: args.rpId,
      signerSelection,
      options,
      ...(args.confirmationConfigOverride
        ? { confirmationConfigOverride: args.confirmationConfigOverride }
        : {}),
    });
  }
  if (signerSelection.mode !== 'ed25519_only' && signerSelection.mode !== 'ed25519_and_ecdsa') {
    throw new Error(
      'Unified wallet registration currently supports ed25519_only, ecdsa_only, and ed25519_and_ecdsa signer selection',
    );
  }

  const ed25519Selection = signerSelection.ed25519;
  const ecdsaSelection =
    signerSelection.mode === 'ed25519_and_ecdsa' ? signerSelection.ecdsa : null;
  const nearAccountId = toAccountId(ed25519Selection.nearAccountId);
  const rpId = String(args.rpId || '').trim();
  if (!rpId) {
    throw new Error('registerWallet requires rpId');
  }

  emitRegistrationEvent(onEvent, nearAccountId, {
    authMethod: args.authMethod.kind,
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });

  try {
    await validateRegistrationInputs(
      context,
      nearAccountId,
      args.authMethod.kind,
      onEvent,
      onError,
    );

    const relayerUrl = String(context.configs.network.relayer.url || '').trim();
    if (!relayerUrl) {
      throw new Error('registerWallet requires relayer.url');
    }

    const managedGrant = await createManagedRegistrationFlowGrant({
      context,
      nearAccountId: String(nearAccountId),
      rpId,
    });
    const intentResponse = await createWalletRegistrationIntent({
      relayerUrl,
      request: {
        wallet,
        rpId,
        authMethod: args.authMethod,
        signerSelection,
      },
      headers: {
        Authorization: `Bearer ${managedGrant.token}`,
      },
    });
    const localDigestB64u = await computeRegistrationIntentDigest(intentResponse.intent);
    if (localDigestB64u !== intentResponse.registrationIntentDigestB64u) {
      throw new Error('Registration intent digest mismatch');
    }
    const runtimePolicyScope = intentResponse.intent.runtimePolicyScope;
    if (!runtimePolicyScope) {
      throw new Error('Registration intent is missing runtime policy scope');
    }
    if (!runtimePolicyScope.signingRootVersion) {
      throw new Error('Registration intent is missing signing root version');
    }
    const thresholdRuntimePolicyScope: ThresholdRuntimePolicyScope = {
      orgId: runtimePolicyScope.orgId,
      projectId: runtimePolicyScope.projectId,
      envId: runtimePolicyScope.envId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
    };
    const signingRootId = signingRootScopeFromRuntimePolicyScope(
      thresholdRuntimePolicyScope,
    ).signingRootId;
    if (!signingRootId) {
      throw new Error('Registration intent is missing signing root scope');
    }

    let ed25519PrfFirstB64u = '';
    let ecdsaClientRootShare32B64u = '';
    let emailOtpClientRootShareHandle:
      | Awaited<
          ReturnType<SigningEnginePublic['prepareEmailOtpRegistrationEnrollmentMaterialInternal']>
        >['clientRootShareHandle']
      | null = null;
    let emailOtpChallengeId = '';
    let emailOtpEmail = '';
    let emailOtpProviderSubject = '';
    let emailOtpEnrollment:
      | Awaited<
          ReturnType<SigningEnginePublic['prepareEmailOtpRegistrationEnrollmentMaterialInternal']>
        >['emailOtpEnrollment']
      | null = null;
    let passkeyAuthority: Awaited<ReturnType<typeof collectPasskeyRegistrationAuthority>> | null =
      null;
    let startAuthority:
      | {
          kind: 'passkey';
          webauthnRegistration: unknown;
        }
      | {
          kind: 'email_otp';
          emailOtpRegistrationProof: Awaited<
            ReturnType<typeof collectEmailOtpRegistrationAuthority>
          >['proof'];
        };
    if (args.authMethod.kind === 'passkey') {
      emitRegistrationEvent(onEvent, nearAccountId, {
        authMethod: args.authMethod.kind,
        phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_STARTED,
        status: 'waiting_for_user',
        interaction: {
          kind: 'passkey_create',
          overlay: 'show',
        },
      });
      const confirmationConfig: Partial<ConfirmationConfig> = {
        uiMode: 'modal',
        behavior: 'requireClick',
        ...(args.confirmationConfigOverride ?? options?.confirmationConfig ?? {}),
      };
      passkeyAuthority = await collectPasskeyRegistrationAuthority({
        context,
        walletId: String(intentResponse.intent.walletId),
        signerSlot: ed25519Selection.signerSlot,
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
        options,
        confirmationConfigOverride: confirmationConfig,
      });
      ed25519PrfFirstB64u = passkeyAuthority.prfFirstB64u;
      ecdsaClientRootShare32B64u = passkeyAuthority.ecdsaClientRootShare32B64u;
      startAuthority = {
        kind: 'passkey',
        webauthnRegistration: passkeyAuthority.webauthnRegistration,
      };
      emitRegistrationEvent(onEvent, nearAccountId, {
        authMethod: args.authMethod.kind,
        phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_SUCCEEDED,
        status: 'succeeded',
        interaction: {
          kind: 'passkey_create',
          overlay: 'hide',
        },
      });
    } else {
      const emailAuthority = await collectEmailOtpRegistrationAuthority({
        authMethod: args.authMethod,
        relayUrl: relayerUrl,
        walletId: String(intentResponse.intent.walletId),
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
        appSessionJwt: args.authMethod.appSessionJwt,
      });
      const enrollment =
        await context.signingEngine.prepareEmailOtpRegistrationEnrollmentMaterialInternal({
          relayUrl: relayerUrl,
          walletId: toWalletId(intentResponse.intent.walletId),
          userId: emailAuthority.providerSubject,
          rpId,
          appSessionJwt: args.authMethod.appSessionJwt,
        });
      ed25519PrfFirstB64u = enrollment.thresholdEd25519PrfFirstB64u;
      emailOtpClientRootShareHandle = enrollment.clientRootShareHandle;
      emailOtpEnrollment = enrollment.emailOtpEnrollment;
      emailOtpChallengeId = emailAuthority.challengeId;
      emailOtpEmail = emailAuthority.email;
      emailOtpProviderSubject = emailAuthority.providerSubject;
      startAuthority = {
        kind: 'email_otp',
        emailOtpRegistrationProof: emailAuthority.proof,
      };
    }

    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_STARTED,
      status: 'running',
    });
    const hssClientMaterial =
      args.authMethod.kind === 'passkey'
        ? await prepareThresholdEd25519RegistrationHssClientMaterial({
            context,
            credential: passkeyAuthority!.credential,
            signingRootId,
            nearAccountId,
            keyPurpose: ed25519Selection.keyPurpose,
            keyVersion: ed25519Selection.keyVersion,
            participantIds: ed25519Selection.participantIds,
            derivationVersion: ed25519Selection.derivationVersion,
          })
        : await prepareThresholdEd25519RegistrationHssClientMaterialFromPrfFirst({
            context,
            prfFirstB64u: ed25519PrfFirstB64u,
            signingRootId,
            nearAccountId,
            keyPurpose: ed25519Selection.keyPurpose,
            keyVersion: ed25519Selection.keyVersion,
            participantIds: ed25519Selection.participantIds,
            derivationVersion: ed25519Selection.derivationVersion,
          });
    const startedCeremony = await startWalletRegistration({
      relayerUrl,
      registrationIntentGrant: intentResponse.registrationIntentGrant,
      registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
      intent: intentResponse.intent,
      ...startAuthority,
    });
    if (!startedCeremony.ed25519) {
      throw new Error('Wallet registration start did not return Ed25519 HSS material');
    }
    if (ecdsaSelection && !startedCeremony.ecdsa) {
      throw new Error('Wallet registration start did not return ECDSA HSS material');
    }
    const ecdsaPrepare = startedCeremony.ecdsa?.prepare;
    const ecdsaPreparedClientBootstrapPromise =
      ecdsaSelection && ecdsaPrepare
        ? (async () =>
            args.authMethod.kind === 'email_otp'
              ? await (async () => {
                  if (!emailOtpClientRootShareHandle) {
                    throw new Error(
                      'Email OTP ECDSA registration prepare is missing worker handle',
                    );
                  }
                  return await context.signingEngine.prepareWalletRegistrationEcdsaPreparedClientBootstrapFromEmailOtpHandle(
                    {
                      prepare: ecdsaPrepare,
                      clientRootShareHandle: emailOtpClientRootShareHandle,
                    },
                  );
                })()
              : await context.signingEngine.prepareWalletRegistrationEcdsaPreparedClientBootstrap({
                  prepare: ecdsaPrepare,
                  clientRootShare32B64u: ecdsaClientRootShare32B64u,
                }))()
        : Promise.resolve(null);

    const ed25519ClientRequestPromise = prepareThresholdEd25519RegistrationHssClientRequest({
      context,
      material: hssClientMaterial,
      preparedSession: startedCeremony.ed25519.preparedSession,
      clientOtOfferMessageB64u: startedCeremony.ed25519.clientOtOfferMessageB64u,
      ceremonyHandle: startedCeremony.ed25519.ceremonyHandle,
    });
    const [ecdsaPreparedClientBootstrap, { clientRequest, clientOutputMaskB64u }] =
      await Promise.all([ecdsaPreparedClientBootstrapPromise, ed25519ClientRequestPromise]);
    const responded = await respondWalletRegistrationHss({
      relayerUrl,
      registrationCeremonyId: startedCeremony.registrationCeremonyId,
      ed25519: {
        clientRequest: {
          clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
        },
      },
      ...(ecdsaPreparedClientBootstrap
        ? { ecdsa: { clientBootstrap: ecdsaPreparedClientBootstrap.clientBootstrap } }
        : {}),
    });
    if (!responded.ed25519) {
      throw new Error('Wallet registration HSS respond did not return Ed25519 server input');
    }
    if (ecdsaSelection && !responded.ecdsa?.bootstrap) {
      throw new Error('Wallet registration HSS respond did not return ECDSA bootstrap material');
    }
    const ecdsaBootstrap =
      ecdsaPreparedClientBootstrap && responded.ecdsa?.bootstrap
        ? parseWalletRegistrationEcdsaHssRespond({
            localBootstrap: ecdsaPreparedClientBootstrap.localClientBootstrap,
            serverBootstrap: responded.ecdsa.bootstrap,
          })
        : null;
    const evaluationResult = await buildThresholdEd25519RegistrationHssClientOwnedArtifact({
      context,
      preparedSession: startedCeremony.ed25519.preparedSession,
      clientRequest,
      serverInputDelivery: responded.ed25519,
      clientOutputMaskB64u,
    });

    const requestedPolicy = createThresholdWarmSessionPolicyDraft(context, {
      participantIds: hssClientMaterial.hssContext.participantIds,
    });
    if (!requestedPolicy) {
      throw new Error('Threshold warm-session defaults are disabled for registration');
    }
    const finalized = await finalizeWalletRegistration({
      relayerUrl,
      registrationCeremonyId: startedCeremony.registrationCeremonyId,
      ed25519: {
        evaluationResult,
        sessionPolicy: buildThresholdWarmSessionRequestEnvelope({
          rpId,
          requestedPolicy,
          nearAccountId: String(nearAccountId),
        }).session_policy,
        sessionKind: 'jwt',
      },
      ...(ecdsaBootstrap
        ? {
            ecdsa: {
              expectedKeyHandles: [ecdsaBootstrap.keyHandle],
            },
          }
        : {}),
      ...(emailOtpEnrollment ? { emailOtpEnrollment } : {}),
    });
    if (!finalized.ed25519) {
      throw new Error('Wallet registration finalize did not return Ed25519 key material');
    }
    const ecdsaWalletKeys = finalized.ecdsa?.walletKeys || [];
    if (ecdsaSelection && ecdsaWalletKeys.length === 0) {
      throw new Error('Wallet registration finalize did not return ECDSA wallet keys');
    }
    registrationTimingSummary.thresholdEd25519PrepareMs = Math.round(
      performance.now() - registrationStartedAt,
    );
    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_SUCCEEDED,
      status: 'succeeded',
      data: {
        verified: true,
        nearPublicKey: finalized.ed25519.publicKey,
      },
    });

    registrationState.accountCreated = ed25519Selection.createNearAccount;
    registrationState.contractRegistered = true;
    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_07_ACCOUNT_VERIFY_STARTED,
      status: 'running',
    });
    const completedThresholdEd25519Registration = completeRegisteredThresholdEd25519Registration({
      thresholdEd25519: finalized.ed25519,
      expectedSessionPolicy: buildThresholdWarmSessionRequestEnvelope({
        rpId,
        requestedPolicy,
        nearAccountId: String(nearAccountId),
        relayerKeyId: finalized.ed25519.relayerKeyId,
      }).session_policy,
    });
    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_07_ACCOUNT_VERIFY_SUCCEEDED,
      status: 'succeeded',
    });

    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
      status: 'running',
    });
    const localPersistenceStartedAt = performance.now();
    const storedRegistration =
      args.authMethod.kind === 'passkey'
        ? await context.signingEngine.storeWalletEd25519RegistrationData({
            walletId: finalized.walletId,
            nearAccountId,
            credential: passkeyAuthority!.credential,
            operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
            signerSlot: ed25519Selection.signerSlot,
            relayerKeyId: finalized.ed25519.relayerKeyId,
            keyVersion: finalized.ed25519.keyVersion,
            participantIds: finalized.ed25519.participantIds,
            clientParticipantId: finalized.ed25519.clientParticipantId,
            relayerParticipantId: finalized.ed25519.relayerParticipantId,
          })
        : await context.signingEngine.storeWalletEmailOtpEd25519RegistrationData({
            walletId: finalized.walletId,
            nearAccountId,
            email: emailOtpEmail,
            challengeId: emailOtpChallengeId,
            operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
            signerSlot: ed25519Selection.signerSlot,
            relayerKeyId: finalized.ed25519.relayerKeyId,
            keyVersion: finalized.ed25519.keyVersion,
            participantIds: finalized.ed25519.participantIds,
            clientParticipantId: finalized.ed25519.clientParticipantId,
            relayerParticipantId: finalized.ed25519.relayerParticipantId,
          });
    const signerSlot = storedRegistration.signerSlot;
    const persistedUser = await context.signingEngine.getUserBySignerSlot(
      nearAccountId,
      signerSlot,
    );
    if (!persistedUser) {
      throw new Error(
        `[Registration] profile/account mapping was not persisted for ${String(
          nearAccountId,
        )} signer slot ${signerSlot}`,
      );
    }
    const thresholdEd25519RegistrationSessionPolicy = buildThresholdWarmSessionRequestEnvelope({
      rpId,
      requestedPolicy,
      nearAccountId: String(nearAccountId),
      relayerKeyId: finalized.ed25519.relayerKeyId,
    }).session_policy;
    if (args.authMethod.kind === 'email_otp') {
      await persistRegisteredThresholdEd25519Session({
        signingEngine: context.signingEngine,
        nearAccountId,
        signerSlot,
        auth: {
          kind: 'email_otp',
          emailOtpAuthContext: buildRegistrationEmailOtpAuthContext({
            configs: context.configs,
            providerSubject: emailOtpProviderSubject,
          }),
        },
        rpId,
        relayerUrl,
        prfFirstB64u: hssClientMaterial.prfFirstB64u,
        registrationHssClientMaterial: hssClientMaterial,
        registrationSessionPolicy: thresholdEd25519RegistrationSessionPolicy,
        completedRegistration: completedThresholdEd25519Registration,
      });
    } else {
      await persistRegisteredThresholdEd25519Session({
        signingEngine: context.signingEngine,
        nearAccountId,
        signerSlot,
        auth: { kind: 'passkey' },
        rpId,
        relayerUrl,
        prfFirstB64u: hssClientMaterial.prfFirstB64u,
        registrationSessionPolicy: thresholdEd25519RegistrationSessionPolicy,
        completedRegistration: completedThresholdEd25519Registration,
      });
    }
    if (ecdsaWalletKeys.length > 0) {
      if (!ecdsaPreparedClientBootstrap || !ecdsaBootstrap) {
        throw new Error('Wallet registration ECDSA session material was not prepared');
      }
      await context.signingEngine.persistWalletRegistrationEcdsaBootstrapForWalletKeys({
        walletId: toWalletId(finalized.walletId),
        relayerUrl,
        preparedClientBootstrap: ecdsaPreparedClientBootstrap,
        bootstrap: ecdsaBootstrap,
        walletKeys: ecdsaWalletKeys,
        auth:
          args.authMethod.kind === 'email_otp'
            ? {
                kind: 'email_otp',
                emailOtpAuthContext: buildRegistrationEmailOtpAuthContext({
                  configs: context.configs,
                  providerSubject: emailOtpProviderSubject,
                }),
              }
            : { kind: 'passkey' },
      });
      if (args.authMethod.kind === 'passkey') {
        await context.signingEngine.storeWalletEcdsaSignerRecords({
          walletId: finalized.walletId,
          walletKeys: ecdsaWalletKeys,
        });
      } else {
        await context.signingEngine.storeWalletEmailOtpEcdsaSignerRecords({
          walletId: finalized.walletId,
          walletKeys: ecdsaWalletKeys,
        });
      }
    }
    await assertImmediateRegistrationSigningLanes({
      signingEngine: context.signingEngine,
      walletId: finalized.walletId,
      authMethod: args.authMethod.kind,
      expectEd25519: true,
      expectedEcdsaChainTargets: ecdsaSelection
        ? expectedEcdsaChainTargetsFromRegistrationSpec(ecdsaSelection)
        : [],
    });
    registrationTimingSummary.localPersistenceMs = Math.round(
      performance.now() - localPersistenceStartedAt,
    );
    registrationState.databaseStored = true;
    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
      status: 'succeeded',
      data: {
        thresholdPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
        relayerKeyId: completedThresholdEd25519Registration.registered.relayerKeyId,
        signerSlot,
      },
    });

    if (passkeyAuthority) {
      void prewarmThresholdEd25519ClientBaseFromCredential({
        context,
        credential: passkeyAuthority.credential,
        nearAccountId,
        signerSlot,
      }).catch(() => undefined);
    }

    try {
      await context.signingEngine.initializeCurrentUser(nearAccountId, context.nearClient);
    } catch (initErr) {
      console.warn('Failed to initialize current user after wallet registration:', initErr);
    }

    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_11_COMPLETED,
      status: 'succeeded',
    });
    const primaryEcdsaWalletKey = ecdsaWalletKeys[0] || null;
    const successResult: RegistrationResult = {
      success: true,
      nearAccountId,
      operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
      transactionId: registrationState.contractTransactionId,
      ...(primaryEcdsaWalletKey
        ? {
            thresholdEcdsaEthereumAddress: primaryEcdsaWalletKey.thresholdOwnerAddress,
            thresholdEcdsaPublicKeyB64u: primaryEcdsaWalletKey.thresholdEcdsaPublicKeyB64u,
          }
        : {}),
    };
    console.info('[Registration] wallet flow timings', {
      nearAccountId,
      ...registrationTimingSummary,
      totalMs: Math.round(performance.now() - registrationStartedAt),
    });
    afterCall?.(true, successResult);
    return successResult;
  } catch (error: unknown) {
    const errorCode =
      error && typeof error === 'object' && 'code' in error
        ? String((error as { code?: unknown }).code || '').trim()
        : '';
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', nearAccountId);
    const rollback = await performRegistrationRollback(
      registrationState,
      nearAccountId,
      context.signingEngine,
    );
    const errorObject = new Error(errorMessage);
    if (errorCode) {
      (errorObject as Error & { code?: string }).code = errorCode;
    }
    onError?.(errorObject);
    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
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
    console.info('[Registration] wallet flow timings', {
      nearAccountId,
      ...registrationTimingSummary,
      totalMs: Math.round(performance.now() - registrationStartedAt),
      failed: true,
    });
    afterCall?.(false);
    return result;
  }
}

export async function addWalletSigner(args: {
  context: PasskeyManagerContext;
  walletId: WalletId | string;
  rpId: string;
  signerSelection: AddSignerSelection;
  options: RegistrationHooksOptions;
}): Promise<RegistrationResult> {
  const { context, signerSelection } = args;
  const options = args.options || {};
  const { onEvent, onError, afterCall } = options;
  const walletId = walletIdFromString(String(args.walletId || '').trim());
  const eventAccountId = String(walletId) as AccountId;
  const rpId = String(args.rpId || '').trim();
  const startedAt = performance.now();

  if (!walletId) {
    throw new Error('addWalletSigner requires walletId');
  }
  if (!rpId) {
    throw new Error('addWalletSigner requires rpId');
  }
  emitRegistrationEvent(onEvent, eventAccountId, {
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });

  try {
    const relayerUrl = String(context.configs.network.relayer.url || '').trim();
    if (!relayerUrl) {
      throw new Error('addWalletSigner requires relayer.url');
    }

    const managedGrant = await createManagedRegistrationFlowGrant({
      context,
      nearAccountId: String(walletId),
      rpId,
    });
    const intentResponse = await createWalletAddSignerIntent({
      relayerUrl,
      walletId,
      request: {
        walletId,
        rpId,
        signerSelection,
      },
      headers: {
        Authorization: `Bearer ${managedGrant.token}`,
      },
    });
    const localDigestB64u = await computeAddSignerIntentDigest(intentResponse.intent);
    if (localDigestB64u !== intentResponse.addSignerIntentDigestB64u) {
      throw new Error('Add-signer intent digest mismatch');
    }

    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_STARTED,
      status: 'waiting_for_user',
      interaction: {
        kind: 'passkey_assert',
        overlay: 'show',
      },
    });
    const authenticators = await IndexedDBManager.listProfileAuthenticators(String(walletId));
    const allowCredentials = authenticators.map((authenticator) => ({
      id: String(authenticator.credentialId || ''),
      type: 'public-key',
      transports: Array.isArray(authenticator.transports)
        ? (authenticator.transports as AuthenticatorTransport[])
        : [],
    }));
    const webauthnAuthentication =
      await context.signingEngine.getAuthenticationCredentialsSerialized({
        nearAccountId: eventAccountId,
        challengeB64u: intentResponse.addSignerIntentDigestB64u,
        allowCredentials,
        includeSecondPrfOutput: false,
      });
    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_SUCCEEDED,
      status: 'succeeded',
      interaction: {
        kind: 'passkey_assert',
        overlay: 'hide',
      },
    });

    const redactedAuthentication = redactCredentialExtensionOutputs(webauthnAuthentication);
    if (signerSelection.mode === 'ed25519') {
      const runtimePolicyScope = intentResponse.intent.runtimePolicyScope;
      if (!runtimePolicyScope?.signingRootVersion) {
        throw new Error('Add-signer intent is missing runtime policy scope');
      }
      const thresholdRuntimePolicyScope: ThresholdRuntimePolicyScope = {
        orgId: runtimePolicyScope.orgId,
        projectId: runtimePolicyScope.projectId,
        envId: runtimePolicyScope.envId,
        signingRootVersion: runtimePolicyScope.signingRootVersion,
      };
      const signingRootId = signingRootScopeFromRuntimePolicyScope(
        thresholdRuntimePolicyScope,
      ).signingRootId;
      if (!signingRootId) {
        throw new Error('Add-signer intent is missing signing root scope');
      }
      const nearAccountId = toAccountId(signerSelection.ed25519.nearAccountId);
      const hssClientMaterial = await prepareThresholdEd25519RegistrationHssClientMaterial({
        context,
        credential: webauthnAuthentication,
        signingRootId,
        nearAccountId,
        keyPurpose: signerSelection.ed25519.keyPurpose,
        keyVersion: signerSelection.ed25519.keyVersion,
        participantIds: signerSelection.ed25519.participantIds,
        derivationVersion: signerSelection.ed25519.derivationVersion,
      });
      const startedCeremony = await startWalletAddSigner({
        relayerUrl,
        walletId,
        addSignerIntentGrant: intentResponse.addSignerIntentGrant,
        addSignerIntentDigestB64u: intentResponse.addSignerIntentDigestB64u,
        intent: intentResponse.intent,
        auth: {
          kind: 'webauthn_assertion',
          credential: redactedAuthentication,
          expectedChallengeDigestB64u: intentResponse.addSignerIntentDigestB64u,
        },
      });
      if (!startedCeremony.ed25519) {
        throw new Error('Wallet add-signer start did not return Ed25519 HSS material');
      }
      const { clientRequest, clientOutputMaskB64u } =
        await prepareThresholdEd25519RegistrationHssClientRequest({
          context,
          material: hssClientMaterial,
          preparedSession: startedCeremony.ed25519.preparedSession,
          clientOtOfferMessageB64u: startedCeremony.ed25519.clientOtOfferMessageB64u,
          ceremonyHandle: startedCeremony.ed25519.ceremonyHandle,
        });
      const responded = await respondWalletAddSignerHss({
        relayerUrl,
        walletId,
        addSignerCeremonyId: startedCeremony.addSignerCeremonyId,
        ed25519: {
          clientRequest: {
            clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
          },
        },
      });
      if (!responded.ed25519) {
        throw new Error('Wallet add-signer HSS respond did not return Ed25519 server input');
      }
      const evaluationResult = await buildThresholdEd25519RegistrationHssClientOwnedArtifact({
        context,
        preparedSession: startedCeremony.ed25519.preparedSession,
        clientRequest,
        serverInputDelivery: responded.ed25519,
        clientOutputMaskB64u,
      });
      const requestedPolicy = createThresholdWarmSessionPolicyDraft(context, {
        participantIds: hssClientMaterial.hssContext.participantIds,
      });
      if (!requestedPolicy) {
        throw new Error('Threshold warm-session defaults are disabled for add-signer');
      }
      const finalized = await finalizeWalletAddSigner({
        relayerUrl,
        walletId,
        addSignerCeremonyId: startedCeremony.addSignerCeremonyId,
        ed25519: {
          evaluationResult,
          sessionPolicy: buildThresholdWarmSessionRequestEnvelope({
            rpId,
            requestedPolicy,
            nearAccountId: String(nearAccountId),
          }).session_policy,
          sessionKind: 'jwt',
        },
      });
      if (!finalized.ed25519) {
        throw new Error('Wallet add-signer finalize did not return Ed25519 key material');
      }
      const completedThresholdEd25519Registration = completeRegisteredThresholdEd25519Registration({
        thresholdEd25519: finalized.ed25519,
        expectedSessionPolicy: buildThresholdWarmSessionRequestEnvelope({
          rpId,
          requestedPolicy,
          nearAccountId: String(nearAccountId),
          relayerKeyId: finalized.ed25519.relayerKeyId,
        }).session_policy,
      });

      emitRegistrationEvent(onEvent, eventAccountId, {
        phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
        status: 'running',
      });
      const storedRegistration = await context.signingEngine.storeWalletEd25519SignerRecord({
        walletId,
        nearAccountId,
        credential: redactedAuthentication,
        operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
        signerSlot: signerSelection.ed25519.signerSlot,
        relayerKeyId: finalized.ed25519.relayerKeyId,
        keyVersion: finalized.ed25519.keyVersion,
        participantIds: finalized.ed25519.participantIds,
        clientParticipantId: finalized.ed25519.clientParticipantId,
        relayerParticipantId: finalized.ed25519.relayerParticipantId,
      });
      await persistRegisteredThresholdEd25519Session({
        signingEngine: context.signingEngine,
        nearAccountId,
        signerSlot: storedRegistration.signerSlot,
        auth: { kind: 'passkey' },
        rpId,
        relayerUrl,
        prfFirstB64u: hssClientMaterial.prfFirstB64u,
        registrationSessionPolicy: buildThresholdWarmSessionRequestEnvelope({
          rpId,
          requestedPolicy,
          nearAccountId: String(nearAccountId),
          relayerKeyId: finalized.ed25519.relayerKeyId,
        }).session_policy,
        completedRegistration: completedThresholdEd25519Registration,
      });
      emitRegistrationEvent(onEvent, eventAccountId, {
        phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
        status: 'succeeded',
      });
      emitRegistrationEvent(onEvent, eventAccountId, {
        phase: RegistrationEventPhase.STEP_11_COMPLETED,
        status: 'succeeded',
      });

      const result: RegistrationResult = {
        success: true,
        nearAccountId,
        operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
      };
      console.info('[Registration] add-signer flow timings', {
        walletId: String(walletId),
        totalMs: Math.round(performance.now() - startedAt),
      });
      afterCall?.(true, result);
      return result;
    }

    const clientRootShare32B64u =
      await derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential(webauthnAuthentication);

    const startedCeremony = await startWalletAddSigner({
      relayerUrl,
      walletId,
      addSignerIntentGrant: intentResponse.addSignerIntentGrant,
      addSignerIntentDigestB64u: intentResponse.addSignerIntentDigestB64u,
      intent: intentResponse.intent,
      auth: {
        kind: 'webauthn_assertion',
        credential: redactedAuthentication,
        expectedChallengeDigestB64u: intentResponse.addSignerIntentDigestB64u,
      },
    });
    if (!startedCeremony.ecdsa) {
      throw new Error('Wallet add-signer start did not return ECDSA HSS material');
    }
    const preparedClientBootstrap =
      await context.signingEngine.prepareWalletRegistrationEcdsaPreparedClientBootstrap({
        prepare: startedCeremony.ecdsa.prepare,
        clientRootShare32B64u,
      });
    const responded = await respondWalletAddSignerHss({
      relayerUrl,
      walletId,
      addSignerCeremonyId: startedCeremony.addSignerCeremonyId,
      ecdsa: { clientBootstrap: preparedClientBootstrap.clientBootstrap },
    });
    if (!responded.ecdsa?.bootstrap) {
      throw new Error('Wallet add-signer HSS respond did not return ECDSA bootstrap material');
    }
    const ecdsaBootstrap = parseWalletRegistrationEcdsaHssRespond({
      localBootstrap: preparedClientBootstrap.localClientBootstrap,
      serverBootstrap: responded.ecdsa.bootstrap,
    });
    const finalized = await finalizeWalletAddSigner({
      relayerUrl,
      walletId,
      addSignerCeremonyId: startedCeremony.addSignerCeremonyId,
      ecdsa: {
        expectedKeyHandles: [ecdsaBootstrap.keyHandle],
      },
    });
    const walletKeys = finalized.ecdsa?.walletKeys || [];
    if (walletKeys.length === 0) {
      throw new Error('Wallet add-signer finalize did not return ECDSA wallet keys');
    }

    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
      status: 'running',
    });
    await context.signingEngine.persistWalletRegistrationEcdsaBootstrapForWalletKeys({
      walletId: toWalletId(walletId),
      relayerUrl,
      preparedClientBootstrap,
      bootstrap: ecdsaBootstrap,
      walletKeys,
      auth: { kind: 'passkey' },
    });
    await context.signingEngine.storeWalletEcdsaSignerRecords({
      walletId,
      walletKeys,
    });
    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
      status: 'succeeded',
    });
    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_11_COMPLETED,
      status: 'succeeded',
    });

    const primaryKey = walletKeys[0];
    const result: RegistrationResult = {
      success: true,
      thresholdEcdsaEthereumAddress: primaryKey.thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u: primaryKey.thresholdEcdsaPublicKeyB64u,
    };
    console.info('[Registration] add-signer flow timings', {
      walletId: String(walletId),
      totalMs: Math.round(performance.now() - startedAt),
    });
    afterCall?.(true, result);
    return result;
  } catch (error: unknown) {
    const errorCode =
      error && typeof error === 'object' && 'code' in error
        ? String((error as { code?: unknown }).code || '').trim()
        : '';
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', eventAccountId);
    const errorObject = new Error(errorMessage);
    if (errorCode) {
      (errorObject as Error & { code?: string }).code = errorCode;
    }
    onError?.(errorObject);
    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.FAILED,
      status: 'failed',
      message: errorMessage,
      interaction: {
        kind: 'passkey_assert',
        overlay: 'hide',
      },
      error: {
        ...(errorCode ? { code: errorCode } : {}),
        message: errorMessage,
      },
    });
    const result: RegistrationResult = {
      success: false,
      error: errorMessage,
      ...(errorCode ? { errorCode } : {}),
    };
    console.info('[Registration] add-signer flow timings', {
      walletId: String(walletId),
      totalMs: Math.round(performance.now() - startedAt),
      failed: true,
    });
    afterCall?.(false);
    return result;
  }
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
  authMethod: RegistrationAuthMethodInput['kind'],
  onEvent?: RegistrationHooksOptions['onEvent'],
  onError?: (error: Error) => void,
) => {
  emitRegistrationEvent(onEvent, nearAccountId, {
    authMethod,
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
    authMethod,
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
        console.debug(
          'Preserving local registration data because on-chain account state is immutable',
        );
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
