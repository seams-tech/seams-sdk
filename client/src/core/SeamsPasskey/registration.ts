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
  prepareThresholdEd25519RegistrationHssClientRequest,
  persistRegisteredThresholdEd25519Session,
} from './thresholdWarmSessionBootstrap';
import type { SigningEnginePublic } from '../signingEngine/SigningEngine';
import { type ConfirmationConfig } from '../types/signer-worker';
import { toAccountId, type AccountId } from '../types/accountIds';
import type { WebAuthnRegistrationCredential } from '../types/webauthn';
import { getUserFriendlyErrorMessage } from '@shared/utils/errors';
import { checkNearAccountExistsBestEffort } from '../rpcClients/near/rpcCalls';
import { redactCredentialExtensionOutputs } from '../signingEngine/webauthnAuth/credentials/credentialExtensions';
import {
  derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential,
  derivePasskeyThresholdEcdsaClientRootShare32B64uFromPrfFirst,
} from '../signingEngine/session/passkey/ecdsaClientRoot';
import { normalizeRegistrationCredential } from '../signingEngine/webauthnAuth/credentials/helpers';
import { IndexedDBManager } from '../indexedDB';
import type { ThresholdRuntimePolicyScope } from '../signingEngine/threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  AddSignerSelection,
  RegisterWalletSubjectInput,
  RegistrationSignerSelection,
  WalletSubjectId,
} from '@shared/utils/registrationIntent';
import { walletSubjectIdFromString } from '@shared/utils/registrationIntent';
import { toWalletId } from '../signingEngine/interfaces/ecdsaChainTarget';
import { computeRegistrationIntentDigest } from '@/utils/intentDigest';
import { computeAddSignerIntentDigest } from '@/utils/intentDigest';
import {
  createWalletAddSignerIntent,
  createWalletRegistrationIntent,
  finalizeWalletAddSigner,
  finalizeWalletRegistration,
  respondWalletAddSignerHss,
  respondWalletRegistrationHss,
  startWalletAddSigner,
  startWalletRegistration,
} from '../rpcClients/relayer/walletRegistration';
import { buildPasskeyNearWalletRegistrationSignerSelection } from './registrationSignerSelection';

// Registration forces a visible, clickable confirmation for cross-origin safety.

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
  const accountId = toAccountId(nearAccountId);
  const iframeRpId = String(context.configs.wallet.iframe.rpIdOverride || '').trim();
  const rpId = iframeRpId || context.signingEngine.getRpId();
  if (!rpId) {
    throw new Error('Missing rpId for relay registration');
  }
  return await registerWallet({
    context,
    walletSubject: {
      kind: 'provided',
      walletSubjectId: walletSubjectIdFromString(String(accountId)),
    },
    rpId,
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
  walletSubject: RegisterWalletSubjectInput;
  rpId: string;
  signerSelection: Extract<RegistrationSignerSelection, { mode: 'ecdsa_only' }>;
  options: RegistrationHooksOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
}): Promise<RegistrationResult> {
  const { context, walletSubject, signerSelection } = args;
  const options = args.options || {};
  const { onEvent, onError, afterCall } = options;
  const startedAt = performance.now();
  const rpId = String(args.rpId || '').trim();
  const initialEventAccountId = String(
    walletSubject.kind === 'provided' ? walletSubject.walletSubjectId : 'wallet-registration',
  ) as AccountId;

  if (!rpId) {
    throw new Error('registerWallet requires rpId');
  }

  emitRegistrationEvent(onEvent, initialEventAccountId, {
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
      ...(walletSubject.kind === 'provided'
        ? { walletSubjectId: String(walletSubject.walletSubjectId || '').trim() }
        : {}),
      rpId,
    });
    const intentResponse = await createWalletRegistrationIntent({
      relayerUrl,
      request: {
        walletSubject,
        rpId,
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

    const walletSubjectId = intentResponse.intent.walletSubjectId;
    const eventAccountId = String(walletSubjectId) as AccountId;
    emitRegistrationEvent(onEvent, eventAccountId, {
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
    const registrationSession =
      await context.signingEngine.requestRegistrationCredentialConfirmation({
        nearAccountId: String(walletSubjectId),
        signerSlot: 1,
        confirmerText: options?.confirmerText,
        confirmationConfigOverride: confirmationConfig,
        challengeB64u: intentResponse.registrationIntentDigestB64u,
      });
    const credential = registrationSession.credential;
    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_SUCCEEDED,
      status: 'succeeded',
      interaction: {
        kind: 'passkey_create',
        overlay: 'hide',
      },
    });

    const clientRootShare32B64u =
      await derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential(credential);
    if (!clientRootShare32B64u) {
      throw new Error(
        'Failed to derive threshold ECDSA client root share from passkey registration',
      );
    }
    const serializedCredential = redactCredentialExtensionOutputs<WebAuthnRegistrationCredential>(
      normalizeRegistrationCredential(credential),
    );
    if (!Array.isArray(serializedCredential.response.transports)) {
      serializedCredential.response.transports = [];
    }

    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_STARTED,
      status: 'running',
    });
    const startedCeremony = await startWalletRegistration({
      relayerUrl,
      registrationIntentGrant: intentResponse.registrationIntentGrant,
      registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
      intent: intentResponse.intent,
      webauthnRegistration: serializedCredential,
    });
    if (!startedCeremony.ecdsa) {
      throw new Error('Wallet registration start did not return ECDSA HSS material');
    }
    const preparedClientBootstrap =
      await context.signingEngine.prepareWalletRegistrationEcdsaPreparedClientBootstrap({
        prepare: startedCeremony.ecdsa.prepare,
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
    const finalized = await finalizeWalletRegistration({
      relayerUrl,
      registrationCeremonyId: startedCeremony.registrationCeremonyId,
      ecdsa: {
        expectedKeyHandles: [responded.ecdsa.bootstrap.keyHandle],
      },
    });
    const walletKeys = finalized.ecdsa?.walletKeys || [];
    if (walletKeys.length === 0) {
      throw new Error('Wallet registration finalize did not return ECDSA wallet keys');
    }
    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_SUCCEEDED,
      status: 'succeeded',
    });

    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
      status: 'running',
    });
    await context.signingEngine.storeWalletSubjectEcdsaRegistrationData({
      walletSubjectId: finalized.walletSubjectId,
      credential,
      walletKeys,
    });
    await context.signingEngine.persistWalletRegistrationEcdsaBootstrapForWalletKeys({
      walletId: toWalletId(finalized.walletSubjectId),
      relayerUrl,
      preparedClientBootstrap,
      bootstrap: responded.ecdsa.bootstrap,
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
    console.info('[Registration] ECDSA wallet flow timings', {
      walletSubjectId: String(finalized.walletSubjectId),
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
      walletSubjectId:
        walletSubject.kind === 'provided' ? String(walletSubject.walletSubjectId) : undefined,
      totalMs: Math.round(performance.now() - startedAt),
      failed: true,
    });
    afterCall?.(false);
    return result;
  }
}

export async function registerWallet(args: {
  context: PasskeyManagerContext;
  walletSubject: RegisterWalletSubjectInput;
  rpId: string;
  signerSelection: RegistrationSignerSelection;
  options: RegistrationHooksOptions;
  authenticatorOptions: AuthenticatorOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
}): Promise<RegistrationResult> {
  const { context, walletSubject, signerSelection } = args;
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
      walletSubject,
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
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });

  try {
    await validateRegistrationInputs(context, nearAccountId, onEvent, onError);

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
        walletSubject,
        rpId,
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
      behavior: 'requireClick',
      ...(args.confirmationConfigOverride ?? options?.confirmationConfig ?? {}),
    };
    const registrationSession =
      await context.signingEngine.requestRegistrationCredentialConfirmation({
        nearAccountId: String(nearAccountId),
        signerSlot: ed25519Selection.signerSlot,
        confirmerText: options?.confirmerText,
        confirmationConfigOverride: confirmationConfig,
        challengeB64u: intentResponse.registrationIntentDigestB64u,
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

    emitRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_STARTED,
      status: 'running',
    });
    const hssClientMaterial = await prepareThresholdEd25519RegistrationHssClientMaterial({
      context,
      credential,
      signingRootId,
      nearAccountId,
      keyPurpose: ed25519Selection.keyPurpose,
      keyVersion: ed25519Selection.keyVersion,
      participantIds: ed25519Selection.participantIds,
      derivationVersion: ed25519Selection.derivationVersion,
    });
    const thresholdPrfFirstB64u = hssClientMaterial.prfFirstB64u;

    const serializedCredential = redactCredentialExtensionOutputs<WebAuthnRegistrationCredential>(
      normalizeRegistrationCredential(credential),
    );
    if (!Array.isArray(serializedCredential.response.transports)) {
      serializedCredential.response.transports = [];
    }
    const startedCeremony = await startWalletRegistration({
      relayerUrl,
      registrationIntentGrant: intentResponse.registrationIntentGrant,
      registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
      intent: intentResponse.intent,
      webauthnRegistration: serializedCredential,
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
            await context.signingEngine.prepareWalletRegistrationEcdsaPreparedClientBootstrap({
              prepare: ecdsaPrepare,
              clientRootShare32B64u:
                await derivePasskeyThresholdEcdsaClientRootShare32B64uFromPrfFirst(
                  thresholdPrfFirstB64u,
                ),
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
      ...(responded.ecdsa?.bootstrap
        ? {
            ecdsa: {
              expectedKeyHandles: [responded.ecdsa.bootstrap.keyHandle],
            },
          }
        : {}),
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
      phase: RegistrationEventPhase.STEP_07_ACCOUNT_VERIFY_SUCCEEDED,
      status: 'succeeded',
    });

    emitRegistrationEvent(onEvent, nearAccountId, {
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
      status: 'running',
    });
    const localPersistenceStartedAt = performance.now();
    const storedRegistration =
      await context.signingEngine.storeWalletSubjectEd25519RegistrationData({
        walletSubjectId: finalized.walletSubjectId,
        nearAccountId,
        credential,
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
    await persistRegisteredThresholdEd25519Session({
      signingEngine: context.signingEngine,
      nearAccountId,
      signerSlot,
      rpId,
      relayerUrl,
      prfFirstB64u: thresholdPrfFirstB64u,
      registrationSessionPolicy: buildThresholdWarmSessionRequestEnvelope({
        rpId,
        requestedPolicy,
        nearAccountId: String(nearAccountId),
        relayerKeyId: finalized.ed25519.relayerKeyId,
      }).session_policy,
      completedRegistration: completedThresholdEd25519Registration,
    });
    if (ecdsaWalletKeys.length > 0) {
      await context.signingEngine.storeWalletSubjectEcdsaSignerRecords({
        walletSubjectId: finalized.walletSubjectId,
        walletKeys: ecdsaWalletKeys,
      });
      if (!ecdsaPreparedClientBootstrap || !responded.ecdsa?.bootstrap) {
        throw new Error('Wallet registration ECDSA session material was not prepared');
      }
      await context.signingEngine.persistWalletRegistrationEcdsaBootstrapForWalletKeys({
        walletId: toWalletId(finalized.walletSubjectId),
        relayerUrl,
        preparedClientBootstrap: ecdsaPreparedClientBootstrap,
        bootstrap: responded.ecdsa.bootstrap,
        walletKeys: ecdsaWalletKeys,
      });
    }
    registrationTimingSummary.localPersistenceMs = Math.round(
      performance.now() - localPersistenceStartedAt,
    );
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

    void prewarmThresholdEd25519ClientBaseFromCredential({
      context,
      credential,
      nearAccountId,
      signerSlot,
    }).catch(() => undefined);

    try {
      await context.signingEngine.initializeCurrentUser(nearAccountId, context.nearClient);
    } catch (initErr) {
      console.warn('Failed to initialize current user after wallet registration:', initErr);
    }

    emitRegistrationEvent(onEvent, nearAccountId, {
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
  walletSubjectId: WalletSubjectId | string;
  rpId: string;
  signerSelection: AddSignerSelection;
  options: RegistrationHooksOptions;
}): Promise<RegistrationResult> {
  const { context, signerSelection } = args;
  const options = args.options || {};
  const { onEvent, onError, afterCall } = options;
  const walletSubjectId = walletSubjectIdFromString(String(args.walletSubjectId || '').trim());
  const eventAccountId = String(walletSubjectId) as AccountId;
  const rpId = String(args.rpId || '').trim();
  const startedAt = performance.now();

  if (!walletSubjectId) {
    throw new Error('addWalletSigner requires walletSubjectId');
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
      nearAccountId: String(walletSubjectId),
      rpId,
    });
    const intentResponse = await createWalletAddSignerIntent({
      relayerUrl,
      walletSubjectId,
      request: {
        walletSubjectId,
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
    const authenticators = await IndexedDBManager.clientDB.listProfileAuthenticators(
      String(walletSubjectId),
    );
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
        walletSubjectId,
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
        walletSubjectId,
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
        walletSubjectId,
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
      const storedRegistration = await context.signingEngine.storeWalletSubjectEd25519SignerRecord({
        walletSubjectId,
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
        walletSubjectId: String(walletSubjectId),
        totalMs: Math.round(performance.now() - startedAt),
      });
      afterCall?.(true, result);
      return result;
    }

    const clientRootShare32B64u =
      await derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential(webauthnAuthentication);

    const startedCeremony = await startWalletAddSigner({
      relayerUrl,
      walletSubjectId,
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
      walletSubjectId,
      addSignerCeremonyId: startedCeremony.addSignerCeremonyId,
      ecdsa: { clientBootstrap: preparedClientBootstrap.clientBootstrap },
    });
    if (!responded.ecdsa?.bootstrap) {
      throw new Error('Wallet add-signer HSS respond did not return ECDSA bootstrap material');
    }
    const finalized = await finalizeWalletAddSigner({
      relayerUrl,
      walletSubjectId,
      addSignerCeremonyId: startedCeremony.addSignerCeremonyId,
      ecdsa: {
        expectedKeyHandles: [responded.ecdsa.bootstrap.keyHandle],
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
    await context.signingEngine.storeWalletSubjectEcdsaSignerRecords({
      walletSubjectId,
      walletKeys,
    });
    await context.signingEngine.persistWalletRegistrationEcdsaBootstrapForWalletKeys({
      walletId: toWalletId(walletSubjectId),
      relayerUrl,
      preparedClientBootstrap,
      bootstrap: responded.ecdsa.bootstrap,
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
      walletSubjectId: String(walletSubjectId),
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
      walletSubjectId: String(walletSubjectId),
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
