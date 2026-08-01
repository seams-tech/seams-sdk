import {
  AccountSyncEventPhase,
  createAccountSyncFlowEvent,
  type CreateAccountSyncFlowEventInput,
  type SyncAccountHooksOptions,
} from '@/core/types/sdkSentEvents';
import type { SyncAccountResult } from '@/core/types/sdkPublicResults';
import type {
  AccountSyncSigningSurface,
  AccountSyncWebContext,
} from '@/SeamsWeb/signingSurface/types';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  getPrfFirstB64uFromCredential,
  redactCredentialExtensionOutputs,
} from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import {
  parsePasskeyEd25519YaoSyncResponseV1,
  recoverParsedPasskeyEd25519YaoCapabilityV1,
  type PasskeyEd25519YaoRecoveryResultV1,
  type ParsedPasskeyEd25519YaoSyncResponseV1,
} from '@/core/signingEngine/flows/recovery/passkeyEd25519YaoRecovery';
import { restoreLocalLoginState } from '@/SeamsWeb/operations/session/restoreLocalLoginState';
import { base64UrlDecode } from '@shared/utils/base64';
import { errorMessage } from '@shared/utils/errors';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import { isPlainObject } from '@shared/utils/validation';
import {
  assertSameRecoveryResolvedWalletBinding,
  parseRecoveryResolvedWalletBindingFromResponse,
  type RecoveryResolvedWalletBinding,
} from './recoveryWalletBinding';
import {
  buildPasskeyEd25519RestoreMetadata,
  persistPasskeyEd25519YaoSessionForRefresh,
} from '@/core/signingEngine/session/passkey/ed25519YaoSealedSession';
import {
  nearEd25519YaoMaterialActivationFromMetadata,
  nearEd25519YaoMaterialActivationFromPublicFacts,
} from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';

export type { SyncAccountResult };

type SyncOptionsV1 = {
  readonly challengeId: string;
  readonly challengeB64u: string;
  readonly credentialIds: readonly string[];
  readonly walletBinding: RecoveryResolvedWalletBinding | null;
};

export type PasskeyEd25519YaoUnlockRecoveryV1 = {
  readonly recovery: PasskeyEd25519YaoRecoveryResultV1;
  readonly credential: WebAuthnAuthenticationCredential;
  readonly verifiedBinding: RecoveryResolvedWalletBinding;
};

export type RecoverPasskeyEd25519YaoForUnlockInputV1 = {
  readonly walletId: string | null;
  readonly relayerUrl: string;
  readonly rpId: string;
  readonly fetch: typeof fetch;
  readonly collectCredential: (input: {
    readonly challengeB64u: string;
    readonly credentialIds: readonly string[];
  }) => Promise<WebAuthnAuthenticationCredential>;
  readonly activateCapability: AccountSyncSigningSurface['activateVerifiedNearEd25519YaoSigningCapability'];
  readonly withExactEd25519MaterialOwner: AccountSyncSigningSurface['withExactEd25519MaterialOwner'];
  readonly sessionPersistence: Pick<
    AccountSyncSigningSurface,
    'hydrateSigningSession' | 'persistSigningSessionSealForThresholdSession'
  >;
  readonly onPromptStarted?: () => void;
  readonly onPromptSucceeded?: () => void;
  readonly onRelayVerifyStarted?: () => void;
  readonly onRelayVerifySucceeded?: (binding: RecoveryResolvedWalletBinding) => void;
};

type RecoveredCapabilityOwnershipV1 =
  | { readonly kind: 'empty' }
  | {
      readonly kind: 'caller_owned';
      readonly recovery: PasskeyEd25519YaoRecoveryResultV1;
    }
  | {
      readonly kind: 'registry_owned';
      readonly recovery: PasskeyEd25519YaoRecoveryResultV1;
    }
  | { readonly kind: 'committed' };

function syncAccountFailure(error: string): SyncAccountResult {
  return { success: false, error };
}

function fetchWithGlobalThis(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  return globalThis.fetch(input, init);
}

function emitSyncAccountEvent(args: {
  onEvent: SyncAccountHooksOptions['onEvent'];
  flowId: string;
  event: Omit<CreateAccountSyncFlowEventInput, 'flowId'>;
}): void {
  try {
    args.onEvent?.(createAccountSyncFlowEvent({ flowId: args.flowId, ...args.event }));
  } catch {}
}

function requireRelayerUrl(context: AccountSyncWebContext): string {
  const relayerUrl = String(context.configs.network.relayer?.url || '').trim();
  if (!relayerUrl) throw new Error('missing_relayer_url');
  return relayerUrl;
}

function requireRpId(context: AccountSyncWebContext): string {
  const parsed = parseWebAuthnRpId(context.signingEngine.getRpId());
  if (!parsed.ok) throw new Error('missing_rp_id');
  return parsed.value;
}

function parseCredentialIds(value: unknown): readonly string[] {
  if (!Array.isArray(value)) return [];
  const ids: string[] = [];
  for (const raw of value) {
    const id = typeof raw === 'string' ? raw.trim() : '';
    if (id) ids.push(id);
  }
  return ids;
}

async function readJsonOrNull(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function requestSyncOptions(input: {
  readonly relayerUrl: string;
  readonly rpId: string;
  readonly walletId: string | null;
  readonly fetch: typeof fetch;
}): Promise<SyncOptionsV1> {
  const response = await input.fetch(`${input.relayerUrl}/sync-account/options`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      rp_id: input.rpId,
      ...(input.walletId ? { account_id: input.walletId } : {}),
    }),
  });
  const raw = await readJsonOrNull(response);
  if (!response.ok || !isPlainObject(raw) || raw.ok !== true) {
    const message = isPlainObject(raw) ? String(raw.message || raw.code || '') : '';
    throw new Error(message || `sync-account/options failed (HTTP ${response.status})`);
  }
  const challengeId = String(raw.challengeId || '').trim();
  const challengeB64u = String(raw.challengeB64u || '').trim();
  if (!challengeId || !challengeB64u) {
    throw new Error('sync-account/options returned an invalid challenge');
  }
  const walletBinding = isPlainObject(raw.walletBinding)
    ? parseRecoveryResolvedWalletBindingFromResponse(raw, 'sync-account/options')
    : null;
  const credentialIds = parseCredentialIds(raw.credentialIds);
  if (input.walletId && (!walletBinding || credentialIds.length === 0)) {
    throw new Error(`No passkey recovery capability found for wallet ${input.walletId}`);
  }
  return { challengeId, challengeB64u, credentialIds, walletBinding };
}

function requireSelectedCredentialId(credential: WebAuthnAuthenticationCredential): string {
  const id = String(credential.id || '').trim();
  const rawId = String(credential.rawId || '').trim();
  if (!id || !rawId || id !== rawId) {
    throw new Error('selected passkey credential identity is invalid');
  }
  return rawId;
}

async function verifySyncCredential(input: {
  readonly relayerUrl: string;
  readonly challengeId: string;
  readonly credential: WebAuthnAuthenticationCredential;
  readonly fetch: typeof fetch;
}): Promise<Record<string, unknown>> {
  const response = await input.fetch(`${input.relayerUrl}/sync-account/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challengeId: input.challengeId,
      webauthn_authentication: redactCredentialExtensionOutputs<WebAuthnAuthenticationCredential>(
        input.credential,
      ),
    }),
  });
  const raw = await readJsonOrNull(response);
  if (!response.ok || !isPlainObject(raw) || raw.ok !== true || raw.verified !== true) {
    const message = isPlainObject(raw) ? String(raw.message || raw.code || '') : '';
    throw new Error(message || `sync-account/verify failed (HTTP ${response.status})`);
  }
  return raw;
}

function assertNeverRecoveredCapabilityOwnership(value: never): never {
  throw new Error(`Unexpected recovered capability ownership: ${String(value)}`);
}

async function disposeRecoveredCapability(input: {
  readonly context: AccountSyncWebContext;
  readonly ownership: RecoveredCapabilityOwnershipV1;
}): Promise<void> {
  const ownership = input.ownership;
  switch (ownership.kind) {
    case 'caller_owned':
      ownership.recovery.activeClient.dispose();
      await input.context.signingEngine.clearVolatileWarmSigningMaterial(
        ownership.recovery.parsed.walletId,
      );
      return;
    case 'registry_owned':
      await input.context.signingEngine.clearVolatileWarmSigningMaterial(
        ownership.recovery.parsed.walletId,
      );
      return;
    case 'empty':
    case 'committed':
      return;
    default:
      return assertNeverRecoveredCapabilityOwnership(ownership);
  }
}

function assertRecoveredCapabilityBinding(input: {
  readonly requestedWalletId: string | null;
  readonly rpId: string;
  readonly optionsBinding: RecoveryResolvedWalletBinding | null;
  readonly verifiedBinding: RecoveryResolvedWalletBinding;
  readonly recovery: PasskeyEd25519YaoRecoveryResultV1;
  readonly selectedCredentialId: string;
}): void {
  if (input.optionsBinding) {
    assertSameRecoveryResolvedWalletBinding(
      input.optionsBinding,
      input.verifiedBinding,
      'sync-account/verify',
    );
  }
  const recovered = input.recovery.parsed;
  if (
    input.verifiedBinding.rpId !== input.rpId ||
    (input.requestedWalletId !== null &&
      input.requestedWalletId !== String(input.verifiedBinding.walletId)) ||
    String(recovered.walletId) !== String(input.verifiedBinding.walletId) ||
    String(recovered.nearAccountId) !== String(input.verifiedBinding.nearAccountId) ||
    recovered.nearEd25519SigningKeyId !== String(input.verifiedBinding.nearEd25519SigningKeyId) ||
    recovered.credentialIdB64u !== input.verifiedBinding.credentialIdB64u ||
    recovered.credentialIdB64u !== input.selectedCredentialId ||
    recovered.signerSlot !== input.verifiedBinding.signerSlot
  ) {
    throw new Error('recovered Yao capability does not match the verified wallet binding');
  }
}

type RecoverAndCommitPasskeyEd25519UnlockInput = {
  parsed: ParsedPasskeyEd25519YaoSyncResponseV1;
  ownedPasskeyPrfFirst: Uint8Array;
  relayerUrl: string;
  rpId: string;
  fetch: typeof fetch;
  requestedWalletId: string | null;
  optionsBinding: RecoveryResolvedWalletBinding | null;
  verifiedBinding: RecoveryResolvedWalletBinding;
  selectedCredentialId: string;
  prfFirstB64u: string;
  sessionPersistence: RecoverPasskeyEd25519YaoForUnlockInputV1['sessionPersistence'];
  activateCapability: RecoverPasskeyEd25519YaoForUnlockInputV1['activateCapability'];
};

async function recoverAndCommitPasskeyEd25519Unlock(
  input: RecoverAndCommitPasskeyEd25519UnlockInput,
): Promise<PasskeyEd25519YaoRecoveryResultV1> {
  let recovery: PasskeyEd25519YaoRecoveryResultV1 | null = null;
  try {
    recovery = await recoverParsedPasskeyEd25519YaoCapabilityV1({
      parsed: input.parsed,
      ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
      relayerUrl: input.relayerUrl,
      rpId: input.rpId,
      fetch: input.fetch,
    });
    assertRecoveredCapabilityBinding({
      requestedWalletId: input.requestedWalletId,
      rpId: input.rpId,
      optionsBinding: input.optionsBinding,
      verifiedBinding: input.verifiedBinding,
      recovery,
      selectedCredentialId: input.selectedCredentialId,
    });
    const recoveredActivation = nearEd25519YaoMaterialActivationFromMetadata(
      recovery.activeClient.metadata(),
    );
    await persistPasskeyEd25519YaoSessionForRefresh({
      persistence: input.sessionPersistence,
      session: recovery.walletSessionState,
      prfFirstB64u: input.prfFirstB64u,
      ed25519Restore: buildPasskeyEd25519RestoreMetadata({
        rpId: input.rpId,
        nearAccountId: String(recovery.parsed.nearAccountId),
        nearEd25519SigningKeyId: recovery.parsed.nearEd25519SigningKeyId,
        relayerKeyId: recovery.parsed.relayerKeyId,
        participantIds: recovery.parsed.session.participantIds,
        runtimePolicyScope: recovery.parsed.session.runtimePolicyScope,
        signerSlot: recovery.parsed.signerSlot,
        routerAbNormalSigning: recovery.parsed.session.routerAbNormalSigning,
        credentialIdB64u: recovery.parsed.credentialIdB64u,
        materialActivation: recoveredActivation,
      }),
      materialActivation: recoveredActivation,
    });
    const activated = await input.activateCapability({
      activeClient: recovery.activeClient,
      walletSessionState: recovery.walletSessionState,
    });
    if (
      !mpcMaterialActivationRefsEqual(
        activated.materialActivation,
        recoveredActivation,
      )
    ) {
      throw new Error('Passkey Ed25519 registry activation changed during recovery commit');
    }
    return recovery;
  } catch (error) {
    recovery?.activeClient.dispose();
    throw error;
  }
}

export async function recoverPasskeyEd25519YaoForUnlockV1(
  input: RecoverPasskeyEd25519YaoForUnlockInputV1,
): Promise<PasskeyEd25519YaoUnlockRecoveryV1> {
  const requestedWalletId = input.walletId === null ? null : String(input.walletId).trim();
  if (input.walletId !== null && !requestedWalletId) {
    throw new Error('passkey Yao unlock recovery requires a valid walletId');
  }
  const syncOptions = await requestSyncOptions({
    relayerUrl: input.relayerUrl,
    rpId: input.rpId,
    walletId: requestedWalletId || null,
    fetch: input.fetch,
  });
  input.onPromptStarted?.();
  const credential = await input.collectCredential({
    challengeB64u: syncOptions.challengeB64u,
    credentialIds: syncOptions.credentialIds,
  });
  input.onPromptSucceeded?.();
  const selectedCredentialId = requireSelectedCredentialId(credential);
  const prfFirstB64u = getPrfFirstB64uFromCredential(credential);
  if (!prfFirstB64u) throw new Error('selected passkey did not return PRF.first');
  input.onRelayVerifyStarted?.();
  const verified = await verifySyncCredential({
    relayerUrl: input.relayerUrl,
    challengeId: syncOptions.challengeId,
    credential,
    fetch: input.fetch,
  });
  const verifiedBinding = parseRecoveryResolvedWalletBindingFromResponse(
    verified,
    'sync-account/verify',
  );
  input.onRelayVerifySucceeded?.(verifiedBinding);
  const ownedPasskeyPrfFirst = base64UrlDecode(prfFirstB64u);
  try {
    const parsed = parsePasskeyEd25519YaoSyncResponseV1(verified);
    const expectedMaterialActivation = nearEd25519YaoMaterialActivationFromPublicFacts({
      activationId: parsed.session.thresholdSessionId,
      activeCapabilityBinding: parsed.capability.activeCapabilityBinding,
      walletId: String(parsed.walletId),
      registeredPublicKey: parsed.capability.registeredPublicKey,
      lifecycleId: parsed.capability.lifecycle.lifecycleId,
      signingWorkerId: parsed.capability.lifecycle.signingWorkerId,
    });
    const recovery = await input.withExactEd25519MaterialOwner({
      materialActivation: expectedMaterialActivation,
      nearAccountId: parsed.nearAccountId,
      task: recoverAndCommitPasskeyEd25519Unlock.bind(undefined, {
        parsed,
        ownedPasskeyPrfFirst,
        relayerUrl: input.relayerUrl,
        rpId: input.rpId,
        fetch: input.fetch,
        requestedWalletId: requestedWalletId || null,
        optionsBinding: syncOptions.walletBinding,
        verifiedBinding,
        selectedCredentialId,
        prfFirstB64u,
        sessionPersistence: input.sessionPersistence,
        activateCapability: input.activateCapability,
      }),
    });
    return { recovery, credential, verifiedBinding };
  } finally {
    ownedPasskeyPrfFirst.fill(0);
  }
}

async function persistRecoveredPasskey(input: {
  readonly context: AccountSyncWebContext;
  readonly recovery: PasskeyEd25519YaoRecoveryResultV1;
  readonly credential: WebAuthnAuthenticationCredential;
}): Promise<void> {
  const parsed = input.recovery.parsed;
  const credentialPublicKey = base64UrlDecode(parsed.credentialPublicKeyB64u);
  await input.context.signingEngine.storeUserData({
    walletId: String(parsed.walletId),
    nearAccountId: parsed.nearAccountId,
    signerSlot: parsed.signerSlot,
    operationalPublicKey: parsed.operationalPublicKey,
    lastUpdated: Date.now(),
    passkeyCredential: {
      id: String(input.credential.id || ''),
      rawId: String(input.credential.rawId || ''),
    },
    version: 2,
  });
  await input.context.signingEngine.storeAuthenticator({
    nearAccountId: parsed.nearAccountId,
    credentialId: parsed.credentialIdB64u,
    credentialPublicKey,
    transports: [],
    name: `Passkey for ${String(parsed.walletId)}`,
    registered: new Date().toISOString(),
    syncedAt: new Date().toISOString(),
    signerSlot: parsed.signerSlot,
  });
}

type SyncAccountRecoveryCallbacksV1 = {
  readonly signingSurface: AccountSyncSigningSurface;
  readonly requestedWalletId: string | null;
  readonly onEvent: SyncAccountHooksOptions['onEvent'];
  readonly flowId: string;
};

function syncAccountAllowCredential(credentialId: string): WebAuthnAllowCredential {
  return { id: credentialId, type: 'public-key', transports: [] };
}

async function collectSyncAccountRecoveryCredential(
  callbacks: SyncAccountRecoveryCallbacksV1,
  input: { readonly challengeB64u: string; readonly credentialIds: readonly string[] },
): Promise<WebAuthnAuthenticationCredential> {
  return await callbacks.signingSurface.getAuthenticationCredentialsSerialized({
    subjectId: callbacks.requestedWalletId || 'account-sync',
    challengeB64u: input.challengeB64u,
    allowCredentials: input.credentialIds.map(syncAccountAllowCredential),
    includeSecondPrfOutput: false,
  });
}

function emitSyncAccountPromptStarted(callbacks: SyncAccountRecoveryCallbacksV1): void {
  emitSyncAccountEvent({
    onEvent: callbacks.onEvent,
    flowId: callbacks.flowId,
    event: {
      phase: AccountSyncEventPhase.STEP_02_PASSKEY_PROMPT_STARTED,
      status: 'waiting_for_user',
      ...(callbacks.requestedWalletId ? { accountId: callbacks.requestedWalletId } : {}),
      interaction: { kind: 'passkey_assert', overlay: 'show' },
    },
  });
}

function emitSyncAccountPromptSucceeded(callbacks: SyncAccountRecoveryCallbacksV1): void {
  emitSyncAccountEvent({
    onEvent: callbacks.onEvent,
    flowId: callbacks.flowId,
    event: {
      phase: AccountSyncEventPhase.STEP_02_PASSKEY_PROMPT_SUCCEEDED,
      status: 'succeeded',
      ...(callbacks.requestedWalletId ? { accountId: callbacks.requestedWalletId } : {}),
      interaction: { kind: 'passkey_assert', overlay: 'hide' },
    },
  });
}

function emitSyncAccountRelayVerifyStarted(callbacks: SyncAccountRecoveryCallbacksV1): void {
  emitSyncAccountEvent({
    onEvent: callbacks.onEvent,
    flowId: callbacks.flowId,
    event: {
      phase: AccountSyncEventPhase.STEP_03_RELAY_VERIFY_STARTED,
      status: 'started',
      ...(callbacks.requestedWalletId ? { accountId: callbacks.requestedWalletId } : {}),
    },
  });
}

function emitSyncAccountRelayVerifySucceeded(
  callbacks: SyncAccountRecoveryCallbacksV1,
  binding: RecoveryResolvedWalletBinding,
): void {
  emitSyncAccountEvent({
    onEvent: callbacks.onEvent,
    flowId: callbacks.flowId,
    event: {
      phase: AccountSyncEventPhase.STEP_03_RELAY_VERIFY_SUCCEEDED,
      status: 'succeeded',
      accountId: String(binding.walletId),
    },
  });
}

export async function syncAccount(
  context: AccountSyncWebContext,
  walletId: string | null,
  options?: SyncAccountHooksOptions,
): Promise<SyncAccountResult> {
  const requestedWalletId = walletId ? walletIdFromString(String(walletId)) : null;
  const flowId = `account-sync:${String(requestedWalletId || 'discovery')}`;
  let recoveryOwnership: RecoveredCapabilityOwnershipV1 = { kind: 'empty' };
  try {
    const relayerUrl = requireRelayerUrl(context);
    const rpId = requireRpId(context);
    emitSyncAccountEvent({
      onEvent: options?.onEvent,
      flowId,
      event: {
        phase: AccountSyncEventPhase.STEP_01_STARTED,
        status: 'started',
        ...(requestedWalletId ? { accountId: String(requestedWalletId) } : {}),
      },
    });
    const recoveryCallbacks: SyncAccountRecoveryCallbacksV1 = {
      signingSurface: context.signingEngine,
      requestedWalletId: requestedWalletId ? String(requestedWalletId) : null,
      onEvent: options?.onEvent,
      flowId,
    };
    const recovered = await recoverPasskeyEd25519YaoForUnlockV1({
      walletId: requestedWalletId ? String(requestedWalletId) : null,
      relayerUrl,
      rpId,
      fetch: fetchWithGlobalThis,
      collectCredential: collectSyncAccountRecoveryCredential.bind(undefined, recoveryCallbacks),
      activateCapability:
        context.signingEngine.activateVerifiedNearEd25519YaoSigningCapability.bind(
          context.signingEngine,
        ),
      withExactEd25519MaterialOwner:
        context.signingEngine.withExactEd25519MaterialOwner.bind(context.signingEngine),
      sessionPersistence: context.signingEngine,
      onPromptStarted: emitSyncAccountPromptStarted.bind(undefined, recoveryCallbacks),
      onPromptSucceeded: emitSyncAccountPromptSucceeded.bind(undefined, recoveryCallbacks),
      onRelayVerifyStarted: emitSyncAccountRelayVerifyStarted.bind(undefined, recoveryCallbacks),
      onRelayVerifySucceeded: emitSyncAccountRelayVerifySucceeded.bind(
        undefined,
        recoveryCallbacks,
      ),
    });
    const { credential, recovery, verifiedBinding } = recovered;
    recoveryOwnership = { kind: 'registry_owned', recovery };
    await persistRecoveredPasskey({ context, recovery, credential });
    emitSyncAccountEvent({
      onEvent: options?.onEvent,
      flowId,
      event: {
        phase: AccountSyncEventPhase.STEP_04_AUTHENTICATOR_SAVED,
        status: 'succeeded',
        accountId: String(verifiedBinding.walletId),
      },
    });
    emitSyncAccountEvent({
      onEvent: options?.onEvent,
      flowId,
      event: {
        phase: AccountSyncEventPhase.STEP_05_THRESHOLD_SESSION_READY,
        status: 'succeeded',
        accountId: String(verifiedBinding.walletId),
      },
    });
    await context.signingEngine.activateAuthenticatedWalletState({
      walletId: verifiedBinding.walletId,
      nearAccountId: verifiedBinding.nearAccountId,
      signerSlot: verifiedBinding.signerSlot,
      nearClient: context.nearClient,
    });
    const restored = await restoreLocalLoginState({
      context,
      walletId: verifiedBinding.walletId,
      nearAccountId: verifiedBinding.nearAccountId,
      nearEd25519SigningKeyId: verifiedBinding.nearEd25519SigningKeyId,
      signerSlot: verifiedBinding.signerSlot,
    });
    recoveryOwnership = { kind: 'committed' };
    emitSyncAccountEvent({
      onEvent: options?.onEvent,
      flowId,
      event: {
        phase: AccountSyncEventPhase.STEP_06_COMPLETED,
        status: 'succeeded',
        accountId: String(verifiedBinding.walletId),
      },
    });
    return {
      success: true,
      accountId: String(verifiedBinding.walletId),
      walletId: String(verifiedBinding.walletId),
      nearAccountId: String(verifiedBinding.nearAccountId),
      nearEd25519SigningKeyId: String(verifiedBinding.nearEd25519SigningKeyId),
      publicKey: recovery.parsed.operationalPublicKey,
      message: 'Account synced successfully',
      loginState: { isLoggedIn: restored.isLoggedIn },
    };
  } catch (error: unknown) {
    let message = errorMessage(error) || 'syncAccount failed';
    try {
      await disposeRecoveredCapability({ context, ownership: recoveryOwnership });
    } catch (cleanupError: unknown) {
      const cleanupMessage = errorMessage(cleanupError) || 'recovered capability cleanup failed';
      message = `${message}; ${cleanupMessage}`;
    }
    emitSyncAccountEvent({
      onEvent: options?.onEvent,
      flowId,
      event: {
        phase: AccountSyncEventPhase.FAILED,
        status: 'failed',
        ...(requestedWalletId ? { accountId: String(requestedWalletId) } : {}),
        error: { message },
      },
    });
    return syncAccountFailure(message);
  }
}
