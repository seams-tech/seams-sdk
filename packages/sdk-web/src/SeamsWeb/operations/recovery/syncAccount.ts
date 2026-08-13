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
  buildRecoveredWalletSessionState,
  passkeyEd25519YaoLaneReferenceFromRecovery,
  type PasskeyEd25519YaoRecoveryResultV1,
  type ParsedPasskeyEd25519YaoSyncResponseV1,
} from '@/core/signingEngine/flows/recovery/passkeyEd25519YaoRecovery';
import { restoreLocalLoginState } from '@/SeamsWeb/operations/session/restoreLocalLoginState';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { errorMessage } from '@shared/utils/errors';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import { isPlainObject } from '@shared/utils/validation';
import {
  assertSameRecoveryResolvedWalletBinding,
  parseRecoveryResolvedWalletBindingFromResponse,
  type RecoveryResolvedWalletBinding,
} from './recoveryWalletBinding';
import { nearEd25519YaoMaterialActivationFromMetadata } from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { joinCustodyWireFromEnvelopeRecord } from '@/core/signingEngine/walletCustody/joinCustodyWire';
import {
  openOrRejoinWalletCustodyEd25519V1,
  openWalletCustodyEd25519ActiveClientV1,
  walletCustodyCacheEnvelopeFromRecordV1,
  type WalletCustodyActivationFactsV1,
} from '@/core/signingEngine/walletCustody/openCustodyCache';
import {
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  type WalletCustodyEd25519MaterialBindingV1,
} from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import {
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type { ThresholdEcdsaChainTarget } from '@/core/platform/types';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { alphabetizeStringify } from '@shared/utils/digests';

export type { SyncAccountResult };

type SyncOptionsV1 = {
  readonly challengeId: string;
  readonly challengeB64u: string;
  readonly credentialIds: readonly string[];
  readonly walletBinding: RecoveryResolvedWalletBinding | null;
};

export type PreparedSyncAccountChallenge = Readonly<{
  readonly walletId: string | null;
  readonly relayerUrl: string;
  readonly rpId: string;
  readonly syncOptions: SyncOptionsV1;
}>;

export type PasskeyEd25519YaoUnlockRecoveryV1 = {
  readonly recovery: PasskeyEd25519YaoRecoveryResultV1;
  readonly credential: WebAuthnAuthenticationCredential;
  readonly verifiedBinding: RecoveryResolvedWalletBinding;
  readonly ecdsaContinuity: ParsedWalletCustodyEcdsaContinuityV1;
};

type ParsedWalletCustodyEcdsaSignerV1 = {
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly walletKey: {
    readonly walletId: string;
    readonly keyHandle: string;
    readonly ecdsaThresholdKeyId: string;
    readonly signingRootId: string;
    readonly signingRootVersion: string;
    readonly relayerKeyId: string;
    readonly contextBinding32B64u: string;
    readonly derivationClientSharePublicKey33B64u: string;
    readonly participantIds: readonly [number, number];
    readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  };
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
};

type ParsedWalletCustodyEcdsaContinuityV1 = {
  readonly kind: 'wallet_custody_ecdsa_sync_continuity_v1';
  readonly signers: readonly ParsedWalletCustodyEcdsaSignerV1[];
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
  readonly prepared?: SyncOptionsV1;
  readonly credential?: WebAuthnAuthenticationCredential;
  readonly activateCapability: AccountSyncSigningSurface['activateVerifiedNearEd25519YaoMaterial'];
  readonly withExactEd25519MaterialOwner: AccountSyncSigningSurface['withExactEd25519MaterialOwner'];
  readonly sessionPersistence: Pick<
    AccountSyncSigningSurface,
    'upsertEd25519YaoPublicCapabilityLaneReference'
  >;
  readonly rejoinWalletCustodyNearEd25519KeySet: AccountSyncSigningSurface['rejoinWalletCustodyNearEd25519KeySet'];
  readonly rejoinWalletCustodyEvmFamilyKeySet: AccountSyncSigningSurface['rejoinWalletCustodyEvmFamilyKeySet'];
  readonly restoreWalletCustodyEcdsaContinuity: AccountSyncSigningSurface['restoreWalletCustodyEcdsaContinuity'];
  readonly loadWalletCustodyEd25519Material: AccountSyncSigningSurface['loadWalletCustodyEd25519Material'];
  readonly persistWalletCustodyEd25519Material: AccountSyncSigningSurface['persistWalletCustodyEd25519Material'];
  readonly prepareLocalProfile: (
    parsed: ParsedPasskeyEd25519YaoSyncResponseV1,
    credential: WebAuthnAuthenticationCredential,
  ) => Promise<void>;
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

function requireSyncString(record: Record<string, unknown>, field: string): string {
  const value = String(record[field] || '').trim();
  if (!value) throw new Error(`sync-account ${field} is required`);
  return value;
}

function parseSyncEcdsaChainTarget(value: unknown): ThresholdEcdsaChainTarget {
  if (!isPlainObject(value)) throw new Error('sync-account ECDSA chain target is invalid');
  const chainId = Number(value.chainId);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    throw new Error('sync-account ECDSA chain id is invalid');
  }
  if (value.kind === 'evm' && value.namespace === 'eip155') {
    const networkSlug = String(value.networkSlug || '').trim() || `evm-${chainId}`;
    return { kind: 'evm', namespace: 'eip155', chainId, networkSlug };
  }
  if (value.kind === 'tempo') {
    const networkSlug = String(value.networkSlug || '').trim() || `tempo-${chainId}`;
    return { kind: 'tempo', chainId, networkSlug };
  }
  throw new Error('sync-account ECDSA chain family is invalid');
}

function parseSyncEcdsaParticipantIds(value: unknown): readonly [number, number] {
  if (!Array.isArray(value) || value.length !== 2 || value[0] !== 1 || value[1] !== 2) {
    throw new Error('sync-account ECDSA participant ids are invalid');
  }
  return [1, 2];
}

function parseWalletCustodyEcdsaContinuity(
  raw: unknown,
  expectedWalletId: string,
): ParsedWalletCustodyEcdsaContinuityV1 {
  const response = isPlainObject(raw) ? raw : {};
  const continuity = response.ecdsaCustody;
  if (!isPlainObject(continuity) || continuity.kind !== 'wallet_custody_ecdsa_sync_continuity_v1') {
    throw new Error('sync-account ECDSA custody continuity is invalid');
  }
  if (!Array.isArray(continuity.signers)) {
    throw new Error('sync-account ECDSA custody signer list is invalid');
  }
  const signers: ParsedWalletCustodyEcdsaSignerV1[] = [];
  for (const rawSigner of continuity.signers) {
    if (!isPlainObject(rawSigner) || !isPlainObject(rawSigner.walletKey)) {
      throw new Error('sync-account ECDSA custody signer is invalid');
    }
    const walletKey = rawSigner.walletKey;
    const walletId = requireSyncString(walletKey, 'walletId');
    if (walletId !== expectedWalletId) {
      throw new Error('sync-account ECDSA custody signer changed the wallet identity');
    }
    signers.push({
      chainTarget: parseSyncEcdsaChainTarget(rawSigner.chainTarget),
      walletKey: {
        walletId,
        keyHandle: requireSyncString(walletKey, 'keyHandle'),
        ecdsaThresholdKeyId: requireSyncString(walletKey, 'ecdsaThresholdKeyId'),
        signingRootId: requireSyncString(walletKey, 'signingRootId'),
        signingRootVersion: requireSyncString(walletKey, 'signingRootVersion'),
        relayerKeyId: requireSyncString(walletKey, 'relayerKeyId'),
        contextBinding32B64u: requireSyncString(walletKey, 'contextBinding32B64u'),
        derivationClientSharePublicKey33B64u: requireSyncString(
          walletKey,
          'derivationClientSharePublicKey33B64u',
        ),
        participantIds: parseSyncEcdsaParticipantIds(walletKey.participantIds),
        publicCapability: parseRouterAbEcdsaDerivationPublicCapabilityV1(
          walletKey.publicCapability,
        ),
      },
      activationReceipt: parseRouterAbEcdsaRegistrationActivationReceiptV1(
        rawSigner.activationReceipt,
      ),
      runtimePolicyScope: normalizeRuntimePolicyScope(rawSigner.runtimePolicyScope),
    });
  }
  return { kind: 'wallet_custody_ecdsa_sync_continuity_v1', signers };
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

export async function prepareSyncAccountChallenge(
  context: AccountSyncWebContext,
  walletId: string | null,
): Promise<PreparedSyncAccountChallenge> {
  const requestedWalletId = walletId ? walletIdFromString(String(walletId)) : null;
  const relayerUrl = requireRelayerUrl(context);
  const rpId = requireRpId(context);
  const syncOptions = await requestSyncOptions({
    relayerUrl,
    rpId,
    walletId: requestedWalletId ? String(requestedWalletId) : null,
    fetch: fetchWithGlobalThis,
  });
  return Object.freeze({
    walletId: requestedWalletId ? String(requestedWalletId) : null,
    relayerUrl,
    rpId,
    syncOptions,
  });
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
  ownedFactorSecret: Uint8Array;
  relayerUrl: string;
  rpId: string;
  requestedWalletId: string | null;
  optionsBinding: RecoveryResolvedWalletBinding | null;
  verifiedBinding: RecoveryResolvedWalletBinding;
  selectedCredentialId: string;
  sessionPersistence: RecoverPasskeyEd25519YaoForUnlockInputV1['sessionPersistence'];
  activateCapability: RecoverPasskeyEd25519YaoForUnlockInputV1['activateCapability'];
  rejoinWalletCustodyNearEd25519KeySet: RecoverPasskeyEd25519YaoForUnlockInputV1['rejoinWalletCustodyNearEd25519KeySet'];
  loadWalletCustodyEd25519Material: RecoverPasskeyEd25519YaoForUnlockInputV1['loadWalletCustodyEd25519Material'];
  persistWalletCustodyEd25519Material: RecoverPasskeyEd25519YaoForUnlockInputV1['persistWalletCustodyEd25519Material'];
};

function walletCustodyActivationFacts(
  parsed: ParsedPasskeyEd25519YaoSyncResponseV1,
): WalletCustodyActivationFactsV1 {
  const continuity = parsed.capability.registrationContinuity;
  if (continuity.kind !== 'registration') {
    throw new Error('wallet custody cold unlock requires registration continuity');
  }
  return {
    materialActivation: parsed.capability.materialActivation,
    lifecycleId: parsed.capability.lifecycle.lifecycleId,
    signingRootVersion: parsed.capability.lifecycle.rootShareEpoch,
    signingRootId: parsed.capability.applicationBinding.signing_root_id,
    signerSetId: parsed.capability.lifecycle.signerSetId,
    thresholdSessionId: parsed.capability.lifecycle.thresholdSessionId,
    activationTranscriptB64u: base64UrlEncode(Uint8Array.from(continuity.activationTranscript)),
    activationCapabilityBindingB64u: base64UrlEncode(
      Uint8Array.from(parsed.capability.activeCapabilityBinding),
    ),
  };
}

async function loadExpectedWalletCustodyEd25519Material(input: {
  readonly load: RecoverPasskeyEd25519YaoForUnlockInputV1['loadWalletCustodyEd25519Material'];
  readonly parsed: ParsedPasskeyEd25519YaoSyncResponseV1;
}) {
  return await input.load({
    nearAccountId: String(input.parsed.nearAccountId),
    signerSlot: input.parsed.signerSlot,
    expectedRegisteredPublicKeyB64u: base64UrlEncode(
      Uint8Array.from(input.parsed.capability.registeredPublicKey),
    ),
  });
}

function walletCustodyMaterialBinding(input: {
  readonly parsed: ParsedPasskeyEd25519YaoSyncResponseV1;
  readonly applicationBindingDigestB64u: string;
  readonly metadata: Awaited<
    ReturnType<AccountSyncSigningSurface['rejoinWalletCustodyNearEd25519KeySet']>
  >['metadata'];
}): WalletCustodyEd25519MaterialBindingV1 {
  return {
    kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
    applicationBindingDigestB64u: input.applicationBindingDigestB64u,
    registeredPublicKeyB64u: base64UrlEncode(input.metadata.registeredPublicKey),
    participantIds: input.metadata.participantIds,
    stateEpoch: String(input.metadata.stateEpoch),
    walletId: String(input.parsed.walletId),
    nearAccountId: String(input.parsed.nearAccountId),
    nearEd25519SigningKeyId: input.parsed.nearEd25519SigningKeyId,
    signerSlot: input.parsed.signerSlot,
    signingWorkerId: input.parsed.relayerKeyId,
    signingWorkerVerifyingShareB64u: base64UrlEncode(input.metadata.signingWorkerVerifyingShare),
  };
}

async function recoverAndCommitPasskeyEd25519Unlock(
  input: RecoverAndCommitPasskeyEd25519UnlockInput,
): Promise<PasskeyEd25519YaoRecoveryResultV1> {
  const continuity = input.parsed.capability.registrationContinuity;
  if (continuity.kind !== 'registration') {
    throw new Error('wallet custody cold unlock requires registration continuity');
  }
  const custodyWire = joinCustodyWireFromEnvelopeRecord(input.parsed.walletCustody.envelope);
  if (!custodyWire.ok) throw new Error(custodyWire.reason);
  const cacheSecret = input.ownedFactorSecret.slice();
  let rejoinSecret: Uint8Array | null = null;
  let openSecret: Uint8Array | null = null;
  let activeClient: PasskeyEd25519YaoRecoveryResultV1['activeClient'] | null = null;
  try {
    const envelope = walletCustodyCacheEnvelopeFromRecordV1(input.parsed.walletCustody.envelope);
    const activation = walletCustodyActivationFacts(input.parsed);
    const cached = await openOrRejoinWalletCustodyEd25519V1({
      loadCachedMaterial: loadExpectedWalletCustodyEd25519Material.bind(undefined, {
        load: input.loadWalletCustodyEd25519Material,
        parsed: input.parsed,
      }),
      activation,
      envelope,
      ownedFactorSecret: cacheSecret,
    });
    if (cached.kind === 'opened') {
      activeClient = cached.activeClient;
    } else {
      rejoinSecret = input.ownedFactorSecret.slice();
      openSecret = input.ownedFactorSecret.slice();
      const rejoined = await input.rejoinWalletCustodyNearEd25519KeySet({
        walletId: String(input.parsed.walletId),
        custodyJson: custodyWire.custodyJson,
        factorSecret: rejoinSecret.buffer,
        nearEd25519SigningKeyId: input.parsed.nearEd25519SigningKeyId,
        registrationCeremonyId: continuity.admissionRequest.scope.lifecycle_id,
        admissionRequest: continuity.admissionRequest,
        admissionReceipt: continuity.admissionReceipt,
        participantIds: input.parsed.capability.participantIds,
        registeredPublicKeyB64u: base64UrlEncode(
          Uint8Array.from(input.parsed.capability.registeredPublicKey),
        ),
        routerOrigin: new URL(input.relayerUrl).origin,
        walletSessionJwt: input.parsed.session.walletSessionJwt,
      });
      const materialBinding = walletCustodyMaterialBinding({
        parsed: input.parsed,
        applicationBindingDigestB64u: rejoined.localMaterial.applicationBindingDigestB64u,
        metadata: rejoined.metadata,
      });
      await input.persistWalletCustodyEd25519Material({
        binding: materialBinding,
        sealed: {
          ciphertextB64u: rejoined.localMaterial.b64u,
          nonceB64u: rejoined.localMaterial.nonceB64u,
        },
      });
      activeClient = await openWalletCustodyEd25519ActiveClientV1({
        material: {
          binding: materialBinding,
          sealed: {
            ciphertextB64u: rejoined.localMaterial.b64u,
            nonceB64u: rejoined.localMaterial.nonceB64u,
          },
        },
        activation,
        envelope,
        ownedFactorSecret: openSecret,
      });
    }
    if (!activeClient) {
      throw new Error('Wallet custody recovery produced no active Ed25519 client');
    }
    const walletSessionState = buildRecoveredWalletSessionState({
      parsed: input.parsed,
      relayerUrl: input.relayerUrl,
      rpId: input.rpId,
    });
    const recovery: PasskeyEd25519YaoRecoveryResultV1 = {
      activeClient,
      walletSessionState,
      parsed: input.parsed,
    };
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
    const activated = await input.activateCapability({
      activeClient: recovery.activeClient,
      facts: {
        thresholdSessionId: recovery.walletSessionState.thresholdSessionId,
        signer: recovery.walletSessionState.signingLane.identity.signer,
        signingRootId: recovery.walletSessionState.signingRootId,
        signingRootVersion: recovery.walletSessionState.signingRootVersion,
        routerAbNormalSigning: recovery.walletSessionState.routerAbNormalSigning,
        runtimePolicyScope: recovery.walletSessionState.runtimePolicyScope,
        relayerUrl: recovery.walletSessionState.relayerUrl,
      },
    });
    if (!mpcMaterialActivationRefsEqual(activated.materialActivation, recoveredActivation)) {
      throw new Error('Passkey Ed25519 registry activation changed during recovery commit');
    }
    await input.sessionPersistence.upsertEd25519YaoPublicCapabilityLaneReference(
      passkeyEd25519YaoLaneReferenceFromRecovery({
        walletSessionState: recovery.walletSessionState,
        materialActivation: activated.materialActivation,
      }),
    );
    return recovery;
  } catch (error) {
    activeClient?.dispose();
    throw error;
  } finally {
    cacheSecret.fill(0);
    rejoinSecret?.fill(0);
    openSecret?.fill(0);
  }
}

function ethereumAddressFromAddress20B64u(value: string): `0x${string}` {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 20) throw new Error('ECDSA custody address must contain 20 bytes');
  let hex = '0x';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex as `0x${string}`;
}

function assertOneEcdsaCustodyIdentity(
  continuity: ParsedWalletCustodyEcdsaContinuityV1,
): ParsedWalletCustodyEcdsaSignerV1 | null {
  const first = continuity.signers[0];
  if (!first) return null;
  const chainTargets = new Set<string>();
  for (const signer of continuity.signers.slice(1)) {
    if (
      signer.walletKey.keyHandle !== first.walletKey.keyHandle ||
      alphabetizeStringify(signer.walletKey.publicCapability) !==
        alphabetizeStringify(first.walletKey.publicCapability) ||
      alphabetizeStringify(signer.activationReceipt) !==
        alphabetizeStringify(first.activationReceipt) ||
      alphabetizeStringify(signer.runtimePolicyScope) !==
        alphabetizeStringify(first.runtimePolicyScope)
    ) {
      throw new Error('sync-account returned conflicting ECDSA custody identities');
    }
  }
  for (const signer of continuity.signers) {
    const key = thresholdEcdsaChainTargetKey(signer.chainTarget);
    if (chainTargets.has(key)) {
      throw new Error('sync-account returned duplicate ECDSA custody chain targets');
    }
    chainTargets.add(key);
  }
  return first;
}

async function restoreWalletCustodyEcdsaContinuity(input: {
  readonly signingSurface: Pick<
    AccountSyncSigningSurface,
    'rejoinWalletCustodyEvmFamilyKeySet' | 'restoreWalletCustodyEcdsaContinuity'
  >;
  readonly parsed: ParsedPasskeyEd25519YaoSyncResponseV1;
  readonly continuity: ParsedWalletCustodyEcdsaContinuityV1;
  readonly ownedFactorSecret: Uint8Array;
}): Promise<void> {
  const signer = assertOneEcdsaCustodyIdentity(input.continuity);
  if (!signer) return;
  const custodyWire = joinCustodyWireFromEnvelopeRecord(input.parsed.walletCustody.envelope);
  if (!custodyWire.ok) throw new Error(custodyWire.reason);
  const walletKey = signer.walletKey;
  const identity = signer.activationReceipt.ecdsa_activation.public_identity;
  const factorSecret = input.ownedFactorSecret.slice();
  const [firstChainTarget, ...remainingChainTargets] = input.continuity.signers.map(
    (entry) => entry.chainTarget,
  );
  if (!firstChainTarget) return;
  try {
    const rejoined = await input.signingSurface.rejoinWalletCustodyEvmFamilyKeySet({
      walletId: walletKey.walletId,
      custodyJson: custodyWire.custodyJson,
      factorSecret: factorSecret.buffer,
      evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
        walletId: walletKey.walletId,
        signingRootId: walletKey.signingRootId,
        signingRootVersion: walletKey.signingRootVersion,
      }),
      applicationBindingDigestB64u:
        walletKey.publicCapability.context.application_binding_digest_b64u,
      registeredClientRootPublicKey33B64u: walletKey.derivationClientSharePublicKey33B64u,
      relayerPublicIdentityJson: JSON.stringify({
        relayerKeyId: walletKey.relayerKeyId,
        relayerPublicKey33B64u: identity.server_public_key33_b64u,
        groupPublicKey33B64u: identity.threshold_public_key33_b64u,
        ethereumAddress: ethereumAddressFromAddress20B64u(identity.ethereum_address20_b64u),
        relayerShareRetryCounter: identity.server_share_retry_counter,
      }),
    });
    await input.signingSurface.restoreWalletCustodyEcdsaContinuity({
      authority: input.parsed.authority,
      chainTargets: [firstChainTarget, ...remainingChainTargets],
      walletId: walletKey.walletId,
      keyHandle: walletKey.keyHandle,
      ecdsaThresholdKeyId: walletKey.ecdsaThresholdKeyId,
      signingRootId: walletKey.signingRootId,
      signingRootVersion: walletKey.signingRootVersion,
      relayerKeyId: walletKey.relayerKeyId,
      participantIds: walletKey.participantIds,
      publicCapability: walletKey.publicCapability,
      activationReceipt: signer.activationReceipt,
      runtimePolicyScope: signer.runtimePolicyScope,
      readyStateBlobB64u: rejoined.readyStateBlobB64u,
      publicFacts: rejoined.publicFacts,
    });
  } finally {
    factorSecret.fill(0);
  }
}

export async function recoverPasskeyEd25519YaoForUnlockV1(
  input: RecoverPasskeyEd25519YaoForUnlockInputV1,
): Promise<PasskeyEd25519YaoUnlockRecoveryV1> {
  const requestedWalletId = input.walletId === null ? null : String(input.walletId).trim();
  if (input.walletId !== null && !requestedWalletId) {
    throw new Error('passkey Yao unlock recovery requires a valid walletId');
  }
  const syncOptions =
    input.prepared ??
    (await requestSyncOptions({
      relayerUrl: input.relayerUrl,
      rpId: input.rpId,
      walletId: requestedWalletId || null,
      fetch: input.fetch,
    }));
  if (input.prepared && !input.credential) {
    throw new Error('prepared account-sync challenge requires a CTA credential');
  }
  input.onPromptStarted?.();
  const credential = input.credential
    ? input.credential
    : await input.collectCredential({
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
  const ownedFactorSecret = base64UrlDecode(prfFirstB64u);
  try {
    const parsed = parsePasskeyEd25519YaoSyncResponseV1(verified);
    const ecdsaContinuity = parseWalletCustodyEcdsaContinuity(verified, String(parsed.walletId));
    await input.prepareLocalProfile(parsed, credential);
    const recovery = await input.withExactEd25519MaterialOwner({
      materialActivation: parsed.capability.materialActivation,
      nearAccountId: parsed.nearAccountId,
      task: recoverAndCommitPasskeyEd25519Unlock.bind(undefined, {
        parsed,
        ownedFactorSecret,
        relayerUrl: input.relayerUrl,
        rpId: input.rpId,
        requestedWalletId: requestedWalletId || null,
        optionsBinding: syncOptions.walletBinding,
        verifiedBinding,
        selectedCredentialId,
        sessionPersistence: input.sessionPersistence,
        activateCapability: input.activateCapability,
        rejoinWalletCustodyNearEd25519KeySet: input.rejoinWalletCustodyNearEd25519KeySet,
        loadWalletCustodyEd25519Material: input.loadWalletCustodyEd25519Material,
        persistWalletCustodyEd25519Material: input.persistWalletCustodyEd25519Material,
      }),
    });
    await restoreWalletCustodyEcdsaContinuity({
      signingSurface: {
        rejoinWalletCustodyEvmFamilyKeySet: input.rejoinWalletCustodyEvmFamilyKeySet,
        restoreWalletCustodyEcdsaContinuity: input.restoreWalletCustodyEcdsaContinuity,
      },
      parsed,
      continuity: ecdsaContinuity,
      ownedFactorSecret,
    });
    return { recovery, credential, verifiedBinding, ecdsaContinuity };
  } finally {
    ownedFactorSecret.fill(0);
  }
}

async function persistRecoveredPasskey(input: {
  readonly context: AccountSyncWebContext;
  readonly parsed: ParsedPasskeyEd25519YaoSyncResponseV1;
  readonly credential: WebAuthnAuthenticationCredential;
}): Promise<void> {
  const parsed = input.parsed;
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

async function prepareSyncedPasskeyLocalProfile(
  context: AccountSyncWebContext,
  parsed: ParsedPasskeyEd25519YaoSyncResponseV1,
  credential: WebAuthnAuthenticationCredential,
): Promise<void> {
  await persistRecoveredPasskey({ context, parsed, credential });
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

async function syncAccountInternal(
  context: AccountSyncWebContext,
  walletId: string | null,
  options?: SyncAccountHooksOptions,
  preparedChallenge?: PreparedSyncAccountChallenge,
  preparedCredential?: WebAuthnAuthenticationCredential,
): Promise<SyncAccountResult> {
  const requestedWalletId = walletId ? walletIdFromString(String(walletId)) : null;
  if (
    preparedChallenge &&
    preparedChallenge.walletId !== (requestedWalletId ? String(requestedWalletId) : null)
  ) {
    throw new Error('prepared account-sync challenge wallet binding changed');
  }
  const flowId = `account-sync:${String(requestedWalletId || 'discovery')}`;
  let recoveryOwnership: RecoveredCapabilityOwnershipV1 = { kind: 'empty' };
  try {
    const relayerUrl = preparedChallenge?.relayerUrl ?? requireRelayerUrl(context);
    const rpId = preparedChallenge?.rpId ?? requireRpId(context);
    if (preparedChallenge) {
      if (requireRelayerUrl(context) !== relayerUrl || requireRpId(context) !== rpId) {
        throw new Error('prepared account-sync challenge runtime binding changed');
      }
    }
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
      ...(preparedChallenge
        ? { prepared: preparedChallenge.syncOptions, credential: preparedCredential }
        : {}),
      collectCredential: collectSyncAccountRecoveryCredential.bind(undefined, recoveryCallbacks),
      activateCapability: context.signingEngine.activateVerifiedNearEd25519YaoMaterial.bind(
        context.signingEngine,
      ),
      withExactEd25519MaterialOwner: context.signingEngine.withExactEd25519MaterialOwner.bind(
        context.signingEngine,
      ),
      sessionPersistence: context.signingEngine,
      rejoinWalletCustodyNearEd25519KeySet:
        context.signingEngine.rejoinWalletCustodyNearEd25519KeySet.bind(context.signingEngine),
      rejoinWalletCustodyEvmFamilyKeySet:
        context.signingEngine.rejoinWalletCustodyEvmFamilyKeySet.bind(context.signingEngine),
      restoreWalletCustodyEcdsaContinuity:
        context.signingEngine.restoreWalletCustodyEcdsaContinuity.bind(context.signingEngine),
      loadWalletCustodyEd25519Material: context.signingEngine.loadWalletCustodyEd25519Material.bind(
        context.signingEngine,
      ),
      persistWalletCustodyEd25519Material:
        context.signingEngine.persistWalletCustodyEd25519Material.bind(context.signingEngine),
      prepareLocalProfile: prepareSyncedPasskeyLocalProfile.bind(undefined, context),
      onPromptStarted: emitSyncAccountPromptStarted.bind(undefined, recoveryCallbacks),
      onPromptSucceeded: emitSyncAccountPromptSucceeded.bind(undefined, recoveryCallbacks),
      onRelayVerifyStarted: emitSyncAccountRelayVerifyStarted.bind(undefined, recoveryCallbacks),
      onRelayVerifySucceeded: emitSyncAccountRelayVerifySucceeded.bind(
        undefined,
        recoveryCallbacks,
      ),
    });
    const { recovery, verifiedBinding } = recovered;
    recoveryOwnership = { kind: 'registry_owned', recovery };
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

export async function syncAccount(
  context: AccountSyncWebContext,
  walletId: string | null,
  options?: SyncAccountHooksOptions,
): Promise<SyncAccountResult> {
  return await syncAccountInternal(context, walletId, options);
}

export async function syncAccountWithPreparedCredential(
  context: AccountSyncWebContext,
  preparedChallenge: PreparedSyncAccountChallenge,
  credential: WebAuthnAuthenticationCredential,
  options?: SyncAccountHooksOptions,
): Promise<SyncAccountResult> {
  return await syncAccountInternal(
    context,
    preparedChallenge.walletId,
    options,
    preparedChallenge,
    credential,
  );
}
