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
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { errorMessage } from '@shared/utils/errors';
import type { WalletCapabilitySubjectV1 } from '@shared/device-linking/contracts';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseThresholdEd25519SessionId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type MpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletId,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import { isPlainObject } from '@shared/utils/validation';
import { IndexedDBManager, walletSessionAuthorizations } from '@/core/indexedDB';
import { persistPasskeyEd25519YaoSignerMaterialV1 } from '@/core/signingEngine/session/passkey/ed25519YaoLocalMaterial';
import { buildThresholdEd25519Participants2pV1 } from '@shared/threshold/participants';
import {
  assertSameRecoveryWalletIdentity,
  parseRecoveryResolvedWalletBindingFromResponse,
  type RecoveryResolvedWalletBinding,
} from './recoveryWalletBinding';
import { nearEd25519YaoMaterialActivationFromMetadata } from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { joinCustodyWireFromEnvelopeRecord } from '@/core/signingEngine/walletCustody/joinCustodyWire';
import type { RouterAbEd25519YaoSealableActiveClientV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import {
  openOrRejoinWalletCustodyEd25519V1,
  openWalletCustodyEd25519ActiveClientV1,
  walletCustodyActivationFactsFromActiveClientMetadataV1,
  walletCustodyCacheEnvelopeFromRecordV1,
  type WalletCustodyActivationFactsV1,
} from '@/core/signingEngine/walletCustody/openCustodyCache';
import {
  buildPasskeyEd25519RestoreMetadata,
  persistPasskeyEd25519YaoSessionForRefresh,
} from '@/core/signingEngine/session/passkey/ed25519YaoSealedSession';
import {
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  type WalletCustodyEd25519MaterialBindingV1,
} from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import { rememberPasskeyCustodySessionEnvelope } from '@/core/signingEngine/session/passkey/passkeyCustodySessionCache';
import {
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaCredentialFreeSessionActivationResponseV1,
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaCredentialFreeSessionActivationResponseV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type { ThresholdEcdsaChainTarget } from '@/core/platform/types';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { alphabetizeStringify } from '@shared/utils/digests';
import { replaceActiveWalletAuthorityEd25519MaterialActivationV1 } from '@shared/authorization/walletAuthority';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionMintId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';

export type { SyncAccountResult };

type SyncAccountAttemptV1 =
  | { readonly kind: 'initial' }
  | {
      readonly kind: 'replacement_after_committed';
      readonly walletId: WalletId;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
    };

type SyncAccountVerificationResultV1 =
  | { readonly kind: 'verified'; readonly response: Record<string, unknown> }
  | {
      readonly kind: 'already_committed';
      readonly walletId: WalletId;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
    };

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

export type PasskeyEd25519YaoUnlockRecoveryV1 =
  | {
      readonly kind: 'recovered';
      readonly recovery: PasskeyEd25519YaoRecoveryResultV1;
      readonly credential: WebAuthnAuthenticationCredential;
      readonly verifiedBinding: RecoveryResolvedWalletBinding;
      readonly ecdsaContinuity: ParsedWalletCustodyEcdsaContinuityV1;
    }
  | {
      readonly kind: 'already_committed';
      readonly walletId: WalletId;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
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

type ParsedWalletCustodyEcdsaContinuityV1 =
  | {
      readonly kind: 'wallet_custody_ecdsa_sync_continuity_v1';
      readonly state: 'absent';
      readonly signers: readonly [];
      readonly sessionActivation?: never;
    }
  | {
      readonly kind: 'wallet_custody_ecdsa_sync_continuity_v1';
      readonly state: 'activated';
      readonly signers: readonly [
        ParsedWalletCustodyEcdsaSignerV1,
        ...ParsedWalletCustodyEcdsaSignerV1[],
      ];
      readonly sessionActivation: RouterAbEcdsaCredentialFreeSessionActivationResponseV1;
    };

export type RecoverPasskeyEd25519YaoForUnlockInputV1 = {
  readonly walletId: string | null;
  readonly relayerUrl: string;
  readonly rpId: string;
  readonly fetch: typeof fetch;
  readonly expectedCredentialIdB64u: WebAuthnCredentialIdB64u | null;
  readonly expectedWalletAuthMethodId: WalletAuthMethodId | null;
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
    'hydrateSigningSession' | 'upsertEd25519YaoPublicCapabilityLaneReference'
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

type EcdsaSignWalletCapabilitySubjectV1 = {
  readonly kind: 'sign';
  readonly keyFamily: 'ecdsa_secp256k1';
  readonly materialActivation: MpcMaterialActivationRef;
};

function isEcdsaSignWalletSessionSubject(
  subject: WalletCapabilitySubjectV1,
): subject is EcdsaSignWalletCapabilitySubjectV1 {
  return subject.kind === 'sign' && subject.keyFamily === 'ecdsa_secp256k1';
}

function findEcdsaSignWalletSessionSubject(
  subjects: readonly WalletCapabilitySubjectV1[],
): EcdsaSignWalletCapabilitySubjectV1 | null {
  for (const subject of subjects) {
    if (isEcdsaSignWalletSessionSubject(subject)) return subject;
  }
  return null;
}

function parseWalletCustodyEcdsaContinuity(
  raw: unknown,
  expected: ParsedPasskeyEd25519YaoSyncResponseV1,
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
    if (walletId !== String(expected.walletId)) {
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
  const first = signers[0];
  if (!first) {
    if (response.ecdsaSession !== undefined || response.ecdsaActivationReceipt !== undefined) {
      throw new Error('sync-account returned an ECDSA session without custody continuity');
    }
    return {
      kind: 'wallet_custody_ecdsa_sync_continuity_v1',
      state: 'absent',
      signers: [],
    };
  }
  const sessionActivation = parseRouterAbEcdsaCredentialFreeSessionActivationResponseV1(
    response.ecdsaSession,
  );
  const activationReceipt = parseRouterAbEcdsaRegistrationActivationReceiptV1(
    response.ecdsaActivationReceipt,
  );
  const ecdsaSignSubject = findEcdsaSignWalletSessionSubject(
    expected.walletSession.capabilitySubjects,
  );
  if (
    !ecdsaSignSubject ||
    sessionActivation.session.authorization_id !== expected.walletSession.authorizationId ||
    alphabetizeStringify(sessionActivation.public_capability) !==
      alphabetizeStringify(first.walletKey.publicCapability) ||
    alphabetizeStringify(activationReceipt) !== alphabetizeStringify(first.activationReceipt) ||
    !mpcMaterialActivationRefsEqual(
      ecdsaSignSubject.materialActivation,
      routerAbMpcMaterialActivationRefFromWire(
        sessionActivation.public_capability.material_activation,
      ),
    ) ||
    sessionActivation.session.wallet_session_id !== expected.session.walletSessionId ||
    sessionActivation.session.quota_id !== expected.session.quotaId ||
    sessionActivation.session.expires_at_ms !== expected.session.expiresAtMs ||
    sessionActivation.session.remaining_uses !== expected.session.remainingUses
  ) {
    throw new Error('sync-account ECDSA session changed the Wallet Session or custody identity');
  }
  return {
    kind: 'wallet_custody_ecdsa_sync_continuity_v1',
    state: 'activated',
    signers: [first, ...signers.slice(1)],
    sessionActivation,
  };
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

function requireSelectedCredentialId(
  credential: WebAuthnAuthenticationCredential,
): WebAuthnCredentialIdB64u {
  const id = String(credential.id || '').trim();
  const rawId = String(credential.rawId || '').trim();
  if (!id || !rawId || id !== rawId) {
    throw new Error('selected passkey credential identity is invalid');
  }
  const parsed = parseWebAuthnCredentialIdB64u(rawId);
  if (!parsed.ok) throw new Error('selected passkey credential identity is invalid');
  return parsed.value;
}

function credentialIdsForSyncAccountRecovery(
  syncOptions: SyncOptionsV1,
  expectedCredentialIdB64u: WebAuthnCredentialIdB64u | null,
): readonly string[] {
  if (expectedCredentialIdB64u === null) return syncOptions.credentialIds;
  if (!syncOptions.credentialIds.includes(expectedCredentialIdB64u)) {
    throw new Error('replacement account-sync challenge changed the selected passkey');
  }
  return [expectedCredentialIdB64u];
}

function parseCanonicalTerminalIdentity<T>(
  raw: unknown,
  parser: (value: unknown) => { readonly ok: true; readonly value: T } | { readonly ok: false },
): T | null {
  if (typeof raw !== 'string' || raw.trim() !== raw || !raw) return null;
  const parsed = parser(raw);
  return parsed.ok ? parsed.value : null;
}

function parseExactSyncAccountAlreadyCommittedResponse(input: {
  readonly response: Response;
  readonly raw: unknown;
  readonly expectedWalletId: WalletId | null;
}): { readonly walletId: WalletId; readonly walletAuthMethodId: WalletAuthMethodId } | null {
  if (input.response.status !== 409 || !isPlainObject(input.raw)) return null;
  const raw = input.raw;
  if (
    raw.ok !== false ||
    raw.code !== 'already_committed' ||
    raw.kind !== 'already_committed' ||
    raw.next !== 'unlock_exact_method'
  ) {
    return null;
  }
  const identityFields = [
    'walletId',
    'authorityId',
    'walletAuthMethodId',
    'mintId',
    'authorizationId',
    'walletSessionId',
    'quotaId',
  ] as const;
  if (
    identityFields.some((field) => {
      const value = raw[field];
      return typeof value !== 'string' || !value.trim();
    })
  ) {
    return null;
  }
  if (
    'walletSessionToken' in raw ||
    'walletSessionJwt' in raw ||
    'sessionKind' in raw ||
    'walletSession' in raw ||
    'operationCredential' in raw ||
    'credential' in raw
  ) {
    return null;
  }
  const walletId = parseCanonicalTerminalIdentity(raw.walletId, parseWalletId);
  const authorityId = parseCanonicalTerminalIdentity(raw.authorityId, parseWalletAuthorityId);
  const walletAuthMethodId = parseCanonicalTerminalIdentity(
    raw.walletAuthMethodId,
    parseWalletAuthMethodId,
  );
  const mintId = parseCanonicalTerminalIdentity(raw.mintId, parseWalletSessionMintId);
  const authorizationId = parseCanonicalTerminalIdentity(
    raw.authorizationId,
    parseWalletSessionAuthorizationId,
  );
  const walletSessionId = parseCanonicalTerminalIdentity(raw.walletSessionId, parseWalletSessionId);
  const quotaId = parseCanonicalTerminalIdentity(raw.quotaId, parseMpcWalletSigningQuotaId);
  if (
    !walletId ||
    !authorityId ||
    !walletAuthMethodId ||
    !mintId ||
    !authorizationId ||
    !walletSessionId ||
    !quotaId
  ) {
    return null;
  }
  if (input.expectedWalletId !== null && walletId !== input.expectedWalletId) {
    return null;
  }
  return { walletId, walletAuthMethodId };
}

async function verifySyncCredential(input: {
  readonly relayerUrl: string;
  readonly challengeId: string;
  readonly expectedWalletId: WalletId | null;
  readonly selectedCredentialId: WebAuthnCredentialIdB64u;
  readonly credential: WebAuthnAuthenticationCredential;
  readonly fetch: typeof fetch;
}): Promise<SyncAccountVerificationResultV1> {
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
    const committed = parseExactSyncAccountAlreadyCommittedResponse({
      response,
      raw,
      expectedWalletId: input.expectedWalletId,
    });
    if (committed) {
      return {
        kind: 'already_committed',
        walletId: committed.walletId,
        walletAuthMethodId: committed.walletAuthMethodId,
        credentialIdB64u: input.selectedCredentialId,
      };
    }
    const message = isPlainObject(raw) ? String(raw.message || raw.code || '') : '';
    throw new Error(message || `sync-account/verify failed (HTTP ${response.status})`);
  }
  return { kind: 'verified', response: raw };
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
  readonly requestedWalletId: WalletId | null;
  readonly expectedWalletAuthMethodId: WalletAuthMethodId | null;
  readonly rpId: string;
  readonly optionsBinding: RecoveryResolvedWalletBinding | null;
  readonly verifiedBinding: RecoveryResolvedWalletBinding;
  readonly parsed: ParsedPasskeyEd25519YaoSyncResponseV1;
  readonly selectedCredentialId: WebAuthnCredentialIdB64u;
}): void {
  if (input.optionsBinding) {
    assertSameRecoveryWalletIdentity(
      input.optionsBinding,
      input.verifiedBinding,
      'sync-account/verify',
    );
  }
  const recovered = input.parsed;
  if (
    input.verifiedBinding.rpId !== input.rpId ||
    (input.requestedWalletId !== null &&
      input.requestedWalletId !== input.verifiedBinding.walletId) ||
    String(recovered.walletId) !== String(input.verifiedBinding.walletId) ||
    String(recovered.nearAccountId) !== String(input.verifiedBinding.nearAccountId) ||
    recovered.nearEd25519SigningKeyId !== String(input.verifiedBinding.nearEd25519SigningKeyId) ||
    recovered.credentialIdB64u !== input.verifiedBinding.credentialIdB64u ||
    recovered.credentialIdB64u !== input.selectedCredentialId ||
    (input.expectedWalletAuthMethodId !== null &&
      String(recovered.walletAuthMethodId) !== input.expectedWalletAuthMethodId) ||
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

function isSealablePasskeyEd25519YaoClient(
  activeClient: PasskeyEd25519YaoRecoveryResultV1['activeClient'],
): activeClient is RouterAbEd25519YaoSealableActiveClientV1 {
  return (
    'sealLocalMaterial' in activeClient && typeof activeClient.sealLocalMaterial === 'function'
  );
}

async function recoverAndCommitPasskeyEd25519Unlock(
  input: RecoverAndCommitPasskeyEd25519UnlockInput,
): Promise<PasskeyEd25519YaoRecoveryResultV1> {
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
        recoveryBasis: input.parsed.capability,
        routerOrigin: new URL(input.relayerUrl).origin,
        walletSessionToken: input.parsed.operationCredential.token,
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
        activation: walletCustodyActivationFactsFromActiveClientMetadataV1(rejoined.metadata),
        envelope,
        ownedFactorSecret: openSecret,
      });
    }
    if (!activeClient) {
      throw new Error('Wallet custody recovery produced no active Ed25519 client');
    }
    if (!isSealablePasskeyEd25519YaoClient(activeClient)) {
      throw new Error('Wallet custody recovery produced an unsealable Ed25519 client');
    }
    const recoveredThresholdSessionId = parseThresholdEd25519SessionId(
      activeClient.metadata().scope.threshold_session_id,
    );
    if (!recoveredThresholdSessionId.ok) {
      throw new Error('Wallet custody recovery returned an invalid threshold session identity');
    }
    const envelopeFactor = input.parsed.walletCustody.envelope.factor;
    if (envelopeFactor.kind !== 'passkey') {
      throw new Error('Wallet custody recovery returned a different factor authority');
    }
    await persistPasskeyEd25519YaoSignerMaterialV1({
      store: IndexedDBManager,
      activeClient,
      identity: {
        walletId: String(input.parsed.walletId),
        nearAccountId: String(input.parsed.nearAccountId),
        nearEd25519SigningKeyId: String(input.parsed.nearEd25519SigningKeyId),
        thresholdSessionId: recoveredThresholdSessionId.value,
        signerSlot: input.parsed.signerSlot,
        rpId: envelopeFactor.rpId,
        credentialIdB64u: envelopeFactor.credentialIdB64u,
        signingRootId: input.parsed.capability.applicationBinding.signing_root_id,
        signingRootVersion: input.parsed.capability.lifecycle.rootShareEpoch,
        signingWorkerId: input.parsed.relayerKeyId,
      },
      stableServerScope: {
        relayerKeyId: input.parsed.relayerKeyId,
        participantIds: input.parsed.session.participantIds,
        runtimePolicyScope: input.parsed.capability.runtimePolicyScope,
        routerAbNormalSigning: input.parsed.session.routerAbNormalSigning,
      },
      passkeyPrfFirstB64u: base64UrlEncode(input.ownedFactorSecret),
    });
    const walletSessionState = buildRecoveredWalletSessionState({
      parsed: input.parsed,
      relayerUrl: input.relayerUrl,
      rpId: input.rpId,
      thresholdSessionId: recoveredThresholdSessionId.value,
    });
    const recovery: PasskeyEd25519YaoRecoveryResultV1 = {
      activeClient,
      walletSessionState,
      parsed: input.parsed,
    };
    const recoveredActivation = nearEd25519YaoMaterialActivationFromMetadata(
      recovery.activeClient.metadata(),
    );
    await persistPasskeyEd25519YaoSessionForRefresh({
      persistence: input.sessionPersistence,
      session: recovery.walletSessionState,
      prfFirstB64u: base64UrlEncode(input.ownedFactorSecret),
      ed25519Restore: buildPasskeyEd25519RestoreMetadata({
        rpId: envelopeFactor.rpId,
        nearAccountId: String(input.parsed.nearAccountId),
        nearEd25519SigningKeyId: String(input.parsed.nearEd25519SigningKeyId),
        relayerKeyId: input.parsed.relayerKeyId,
        participantIds: input.parsed.session.participantIds,
        runtimePolicyScope: input.parsed.session.runtimePolicyScope,
        signerSlot: input.parsed.signerSlot,
        routerAbNormalSigning: input.parsed.session.routerAbNormalSigning,
        credentialIdB64u: envelopeFactor.credentialIdB64u,
        materialActivation: recoveredActivation,
      }),
      materialActivation: recoveredActivation,
    });
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
    const recoveredAuthority = await replaceActiveWalletAuthorityEd25519MaterialActivationV1({
      authority: input.parsed.foundingAuthority,
      materialActivation: activated.materialActivation,
      updatedAtMs: Date.now(),
    });
    await IndexedDBManager.persistFoundingWalletAuthority({
      authority: recoveredAuthority,
      authMethod: input.parsed.foundingAuthMethod,
    });
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
  if (continuity.state === 'absent') return null;
  const first = continuity.signers[0];
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
  const requestedWalletIdString = input.walletId === null ? null : String(input.walletId).trim();
  if (input.walletId !== null && !requestedWalletIdString) {
    throw new Error('passkey Yao unlock recovery requires a valid walletId');
  }
  const requestedWalletId = requestedWalletIdString
    ? walletIdFromString(requestedWalletIdString)
    : null;
  const syncOptions =
    input.prepared ??
    (await requestSyncOptions({
      relayerUrl: input.relayerUrl,
      rpId: input.rpId,
      walletId: requestedWalletId ? String(requestedWalletId) : null,
      fetch: input.fetch,
    }));
  if (input.prepared && !input.credential) {
    throw new Error('prepared account-sync challenge requires a CTA credential');
  }
  const credentialIds = credentialIdsForSyncAccountRecovery(
    syncOptions,
    input.expectedCredentialIdB64u,
  );
  input.onPromptStarted?.();
  const credential = input.credential
    ? input.credential
    : await input.collectCredential({
        challengeB64u: syncOptions.challengeB64u,
        credentialIds,
      });
  input.onPromptSucceeded?.();
  const selectedCredentialId = requireSelectedCredentialId(credential);
  if (
    input.expectedCredentialIdB64u !== null &&
    selectedCredentialId !== input.expectedCredentialIdB64u
  ) {
    throw new Error('replacement account-sync assertion changed the selected passkey');
  }
  const prfFirstB64u = getPrfFirstB64uFromCredential(credential);
  if (!prfFirstB64u) throw new Error('selected passkey did not return PRF.first');
  input.onRelayVerifyStarted?.();
  const verification = await verifySyncCredential({
    relayerUrl: input.relayerUrl,
    challengeId: syncOptions.challengeId,
    expectedWalletId: requestedWalletId,
    selectedCredentialId,
    credential,
    fetch: input.fetch,
  });
  if (verification.kind === 'already_committed') return verification;
  const verified = verification.response;
  const verifiedBinding = parseRecoveryResolvedWalletBindingFromResponse(
    verified,
    'sync-account/verify',
  );
  input.onRelayVerifySucceeded?.(verifiedBinding);
  const ownedFactorSecret = base64UrlDecode(prfFirstB64u);
  try {
    const parsed = parsePasskeyEd25519YaoSyncResponseV1(verified);
    const ecdsaContinuity = parseWalletCustodyEcdsaContinuity(verified, parsed);
    assertRecoveredCapabilityBinding({
      requestedWalletId,
      expectedWalletAuthMethodId: input.expectedWalletAuthMethodId,
      rpId: input.rpId,
      optionsBinding: syncOptions.walletBinding,
      verifiedBinding,
      parsed,
      selectedCredentialId,
    });
    await input.prepareLocalProfile(parsed, credential);
    const recovery = await input.withExactEd25519MaterialOwner({
      materialActivation: parsed.capability.materialActivation,
      nearAccountId: parsed.nearAccountId,
      task: recoverAndCommitPasskeyEd25519Unlock.bind(undefined, {
        parsed,
        ownedFactorSecret,
        relayerUrl: input.relayerUrl,
        rpId: input.rpId,
        sessionPersistence: input.sessionPersistence,
        activateCapability: input.activateCapability,
        rejoinWalletCustodyNearEd25519KeySet: input.rejoinWalletCustodyNearEd25519KeySet,
        loadWalletCustodyEd25519Material: input.loadWalletCustodyEd25519Material,
        persistWalletCustodyEd25519Material: input.persistWalletCustodyEd25519Material,
      }),
    });
    await rememberPasskeyCustodySessionEnvelope({
      walletId: String(parsed.walletId),
      credentialIdB64u: parsed.credentialIdB64u,
      envelope: parsed.walletCustody.envelope,
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
    return { kind: 'recovered', recovery, credential, verifiedBinding, ecdsaContinuity };
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
    nearEd25519SigningKeyId: parsed.nearEd25519SigningKeyId,
    lastUpdated: Date.now(),
    passkeyCredential: {
      id: String(input.credential.id || ''),
      rawId: String(input.credential.rawId || ''),
    },
    version: 2,
  });
  // The signer rows live under the NEAR account profile; session identity
  // finds them by pivoting through the canonical wallet profile's provisioning
  // record. A synced device joins a wallet whose NEAR account already exists,
  // so provisioning is observed ready — without this write the wallet unlocks
  // and then cannot name its own NEAR identity.
  await input.context.signingEngine.setWalletNearProvisioningState({
    walletId: parsed.walletId,
    status: 'near_ready',
    nearAccountId: parsed.nearAccountId,
  });
  const walletAuthenticators = await IndexedDBManager.listWalletPasskeyAuthenticators(
    String(parsed.walletId),
  );
  const existingAuthenticator = walletAuthenticators.find(
    (authenticator) => authenticator.credentialId === parsed.credentialIdB64u,
  );
  if (existingAuthenticator) {
    if (
      existingAuthenticator.signerSlot !== parsed.signerSlot ||
      base64UrlEncode(existingAuthenticator.credentialPublicKey) !== parsed.credentialPublicKeyB64u
    ) {
      throw new Error('Stored linked passkey authenticator does not match account sync');
    }
  } else {
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

  await IndexedDBManager.persistFoundingWalletAuthority({
    authority: parsed.foundingAuthority,
    authMethod: parsed.foundingAuthMethod,
  });
}

async function persistRecoveredNearThresholdKeyMaterial(
  signingSurface: Pick<AccountSyncSigningSurface, 'storeNearThresholdKeyMaterial'>,
  parsed: ParsedPasskeyEd25519YaoSyncResponseV1,
): Promise<void> {
  await signingSurface.storeNearThresholdKeyMaterial({
    nearAccountId: parsed.nearAccountId,
    signerSlot: parsed.signerSlot,
    publicKey: parsed.operationalPublicKey,
    relayerKeyId: parsed.relayerKeyId,
    keyVersion: parsed.keyVersion,
    participants: buildThresholdEd25519Participants2pV1({
      clientParticipantId: parsed.session.participantIds[0],
      relayerParticipantId: parsed.session.participantIds[1],
      relayerKeyId: parsed.relayerKeyId,
      clientShareDerivation: 'prf_first_v1',
    }),
    signerId: parsed.operationalPublicKey,
  });
}

async function persistRecoveredWalletSessionAuthorization(
  parsed: ParsedPasskeyEd25519YaoSyncResponseV1,
): Promise<void> {
  await walletSessionAuthorizations.writeExactWithOperationCredential({
    record: parsed.walletSession,
    operationCredential: parsed.operationCredential,
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
  attempt: SyncAccountAttemptV1,
  options?: SyncAccountHooksOptions,
  preparedChallenge?: PreparedSyncAccountChallenge,
  preparedCredential?: WebAuthnAuthenticationCredential,
): Promise<SyncAccountResult> {
  const requestedWalletId = walletId ? walletIdFromString(String(walletId)) : null;
  if (attempt.kind === 'replacement_after_committed' && requestedWalletId !== attempt.walletId) {
    throw new Error('replacement account-sync attempt changed the committed wallet');
  }
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
      expectedCredentialIdB64u:
        attempt.kind === 'replacement_after_committed' ? attempt.credentialIdB64u : null,
      expectedWalletAuthMethodId:
        attempt.kind === 'replacement_after_committed' ? attempt.walletAuthMethodId : null,
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
    if (recovered.kind === 'already_committed') {
      if (attempt.kind === 'initial') {
        return await syncAccountInternal(
          context,
          recovered.walletId,
          {
            kind: 'replacement_after_committed',
            walletId: recovered.walletId,
            walletAuthMethodId: recovered.walletAuthMethodId,
            credentialIdB64u: recovered.credentialIdB64u,
          },
          options,
        );
      }
      throw new Error(
        'sync-account/verify remained already committed after one replacement attempt',
      );
    }
    const { recovery, verifiedBinding } = recovered;
    recoveryOwnership = { kind: 'registry_owned', recovery };
    await persistRecoveredWalletSessionAuthorization(recovery.parsed);
    await persistRecoveredNearThresholdKeyMaterial(context.signingEngine, recovery.parsed);
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
      loginState: { isLoggedIn: true },
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
  return await syncAccountInternal(context, walletId, { kind: 'initial' }, options);
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
    { kind: 'initial' },
    options,
    preparedChallenge,
    credential,
  );
}
