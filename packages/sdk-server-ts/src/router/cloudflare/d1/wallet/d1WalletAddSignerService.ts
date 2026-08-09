import {
  addSignerIntentGrantFromString,
  computeAddSignerIntentDigestB64u,
  type AddSignerIntentV1,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type {
  WalletAddSignerFinalizeRequest,
  WalletAddSignerFinalizeResponse,
  WalletAddSignerEcdsaActivationRequest,
  WalletAddSignerEcdsaActivationResponse,
  WalletAddSignerEcdsaDerivationRespondRequest,
  WalletAddSignerEcdsaDerivationRespondResponse,
  WalletAddSignerStartRequest,
  WalletAddSignerStartResponse,
} from '../../../../core/registrationContracts';
import { registrationPreparationIdFromString } from '../../../../core/registrationContracts';
import type { D1WalletStore } from '../../../../core/d1WalletStore';
import type {
  StoredEd25519YaoAddSignerActivation,
  StoredEcdsaAddSignerActivated,
  StoredEcdsaAddSignerActivationClaimed,
  StoredWalletAddSignerCeremony,
  StoredAddSignerIntent,
  StoredWalletAddSignerFinalizeRequest,
  StoredWalletAddSignerSignerState,
} from '../../../../core/RegistrationCeremonyStore';
import { CloudflareD1RegistrationCeremonyIntentStore } from '../registration/d1RegistrationCeremonyStore';
import {
  buildD1EcdsaWalletKeysFromBootstrap,
  buildD1WalletEcdsaSignerRecords,
  normalizeThresholdEcdsaChainTargets,
  parseD1WalletAddSignerFinalizeTerminalResponse,
  parseD1StoredAddSignerIntent,
  parseD1StoredAddSignerAuth,
  parseD1StoredWalletAddSignerCeremony,
  parseD1RuntimePolicyScope,
  parseWalletIdForIntent,
} from '../registration/d1RegistrationCeremonyRecords';
import { buildD1EvmFamilyEcdsaRegistrationPrepare } from '../registration/d1EvmFamilyEcdsaRegistrationBranch';
import { CloudflareD1WalletAuthMethodService } from './d1WalletAuthMethodService';
import {
  buildRouterAbEd25519YaoAddSignerAdmissionRequestV1,
  createRouterAbEd25519YaoMaterialActivationRefV1,
  type RouterAbEd25519YaoProductRegistrationRuntimeV1,
} from '../../../domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import { buildRouterAbEd25519YaoRegistrationCapabilityRecordV1 } from '../../../domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
  implicitNearAccountIdFromEd25519PublicKeyBytes,
} from '../ed25519Yao/d1Ed25519YaoWalletSigner';
import { buildRouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { computeWalletAddSignerEcdsaActivationRequestDigestB64u } from '@shared/utils/walletAddSignerActivation';
import {
  routerAbEcdsaStrictRegistrationRequestMatchesFacts,
  type RouterAbEcdsaStrictRegistrationPort,
} from '../../../domains/ecdsa/routerAbEcdsaStrictRegistration';
import {
  buildActivatedEcdsaFamilyBootstrap,
  ecdsaStrictRegistrationAuthority,
  exactEcdsaParticipantPair,
} from '../registration/d1WalletRegistrationService';
import {
  parseRouterAbEd25519YaoRegistrationSideEffectRecordV1,
  runRouterAbEd25519YaoRegistrationSideEffectV1,
  throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1,
  type RouterAbEd25519YaoRegistrationSideEffectRecordV1,
  type RouterAbEd25519YaoRegistrationSideEffectStoreV1,
} from '../../../domains/ed25519Yao/registration/routerAbEd25519YaoRegistrationSideEffectBoundary';

type StartWalletAddSignerInput = WalletAddSignerStartRequest;
type RespondWalletAddSignerDerivationInput = WalletAddSignerEcdsaDerivationRespondRequest;
type ActivateWalletAddSignerEcdsaInput = WalletAddSignerEcdsaActivationRequest;
type FinalizeWalletAddSignerInput = WalletAddSignerFinalizeRequest;

type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore;
type WalletStoreProvider = () => D1WalletStore;
type Ed25519YaoProductRegistrationProvider =
  () => RouterAbEd25519YaoProductRegistrationRuntimeV1 | null;

type Ed25519AddSignerIntent = AddSignerIntentV1 & {
  readonly signerSelection: Extract<AddSignerIntentV1['signerSelection'], { mode: 'ed25519' }>;
};

const ADD_SIGNER_CEREMONY_TTL_MS = 10 * 60_000;
const ADD_SIGNER_REPLAY_TTL_MS = 10 * 60_000;
const WALLET_ADD_SIGNER_START_RESUME_AFTER_MS = 30_000;
const WALLET_ADD_SIGNER_FINALIZE_RESUME_AFTER_MS = 30_000;
const WALLET_ADD_SIGNER_ROUTER_POLICY_VERSION = 'wallet-add-signer-v1';

export type D1WalletAddSignerStartPreparedV1 = {
  readonly kind: 'd1_wallet_add_signer_start_prepared_v1';
  readonly addSignerCeremonyId: string;
  readonly registrationPreparationId: string;
  readonly expiresAtMs: number;
  readonly storedIntent: StoredAddSignerIntent;
  readonly auth: StoredWalletAddSignerCeremony['auth'];
};

export type D1WalletAddSignerStartTerminalV1 =
  | {
      readonly kind: 'd1_wallet_add_signer_start_succeeded_v1';
      readonly ceremony: StoredWalletAddSignerCeremony;
      readonly response: Extract<WalletAddSignerStartResponse, { readonly ok: true }>;
    }
  | {
      readonly kind: 'd1_wallet_add_signer_start_rejected_v1';
      readonly response: Extract<WalletAddSignerStartResponse, { readonly ok: false }>;
    };

export type D1WalletAddSignerStartSideEffectStore = RouterAbEd25519YaoRegistrationSideEffectStoreV1<
  D1WalletAddSignerStartTerminalV1,
  D1WalletAddSignerStartPreparedV1
>;

export type D1WalletAddSignerStartSideEffectRecord =
  RouterAbEd25519YaoRegistrationSideEffectRecordV1<
    D1WalletAddSignerStartTerminalV1,
    D1WalletAddSignerStartPreparedV1
  >;

export type D1WalletAddSignerFinalizePreparedV1 =
  | {
      readonly kind: 'd1_wallet_add_signer_finalize_ed25519_prepared_v1';
      readonly finalizingAtMs: number;
    }
  | {
      readonly kind: 'd1_wallet_add_signer_finalize_ecdsa_prepared_v1';
      readonly signerWriteAtMs: number;
    };

export type D1WalletAddSignerFinalizeSideEffectStore =
  RouterAbEd25519YaoRegistrationSideEffectStoreV1<
    WalletAddSignerFinalizeResponse,
    D1WalletAddSignerFinalizePreparedV1
  >;

export type D1WalletAddSignerFinalizeSideEffectRecord =
  RouterAbEd25519YaoRegistrationSideEffectRecordV1<
    WalletAddSignerFinalizeResponse,
    D1WalletAddSignerFinalizePreparedV1
  >;

function addSignerRecordValue(value: unknown): Record<string, unknown> | null {
  return isPlainObject(value) ? value : null;
}

function walletAddSignerStartResponseFromCeremony(
  ceremony: StoredWalletAddSignerCeremony,
): Extract<WalletAddSignerStartResponse, { readonly ok: true }> | null {
  const base = {
    ok: true as const,
    addSignerCeremonyId: ceremony.addSignerCeremonyId,
    intent: ceremony.intent,
  };
  switch (ceremony.signerState.kind) {
    case 'near_ed25519_yao_add_signer_authorized':
      return {
        ...base,
        kind: 'near_ed25519',
        ed25519: { admissionRequest: ceremony.signerState.admissionRequest },
      };
    case 'ecdsa_add_signer_prepared':
      return {
        ...base,
        kind: 'evm_family_ecdsa',
        ecdsa: {
          kind: ceremony.signerState.derivationKind,
          chainTargets: ceremony.signerState.chainTargets,
          prepare: ceremony.signerState.prepare,
          strictRegistration: ceremony.signerState.strictRegistration,
        },
      };
    case 'ecdsa_add_signer_pending_activation':
    case 'ecdsa_add_signer_activation_claimed':
    case 'ecdsa_add_signer_activated':
    case 'near_ed25519_yao_add_signer_activated':
    case 'near_ed25519_yao_add_signer_finalizing':
      return null;
    default:
      return assertNeverWalletAddSignerState(ceremony.signerState);
  }
}

function parseWalletAddSignerStartPrepared(raw: unknown): D1WalletAddSignerStartPreparedV1 | null {
  const record = addSignerRecordValue(raw);
  if (!record || record.kind !== 'd1_wallet_add_signer_start_prepared_v1') return null;
  const addSignerCeremonyId = toOptionalTrimmedString(record.addSignerCeremonyId);
  const registrationPreparationId = toOptionalTrimmedString(record.registrationPreparationId);
  const expiresAtMs = record.expiresAtMs;
  const storedIntent = parseD1StoredAddSignerIntent(record.storedIntent);
  const auth = parseD1StoredAddSignerAuth(record.auth);
  if (
    !addSignerCeremonyId ||
    !registrationPreparationId ||
    typeof expiresAtMs !== 'number' ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= 0 ||
    !storedIntent ||
    !auth
  ) {
    return null;
  }
  return {
    kind: 'd1_wallet_add_signer_start_prepared_v1',
    addSignerCeremonyId,
    registrationPreparationId,
    expiresAtMs,
    storedIntent,
    auth,
  };
}

function parseWalletAddSignerStartTerminal(raw: unknown): D1WalletAddSignerStartTerminalV1 | null {
  const record = addSignerRecordValue(raw);
  if (!record) return null;
  if (record.kind === 'd1_wallet_add_signer_start_rejected_v1') {
    const response = addSignerRecordValue(record.response);
    const code = toOptionalTrimmedString(response?.code);
    const message = toOptionalTrimmedString(response?.message);
    return response?.ok === false && code && message
      ? {
          kind: 'd1_wallet_add_signer_start_rejected_v1',
          response: { ok: false, code, message },
        }
      : null;
  }
  if (record.kind !== 'd1_wallet_add_signer_start_succeeded_v1') return null;
  const ceremony = parseD1StoredWalletAddSignerCeremony(record.ceremony);
  const response = addSignerRecordValue(record.response);
  if (!ceremony || !response || response.ok !== true) return null;
  const parsedResponse = walletAddSignerStartResponseFromCeremony(ceremony);
  if (!parsedResponse || alphabetizeStringify(parsedResponse) !== alphabetizeStringify(response)) {
    return null;
  }
  return {
    kind: 'd1_wallet_add_signer_start_succeeded_v1',
    ceremony,
    response: parsedResponse,
  };
}

export function parseD1WalletAddSignerStartSideEffectRecord(
  raw: unknown,
): D1WalletAddSignerStartSideEffectRecord | null {
  return parseRouterAbEd25519YaoRegistrationSideEffectRecordV1(raw, {
    operation: 'add_signer_start',
    parsePrepared: parseWalletAddSignerStartPrepared,
    parseResponse: parseWalletAddSignerStartTerminal,
  });
}

async function walletAddSignerStartStableToken(grant: string, domain: string): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(`${domain}\u0000${grant}`));
}

async function walletAddSignerStartRequestFingerprint(
  request: StartWalletAddSignerInput,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(request)));
}

async function buildD1WalletAddSignerStartPrepared(input: {
  readonly storedIntent: StoredAddSignerIntent;
  readonly auth: StoredWalletAddSignerCeremony['auth'];
}): Promise<D1WalletAddSignerStartPreparedV1> {
  return {
    kind: 'd1_wallet_add_signer_start_prepared_v1',
    addSignerCeremonyId: `wasc_${await walletAddSignerStartStableToken(
      input.storedIntent.grant,
      'wallet-add-signer-ceremony-v1',
    )}`,
    registrationPreparationId: `regprep_${await walletAddSignerStartStableToken(
      input.storedIntent.grant,
      'wallet-add-signer-preparation-v1',
    )}`,
    expiresAtMs: Math.min(input.storedIntent.expiresAtMs, Date.now() + ADD_SIGNER_CEREMONY_TTL_MS),
    storedIntent: input.storedIntent,
    auth: input.auth,
  };
}

async function returnD1WalletAddSignerStartPrepared(
  prepared: D1WalletAddSignerStartPreparedV1,
): Promise<D1WalletAddSignerStartPreparedV1> {
  return prepared;
}

async function rejectUnexpectedWalletAddSignerStartPreparation(): Promise<never> {
  throw new Error('persisted add-signer start claim disappeared during reconciliation');
}

async function fingerprintD1WalletAddSignerStartPrepared(
  prepared: D1WalletAddSignerStartPreparedV1,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(prepared)));
}

function parseWalletAddSignerFinalizePrepared(
  raw: unknown,
): D1WalletAddSignerFinalizePreparedV1 | null {
  const record = addSignerRecordValue(raw);
  if (!record) return null;
  if (record.kind === 'd1_wallet_add_signer_finalize_ed25519_prepared_v1') {
    const finalizingAtMs = record.finalizingAtMs;
    if (
      typeof finalizingAtMs !== 'number' ||
      !Number.isSafeInteger(finalizingAtMs) ||
      finalizingAtMs <= 0
    ) {
      return null;
    }
    return {
      kind: 'd1_wallet_add_signer_finalize_ed25519_prepared_v1',
      finalizingAtMs,
    };
  }
  if (record.kind !== 'd1_wallet_add_signer_finalize_ecdsa_prepared_v1') return null;
  const signerWriteAtMs = record.signerWriteAtMs;
  return typeof signerWriteAtMs === 'number' &&
    Number.isSafeInteger(signerWriteAtMs) &&
    signerWriteAtMs > 0
    ? { kind: 'd1_wallet_add_signer_finalize_ecdsa_prepared_v1', signerWriteAtMs }
    : null;
}

export function parseD1WalletAddSignerFinalizeSideEffectRecord(
  raw: unknown,
): D1WalletAddSignerFinalizeSideEffectRecord | null {
  return parseRouterAbEd25519YaoRegistrationSideEffectRecordV1(raw, {
    operation: 'add_signer_finalize',
    parsePrepared: parseWalletAddSignerFinalizePrepared,
    parseResponse: parseD1WalletAddSignerFinalizeTerminalResponse,
  });
}

async function fingerprintD1WalletAddSignerFinalizePrepared(
  prepared: D1WalletAddSignerFinalizePreparedV1,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(prepared)));
}

async function returnD1WalletAddSignerFinalizePrepared(
  prepared: D1WalletAddSignerFinalizePreparedV1,
): Promise<D1WalletAddSignerFinalizePreparedV1> {
  return prepared;
}

async function rejectUnexpectedWalletAddSignerFinalizePreparation(): Promise<never> {
  throw new Error('persisted add-signer finalize claim disappeared during reconciliation');
}

function buildD1WalletAddSignerFinalizePrepared(input: {
  readonly request: StoredWalletAddSignerFinalizeRequest;
  readonly ceremony: StoredWalletAddSignerCeremony;
  readonly nowMs: number;
}): D1WalletAddSignerFinalizePreparedV1 {
  if (input.request.kind === 'evm_family_ecdsa') {
    return {
      kind: 'd1_wallet_add_signer_finalize_ecdsa_prepared_v1',
      signerWriteAtMs: input.nowMs,
    };
  }
  if (input.ceremony.signerState.kind === 'near_ed25519_yao_add_signer_finalizing') {
    return {
      kind: 'd1_wallet_add_signer_finalize_ed25519_prepared_v1',
      finalizingAtMs: input.ceremony.signerState.finalizingAtMs,
    };
  }
  return {
    kind: 'd1_wallet_add_signer_finalize_ed25519_prepared_v1',
    finalizingAtMs: input.nowMs,
  };
}

function rejectedWalletAddSignerStartTerminal(
  code: string,
  message: string,
): D1WalletAddSignerStartTerminalV1 {
  return {
    kind: 'd1_wallet_add_signer_start_rejected_v1',
    response: { ok: false, code, message },
  };
}

function rejectedWalletAddSignerStartResult(input: {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
}): D1WalletAddSignerStartTerminalV1 {
  return rejectedWalletAddSignerStartTerminal(input.code, input.message);
}

function successfulWalletAddSignerStartTerminal(
  ceremony: StoredWalletAddSignerCeremony,
): D1WalletAddSignerStartTerminalV1 {
  const response = walletAddSignerStartResponseFromCeremony(ceremony);
  if (!response) throw new Error('add-signer ceremony cannot produce a start response');
  return { kind: 'd1_wallet_add_signer_start_succeeded_v1', ceremony, response };
}

function assertNeverWalletAddSignerState(value: never): never {
  throw new Error(`Unhandled add-signer state: ${String(value)}`);
}

function assertNeverWalletAddSignerStartRun(value: never): never {
  throw new Error(`Unhandled wallet add-signer start result: ${String(value)}`);
}

function assertNeverWalletAddSignerFinalizeRun(value: never): never {
  throw new Error(`Unhandled wallet add-signer finalize result: ${String(value)}`);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function resolveEd25519AddSignerParticipantIds(
  selection: Extract<AddSignerIntentV1['signerSelection'], { mode: 'ed25519' }>,
): readonly [number, number] | null {
  const participantIds = selection.ed25519.participantIds;
  const firstParticipantId = participantIds[0];
  const secondParticipantId = participantIds[1];
  if (
    participantIds.length !== 2 ||
    firstParticipantId === undefined ||
    secondParticipantId === undefined ||
    !Number.isSafeInteger(firstParticipantId) ||
    !Number.isSafeInteger(secondParticipantId) ||
    firstParticipantId <= 0 ||
    secondParticipantId <= 0 ||
    firstParticipantId === secondParticipantId
  ) {
    return null;
  }
  return [firstParticipantId, secondParticipantId];
}

async function cleanupFinalizedAddSignerCeremony(input: {
  readonly store: CloudflareD1RegistrationCeremonyIntentStore;
  readonly addSignerCeremonyId: string;
}): Promise<void> {
  try {
    await input.store.takeAddSignerCeremony(input.addSignerCeremonyId);
  } catch {
    // The outer completion remains authoritative and retries cleanup.
  }
}

function finalizeRequestsMatch(
  left: StoredWalletAddSignerFinalizeRequest,
  right: StoredWalletAddSignerFinalizeRequest,
): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

function normalizeWalletAddSignerFinalizeRequest(
  request: FinalizeWalletAddSignerInput,
  idempotencyKey: string,
): StoredWalletAddSignerFinalizeRequest {
  if (request.kind === 'near_ed25519') {
    return {
      kind: 'near_ed25519',
      addSignerCeremonyId: request.addSignerCeremonyId,
      idempotencyKey,
      activationReference: {
        lifecycleId: request.ed25519.activationReference.lifecycle_id,
        sessionId: request.ed25519.activationReference.session_id,
      },
    };
  }
  const expectedKeyHandle = toOptionalTrimmedString(request.ecdsa.expectedKeyHandles[0]);
  if (!expectedKeyHandle) throw new Error('one exact ECDSA key handle is required');
  return {
    kind: 'evm_family_ecdsa',
    addSignerCeremonyId: request.addSignerCeremonyId,
    idempotencyKey,
    expectedKeyHandles: [expectedKeyHandle],
  };
}

function updateAddSignerCeremonyState(input: {
  readonly ceremony: StoredWalletAddSignerCeremony;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly signerState: StoredWalletAddSignerSignerState;
}): StoredWalletAddSignerCeremony {
  return {
    addSignerCeremonyId: input.ceremony.addSignerCeremonyId,
    intent: input.ceremony.intent,
    digestB64u: input.ceremony.digestB64u,
    orgId: input.ceremony.orgId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    expiresAtMs: input.ceremony.expiresAtMs,
    auth: input.ceremony.auth,
    signerState: input.signerState,
  };
}

function storedEcdsaAddSignerBootstrap(
  bootstrap: StoredEcdsaAddSignerActivated['bootstrap'],
): StoredEcdsaAddSignerActivated['bootstrap'] {
  return {
    formatVersion: bootstrap.formatVersion,
    walletId: bootstrap.walletId,
    evmFamilySigningKeySlotId: bootstrap.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
    relayerKeyId: bootstrap.relayerKeyId,
    applicationBindingDigestB64u: bootstrap.applicationBindingDigestB64u,
    contextBinding32B64u: bootstrap.contextBinding32B64u,
    publicIdentity: bootstrap.publicIdentity,
    clientShareRetryCounter: bootstrap.clientShareRetryCounter,
    relayerShareRetryCounter: bootstrap.relayerShareRetryCounter,
    publicTranscriptDigest32B64u: bootstrap.publicTranscriptDigest32B64u,
    keyHandle: bootstrap.keyHandle,
    signingRootId: bootstrap.signingRootId,
    signingRootVersion: bootstrap.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u,
    ethereumAddress: bootstrap.ethereumAddress,
    relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
    thresholdSessionId: bootstrap.thresholdSessionId,
    activationEpoch: bootstrap.activationEpoch,
    expiresAtMs: bootstrap.expiresAtMs,
    expiresAt: bootstrap.expiresAt,
    remainingUses: bootstrap.remainingUses,
    participantIds: [...exactEcdsaParticipantPair(bootstrap.participantIds)],
    routerAbEcdsaDerivationNormalSigning: bootstrap.routerAbEcdsaDerivationNormalSigning,
  };
}

export class CloudflareD1WalletAddSignerService {
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  private readonly getEd25519YaoProductRegistration: Ed25519YaoProductRegistrationProvider;
  private readonly ecdsaStrictRegistration: RouterAbEcdsaStrictRegistrationPort;
  private readonly getWalletStore: WalletStoreProvider;
  private readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  private readonly startSideEffects: D1WalletAddSignerStartSideEffectStore;
  private readonly finalizeSideEffects: D1WalletAddSignerFinalizeSideEffectStore;

  constructor(input: {
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
    readonly getEd25519YaoProductRegistration: Ed25519YaoProductRegistrationProvider;
    readonly ecdsaStrictRegistration: RouterAbEcdsaStrictRegistrationPort;
    readonly getWalletStore: WalletStoreProvider;
    readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
    readonly startSideEffects: D1WalletAddSignerStartSideEffectStore;
    readonly finalizeSideEffects: D1WalletAddSignerFinalizeSideEffectStore;
  }) {
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
    this.getEd25519YaoProductRegistration = input.getEd25519YaoProductRegistration;
    this.ecdsaStrictRegistration = input.ecdsaStrictRegistration;
    this.getWalletStore = input.getWalletStore;
    this.walletAuthMethods = input.walletAuthMethods;
    this.startSideEffects = input.startSideEffects;
    this.finalizeSideEffects = input.finalizeSideEffects;
  }

  async getWalletAddSignerRuntimePolicyScope(
    addSignerCeremonyId: string,
  ): Promise<NonNullable<ReturnType<typeof parseD1RuntimePolicyScope>> | null> {
    const store = this.getRegistrationCeremonyIntentStore();
    const ceremony = await store.getAddSignerCeremony(addSignerCeremonyId);
    if (!ceremony) return null;
    return parseD1RuntimePolicyScope(ceremony.intent.runtimePolicyScope) ?? null;
  }

  async startWalletAddSigner(
    request: StartWalletAddSignerInput,
  ): Promise<WalletAddSignerStartResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const walletId = parseWalletIdForIntent(request.walletId);
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const grant = addSignerIntentGrantFromString(
        toOptionalTrimmedString(request.addSignerIntentGrant) || '',
      );
      if (!grant) {
        return { ok: false, code: 'invalid_grant', message: 'add-signer intent grant is required' };
      }
      if (request.intent.walletId !== walletId) {
        return { ok: false, code: 'invalid_body', message: 'add-signer walletId mismatch' };
      }
      const digestB64u = toOptionalTrimmedString(request.addSignerIntentDigestB64u);
      const requestDigest = await computeAddSignerIntentDigestB64u(request.intent);
      if (!digestB64u || digestB64u !== requestDigest) {
        return { ok: false, code: 'invalid_body', message: 'add-signer intent digest mismatch' };
      }
      const requestFingerprint = await walletAddSignerStartRequestFingerprint(request);
      const startKey = `add-signer:${await walletAddSignerStartStableToken(
        grant,
        'wallet-add-signer-start-claim-v1',
      )}`;
      const existing = await this.startSideEffects.read(startKey);
      let prepared: D1WalletAddSignerStartPreparedV1 | null = null;
      if (existing.kind === 'missing') {
        const preview = await store.getAddSignerIntent(grant);
        if (!preview) {
          return { ok: false, code: 'invalid_grant', message: 'add-signer intent grant expired' };
        }
        if (
          digestB64u !== preview.digestB64u ||
          alphabetizeStringify(request.intent) !== alphabetizeStringify(preview.intent)
        ) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'add-signer intent does not match its grant',
          };
        }
        if (
          preview.intent.signerSelection.mode === 'ed25519' &&
          request.auth.kind !== 'webauthn_assertion'
        ) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'Ed25519 Yao add-signer requires a fresh WebAuthn assertion',
          };
        }
        const storedAuth = await this.walletAuthMethods.resolveAddSignerExistingAuth({
          auth: request.auth,
          walletId,
          intent: preview.intent,
          nowMs: Date.now(),
        });
        if (!storedAuth.ok) return storedAuth;
        prepared = await buildD1WalletAddSignerStartPrepared({
          storedIntent: preview,
          auth: storedAuth.auth,
        });
      }
      const run = await runRouterAbEd25519YaoRegistrationSideEffectV1(this.startSideEffects, {
        kind: 'prepared_resumable',
        operation: 'add_signer_start',
        key: startKey,
        requestFingerprint,
        resumeAfterMs: WALLET_ADD_SIGNER_START_RESUME_AFTER_MS,
        nowMs: Date.now,
        prepare: prepared
          ? returnD1WalletAddSignerStartPrepared.bind(null, prepared)
          : rejectUnexpectedWalletAddSignerStartPreparation,
        derivePreparedArtifactFingerprint: fingerprintD1WalletAddSignerStartPrepared,
        execute: this.executeWalletAddSignerStartSideEffect.bind(this, {
          request,
          store,
          walletId,
        }),
      });
      switch (run.kind) {
        case 'executed':
        case 'exact_replay':
          return run.value.response;
        case 'request_conflict':
          return {
            ok: false,
            code: 'idempotency_conflict',
            message: 'add-signer intent grant belongs to a different start request',
          };
        case 'in_progress':
          return {
            ok: false,
            code: 'conflict',
            message: 'add-signer start is already in progress; retry later',
          };
        case 'uncertain':
          return {
            ok: false,
            code: 'internal',
            message: run.message || 'Failed to reconcile wallet add-signer start',
          };
        default:
          return assertNeverWalletAddSignerStartRun(run);
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet add-signer ceremony',
      };
    }
  }

  private async executeWalletAddSignerStartSideEffect(
    input: {
      readonly request: StartWalletAddSignerInput;
      readonly store: CloudflareD1RegistrationCeremonyIntentStore;
      readonly walletId: WalletId;
    },
    prepared: D1WalletAddSignerStartPreparedV1,
    attempt: 'fresh' | 'resumed',
  ): Promise<D1WalletAddSignerStartTerminalV1> {
    const terminal = await this.executeWalletAddSignerStart(input, prepared, attempt);
    if (terminal.kind === 'd1_wallet_add_signer_start_rejected_v1') {
      throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1(terminal.response);
    }
    return terminal;
  }

  private async executeWalletAddSignerStart(
    input: {
      readonly request: StartWalletAddSignerInput;
      readonly store: CloudflareD1RegistrationCeremonyIntentStore;
      readonly walletId: WalletId;
    },
    prepared: D1WalletAddSignerStartPreparedV1,
    attempt: 'fresh' | 'resumed',
  ): Promise<D1WalletAddSignerStartTerminalV1> {
    const existingCeremony = await input.store.getAddSignerCeremony(prepared.addSignerCeremonyId);
    if (existingCeremony) {
      if (
        existingCeremony.digestB64u !== prepared.storedIntent.digestB64u ||
        alphabetizeStringify(existingCeremony.intent) !==
          alphabetizeStringify(prepared.storedIntent.intent)
      ) {
        throw new Error('add-signer ceremony conflicts with its durable claim');
      }
      return successfulWalletAddSignerStartTerminal(existingCeremony);
    }
    if (input.request.addSignerIntentDigestB64u !== prepared.storedIntent.digestB64u) {
      return rejectedWalletAddSignerStartTerminal(
        'invalid_body',
        'add-signer intent digest mismatch',
      );
    }
    if (
      alphabetizeStringify(input.request.intent) !==
      alphabetizeStringify(prepared.storedIntent.intent)
    ) {
      return rejectedWalletAddSignerStartTerminal(
        'invalid_body',
        'add-signer intent does not match its grant',
      );
    }
    const walletStore = this.getWalletStore();
    const wallet = await walletStore.getWallet({ walletId: input.walletId });
    if (!wallet) return rejectedWalletAddSignerStartTerminal('not_found', 'wallet not found');
    const runtimePolicyScope = parseD1RuntimePolicyScope(
      prepared.storedIntent.intent.runtimePolicyScope,
    );
    if (!runtimePolicyScope) {
      return rejectedWalletAddSignerStartTerminal(
        'invalid_body',
        'add-signer requires a runtime policy scope',
      );
    }
    const selection = prepared.storedIntent.intent.signerSelection;
    let yaoRuntime: RouterAbEd25519YaoProductRegistrationRuntimeV1 | null = null;
    if (selection.mode === 'ed25519') {
      const ed25519Selection = selection.ed25519;
      if (ed25519Selection.mode !== 'create_implicit_near_account') {
        return rejectedWalletAddSignerStartTerminal(
          'invalid_body',
          'Ed25519 Yao add-signer requires implicit NEAR account creation',
        );
      }
      const participantIds = resolveEd25519AddSignerParticipantIds(selection);
      if (!participantIds) {
        return rejectedWalletAddSignerStartTerminal(
          'invalid_body',
          'Ed25519 Yao add-signer requires two distinct positive participants',
        );
      }
      const occupied = await walletStore.getEd25519SignerBySlot({
        walletId: input.walletId,
        signerSlot: ed25519Selection.signerSlot,
      });
      if (occupied) {
        return rejectedWalletAddSignerStartTerminal(
          'signer_conflict',
          'Ed25519 signer slot is already occupied',
        );
      }
      yaoRuntime = this.getEd25519YaoProductRegistration();
      if (!yaoRuntime) {
        return rejectedWalletAddSignerStartTerminal(
          'not_configured',
          'Ed25519 Yao add-signer is not configured on this server',
        );
      }
    }
    const consumedIntent = await input.store.takeAddSignerIntent(prepared.storedIntent.grant);
    if (!consumedIntent && attempt === 'fresh') {
      return rejectedWalletAddSignerStartTerminal(
        'invalid_grant',
        'add-signer intent grant expired',
      );
    }
    if (
      consumedIntent &&
      alphabetizeStringify(consumedIntent) !== alphabetizeStringify(prepared.storedIntent)
    ) {
      throw new Error('consumed add-signer intent conflicts with its durable claim');
    }
    const storedIntent = consumedIntent || prepared.storedIntent;
    const signingRootId = storedIntent.signingRootId || deriveSigningRootId(runtimePolicyScope);
    const signingRootVersion =
      toOptionalTrimmedString(storedIntent.signingRootVersion) ||
      runtimePolicyScope.signingRootVersion;
    let ceremony: StoredWalletAddSignerCeremony;
    if (selection.mode === 'ed25519' && yaoRuntime) {
      if (prepared.auth.kind !== 'webauthn_assertion') {
        return rejectedWalletAddSignerStartTerminal(
          'unauthorized',
          'Ed25519 Yao add-signer requires a fresh WebAuthn assertion',
        );
      }
      const ed25519Intent: Ed25519AddSignerIntent = {
        version: 'add_signer_intent_v1',
        walletId: storedIntent.intent.walletId,
        signerSelection: selection,
        runtimePolicyScope,
        nonceB64u: storedIntent.intent.nonceB64u,
      };
      const admissionRequest = await buildRouterAbEd25519YaoAddSignerAdmissionRequestV1({
        addSignerCeremonyId: prepared.addSignerCeremonyId,
        walletId: input.walletId,
        signingRootId,
        signingRootVersion,
        selection,
        signingWorkerId: yaoRuntime.signingWorkerId,
        materialActivation: createRouterAbEd25519YaoMaterialActivationRefV1({
          walletId: input.walletId,
          signingWorkerId: yaoRuntime.signingWorkerId,
        }),
      });
      const bound = await yaoRuntime.bindVerifiedIntent({
        kind: 'verified_add_signer_intent',
        addSignerIntentGrant: storedIntent.grant,
        intent: ed25519Intent,
        admissionRequest,
        expiresAtMs: prepared.expiresAtMs,
      });
      if (!bound.ok) return rejectedWalletAddSignerStartResult(bound);
      ceremony = {
        addSignerCeremonyId: prepared.addSignerCeremonyId,
        intent: ed25519Intent,
        digestB64u: storedIntent.digestB64u,
        orgId: runtimePolicyScope.orgId,
        signingRootId,
        signingRootVersion,
        expiresAtMs: prepared.expiresAtMs,
        auth: prepared.auth,
        signerState: {
          kind: 'near_ed25519_yao_add_signer_authorized',
          admissionRequest,
        },
      };
    } else if (selection.mode === 'ecdsa') {
      const chainTargets = normalizeThresholdEcdsaChainTargets(selection.ecdsa.chainTargets);
      if (!chainTargets) {
        return rejectedWalletAddSignerStartTerminal(
          'invalid_body',
          'ECDSA add-signer contains an invalid chain target',
        );
      }
      const ecdsaPrepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
        registrationPurpose: 'wallet_add_signer',
        registrationCeremonyId: prepared.addSignerCeremonyId,
        registrationPreparationId: registrationPreparationIdFromString(
          prepared.registrationPreparationId,
        ),
        walletId: input.walletId,
        signingRootId,
        signingRootVersion,
        chainTargets,
        participantIds: [...selection.ecdsa.participantIds],
        runtimePolicyScope,
        strictRegistration: this.ecdsaStrictRegistration,
      });
      if (!ecdsaPrepared.ok) return rejectedWalletAddSignerStartResult(ecdsaPrepared);
      const ecdsa = ecdsaPrepared.ecdsa;
      ceremony = {
        addSignerCeremonyId: prepared.addSignerCeremonyId,
        intent: storedIntent.intent,
        digestB64u: storedIntent.digestB64u,
        orgId: runtimePolicyScope.orgId,
        signingRootId,
        signingRootVersion,
        expiresAtMs: prepared.expiresAtMs,
        auth: prepared.auth,
        signerState: {
          kind: 'ecdsa_add_signer_prepared',
          derivationKind: ecdsa.kind,
          chainTargets: ecdsa.chainTargets,
          prepare: ecdsa.prepare,
          strictRegistration: ecdsa.strictRegistration,
        },
      };
    } else {
      throw new Error('add-signer selection cannot be executed');
    }
    await input.store.putAddSignerCeremony(ceremony);
    return successfulWalletAddSignerStartTerminal(ceremony);
  }

  async respondWalletAddSignerEcdsaDerivation(
    request: RespondWalletAddSignerDerivationInput,
  ): Promise<WalletAddSignerEcdsaDerivationRespondResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const ceremony = await store.getAddSignerCeremony(request.addSignerCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
      }
      if (ceremony.intent.signerSelection.mode !== 'ecdsa') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'Cloudflare D1 add-signer respond currently supports ECDSA signer selection',
        };
      }
      if (ceremony.signerState.kind === 'ecdsa_add_signer_pending_activation') {
        if (
          !routerAbEcdsaStrictRegistrationRequestMatchesFacts({
            request: request.ecdsa.strictRegistration,
            facts: ceremony.signerState.strictRegistration,
          })
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA add-signer replay changed the admitted registration request',
          };
        }
        return {
          ok: true,
          addSignerCeremonyId: ceremony.addSignerCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_forwarded_v1',
            strictResult: ceremony.signerState.publicResponse,
          },
        };
      }
      if (ceremony.signerState.kind !== 'ecdsa_add_signer_prepared') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'one prepared ECDSA add-signer registration is required',
        };
      }
      if (
        !routerAbEcdsaStrictRegistrationRequestMatchesFacts({
          request: request.ecdsa.strictRegistration,
          facts: ceremony.signerState.strictRegistration,
        })
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA add-signer request does not match the admitted ceremony facts',
        };
      }
      const registered = await this.ecdsaStrictRegistration.register({
        request: request.ecdsa.strictRegistration,
        requestPolicy: {
          policyVersion: WALLET_ADD_SIGNER_ROUTER_POLICY_VERSION,
          requestDigestB64u: request.ecdsa.requestDigestB64u,
        },
        authority: ecdsaStrictRegistrationAuthority(ceremony.signerState.strictRegistration),
      });
      if (!registered.ok) {
        return {
          ok: false,
          code: registered.code,
          message: registered.message,
        };
      }
      await store.updateAddSignerCeremony({
        expected: ceremony,
        next: updateAddSignerCeremonyState({
          ceremony,
          signingRootId: ceremony.signingRootId,
          signingRootVersion: ceremony.signingRootVersion,
          signerState: {
            kind: 'ecdsa_add_signer_pending_activation',
            derivationKind: ceremony.signerState.derivationKind,
            chainTargets: ceremony.signerState.chainTargets,
            prepare: ceremony.signerState.prepare,
            strictRegistration: ceremony.signerState.strictRegistration,
            registrationRequest: request.ecdsa.strictRegistration,
            pendingActivation: registered.value.pendingActivation,
            publicResponse: registered.value.publicResponse,
          },
        }),
      });
      return {
        ok: true,
        addSignerCeremonyId: ceremony.addSignerCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_forwarded_v1',
          strictResult: registered.value.publicResponse,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to respond to wallet add-signer ceremony',
      };
    }
  }

  /**
   * Idempotent under the canonical activation coordinates. The client computes
   * the activation request digest from the canonical add-signer command
   * (`wallet_add_signer_activate_v2`); this method recomputes it, records the
   * coordinates as a claim before any Router custody work, and replays the
   * committed receipt to any later activate with the same coordinates — the
   * replay is also how completion is queried since the standalone
   * prepare/query routes were removed.
   */
  async activateWalletAddSignerEcdsa(
    request: ActivateWalletAddSignerEcdsaInput,
  ): Promise<WalletAddSignerEcdsaActivationResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const ceremony = await store.getAddSignerCeremony(request.addSignerCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
      }
      const requestDigestB64u = base64UrlEncode(
        Uint8Array.from(request.ecdsa.expectedActivationRequestDigest.bytes),
      );
      const state = ceremony.signerState;
      if (state.kind === 'ecdsa_add_signer_activated') {
        if (
          alphabetizeStringify(state.publicFacts) !==
          alphabetizeStringify(request.ecdsa.publicFacts)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA add-signer activation replay changed the verified client facts',
          };
        }
        if (state.activationRequestDigestB64u !== requestDigestB64u) {
          return {
            ok: false,
            code: 'activation_digest_mismatch',
            message: 'ECDSA add-signer activation replay changed the request digest',
          };
        }
        return {
          ok: true,
          addSignerCeremonyId: ceremony.addSignerCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_activated_v1',
            activation: state.activation,
            bootstrap: state.bootstrap,
          },
        };
      }
      if (
        ceremony.intent.signerSelection.mode !== 'ecdsa' ||
        (state.kind !== 'ecdsa_add_signer_pending_activation' &&
          state.kind !== 'ecdsa_add_signer_activation_claimed')
      ) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'one pending ECDSA add-signer activation is required',
        };
      }
      let claimedCeremony: StoredWalletAddSignerCeremony;
      let claimedState: StoredEcdsaAddSignerActivationClaimed;
      if (state.kind === 'ecdsa_add_signer_pending_activation') {
        const canonicalDigestB64u = await computeWalletAddSignerEcdsaActivationRequestDigestB64u({
          addSignerCeremonyId: ceremony.addSignerCeremonyId,
          activationCorrelationId: request.ecdsa.activationCorrelationId,
          publicFacts: request.ecdsa.publicFacts,
        });
        if (canonicalDigestB64u !== requestDigestB64u) {
          return {
            ok: false,
            code: 'activation_digest_mismatch',
            message:
              'ECDSA add-signer activation request digest is not the canonical command digest',
          };
        }
        claimedState = {
          kind: 'ecdsa_add_signer_activation_claimed',
          derivationKind: state.derivationKind,
          chainTargets: state.chainTargets,
          prepare: state.prepare,
          strictRegistration: state.strictRegistration,
          registrationRequest: state.registrationRequest,
          pendingActivation: state.pendingActivation,
          publicResponse: state.publicResponse,
          publicFacts: request.ecdsa.publicFacts,
          activationRequestDigestB64u: canonicalDigestB64u,
        };
        claimedCeremony = updateAddSignerCeremonyState({
          ceremony,
          signingRootId: ceremony.signingRootId,
          signingRootVersion: ceremony.signingRootVersion,
          signerState: claimedState,
        });
        await store.updateAddSignerCeremony({ expected: ceremony, next: claimedCeremony });
      } else {
        if (state.activationRequestDigestB64u !== requestDigestB64u) {
          return {
            ok: false,
            code: 'activation_digest_mismatch',
            message: 'ECDSA add-signer activation claim was prepared for a different digest',
          };
        }
        if (
          alphabetizeStringify(state.publicFacts) !==
          alphabetizeStringify(request.ecdsa.publicFacts)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA add-signer activation claim belongs to different verified client facts',
          };
        }
        claimedCeremony = ceremony;
        claimedState = state;
      }
      const activated = await this.ecdsaStrictRegistration.activate({
        activationCorrelationId: request.ecdsa.activationCorrelationId,
        activationRequestDigestB64u: claimedState.activationRequestDigestB64u,
        pendingActivation: claimedState.pendingActivation,
        clientActivation: claimedState.publicFacts,
        requestPolicy: {
          policyVersion: WALLET_ADD_SIGNER_ROUTER_POLICY_VERSION,
          requestDigestB64u: claimedState.publicFacts.registrationRequestDigestB64u,
        },
        authority: ecdsaStrictRegistrationAuthority(claimedState.strictRegistration),
      });
      if (!activated.ok) {
        if (!activated.retryable) await store.takeAddSignerCeremony(ceremony.addSignerCeremonyId);
        return { ok: false, code: activated.code, message: activated.message };
      }
      let bootstrap: StoredEcdsaAddSignerActivated['bootstrap'];
      try {
        bootstrap = storedEcdsaAddSignerBootstrap(
          await buildActivatedEcdsaFamilyBootstrap({
            branch: claimedState,
            publicFacts: claimedState.publicFacts,
            activation: activated.value,
          }),
        );
      } catch (error: unknown) {
        /* The Router commit may already be durable. Keep the claim: a retry
           with the same coordinates replays the canonical activation and
           finishes these legs. */
        return {
          ok: false,
          code: 'ecdsa_activation_terminal_failure',
          message: errorMessage(error) || 'ECDSA add-signer activation failed',
        };
      }
      const activatedState: StoredEcdsaAddSignerActivated = {
        kind: 'ecdsa_add_signer_activated',
        derivationKind: claimedState.derivationKind,
        chainTargets: claimedState.chainTargets,
        prepare: claimedState.prepare,
        strictRegistration: claimedState.strictRegistration,
        registrationRequest: claimedState.registrationRequest,
        publicFacts: claimedState.publicFacts,
        activationRequestDigestB64u: claimedState.activationRequestDigestB64u,
        activation: activated.value,
        publicCapability: buildRouterAbEcdsaDerivationPublicCapabilityV1({
          registrationFacts: claimedState.strictRegistration,
          registrationRequest: claimedState.registrationRequest,
          clientActivation: claimedState.publicFacts,
          activationReceipt: activated.value,
        }),
        bootstrap,
      };
      try {
        await store.updateAddSignerCeremony({
          expected: claimedCeremony,
          next: updateAddSignerCeremonyState({
            ceremony: claimedCeremony,
            signingRootId: claimedCeremony.signingRootId,
            signingRootVersion: claimedCeremony.signingRootVersion,
            signerState: activatedState,
          }),
        });
      } catch (error: unknown) {
        /* A concurrent activate with the same coordinates may have committed
           first; accept only an identical outcome. */
        const reconciled = await store.getAddSignerCeremony(ceremony.addSignerCeremonyId);
        const reconciledState = reconciled?.signerState;
        if (
          reconciledState?.kind !== 'ecdsa_add_signer_activated' ||
          alphabetizeStringify(reconciledState.publicFacts) !==
            alphabetizeStringify(activatedState.publicFacts) ||
          alphabetizeStringify(reconciledState.activation) !==
            alphabetizeStringify(activatedState.activation) ||
          alphabetizeStringify(reconciledState.bootstrap) !==
            alphabetizeStringify(activatedState.bootstrap)
        ) {
          return {
            ok: false,
            code: 'ecdsa_activation_terminal_failure',
            message: errorMessage(error) || 'ECDSA add-signer activation failed',
          };
        }
      }
      return {
        ok: true,
        addSignerCeremonyId: ceremony.addSignerCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activated_v1',
          activation: activatedState.activation,
          bootstrap: activatedState.bootstrap,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to activate wallet add-signer ceremony',
      };
    }
  }

  async finalizeWalletAddSigner(
    request: FinalizeWalletAddSignerInput,
  ): Promise<WalletAddSignerFinalizeResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const idempotencyKey = toOptionalTrimmedString(request.idempotencyKey);
      if (!idempotencyKey) {
        return { ok: false, code: 'invalid_body', message: 'idempotencyKey is required' };
      }
      const finalizeRequest = normalizeWalletAddSignerFinalizeRequest(request, idempotencyKey);
      const claimKey = `add-signer-finalize:${finalizeRequest.addSignerCeremonyId}`;
      const existing = await this.finalizeSideEffects.read(claimKey);
      let prepared: D1WalletAddSignerFinalizePreparedV1 | null = null;
      if (existing.kind === 'missing') {
        const exactReplay = await store.getAddSignerFinalizeReplay({
          addSignerCeremonyId: finalizeRequest.addSignerCeremonyId,
          idempotencyKey,
        });
        const replay =
          exactReplay ||
          (await store.getAddSignerFinalizeReplayForCeremony(finalizeRequest.addSignerCeremonyId));
        if (replay) {
          if (!finalizeRequestsMatch(replay.request, finalizeRequest)) {
            return {
              ok: false,
              code: 'idempotency_conflict',
              message: 'idempotencyKey is already bound to another add-signer finalize request',
            };
          }
          await cleanupFinalizedAddSignerCeremony({
            store,
            addSignerCeremonyId: finalizeRequest.addSignerCeremonyId,
          });
          return replay.response;
        }
        const ceremony = await store.getAddSignerCeremony(finalizeRequest.addSignerCeremonyId);
        if (!ceremony) {
          return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
        }
        prepared = buildD1WalletAddSignerFinalizePrepared({
          request: finalizeRequest,
          ceremony,
          nowMs: Date.now(),
        });
      }
      const requestFingerprint = base64UrlEncode(
        await sha256BytesUtf8(alphabetizeStringify(finalizeRequest)),
      );
      const run = await runRouterAbEd25519YaoRegistrationSideEffectV1(this.finalizeSideEffects, {
        kind: 'prepared_resumable',
        operation: 'add_signer_finalize',
        key: claimKey,
        requestFingerprint,
        resumeAfterMs: WALLET_ADD_SIGNER_FINALIZE_RESUME_AFTER_MS,
        nowMs: Date.now,
        prepare: prepared
          ? returnD1WalletAddSignerFinalizePrepared.bind(null, prepared)
          : rejectUnexpectedWalletAddSignerFinalizePreparation,
        derivePreparedArtifactFingerprint: fingerprintD1WalletAddSignerFinalizePrepared,
        execute: this.executeWalletAddSignerFinalizeSideEffect.bind(this, {
          finalizeRequest,
          store,
          consumerBinding: requestFingerprint,
        }),
      });
      switch (run.kind) {
        case 'executed':
        case 'exact_replay':
          if (run.value.ok) {
            await cleanupFinalizedAddSignerCeremony({
              store,
              addSignerCeremonyId: finalizeRequest.addSignerCeremonyId,
            });
          }
          return run.value;
        case 'request_conflict':
          return {
            ok: false,
            code: 'idempotency_conflict',
            message: 'add-signer ceremony belongs to a different finalize request',
          };
        case 'in_progress':
          return {
            ok: false,
            code: 'conflict',
            message: 'add-signer finalize is already in progress; retry later',
          };
        case 'uncertain':
          return {
            ok: false,
            code: 'internal',
            message: run.message || 'Failed to reconcile wallet add-signer finalize',
          };
        default:
          return assertNeverWalletAddSignerFinalizeRun(run);
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to finalize wallet add-signer ceremony',
      };
    }
  }

  private async executeWalletAddSignerFinalizeSideEffect(
    input: {
      readonly finalizeRequest: StoredWalletAddSignerFinalizeRequest;
      readonly store: CloudflareD1RegistrationCeremonyIntentStore;
      readonly consumerBinding: string;
    },
    prepared: D1WalletAddSignerFinalizePreparedV1,
  ): Promise<WalletAddSignerFinalizeResponse> {
    const response = await this.executeWalletAddSignerFinalize(input, prepared);
    return response.ok ? response : throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1(response);
  }

  private async executeWalletAddSignerFinalize(
    input: {
      readonly finalizeRequest: StoredWalletAddSignerFinalizeRequest;
      readonly store: CloudflareD1RegistrationCeremonyIntentStore;
      readonly consumerBinding: string;
    },
    prepared: D1WalletAddSignerFinalizePreparedV1,
  ): Promise<WalletAddSignerFinalizeResponse> {
    const store = input.store;
    const finalizeRequest = input.finalizeRequest;
    const idempotencyKey = finalizeRequest.idempotencyKey;
    const exactReplay = await store.getAddSignerFinalizeReplay({
      addSignerCeremonyId: finalizeRequest.addSignerCeremonyId,
      idempotencyKey,
    });
    const replay =
      exactReplay ||
      (await store.getAddSignerFinalizeReplayForCeremony(finalizeRequest.addSignerCeremonyId));
    if (replay) {
      if (!finalizeRequestsMatch(replay.request, finalizeRequest)) {
        return {
          ok: false,
          code: 'idempotency_conflict',
          message: 'idempotencyKey is already bound to another add-signer finalize request',
        };
      }
      return replay.response;
    }
    let ceremony = await store.getAddSignerCeremony(finalizeRequest.addSignerCeremonyId);
    if (!ceremony) {
      return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
    }
    if (finalizeRequest.kind === 'near_ed25519') {
      if (prepared.kind !== 'd1_wallet_add_signer_finalize_ed25519_prepared_v1') {
        throw new Error('Ed25519 add-signer finalize claim changed branch');
      }
      if (
        ceremony.intent.signerSelection.mode !== 'ed25519' ||
        ceremony.auth.kind !== 'webauthn_assertion'
      ) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'authorized WebAuthn Ed25519 Yao add-signer state is required',
        };
      }
      const webAuthnAuth = ceremony.auth;
      const runtimePolicyScope = parseD1RuntimePolicyScope(ceremony.intent.runtimePolicyScope);
      const participantIds = resolveEd25519AddSignerParticipantIds(ceremony.intent.signerSelection);
      if (!runtimePolicyScope || !participantIds) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Ed25519 Yao add-signer scope is invalid',
        };
      }
      const signingRootId = toOptionalTrimmedString(ceremony.signingRootId);
      const signingRootVersion = toOptionalTrimmedString(ceremony.signingRootVersion);
      if (
        !signingRootId ||
        signingRootId !== deriveSigningRootId(runtimePolicyScope) ||
        !signingRootVersion ||
        signingRootVersion !== runtimePolicyScope.signingRootVersion
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'Ed25519 Yao add-signer signing-root scope is invalid',
        };
      }
      const yaoRuntime = this.getEd25519YaoProductRegistration();
      if (!yaoRuntime) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Ed25519 Yao add-signer is not configured on this server',
        };
      }
      const walletStore = this.getWalletStore();
      const wallet = await walletStore.getWallet({ walletId: ceremony.intent.walletId });
      if (!wallet) return { ok: false, code: 'not_found', message: 'wallet not found' };
      const selection = ceremony.intent.signerSelection.ed25519;
      const requestedActivationReference = finalizeRequest.activationReference;
      const currentState = ceremony.signerState;
      let activation: StoredEd25519YaoAddSignerActivation;
      if (currentState.kind === 'near_ed25519_yao_add_signer_authorized') {
        const occupied = await walletStore.getEd25519SignerBySlot({
          walletId: ceremony.intent.walletId,
          signerSlot: selection.signerSlot,
        });
        if (occupied) {
          return {
            ok: false,
            code: 'signer_conflict',
            message: 'Ed25519 signer slot is already occupied',
          };
        }
        const consumed = await yaoRuntime.consumeActivated({
          reference: requestedActivationReference,
          consumerBinding: input.consumerBinding,
        });
        if (!consumed.ok) return consumed;
        if (
          alphabetizeStringify(consumed.activation.admissionRequest) !==
          alphabetizeStringify(currentState.admissionRequest)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'activated Ed25519 Yao add-signer result does not match its ceremony',
          };
        }
        activation = {
          finalizeRequest,
          activation: consumed.activation,
        };
        const activatedCeremony = updateAddSignerCeremonyState({
          ceremony,
          signingRootId,
          signingRootVersion,
          signerState: {
            kind: 'near_ed25519_yao_add_signer_activated',
            finalizeRequest: activation.finalizeRequest,
            activation: activation.activation,
          },
        });
        await store.updateAddSignerCeremony({
          expected: ceremony,
          next: activatedCeremony,
        });
        ceremony = activatedCeremony;
      } else if (
        currentState.kind === 'near_ed25519_yao_add_signer_activated' ||
        currentState.kind === 'near_ed25519_yao_add_signer_finalizing'
      ) {
        activation = currentState;
        if (!finalizeRequestsMatch(activation.finalizeRequest, finalizeRequest)) {
          return {
            ok: false,
            code: 'idempotency_conflict',
            message: 'Ed25519 Yao finalize request does not match the stored finalize state',
          };
        }
      } else {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'authorized Ed25519 Yao add-signer state is required',
        };
      }

      let response: Extract<
        Extract<WalletAddSignerFinalizeResponse, { ok: true }>,
        { kind: 'near_ed25519' }
      >;
      let signer: Parameters<D1WalletStore['putEd25519SignerIfSlotAvailable']>[0];
      let finalizingAtMs: number;
      if (currentState.kind === 'near_ed25519_yao_add_signer_finalizing') {
        response = currentState.response;
        signer = currentState.signer;
        finalizingAtMs = currentState.finalizingAtMs;
      } else {
        const publicKeyBytes = activation.activation.result.public_receipt.registered_public_key;
        const publicKey = ed25519NearPublicKeyFromBytes(publicKeyBytes);
        const nearAccountId = implicitNearAccountIdFromEd25519PublicKeyBytes(publicKeyBytes);
        const nearEd25519SigningKeyId =
          activation.activation.admissionRequest.application_binding.near_ed25519_signing_key_id;
        const capabilityInstallation = {
          kind: 'router_ab_ed25519_yao_registration_finalize_capability_v1',
          activeCapabilityBinding: activation.activation.result.binding.session_id,
          nearAccountId,
          registrationAdmissionRequest: activation.activation.admissionRequest,
          registrationAdmissionReceipt: activation.activation.admissionReceipt,
          registrationResult: activation.activation.result,
          runtimePolicyScope,
        } as const;
        const activeYaoCapability =
          buildRouterAbEd25519YaoRegistrationCapabilityRecordV1(capabilityInstallation);
        if (!activeYaoCapability.ok) {
          return throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1(activeYaoCapability);
        }
        finalizingAtMs = prepared.finalizingAtMs;
        const ed25519 = {
          signerSlot: selection.signerSlot,
          nearAccountId,
          nearEd25519SigningKeyId,
          publicKey,
          relayerKeyId: yaoRuntime.signingWorkerId,
          keyVersion: selection.keyVersion,
          recoveryExportCapable: true,
          participantIds,
        } as const;
        response = {
          ok: true,
          kind: 'near_ed25519',
          walletId: ceremony.intent.walletId,
          rpId: webAuthnAuth.rpId,
          credentialIdB64u: webAuthnAuth.credentialIdB64u,
          ed25519,
        };
        signer = buildYaoEd25519WalletSignerRecord({
          walletId: ceremony.intent.walletId,
          nearAccountId,
          nearEd25519SigningKeyId,
          thresholdSessionId: activation.activation.admissionRequest.scope.threshold_session_id,
          signerSlot: selection.signerSlot,
          publicKey,
          signingWorkerId: yaoRuntime.signingWorkerId,
          keyVersion: selection.keyVersion,
          participantIds,
          signingRootId,
          signingRootVersion,
          runtimePolicyScope,
          activeYaoCapability: activeYaoCapability.record,
          now: finalizingAtMs,
        });
        await store.updateAddSignerCeremony({
          expected: ceremony,
          next: updateAddSignerCeremonyState({
            ceremony,
            signingRootId,
            signingRootVersion,
            signerState: {
              kind: 'near_ed25519_yao_add_signer_finalizing',
              finalizeRequest: activation.finalizeRequest,
              activation: activation.activation,
              response,
              signer,
              finalizingAtMs,
            },
          }),
        });
      }

      if (
        response.walletId !== ceremony.intent.walletId ||
        response.rpId !== webAuthnAuth.rpId ||
        response.credentialIdB64u !== webAuthnAuth.credentialIdB64u ||
        response.ed25519.signerSlot !== selection.signerSlot ||
        signer.walletId !== response.walletId ||
        signer.signerSlot !== response.ed25519.signerSlot ||
        signer.nearAccountId !== response.ed25519.nearAccountId ||
        signer.nearEd25519SigningKeyId !== response.ed25519.nearEd25519SigningKeyId ||
        signer.thresholdSessionId !==
          activation.activation.admissionRequest.scope.threshold_session_id ||
        signer.publicKey !== response.ed25519.publicKey ||
        signer.signingWorkerId !== response.ed25519.relayerKeyId ||
        signer.keyVersion !== response.ed25519.keyVersion ||
        signer.signingRootId !== signingRootId ||
        signer.signingRootVersion !== signingRootVersion ||
        alphabetizeStringify(signer.participantIds) !==
          alphabetizeStringify(response.ed25519.participantIds) ||
        alphabetizeStringify(signer.runtimePolicyScope) !== alphabetizeStringify(runtimePolicyScope)
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'stored Ed25519 Yao add-signer finalize plan is invalid',
        };
      }
      const inserted = await walletStore.putEd25519SignerIfSlotAvailable(signer);
      if (!inserted) {
        const existing = await walletStore.getEd25519SignerBySlot({
          walletId: ceremony.intent.walletId,
          signerSlot: selection.signerSlot,
        });
        if (!existing || alphabetizeStringify(existing) !== alphabetizeStringify(signer)) {
          return {
            ok: false,
            code: 'signer_conflict',
            message: 'Ed25519 signer slot is already occupied',
          };
        }
      }
      const installed = await yaoRuntime.installPersistedActiveCapability(
        signer.activeYaoCapability,
      );
      if (!installed.ok) {
        return throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1(installed);
      }
      await store.putAddSignerFinalizeReplay({
        kind: 'wallet_add_signer_finalize_replay_v1',
        addSignerCeremonyId: ceremony.addSignerCeremonyId,
        idempotencyKey,
        request: finalizeRequest,
        response,
        createdAtMs: finalizingAtMs,
        expiresAtMs: finalizingAtMs + ADD_SIGNER_REPLAY_TTL_MS,
      });
      return response;
    }
    if (prepared.kind !== 'd1_wallet_add_signer_finalize_ecdsa_prepared_v1') {
      throw new Error('ECDSA add-signer finalize claim changed branch');
    }
    if (
      ceremony.intent.signerSelection.mode !== 'ecdsa' ||
      ceremony.signerState.kind !== 'ecdsa_add_signer_activated'
    ) {
      return {
        ok: false,
        code: 'invalid_state',
        message: 'activated ECDSA add-signer registration is required before finalize',
      };
    }
    const expectedKeyHandle = finalizeRequest.expectedKeyHandles[0];
    if (expectedKeyHandle !== ceremony.signerState.bootstrap.keyHandle) {
      return {
        ok: false,
        code: 'key_handle_mismatch',
        message: 'ECDSA add-signer finalize expected key handle mismatch',
      };
    }
    const bootstraps: {
      chainTarget: StoredEcdsaAddSignerActivated['chainTargets'][number];
      bootstrap: StoredEcdsaAddSignerActivated['bootstrap'];
    }[] = [];
    for (const chainTarget of ceremony.signerState.chainTargets) {
      bootstraps.push({
        chainTarget,
        bootstrap: ceremony.signerState.bootstrap,
      });
    }
    const walletKeyResult = buildD1EcdsaWalletKeysFromBootstrap({
      bootstraps,
      publicCapability: ceremony.signerState.publicCapability,
      errorContext: 'ECDSA add-signer finalize',
    });
    if (!walletKeyResult.ok) return walletKeyResult;
    const walletKeys = walletKeyResult.walletKeys;
    const runtimePolicyScope = parseD1RuntimePolicyScope(ceremony.intent.runtimePolicyScope);
    if (!runtimePolicyScope) {
      return { ok: false, code: 'invalid_state', message: 'ECDSA add-signer scope is invalid' };
    }
    const signerWriteNow = prepared.signerWriteAtMs;
    const walletStore = this.getWalletStore();
    const wallet = await walletStore.getWallet({ walletId: ceremony.intent.walletId });
    if (!wallet) return { ok: false, code: 'not_found', message: 'wallet not found' };
    const walletSigners = buildD1WalletEcdsaSignerRecords({
      walletId: ceremony.intent.walletId,
      walletKeys,
      activationReceipt: ceremony.signerState.activation,
      runtimePolicyScope,
      now: signerWriteNow,
    });
    await walletStore.putSigners(walletSigners);
    const response: Extract<WalletAddSignerFinalizeResponse, { ok: true }> = {
      ok: true,
      kind: 'evm_family_ecdsa',
      walletId: ceremony.intent.walletId,
      ...(ceremony.auth.kind === 'webauthn_assertion' ? { rpId: ceremony.auth.rpId } : {}),
      ecdsa: {
        walletKeys,
      },
    };
    await store.putAddSignerFinalizeReplay({
      kind: 'wallet_add_signer_finalize_replay_v1',
      addSignerCeremonyId: ceremony.addSignerCeremonyId,
      idempotencyKey,
      request: finalizeRequest,
      response,
      createdAtMs: signerWriteNow,
      expiresAtMs: signerWriteNow + ADD_SIGNER_REPLAY_TTL_MS,
    });
    return response;
  }
}
