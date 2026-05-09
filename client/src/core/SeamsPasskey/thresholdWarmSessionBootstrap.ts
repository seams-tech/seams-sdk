import {
  buildThresholdEd25519Participants2pV1,
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  normalizeThresholdEd25519ParticipantIds,
} from '@shared/threshold/participants';
import { isObject } from '@shared/utils/validation';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  AccountId,
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../types';
import { toAccountId } from '../types/accountIds';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import { IndexedDBManager } from '../indexedDB';
import {
  getNearThresholdKeyMaterial,
  storeNearThresholdKeyMaterial,
} from '../accountData/near/keyMaterial';
import { persistWarmSessionEd25519Capability } from '../signingEngine/session/warmCapabilities/persistence';
import { getPrfFirstB64uFromCredential } from '../signingEngine/threshold/crypto/webauthn';
import {
  getStoredThresholdEd25519SessionRecordForAccount,
  persistStoredThresholdEd25519SessionClientBase,
} from '../signingEngine/session/persistence/records';
import {
  THRESHOLD_SESSION_POLICY_VERSION,
  generateThresholdSessionId,
  generateWalletSigningSessionId,
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '../signingEngine/threshold/sessionPolicy';
import type { PasskeyManagerContext } from './index';
import {
  type CreateAccountAndRegisterThresholdEd25519Response,
  createManagedRegistrationFlowGrant,
  finalizeThresholdEd25519HssServerCeremonyWithRelayRegistration,
  prepareThresholdEd25519HssServerCeremonyWithRelayRegistration,
  respondThresholdEd25519HssServerCeremonyWithRelayRegistration,
  type CreateAccountAndRegisterThresholdEd25519Input,
  type ThresholdEd25519RegistrationHssFinalizeResult,
} from './faucets/createAccountRelayServer';
import {
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from '../signingEngine/threshold/ed25519/hssClientBase';
import { resolveThresholdWarmSessionDefaults } from './thresholdWarmSessionDefaults';

export const THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1 = 'threshold-ed25519-hss-v1';

export type ThresholdWarmSessionPolicyDraft = {
  sessionId: string;
  walletSigningSessionId?: string;
  ttlMs: number;
  remainingUses: number;
  participantIds?: number[];
};

export type ThresholdWarmSessionRequestEnvelope = {
  session_policy: {
    version: typeof THRESHOLD_SESSION_POLICY_VERSION;
    nearAccountId?: string;
    rpId: string;
    relayerKeyId?: string;
    sessionId: string;
    walletSigningSessionId?: string;
    participantIds?: number[];
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    ttlMs: number;
    remainingUses: number;
  };
  session_kind: 'jwt';
};

export type PreparedThresholdEd25519RegistrationWithHss = {
  hssFinalize: ThresholdEd25519RegistrationHssFinalizeResult;
  registrationInput: CreateAccountAndRegisterThresholdEd25519Input;
};

export type CompletedThresholdEd25519Registration = {
  registered: CreateAccountAndRegisterThresholdEd25519Response;
  operationalPublicKey: string;
};

type ThresholdWarmSessionRelayResult = {
  sessionKind?: string;
  sessionId?: string;
  walletSigningSessionId?: string;
  expiresAtMs?: number;
  participantIds?: number[];
  remainingUses?: number;
  jwt?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

const thresholdEd25519ClientBasePrewarmBySessionId = new Map<string, Promise<void>>();

function parsePositiveInt(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

export function createThresholdWarmSessionPolicyDraft(
  context: PasskeyManagerContext,
  input?: { sessionId?: string; participantIds?: number[] },
): ThresholdWarmSessionPolicyDraft | null {
  const defaults = resolveThresholdWarmSessionDefaults(context);
  if (!defaults) return null;
  const sessionId = String(input?.sessionId || '').trim() || generateThresholdSessionId();
  const walletSigningSessionId = generateWalletSigningSessionId();
  const participantIds = normalizeThresholdEd25519ParticipantIds(input?.participantIds);
  return {
    sessionId,
    walletSigningSessionId,
    ttlMs: defaults.ttlMs,
    remainingUses: defaults.remainingUses,
    ...(participantIds ? { participantIds } : {}),
  };
}

export function buildThresholdWarmSessionRequestEnvelope(args: {
  rpId: string;
  requestedPolicy: ThresholdWarmSessionPolicyDraft;
  nearAccountId?: string;
  relayerKeyId?: string;
}): ThresholdWarmSessionRequestEnvelope {
  const rpId = String(args.rpId || '').trim();
  const sessionId = String(args.requestedPolicy.sessionId || '').trim();
  if (!rpId || !sessionId) {
    throw new Error('Threshold warm-session request is missing rpId or sessionId');
  }
  return {
    session_policy: {
      version: THRESHOLD_SESSION_POLICY_VERSION,
      ...(args.nearAccountId ? { nearAccountId: String(args.nearAccountId || '').trim() } : {}),
      rpId,
      ...(args.relayerKeyId ? { relayerKeyId: String(args.relayerKeyId || '').trim() } : {}),
      sessionId,
      ...(args.requestedPolicy.walletSigningSessionId
        ? { walletSigningSessionId: args.requestedPolicy.walletSigningSessionId }
        : {}),
      ...(Array.isArray(args.requestedPolicy.participantIds)
        ? { participantIds: args.requestedPolicy.participantIds }
        : {}),
      ttlMs: args.requestedPolicy.ttlMs,
      remainingUses: args.requestedPolicy.remainingUses,
    },
    session_kind: 'jwt',
  };
}

export async function prepareThresholdEd25519RegistrationWithHss(args: {
  context: PasskeyManagerContext;
  credential: WebAuthnRegistrationCredential;
  nearAccountId: AccountId | string;
  rpId: string;
  authenticatorOptions?: AuthenticatorOptions;
  onProgress?: (message: string) => void;
}): Promise<PreparedThresholdEd25519RegistrationWithHss> {
  args.onProgress?.('Resolving registration scope...');
  const managedRegistrationFlow = await createManagedRegistrationFlowGrant({
    context: args.context,
    nearAccountId: String(args.nearAccountId),
    rpId: args.rpId,
  });
  const runtimePolicyScope = managedRegistrationFlow.runtimePolicyScope;
  const requestedPolicy = createThresholdWarmSessionPolicyDraft(args.context);
  if (!requestedPolicy) {
    throw new Error('Threshold warm-session defaults are disabled for registration');
  }
  args.onProgress?.('Preparing threshold Ed25519 signer from passkey...');
  const signingRootId = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope).signingRootId;
  const prepared =
    await args.context.signingEngine.prepareThresholdEd25519HssClientCeremonyFromCredential({
      credential: args.credential,
      signingRootId,
      nearAccountId: args.nearAccountId,
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion: THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1,
      participantIds: normalizeThresholdEd25519ParticipantIds(requestedPolicy.participantIds) || [
        ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
      ],
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      onProgress: args.onProgress,
    });
  if (!prepared.success) {
    throw new Error(prepared.error || 'Failed to prepare threshold Ed25519 HSS registration');
  }

  args.onProgress?.('Preparing threshold Ed25519 relay ceremony...');
  const preparedRelayCeremony = await prepareThresholdEd25519HssServerCeremonyWithRelayRegistration(
    {
      context: args.context,
      nearAccountId: String(args.nearAccountId),
      rpId: args.rpId,
      hssContext: {
        signingRootId,
        nearAccountId: String(args.nearAccountId),
        keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
        keyVersion: THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1,
        participantIds: prepared.participantIds,
        derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      },
    },
  );

  const clientRequest = await args.context.signingEngine.prepareThresholdEd25519HssClientRequest({
    evaluatorDriverStateB64u: preparedRelayCeremony.preparedSession.evaluatorDriverStateB64u,
    clientOtOfferMessageB64u: preparedRelayCeremony.clientOtOfferMessageB64u,
    clientInputs: {
      contextBindingB64u: prepared.contextBindingB64u,
      yClientB64u: prepared.yClientB64u,
      tauClientB64u: prepared.tauClientB64u,
    },
  });

  const responded = await respondThresholdEd25519HssServerCeremonyWithRelayRegistration({
    context: args.context,
    nearAccountId: String(args.nearAccountId),
    rpId: args.rpId,
    ceremonyHandle: preparedRelayCeremony.ceremonyHandle,
    clientRequest,
  });

  args.onProgress?.('Finalizing threshold Ed25519 registration material...');
  const hssFinalize = await finalizeThresholdEd25519HssServerCeremonyWithRelayRegistration({
    context: args.context,
    nearAccountId: String(args.nearAccountId),
    rpId: args.rpId,
    ceremonyHandle: preparedRelayCeremony.ceremonyHandle,
  });
  if (!hssFinalize.publicKey || !hssFinalize.relayerKeyId) {
    throw new Error('Threshold Ed25519 registration HSS finalize returned incomplete key material');
  }

  return {
    hssFinalize,
    registrationInput: {
      keyVersion: THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1,
      recoveryExportCapable: true,
      publicKey: hssFinalize.publicKey,
      relayerKeyId: hssFinalize.relayerKeyId,
      sessionPolicy: {
        version: THRESHOLD_SESSION_POLICY_VERSION,
        nearAccountId: String(args.nearAccountId),
        rpId: args.rpId,
        relayerKeyId: hssFinalize.relayerKeyId,
        sessionId: requestedPolicy.sessionId,
        walletSigningSessionId: requestedPolicy.walletSigningSessionId || requestedPolicy.sessionId,
        participantIds: prepared.participantIds,
        ttlMs: requestedPolicy.ttlMs,
        remainingUses: requestedPolicy.remainingUses,
        runtimePolicyScope,
      },
      sessionKind: 'jwt',
    },
  };
}

export function requireThresholdEd25519WarmSessionKeyVersion(
  raw: unknown,
  errorContext: string,
): {
  keyVersion: string;
} {
  const section = isObject(raw) ? raw : {};
  const keyVersion = String(section.keyVersion || '').trim();
  const recoveryExportCapable =
    typeof section.recoveryExportCapable === 'boolean'
      ? Boolean(section.recoveryExportCapable)
      : undefined;
  if (
    keyVersion !== THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1 ||
    recoveryExportCapable !== true
  ) {
    throw new Error(`${errorContext} returned incomplete threshold-ed25519 key metadata`);
  }
  return { keyVersion };
}

export function completeRegisteredThresholdEd25519Registration(args: {
  thresholdEd25519: CreateAccountAndRegisterThresholdEd25519Response | undefined;
  expectedSessionPolicy: ThresholdWarmSessionRequestEnvelope['session_policy'];
}): CompletedThresholdEd25519Registration {
  const thresholdEd25519 = args.thresholdEd25519;
  if (!thresholdEd25519) {
    throw new Error('Registration did not return threshold-ed25519 material');
  }
  if (
    String(thresholdEd25519.keyVersion || '').trim() !==
    THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1
  ) {
    throw new Error('Registration did not return the active threshold-ed25519 keyVersion');
  }
  if (thresholdEd25519.recoveryExportCapable !== true) {
    throw new Error('Registration did not return recoveryExportCapable=true for threshold-ed25519');
  }
  const operationalPublicKey = String(thresholdEd25519.publicKey || '').trim();
  const relayerKeyId = String(thresholdEd25519.relayerKeyId || '').trim();
  if (!operationalPublicKey) {
    throw new Error('Missing account public key after registration');
  }
  if (!relayerKeyId) {
    throw new Error('Threshold registration did not return relayerKeyId');
  }

  const session = thresholdEd25519.session;
  const sessionKind = String(session?.sessionKind || '')
    .trim()
    .toLowerCase();
  const sessionId = String(session?.sessionId || '').trim();
  const sessionAuthToken = String(session?.jwt || '').trim();
  const expiresAtMs = Number(session?.expiresAtMs);
  if (
    sessionKind !== 'jwt' ||
    !sessionId ||
    !sessionAuthToken ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= 0
  ) {
    throw new Error('Registration did not return a valid threshold-ed25519 warm session');
  }
  if (sessionId !== String(args.expectedSessionPolicy.sessionId || '').trim()) {
    throw new Error('threshold-ed25519 sessionId mismatch');
  }
  const walletSigningSessionId = String(session?.walletSigningSessionId || '').trim();
  const expectedWalletSigningSessionId = String(
    args.expectedSessionPolicy.walletSigningSessionId || args.expectedSessionPolicy.sessionId || '',
  ).trim();
  if (walletSigningSessionId && walletSigningSessionId !== expectedWalletSigningSessionId) {
    throw new Error('threshold-ed25519 walletSigningSessionId mismatch');
  }

  return {
    registered: thresholdEd25519,
    operationalPublicKey,
  };
}

export async function storeThresholdEd25519KeyMaterial(args: {
  nearAccountId: AccountId | string;
  signerSlot: number;
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  clientParticipantId?: number | null;
  relayerParticipantId?: number | null;
  relayerUrl?: string | null;
  timestamp?: number;
}): Promise<void> {
  const nearAccountId = String(args.nearAccountId || '').trim();
  const publicKey = String(args.publicKey || '').trim();
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const keyVersion = String(args.keyVersion || '').trim();
  if (!nearAccountId) {
    throw new Error('Threshold Ed25519 key persistence requires nearAccountId');
  }
  if (!Number.isSafeInteger(args.signerSlot) || args.signerSlot < 1) {
    throw new Error('Threshold Ed25519 key persistence requires signerSlot >= 1');
  }
  if (!publicKey) {
    throw new Error('Threshold Ed25519 key persistence requires publicKey');
  }
  if (!relayerKeyId || !keyVersion) {
    throw new Error('Threshold Ed25519 key persistence requires complete relayer metadata');
  }

  await storeNearThresholdKeyMaterial(
    {
      clientDB: IndexedDBManager.clientDB,
      accountKeyMaterialDB: IndexedDBManager.accountKeyMaterialDB,
    },
    {
      nearAccountId: nearAccountId as AccountId,
      signerSlot: args.signerSlot,
      publicKey,
      relayerKeyId,
      keyVersion,
      participants: buildThresholdEd25519Participants2pV1({
        clientParticipantId: Number.isFinite(Number(args.clientParticipantId))
          ? Math.floor(Number(args.clientParticipantId))
          : null,
        relayerParticipantId: Number.isFinite(Number(args.relayerParticipantId))
          ? Math.floor(Number(args.relayerParticipantId))
          : null,
        relayerKeyId,
        relayerUrl: args.relayerUrl,
        clientShareDerivation: 'prf_first_v1',
      }),
      timestamp: typeof args.timestamp === 'number' ? args.timestamp : Date.now(),
    },
  );
}

export async function persistRegisteredThresholdEd25519Session(args: {
  signingEngine: PasskeyManagerContext['signingEngine'];
  nearAccountId: AccountId;
  signerSlot: number;
  rpId: string;
  relayerUrl: string;
  prfFirstB64u: string | null;
  registrationSessionPolicy: ThresholdWarmSessionRequestEnvelope['session_policy'];
  completedRegistration: CompletedThresholdEd25519Registration;
}): Promise<void> {
  await storeThresholdEd25519KeyMaterial({
    nearAccountId: args.nearAccountId,
    signerSlot: args.signerSlot,
    publicKey: args.completedRegistration.registered.publicKey,
    relayerKeyId: args.completedRegistration.registered.relayerKeyId,
    keyVersion: args.completedRegistration.registered.keyVersion,
    clientParticipantId: args.completedRegistration.registered.clientParticipantId,
    relayerParticipantId: args.completedRegistration.registered.relayerParticipantId,
    relayerUrl: args.relayerUrl,
    timestamp: Date.now(),
  });

  if (!args.prfFirstB64u) return;

  const session = args.completedRegistration.registered.session;
  if (!session) {
    throw new Error('Threshold Ed25519 warm session missing from registration response');
  }
  const sessionId = String(session.sessionId || '').trim();
  const jwt = String(session.jwt || '').trim();
  const walletSigningSessionId =
    String(session.walletSigningSessionId || '').trim() ||
    String(args.registrationSessionPolicy.walletSigningSessionId || '').trim() ||
    String(args.registrationSessionPolicy.sessionId || '').trim();
  const expiresAtMs = Number(session.expiresAtMs);
  const remainingUsesRaw =
    typeof session.remainingUses === 'number'
      ? session.remainingUses
      : Number(session.remainingUses);
  const remainingUses =
    Number.isFinite(remainingUsesRaw) && remainingUsesRaw > 0
      ? Math.floor(remainingUsesRaw)
      : Math.max(1, Math.floor(Number(args.registrationSessionPolicy.remainingUses) || 1));
  const participantIds = Array.isArray(session.participantIds)
    ? session.participantIds
    : normalizeThresholdEd25519ParticipantIds(args.registrationSessionPolicy.participantIds) || [
        ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
      ];
  const runtimePolicyScope =
    session.runtimePolicyScope || args.registrationSessionPolicy.runtimePolicyScope;

  persistWarmSessionEd25519Capability({
    nearAccountId: String(args.nearAccountId),
    rpId: args.rpId,
    relayerUrl: args.relayerUrl,
    relayerKeyId: args.completedRegistration.registered.relayerKeyId,
    participantIds,
    sessionKind: 'jwt' as ThresholdSessionKind,
    sessionId,
    walletSigningSessionId,
    expiresAtMs,
    remainingUses,
    jwt,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    source: 'registration',
  });

  await args.signingEngine.hydrateSigningSession({
    sessionId,
    prfFirstB64u: args.prfFirstB64u,
    expiresAtMs,
    remainingUses,
    transport: {
      curve: 'ed25519',
      relayerUrl: args.relayerUrl,
      ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
      ...(jwt ? { thresholdSessionAuthToken: jwt } : {}),
    },
  });
}

export async function reconstructThresholdEd25519ClientBaseFromWarmSession(args: {
  context: PasskeyManagerContext;
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
  nearAccountId: AccountId | string;
  relayerUrl: string;
  relayerKeyId: string;
  session: ThresholdWarmSessionRelayResult;
  keyVersion: string;
  participantIdsHint?: number[];
}): Promise<string> {
  const thresholdSessionId = String(args.session.sessionId || '').trim();
  const thresholdSessionAuthToken = String(args.session.jwt || '').trim();
  if (!thresholdSessionId || !thresholdSessionAuthToken) {
    throw new Error('Threshold Ed25519 warm session is missing JWT session state');
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(args.session.runtimePolicyScope);
  const signingRootId = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope).signingRootId
    : '';
  if (!signingRootId) {
    throw new Error(
      'Threshold Ed25519 warm session is missing canonical single-key HSS signing-root scope',
    );
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.session.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.participantIdsHint) || [
      ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
    ];
  const relayerUrl = String(args.relayerUrl || '').trim();
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const keyVersion = String(args.keyVersion || '').trim();
  if (!relayerUrl || !relayerKeyId || !keyVersion) {
    throw new Error('Threshold Ed25519 warm-session reconstruction is missing relay metadata');
  }
  const prepared =
    await args.context.signingEngine.prepareThresholdEd25519HssClientCeremonyFromCredential({
      credential: args.credential,
      signingRootId,
      nearAccountId: args.nearAccountId,
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion,
      participantIds,
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
    });
  if (!prepared.success) {
    throw new Error(
      prepared.error || 'Failed to prepare threshold Ed25519 HSS reconstruction ceremony',
    );
  }
  const completed = await args.context.signingEngine.runThresholdEd25519HssCeremonyWithSession({
    relayerUrl,
    thresholdSessionAuthToken,
    relayerKeyId,
    operation: 'warm_session_reconstruction',
    context: {
      signingRootId,
      nearAccountId: args.nearAccountId,
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion,
      participantIds,
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
    },
    clientInputs: {
      contextBindingB64u: prepared.contextBindingB64u,
      yClientB64u: prepared.yClientB64u,
      tauClientB64u: prepared.tauClientB64u,
    },
  });
  if (!completed.success || !completed.clientOutput?.xClientBaseB64u) {
    throw new Error(
      completed.error || 'Failed to reconstruct threshold Ed25519 single-key HSS client base',
    );
  }
  const xClientBaseB64u = String(completed.clientOutput.xClientBaseB64u || '').trim();
  const persisted = persistStoredThresholdEd25519SessionClientBase({
    thresholdSessionId,
    xClientBaseB64u,
  });
  if (!persisted) {
    throw new Error('Failed to persist HSS client output to the threshold session store');
  }
  return xClientBaseB64u;
}

export async function prewarmThresholdEd25519ClientBaseFromCredential(args: {
  context: PasskeyManagerContext;
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
  nearAccountId: AccountId | string;
  signerSlot: number;
}): Promise<void> {
  const nearAccountId = String(args.nearAccountId || '').trim();
  const signerSlot = Number(args.signerSlot);
  if (!nearAccountId) return;
  if (!Number.isInteger(signerSlot) || signerSlot <= 0) return;

  const sessionRecord = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
  if (!sessionRecord) return;
  if (String(sessionRecord.xClientBaseB64u || '').trim()) return;

  const thresholdSessionId = String(sessionRecord.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;

  const existingTask = thresholdEd25519ClientBasePrewarmBySessionId.get(thresholdSessionId);
  if (existingTask) {
    await existingTask;
    return;
  }

  const task = (async (): Promise<void> => {
    const thresholdKeyMaterial = await getNearThresholdKeyMaterial(
      {
        clientDB: IndexedDBManager.clientDB,
        accountKeyMaterialDB: IndexedDBManager.accountKeyMaterialDB,
      },
      toAccountId(nearAccountId),
      signerSlot,
    ).catch(() => null);
    if (!thresholdKeyMaterial) return;

    if (sessionRecord.thresholdSessionKind !== 'jwt') return;
    if (!String(sessionRecord.thresholdSessionAuthToken || '').trim()) return;
    if (!sessionRecord.runtimePolicyScope) return;

    const startedAt = performance.now();
    try {
      await reconstructThresholdEd25519ClientBaseFromWarmSession({
        context: args.context,
        credential: args.credential,
        nearAccountId,
        relayerUrl: sessionRecord.relayerUrl,
        relayerKeyId: sessionRecord.relayerKeyId || thresholdKeyMaterial.relayerKeyId,
        session: {
          sessionKind: sessionRecord.thresholdSessionKind,
          sessionId: sessionRecord.thresholdSessionId,
          expiresAtMs: sessionRecord.expiresAtMs,
          participantIds: sessionRecord.participantIds,
          remainingUses: sessionRecord.remainingUses,
          jwt: sessionRecord.thresholdSessionAuthToken,
          runtimePolicyScope: sessionRecord.runtimePolicyScope,
        },
        keyVersion: thresholdKeyMaterial.keyVersion,
        participantIdsHint: thresholdKeyMaterial.participants.map((participant) => participant.id),
      });
      console.debug('[threshold-ed25519] background client-base prewarm complete', {
        nearAccountId,
        thresholdSessionId,
        durationMs: Math.round(performance.now() - startedAt),
      });
    } catch (error: unknown) {
      console.warn('[threshold-ed25519] background client-base prewarm failed', {
        nearAccountId,
        thresholdSessionId,
        durationMs: Math.round(performance.now() - startedAt),
        error: error instanceof Error ? error.message : String(error),
      });
    }
  })().finally(() => {
    thresholdEd25519ClientBasePrewarmBySessionId.delete(thresholdSessionId);
  });

  thresholdEd25519ClientBasePrewarmBySessionId.set(thresholdSessionId, task);
  await task;
}

export async function hydrateThresholdWarmSessionFromRelay(args: {
  context: PasskeyManagerContext;
  nearAccountId: AccountId | string;
  relayerUrl: string;
  rpId: string;
  relayerKeyId: string;
  credential: WebAuthnAuthenticationCredential | WebAuthnRegistrationCredential;
  requestedPolicy: ThresholdWarmSessionPolicyDraft;
  session: ThresholdWarmSessionRelayResult;
  participantIdsHint?: number[];
}): Promise<{
  sessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  participantIds: number[];
}> {
  const sessionKind = String(args.session?.sessionKind || 'jwt')
    .trim()
    .toLowerCase() as ThresholdSessionKind;
  if (sessionKind !== 'jwt') {
    throw new Error('threshold-ed25519 bootstrap sessionKind must be jwt');
  }

  const sessionId =
    String(args.session?.sessionId || '').trim() ||
    String(args.requestedPolicy.sessionId || '').trim();
  const walletSigningSessionId =
    String(args.session?.walletSigningSessionId || '').trim() ||
    String(args.requestedPolicy.walletSigningSessionId || '').trim() ||
    String(args.requestedPolicy.sessionId || '').trim();
  const sessionAuthToken = String(args.session?.jwt || '').trim();
  const expiresAtMs = Number(args.session?.expiresAtMs);
  if (!sessionId || !sessionAuthToken || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('threshold-ed25519 bootstrap response missing session fields');
  }

  const remainingUsesRaw = parsePositiveInt(args.session?.remainingUses);
  const remainingUses =
    remainingUsesRaw > 0 ? remainingUsesRaw : parsePositiveInt(args.requestedPolicy.remainingUses);
  if (remainingUses <= 0) {
    throw new Error('threshold-ed25519 bootstrap response missing remainingUses');
  }

  const participantIds = normalizeThresholdEd25519ParticipantIds(args.session?.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.requestedPolicy.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.participantIdsHint) || [
      ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
    ];
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(args.session?.runtimePolicyScope);
  const prfFirstB64u = String(getPrfFirstB64uFromCredential(args.credential) || '').trim();
  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output from credential for threshold session hydration');
  }

  persistWarmSessionEd25519Capability({
    nearAccountId: String(args.nearAccountId),
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds,
    sessionKind: 'jwt',
    sessionId,
    walletSigningSessionId,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    jwt: sessionAuthToken,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    source: 'bootstrap',
  });
  await args.context.signingEngine.hydrateSigningSession({
    sessionId,
    prfFirstB64u,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    transport: {
      curve: 'ed25519',
      relayerUrl: String(args.relayerUrl || '').trim(),
      ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
      ...(sessionAuthToken ? { thresholdSessionAuthToken: sessionAuthToken } : {}),
    },
  });

  return {
    sessionId,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    participantIds,
  };
}
