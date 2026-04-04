import {
  buildThresholdEd25519Participants2pV1,
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  normalizeThresholdEd25519ParticipantIds,
} from '@shared/threshold/participants';
import { isObject } from '@shared/utils/validation';
import type {
  AccountId,
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../types';
import { toAccountId } from '../types/accountIds';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import { IndexedDBManager } from '../indexedDB';
import { getNearThresholdKeyMaterial, storeNearThresholdKeyMaterial } from '../accountData/near/keyMaterial';
import {
  buildAndCacheEd25519AuthSession,
  type Ed25519SessionKind,
} from '../signingEngine/threshold/session/ed25519AuthSession';
import { getPrfFirstB64uFromCredential } from '../signingEngine/threshold/webauthn';
import { getStoredThresholdEd25519SessionRecordForAccount } from '../signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import {
  THRESHOLD_SESSION_POLICY_VERSION,
  generateThresholdSessionId,
} from '../signingEngine/threshold/session/sessionPolicy';
import type { PasskeyManagerContext } from './index';
import {
  type CreateAccountAndRegisterThresholdEd25519Response,
  createManagedRegistrationFlowGrant,
  finalizeThresholdEd25519HssServerCeremonyWithRelayRegistration,
  prepareThresholdEd25519HssServerCeremonyWithRelayRegistration,
  type CreateAccountAndRegisterThresholdEd25519Input,
  type ThresholdEd25519RegistrationHssFinalizeResult,
} from './faucets/createAccountRelayServer';
import {
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from '../signingEngine/orchestration/near/shared/ensureThresholdEd25519HssClientBase';
import { resolveThresholdWarmSessionDefaults } from './thresholdWarmSessionDefaults';

export const THRESHOLD_ED25519_OPTION_A_KEY_VERSION_V1 = 'threshold-ed25519-hss-v1';

export type ThresholdWarmSessionPolicyDraft = {
  sessionId: string;
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
    participantIds?: number[];
    ttlMs: number;
    remainingUses: number;
  };
  session_kind: 'jwt';
};

export type PreparedThresholdEd25519RegistrationWithHss = {
  hssFinalize: ThresholdEd25519RegistrationHssFinalizeResult;
  registrationInput: CreateAccountAndRegisterThresholdEd25519Input;
  managedRegistrationBootstrapToken: string;
};

export type CompletedThresholdEd25519Registration = {
  registered: CreateAccountAndRegisterThresholdEd25519Response;
  operationalPublicKey: string;
};

type ThresholdWarmSessionRelayResult = {
  sessionKind?: string;
  sessionId?: string;
  expiresAtMs?: number;
  participantIds?: number[];
  remainingUses?: number;
  jwt?: string;
  runtimeSnapshotScope?: { orgId?: string; environmentId?: string; projectId?: string };
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
  const participantIds = normalizeThresholdEd25519ParticipantIds(input?.participantIds);
  return {
    sessionId,
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
  const runtimeSnapshotScope = managedRegistrationFlow.runtimeSnapshotScope;
  const requestedPolicy = createThresholdWarmSessionPolicyDraft(args.context);
  if (!requestedPolicy) {
    throw new Error('Threshold warm-session defaults are disabled for registration');
  }
  args.onProgress?.('Preparing threshold Ed25519 signer from passkey...');
  const prepared =
    await args.context.signingEngine.prepareThresholdEd25519HssClientCeremonyFromCredential({
      credential: args.credential,
      orgId: runtimeSnapshotScope.orgId,
      nearAccountId: args.nearAccountId,
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion: THRESHOLD_ED25519_OPTION_A_KEY_VERSION_V1,
      participantIds: normalizeThresholdEd25519ParticipantIds(requestedPolicy.participantIds) || [
        ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
      ],
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      onProgress: args.onProgress,
    });
  if (!prepared.success || !prepared.preparedSession || !prepared.clientRequest) {
    throw new Error(prepared.error || 'Failed to prepare threshold Ed25519 Option A registration');
  }

  args.onProgress?.('Preparing threshold Ed25519 relay ceremony...');
  const preparedRelayCeremony = await prepareThresholdEd25519HssServerCeremonyWithRelayRegistration({
    context: args.context,
    nearAccountId: String(args.nearAccountId),
    rpId: args.rpId,
    managedRegistrationBootstrapToken: managedRegistrationFlow.token,
    hssContext: {
      orgId: runtimeSnapshotScope.orgId,
      nearAccountId: String(args.nearAccountId),
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion: THRESHOLD_ED25519_OPTION_A_KEY_VERSION_V1,
      participantIds: prepared.participantIds,
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
    },
    preparedSession: prepared.preparedSession,
    clientRequest: prepared.clientRequest,
  });

  const evaluationResult = await args.context.signingEngine.evaluateThresholdEd25519HssResult({
    preparedSession: prepared.preparedSession,
    clientRequest: prepared.clientRequest,
    serverMessage: preparedRelayCeremony.serverMessage,
  });

  args.onProgress?.('Finalizing threshold Ed25519 registration material...');
  const hssFinalize = await finalizeThresholdEd25519HssServerCeremonyWithRelayRegistration({
    context: args.context,
    nearAccountId: String(args.nearAccountId),
    rpId: args.rpId,
    managedRegistrationBootstrapToken: managedRegistrationFlow.token,
    ceremonyHandle: preparedRelayCeremony.ceremonyHandle,
    evaluationResult,
  });
  if (!hssFinalize.publicKey || !hssFinalize.relayerKeyId) {
    throw new Error('Threshold Ed25519 registration HSS finalize returned incomplete key material');
  }

  return {
    hssFinalize,
    managedRegistrationBootstrapToken: managedRegistrationFlow.token,
    registrationInput: {
      keyVersion: THRESHOLD_ED25519_OPTION_A_KEY_VERSION_V1,
      recoveryExportCapable: true,
      publicKey: hssFinalize.publicKey,
      relayerKeyId: hssFinalize.relayerKeyId,
      sessionPolicy: {
        version: THRESHOLD_SESSION_POLICY_VERSION,
        nearAccountId: String(args.nearAccountId),
        rpId: args.rpId,
        relayerKeyId: hssFinalize.relayerKeyId,
        sessionId: requestedPolicy.sessionId,
        participantIds: prepared.participantIds,
        ttlMs: requestedPolicy.ttlMs,
        remainingUses: requestedPolicy.remainingUses,
        runtimeSnapshotScope,
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
  if (keyVersion !== THRESHOLD_ED25519_OPTION_A_KEY_VERSION_V1 || recoveryExportCapable !== true) {
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
    String(thresholdEd25519.keyVersion || '').trim() !== THRESHOLD_ED25519_OPTION_A_KEY_VERSION_V1
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
  const sessionJwt = String(session?.jwt || '').trim();
  const expiresAtMs = Number(session?.expiresAtMs);
  if (
    sessionKind !== 'jwt' ||
    !sessionId ||
    !sessionJwt ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= 0
  ) {
    throw new Error('Registration did not return a valid threshold-ed25519 warm session');
  }
  if (sessionId !== String(args.expectedSessionPolicy.sessionId || '').trim()) {
    throw new Error('threshold-ed25519 sessionId mismatch');
  }

  return {
    registered: thresholdEd25519,
    operationalPublicKey,
  };
}

export async function storeThresholdEd25519KeyMaterial(args: {
  nearAccountId: AccountId | string;
  deviceNumber: number;
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
  if (!Number.isSafeInteger(args.deviceNumber) || args.deviceNumber < 1) {
    throw new Error('Threshold Ed25519 key persistence requires deviceNumber >= 1');
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
      deviceNumber: args.deviceNumber,
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
  deviceNumber: number;
  rpId: string;
  relayerUrl: string;
  prfFirstB64u: string | null;
  registrationSessionPolicy: ThresholdWarmSessionRequestEnvelope['session_policy'];
  completedRegistration: CompletedThresholdEd25519Registration;
}): Promise<void> {
  await storeThresholdEd25519KeyMaterial({
    nearAccountId: args.nearAccountId,
    deviceNumber: args.deviceNumber,
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

  await buildAndCacheEd25519AuthSession({
    nearAccountId: String(args.nearAccountId),
    rpId: args.rpId,
    relayerUrl: args.relayerUrl,
    relayerKeyId: args.completedRegistration.registered.relayerKeyId,
    participantIds,
    sessionKind: 'jwt' as Ed25519SessionKind,
    sessionId,
    expiresAtMs,
    remainingUses,
    jwt,
    ...(session.runtimeSnapshotScope ? { runtimeSnapshotScope: session.runtimeSnapshotScope } : {}),
    policyTtlMs: args.registrationSessionPolicy.ttlMs,
    policyRemainingUses: args.registrationSessionPolicy.remainingUses,
    source: 'registration',
  });

  void args.signingEngine
    .hydrateSigningSession({
      nearAccountId: args.nearAccountId,
      signerKind: 'threshold-ed25519',
      sessionId,
      prfFirstB64u: args.prfFirstB64u,
      expiresAtMs,
      remainingUses,
      setActiveSigningSessionId: true,
    })
    .catch((error: unknown) => {
      console.warn(
        '[threshold-ed25519] deferred warm-session PRF cache hydrate failed after registration',
        error,
      );
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
  const thresholdSessionJwt = String(args.session.jwt || '').trim();
  if (!thresholdSessionId || !thresholdSessionJwt) {
    throw new Error('Threshold Ed25519 warm session is missing JWT session state');
  }
  const orgId = String(args.session.runtimeSnapshotScope?.orgId || '').trim();
  if (!orgId) {
    throw new Error('Threshold Ed25519 warm session is missing canonical Option A org scope');
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
      orgId,
      nearAccountId: args.nearAccountId,
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion,
      participantIds,
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
    });
  if (!prepared.success || !prepared.preparedSession || !prepared.clientRequest) {
    throw new Error(
      prepared.error || 'Failed to prepare threshold Ed25519 Option A registration ceremony',
    );
  }
  const completed = await args.context.signingEngine.runThresholdEd25519HssCeremonyWithSession({
    relayerUrl,
    thresholdSessionJwt,
    relayerKeyId,
    preparedSession: prepared.preparedSession,
    clientRequest: prepared.clientRequest,
    persistToThresholdSessionId: thresholdSessionId,
  });
  if (!completed.success || !completed.clientOutput?.xClientBaseB64u) {
    throw new Error(
      completed.error || 'Failed to reconstruct threshold Ed25519 Option A client base',
    );
  }
  return String(completed.clientOutput.xClientBaseB64u || '').trim();
}

export async function prewarmThresholdEd25519ClientBaseFromCredential(args: {
  context: PasskeyManagerContext;
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
  nearAccountId: AccountId | string;
  deviceNumber: number;
}): Promise<void> {
  const nearAccountId = String(args.nearAccountId || '').trim();
  const deviceNumber = Number(args.deviceNumber);
  if (!nearAccountId) return;
  if (!Number.isInteger(deviceNumber) || deviceNumber <= 0) return;

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
      deviceNumber,
    ).catch(() => null);
    if (!thresholdKeyMaterial) return;

    if (sessionRecord.thresholdSessionKind !== 'jwt') return;
    if (!String(sessionRecord.thresholdSessionJwt || '').trim()) return;
    if (!String(sessionRecord.runtimeSnapshotScope?.orgId || '').trim()) return;

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
          jwt: sessionRecord.thresholdSessionJwt,
          runtimeSnapshotScope: sessionRecord.runtimeSnapshotScope,
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
  setActiveSigningSessionId?: boolean;
}): Promise<{
  sessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  participantIds: number[];
}> {
  const sessionKind = String(args.session?.sessionKind || 'jwt')
    .trim()
    .toLowerCase() as Ed25519SessionKind;
  if (sessionKind !== 'jwt') {
    throw new Error('threshold-ed25519 bootstrap sessionKind must be jwt');
  }

  const sessionId =
    String(args.session?.sessionId || '').trim() ||
    String(args.requestedPolicy.sessionId || '').trim();
  const sessionJwt = String(args.session?.jwt || '').trim();
  const expiresAtMs = Number(args.session?.expiresAtMs);
  if (!sessionId || !sessionJwt || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
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
  const prfFirstB64u = String(getPrfFirstB64uFromCredential(args.credential) || '').trim();
  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output from credential for threshold session hydration');
  }

  await buildAndCacheEd25519AuthSession({
    nearAccountId: String(args.nearAccountId),
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds,
    sessionKind: 'jwt',
    sessionId,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    jwt: sessionJwt,
    source: 'bootstrap',
  });
  await args.context.signingEngine.hydrateSigningSession({
    nearAccountId: args.nearAccountId,
    signerKind: 'threshold-ed25519',
    sessionId,
    prfFirstB64u,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    setActiveSigningSessionId: args.setActiveSigningSessionId !== false,
  });

  return {
    sessionId,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    participantIds,
  };
}
