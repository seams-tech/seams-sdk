import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { requireTrimmedString } from '@shared/utils/validation';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import type { ThresholdEd25519SessionRecord } from '../persistence/records';
import {
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProvider,
  emailOtpAuthContextProviderUserId,
  emailOtpAuthContextRetention,
} from '../identity/laneIdentity';
import {
  readExactSealedSession,
  type BuildCurrentSealedSessionRecordInput,
} from '../persistence/sealedSessionStore';
import {
  requestSealEmailOtpWarmSessionMaterial,
  type EmailOtpWarmSessionTransport,
} from './workerRequests';

export type EmailOtpEd25519YaoPublicationPorts = {
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  registerSigningSession: (
    record: Extract<BuildCurrentSealedSessionRecordInput, { curve: 'ed25519' }>,
  ) => Promise<void>;
  readExactSealedSession: typeof readExactSealedSession;
};

function requirePositiveInteger(value: unknown, label: string): number {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 1) {
    throw new Error(`${label} must be positive for Email OTP Ed25519 sealed refresh`);
  }
  return normalized;
}

function buildEd25519YaoSealTransport(args: {
  relayerUrl: string;
  walletSessionJwt: string;
  groupId: string;
}): EmailOtpWarmSessionTransport {
  return {
    relayerUrl: args.relayerUrl,
    walletSessionJwt: args.walletSessionJwt,
    groupId: args.groupId,
  };
}

export async function persistEmailOtpEd25519YaoSessionForRefresh(
  args: {
    record: ThresholdEd25519SessionRecord;
    rpId: string;
  },
  ports: EmailOtpEd25519YaoPublicationPorts,
): Promise<void> {
  const record = args.record;
  const authContext = record.emailOtpAuthContext;
  if (record.source !== 'email_otp' || !authContext) {
    throw new Error('Email OTP Ed25519 sealed refresh requires Email OTP session authority');
  }
  if (ports.configs.signing.sessionPersistenceMode !== 'sealed_refresh_v1') return;
  if (emailOtpAuthContextRetention(authContext) !== 'session') return;

  const workerContext = ports.getSignerWorkerContext();
  if (!workerContext) {
    throw new Error('Email OTP Ed25519 sealed refresh requires the dedicated Email OTP worker');
  }
  const thresholdSessionId = requireTrimmedString(record.thresholdSessionId, 'thresholdSessionId');
  const signingGrantId = requireTrimmedString(record.signingGrantId, 'signingGrantId');
  const walletSessionJwt = requireTrimmedString(record.walletSessionJwt, 'walletSessionJwt');
  const relayerUrl = requireTrimmedString(record.relayerUrl, 'relayerUrl');
  const groupId = SIGNING_SESSION_SEAL_GROUP_ID;
  const runtimePolicyScope = record.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('runtimePolicyScope is required for Email OTP Ed25519 sealed refresh');
  }
  const transport = buildEd25519YaoSealTransport({
    relayerUrl,
    walletSessionJwt,
    groupId,
  });
  const sealed = await requestSealEmailOtpWarmSessionMaterial({
    workerCtx: workerContext,
    sessionId: thresholdSessionId,
    transport,
  });
  if (!sealed.ok) {
    throw new Error(`Email OTP Ed25519 sealed refresh failed (${sealed.code}): ${sealed.message}`);
  }
  const nowMs = Date.now();
  const expiresAtMs = requirePositiveInteger(sealed.expiresAtMs, 'expiresAtMs');
  const remainingUses = requirePositiveInteger(sealed.remainingUses, 'remainingUses');
  const keyVersion = requireTrimmedString(sealed.keyVersion, 'keyVersion');
  const providerSubjectId = requireTrimmedString(
    emailOtpAuthContextProviderUserId(authContext),
    'providerSubjectId',
  );
  await ports.registerSigningSession({
    thresholdSessionId,
    sealedSecretB64u: requireTrimmedString(sealed.sealedSecretB64u, 'sealedSecretB64u'),
    authMethod: 'email_otp',
    signingGrantId,
    keyVersion,
    groupId,
    issuedAtMs: nowMs,
    expiresAtMs,
    remainingUses,
    updatedAtMs: nowMs,
    curve: 'ed25519',
    thresholdSessionIds: { ed25519: thresholdSessionId },
    walletId: String(record.walletId),
    relayerUrl,
    ed25519Restore: {
      nearAccountId: String(record.nearAccountId),
      nearEd25519SigningKeyId: String(record.nearEd25519SigningKeyId),
      rpId: requireTrimmedString(args.rpId, 'rpId'),
      providerSubjectId,
      provider: emailOtpAuthContextProvider(authContext),
      emailHashHex: requireTrimmedString(
        emailOtpAuthContextEmailHashHex(authContext),
        'emailHashHex',
      ),
      relayerKeyId: requireTrimmedString(record.relayerKeyId, 'relayerKeyId'),
      participantIds: Array.from(record.participantIds),
      runtimePolicyScope,
      signerSlot: requirePositiveInteger(record.signerSlot, 'signerSlot'),
      routerAbNormalSigning: record.routerAbNormalSigning,
      walletSessionJwt,
      sessionKind: 'jwt',
    },
  });
  const persisted = await ports.readExactSealedSession(thresholdSessionId, {
    authMethod: 'email_otp',
    curve: 'ed25519',
  });
  if (
    !persisted ||
    persisted.curve !== 'ed25519' ||
    persisted.thresholdSessionIds.ed25519 !== thresholdSessionId ||
    persisted.signingGrantId !== signingGrantId ||
    persisted.ed25519Restore.providerSubjectId !== providerSubjectId
  ) {
    throw new Error('Email OTP Ed25519 sealed refresh read-back did not match the exact session');
  }
}
