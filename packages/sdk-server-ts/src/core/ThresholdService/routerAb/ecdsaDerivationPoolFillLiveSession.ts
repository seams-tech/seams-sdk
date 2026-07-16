import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { safeErrorMessage } from '@shared/utils/errors';
import { sha256BytesSync } from '../evmCryptoWasm';
import { ensureRouterAbEcdsaSigningWorkerWasm } from '../routerAbEcdsaSigningWorkerWasm';
import type { RouterAbEcdsaDerivationPoolFillSessionRecord } from '../stores/EcdsaSigningStore';
import { ThresholdEcdsaPresignSession } from '../../../../../../wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker.js';

export type RouterAbEcdsaDerivationPoolFillParseOk<T> = { ok: true; value: T };
export type RouterAbEcdsaDerivationPoolFillParseErr = { ok: false; code: string; message: string };
export type RouterAbEcdsaDerivationPoolFillParseResult<T> =
  | RouterAbEcdsaDerivationPoolFillParseOk<T>
  | RouterAbEcdsaDerivationPoolFillParseErr;

export type RouterAbEcdsaDerivationPoolFillWasmPoll = {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoingMessagesB64u: string[];
};

export type RouterAbEcdsaDerivationPresignatureMaterial = {
  presignatureId: string;
  bigRB64u: string;
  kShareB64u: string;
  sigmaShareB64u: string;
};

export type RouterAbEcdsaDerivationPoolFillPreparedStep =
  | {
      mode: 'terminal';
      presignDone: RouterAbEcdsaDerivationPresignatureMaterial;
    }
  | {
      mode: 'immediate';
      response: {
        ok: true;
        stage: 'triples_done';
        event: 'triples_done';
        outgoingMessagesB64u: [];
      };
    }
  | {
      mode: 'advance';
      polled: RouterAbEcdsaDerivationPoolFillWasmPoll;
      nextRecord: RouterAbEcdsaDerivationPoolFillSessionRecord;
      presignDone: RouterAbEcdsaDerivationPresignatureMaterial | null;
    };

export type RouterAbEcdsaDerivationPoolFillLiveSessionCreateInput = {
  presignSessionId: string;
  record: RouterAbEcdsaDerivationPoolFillSessionRecord;
  participantIds: number[];
  relayerParticipantId: number;
  relayerThresholdShare32B64u: string;
  groupPublicKey33B64u: string;
};

export type RouterAbEcdsaDerivationPoolFillLiveSessionCreateValue = {
  record: RouterAbEcdsaDerivationPoolFillSessionRecord;
  stage: RouterAbEcdsaDerivationPoolFillWasmPoll['stage'];
  outgoingMessagesB64u: string[];
};

export type RouterAbEcdsaDerivationPoolFillLiveSessionStepInput = {
  presignSessionId: string;
  record: RouterAbEcdsaDerivationPoolFillSessionRecord;
  requestedStage: 'triples' | 'presign';
  outgoingMessagesB64u: string[];
  thresholdExpiresAtMs: number;
};

export interface RouterAbEcdsaDerivationPoolFillLiveSessionOwner {
  createSession(
    input: RouterAbEcdsaDerivationPoolFillLiveSessionCreateInput,
  ): Promise<
    RouterAbEcdsaDerivationPoolFillParseResult<RouterAbEcdsaDerivationPoolFillLiveSessionCreateValue>
  >;
  stepSession(
    input: RouterAbEcdsaDerivationPoolFillLiveSessionStepInput,
  ): Promise<
    RouterAbEcdsaDerivationPoolFillParseResult<RouterAbEcdsaDerivationPoolFillPreparedStep>
  >;
  deleteSession(presignSessionId: string): Promise<void>;
}

type LiveSessionEntry = {
  session: ThresholdEcdsaPresignSession;
  record: RouterAbEcdsaDerivationPoolFillSessionRecord;
};

export function normalizeWasmPresignStage(
  rawStage: string,
): 'triples' | 'triples_done' | 'presign' | 'done' {
  if (rawStage === 'triples_done') return 'triples_done';
  if (rawStage === 'presign') return 'presign';
  if (rawStage === 'done') return 'done';
  return 'triples';
}

export function pollWasmPresignSession(
  session: ThresholdEcdsaPresignSession,
): RouterAbEcdsaDerivationPoolFillWasmPoll {
  const polled = session.poll() as { stage?: string; outgoing?: Uint8Array[]; event?: string };
  const outgoingMessages = Array.isArray(polled?.outgoing) ? polled.outgoing : [];
  return {
    stage: normalizeWasmPresignStage(String(polled?.stage || session.stage() || 'triples')),
    event:
      polled?.event === 'triples_done' || polled?.event === 'presign_done' ? polled.event : 'none',
    outgoingMessagesB64u: outgoingMessages.map((msg) => base64UrlEncode(msg)),
  };
}

export function freePresignSession(session: ThresholdEcdsaPresignSession): void {
  try {
    session.free();
  } catch {
    // Best-effort cleanup only.
  }
}

export function takePresignatureFromSession(
  session: ThresholdEcdsaPresignSession,
): RouterAbEcdsaDerivationPoolFillParseResult<RouterAbEcdsaDerivationPresignatureMaterial> {
  const presig97 = session.take_presignature_97();
  if (presig97.length !== 97) {
    return {
      ok: false,
      code: 'internal',
      message: `Invalid presignature bytes (expected 97, got ${presig97.length})`,
    };
  }
  const bigR33 = presig97.slice(0, 33);
  const kShare32 = presig97.slice(33, 65);
  const sigmaShare32 = presig97.slice(65, 97);
  return {
    ok: true,
    value: {
      presignatureId: computePresignatureIdFromBigRBytes(bigR33),
      bigRB64u: base64UrlEncode(bigR33),
      kShareB64u: base64UrlEncode(kShare32),
      sigmaShareB64u: base64UrlEncode(sigmaShare32),
    },
  };
}

export class InMemoryRouterAbEcdsaDerivationPoolFillLiveSessionOwner implements RouterAbEcdsaDerivationPoolFillLiveSessionOwner {
  private readonly livePresignSessionById = new Map<string, LiveSessionEntry>();
  private readonly presignSessionStepInFlight = new Set<string>();

  async createSession(
    input: RouterAbEcdsaDerivationPoolFillLiveSessionCreateInput,
  ): Promise<
    RouterAbEcdsaDerivationPoolFillParseResult<RouterAbEcdsaDerivationPoolFillLiveSessionCreateValue>
  > {
    await ensureRouterAbEcdsaSigningWorkerWasm();
    const created = createLiveSessionEntry(input);
    if (!created.ok) return created;
    this.deleteEntry(input.presignSessionId);
    this.livePresignSessionById.set(input.presignSessionId, {
      session: created.value.session,
      record: created.value.record,
    });
    return {
      ok: true,
      value: {
        record: created.value.record,
        stage: created.value.stage,
        outgoingMessagesB64u: created.value.outgoingMessagesB64u,
      },
    };
  }

  async stepSession(
    input: RouterAbEcdsaDerivationPoolFillLiveSessionStepInput,
  ): Promise<
    RouterAbEcdsaDerivationPoolFillParseResult<RouterAbEcdsaDerivationPoolFillPreparedStep>
  > {
    if (this.presignSessionStepInFlight.has(input.presignSessionId)) {
      return {
        ok: false,
        code: 'stale_session_state',
        message: 'Presign session step already in progress; retry step',
      };
    }
    this.presignSessionStepInFlight.add(input.presignSessionId);
    try {
      const entry = this.resolveLiveEntry(input.presignSessionId, input.record);
      if (!entry.ok) return entry;
      const prepared = preparePoolFillLiveStep({
        session: entry.value.session,
        record: input.record,
        requestedStage: input.requestedStage,
        outgoingMessagesB64u: input.outgoingMessagesB64u,
        thresholdExpiresAtMs: input.thresholdExpiresAtMs,
      });
      if (prepared.ok && prepared.value.mode === 'advance') {
        entry.value.record = prepared.value.nextRecord;
      }
      return prepared;
    } finally {
      this.presignSessionStepInFlight.delete(input.presignSessionId);
    }
  }

  async deleteSession(presignSessionId: string): Promise<void> {
    this.deleteEntry(presignSessionId);
  }

  private deleteEntry(presignSessionId: string): void {
    const existing = this.livePresignSessionById.get(presignSessionId);
    if (!existing) return;
    this.livePresignSessionById.delete(presignSessionId);
    freePresignSession(existing.session);
  }

  private resolveLiveEntry(
    presignSessionId: string,
    record: RouterAbEcdsaDerivationPoolFillSessionRecord,
  ): RouterAbEcdsaDerivationPoolFillParseResult<LiveSessionEntry> {
    const existing = this.livePresignSessionById.get(presignSessionId);
    if (!existing) {
      return staleLiveSession('cache_miss');
    }
    if (Date.now() > existing.record.expiresAtMs) {
      this.deleteEntry(presignSessionId);
      return staleLiveSession('cache_expired');
    }
    if (existing.record.version !== record.version) {
      return staleLiveSession('cache_version_mismatch');
    }
    if (existing.record.stage !== record.stage) {
      return staleLiveSession('cache_stage_mismatch');
    }
    return { ok: true, value: existing };
  }
}

export function createLiveSessionEntry(
  input: RouterAbEcdsaDerivationPoolFillLiveSessionCreateInput,
):
  | {
      ok: true;
      value: LiveSessionEntry & RouterAbEcdsaDerivationPoolFillLiveSessionCreateValue;
    }
  | RouterAbEcdsaDerivationPoolFillParseErr {
  const relayerThresholdShare32 = decodeFixedB64u(input.relayerThresholdShare32B64u, 32);
  if (!relayerThresholdShare32.ok) return relayerThresholdShare32;
  const groupPublicKey33 = decodeFixedB64u(input.groupPublicKey33B64u, 33);
  if (!groupPublicKey33.ok) return groupPublicKey33;
  const session = new ThresholdEcdsaPresignSession(
    new Uint32Array(input.participantIds),
    input.relayerParticipantId,
    2,
    relayerThresholdShare32.value,
    groupPublicKey33.value,
  );
  const polled = pollWasmPresignSession(session);
  const record = {
    ...input.record,
    stage: polled.stage,
  };
  return {
    ok: true,
    value: {
      session,
      record,
      stage: polled.stage,
      outgoingMessagesB64u: polled.outgoingMessagesB64u,
    },
  };
}

export function preparePoolFillLiveStep(input: {
  session: ThresholdEcdsaPresignSession;
  record: RouterAbEcdsaDerivationPoolFillSessionRecord;
  requestedStage: 'triples' | 'presign';
  outgoingMessagesB64u: string[];
  thresholdExpiresAtMs: number;
}): RouterAbEcdsaDerivationPoolFillParseResult<RouterAbEcdsaDerivationPoolFillPreparedStep> {
  const currentStage = normalizeWasmPresignStage(input.session.stage());
  if (currentStage !== input.record.stage) {
    return {
      ok: false,
      code: 'internal',
      message: 'presign session stage mismatch',
    };
  }

  if (currentStage === 'done') {
    const terminal = takePresignatureFromSession(input.session);
    if (!terminal.ok) return terminal;
    return { ok: true, value: { mode: 'terminal', presignDone: terminal.value } };
  }

  if (currentStage === 'triples_done' && input.requestedStage === 'triples') {
    return {
      ok: true,
      value: {
        mode: 'immediate',
        response: {
          ok: true,
          stage: 'triples_done',
          event: 'triples_done',
          outgoingMessagesB64u: [],
        },
      },
    };
  }

  if (input.requestedStage === 'presign' && currentStage === 'triples_done') {
    try {
      input.session.start_presign();
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'server is not ready for presign',
      };
    }
  } else if (input.requestedStage === 'presign' && currentStage === 'triples') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'server is not ready for presign (triples still running)',
    };
  } else if (input.requestedStage === 'triples' && currentStage !== 'triples') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'stage regression is not allowed',
    };
  }

  const decodedIncoming = decodePresignIncomingMessages(input.outgoingMessagesB64u);
  if (!decodedIncoming.ok) return decodedIncoming;

  for (const decoded of decodedIncoming.value) {
    try {
      input.session.message(input.record.clientParticipantId, decoded);
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Protocol rejected message: ${safeErrorMessage(e) || 'error'}`,
      };
    }
  }

  let polled: RouterAbEcdsaDerivationPoolFillWasmPoll;
  try {
    polled = pollWasmPresignSession(input.session);
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `Protocol failed: ${safeErrorMessage(error) || 'error'}`,
    };
  }
  const nextExpiresAtMs = Math.min(input.record.expiresAtMs, input.thresholdExpiresAtMs);
  const nextRecord: RouterAbEcdsaDerivationPoolFillSessionRecord = {
    ...input.record,
    stage: polled.stage,
    version: input.record.version + 1,
    expiresAtMs: nextExpiresAtMs,
    updatedAtMs: Date.now(),
  };

  let presignDone: RouterAbEcdsaDerivationPresignatureMaterial | null = null;
  if (polled.event === 'presign_done') {
    const done = takePresignatureFromSession(input.session);
    if (!done.ok) return done;
    presignDone = done.value;
  }

  return {
    ok: true,
    value: {
      mode: 'advance',
      polled,
      nextRecord,
      presignDone,
    },
  };
}

function computePresignatureIdFromBigRBytes(bigR33: Uint8Array): string {
  const digest = sha256BytesSync(bigR33);
  return `presig-${base64UrlEncode(digest)}`;
}

function decodeFixedB64u(
  value: string,
  expectedLength: number,
): RouterAbEcdsaDerivationPoolFillParseResult<Uint8Array> {
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(value);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'pool-fill live-session material must be valid base64url',
    };
  }
  if (decoded.length !== expectedLength) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `pool-fill live-session material must decode to ${expectedLength} bytes`,
    };
  }
  return { ok: true, value: decoded };
}

function decodePresignIncomingMessages(
  outgoingMessagesB64u: string[],
): RouterAbEcdsaDerivationPoolFillParseResult<Uint8Array[]> {
  const decoded: Uint8Array[] = [];
  for (const msgB64u of outgoingMessagesB64u) {
    try {
      decoded.push(base64UrlDecode(msgB64u));
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'outgoingMessagesB64u contains invalid base64url',
      };
    }
  }
  return { ok: true, value: decoded };
}

function staleLiveSession(reason: string): RouterAbEcdsaDerivationPoolFillParseErr {
  return {
    ok: false,
    code: 'stale_session_state',
    message: `Router A/B ECDSA derivation pool-fill live session unavailable (${reason})`,
  };
}
