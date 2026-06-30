import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { ensureEthSignerWasm, sha256BytesSync } from '../ethSignerWasm';
import type { RouterAbEcdsaHssPoolFillSessionRecord } from '../stores/EcdsaSigningStore';
import { ThresholdEcdsaPresignSession } from '../../../../../../wasm/eth_signer/pkg/eth_signer.js';

export type RouterAbEcdsaHssPoolFillParseOk<T> = { ok: true; value: T };
export type RouterAbEcdsaHssPoolFillParseErr = { ok: false; code: string; message: string };
export type RouterAbEcdsaHssPoolFillParseResult<T> =
  | RouterAbEcdsaHssPoolFillParseOk<T>
  | RouterAbEcdsaHssPoolFillParseErr;

export type RouterAbEcdsaHssPoolFillWasmPoll = {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoingMessagesB64u: string[];
};

export type RouterAbEcdsaHssPresignatureMaterial = {
  presignatureId: string;
  bigRB64u: string;
  kShareB64u: string;
  sigmaShareB64u: string;
};

export type RouterAbEcdsaHssPoolFillPreparedStep =
  | {
      mode: 'terminal';
      presignDone: RouterAbEcdsaHssPresignatureMaterial;
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
      polled: RouterAbEcdsaHssPoolFillWasmPoll;
      nextRecord: RouterAbEcdsaHssPoolFillSessionRecord;
      presignDone: RouterAbEcdsaHssPresignatureMaterial | null;
    };

export type RouterAbEcdsaHssPoolFillLiveSessionCreateInput = {
  presignSessionId: string;
  record: RouterAbEcdsaHssPoolFillSessionRecord;
  participantIds: number[];
  relayerParticipantId: number;
  relayerThresholdShare32B64u: string;
  groupPublicKey33B64u: string;
};

export type RouterAbEcdsaHssPoolFillLiveSessionCreateValue = {
  record: RouterAbEcdsaHssPoolFillSessionRecord;
  stage: RouterAbEcdsaHssPoolFillWasmPoll['stage'];
  outgoingMessagesB64u: string[];
};

export type RouterAbEcdsaHssPoolFillLiveSessionStepInput = {
  presignSessionId: string;
  record: RouterAbEcdsaHssPoolFillSessionRecord;
  requestedStage: 'triples' | 'presign';
  outgoingMessagesB64u: string[];
  thresholdExpiresAtMs: number;
};

export interface RouterAbEcdsaHssPoolFillLiveSessionOwner {
  createSession(
    input: RouterAbEcdsaHssPoolFillLiveSessionCreateInput,
  ): Promise<
    RouterAbEcdsaHssPoolFillParseResult<RouterAbEcdsaHssPoolFillLiveSessionCreateValue>
  >;
  stepSession(
    input: RouterAbEcdsaHssPoolFillLiveSessionStepInput,
  ): Promise<RouterAbEcdsaHssPoolFillParseResult<RouterAbEcdsaHssPoolFillPreparedStep>>;
  deleteSession(presignSessionId: string): Promise<void>;
}

type LiveSessionEntry = {
  session: ThresholdEcdsaPresignSession;
  record: RouterAbEcdsaHssPoolFillSessionRecord;
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
): RouterAbEcdsaHssPoolFillWasmPoll {
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
): RouterAbEcdsaHssPoolFillParseResult<RouterAbEcdsaHssPresignatureMaterial> {
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

export class InMemoryRouterAbEcdsaHssPoolFillLiveSessionOwner
  implements RouterAbEcdsaHssPoolFillLiveSessionOwner
{
  private readonly livePresignSessionById = new Map<string, LiveSessionEntry>();
  private readonly presignSessionStepInFlight = new Set<string>();

  async createSession(
    input: RouterAbEcdsaHssPoolFillLiveSessionCreateInput,
  ): Promise<
    RouterAbEcdsaHssPoolFillParseResult<RouterAbEcdsaHssPoolFillLiveSessionCreateValue>
  > {
    await ensureEthSignerWasm();
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
    input: RouterAbEcdsaHssPoolFillLiveSessionStepInput,
  ): Promise<RouterAbEcdsaHssPoolFillParseResult<RouterAbEcdsaHssPoolFillPreparedStep>> {
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
    record: RouterAbEcdsaHssPoolFillSessionRecord,
  ): RouterAbEcdsaHssPoolFillParseResult<LiveSessionEntry> {
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

export function createLiveSessionEntry(input: RouterAbEcdsaHssPoolFillLiveSessionCreateInput):
  | {
      ok: true;
      value: LiveSessionEntry & RouterAbEcdsaHssPoolFillLiveSessionCreateValue;
    }
  | RouterAbEcdsaHssPoolFillParseErr {
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
  record: RouterAbEcdsaHssPoolFillSessionRecord;
  requestedStage: 'triples' | 'presign';
  outgoingMessagesB64u: string[];
  thresholdExpiresAtMs: number;
}): RouterAbEcdsaHssPoolFillParseResult<RouterAbEcdsaHssPoolFillPreparedStep> {
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
        message: `Protocol rejected message: ${String(e || 'error')}`,
      };
    }
  }

  const polled = pollWasmPresignSession(input.session);
  const nextExpiresAtMs = Math.min(input.record.expiresAtMs, input.thresholdExpiresAtMs);
  const nextRecord: RouterAbEcdsaHssPoolFillSessionRecord = {
    ...input.record,
    stage: polled.stage,
    version: input.record.version + 1,
    expiresAtMs: nextExpiresAtMs,
    updatedAtMs: Date.now(),
  };

  let presignDone: RouterAbEcdsaHssPresignatureMaterial | null = null;
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
): RouterAbEcdsaHssPoolFillParseResult<Uint8Array> {
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
): RouterAbEcdsaHssPoolFillParseResult<Uint8Array[]> {
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

function staleLiveSession(reason: string): RouterAbEcdsaHssPoolFillParseErr {
  return {
    ok: false,
    code: 'stale_session_state',
    message: `Router A/B ECDSA-HSS pool-fill live session unavailable (${reason})`,
  };
}
