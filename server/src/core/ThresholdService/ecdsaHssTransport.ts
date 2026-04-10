import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { sha256BytesUtf8 } from '@shared/utils/digests';

export type ThresholdEcdsaHssHiddenEvalClientRequestEnvelope = {
  v: 1;
  kind: 'threshold_ecdsa_hss_hidden_eval_client_request_v1';
  ceremonyId: string;
  preparedServerSessionB64u: string;
  serverAssistInitB64u: string;
  clientEvalRequestB64u: string;
};

export type ThresholdEcdsaHssHiddenEvalServerResponseEnvelope = {
  v: 1;
  kind: 'threshold_ecdsa_hss_hidden_eval_server_response_v1';
  ceremonyId: string;
  requestDigestB64u: string;
  serverEvalResponseB64u: string;
};

export type ThresholdEcdsaHssHiddenEvalFinalizeEnvelope = {
  v: 1;
  kind: 'threshold_ecdsa_hss_hidden_eval_client_finalize_v1';
  ceremonyId: string;
  requestDigestB64u: string;
  responseDigestB64u: string;
  clientEvalFinalizeB64u: string;
};

export function createOpaqueBase64Envelope(value: unknown): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

export function parseOpaqueBase64Envelope(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(base64UrlDecode(value)));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

export async function computeThresholdEcdsaHssRequestDigestB64u(
  requestMessageB64u: string,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(requestMessageB64u));
}

export function parseThresholdEcdsaHssHiddenEvalClientRequestEnvelope(
  requestMessageB64u: string,
): ThresholdEcdsaHssHiddenEvalClientRequestEnvelope | null {
  const parsed = parseOpaqueBase64Envelope(requestMessageB64u);
  if (!parsed) return null;
  const v = Number(parsed.v);
  const kind = String(parsed.kind || '').trim();
  const ceremonyId = String(parsed.ceremonyId || '').trim();
  const preparedServerSessionB64u = String(parsed.preparedServerSessionB64u || '').trim();
  const serverAssistInitB64u = String(parsed.serverAssistInitB64u || '').trim();
  const clientEvalRequestB64u = String(parsed.clientEvalRequestB64u || '').trim();
  if (
    v !== 1 ||
    kind !== 'threshold_ecdsa_hss_hidden_eval_client_request_v1' ||
    !ceremonyId ||
    !preparedServerSessionB64u ||
    !serverAssistInitB64u ||
    !clientEvalRequestB64u
  ) {
    return null;
  }
  return {
    v: 1,
    kind,
    ceremonyId,
    preparedServerSessionB64u,
    serverAssistInitB64u,
    clientEvalRequestB64u,
  };
}

export function parseThresholdEcdsaHssHiddenEvalServerResponseEnvelope(
  responseMessageB64u: string,
): ThresholdEcdsaHssHiddenEvalServerResponseEnvelope | null {
  const parsed = parseOpaqueBase64Envelope(responseMessageB64u);
  if (!parsed) return null;
  const v = Number(parsed.v);
  const kind = String(parsed.kind || '').trim();
  const ceremonyId = String(parsed.ceremonyId || '').trim();
  const requestDigestB64u = String(parsed.requestDigestB64u || '').trim();
  const serverEvalResponseB64u = String(parsed.serverEvalResponseB64u || '').trim();
  if (
    v !== 1 ||
    kind !== 'threshold_ecdsa_hss_hidden_eval_server_response_v1' ||
    !ceremonyId ||
    !requestDigestB64u ||
    !serverEvalResponseB64u
  ) {
    return null;
  }
  return {
    v: 1,
    kind,
    ceremonyId,
    requestDigestB64u,
    serverEvalResponseB64u,
  };
}

export function parseThresholdEcdsaHssHiddenEvalFinalizeEnvelope(
  finalizeMessageB64u: string,
): ThresholdEcdsaHssHiddenEvalFinalizeEnvelope | null {
  const parsed = parseOpaqueBase64Envelope(finalizeMessageB64u);
  if (!parsed) return null;
  const v = Number(parsed.v);
  const kind = String(parsed.kind || '').trim();
  const ceremonyId = String(parsed.ceremonyId || '').trim();
  const requestDigestB64u = String(parsed.requestDigestB64u || '').trim();
  const responseDigestB64u = String(parsed.responseDigestB64u || '').trim();
  const clientEvalFinalizeB64u = String(parsed.clientEvalFinalizeB64u || '').trim();
  if (
    v !== 1 ||
    kind !== 'threshold_ecdsa_hss_hidden_eval_client_finalize_v1' ||
    !ceremonyId ||
    !requestDigestB64u ||
    !responseDigestB64u ||
    !clientEvalFinalizeB64u
  ) {
    return null;
  }
  return {
    v: 1,
    kind,
    ceremonyId,
    requestDigestB64u,
    responseDigestB64u,
    clientEvalFinalizeB64u,
  };
}
