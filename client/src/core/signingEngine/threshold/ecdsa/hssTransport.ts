import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { sha256BytesUtf8 } from '@shared/utils/digests';

export type ThresholdEcdsaHssHiddenEvalClientRequestEnvelopeV1 = {
  v: 1;
  kind: 'threshold_ecdsa_hss_hidden_eval_client_request_v1';
  ceremonyId: string;
  preparedServerSessionB64u: string;
  serverAssistInitB64u: string;
  clientEvalRequestB64u: string;
};

export type ThresholdEcdsaHssHiddenEvalServerResponseEnvelopeV1 = {
  v: 1;
  kind: 'threshold_ecdsa_hss_hidden_eval_server_response_v1';
  ceremonyId: string;
  requestDigestB64u: string;
  serverEvalResponseB64u: string;
};

export type ThresholdEcdsaHssHiddenEvalFinalizeEnvelopeV1 = {
  v: 1;
  kind: 'threshold_ecdsa_hss_hidden_eval_client_finalize_v1';
  ceremonyId: string;
  requestDigestB64u: string;
  responseDigestB64u: string;
  clientEvalFinalizeB64u: string;
};

function encodeOpaqueBase64Envelope(value: unknown): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

function parseOpaqueBase64Envelope(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(base64UrlDecode(value)));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function encodeThresholdEcdsaHssHiddenEvalRequestMessage(args: {
  ceremonyId: string;
  preparedServerSessionB64u: string;
  serverAssistInitB64u: string;
  clientEvalRequestB64u: string;
}): string {
  const envelope: ThresholdEcdsaHssHiddenEvalClientRequestEnvelopeV1 = {
    v: 1,
    kind: 'threshold_ecdsa_hss_hidden_eval_client_request_v1',
    ceremonyId: args.ceremonyId,
    preparedServerSessionB64u: args.preparedServerSessionB64u,
    serverAssistInitB64u: args.serverAssistInitB64u,
    clientEvalRequestB64u: args.clientEvalRequestB64u,
  };
  return encodeOpaqueBase64Envelope(envelope);
}

export function parseThresholdEcdsaHssHiddenEvalServerResponseMessage(
  responseMessageB64u: string,
): ThresholdEcdsaHssHiddenEvalServerResponseEnvelopeV1 | null {
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

export async function createThresholdEcdsaHssHiddenEvalFinalizeMessage(args: {
  ceremonyId: string;
  requestMessageB64u: string;
  responseMessageB64u: string;
  clientEvalFinalizeB64u: string;
}): Promise<string> {
  const responseEnvelope = parseThresholdEcdsaHssHiddenEvalServerResponseMessage(
    args.responseMessageB64u,
  );
  if (!responseEnvelope) {
    throw new Error(
      'Threshold ECDSA HSS hidden-eval respond response did not contain a valid server response envelope',
    );
  }
  if (responseEnvelope.ceremonyId !== String(args.ceremonyId || '').trim()) {
    throw new Error(
      'Threshold ECDSA HSS hidden-eval server response envelope ceremonyId did not match the active ceremony',
    );
  }
  const requestDigestB64u = base64UrlEncode(await sha256BytesUtf8(args.requestMessageB64u));
  if (responseEnvelope.requestDigestB64u !== requestDigestB64u) {
    throw new Error(
      'Threshold ECDSA HSS hidden-eval server response envelope was not bound to the active client request',
    );
  }
  const responseDigestB64u = base64UrlEncode(await sha256BytesUtf8(args.responseMessageB64u));
  const envelope: ThresholdEcdsaHssHiddenEvalFinalizeEnvelopeV1 = {
    v: 1,
    kind: 'threshold_ecdsa_hss_hidden_eval_client_finalize_v1',
    ceremonyId: args.ceremonyId,
    requestDigestB64u,
    responseDigestB64u,
    clientEvalFinalizeB64u: String(args.clientEvalFinalizeB64u || '').trim(),
  };
  if (!envelope.clientEvalFinalizeB64u) {
    throw new Error(
      'Threshold ECDSA HSS hidden-eval finalize requires clientEvalFinalizeB64u',
    );
  }
  return encodeOpaqueBase64Envelope(envelope);
}
