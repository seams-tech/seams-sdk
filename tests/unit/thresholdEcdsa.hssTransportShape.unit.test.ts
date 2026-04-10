import { expect, test } from '@playwright/test';
import { base64UrlDecode } from '@shared/utils/base64';
import {
  createThresholdEcdsaHssHiddenEvalFinalizeMessage,
  encodeThresholdEcdsaHssHiddenEvalRequestMessage,
  parseThresholdEcdsaHssHiddenEvalServerResponseMessage,
} from '@/core/signingEngine/threshold/workflows/thresholdEcdsaHssTransport';
import {
  computeThresholdEcdsaHssRequestDigestB64u,
  createOpaqueBase64Envelope,
  parseThresholdEcdsaHssHiddenEvalClientRequestEnvelope,
  parseThresholdEcdsaHssHiddenEvalFinalizeEnvelope,
  parseThresholdEcdsaHssHiddenEvalServerResponseEnvelope,
} from '@server/core/ThresholdService/ecdsaHssTransport';

function parseClientOpaqueBase64Envelope(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(base64UrlDecode(value)));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

test.describe('threshold-ecdsa hss transport shape', () => {
  test('hidden-eval staged request shape roundtrips across client/server helpers', () => {
    const requestMessageB64u = encodeThresholdEcdsaHssHiddenEvalRequestMessage({
      ceremonyId: 'ceremony-2',
      preparedServerSessionB64u: 'prepared-hidden',
      serverAssistInitB64u: 'assist-hidden',
      clientEvalRequestB64u: 'client-eval-request',
    });

    const parsed = parseThresholdEcdsaHssHiddenEvalClientRequestEnvelope(requestMessageB64u);
    expect(parsed).toEqual({
      v: 1,
      kind: 'threshold_ecdsa_hss_hidden_eval_client_request_v1',
      ceremonyId: 'ceremony-2',
      preparedServerSessionB64u: 'prepared-hidden',
      serverAssistInitB64u: 'assist-hidden',
      clientEvalRequestB64u: 'client-eval-request',
    });
    expect(Object.keys(parseClientOpaqueBase64Envelope(requestMessageB64u) || {}).sort()).toEqual([
      'ceremonyId',
      'clientEvalRequestB64u',
      'kind',
      'preparedServerSessionB64u',
      'serverAssistInitB64u',
      'v',
    ]);
    expect(requestMessageB64u).not.toContain('yClient32LeB64u');
    expect(requestMessageB64u).not.toContain('clientRootShare32B64u');
  });

  test('hidden-eval finalize binding enforces request and response digests', async () => {
    const requestMessageB64u = encodeThresholdEcdsaHssHiddenEvalRequestMessage({
      ceremonyId: 'ceremony-4',
      preparedServerSessionB64u: 'prepared-hidden',
      serverAssistInitB64u: 'assist-hidden',
      clientEvalRequestB64u: 'client-eval-request',
    });
    const responseMessageB64u = createOpaqueBase64Envelope({
      v: 1,
      kind: 'threshold_ecdsa_hss_hidden_eval_server_response_v1',
      ceremonyId: 'ceremony-4',
      requestDigestB64u: await computeThresholdEcdsaHssRequestDigestB64u(requestMessageB64u),
      serverEvalResponseB64u: 'server-eval-response',
    });

    const parsedClient = parseThresholdEcdsaHssHiddenEvalServerResponseMessage(
      responseMessageB64u,
    );
    const parsedServer = parseThresholdEcdsaHssHiddenEvalServerResponseEnvelope(
      responseMessageB64u,
    );
    expect(parsedClient).toEqual(parsedServer);
    expect(Object.keys(parseClientOpaqueBase64Envelope(responseMessageB64u) || {}).sort()).toEqual([
      'ceremonyId',
      'kind',
      'requestDigestB64u',
      'serverEvalResponseB64u',
      'v',
    ]);
    expect(responseMessageB64u).not.toContain('yClient32LeB64u');
    expect(responseMessageB64u).not.toContain('clientRootShare32B64u');

    const finalizeMessageB64u = await createThresholdEcdsaHssHiddenEvalFinalizeMessage({
      ceremonyId: 'ceremony-4',
      requestMessageB64u,
      responseMessageB64u,
      clientEvalFinalizeB64u: 'client-eval-finalize',
    });
    const finalizeEnvelope = parseThresholdEcdsaHssHiddenEvalFinalizeEnvelope(
      finalizeMessageB64u,
    );
    expect(finalizeEnvelope?.kind).toBe('threshold_ecdsa_hss_hidden_eval_client_finalize_v1');
    expect(finalizeEnvelope?.ceremonyId).toBe('ceremony-4');
    expect(finalizeEnvelope?.requestDigestB64u).toBe(
      await computeThresholdEcdsaHssRequestDigestB64u(requestMessageB64u),
    );
    expect(finalizeEnvelope?.clientEvalFinalizeB64u).toBe('client-eval-finalize');
    expect(Object.keys(parseClientOpaqueBase64Envelope(finalizeMessageB64u) || {}).sort()).toEqual([
      'ceremonyId',
      'clientEvalFinalizeB64u',
      'kind',
      'requestDigestB64u',
      'responseDigestB64u',
      'v',
    ]);
    expect(finalizeMessageB64u).not.toContain('yClient32LeB64u');
    expect(finalizeMessageB64u).not.toContain('clientRootShare32B64u');

    await expect(
      createThresholdEcdsaHssHiddenEvalFinalizeMessage({
        ceremonyId: 'ceremony-4',
        requestMessageB64u,
        responseMessageB64u: createOpaqueBase64Envelope({
          v: 1,
          kind: 'threshold_ecdsa_hss_hidden_eval_server_response_v1',
          ceremonyId: 'ceremony-4',
          requestDigestB64u: 'bad-digest',
          serverEvalResponseB64u: 'server-eval-response',
        }),
        clientEvalFinalizeB64u: 'client-eval-finalize',
      }),
    ).rejects.toThrow(/active client request/i);
  });

  test('server hidden-eval parsers reject removed cleartext staged envelopes', () => {
    const legacyCleartextRequest = createOpaqueBase64Envelope({
      v: 1,
      kind: 'threshold_ecdsa_hss_client_request_v1',
      ceremonyId: 'legacy',
      preparedServerSessionB64u: 'prepared',
      serverAssistInitB64u: 'assist',
      yClient32LeB64u: 'raw-client-root-share',
    });
    const legacyCleartextResponse = createOpaqueBase64Envelope({
      v: 1,
      kind: 'threshold_ecdsa_hss_server_response_v1',
      ceremonyId: 'legacy',
      requestDigestB64u: 'digest',
    });

    expect(parseThresholdEcdsaHssHiddenEvalClientRequestEnvelope(legacyCleartextRequest)).toBeNull();
    expect(parseThresholdEcdsaHssHiddenEvalServerResponseEnvelope(legacyCleartextResponse)).toBeNull();
  });
});
