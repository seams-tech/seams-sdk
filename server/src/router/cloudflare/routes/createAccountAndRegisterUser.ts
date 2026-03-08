import type {
  CreateAccountAndRegisterRequest,
  CreateAccountAndRegisterResult,
} from '../../../core/types';
import type { CloudflareRelayContext } from '../createCloudflareRouter';
import type { RelayApiKeyPrincipal } from '../../relay';
import { isObject, json, readJson } from '../http';
import { signThresholdSessionJwt } from '../../commonRouterUtils';
import {
  extractBearerCredential,
  extractRelayEnvironmentId,
  resolveSourceIpFromFetchHeaders,
} from '../../relayApiKeyAuth';
import { parseBootstrapToken } from '../../../console/bootstrapTokens';
import { computeRegistrationBootstrapRequestHashSha256 } from '@shared/utils/registrationBootstrapHash';

export async function handleCreateAccountAndRegisterUser(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/registration/bootstrap') return null;

  const body = await readJson(ctx.request);
  if (!isObject(body)) {
    return json({ code: 'invalid_body', message: 'JSON body required' }, { status: 400 });
  }

  const new_account_id = typeof body.new_account_id === 'string' ? body.new_account_id : '';
  const new_public_key =
    typeof body.new_public_key === 'string' ? String(body.new_public_key || '').trim() : '';
  const device_number =
    typeof (body as Record<string, unknown>).device_number === 'number'
      ? (body as Record<string, unknown>).device_number
      : Number((body as Record<string, unknown>).device_number);
  const threshold_ed25519 = isObject((body as Record<string, unknown>).threshold_ed25519)
    ? (body as Record<string, unknown>).threshold_ed25519
    : undefined;
  const threshold_ecdsa = isObject((body as Record<string, unknown>).threshold_ecdsa)
    ? (body as Record<string, unknown>).threshold_ecdsa
    : undefined;
  const rp_id =
    typeof (body as Record<string, unknown>).rp_id === 'string'
      ? String((body as Record<string, unknown>).rp_id || '').trim()
      : '';
  const webauthn_registration = isObject(body.webauthn_registration)
    ? body.webauthn_registration
    : null;
  const authenticator_options = isObject((body as Record<string, unknown>).authenticator_options)
    ? (body as Record<string, unknown>).authenticator_options
    : undefined;

  if (!new_account_id) {
    return json(
      { code: 'invalid_body', message: 'Missing or invalid new_account_id' },
      { status: 400 },
    );
  }
  if (!rp_id) {
    return json({ code: 'invalid_body', message: 'Missing or invalid rp_id' }, { status: 400 });
  }
  if (!webauthn_registration) {
    return json(
      { code: 'invalid_body', message: 'Missing or invalid webauthn_registration' },
      { status: 400 },
    );
  }

  let apiKeyPrincipal: RelayApiKeyPrincipal | null = null;
  const apiKeyAuth = ctx.opts.apiKeyAuth;
  const bootstrapTokenStore = ctx.opts.bootstrapTokenStore;
  const credential = extractBearerCredential(ctx.request.headers);
  const tokenCandidate = credential ? parseBootstrapToken(credential) : null;
  if (apiKeyAuth || bootstrapTokenStore) {
    if (!credential) {
      const code = bootstrapTokenStore && !apiKeyAuth ? 'bootstrap_token_missing' : 'secret_key_missing';
      const message = bootstrapTokenStore && !apiKeyAuth ? 'Missing bootstrap token' : 'Missing secret key';
      return json({ success: false, code, error: message }, { status: 401 });
    }

    if (tokenCandidate) {
      if (!bootstrapTokenStore) {
        return json(
          { success: false, code: 'bootstrap_token_invalid', error: 'Invalid bootstrap token' },
          { status: 401 },
        );
      }
      const requestHashSha256 = await computeRegistrationBootstrapRequestHashSha256(body);
      const redeemResult = await bootstrapTokenStore.redeemToken({
        token: credential,
        origin: ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || '',
        method: 'POST',
        path: '/registration/bootstrap',
        requestHashSha256,
      });
      if (!redeemResult.ok) {
        return json(
          {
            success: false,
            code: redeemResult.code,
            error: redeemResult.message,
          },
          { status: redeemResult.status },
        );
      }
      apiKeyPrincipal = {
        apiKeyId: redeemResult.record.publishableKeyId,
        orgId: redeemResult.record.orgId,
        environmentId: redeemResult.record.environmentId,
        scopes: ['accounts.create'],
      };
    } else {
      if (!apiKeyAuth) {
        return json(
          { success: false, code: 'secret_key_invalid', error: 'Invalid secret key' },
          { status: 401 },
        );
      }
      const environmentId = extractRelayEnvironmentId(ctx.request.headers);
      const sourceIp = resolveSourceIpFromFetchHeaders(ctx.request.headers);
      const authResult = await apiKeyAuth.authenticate({
        secret: credential,
        endpoint: 'POST /registration/bootstrap',
        requiredScopes: ['accounts.create'],
        ...(sourceIp ? { sourceIp } : {}),
        ...(environmentId ? { environmentId } : {}),
      });
      if (!authResult.ok) {
        return json(
          {
            success: false,
            code: authResult.code,
            error: authResult.message,
          },
          { status: authResult.status },
        );
      }
      apiKeyPrincipal = authResult.principal;
    }
  }

  const input = {
    new_account_id,
    ...(new_public_key ? { new_public_key } : {}),
    device_number,
    ...(threshold_ed25519 ? { threshold_ed25519 } : {}),
    ...(threshold_ecdsa ? { threshold_ecdsa } : {}),
    rp_id,
    webauthn_registration,
    expected_origin:
      ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || undefined,
    authenticator_options,
  } as unknown as CreateAccountAndRegisterRequest;

  const result = await ctx.service.createAccountAndRegisterUser(input);
  const response: CreateAccountAndRegisterResult = result;

  if (ctx.opts.apiKeyUsageMeter && apiKeyPrincipal) {
    try {
      await ctx.opts.apiKeyUsageMeter.recordEvent({
        orgId: apiKeyPrincipal.orgId,
        environmentId: apiKeyPrincipal.environmentId,
        apiKeyId: apiKeyPrincipal.apiKeyId,
        endpoint: 'POST /registration/bootstrap',
        walletId: new_account_id,
        action: 'wallet_created',
        succeeded: Boolean(response.success),
        occurredAt: new Date().toISOString(),
        sourceEventId: `registration_bootstrap:${apiKeyPrincipal.apiKeyId}:${new_account_id}`,
      });
    } catch (error: unknown) {
      ctx.logger.warn('[relay][api-key] usage meter event failed', {
        endpoint: 'POST /registration/bootstrap',
        orgId: apiKeyPrincipal.orgId,
        environmentId: apiKeyPrincipal.environmentId,
        apiKeyId: apiKeyPrincipal.apiKeyId,
        walletId: new_account_id,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  if (!response.success) return json(response, { status: 400 });

  const session = ctx.opts.session;
  if (!session) return json(response, { status: 200 });

  if (response.thresholdEd25519?.session) {
    const signed = await signThresholdSessionJwt({
      session,
      kind: 'threshold_ed25519_session_v1',
      userId: new_account_id,
      rpId: rp_id,
      relayerKeyId: response.thresholdEd25519.relayerKeyId,
      sessionInfo: response.thresholdEd25519.session,
      fallbackParticipantIds: response.thresholdEd25519.participantIds,
      requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
      invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
    });
    if (!signed.ok) {
      return json({ success: false, error: signed.message }, { status: signed.status });
    }
    response.thresholdEd25519.session.jwt = signed.jwt;
  }

  if (response.thresholdEcdsa?.session) {
    const signed = await signThresholdSessionJwt({
      session,
      kind: 'threshold_ecdsa_session_v1',
      userId: new_account_id,
      rpId: rp_id,
      relayerKeyId: response.thresholdEcdsa.relayerKeyId,
      sessionInfo: response.thresholdEcdsa.session,
      fallbackParticipantIds: response.thresholdEcdsa.participantIds,
      requireJwtErrorMessage: 'threshold_ecdsa.session_kind must be jwt',
      invalidPayloadErrorMessage: 'invalid thresholdEcdsa session payload for jwt signing',
    });
    if (!signed.ok) {
      return json({ success: false, error: signed.message }, { status: signed.status });
    }
    response.thresholdEcdsa.session.jwt = signed.jwt;
  }

  return json(response, { status: 200 });
}
