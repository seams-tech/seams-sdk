import { expect, test } from '@playwright/test';
import type { RouterAbEcdsaRegistrationRequestV1 } from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import {
  createRouterAbEcdsaStrictRegistrationPort,
  parseStoredRouterAbEcdsaPendingActivationV1,
} from '../../packages/wallet-server/src/router/domains/ecdsa/routerAbEcdsaStrictRegistration';
import { parseCorrelationId } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { parseRouterAbMpcMaterialActivationRef } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { createRouterAbTraceContextV1 } from '../../packages/shared-ts/src/utils/routerAbTraceContext';
import { fixtureRouterAbEcdsaActivationFacts } from '../helpers/routerAbSigningRuntimeTestUtils';

async function configurationFailureFetch(): Promise<Response> {
  return new Response(
    'InvalidLocalServiceConfig: router_project_policy.evaluate returned HTTP status 422',
    { status: 500 },
  );
}

class TraceCapturingRouter {
  request: Request | null = null;

  constructor(private readonly serverTiming: string | null = null) {}

  async fetch(input: RequestInfo | URL): Promise<Response> {
    this.request = new Request(input);
    const response = await configurationFailureFetch();
    if (!this.serverTiming) return response;
    const headers = new Headers(response.headers);
    headers.set('Server-Timing', this.serverTiming);
    return new Response(await response.clone().text(), {
      status: response.status,
      headers,
    });
  }
}

async function issueCeremonyToken(): Promise<string> {
  return 'ceremony-token';
}

async function issueRegistrationCeremonyToken(): Promise<string> {
  return 'registration-ceremony-token';
}

const REQUEST_POLICY = {
  policyVersion: 'wallet-registration-v1',
  requestDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
} as const;

function emptyJwks(): { readonly keys: readonly JsonWebKey[] } {
  return { keys: [] };
}

test('coordinator configuration failures are terminal registration failures', async () => {
  const request = strictRegistrationRequest();
  const port = createRouterAbEcdsaStrictRegistrationPort({
    router: {
      fetch: configurationFailureFetch,
    },
    tokenIssuer: {
      issue: issueCeremonyToken,
      issueRequest: issueCeremonyToken,
      issueRegistration: issueRegistrationCeremonyToken,
      publicJwks: emptyJwks,
    },
    tokenScope: {
      orgId: 'org_abcdefgh1234',
      projectId: 'local-smoke-project',
      environment: 'local',
    },
    topology: {
      routerId: request.router_id,
      signerSet: request.signer_set,
      deriverRecipientKeys: {
        deriver_a: {
          role: 'signer_a',
          key_epoch: 'epoch-1',
          public_key: 'deriver-a-public-key',
        },
        deriver_b: {
          role: 'signer_b',
          key_epoch: 'epoch-1',
          public_key: 'deriver-b-public-key',
        },
      },
    },
  });

  await expect(
    port.register({
      request,
      requestPolicy: REQUEST_POLICY,
      authority: {
        subjectId: request.client_id,
        sessionId: request.lifecycle.session_id,
        accountId: request.lifecycle.account_id,
        expiresAtMs: request.expires_at_ms,
      },
    }),
  ).resolves.toEqual({
    ok: false,
    code: 'invalid_local_service_config',
    message: 'InvalidLocalServiceConfig: router_project_policy.evaluate returned HTTP status 422',
    retryable: false,
  });
});

test('strict ECDSA registration forwards the opaque trace correlation header', async () => {
  const request = strictRegistrationRequest();
  const router = new TraceCapturingRouter();
  const port = createRouterAbEcdsaStrictRegistrationPort({
    router,
    tokenIssuer: {
      issue: issueCeremonyToken,
      issueRequest: issueCeremonyToken,
      issueRegistration: issueRegistrationCeremonyToken,
      publicJwks: emptyJwks,
    },
    tokenScope: {
      orgId: 'org_abcdefgh1234',
      projectId: 'local-smoke-project',
      environment: 'local',
    },
    topology: {
      routerId: request.router_id,
      signerSet: request.signer_set,
      deriverRecipientKeys: {
        deriver_a: {
          role: 'signer_a',
          key_epoch: 'epoch-1',
          public_key: 'deriver-a-public-key',
        },
        deriver_b: {
          role: 'signer_b',
          key_epoch: 'epoch-1',
          public_key: 'deriver-b-public-key',
        },
      },
    },
  });
  const traceContext = createRouterAbTraceContextV1();

  await port.register({
    request,
    requestPolicy: REQUEST_POLICY,
    authority: {
      subjectId: request.client_id,
      sessionId: request.lifecycle.session_id,
      accountId: request.lifecycle.account_id,
      expiresAtMs: request.expires_at_ms,
    },
    traceContext,
  });

  expect(router.request?.headers.get('x-seams-trace-id')).toBe(traceContext.value);
});

test('initial ECDSA registration forwards the server-resolved tenant-root selector', async () => {
  const request = strictRegistrationRequest();
  const router = new TraceCapturingRouter();
  const port = strictRegistrationPortForRequest({ request, router });
  const tenantRoot = {
    identityDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    custodyLineageB64u: 'AAAAAAAAAAAAAAAAAAAAAA',
  } as const;

  await port.registerInitialWithTenantRoot({
    request,
    tenantRoot,
    requestPolicy: REQUEST_POLICY,
    authority: {
      subjectId: request.client_id,
      sessionId: request.lifecycle.session_id,
      accountId: request.lifecycle.account_id,
      expiresAtMs: request.expires_at_ms,
    },
  });

  expect(await router.request?.json()).toEqual({
    registration_request: request,
    tenant_root: {
      identity_digest_b64u: tenantRoot.identityDigestB64u,
      custody_lineage_b64u: tenantRoot.custodyLineageB64u,
    },
  });
});

test('strict ECDSA activation forwards the exact Rust wire envelope', async () => {
  const request = strictRegistrationRequest();
  const router = new TraceCapturingRouter();
  const port = strictRegistrationPortForRequest({ request, router });
  const activationCorrelationId = parseCorrelationId(request.lifecycle.lifecycle_id);
  const materialActivation = parseRouterAbMpcMaterialActivationRef({
    kind: 'mpc_material_activation_ref',
    activation_id: 'activation-1',
    capability: 'ecdsa-signing-capability',
    material_owner: request.lifecycle.account_id,
    key_binding: 'key-binding-1',
    lifecycle_binding: request.lifecycle.lifecycle_id,
    signing_worker: request.lifecycle.selected_server_id,
  });

  await port.activate({
    activationCorrelationId,
    activationRequestDigestB64u: REQUEST_POLICY.requestDigestB64u,
    materialActivation,
    pendingActivation: parseStoredRouterAbEcdsaPendingActivationV1({
      kind: 'router_ab_ecdsa_pending_activation_v1',
      canonicalPayloadJson: '{"activation":{},"activation_context":{},"registration":{}}',
    }),
    clientActivation: fixtureRouterAbEcdsaActivationFacts(),
    requestPolicy: REQUEST_POLICY,
    authority: {
      subjectId: request.client_id,
      sessionId: request.lifecycle.session_id,
      accountId: request.lifecycle.account_id,
      expiresAtMs: request.expires_at_ms,
    },
  });

  expect(await router.request?.json()).toEqual({
    activation_correlation_id: activationCorrelationId,
    pending: {
      activation: {},
      activation_context: {},
      registration: {},
    },
    client_activation: fixtureRouterAbEcdsaActivationFacts(),
    material_activation: materialActivation,
  });
});

/* Refactor 94B Phase 0. Role diagnostics are presence-only: whether the leg
   returned Server-Timing is recorded, what it said is not. The value carries
   role and span names from inside the MPC topology, so it reaches the timing
   fold and nothing else. */
test('strict ECDSA registration reports header presence without its contents', async () => {
  const secret = 'router_internal_span;dur=42, deriver_a_internal;dur=7';
  for (const [serverTiming, expected] of [
    [secret, 'present'],
    [null, 'absent'],
  ] as const) {
    const request = strictRegistrationRequest();
    const router = new TraceCapturingRouter(serverTiming);
    const port = strictRegistrationPortForRequest({ request, router });
    const presences: { leg: string; serverTiming: 'present' | 'absent' }[] = [];
    const timingHeaders: string[] = [];

    await port.register({
      request,
      requestPolicy: REQUEST_POLICY,
      authority: {
        subjectId: request.client_id,
        sessionId: request.lifecycle.session_id,
        accountId: request.lifecycle.account_id,
        expiresAtMs: request.expires_at_ms,
      },
      onServerTiming: (header) => timingHeaders.push(header),
      onHeaderPresence: (presence) => presences.push({ ...presence }),
    });

    /* Absence is an observation too, so it is reported either way. */
    expect(presences).toHaveLength(1);
    expect(presences[0]?.serverTiming).toBe(expected);

    /* Nothing the presence sink saw may contain the header's contents. */
    const presenceJson = JSON.stringify(presences);
    for (const fragment of ['router_internal_span', 'deriver_a_internal', 'dur=', '42']) {
      expect(presenceJson).not.toContain(fragment);
    }

    /* The value goes only to the timing sink, which folds it to fixed names. */
    expect(timingHeaders).toEqual(serverTiming ? [secret] : []);
  }
});

function strictRegistrationPortForRequest(args: {
  request: RouterAbEcdsaRegistrationRequestV1;
  router: TraceCapturingRouter;
}) {
  return createRouterAbEcdsaStrictRegistrationPort({
    router: args.router,
    tokenIssuer: {
      issue: issueCeremonyToken,
      issueRequest: issueCeremonyToken,
      issueRegistration: issueRegistrationCeremonyToken,
      publicJwks: emptyJwks,
    },
    tokenScope: {
      orgId: 'org_abcdefgh1234',
      projectId: 'local-smoke-project',
      environment: 'local',
    },
    topology: {
      routerId: args.request.router_id,
      signerSet: args.request.signer_set,
      deriverRecipientKeys: {
        deriver_a: { role: 'signer_a', key_epoch: 'epoch-1', public_key: 'deriver-a-public-key' },
        deriver_b: { role: 'signer_b', key_epoch: 'epoch-1', public_key: 'deriver-b-public-key' },
      },
    },
  });
}

function strictRegistrationRequest(): RouterAbEcdsaRegistrationRequestV1 {
  const digest = { bytes: new Array<number>(32).fill(0) };
  return {
    registration_purpose: 'wallet_registration',
    context: { application_binding_digest_b64u: 'application-binding' },
    lifecycle: {
      lifecycle_id: 'wrc_terminal_failure',
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: 'root-share-epoch-1',
      account_id: 'frost-fjord-rgcmpa',
      session_id: 'threshold-session-1',
      signer_set_id: 'signer-set-v1',
      selected_server_id: 'signing-worker-1',
    },
    signer_set: {
      signer_set_id: 'signer-set-v1',
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'signer-a',
        key_epoch: 'epoch-1',
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'signer-b',
        key_epoch: 'epoch-1',
      },
      selected_server: {
        server_id: 'signing-worker-1',
        key_epoch: 'epoch-1',
        recipient_encryption_key: 'signing-worker-public-key',
      },
    },
    router_id: 'local-router',
    client_id: 'frost-fjord-rgcmpa',
    replay_nonce: 'registration-replay',
    expires_at_ms: Date.now() + 60_000,
    client_ephemeral_public_key: 'client-ephemeral-public-key',
    deriver_a_envelope: {
      recipient_role: 'signer_a',
      header_digest: digest,
      aad_digest: digest,
      ciphertext: { bytes: [1] },
    },
    deriver_b_envelope: {
      recipient_role: 'signer_b',
      header_digest: digest,
      aad_digest: digest,
      ciphertext: { bytes: [2] },
    },
  };
}
