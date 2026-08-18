import {
  parseRouterAbEcdsaDerivationActivationCommitQueryResultV1,
  parseRouterAbEcdsaDerivationActivationPrepareResultV1,
  parseRouterAbEcdsaDerivationExplicitExportRequestV1,
  projectRouterAbEcdsaDerivationExplicitExportRequestToProtocolV1,
  parseRouterAbEcdsaExplicitExportProtocolForwardedResponseV1,
  parseRouterAbEcdsaDerivationActivationRefreshCommitRequestV1,
  parseRouterAbEcdsaDerivationActivationRefreshResponseV1,
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  parseRouterAbEcdsaStrictForwardedRegistrationResponseV1,
  type RouterAbEcdsaDerivationActivationCommitQueryResultV1,
  type RouterAbEcdsaDerivationActivationPrepareResultV1,
  type RouterAbEcdsaDerivationActivationRefreshCommitRequestV1,
  type RouterAbEcdsaDerivationActivationRefreshRequestV1,
  type RouterAbEcdsaDerivationActivationRefreshResponseV1,
  type RouterAbEcdsaDerivationExplicitExportRequestV1,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbEcdsaExplicitExportForwardedResponseV1,
  type RouterAbEcdsaDerivationSignerSetV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaRegistrationRecipientKeysV1,
  type RouterAbEcdsaRegistrationRequestFactsV1,
  type RouterAbEcdsaRegistrationRequestV1,
  type RouterAbEcdsaStrictForwardedRegistrationResponseV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
  type RouterAbPublicDigest32V1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbNormalSigningAuthorizationWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { CorrelationId } from '@shared/utils/canonicalPrimitives';
import {
  ROUTER_AB_TRACE_ID_HEADER_V1,
  type RouterAbTraceContextV1,
} from '@shared/utils/routerAbTraceContext';

type JsonObject = Record<string, unknown>;
declare const routerAbEcdsaPendingActivationJsonBrand: unique symbol;

type RouterAbEcdsaPendingActivationJsonV1 = string & {
  readonly [routerAbEcdsaPendingActivationJsonBrand]: true;
};

type RouterAbEcdsaStrictFailure = {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
  readonly retryable: boolean;
};

export type RouterAbEcdsaPendingActivationV1 = {
  readonly kind: 'router_ab_ecdsa_pending_activation_v1';
  readonly canonicalPayloadJson: RouterAbEcdsaPendingActivationJsonV1;
};

export type RouterAbEcdsaStrictRegistrationResult =
  | {
      readonly ok: true;
      readonly value: {
        readonly publicResponse: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
        readonly pendingActivation: RouterAbEcdsaPendingActivationV1;
      };
    }
  | RouterAbEcdsaStrictFailure;

export type RouterAbEcdsaStrictActivationResult =
  | {
      readonly ok: true;
      readonly value: RouterAbEcdsaRegistrationActivationReceiptV1;
    }
  | RouterAbEcdsaStrictFailure;

export type RouterAbEcdsaStrictActivationPrepareResult =
  | {
      readonly ok: true;
      readonly value: RouterAbEcdsaDerivationActivationPrepareResultV1;
    }
  | RouterAbEcdsaStrictFailure;

export type RouterAbEcdsaStrictActivationQueryResult =
  | {
      readonly ok: true;
      readonly value: RouterAbEcdsaDerivationActivationCommitQueryResultV1;
    }
  | RouterAbEcdsaStrictFailure;

export type RouterAbEcdsaStrictRegistrationAuthority = {
  readonly subjectId: string;
  readonly sessionId: string;
  readonly accountId: string;
  readonly expiresAtMs: number;
};

export type RouterAbEcdsaStrictExportAuthority = RouterAbEcdsaStrictRegistrationAuthority & {
  readonly keyHandle: string;
  // The Gateway-attested operation authority for this export. The router
  // cross-checks it against the request's own authorization branch.
  readonly authorization: RouterAbNormalSigningAuthorizationWire;
  // Server-private identity forwarded only to Router and SigningWorker.
  readonly privateAuthorization: RouterAbEcdsaStrictExportPrivateAuthorization;
  readonly normalSigningScope: RouterAbEcdsaDerivationNormalSigningScopeV1;
};

export type RouterAbEcdsaStrictExportPrivateAuthorization =
  | {
      readonly kind: 'reusable_wallet_session';
      readonly walletSessionId: string;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly evidenceSetDigest: string;
    };

export type RouterAbEcdsaStrictRegistrationTopology = {
  readonly routerId: string;
  readonly signerSet: RouterAbEcdsaDerivationSignerSetV1;
  readonly deriverRecipientKeys: RouterAbEcdsaRegistrationRecipientKeysV1;
};

export type RouterAbEcdsaRegistrationRequestPolicyV1 = {
  readonly policyVersion: string;
  readonly requestDigestB64u: string;
};

type RouterAbRequestPolicyClaimsInputV1 = {
  readonly policyVersion: string;
  readonly workKind: 'registration_prepare' | 'key_export' | 'server_share_refresh';
  readonly requestDigest: { readonly bytes: readonly number[] };
};

/**
 * Receives the Router's raw `Server-Timing` header, when it sent one
 * (Refactor 94B Phase 0). Diagnostics only: the Router's spans never reach the
 * response body, and a caller that omits this sink changes nothing about the
 * ceremony. Called at most once per forwarded request, before the result is
 * parsed, so a failing leg still reports where its time went.
 */
export type RouterAbEcdsaStrictServerTimingSink = (header: string) => void;

/**
 * Refactor 94B Phase 0. Reports whether a role leg returned the diagnostics
 * header we expect, and nothing about what it contained.
 *
 * `Server-Timing` carries role and span names from inside the MPC topology.
 * A missing header and an empty one are different failures — the first means
 * the leg never emitted diagnostics, the second that it emitted nothing
 * measurable — so presence is worth recording. The value is not: it is
 * attacker-influencable in principle and identifying in practice, so it is
 * never passed here.
 */
export type RouterAbEcdsaStrictHeaderPresenceSink = (presence: {
  readonly leg: string;
  readonly serverTiming: 'present' | 'absent';
}) => void;

export interface RouterAbEcdsaStrictRegistrationPort {
  topology(): RouterAbEcdsaStrictRegistrationTopology;
  register(input: {
    readonly request: RouterAbEcdsaRegistrationRequestV1;
    readonly requestPolicy: RouterAbEcdsaRegistrationRequestPolicyV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
    readonly traceContext?: RouterAbTraceContextV1;
    readonly onServerTiming?: RouterAbEcdsaStrictServerTimingSink;
    readonly onHeaderPresence?: RouterAbEcdsaStrictHeaderPresenceSink;
  }): Promise<RouterAbEcdsaStrictRegistrationResult>;
  activate(input: {
    readonly activationCorrelationId: CorrelationId;
    readonly activationRequestDigestB64u: string;
    readonly pendingActivation: RouterAbEcdsaPendingActivationV1;
    readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
    readonly requestPolicy: RouterAbEcdsaRegistrationRequestPolicyV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
    readonly traceContext?: RouterAbTraceContextV1;
    readonly onServerTiming?: RouterAbEcdsaStrictServerTimingSink;
    readonly onHeaderPresence?: RouterAbEcdsaStrictHeaderPresenceSink;
  }): Promise<RouterAbEcdsaStrictActivationResult>;
}

export type RouterAbEcdsaStrictExportResult =
  | {
      readonly ok: true;
      readonly value: RouterAbEcdsaExplicitExportForwardedResponseV1;
    }
  | RouterAbEcdsaStrictFailure;

export type RouterAbEcdsaStrictRefreshResult =
  | {
      readonly ok: true;
      readonly value: RouterAbEcdsaDerivationActivationRefreshResponseV1;
    }
  | RouterAbEcdsaStrictFailure;

export interface RouterAbEcdsaStrictPostRegistrationPort {
  topology(): RouterAbEcdsaStrictRegistrationTopology;
  explicitExport(input: {
    readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
    readonly requestDigestB64u: string;
    readonly authority: RouterAbEcdsaStrictExportAuthority;
  }): Promise<RouterAbEcdsaStrictExportResult>;
  refresh(input: {
    readonly request: RouterAbEcdsaDerivationActivationRefreshCommitRequestV1;
    readonly requestDigestB64u: string;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<RouterAbEcdsaStrictRefreshResult>;
}

export type RouterAbEcdsaCeremonyTokenClaims = {
  readonly subjectId: string;
  readonly sessionId: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly environment: string;
  readonly accountId: string;
  readonly expiresAtMs: number;
};

export type RouterAbEcdsaEd25519CeremonyTokenIssuerConfig = {
  readonly issuer: string;
  readonly audience: string;
  readonly keyId: string;
  readonly privateJwk: RouterAbEcdsaEd25519PrivateJwk;
};

export type RouterAbEcdsaEd25519PrivateJwk = JsonWebKey & {
  readonly kty: 'OKP';
  readonly crv: 'Ed25519';
  readonly x: string;
  readonly d: string;
};

export interface RouterAbEcdsaCeremonyTokenIssuer {
  issue(claims: RouterAbEcdsaCeremonyTokenClaims): Promise<string>;
  issueRequest(
    claims: RouterAbEcdsaCeremonyTokenClaims,
    requestPolicy: RouterAbRequestPolicyClaimsInputV1,
  ): Promise<string>;
  publicJwks(): { readonly keys: readonly JsonWebKey[] };
}

type StrictRegistrationForwarderConfig = {
  readonly router: {
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  };
  readonly tokenIssuer: RouterAbEcdsaCeremonyTokenIssuer;
  readonly tokenScope: {
    readonly orgId: string;
    readonly projectId: string;
    readonly environment: string;
  };
  readonly topology: RouterAbEcdsaStrictRegistrationTopology;
};

const STRICT_ECDSA_REGISTRATION_PATH = '/router-ab/ecdsa-derivation/register';
const STRICT_ECDSA_ACTIVATION_PATH = '/router-ab/ecdsa-derivation/activate';
const STRICT_ECDSA_EXPORT_PATH = '/router-ab/ecdsa-derivation/export';
const STRICT_ECDSA_REFRESH_PATH = '/router-ab/ecdsa-derivation/refresh';
const STRICT_ECDSA_POST_REGISTRATION_POLICY_VERSION =
  'router-ab-ecdsa-post-registration-request-policy-v1';
const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';

class StrictRegistrationForwarder implements RouterAbEcdsaStrictRegistrationPort {
  constructor(private readonly config: StrictRegistrationForwarderConfig) {}

  topology(): RouterAbEcdsaStrictRegistrationTopology {
    return this.config.topology;
  }

  async register(input: {
    readonly request: RouterAbEcdsaRegistrationRequestV1;
    readonly requestPolicy: RouterAbEcdsaRegistrationRequestPolicyV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
    readonly traceContext?: RouterAbTraceContextV1;
    readonly onServerTiming?: RouterAbEcdsaStrictServerTimingSink;
    readonly onHeaderPresence?: RouterAbEcdsaStrictHeaderPresenceSink;
  }): Promise<RouterAbEcdsaStrictRegistrationResult> {
    const authorityFailure = validateRegistrationAuthorityBinding(input);
    if (authorityFailure) return authorityFailure;
    const body = await this.forward({
      kind: 'registration',
      path: STRICT_ECDSA_REGISTRATION_PATH,
      authority: input.authority,
      requestPolicy: input.requestPolicy,
      request: input.request,
      traceContext: input.traceContext,
      onServerTiming: input.onServerTiming,
      onHeaderPresence: input.onHeaderPresence,
    });
    if (!body.ok) return body;
    return parseStrictRegistrationForwardingResult(body.value);
  }

  async activate(input: {
    readonly activationCorrelationId: CorrelationId;
    readonly activationRequestDigestB64u: string;
    readonly pendingActivation: RouterAbEcdsaPendingActivationV1;
    readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
    readonly requestPolicy: RouterAbEcdsaRegistrationRequestPolicyV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
    readonly traceContext?: RouterAbTraceContextV1;
    readonly onServerTiming?: RouterAbEcdsaStrictServerTimingSink;
    readonly onHeaderPresence?: RouterAbEcdsaStrictHeaderPresenceSink;
  }): Promise<RouterAbEcdsaStrictActivationResult> {
    const body = await this.forward({
      kind: 'activation',
      path: STRICT_ECDSA_ACTIVATION_PATH,
      authority: input.authority,
      activationCorrelationId: input.activationCorrelationId,
      requestPolicy: input.requestPolicy,
      pendingActivation: input.pendingActivation,
      clientActivation: input.clientActivation,
      traceContext: input.traceContext,
      onServerTiming: input.onServerTiming,
      onHeaderPresence: input.onHeaderPresence,
    });
    if (!body.ok) return body;
    try {
      const rawReceipt = exactObject(body.value, [
        'ecdsa_activation',
        'lifecycle_id',
        'transcript_digest',
        'activated',
      ]);
      const rawActivation = objectValue(rawReceipt?.ecdsa_activation);
      const activationDigestB64u = nonEmptyString(rawActivation?.activation_digest_b64u);
      const requestDigestB64u = base64UrlString(input.activationRequestDigestB64u, 32);
      if (
        !rawReceipt ||
        rawReceipt.activated !== true ||
        !activationDigestB64u ||
        !requestDigestB64u
      ) {
        throw new Error('MPCRouter returned an incomplete ECDSA activation receipt');
      }
      const receipt = parseRouterAbEcdsaRegistrationActivationReceiptV1({
        activation_correlation_id: input.activationCorrelationId,
        activation_request_digest: { bytes: Array.from(decodeBase64Url(requestDigestB64u)) },
        server_generation: `ecdsa-server-generation-v1:${activationDigestB64u}`,
        ecdsa_activation: rawReceipt.ecdsa_activation,
        lifecycle_id: rawReceipt.lifecycle_id,
        transcript_digest: rawReceipt.transcript_digest,
      });
      if (receipt.activation_correlation_id !== input.activationCorrelationId) {
        throw new Error('MPCRouter activation receipt changed the journal correlation');
      }
      return {
        ok: true,
        value: receipt,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'mpc_router_activation_response_invalid',
        message: errorMessage(error, 'MPCRouter returned an invalid ECDSA activation receipt'),
        retryable: false,
      };
    }
  }

  private async forward(
    input: {
      readonly path: string;
      readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
      readonly requestPolicy: RouterAbEcdsaRegistrationRequestPolicyV1;
      readonly traceContext?: RouterAbTraceContextV1;
      readonly onServerTiming?: RouterAbEcdsaStrictServerTimingSink;
      readonly onHeaderPresence?: RouterAbEcdsaStrictHeaderPresenceSink;
    } & (
      | {
          readonly kind: 'registration';
          readonly request: RouterAbEcdsaRegistrationRequestV1;
        }
      | {
          readonly kind: 'activation';
          readonly activationCorrelationId: CorrelationId;
          readonly pendingActivation: RouterAbEcdsaPendingActivationV1;
          readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
        }
    ),
  ): Promise<{ readonly ok: true; readonly value: unknown } | RouterAbEcdsaStrictFailure> {
    const requestPolicy = parseRegistrationRequestPolicy(input.requestPolicy);
    if (!requestPolicy) {
      return {
        ok: false,
        code: 'strict_registration_request_policy_invalid',
        message: 'Strict ECDSA registration request policy is invalid',
        retryable: false,
      };
    }
    const token = await this.config.tokenIssuer.issueRequest(
      ceremonyTokenClaimsForAuthority(input.authority, this.config.tokenScope),
      requestPolicy,
    );
    const headers: Record<string, string> = {
      authorization: `Bearer ${token}`,
      'content-type': JSON_CONTENT_TYPE,
    };
    if (input.traceContext) {
      headers[ROUTER_AB_TRACE_ID_HEADER_V1] = input.traceContext.value;
    }
    const response = await this.config.router.fetch(
      new Request(`https://router.router-ab.internal${input.path}`, {
        method: 'POST',
        headers,
        body: strictForwardBodyJson(input),
      }),
    );
    /* Read before the outcome branch so a failed leg still reports its spans,
       and never let a diagnostics sink fail the ceremony. */
    try {
      const header = response.headers.get('Server-Timing');
      /* Presence is recorded for every leg, including the ones that returned
         nothing — an absent header is the observation worth having. The value
         only ever reaches the timing sink, which folds it into fixed metric
         names; it is never logged. */
      input.onHeaderPresence?.({
        leg: input.path,
        serverTiming: header ? 'present' : 'absent',
      });
      if (header) input.onServerTiming?.(header);
    } catch {
      /* Diagnostics only; never fail the ceremony. */
    }
    const body = await readJsonResponse(response);
    if (!response.ok) {
      const code = responseErrorCode(body, response.status);
      return {
        ok: false,
        code,
        message: responseErrorMessage(body, response.status),
        retryable: responseFailureIsRetryable(response.status, code),
      };
    }
    return { ok: true, value: body };
  }
}

class StrictPostRegistrationForwarder implements RouterAbEcdsaStrictPostRegistrationPort {
  constructor(private readonly config: StrictRegistrationForwarderConfig) {}

  topology(): RouterAbEcdsaStrictRegistrationTopology {
    return this.config.topology;
  }

  async explicitExport(input: {
    readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
    readonly requestDigestB64u: string;
    readonly authority: RouterAbEcdsaStrictExportAuthority;
  }): Promise<RouterAbEcdsaStrictExportResult> {
    const forwarded = await this.forwardRaw({
      kind: 'explicit_export',
      path: STRICT_ECDSA_EXPORT_PATH,
      request: parseRouterAbEcdsaDerivationExplicitExportRequestV1(input.request),
      requestDigestB64u: input.requestDigestB64u,
      authority: input.authority,
    });
    if (!forwarded.ok) return forwarded;
    try {
      return {
        ok: true,
        value: parseRouterAbEcdsaExplicitExportProtocolForwardedResponseV1(forwarded.value),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'mpc_router_export_response_invalid',
        message: errorMessage(error, 'MPCRouter returned an invalid ECDSA export response'),
        retryable: false,
      };
    }
  }

  async refresh(input: {
    readonly request: RouterAbEcdsaDerivationActivationRefreshCommitRequestV1;
    readonly requestDigestB64u: string;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<RouterAbEcdsaStrictRefreshResult> {
    const command = parseRouterAbEcdsaDerivationActivationRefreshCommitRequestV1(input.request);
    const forwarded = await this.forwardRaw({
      kind: 'post_registration_proof',
      path: STRICT_ECDSA_REFRESH_PATH,
      request: command.refresh_request,
      requestDigestB64u: input.requestDigestB64u,
      workKind: 'server_share_refresh',
      authority: input.authority,
    });
    if (!forwarded.ok) return forwarded;
    try {
      const response = parseRouterAbEcdsaDerivationActivationRefreshResponseV1(forwarded.value);
      if (
        response.result !== 'stopped' &&
        response.signing_worker_activation.activation_correlation_id !==
          command.activation_correlation_id
      ) {
        throw new Error('MPCRouter refresh receipt changed the journal correlation');
      }
      return {
        ok: true,
        value: response,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'mpc_router_refresh_response_invalid',
        message: errorMessage(error, 'MPCRouter returned an invalid ECDSA refresh response'),
        retryable: false,
      };
    }
  }

  private async forwardRaw(
    input:
      | {
          readonly kind: 'explicit_export';
          readonly path: string;
          readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
          readonly requestDigestB64u: string;
          readonly authority: RouterAbEcdsaStrictExportAuthority;
        }
      | {
          readonly kind: 'post_registration_proof';
          readonly path: string;
          readonly request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
          readonly requestDigestB64u: string;
          readonly workKind: 'server_share_refresh';
          readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
        },
  ): Promise<{ readonly ok: true; readonly value: unknown } | RouterAbEcdsaStrictFailure> {
    const authorityFailure = validatePostRegistrationAuthorityBinding(input);
    if (authorityFailure) return authorityFailure;
    /* Every post-registration call is request-bound: Router recomputes the
       digest from the forwarded request and rejects a policy that does not
       match it, so refresh carries its own policy exactly as export does. */
    const token = await this.config.tokenIssuer.issueRequest(
      ceremonyTokenClaimsForAuthority(input.authority, this.config.tokenScope),
      postRegistrationRequestPolicy(
        input.kind === 'explicit_export'
          ? { workKind: 'key_export', requestDigestB64u: input.requestDigestB64u }
          : { workKind: input.workKind, requestDigestB64u: input.requestDigestB64u },
      ),
    );
    const response = await this.config.router.fetch(
      new Request(`https://router.router-ab.internal${input.path}`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': JSON_CONTENT_TYPE,
        },
        body: strictPostRegistrationForwardBodyJson(input),
      }),
    );
    const body = await readJsonResponse(response);
    if (!response.ok) {
      const code = responseErrorCode(body, response.status);
      return {
        ok: false,
        code,
        message: responseErrorMessage(body, response.status),
        retryable: responseFailureIsRetryable(response.status, code),
      };
    }
    return { ok: true, value: body };
  }
}

function strictPostRegistrationForwardBodyJson(
  input:
    | {
        readonly kind: 'explicit_export';
        readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
        readonly authority: RouterAbEcdsaStrictExportAuthority;
      }
    | {
        readonly kind: 'post_registration_proof';
        readonly request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
        readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
      },
): string {
  switch (input.kind) {
    case 'explicit_export':
      return JSON.stringify({
        request: projectRouterAbEcdsaDerivationExplicitExportRequestToProtocolV1(input.request),
        export_authority: {
          key_handle: input.authority.keyHandle,
          authorization: input.authority.authorization,
          normal_signing_scope: input.authority.normalSigningScope,
        },
        private_authorization: privateExportAuthorizationWire(input.authority.privateAuthorization),
      });
    case 'post_registration_proof':
      return JSON.stringify(input.request);
  }
}

function privateExportAuthorizationWire(
  authorization: RouterAbEcdsaStrictExportPrivateAuthorization,
):
  | { readonly kind: 'reusable_wallet_session'; readonly wallet_session_id: string }
  | { readonly kind: 'operation_step_up'; readonly evidence_set_digest: string } {
  switch (authorization.kind) {
    case 'reusable_wallet_session':
      return {
        kind: 'reusable_wallet_session',
        wallet_session_id: authorization.walletSessionId,
      };
    case 'operation_step_up':
      return {
        kind: 'operation_step_up',
        evidence_set_digest: authorization.evidenceSetDigest,
      };
    default: {
      const exhaustive: never = authorization;
      throw new Error(`Unsupported private ECDSA export authorization: ${String(exhaustive)}`);
    }
  }
}

function strictForwardBodyJson(
  input:
    | {
        readonly kind: 'registration';
        readonly request: RouterAbEcdsaRegistrationRequestV1;
      }
    | {
        readonly kind: 'activation';
        readonly activationCorrelationId: CorrelationId;
        readonly pendingActivation: RouterAbEcdsaPendingActivationV1;
        readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
      },
): string {
  switch (input.kind) {
    case 'registration':
      return JSON.stringify(input.request);
    case 'activation':
      return `{"activation_correlation_id":${JSON.stringify(input.activationCorrelationId)},"pending":${input.pendingActivation.canonicalPayloadJson},"client_activation":${JSON.stringify(input.clientActivation)}}`;
    default:
      return assertNeverStrictForwardBody(input);
  }
}

function publicDigest32Matches(
  left: RouterAbPublicDigest32V1Wire,
  right: RouterAbPublicDigest32V1Wire,
): boolean {
  return (
    left.bytes.length === 32 &&
    right.bytes.length === 32 &&
    left.bytes.every((value, index) => value === right.bytes[index])
  );
}

function activationDigestMismatchFailure(): RouterAbEcdsaStrictFailure {
  return {
    ok: false,
    code: 'mpc_router_activation_digest_mismatch',
    message: 'ECDSA activation request digest does not match the prepared journal command',
    retryable: false,
  };
}

function assertNeverStrictForwardBody(value: never): never {
  throw new Error(`Unexpected strict ECDSA forwarding body: ${String(value)}`);
}

function canonicalPendingActivationJson(value: unknown): RouterAbEcdsaPendingActivationJsonV1 {
  const record = exactObject(value, ['registration', 'activation_context', 'activation']);
  if (!record) {
    throw new Error('MPCRouter pending activation has an invalid envelope');
  }
  return canonicalJson(value) as RouterAbEcdsaPendingActivationJsonV1;
}

export function parseStoredRouterAbEcdsaPendingActivationV1(
  value: unknown,
): RouterAbEcdsaPendingActivationV1 {
  const record = exactObject(value, ['kind', 'canonicalPayloadJson']);
  if (
    !record ||
    record.kind !== 'router_ab_ecdsa_pending_activation_v1' ||
    typeof record.canonicalPayloadJson !== 'string'
  ) {
    throw new Error('Stored MPCRouter ECDSA pending activation is invalid');
  }
  const parsed = JSON.parse(record.canonicalPayloadJson) as unknown;
  const canonicalPayloadJson = canonicalPendingActivationJson(parsed);
  if (canonicalPayloadJson !== record.canonicalPayloadJson) {
    throw new Error('Stored MPCRouter ECDSA pending activation is not canonical');
  }
  return {
    kind: 'router_ab_ecdsa_pending_activation_v1',
    canonicalPayloadJson,
  };
}

function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new Error('Canonical JSON rejects non-finite numbers');
      return JSON.stringify(value);
    case 'object':
      return canonicalJsonObjectOrArray(value);
    default:
      throw new Error('Canonical JSON contains an unsupported value');
  }
}

function canonicalJsonObjectOrArray(value: object): string {
  if (Array.isArray(value)) {
    const entries: string[] = [];
    for (const entry of value) entries.push(canonicalJson(entry));
    return `[${entries.join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const fields: string[] = [];
  for (const key of keys) {
    fields.push(`${JSON.stringify(key)}:${canonicalJson(record[key])}`);
  }
  return `{${fields.join(',')}}`;
}

function parseStrictRegistrationForwardingResult(
  raw: unknown,
): RouterAbEcdsaStrictRegistrationResult {
  const record = exactObject(raw, ['result', 'response', 'pending_activation']);
  const pendingActivationPayload = objectValue(record?.pending_activation);
  if (!record || record.result !== 'forwarded' || !pendingActivationPayload) {
    return {
      ok: false,
      code: 'mpc_router_registration_rejected',
      message: 'MPCRouter did not return one pending ECDSA registration activation',
      retryable: false,
    };
  }
  try {
    return {
      ok: true,
      value: {
        publicResponse: parseRouterAbEcdsaStrictForwardedRegistrationResponseV1({
          result: 'forwarded',
          response: record.response,
        }),
        pendingActivation: {
          kind: 'router_ab_ecdsa_pending_activation_v1',
          canonicalPayloadJson: canonicalPendingActivationJson(pendingActivationPayload),
        },
      },
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'mpc_router_response_invalid',
      message: errorMessage(error, 'MPCRouter returned an invalid ECDSA registration response'),
      retryable: false,
    };
  }
}

function ceremonyTokenClaimsForAuthority(
  authority: RouterAbEcdsaStrictRegistrationAuthority,
  scope: StrictRegistrationForwarderConfig['tokenScope'],
): RouterAbEcdsaCeremonyTokenClaims {
  return {
    subjectId: authority.subjectId,
    sessionId: authority.sessionId,
    orgId: scope.orgId,
    projectId: scope.projectId,
    environment: scope.environment,
    accountId: authority.accountId,
    expiresAtMs: authority.expiresAtMs,
  };
}

function parseRegistrationRequestPolicy(policy: RouterAbEcdsaRegistrationRequestPolicyV1): {
  readonly policyVersion: string;
  readonly workKind: 'registration_prepare';
  readonly requestDigest: { readonly bytes: readonly number[] };
} | null {
  const policyVersion = nonEmptyString(policy.policyVersion);
  const requestDigestB64u = base64UrlString(policy.requestDigestB64u, 32);
  if (!policyVersion || !requestDigestB64u) return null;
  return {
    policyVersion,
    workKind: 'registration_prepare',
    requestDigest: { bytes: Array.from(decodeBase64Url(requestDigestB64u)) },
  };
}

function postRegistrationRequestPolicy(input: {
  readonly workKind: 'key_export' | 'server_share_refresh';
  readonly requestDigestB64u: string;
}): RouterAbRequestPolicyClaimsInputV1 {
  const requestDigestB64u = base64UrlString(input.requestDigestB64u, 32);
  if (!requestDigestB64u) {
    throw new Error('Strict ECDSA post-registration request digest is invalid');
  }
  return {
    policyVersion: STRICT_ECDSA_POST_REGISTRATION_POLICY_VERSION,
    workKind: input.workKind,
    requestDigest: { bytes: Array.from(decodeBase64Url(requestDigestB64u)) },
  };
}

function validateRegistrationAuthorityBinding(input: {
  readonly request: RouterAbEcdsaRegistrationRequestV1;
  readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
}): RouterAbEcdsaStrictFailure | null {
  if (
    input.request.client_id !== input.authority.subjectId ||
    input.request.lifecycle.session_id !== input.authority.sessionId ||
    input.request.lifecycle.account_id !== input.authority.accountId ||
    input.request.expires_at_ms !== input.authority.expiresAtMs
  ) {
    return {
      ok: false,
      code: 'strict_registration_authority_mismatch',
      message: 'Strict ECDSA registration request is outside the admitted ceremony authority',
      retryable: false,
    };
  }
  return null;
}

function validatePostRegistrationAuthorityBinding(input: {
  readonly request:
    | RouterAbEcdsaDerivationExplicitExportRequestV1
    | RouterAbEcdsaDerivationActivationRefreshRequestV1;
  readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
}): RouterAbEcdsaStrictFailure | null {
  const request = input.request;
  if (
    request.client_id !== input.authority.subjectId ||
    request.lifecycle.session_id !== input.authority.sessionId ||
    request.lifecycle.account_id !== input.authority.accountId ||
    request.expires_at_ms !== input.authority.expiresAtMs
  ) {
    return {
      ok: false,
      code: 'strict_post_registration_authority_mismatch',
      message: 'Strict ECDSA post-registration request is outside the admitted authority',
      retryable: false,
    };
  }
  return null;
}

export function routerAbEcdsaStrictRegistrationRequestMatchesFacts(input: {
  readonly request: RouterAbEcdsaRegistrationRequestV1;
  readonly facts: RouterAbEcdsaRegistrationRequestFactsV1;
}): boolean {
  return (
    routerAbEcdsaStrictRegistrationRequestBindingJson(input.request) ===
    routerAbEcdsaStrictRegistrationFactsBindingJson(input.facts)
  );
}

export function routerAbEcdsaStrictRegistrationFactsBindingJson(
  facts: RouterAbEcdsaRegistrationRequestFactsV1,
): string {
  return canonicalJson({
    registration_purpose: facts.registration_purpose,
    context: facts.context,
    lifecycle: facts.lifecycle,
    signer_set: facts.signer_set,
    router_id: facts.router_id,
    client_id: facts.client_id,
    replay_nonce: facts.replay_nonce,
    expires_at_ms: facts.expires_at_ms,
    deriver_a_role: facts.deriver_recipient_keys.deriver_a.role,
    deriver_b_role: facts.deriver_recipient_keys.deriver_b.role,
  });
}

export function routerAbEcdsaStrictRegistrationRequestBindingJson(
  request: RouterAbEcdsaRegistrationRequestV1,
): string {
  return canonicalJson({
    registration_purpose: request.registration_purpose,
    context: request.context,
    lifecycle: request.lifecycle,
    signer_set: request.signer_set,
    router_id: request.router_id,
    client_id: request.client_id,
    replay_nonce: request.replay_nonce,
    expires_at_ms: request.expires_at_ms,
    deriver_a_role: request.deriver_a_envelope.recipient_role,
    deriver_b_role: request.deriver_b_envelope.recipient_role,
  });
}

class Ed25519CeremonyTokenIssuer implements RouterAbEcdsaCeremonyTokenIssuer {
  private signingKey: Promise<CryptoKey> | null = null;

  constructor(private readonly config: RouterAbEcdsaEd25519CeremonyTokenIssuerConfig) {
    validateCeremonyTokenIssuerConfig(config);
  }

  async issue(claims: RouterAbEcdsaCeremonyTokenClaims): Promise<string> {
    return await this.issueClaims(claims, null);
  }

  async issueRequest(
    claims: RouterAbEcdsaCeremonyTokenClaims,
    requestPolicy: RouterAbRequestPolicyClaimsInputV1,
  ): Promise<string> {
    return await this.issueClaims(claims, requestPolicy);
  }

  private async issueClaims(
    claims: RouterAbEcdsaCeremonyTokenClaims,
    requestPolicy: RouterAbRequestPolicyClaimsInputV1 | null,
  ): Promise<string> {
    validateCeremonyTokenClaims(claims);
    const nowSec = Math.floor(Date.now() / 1000);
    const header = encodeJsonBase64Url({
      alg: 'EdDSA',
      kid: this.config.keyId,
      typ: 'JWT',
    });
    const payload = encodeJsonBase64Url({
      iss: this.config.issuer,
      sub: claims.subjectId,
      aud: this.config.audience,
      iat: nowSec,
      nbf: nowSec,
      exp: Math.ceil(claims.expiresAtMs / 1000),
      sid: claims.sessionId,
      org_id: claims.orgId,
      project_id: claims.projectId,
      environment: claims.environment,
      account_id: claims.accountId,
      ...(requestPolicy ? { routerAbRequestPolicy: requestPolicy } : {}),
    });
    const signingInput = `${header}.${payload}`;
    const signature = await crypto.subtle.sign(
      { name: 'Ed25519' },
      await this.requireSigningKey(),
      new TextEncoder().encode(signingInput),
    );
    return `${signingInput}.${encodeBytesBase64Url(new Uint8Array(signature))}`;
  }

  publicJwks(): { readonly keys: readonly JsonWebKey[] } {
    const { crv, kty, x } = this.config.privateJwk;
    const publicKey: JsonWebKey & {
      readonly alg: 'EdDSA';
      readonly kid: string;
      readonly use: 'sig';
    } = {
      alg: 'EdDSA',
      crv,
      kid: this.config.keyId,
      kty,
      use: 'sig',
      x,
    };
    return {
      keys: [publicKey],
    };
  }

  private requireSigningKey(): Promise<CryptoKey> {
    if (!this.signingKey) {
      this.signingKey = crypto.subtle.importKey(
        'jwk',
        this.config.privateJwk,
        { name: 'Ed25519' },
        false,
        ['sign'],
      );
    }
    return this.signingKey;
  }
}

export function createRouterAbEcdsaStrictRegistrationPort(
  config: StrictRegistrationForwarderConfig,
): RouterAbEcdsaStrictRegistrationPort {
  return new StrictRegistrationForwarder(config);
}

export function createRouterAbEcdsaStrictPostRegistrationPort(
  config: StrictRegistrationForwarderConfig,
): RouterAbEcdsaStrictPostRegistrationPort {
  return new StrictPostRegistrationForwarder(config);
}

export function createRouterAbEcdsaEd25519CeremonyTokenIssuer(
  config: RouterAbEcdsaEd25519CeremonyTokenIssuerConfig,
): RouterAbEcdsaCeremonyTokenIssuer {
  return new Ed25519CeremonyTokenIssuer(config);
}

export function parseRouterAbEcdsaEd25519PrivateJwk(
  raw: unknown,
): RouterAbEcdsaEd25519PrivateJwk | null {
  const record = exactObject(raw, ['kty', 'crv', 'x', 'd']);
  const x = base64UrlString(record?.x, 32);
  const d = base64UrlString(record?.d, 32);
  if (!record || record.kty !== 'OKP' || record.crv !== 'Ed25519' || !x || !d) return null;
  return { kty: 'OKP', crv: 'Ed25519', x, d };
}

export function parseRouterAbEcdsaStrictRegistrationTopology(
  raw: unknown,
): RouterAbEcdsaStrictRegistrationTopology | null {
  const record = exactObject(raw, ['routerId', 'signerSet', 'deriverRecipientKeys']);
  const routerId = nonEmptyString(record?.routerId);
  const signerSet = parseSignerSet(record?.signerSet);
  const deriverRecipientKeys = parseDeriverRecipientKeys(record?.deriverRecipientKeys);
  if (!record || !routerId || !signerSet || !deriverRecipientKeys) return null;
  return { routerId, signerSet, deriverRecipientKeys };
}

function parseSignerSet(raw: unknown): RouterAbEcdsaDerivationSignerSetV1 | null {
  const record = exactObject(raw, [
    'signer_set_id',
    'policy',
    'signer_a',
    'signer_b',
    'selected_server',
  ]);
  const signerSetId = nonEmptyString(record?.signer_set_id);
  const signerA = parseSignerIdentity(record?.signer_a, 'signer_a');
  const signerB = parseSignerIdentity(record?.signer_b, 'signer_b');
  const selectedServer = parseServerIdentity(record?.selected_server);
  if (
    !record ||
    record.policy !== 'all_2' ||
    !signerSetId ||
    !signerA ||
    !signerB ||
    !selectedServer
  ) {
    return null;
  }
  return {
    signer_set_id: signerSetId,
    policy: 'all_2',
    signer_a: signerA,
    signer_b: signerB,
    selected_server: selectedServer,
  };
}

function parseSignerIdentity(
  raw: unknown,
  role: 'signer_a',
): RouterAbEcdsaDerivationSignerSetV1['signer_a'] | null;
function parseSignerIdentity(
  raw: unknown,
  role: 'signer_b',
): RouterAbEcdsaDerivationSignerSetV1['signer_b'] | null;
function parseSignerIdentity(
  raw: unknown,
  role: 'signer_a' | 'signer_b',
):
  | RouterAbEcdsaDerivationSignerSetV1['signer_a']
  | RouterAbEcdsaDerivationSignerSetV1['signer_b']
  | null {
  const record = exactObject(raw, ['role', 'signer_id', 'key_epoch']);
  const signerId = nonEmptyString(record?.signer_id);
  const keyEpoch = nonEmptyString(record?.key_epoch);
  if (!record || record.role !== role || !signerId || !keyEpoch) return null;
  switch (role) {
    case 'signer_a':
      return { role: 'signer_a', signer_id: signerId, key_epoch: keyEpoch };
    case 'signer_b':
      return { role: 'signer_b', signer_id: signerId, key_epoch: keyEpoch };
  }
}

function parseServerIdentity(
  raw: unknown,
): RouterAbEcdsaDerivationSignerSetV1['selected_server'] | null {
  const record = exactObject(raw, ['server_id', 'key_epoch', 'recipient_encryption_key']);
  const serverId = nonEmptyString(record?.server_id);
  const keyEpoch = nonEmptyString(record?.key_epoch);
  const recipientEncryptionKey = nonEmptyString(record?.recipient_encryption_key);
  if (!record || !serverId || !keyEpoch || !recipientEncryptionKey) return null;
  return {
    server_id: serverId,
    key_epoch: keyEpoch,
    recipient_encryption_key: recipientEncryptionKey,
  };
}

function parseDeriverRecipientKeys(raw: unknown): RouterAbEcdsaRegistrationRecipientKeysV1 | null {
  const record = exactObject(raw, ['deriver_a', 'deriver_b']);
  const deriverA = parseDeriverRecipientKey(record?.deriver_a, 'signer_a');
  const deriverB = parseDeriverRecipientKey(record?.deriver_b, 'signer_b');
  return record && deriverA && deriverB ? { deriver_a: deriverA, deriver_b: deriverB } : null;
}

function parseDeriverRecipientKey(
  raw: unknown,
  role: 'signer_a',
): RouterAbEcdsaRegistrationRecipientKeysV1['deriver_a'] | null;
function parseDeriverRecipientKey(
  raw: unknown,
  role: 'signer_b',
): RouterAbEcdsaRegistrationRecipientKeysV1['deriver_b'] | null;
function parseDeriverRecipientKey(
  raw: unknown,
  role: 'signer_a' | 'signer_b',
):
  | RouterAbEcdsaRegistrationRecipientKeysV1['deriver_a']
  | RouterAbEcdsaRegistrationRecipientKeysV1['deriver_b']
  | null {
  const record = exactObject(raw, ['role', 'key_epoch', 'public_key']);
  const keyEpoch = nonEmptyString(record?.key_epoch);
  const publicKey = nonEmptyString(record?.public_key);
  if (!record || record.role !== role || !keyEpoch || !publicKey) return null;
  switch (role) {
    case 'signer_a':
      return { role: 'signer_a', key_epoch: keyEpoch, public_key: publicKey };
    case 'signer_b':
      return { role: 'signer_b', key_epoch: keyEpoch, public_key: publicKey };
  }
}

function validateCeremonyTokenIssuerConfig(
  config: RouterAbEcdsaEd25519CeremonyTokenIssuerConfig,
): void {
  if (
    !nonEmptyString(config.issuer) ||
    !nonEmptyString(config.audience) ||
    !nonEmptyString(config.keyId) ||
    config.privateJwk.kty !== 'OKP' ||
    config.privateJwk.crv !== 'Ed25519' ||
    !base64UrlString(config.privateJwk.x, 32) ||
    !base64UrlString(config.privateJwk.d, 32)
  ) {
    throw new Error('Router A/B ECDSA ceremony token issuer requires an Ed25519 private JWK');
  }
}

function validateCeremonyTokenClaims(claims: RouterAbEcdsaCeremonyTokenClaims): void {
  if (
    !nonEmptyString(claims.subjectId) ||
    !nonEmptyString(claims.sessionId) ||
    !nonEmptyString(claims.orgId) ||
    !nonEmptyString(claims.projectId) ||
    !nonEmptyString(claims.environment) ||
    !nonEmptyString(claims.accountId) ||
    !Number.isSafeInteger(claims.expiresAtMs) ||
    claims.expiresAtMs <= Date.now()
  ) {
    throw new Error('Router A/B ECDSA ceremony token claims are invalid');
  }
}

function exactObject(raw: unknown, keys: readonly string[]): JsonObject | null {
  const record = objectValue(raw);
  if (!record) return null;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length) return null;
  for (let index = 0; index < expected.length; index += 1) {
    if (actual[index] !== expected[index]) return null;
  }
  return record;
}

function objectValue(raw: unknown): JsonObject | null {
  return typeof raw === 'object' && raw !== null && !Array.isArray(raw)
    ? (raw as JsonObject)
    : null;
}

function nonEmptyString(raw: unknown): string | null {
  const value = typeof raw === 'string' ? raw.trim() : '';
  return value || null;
}

function base64UrlString(raw: unknown, decodedLength: number): string | null {
  const value = nonEmptyString(raw);
  if (!value || !/^[A-Za-z0-9_-]+$/u.test(value)) return null;
  try {
    return decodeBase64Url(value).byteLength === decodedLength ? value : null;
  } catch {
    return null;
  }
}

function decodeBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) out[index] = binary.charCodeAt(index);
  return out;
}

function encodeJsonBase64Url(value: JsonObject): string {
  return encodeBytesBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

function encodeBytesBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

async function readJsonResponse(response: Response): Promise<unknown> {
  const body = await response.text();
  if (!body) return null;
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return body;
  }
}

function responseErrorCode(body: unknown, status: number): string {
  if (typeof body === 'string') {
    const protocolCode = protocolErrorCodeFromText(body);
    if (protocolCode) return protocolCode;
  }
  const record = objectValue(body);
  return nonEmptyString(record?.code) || `mpc_router_http_${status}`;
}

function protocolErrorCodeFromText(body: string): string | null {
  const separator = body.indexOf(':');
  if (separator <= 0) return null;
  switch (body.slice(0, separator)) {
    case 'InvalidLocalServiceConfig':
      return 'invalid_local_service_config';
    case 'MissingLocalBinding':
      return 'missing_local_binding';
    case 'ForbiddenLocalBinding':
      return 'forbidden_local_binding';
    default:
      return null;
  }
}

function responseFailureIsRetryable(status: number, code: string): boolean {
  if (status < 500) return false;
  switch (code) {
    case 'invalid_local_service_config':
    case 'missing_local_binding':
    case 'forbidden_local_binding':
      return false;
    default:
      return true;
  }
}

function responseErrorMessage(body: unknown, status: number): string {
  if (typeof body === 'string' && body.trim()) return body.trim();
  const record = objectValue(body);
  return nonEmptyString(record?.message) || `MPCRouter returned HTTP ${status}`;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}
