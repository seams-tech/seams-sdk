import {
  parseRouterAbEcdsaDerivationExplicitExportRequestV1,
  parseRouterAbEcdsaDerivationRecoveryRequestV1,
  parseRouterAbEcdsaDerivationActivationRefreshRequestV1,
  parseRouterAbEcdsaDerivationActivationRefreshForwardedResponseV1,
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  parseRouterAbEcdsaStrictForwardedRegistrationResponseV1,
  type RouterAbEcdsaDerivationActivationRefreshRequestV1,
  type RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1,
  type RouterAbEcdsaDerivationExplicitExportRequestV1,
  type RouterAbEcdsaDerivationRecoveryRequestV1,
  type RouterAbEcdsaDerivationSignerSetV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaRegistrationLifecycleV1,
  type RouterAbEcdsaRegistrationRecipientKeysV1,
  type RouterAbEcdsaRegistrationRequestFactsV1,
  type RouterAbEcdsaRegistrationRequestV1,
  type RouterAbEcdsaStrictForwardedRegistrationResponseV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';

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

export type RouterAbEcdsaStrictRegistrationAuthority = {
  readonly subjectId: string;
  readonly sessionId: string;
  readonly accountId: string;
  readonly expiresAtMs: number;
};

export type RouterAbEcdsaStrictRegistrationTopology = {
  readonly routerId: string;
  readonly signerSet: RouterAbEcdsaDerivationSignerSetV1;
  readonly deriverRecipientKeys: RouterAbEcdsaRegistrationRecipientKeysV1;
};

export interface RouterAbEcdsaStrictRegistrationPort {
  topology(): RouterAbEcdsaStrictRegistrationTopology;
  register(input: {
    readonly request: RouterAbEcdsaRegistrationRequestV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<RouterAbEcdsaStrictRegistrationResult>;
  activate(input: {
    readonly pendingActivation: RouterAbEcdsaPendingActivationV1;
    readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<RouterAbEcdsaStrictActivationResult>;
}

export type RouterAbEcdsaStrictPostRegistrationResult =
  | {
      readonly ok: true;
      readonly value: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
    }
  | RouterAbEcdsaStrictFailure;

export type RouterAbEcdsaStrictRefreshResult =
  | {
      readonly ok: true;
      readonly value: RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1;
    }
  | RouterAbEcdsaStrictFailure;

export interface RouterAbEcdsaStrictPostRegistrationPort {
  topology(): RouterAbEcdsaStrictRegistrationTopology;
  explicitExport(input: {
    readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<RouterAbEcdsaStrictPostRegistrationResult>;
  recover(input: {
    readonly request: RouterAbEcdsaDerivationRecoveryRequestV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<RouterAbEcdsaStrictPostRegistrationResult>;
  refresh(input: {
    readonly request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
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
const STRICT_ECDSA_RECOVERY_PATH = '/router-ab/ecdsa-derivation/recover';
const STRICT_ECDSA_REFRESH_PATH = '/router-ab/ecdsa-derivation/refresh';
const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';

class StrictRegistrationForwarder implements RouterAbEcdsaStrictRegistrationPort {
  constructor(private readonly config: StrictRegistrationForwarderConfig) {}

  topology(): RouterAbEcdsaStrictRegistrationTopology {
    return this.config.topology;
  }

  async register(input: {
    readonly request: RouterAbEcdsaRegistrationRequestV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<RouterAbEcdsaStrictRegistrationResult> {
    const authorityFailure = validateRegistrationAuthorityBinding(input);
    if (authorityFailure) return authorityFailure;
    const body = await this.forward({
      kind: 'registration',
      path: STRICT_ECDSA_REGISTRATION_PATH,
      authority: input.authority,
      request: input.request,
    });
    if (!body.ok) return body;
    return parseStrictRegistrationForwardingResult(body.value);
  }

  async activate(input: {
    readonly pendingActivation: RouterAbEcdsaPendingActivationV1;
    readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<RouterAbEcdsaStrictActivationResult> {
    const body = await this.forward({
      kind: 'activation',
      path: STRICT_ECDSA_ACTIVATION_PATH,
      authority: input.authority,
      pendingActivation: input.pendingActivation,
      clientActivation: input.clientActivation,
    });
    if (!body.ok) return body;
    try {
      return {
        ok: true,
        value: parseRouterAbEcdsaRegistrationActivationReceiptV1(body.value),
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
    } & (
      | {
          readonly kind: 'registration';
          readonly request: RouterAbEcdsaRegistrationRequestV1;
        }
      | {
          readonly kind: 'activation';
          readonly pendingActivation: RouterAbEcdsaPendingActivationV1;
          readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
        }
    ),
  ): Promise<{ readonly ok: true; readonly value: unknown } | RouterAbEcdsaStrictFailure> {
    const token = await this.config.tokenIssuer.issue(
      ceremonyTokenClaimsForAuthority(input.authority, this.config.tokenScope),
    );
    const response = await this.config.router.fetch(
      new Request(`https://router.router-ab.internal${input.path}`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': JSON_CONTENT_TYPE,
        },
        body: strictForwardBodyJson(input),
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

class StrictPostRegistrationForwarder implements RouterAbEcdsaStrictPostRegistrationPort {
  constructor(private readonly config: StrictRegistrationForwarderConfig) {}

  topology(): RouterAbEcdsaStrictRegistrationTopology {
    return this.config.topology;
  }

  async explicitExport(input: {
    readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<RouterAbEcdsaStrictPostRegistrationResult> {
    return await this.forward({
      path: STRICT_ECDSA_EXPORT_PATH,
      request: parseRouterAbEcdsaDerivationExplicitExportRequestV1(input.request),
      authority: input.authority,
    });
  }

  async recover(input: {
    readonly request: RouterAbEcdsaDerivationRecoveryRequestV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<RouterAbEcdsaStrictPostRegistrationResult> {
    return await this.forward({
      path: STRICT_ECDSA_RECOVERY_PATH,
      request: parseRouterAbEcdsaDerivationRecoveryRequestV1(input.request),
      authority: input.authority,
    });
  }

  async refresh(input: {
    readonly request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<RouterAbEcdsaStrictRefreshResult> {
    const forwarded = await this.forwardRaw({
      path: STRICT_ECDSA_REFRESH_PATH,
      request: parseRouterAbEcdsaDerivationActivationRefreshRequestV1(input.request),
      authority: input.authority,
    });
    if (!forwarded.ok) return forwarded;
    try {
      return {
        ok: true,
        value: parseRouterAbEcdsaDerivationActivationRefreshForwardedResponseV1(forwarded.value),
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

  private async forward(input: {
    readonly path: string;
    readonly request:
      | RouterAbEcdsaDerivationExplicitExportRequestV1
      | RouterAbEcdsaDerivationRecoveryRequestV1
      | RouterAbEcdsaDerivationActivationRefreshRequestV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<RouterAbEcdsaStrictPostRegistrationResult> {
    const forwarded = await this.forwardRaw(input);
    if (!forwarded.ok) return forwarded;
    try {
      return {
        ok: true,
        value: parseRouterAbEcdsaStrictForwardedRegistrationResponseV1(forwarded.value),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'mpc_router_post_registration_response_invalid',
        message: errorMessage(
          error,
          'MPCRouter returned an invalid ECDSA post-registration response',
        ),
        retryable: false,
      };
    }
  }

  private async forwardRaw(input: {
    readonly path: string;
    readonly request:
      | RouterAbEcdsaDerivationExplicitExportRequestV1
      | RouterAbEcdsaDerivationRecoveryRequestV1
      | RouterAbEcdsaDerivationActivationRefreshRequestV1;
    readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
  }): Promise<{ readonly ok: true; readonly value: unknown } | RouterAbEcdsaStrictFailure> {
    const authorityFailure = validatePostRegistrationAuthorityBinding(input);
    if (authorityFailure) return authorityFailure;
    const token = await this.config.tokenIssuer.issue(
      ceremonyTokenClaimsForAuthority(input.authority, this.config.tokenScope),
    );
    const response = await this.config.router.fetch(
      new Request(`https://router.router-ab.internal${input.path}`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': JSON_CONTENT_TYPE,
        },
        body: JSON.stringify(input.request),
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

function strictForwardBodyJson(
  input:
    | {
        readonly kind: 'registration';
        readonly request: RouterAbEcdsaRegistrationRequestV1;
      }
    | {
        readonly kind: 'activation';
        readonly pendingActivation: RouterAbEcdsaPendingActivationV1;
        readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
      },
): string {
  switch (input.kind) {
    case 'registration':
      return JSON.stringify(input.request);
    case 'activation':
      return `{"pending":${input.pendingActivation.canonicalPayloadJson},"client_activation":${JSON.stringify(input.clientActivation)}}`;
    default:
      return assertNeverStrictForwardBody(input);
  }
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
    | RouterAbEcdsaDerivationRecoveryRequestV1
    | RouterAbEcdsaDerivationActivationRefreshRequestV1;
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
    input.request.registration_purpose === input.facts.registration_purpose &&
    input.request.context.application_binding_digest_b64u ===
      input.facts.context.application_binding_digest_b64u &&
    registrationLifecycleMatches(input.request.lifecycle, input.facts.lifecycle) &&
    signerSetMatches(input.request.signer_set, input.facts.signer_set) &&
    input.request.router_id === input.facts.router_id &&
    input.request.client_id === input.facts.client_id &&
    input.request.replay_nonce === input.facts.replay_nonce &&
    input.request.expires_at_ms === input.facts.expires_at_ms &&
    input.request.deriver_a_envelope.recipient_role ===
      input.facts.deriver_recipient_keys.deriver_a.role &&
    input.request.deriver_b_envelope.recipient_role ===
      input.facts.deriver_recipient_keys.deriver_b.role
  );
}

function registrationLifecycleMatches(
  left: RouterAbEcdsaRegistrationLifecycleV1,
  right: RouterAbEcdsaRegistrationLifecycleV1,
): boolean {
  return (
    left.lifecycle_id === right.lifecycle_id &&
    left.work_kind === right.work_kind &&
    left.primitive_request_kind === right.primitive_request_kind &&
    left.root_share_epoch === right.root_share_epoch &&
    left.account_id === right.account_id &&
    left.session_id === right.session_id &&
    left.signer_set_id === right.signer_set_id &&
    left.selected_server_id === right.selected_server_id
  );
}

function signerSetMatches(
  left: RouterAbEcdsaDerivationSignerSetV1,
  right: RouterAbEcdsaDerivationSignerSetV1,
): boolean {
  return (
    left.signer_set_id === right.signer_set_id &&
    left.policy === right.policy &&
    left.signer_a.role === right.signer_a.role &&
    left.signer_a.signer_id === right.signer_a.signer_id &&
    left.signer_a.key_epoch === right.signer_a.key_epoch &&
    left.signer_b.role === right.signer_b.role &&
    left.signer_b.signer_id === right.signer_b.signer_id &&
    left.signer_b.key_epoch === right.signer_b.key_epoch &&
    left.selected_server.server_id === right.selected_server.server_id &&
    left.selected_server.key_epoch === right.selected_server.key_epoch &&
    left.selected_server.recipient_encryption_key === right.selected_server.recipient_encryption_key
  );
}

class Ed25519CeremonyTokenIssuer implements RouterAbEcdsaCeremonyTokenIssuer {
  private signingKey: Promise<CryptoKey> | null = null;

  constructor(private readonly config: RouterAbEcdsaEd25519CeremonyTokenIssuerConfig) {
    validateCeremonyTokenIssuerConfig(config);
  }

  async issue(claims: RouterAbEcdsaCeremonyTokenClaims): Promise<string> {
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
