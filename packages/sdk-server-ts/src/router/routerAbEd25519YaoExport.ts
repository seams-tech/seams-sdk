import {
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  deriveRouterAbEd25519YaoExportAuthorizationDigestV1,
  deriveRouterAbEd25519YaoExportConfirmationDigestV1,
  deriveRouterAbEd25519YaoRuntimePolicyBindingV1,
  parseRouterAbEd25519YaoExportAdmissionReceiptV1,
  parseRouterAbEd25519YaoExportAdmissionRequestV1,
  parseRouterAbEd25519YaoExportExecuteRequestV1,
  parseRouterAbEd25519YaoExportResultV1,
  type RouterAbEd25519YaoExportAdmissionReceiptV1,
  type RouterAbEd25519YaoExportAdmissionRequestV1,
  type RouterAbEd25519YaoExportAuthorizationIdentityV1,
  type RouterAbEd25519YaoExportExecuteRequestV1,
  type RouterAbEd25519YaoExportResultV1,
} from '@shared/utils/routerAbEd25519Yao';
import type { AuthFactorIdentity, WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { base64UrlEncode } from '@shared/utils/encoders';
import { isPlainObject } from '@shared/utils/validation';
import type { WebAuthnAuthenticationCredential } from '../core/types';
import { normalizeCorsOrigin } from '../core/SessionService';
import {
  d1WebAuthnCredentialIdB64uFromCredential,
  parseD1WebAuthnAuthenticationCredential,
} from './cloudflare/d1WalletAuthMethodBoundary';
import type { RouterApiWebAuthnService } from './authServicePort';
import {
  parseRouterAbEd25519WalletSessionClaims,
  type RouterAbEd25519WalletSessionClaims,
} from '../core/ThresholdService/validation';
import { headersToRecord, json, readJson } from './cloudflare/http';
import { createRouterApiModule, type RouterApiModule } from './modules';
import { defineRoute } from './routeDefinitions';
import type { SessionAdapter } from './routerApi';
import type {
  RouterApiCloudflareRouteExtensionInput,
  RouterApiRouteExtension,
} from './routeExtensions';
import type {
  RouterAbEd25519YaoActiveCapabilityDescriptorV1,
  RouterAbEd25519YaoActiveCapabilityResolverV1,
} from './routerAbEd25519YaoRecovery';

const EXPORT_AUTH_MAX_TTL_MS = 60_000;
const EXPORT_AUTH_CLOCK_SKEW_MS = 30_000;

export type RouterAbEd25519YaoExportFailure = {
  readonly ok: false;
  readonly status: 400 | 404 | 408 | 409 | 429 | 500 | 502 | 503;
  readonly code:
    | 'invalid_backend_response'
    | 'admission_failed'
    | 'unknown_export'
    | 'binding_mismatch'
    | 'export_consumed'
    | 'execution_failed'
    | 'active_identity_mismatch';
  readonly message: string;
};

export type RouterAbEd25519YaoExportServiceResult<T> =
  | { readonly ok: true; readonly status: 200; readonly value: T }
  | RouterAbEd25519YaoExportFailure;

export type RouterAbEd25519YaoExportBackendResult =
  | { readonly ok: true; readonly body: unknown }
  | {
      readonly ok: false;
      readonly status: 400 | 408 | 409 | 429 | 500 | 502 | 503;
      readonly code: string;
      readonly message: string;
    };

export interface RouterAbEd25519YaoExportBackend {
  admitExport(
    request: RouterAbEd25519YaoExportAdmissionRequestV1,
  ): Promise<RouterAbEd25519YaoExportBackendResult> | RouterAbEd25519YaoExportBackendResult;
  executeExport(
    request: RouterAbEd25519YaoExportExecuteRequestV1,
  ): Promise<RouterAbEd25519YaoExportBackendResult> | RouterAbEd25519YaoExportBackendResult;
}

export interface RouterAbEd25519YaoExportService {
  admitExport(
    request: RouterAbEd25519YaoExportAdmissionRequestV1,
  ): Promise<RouterAbEd25519YaoExportServiceResult<RouterAbEd25519YaoExportAdmissionReceiptV1>>;
  executeExport(
    request: RouterAbEd25519YaoExportExecuteRequestV1,
  ): Promise<RouterAbEd25519YaoExportServiceResult<RouterAbEd25519YaoExportResultV1>>;
}

export type RouterAbEd25519YaoExportAdmissionAuthorization =
  | {
      readonly kind: 'passkey';
      readonly webauthnAuthentication: WebAuthnAuthenticationCredential;
      readonly providerSubjectId?: never;
    }
  | {
      readonly kind: 'email_otp_factor';
      readonly providerSubjectId: string;
      readonly webauthnAuthentication?: never;
    };

export type RouterAbEd25519YaoExportAuthorizationInput =
  | {
      readonly kind: 'admit';
      readonly request: Request;
      readonly body: RouterAbEd25519YaoExportAdmissionRequestV1;
      readonly authorization: RouterAbEd25519YaoExportAdmissionAuthorization;
      readonly expectedOrigin: string;
    }
  | {
      readonly kind: 'execute';
      readonly request: Request;
      readonly body: RouterAbEd25519YaoExportExecuteRequestV1;
    };

export type RouterAbEd25519YaoExportAuthorizationResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly status: 401 | 403 | 409 | 429 | 503;
      readonly code: string;
      readonly message: string;
    };

export interface RouterAbEd25519YaoExportAuthorizationAdapter {
  authorize(
    input: RouterAbEd25519YaoExportAuthorizationInput,
  ):
    | Promise<RouterAbEd25519YaoExportAuthorizationResult>
    | RouterAbEd25519YaoExportAuthorizationResult;
}

type ExportAdmittedState = {
  readonly kind: 'admitted';
  readonly request: RouterAbEd25519YaoExportAdmissionRequestV1;
  readonly receipt: RouterAbEd25519YaoExportAdmissionReceiptV1;
};

type ExportExecutingState = {
  readonly kind: 'executing';
  readonly request: RouterAbEd25519YaoExportAdmissionRequestV1;
  readonly receipt: RouterAbEd25519YaoExportAdmissionReceiptV1;
};

type ExportTerminalState = {
  readonly kind: 'completed' | 'burned';
  readonly request: RouterAbEd25519YaoExportAdmissionRequestV1;
  readonly receipt: RouterAbEd25519YaoExportAdmissionReceiptV1;
};

type ExportLifecycleState = ExportAdmittedState | ExportExecutingState | ExportTerminalState;

export class InMemoryRouterAbEd25519YaoExportStateV1 {
  readonly exports = new Map<string, ExportLifecycleState>();
  readonly authorizationNonces = new Set<string>();
}

function bytesToHex(bytes: readonly number[]): string {
  let encoded = '';
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, '0');
  return encoded;
}

function equalBytes(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function exactParticipants(left: readonly number[], right: readonly number[]): boolean {
  return left.length === 2 && left[0] === right[0] && left[1] === right[1];
}

function exactApplicationBinding(
  left: RouterAbEd25519YaoExportAdmissionRequestV1['application_binding'],
  right: RouterAbEd25519YaoExportAdmissionRequestV1['application_binding'],
): boolean {
  return (
    left.wallet_id === right.wallet_id &&
    left.near_ed25519_signing_key_id === right.near_ed25519_signing_key_id &&
    left.signing_root_id === right.signing_root_id &&
    left.key_creation_signer_slot === right.key_creation_signer_slot
  );
}

function exactActiveLifecycleScope(
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
  capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1,
): boolean {
  const scope = request.scope;
  const lifecycle = capability.lifecycle;
  return (
    scope.account_id === request.application_binding.wallet_id &&
    capability.nearAccountId === bytesToHex(request.registered_public_key) &&
    lifecycle.rootShareEpoch === scope.root_share_epoch &&
    lifecycle.accountId === scope.account_id &&
    lifecycle.walletSessionId === scope.wallet_session_id &&
    lifecycle.signerSetId === scope.signer_set_id &&
    lifecycle.signingWorkerId === scope.signing_worker_id
  );
}

function receiptMatchesAdmissionScope(
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
  receipt: RouterAbEd25519YaoExportAdmissionReceiptV1,
): boolean {
  const scope = request.scope;
  const lifecycle = receipt.binding.ceremony.lifecycle;
  return (
    receipt.binding.ceremony.operation === 'export' &&
    lifecycle.work_kind === 'key_export' &&
    lifecycle.primitive_request_kind === 'export' &&
    lifecycle.lifecycle_id === scope.lifecycle_id &&
    lifecycle.root_share_epoch === scope.root_share_epoch &&
    lifecycle.account_id === scope.account_id &&
    lifecycle.session_id === scope.wallet_session_id &&
    lifecycle.signer_set_id === scope.signer_set_id &&
    lifecycle.selected_server_id === scope.signing_worker_id
  );
}

function exportIdentity(
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
): RouterAbEd25519YaoExportAuthorizationIdentityV1 {
  return {
    scope: request.scope,
    application_binding: request.application_binding,
    participant_ids: request.participant_ids,
    registered_public_key: request.registered_public_key,
    state_epoch: request.state_epoch,
    runtime_policy_binding: request.runtime_policy_binding,
  };
}

function failure(input: {
  status: RouterAbEd25519YaoExportFailure['status'];
  code: RouterAbEd25519YaoExportFailure['code'];
  message: string;
}): RouterAbEd25519YaoExportFailure {
  return { ok: false, ...input };
}

export class InMemoryRouterAbEd25519YaoExportService implements RouterAbEd25519YaoExportService {
  constructor(
    private readonly backend: RouterAbEd25519YaoExportBackend,
    private readonly capabilities: RouterAbEd25519YaoActiveCapabilityResolverV1,
    private readonly state: InMemoryRouterAbEd25519YaoExportStateV1 = new InMemoryRouterAbEd25519YaoExportStateV1(),
  ) {}

  async admitExport(
    request: RouterAbEd25519YaoExportAdmissionRequestV1,
  ): Promise<RouterAbEd25519YaoExportServiceResult<RouterAbEd25519YaoExportAdmissionReceiptV1>> {
    const nonce = bytesToHex(request.authorization.nonce);
    if (this.state.authorizationNonces.has(nonce)) {
      return failure({
        status: 409,
        code: 'admission_failed',
        message: 'Ed25519 Yao export authorization was already used',
      });
    }
    this.state.authorizationNonces.add(nonce);
    const active = await this.capabilities.resolveActiveCapability({
      kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
      walletId: request.application_binding.wallet_id,
      nearAccountId: bytesToHex(request.registered_public_key),
      nearEd25519SigningKeyId: request.application_binding.near_ed25519_signing_key_id,
      signerSlot: request.application_binding.key_creation_signer_slot,
      signingWorkerId: request.scope.signing_worker_id,
      participantIds: request.participant_ids,
    });
    if (!active.ok) {
      return failure({
        status: 409,
        code: 'active_identity_mismatch',
        message: active.message,
      });
    }
    const runtimePolicyBinding = await deriveRouterAbEd25519YaoRuntimePolicyBindingV1(
      active.capability.runtimePolicyScope,
    );
    if (
      !exactActiveLifecycleScope(request, active.capability) ||
      !exactApplicationBinding(request.application_binding, active.capability.applicationBinding) ||
      !exactParticipants(request.participant_ids, active.capability.participantIds) ||
      !equalBytes(request.registered_public_key, active.capability.registeredPublicKey) ||
      request.state_epoch !== active.capability.stateEpoch ||
      !equalBytes(request.runtime_policy_binding, runtimePolicyBinding)
    ) {
      return failure({
        status: 409,
        code: 'active_identity_mismatch',
        message: 'Ed25519 Yao export does not match the exact active key capability',
      });
    }
    let backendResult: RouterAbEd25519YaoExportBackendResult;
    try {
      backendResult = await this.backend.admitExport(request);
    } catch (error: unknown) {
      return failure({
        status: 503,
        code: 'admission_failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }
    if (!backendResult.ok) {
      return failure({
        status: backendResult.status,
        code: 'admission_failed',
        message: `${backendResult.code}: ${backendResult.message}`,
      });
    }
    const parsed = parseRouterAbEd25519YaoExportAdmissionReceiptV1(backendResult.body);
    if (!parsed.ok) {
      return failure({ status: 502, code: 'invalid_backend_response', message: parsed.message });
    }
    if (
      !receiptMatchesAdmissionScope(request, parsed.value) ||
      !equalBytes(
        parsed.value.binding.authorization_digest,
        request.authorization.authorization_digest,
      ) ||
      !equalBytes(parsed.value.binding.registered_public_key, request.registered_public_key) ||
      parsed.value.binding.state_epoch !== request.state_epoch ||
      !equalBytes(parsed.value.binding.runtime_policy_binding, request.runtime_policy_binding)
    ) {
      return failure({
        status: 502,
        code: 'invalid_backend_response',
        message: 'Ed25519 Yao export admission receipt changed an exact binding',
      });
    }
    const session = bytesToHex(parsed.value.binding.ceremony.session_id);
    this.state.exports.set(session, { kind: 'admitted', request, receipt: parsed.value });
    return { ok: true, status: 200, value: parsed.value };
  }

  async executeExport(
    request: RouterAbEd25519YaoExportExecuteRequestV1,
  ): Promise<RouterAbEd25519YaoExportServiceResult<RouterAbEd25519YaoExportResultV1>> {
    const session = bytesToHex(request.binding.ceremony.session_id);
    const current = this.state.exports.get(session);
    if (!current) {
      return failure({ status: 404, code: 'unknown_export', message: 'Unknown export session' });
    }
    if (current.kind !== 'admitted') {
      return failure({
        status: 409,
        code: 'export_consumed',
        message: 'Ed25519 Yao export session was already consumed',
      });
    }
    if (JSON.stringify(current.receipt.binding) !== JSON.stringify(request.binding)) {
      this.state.exports.set(session, { ...current, kind: 'burned' });
      return failure({
        status: 409,
        code: 'binding_mismatch',
        message: 'Ed25519 Yao export execution changed the admitted binding',
      });
    }
    this.state.exports.set(session, { ...current, kind: 'executing' });
    let backendResult: RouterAbEd25519YaoExportBackendResult;
    try {
      backendResult = await this.backend.executeExport(request);
    } catch (error: unknown) {
      this.state.exports.set(session, { ...current, kind: 'burned' });
      return failure({
        status: 503,
        code: 'execution_failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }
    if (!backendResult.ok) {
      this.state.exports.set(session, { ...current, kind: 'burned' });
      return failure({
        status: backendResult.status,
        code: 'execution_failed',
        message: `${backendResult.code}: ${backendResult.message}`,
      });
    }
    const parsed = parseRouterAbEd25519YaoExportResultV1(backendResult.body);
    if (!parsed.ok || JSON.stringify(parsed.value.binding) !== JSON.stringify(request.binding)) {
      this.state.exports.set(session, { ...current, kind: 'burned' });
      return failure({
        status: 502,
        code: 'invalid_backend_response',
        message: parsed.ok ? 'Export result changed the admitted binding' : parsed.message,
      });
    }
    this.state.exports.set(session, { ...current, kind: 'completed' });
    return { ok: true, status: 200, value: parsed.value };
  }
}

function authorizationFailure(input: {
  status: 401 | 403;
  code: string;
  message: string;
}): RouterAbEd25519YaoExportAuthorizationResult {
  return { ok: false, ...input };
}

function claimsMatchExportAdmission(
  claims: RouterAbEd25519WalletSessionClaims,
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
): boolean {
  return (
    claims.walletId === request.application_binding.wallet_id &&
    claims.walletId === request.scope.account_id &&
    claims.nearAccountId === bytesToHex(request.registered_public_key) &&
    claims.nearEd25519SigningKeyId === request.application_binding.near_ed25519_signing_key_id &&
    claims.thresholdSessionId === request.scope.wallet_session_id &&
    claims.relayerKeyId === request.scope.signing_worker_id &&
    claims.routerAbNormalSigning.signingWorkerId === request.scope.signing_worker_id &&
    claims.runtimePolicyScope.signingRootVersion === request.scope.root_share_epoch &&
    exactParticipants(claims.participantIds, request.participant_ids)
  );
}

type ExportAdmissionAuthorizationInput = Extract<
  RouterAbEd25519YaoExportAuthorizationInput,
  { readonly kind: 'admit' }
>;

type ExportExecutionAuthorizationInput = Extract<
  RouterAbEd25519YaoExportAuthorizationInput,
  { readonly kind: 'execute' }
>;

type ExportAuthorizationDigestAuthority =
  | {
      readonly kind: 'passkey';
      readonly credentialIdB64u: string;
      readonly providerSubjectId?: never;
    }
  | {
      readonly kind: 'email_otp';
      readonly providerSubjectId: string;
      readonly credentialIdB64u?: never;
    };

function assertNeverExportAuthorizationInput(value: never): never {
  throw new Error(`Unsupported Ed25519 Yao export authorization input: ${String(value)}`);
}

function assertNeverExportAdmissionAuthorization(value: never): never {
  throw new Error(`Unsupported Ed25519 Yao export admission authorization: ${String(value)}`);
}

function assertNeverWalletAuthFactor(value: never): never {
  throw new Error(`Unsupported Ed25519 Yao export Wallet Session factor: ${String(value)}`);
}

function assertNeverWalletAuthVerifier(value: never): never {
  throw new Error(`Unsupported Ed25519 Yao export Wallet Session verifier: ${String(value)}`);
}

function invalidExportWalletAuthority(): RouterAbEd25519YaoExportAuthorizationResult {
  return authorizationFailure({
    status: 403,
    code: 'export_wallet_authority_invalid',
    message: 'Ed25519 Yao export Wallet Session authority is unsupported',
  });
}

function exportAuthorizationDigestAuthority(
  authority: WalletAuthAuthority,
): ExportAuthorizationDigestAuthority {
  const factor: AuthFactorIdentity = authority.factor;
  switch (factor.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        credentialIdB64u: factor.credentialIdB64u,
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        providerSubjectId: factor.providerUserId,
      };
    default:
      return assertNeverWalletAuthFactor(factor);
  }
}

function authorizeExportExecution(
  claims: RouterAbEd25519WalletSessionClaims,
  input: ExportExecutionAuthorizationInput,
): RouterAbEd25519YaoExportAuthorizationResult {
  const lifecycle = input.body.binding.ceremony.lifecycle;
  if (
    claims.walletId !== lifecycle.account_id ||
    claims.thresholdSessionId !== lifecycle.session_id ||
    claims.relayerKeyId !== lifecycle.selected_server_id
  ) {
    return authorizationFailure({
      status: 403,
      code: 'export_wallet_session_scope_mismatch',
      message: 'Wallet Session claims do not match the export execution',
    });
  }
  return { ok: true };
}

async function authorizePasskeyExportAdmission(args: {
  readonly authority: {
    readonly walletId: string;
    readonly credentialIdB64u: string;
    readonly rpId: Extract<WalletAuthAuthority['verifier'], { readonly kind: 'webauthn' }>['rpId'];
  };
  readonly input: ExportAdmissionAuthorizationInput;
  readonly confirmationDigest: readonly number[];
  readonly webAuthn: Pick<RouterApiWebAuthnService, 'verifyWebAuthnAuthenticationLite'>;
}): Promise<RouterAbEd25519YaoExportAuthorizationResult> {
  switch (args.input.authorization.kind) {
    case 'email_otp_factor':
      return authorizationFailure({
        status: 403,
        code: 'export_authorization_method_mismatch',
        message: 'Ed25519 Yao export authorization method does not match the Wallet Session',
      });
    case 'passkey': {
      const credentialId = d1WebAuthnCredentialIdB64uFromCredential(
        args.input.authorization.webauthnAuthentication,
      );
      if (!credentialId.ok || credentialId.credentialIdB64u !== args.authority.credentialIdB64u) {
        return authorizationFailure({
          status: 403,
          code: 'export_webauthn_credential_mismatch',
          message: 'Fresh export assertion used a different passkey credential',
        });
      }
      const verified = await args.webAuthn.verifyWebAuthnAuthenticationLite({
        userId: args.authority.walletId,
        rpId: args.authority.rpId,
        expectedChallenge: base64UrlEncode(Uint8Array.from(args.confirmationDigest)),
        webauthn_authentication: args.input.authorization.webauthnAuthentication,
        expected_origin: args.input.expectedOrigin,
      });
      if (!verified.success || !verified.verified) {
        return authorizationFailure({
          status: 403,
          code: verified.code || 'export_webauthn_not_verified',
          message: verified.message || 'Fresh export WebAuthn assertion was not verified',
        });
      }
      return { ok: true };
    }
    default:
      return assertNeverExportAdmissionAuthorization(args.input.authorization);
  }
}

function authorizeEmailOtpExportAdmission(args: {
  readonly providerSubjectId: string;
  readonly input: ExportAdmissionAuthorizationInput;
}): RouterAbEd25519YaoExportAuthorizationResult {
  switch (args.input.authorization.kind) {
    case 'passkey':
      return authorizationFailure({
        status: 403,
        code: 'export_authorization_method_mismatch',
        message: 'Ed25519 Yao export authorization method does not match the Wallet Session',
      });
    case 'email_otp_factor':
      if (args.input.authorization.providerSubjectId !== args.providerSubjectId) {
        return authorizationFailure({
          status: 403,
          code: 'export_authorization_method_mismatch',
          message: 'Ed25519 Yao export authorization method does not match the Wallet Session',
        });
      }
      return { ok: true };
    default:
      return assertNeverExportAdmissionAuthorization(args.input.authorization);
  }
}

async function authorizeExportAdmissionFactor(args: {
  readonly claims: RouterAbEd25519WalletSessionClaims;
  readonly input: ExportAdmissionAuthorizationInput;
  readonly confirmationDigest: readonly number[];
  readonly webAuthn: Pick<RouterApiWebAuthnService, 'verifyWebAuthnAuthenticationLite'>;
}): Promise<RouterAbEd25519YaoExportAuthorizationResult> {
  const authority = args.claims.authority;
  const factor: AuthFactorIdentity = authority.factor;
  switch (factor.kind) {
    case 'passkey': {
      const verifier: WalletAuthAuthority['verifier'] = authority.verifier;
      switch (verifier.kind) {
        case 'webauthn':
          return authorizePasskeyExportAdmission({
            authority: {
              walletId: authority.walletId,
              credentialIdB64u: factor.credentialIdB64u,
              rpId: verifier.rpId,
            },
            input: args.input,
            confirmationDigest: args.confirmationDigest,
            webAuthn: args.webAuthn,
          });
        case 'email_otp_wallet_auth_method':
          return invalidExportWalletAuthority();
        default:
          return assertNeverWalletAuthVerifier(verifier);
      }
    }
    case 'email_otp': {
      const verifier: WalletAuthAuthority['verifier'] = authority.verifier;
      switch (verifier.kind) {
        case 'email_otp_wallet_auth_method':
          return authorizeEmailOtpExportAdmission({
            providerSubjectId: factor.providerUserId,
            input: args.input,
          });
        case 'webauthn':
          return invalidExportWalletAuthority();
        default:
          return assertNeverWalletAuthVerifier(verifier);
      }
    }
    default:
      return assertNeverWalletAuthFactor(factor);
  }
}

async function authorizeExportAdmission(args: {
  readonly claims: RouterAbEd25519WalletSessionClaims;
  readonly input: ExportAdmissionAuthorizationInput;
  readonly webAuthn: Pick<RouterApiWebAuthnService, 'verifyWebAuthnAuthenticationLite'>;
}): Promise<RouterAbEd25519YaoExportAuthorizationResult> {
  if (!claimsMatchExportAdmission(args.claims, args.input.body)) {
    return authorizationFailure({
      status: 403,
      code: 'export_wallet_session_scope_mismatch',
      message: 'Wallet Session claims do not match the export admission',
    });
  }
  const nowMs = Date.now();
  const authorization = args.input.body.authorization;
  if (
    authorization.expires_at_ms <= nowMs ||
    authorization.issued_at_ms > nowMs + EXPORT_AUTH_CLOCK_SKEW_MS ||
    authorization.expires_at_ms - authorization.issued_at_ms > EXPORT_AUTH_MAX_TTL_MS
  ) {
    return authorizationFailure({
      status: 403,
      code: 'export_authorization_expired',
      message: 'Ed25519 Yao export authorization is expired or has an invalid lifetime',
    });
  }
  const identity = exportIdentity(args.input.body);
  const expectedConfirmation = await deriveRouterAbEd25519YaoExportConfirmationDigestV1({
    identity,
    nonce: authorization.nonce,
    issuedAtMs: authorization.issued_at_ms,
    expiresAtMs: authorization.expires_at_ms,
  });
  const expectedAuthorization = await deriveRouterAbEd25519YaoExportAuthorizationDigestV1({
    identity,
    confirmationDigest: authorization.confirmation_digest,
    nonce: authorization.nonce,
    issuedAtMs: authorization.issued_at_ms,
    expiresAtMs: authorization.expires_at_ms,
    thresholdSessionId: args.claims.thresholdSessionId,
    signingGrantId: args.claims.signingGrantId,
    authority: exportAuthorizationDigestAuthority(args.claims.authority),
  });
  if (
    !equalBytes(expectedConfirmation, authorization.confirmation_digest) ||
    !equalBytes(expectedAuthorization, authorization.authorization_digest)
  ) {
    return authorizationFailure({
      status: 403,
      code: 'export_authorization_invalid',
      message: 'Ed25519 Yao export authorization digest is invalid',
    });
  }
  return authorizeExportAdmissionFactor({
    claims: args.claims,
    input: args.input,
    confirmationDigest: authorization.confirmation_digest,
    webAuthn: args.webAuthn,
  });
}

export class RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter implements RouterAbEd25519YaoExportAuthorizationAdapter {
  constructor(
    private readonly session: SessionAdapter,
    private readonly webAuthn: Pick<RouterApiWebAuthnService, 'verifyWebAuthnAuthenticationLite'>,
  ) {}

  async authorize(
    input: RouterAbEd25519YaoExportAuthorizationInput,
  ): Promise<RouterAbEd25519YaoExportAuthorizationResult> {
    const parsedSession = await this.session.parse(headersToRecord(input.request.headers));
    if (!parsedSession.ok) {
      return authorizationFailure({
        status: 401,
        code: 'export_wallet_session_missing',
        message: 'Ed25519 Yao export requires a valid Wallet Session JWT',
      });
    }
    const claims = parseRouterAbEd25519WalletSessionClaims(parsedSession.claims);
    if (!claims) {
      return authorizationFailure({
        status: 403,
        code: 'export_wallet_authority_invalid',
        message: 'Ed25519 Yao export requires a valid Wallet Session authority',
      });
    }
    switch (input.kind) {
      case 'admit':
        return authorizeExportAdmission({ claims, input, webAuthn: this.webAuthn });
      case 'execute':
        return authorizeExportExecution(claims, input);
      default:
        return assertNeverExportAuthorizationInput(input);
    }
  }
}

const ROUTES = Object.freeze([
  defineRoute({
    id: 'router_ab_ed25519_yao_export_admit',
    surface: 'relay',
    method: 'POST',
    path: ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
    auth: {
      plane: 'public',
      proof: 'challenge_exchange',
      rationale:
        'Exact-seed export requires fresh passkey assertion or Email OTP factor possession.',
    },
    metering: { kind: 'none' },
    requiredServices: [],
    summary: 'Admit one exact Ed25519 Yao seed export',
  }),
  defineRoute({
    id: 'router_ab_ed25519_yao_export_execute',
    surface: 'relay',
    method: 'POST',
    path: ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
    auth: {
      plane: 'public',
      proof: 'threshold_protocol_state',
      rationale: 'Execution consumes one admitted and passkey-authorized export ceremony.',
    },
    metering: { kind: 'none' },
    requiredServices: [],
    summary: 'Execute one admitted Ed25519 Yao seed export',
  }),
]);

type ExportAdmissionAuthorizationParseResult =
  | {
      readonly ok: true;
      readonly value: RouterAbEd25519YaoExportAdmissionAuthorization;
    }
  | { readonly ok: false; readonly message: string };

type ExportAdmissionEnvelopeParseResult =
  | {
      readonly ok: true;
      readonly protocol: RouterAbEd25519YaoExportAdmissionRequestV1;
      readonly authorization: RouterAbEd25519YaoExportAdmissionAuthorization;
    }
  | { readonly ok: false; readonly message: string };

function firstUnexpectedField(
  record: Record<string, unknown>,
  allowedFields: readonly string[],
): string | null {
  for (const key of Object.keys(record)) {
    if (!allowedFields.includes(key)) return key;
  }
  return null;
}

function parsePasskeyExportAdmissionAuthorization(
  authorization: Record<string, unknown>,
): ExportAdmissionAuthorizationParseResult {
  const unexpectedField = firstUnexpectedField(authorization, ['kind', 'webauthnAuthentication']);
  if (unexpectedField) {
    return {
      ok: false,
      message: `passkey export authorization has unknown field: ${unexpectedField}`,
    };
  }
  const webauthnAuthentication = parseD1WebAuthnAuthenticationCredential(
    authorization.webauthnAuthentication,
  );
  if (!webauthnAuthentication) {
    return { ok: false, message: 'webauthnAuthentication is invalid' };
  }
  return {
    ok: true,
    value: { kind: 'passkey', webauthnAuthentication },
  };
}

function parseEmailOtpExportAdmissionAuthorization(
  authorization: Record<string, unknown>,
): ExportAdmissionAuthorizationParseResult {
  const unexpectedField = firstUnexpectedField(authorization, ['kind', 'providerSubjectId']);
  if (unexpectedField) {
    return {
      ok: false,
      message: `Email OTP export authorization has unknown field: ${unexpectedField}`,
    };
  }
  if (typeof authorization.providerSubjectId !== 'string') {
    return { ok: false, message: 'providerSubjectId must be a string' };
  }
  const providerSubjectId = authorization.providerSubjectId.trim();
  if (!providerSubjectId) {
    return { ok: false, message: 'providerSubjectId is required' };
  }
  return {
    ok: true,
    value: { kind: 'email_otp_factor', providerSubjectId },
  };
}

function parseExportAdmissionAuthorization(
  value: unknown,
): ExportAdmissionAuthorizationParseResult {
  if (!isPlainObject(value)) {
    return { ok: false, message: 'export admission authorization must be an object' };
  }
  switch (value.kind) {
    case 'passkey':
      return parsePasskeyExportAdmissionAuthorization(value);
    case 'email_otp_factor':
      return parseEmailOtpExportAdmissionAuthorization(value);
    default:
      return { ok: false, message: 'export admission authorization kind is invalid' };
  }
}

function parseExportAdmissionEnvelope(value: unknown): ExportAdmissionEnvelopeParseResult {
  if (!isPlainObject(value)) {
    return { ok: false, message: 'export admission envelope must be an object' };
  }
  const record = value;
  const keys = Object.keys(record);
  if (
    keys.length !== 2 ||
    !Object.hasOwn(record, 'protocol') ||
    !Object.hasOwn(record, 'authorization')
  ) {
    return {
      ok: false,
      message: 'export admission envelope requires protocol and authorization',
    };
  }
  const protocol = parseRouterAbEd25519YaoExportAdmissionRequestV1(record.protocol);
  if (!protocol.ok) return protocol;
  const authorization = parseExportAdmissionAuthorization(record.authorization);
  if (!authorization.ok) return authorization;
  return {
    ok: true,
    protocol: protocol.value,
    authorization: authorization.value,
  };
}

class RouterAbEd25519YaoExportRouteExtension implements RouterApiRouteExtension {
  readonly kind = 'cloudflare_route_extension' as const;
  readonly id = 'router_ab_ed25519_yao_export';
  readonly routes = ROUTES;

  constructor(
    private readonly service: RouterAbEd25519YaoExportService,
    private readonly authorization: RouterAbEd25519YaoExportAuthorizationAdapter,
  ) {}

  async handleCloudflareRoute(input: RouterApiCloudflareRouteExtensionInput): Promise<Response> {
    if (input.method !== 'POST') {
      return json(
        { ok: false, code: 'method_not_allowed', message: 'Method not allowed' },
        { status: 405 },
      );
    }
    const raw = await readJson(input.request);
    if (input.pathname === ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1) {
      const parsed = parseExportAdmissionEnvelope(raw);
      if (!parsed.ok)
        return json({ ok: false, code: 'invalid_body', message: parsed.message }, { status: 400 });
      const expectedOrigin = normalizeCorsOrigin(input.request.headers.get('origin') || undefined);
      if (!expectedOrigin) {
        return json(
          {
            ok: false,
            code: 'forbidden',
            message: 'Origin header is required and must be a valid exact origin',
          },
          { status: 403 },
        );
      }
      const authorized = await this.authorization.authorize({
        kind: 'admit',
        request: input.request,
        body: parsed.protocol,
        authorization: parsed.authorization,
        expectedOrigin,
      });
      if (!authorized.ok)
        return json(
          { ok: false, code: authorized.code, message: authorized.message },
          { status: authorized.status },
        );
      const result = await this.service.admitExport(parsed.protocol);
      return result.ok
        ? json(result.value, { status: result.status })
        : json(
            { ok: false, code: result.code, message: result.message },
            { status: result.status },
          );
    }
    if (input.pathname === ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1) {
      const parsed = parseRouterAbEd25519YaoExportExecuteRequestV1(raw);
      if (!parsed.ok)
        return json({ ok: false, code: parsed.code, message: parsed.message }, { status: 400 });
      const authorized = await this.authorization.authorize({
        kind: 'execute',
        request: input.request,
        body: parsed.value,
      });
      if (!authorized.ok)
        return json(
          { ok: false, code: authorized.code, message: authorized.message },
          { status: authorized.status },
        );
      const result = await this.service.executeExport(parsed.value);
      return result.ok
        ? json(result.value, { status: result.status })
        : json(
            { ok: false, code: result.code, message: result.message },
            { status: result.status },
          );
    }
    return json({ ok: false, code: 'not_found', message: 'Not found' }, { status: 404 });
  }
}

export function createRouterAbEd25519YaoExportModule(input: {
  readonly service: RouterAbEd25519YaoExportService;
  readonly authorization: RouterAbEd25519YaoExportAuthorizationAdapter;
}): RouterApiModule {
  return createRouterApiModule({
    id: 'router_ab_ed25519_yao_export',
    routeExtensions: [
      new RouterAbEd25519YaoExportRouteExtension(input.service, input.authorization),
    ],
  });
}
