import type { ThresholdRuntimePolicyScope } from '../../core/types';
import type { RouterApiAuthorizationSessionService } from '../framework/authServicePort';
import type { RouterApiWalletSessionAuthorizationV2AdmissionContext } from '../framework/authServicePort';
import {
  type OpaqueOwnerWalletSessionBinding,
  type ResolvedOpaqueWalletSessionToken,
} from '../../authorization/service';
import type {
  RouterApiProjectEnvironmentResolver,
  RouterApiPublishableKeyAuthAdapter,
} from '../framework/routerApi';
import { extractBearerCredential } from './routerApiKeyAuth';
import {
  type VerifiedOwnerEcdsaWalletSessionAuth,
  type VerifiedOwnerEd25519WalletSessionAuth,
} from './verifiedWalletSessionAuth';
import {
  normalizeRuntimePolicyScope,
  normalizeRuntimePolicyScopeFields,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  walletSessionFailure,
  walletSessionFailureMessage,
  type WalletSessionFailureCode,
} from './walletSessionFailure';
import {
  resolveWalletSessionAuthorizationV2AdministrationAdmission,
  resolveWalletSessionAuthorizationV2Admission,
  type WalletSessionAuthorizationV2AdministrationAdmissionResult,
  type WalletSessionAuthorizationV2AdministrationOperation,
  type WalletSessionAuthorizationV2AdmissionResult,
  type WalletSessionAuthorizationV2RequestedOperation,
} from '../domains/signingOperations/walletExecutionAdmission';

type PlainObject = Record<string, unknown>;
type AuthorizeErr = {
  ok: false;
  code: 'sessions_disabled' | WalletSessionFailureCode;
  message: string;
};

function isPlainObject(input: unknown): input is PlainObject {
  return !!input && typeof input === 'object' && !Array.isArray(input);
}

export type OpaqueOwnerWalletSessionAdmission =
  | {
      readonly kind: 'owner_wallet_session';
      readonly curve: 'ed25519';
      readonly binding: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ed25519' }>;
      readonly walletSessionAuth: VerifiedOwnerEd25519WalletSessionAuth;
      readonly resolved: ResolvedOpaqueWalletSessionToken;
    }
  | {
      readonly kind: 'owner_wallet_session';
      readonly curve: 'ecdsa';
      readonly binding: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }>;
      readonly walletSessionAuth: VerifiedOwnerEcdsaWalletSessionAuth;
      readonly resolved: ResolvedOpaqueWalletSessionToken;
    };

export type WalletSessionOperationCredentialAdmission =
  | {
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly curve: 'ed25519';
      readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
      readonly admission: Extract<
        WalletSessionAuthorizationV2AdmissionResult,
        { readonly ok: true; readonly keyFamily: 'ed25519' }
      >;
    }
  | {
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly curve: 'ecdsa';
      readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
      readonly admission: Extract<
        WalletSessionAuthorizationV2AdmissionResult,
        { readonly ok: true; readonly keyFamily: 'ecdsa_secp256k1' }
      >;
    };

export type WalletSessionOperationCredentialResolution =
  | { readonly kind: 'not_found' }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'admitted'; readonly admission: WalletSessionOperationCredentialAdmission };

type WalletSessionOperationCredentialRequest =
  | Pick<
      Extract<WalletSessionAuthorizationV2RequestedOperation, { readonly keyFamily: 'ed25519' }>,
      'keyFamily' | 'operationKind'
    >
  | Pick<
      Extract<
        WalletSessionAuthorizationV2RequestedOperation,
        { readonly keyFamily: 'ecdsa_secp256k1' }
      >,
      'keyFamily' | 'operationKind'
    >;

export function resolveWalletSessionOperationCredentialAdmissionFromContext(input: {
  readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
  readonly nowMs: number;
  readonly operation: WalletSessionOperationCredentialRequest;
}): Exclude<WalletSessionOperationCredentialResolution, { readonly kind: 'not_found' }> {
  const context = input.context;
  const identity = {
    tenantId: context.authorization.session.tenantId,
    principalId: context.authorization.session.principalId,
    walletId: context.authorization.session.walletId,
  };
  const operation: WalletSessionAuthorizationV2RequestedOperation =
    input.operation.keyFamily === 'ed25519'
      ? { ...identity, keyFamily: 'ed25519', operationKind: input.operation.operationKind }
      : {
          ...identity,
          keyFamily: 'ecdsa_secp256k1',
          operationKind: input.operation.operationKind,
        };
  const admission = resolveWalletSessionAuthorizationV2Admission({
    authorization: context.authorization.session,
    authority: context.authority,
    authMethod: context.authMethod,
    operation,
    retiredAtMs: context.retiredAtMs,
    nowMs: input.nowMs,
  });
  if (!admission.ok || admission.keyFamily !== input.operation.keyFamily) {
    return { kind: 'rejected' };
  }
  if (admission.keyFamily === 'ed25519') {
    return {
      kind: 'admitted',
      admission: {
        kind: 'wallet_session_operation_credential_v1',
        curve: 'ed25519',
        context,
        admission,
      },
    };
  }
  return {
    kind: 'admitted',
    admission: {
      kind: 'wallet_session_operation_credential_v1',
      curve: 'ecdsa',
      context,
      admission,
    },
  };
}

export async function resolveWalletSessionOperationCredentialAdmission(input: {
  readonly authorizationSessions: RouterApiAuthorizationSessionService;
  readonly token: string;
  readonly nowMs: number;
  readonly operation: WalletSessionOperationCredentialRequest;
}): Promise<WalletSessionOperationCredentialResolution> {
  const context =
    await input.authorizationSessions.readWalletSessionAuthorizationV2ByOperationCredential({
      tenantId: input.authorizationSessions.tenantId,
      token: input.token,
      nowMs: input.nowMs,
    });
  if (!context) return { kind: 'not_found' };
  return resolveWalletSessionOperationCredentialAdmissionFromContext({
    context,
    nowMs: input.nowMs,
    operation: input.operation,
  });
}

export type WalletSessionAdministrationRequest = Pick<
  WalletSessionAuthorizationV2AdministrationOperation,
  'kind' | 'walletId'
>;

export type WalletSessionAdministrationAdmission = {
  readonly kind: 'wallet_session_administration_v1';
  readonly operationKind: 'link_devices';
  readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
  readonly admission: Extract<
    WalletSessionAuthorizationV2AdministrationAdmissionResult,
    { readonly ok: true }
  >;
};

export type WalletSessionAdministrationResolution =
  | { readonly kind: 'not_found' }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'admitted'; readonly admission: WalletSessionAdministrationAdmission };

export async function resolveWalletSessionAdministrationAdmission(input: {
  readonly authorizationSessions: RouterApiAuthorizationSessionService;
  readonly token: string;
  readonly nowMs: number;
  readonly operation: WalletSessionAdministrationRequest;
}): Promise<WalletSessionAdministrationResolution> {
  const context =
    await input.authorizationSessions.readWalletSessionAuthorizationV2ByOperationCredential({
      tenantId: input.authorizationSessions.tenantId,
      token: input.token,
      nowMs: input.nowMs,
    });
  if (!context) return { kind: 'not_found' };
  const session = context.authorization.session;
  const admission = resolveWalletSessionAuthorizationV2AdministrationAdmission({
    authorization: session,
    authority: context.authority,
    authMethod: context.authMethod,
    operation: {
      kind: input.operation.kind,
      tenantId: session.tenantId,
      principalId: session.principalId,
      walletId: input.operation.walletId,
    },
    retiredAtMs: context.retiredAtMs,
    nowMs: input.nowMs,
  });
  if (!admission.ok) return { kind: 'rejected' };
  return {
    kind: 'admitted',
    admission: {
      kind: 'wallet_session_administration_v1',
      operationKind: admission.operationKind,
      context,
      admission,
    },
  };
}

export type ThresholdEd25519SessionTokenInputs =
  | {
      readonly ok: true;
      readonly kind: 'owner_wallet_session';
      admission: Extract<OpaqueOwnerWalletSessionAdmission, { readonly curve: 'ed25519' }>;
      binding: Extract<OpaqueOwnerWalletSessionAdmission, { readonly curve: 'ed25519' }>['binding'];
      walletSessionAuth: VerifiedOwnerEd25519WalletSessionAuth;
      body: PlainObject;
    }
  | {
      readonly ok: true;
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly admission: Extract<
        WalletSessionOperationCredentialAdmission,
        { readonly curve: 'ed25519' }
      >;
      readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
      readonly body: PlainObject;
    }
  | AuthorizeErr;

export async function validateRouterAbEd25519WalletSessionTokenInputs(input: {
  body: unknown;
  headers: Record<string, string | string[] | undefined>;
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  nowMs?: () => number;
  operationKind: Extract<
    WalletSessionAuthorizationV2RequestedOperation,
    { readonly keyFamily: 'ed25519' }
  >['operationKind'];
}): Promise<ThresholdEd25519SessionTokenInputs> {
  const authorizationSessions = input.authorizationSessions;
  if (!authorizationSessions) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Sessions are not configured on this server',
    };
  }

  const token = extractBearerCredential(input.headers);
  if (!token) return walletSessionFailure('wallet_session_missing');
  const nowMs = input.nowMs || Date.now;
  let resolution: WalletSessionOperationCredentialResolution;
  try {
    resolution = await resolveWalletSessionOperationCredentialAdmission({
      authorizationSessions,
      token,
      nowMs: nowMs(),
      operation: { keyFamily: 'ed25519', operationKind: input.operationKind },
    });
  } catch {
    return walletSessionFailure('wallet_session_unavailable');
  }
  if (resolution.kind === 'rejected') {
    return walletSessionFailure('wallet_session_scope_mismatch');
  }
  if (resolution.kind === 'not_found') {
    return {
      ok: false,
      code: 'wallet_session_invalid',
      message: walletSessionFailureMessage('wallet_session_invalid'),
    };
  }
  if (resolution.admission.curve !== 'ed25519') {
    return walletSessionFailure('wallet_session_scope_mismatch');
  }
  return {
    ok: true,
    kind: 'wallet_session_operation_credential_v1',
    admission: resolution.admission,
    context: resolution.admission.context,
    body: isPlainObject(input.body) ? input.body : {},
  };
}

export type ThresholdEcdsaSessionInputs =
  | {
      ok: true;
      readonly kind: 'owner_wallet_session';
      admission: Extract<OpaqueOwnerWalletSessionAdmission, { readonly curve: 'ecdsa' }>;
      binding: Extract<OpaqueOwnerWalletSessionAdmission, { readonly curve: 'ecdsa' }>['binding'];
      walletSessionAuth: VerifiedOwnerEcdsaWalletSessionAuth;
      body: PlainObject;
    }
  | {
      readonly ok: true;
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly admission: WalletSessionOperationCredentialAdmission;
      readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
      readonly body: PlainObject;
    }
  | AuthorizeErr;

export async function validateRouterAbEcdsaDerivationWalletSessionInputs(input: {
  body: unknown;
  headers: Record<string, string | string[] | undefined>;
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  nowMs?: () => number;
  operationKind: Extract<
    WalletSessionAuthorizationV2RequestedOperation,
    { readonly keyFamily: 'ecdsa_secp256k1' }
  >['operationKind'];
}): Promise<ThresholdEcdsaSessionInputs> {
  const authorizationSessions = input.authorizationSessions;
  if (!authorizationSessions) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Sessions are not configured on this server',
    };
  }

  const token = extractBearerCredential(input.headers);
  if (!token) return walletSessionFailure('wallet_session_missing');
  const nowMs = input.nowMs || Date.now;
  let resolution: WalletSessionOperationCredentialResolution;
  try {
    resolution = await resolveWalletSessionOperationCredentialAdmission({
      authorizationSessions,
      token,
      nowMs: nowMs(),
      operation: { keyFamily: 'ecdsa_secp256k1', operationKind: input.operationKind },
    });
  } catch {
    return walletSessionFailure('wallet_session_unavailable');
  }
  if (resolution.kind === 'rejected') {
    return walletSessionFailure('wallet_session_scope_mismatch');
  }
  if (resolution.kind === 'not_found') {
    return {
      ok: false,
      code: 'wallet_session_invalid',
      message: walletSessionFailureMessage('wallet_session_invalid'),
    };
  }
  if (resolution.admission.curve !== 'ecdsa') {
    return walletSessionFailure('wallet_session_scope_mismatch');
  }
  return {
    ok: true,
    kind: 'wallet_session_operation_credential_v1',
    admission: resolution.admission,
    context: resolution.admission.context,
    body: isPlainObject(input.body) ? input.body : {},
  };
}

export type ThresholdRuntimePolicyScopeResolution =
  | { ok: true; scope?: ThresholdRuntimePolicyScope }
  | {
      ok: false;
      status: 401 | 403 | 500;
      code: 'route_auth_not_configured' | 'unauthorized' | 'forbidden';
      message: string;
    };

export async function resolveThresholdRuntimePolicyScope(input: {
  explicitScopeRaw: unknown;
  projectEnvironmentIdRaw?: unknown;
  headers: Headers | Record<string, string | string[] | undefined>;
  origin?: string | null;
  publishableKeyAuth?: RouterApiPublishableKeyAuthAdapter | null;
  orgProjectEnv?: RouterApiProjectEnvironmentResolver | null;
}): Promise<ThresholdRuntimePolicyScopeResolution> {
  if (isPlainObject(input.explicitScopeRaw)) {
    try {
      const scope = await resolveActiveRuntimePolicyScopeFromFields({
        orgProjectEnv: input.orgProjectEnv || null,
        fields: normalizeRuntimePolicyScopeFields(input.explicitScopeRaw),
      });
      return {
        ok: true,
        scope,
      };
    } catch {
      return { ok: true };
    }
  }

  // The publishable key is the trigger and the source of truth: its own row
  // carries the environment it belongs to, and the scope below is built purely
  // from the authenticated principal. `projectEnvironmentId` is therefore
  // optional — when a client does send one it is forwarded as a cross-check, so
  // a staging key aimed at a production environment id still fails closed.
  const projectEnvironmentId = String(input.projectEnvironmentIdRaw || '').trim();
  const publishableKey = extractBearerCredential(input.headers);
  if (!publishableKey) {
    // No managed credential presented: this is not a managed deployment.
    if (!projectEnvironmentId) return { ok: true };
    return {
      ok: false,
      status: 401,
      code: 'unauthorized',
      message: 'Managed runtime scope bootstrap requires a publishable key',
    };
  }

  const publishableKeyAuth = input.publishableKeyAuth || null;
  if (!publishableKeyAuth) {
    return {
      ok: false,
      status: 500,
      code: 'route_auth_not_configured',
      message: 'Runtime scope bootstrap requires publishable key auth on this server',
    };
  }

  const origin = String(input.origin || '').trim();
  if (!origin) {
    return {
      ok: false,
      status: 403,
      code: 'forbidden',
      message: 'Managed runtime scope bootstrap requires an Origin header',
    };
  }

  const authResult = await publishableKeyAuth.authenticate({
    secret: publishableKey,
    origin,
    environmentId: projectEnvironmentId,
  });
  if (!authResult.ok) {
    return {
      ok: false,
      status: authResult.status,
      code: authResult.status === 403 ? 'forbidden' : 'unauthorized',
      message: authResult.message,
    };
  }

  const projectEnvironment = await resolveRuntimeProjectEnvironment({
    orgProjectEnv: input.orgProjectEnv || null,
    orgId: authResult.principal.orgId,
    environmentId: authResult.principal.environmentId,
  });
  if (!projectEnvironment) return { ok: true };

  return {
    ok: true,
    scope: {
      orgId: authResult.principal.orgId,
      projectId: projectEnvironment.projectId,
      envId: projectEnvironment.envId,
      signingRootVersion: projectEnvironment.signingRootVersion,
    },
  };
}

export async function resolveActiveRuntimePolicyScopeFromFields(input: {
  orgProjectEnv: RouterApiProjectEnvironmentResolver | null;
  fields: Omit<ThresholdRuntimePolicyScope, 'signingRootVersion'> & {
    readonly signingRootVersion?: string;
  };
}): Promise<ThresholdRuntimePolicyScope> {
  const resolved = await resolveActiveRuntimePolicyScopeForEnvironment({
    orgProjectEnv: input.orgProjectEnv,
    orgId: input.fields.orgId,
    projectId: input.fields.projectId,
    envId: input.fields.envId,
    fallbackSigningRootVersion: input.fields.signingRootVersion,
  });
  if (resolved) return resolved;
  return normalizeRuntimePolicyScope(input.fields);
}

export async function resolveActiveRuntimePolicyScopeForEnvironment(input: {
  orgProjectEnv: RouterApiProjectEnvironmentResolver | null;
  orgId: string;
  environmentId?: string;
  projectId?: string;
  envId?: string;
  fallbackSigningRootVersion?: string;
}): Promise<ThresholdRuntimePolicyScope | undefined> {
  const orgId = String(input.orgId || '').trim();
  if (!orgId) return undefined;
  const activeEnvironment = await resolveRuntimeProjectEnvironment({
    orgProjectEnv: input.orgProjectEnv,
    orgId,
    environmentId: input.environmentId,
    projectId: input.projectId,
    envId: input.envId,
  });
  if (activeEnvironment) {
    return {
      orgId,
      projectId: activeEnvironment.projectId,
      envId: activeEnvironment.envId,
      signingRootVersion: activeEnvironment.signingRootVersion,
    };
  }
  const projectId = String(input.projectId || '').trim();
  const envId = String(input.envId || '').trim();
  const signingRootVersion = String(input.fallbackSigningRootVersion || '').trim();
  if (projectId && envId && signingRootVersion) {
    return { orgId, projectId, envId, signingRootVersion };
  }
  return undefined;
}

async function resolveRuntimeProjectEnvironment(input: {
  orgProjectEnv: RouterApiProjectEnvironmentResolver | null;
  orgId: string;
  environmentId?: string;
  projectId?: string;
  envId?: string;
}): Promise<{ projectId: string; envId: string; signingRootVersion: string } | undefined> {
  if (!input.orgProjectEnv) return undefined;
  try {
    const environmentId = String(input.environmentId || '').trim();
    const projectIdFilter = String(input.projectId || '').trim();
    const envIdFilter = String(input.envId || '').trim();
    const environments = await input.orgProjectEnv.listEnvironments({
      orgId: input.orgId,
      actorUserId: 'runtime-scope-bootstrap',
      roles: ['system'],
      ...(environmentId ? { environmentId } : {}),
      ...(projectIdFilter ? { projectId: projectIdFilter } : {}),
    });
    const environment = environments.find((entry) => {
      if (environmentId && entry.id !== environmentId) return false;
      if (projectIdFilter && entry.projectId !== projectIdFilter) return false;
      if (envIdFilter && entry.key !== envIdFilter) return false;
      return true;
    });
    const projectId = String(environment?.projectId || '').trim();
    const envId = String(environment?.key || '').trim();
    const signingRootVersion = String(environment?.signingRootVersion || '').trim();
    return projectId && envId && signingRootVersion
      ? { projectId, envId, signingRootVersion }
      : undefined;
  } catch {
    return undefined;
  }
}
