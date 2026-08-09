import {
  buildSigningSessionSealApplyPath,
  buildSigningSessionSealRemovePath,
  resolveSigningSessionSealBasePath,
} from '../../threshold/session/signingSessionSeal/transport/shared';
import {
  ROUTER_AB_PUBLIC_KEYSET_PATH,
  ROUTER_AB_PUBLIC_KEYSET_WELL_KNOWN_PATH,
} from '@shared/utils/routerAbPublicKeyset';
import {
  ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
  ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PATH,
  ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH,
  ROUTER_AB_ECDSA_DERIVATION_SESSION_ACTIVATION_PATH,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  ROUTER_AB_ED25519_HEALTH_PATH,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PATH,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH,
  ROUTER_AB_ED25519_WALLET_SESSION_PATH,
} from '@shared/utils/signingSessionSeal';
import {
  API_CREDENTIAL_ROUTE_SCOPES,
  API_CREDENTIAL_TYPES,
  PUBLIC_PROOF_TYPES,
  type RouteAuthPolicy,
} from './routeAuthPolicy';
import {
  ROUTE_SERVICE_KEYS,
  type CoreRouteServiceKey,
  type RouteMethod,
  type RouteServiceKey,
} from './routeExecutionContext';
import type { RouteMeteringPolicy } from './routeMeteringPolicy';

export interface RouteDefinition {
  id: string;
  surface: 'relay';
  method: RouteMethod;
  path: string;
  aliases?: readonly string[];
  auth: RouteAuthPolicy;
  metering: RouteMeteringPolicy;
  requiredServices?: readonly RouteServiceKey[];
  summary: string;
}

export interface RouterApiRouteDefinitionOptions {
  enableEmailRecoveryPrepare?: boolean;
  enableRecoverEmail?: boolean;
  enableHealthz?: boolean;
  enableSigningSessionSeal?: boolean;
  enableReadyz?: boolean;
  signingSessionSealBasePath?: string;
  sessionStatePath?: string;
}

const API_CREDENTIAL_TYPE_SET = new Set<string>(API_CREDENTIAL_TYPES);
const API_CREDENTIAL_ROUTE_SCOPE_SET = new Set<string>(API_CREDENTIAL_ROUTE_SCOPES);
const PUBLIC_PROOF_TYPE_SET = new Set<string>(PUBLIC_PROOF_TYPES);
const ROUTE_SERVICE_KEY_SET = new Set<string>(ROUTE_SERVICE_KEYS);

const ROUTER_API_ROUTER_SERVICE = ['router'] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_WELL_KNOWN_SERVICES = [] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_WALLET_REGISTRATION_SERVICES = [
  'walletRegistration',
  'walletAuthMethods',
  'thresholdRuntime',
  'sessionVersions',
  'webAuthn',
  'nearFunding',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_WALLET_REGISTRATION_SESSION_SERVICES = [
  ...ROUTER_API_WALLET_REGISTRATION_SERVICES,
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_AUTH_PROVIDER_SERVICES = [
  'webAuthn',
  'identity',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_SYNC_ACCOUNT_SERVICES = [
  'webAuthn',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_ED25519_WALLET_SESSION_SERVICES = [
  'walletRegistration',
  'webAuthn',
  'thresholdRuntime',
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_THRESHOLD_RUNTIME_SERVICES = [
  'thresholdRuntime',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_THRESHOLD_SESSION_SERVICES = [
  'thresholdRuntime',
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_NORMAL_SIGNING_PROXY_SERVICES = [
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_ECDSA_STRICT_LIFECYCLE_SERVICES = [
  'thresholdRuntime',
  'webAuthn',
  'sessionVersions',
  'emailOtp',
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_WEBAUTHN_AUTHENTICATOR_SERVICES = [
  'webAuthn',
  'sessionVersions',
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_NEAR_PUBLIC_KEY_SERVICES = [
  'nearFunding',
  'sessionVersions',
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_SESSION_EXCHANGE_SERVICES = [
  'identity',
  'emailOtp',
  'webAuthn',
  'sessionVersions',
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_SESSION_VERSION_SERVICES = [
  'sessionVersions',
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_PASSKEY_CUSTODY_SERVICES = [
  'passkeyCustody',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_WALLET_UNLOCK_SERVICES = [
  'walletUnlock',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_EMAIL_OTP_SESSION_SERVICES = [
  'emailOtp',
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_EMAIL_OTP_PUBLIC_SERVICES = [
  'emailOtp',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_AUTH_IDENTITY_SERVICES = [
  'identity',
  'sessionVersions',
  'webAuthn',
  'emailOtp',
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_EMAIL_RECOVERY_AUTH_SERVICES = [
  'emailRecoveryAuth',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_RECOVER_EMAIL_SERVICES = [
  'recovery',
  'emailRecoveryExecution',
] as const satisfies readonly CoreRouteServiceKey[];
function normalizeAliases(
  path: string,
  aliases: readonly string[] | undefined,
): readonly string[] | undefined {
  if (!aliases || aliases.length === 0) return undefined;
  const seen = new Set<string>();
  const next: string[] = [];
  for (const alias of aliases) {
    const value = String(alias || '').trim();
    if (!value || value === path || seen.has(value)) continue;
    seen.add(value);
    next.push(value);
  }
  return next.length > 0 ? next : undefined;
}

function normalizeRequiredServices(
  id: string,
  requiredServices: readonly RouteServiceKey[] | undefined,
  allowExtensionServices: boolean,
): readonly RouteServiceKey[] | undefined {
  if (!requiredServices || requiredServices.length === 0) return undefined;
  const seen = new Set<string>();
  const next: RouteServiceKey[] = [];
  for (const requiredService of requiredServices) {
    const value = String(requiredService || '').trim();
    if (!value) {
      throw new Error(`route definition requiredServices must contain non-empty values for ${id}`);
    }
    if (!allowExtensionServices && !ROUTE_SERVICE_KEY_SET.has(value)) {
      throw new Error(
        `route definition requiredServices contains unknown service ${value} for ${id}`,
      );
    }
    if (seen.has(value)) continue;
    seen.add(value);
    next.push(value as RouteServiceKey);
  }
  return next.length > 0 ? next : undefined;
}

function normalizeAuthPolicy(id: string, auth: RouteAuthPolicy): RouteAuthPolicy {
  switch (auth.plane) {
    case 'api_credentials': {
      const seenCredentials = new Set<string>();
      const credentials = auth.credentials
        .map((credential) => String(credential || '').trim())
        .filter(Boolean)
        .filter((credential) => {
          if (!API_CREDENTIAL_TYPE_SET.has(credential)) {
            throw new Error(
              `route definition api_credentials auth contains unknown credential ${credential} for ${id}`,
            );
          }
          if (seenCredentials.has(credential)) return false;
          seenCredentials.add(credential);
          return true;
        }) as Extract<RouteAuthPolicy, { plane: 'api_credentials' }>['credentials'];
      if (credentials.length === 0) {
        throw new Error(
          `route definition api_credentials auth must declare at least one credential for ${id}`,
        );
      }

      let scopes: Extract<RouteAuthPolicy, { plane: 'api_credentials' }>['scopes'] | undefined;
      if (auth.scopes && auth.scopes.length > 0) {
        const seenScopes = new Set<string>();
        scopes = auth.scopes
          .map((scope) => String(scope || '').trim())
          .filter(Boolean)
          .filter((scope) => {
            if (!API_CREDENTIAL_ROUTE_SCOPE_SET.has(scope)) {
              throw new Error(
                `route definition api_credentials auth contains unknown scope ${scope} for ${id}`,
              );
            }
            if (seenScopes.has(scope)) return false;
            seenScopes.add(scope);
            return true;
          }) as Extract<RouteAuthPolicy, { plane: 'api_credentials' }>['scopes'];
        if (!scopes || scopes.length === 0) scopes = undefined;
      }

      return {
        ...auth,
        credentials,
        ...(scopes ? { scopes } : {}),
      };
    }
    case 'public': {
      const rationale = String(auth.rationale || '').trim();
      if (!rationale) {
        throw new Error(`route definition public auth rationale is required for ${id}`);
      }
      const proof = auth.proof ? String(auth.proof || '').trim() : '';
      if (proof && !PUBLIC_PROOF_TYPE_SET.has(proof)) {
        throw new Error(`route definition public auth contains unknown proof ${proof} for ${id}`);
      }
      return {
        ...auth,
        rationale,
        ...(proof
          ? { proof: proof as Extract<RouteAuthPolicy, { plane: 'public' }>['proof'] }
          : {}),
      };
    }
    default:
      return auth;
  }
}

export function defineRoute(definition: RouteDefinition): RouteDefinition {
  return normalizeRouteDefinition(definition, false);
}

export function defineRouteExtension(definition: RouteDefinition): RouteDefinition {
  return normalizeRouteDefinition(definition, true);
}

function normalizeRouteDefinition(
  definition: RouteDefinition,
  allowExtensionServices: boolean,
): RouteDefinition {
  const id = String(definition.id || '').trim();
  const path = String(definition.path || '').trim();
  const summary = String(definition.summary || '').trim();
  if (!id) throw new Error('route definition id is required');
  if (!path) throw new Error(`route definition path is required for ${id}`);
  if (!path.startsWith('/')) throw new Error(`route definition path must start with / for ${id}`);
  if (!summary) throw new Error(`route definition summary is required for ${id}`);
  const aliases = normalizeAliases(path, definition.aliases);
  return Object.freeze({
    ...definition,
    auth: normalizeAuthPolicy(id, definition.auth),
    id,
    path,
    aliases,
    summary,
    requiredServices: normalizeRequiredServices(
      id,
      definition.requiredServices,
      allowExtensionServices,
    ),
  });
}

export function findRouteDefinitionById(
  definitions: readonly RouteDefinition[],
  id: string,
): RouteDefinition | null {
  const normalizedId = String(id || '').trim();
  if (!normalizedId) return null;
  for (const definition of definitions) {
    if (definition.id === normalizedId) return definition;
  }
  return null;
}

function matchesPathPattern(pattern: string, pathname: string): boolean {
  const normalizedPattern = String(pattern || '').trim();
  const normalizedPathname = String(pathname || '').trim();
  if (!normalizedPattern || !normalizedPathname) return false;
  if (normalizedPattern === normalizedPathname) return true;

  const patternSegments = normalizedPattern.split('/').filter(Boolean);
  const pathnameSegments = normalizedPathname.split('/').filter(Boolean);
  if (patternSegments.length !== pathnameSegments.length) return false;

  for (let index = 0; index < patternSegments.length; index += 1) {
    const patternSegment = patternSegments[index];
    const pathnameSegment = pathnameSegments[index];
    if (!patternSegment || !pathnameSegment) return false;
    if (patternSegment.startsWith(':')) continue;
    if (patternSegment !== pathnameSegment) return false;
  }
  return true;
}

export function matchesRouteDefinitionRequest(
  route: RouteDefinition,
  method: string,
  pathname: string,
): boolean {
  const normalizedMethod = String(method || '')
    .trim()
    .toUpperCase();
  if (route.method !== normalizedMethod) return false;
  if (matchesPathPattern(route.path, pathname)) return true;
  for (const alias of route.aliases || []) {
    if (matchesPathPattern(alias, pathname)) return true;
  }
  return false;
}

export function findRouteDefinitionForRequest(
  definitions: readonly RouteDefinition[],
  method: string,
  pathname: string,
): RouteDefinition | null {
  for (const definition of definitions) {
    if (matchesRouteDefinitionRequest(definition, method, pathname)) return definition;
  }
  return null;
}

function publicRoute(
  id: string,
  method: RouteMethod,
  path: string,
  summary: string,
  proof: RouteAuthPolicy & { plane: 'public' },
  requiredServices?: readonly RouteServiceKey[],
  metering: RouteMeteringPolicy = { kind: 'none' },
  aliases?: readonly string[],
): RouteDefinition {
  return defineRoute({
    id,
    surface: 'relay',
    method,
    path,
    aliases,
    auth: proof,
    metering,
    requiredServices,
    summary,
  });
}

function sessionPrincipalRoute(
  id: string,
  method: RouteMethod,
  path: string,
  summary: string,
  requiredServices?: readonly RouteServiceKey[],
  aliases?: readonly string[],
): RouteDefinition {
  return defineRoute({
    id,
    surface: 'relay',
    method,
    path,
    aliases,
    auth: { plane: 'session_principal' },
    metering: { kind: 'none' },
    requiredServices,
    summary,
  });
}

function capabilityGrantRoute(
  id: string,
  method: RouteMethod,
  path: string,
  summary: string,
  scheme: 'any' | 'ecdsa' | 'ed25519',
  requiredServices?: readonly RouteServiceKey[],
): RouteDefinition {
  return defineRoute({
    id,
    surface: 'relay',
    method,
    path,
    auth: { plane: 'capability_grant', scheme },
    metering: { kind: 'none' },
    requiredServices,
    summary,
  });
}

function apiCredentialRoute(
  id: string,
  method: RouteMethod,
  path: string,
  summary: string,
  auth: Extract<RouteAuthPolicy, { plane: 'api_credentials' }>,
  metering: RouteMeteringPolicy,
  requiredServices?: readonly RouteServiceKey[],
): RouteDefinition {
  return defineRoute({
    id,
    surface: 'relay',
    method,
    path,
    auth,
    metering,
    requiredServices,
    summary,
  });
}

export function createRouterApiRouteDefinitions(
  options: RouterApiRouteDefinitionOptions = {},
): RouteDefinition[] {
  const sessionStatePath = String(options.sessionStatePath || '').trim() || '/session/state';
  const sessionStateAliases =
    sessionStatePath === '/session/state' ? undefined : ['/session/state'];
  const signingSessionSealBasePath = resolveSigningSessionSealBasePath(
    options.signingSessionSealBasePath,
  );
  const definitions: RouteDefinition[] = [];

  if (options.enableHealthz) {
    definitions.push(
      publicRoute(
        'router_api_healthz',
        'GET',
        '/healthz',
        'Router API health probe',
        { plane: 'public', rationale: 'Health probes are intentionally public diagnostics.' },
        ROUTER_API_ROUTER_SERVICE,
      ),
    );
  }
  if (options.enableReadyz) {
    definitions.push(
      publicRoute(
        'router_api_readyz',
        'GET',
        '/readyz',
        'Router API readiness probe',
        { plane: 'public', rationale: 'Readiness probes are intentionally public diagnostics.' },
        ROUTER_API_ROUTER_SERVICE,
      ),
    );
  }

  definitions.push(
    publicRoute(
      'relay_well_known_webauthn',
      'GET',
      '/.well-known/webauthn',
      'Related Origin Requests manifest',
      { plane: 'public', rationale: 'Well-known discovery endpoints are intentionally public.' },
      ROUTER_API_WELL_KNOWN_SERVICES,
      { kind: 'none' },
      ['/.well-known/webauthn/'],
    ),
    publicRoute(
      'relay_router_ab_public_keyset',
      'GET',
      ROUTER_AB_PUBLIC_KEYSET_PATH,
      'Router A/B public deployment keyset',
      { plane: 'public', rationale: 'Public key discovery endpoints are intentionally public.' },
      [],
      { kind: 'none' },
      [
        ROUTER_AB_PUBLIC_KEYSET_WELL_KNOWN_PATH,
        `${ROUTER_AB_PUBLIC_KEYSET_PATH}/`,
        `${ROUTER_AB_PUBLIC_KEYSET_WELL_KNOWN_PATH}/`,
      ],
    ),
    sessionPrincipalRoute(
      'wallet_custody_credentials_list',
      'GET',
      '/wallets/:walletId/custody/credentials',
      'List wallet passkey credentials and descriptive activity history',
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_custody_credential_label',
      'POST',
      '/wallets/:walletId/custody/credentials/label',
      'Rename one wallet passkey credential without changing custody',
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    apiCredentialRoute(
      'wallet_registration_setup',
      'POST',
      '/wallets/register/setup',
      'Set up a wallet registration ceremony',
      {
        plane: 'api_credentials',
        /* Publishable key only — no bootstrap token to mint and store, and no
           secret-key fallback on a route the browser calls directly. */
        credentials: ['publishable_key'],
        scopes: ['accounts.create'],
        environmentBinding: 'required',
        originBinding: 'required',
      },
      { kind: 'none' },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
    ),
    publicRoute(
      'wallet_registration_respond',
      'POST',
      '/wallets/register/respond',
      'Verify registration authority and continue the ECDSA ceremony',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale:
          'Registration respond is authorized by the signed setup payload and the registration authority proof.',
      },
      ROUTER_API_WALLET_REGISTRATION_SESSION_SERVICES,
    ),
    publicRoute(
      'wallet_registration_activate',
      'POST',
      '/wallets/register/activate',
      'Activate and finalize one wallet ECDSA registration',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'Registration activation is bound to one unexpired server-retained Router ceremony.',
      },
      ROUTER_API_WALLET_REGISTRATION_SESSION_SERVICES,
      { kind: 'event', action: 'wallet_created' },
    ),
    apiCredentialRoute(
      'wallet_recovery_status',
      'GET',
      '/wallets/:walletId/recovery/status',
      'Report how many recovery codes remain and whether the owner saved them',
      {
        plane: 'api_credentials',
        /* Authenticated on purpose, unlike the spend route beside it. Counting
           how many of ten codes remain is an enumeration oracle for a stranger
           and the entire point of a recovery settings screen for the owner —
           the credential is what separates those two callers. */
        credentials: ['publishable_key'],
        scopes: ['wallets.read'],
        environmentBinding: 'required',
        originBinding: 'required',
      },
      /* Reading status costs nothing to meter: it runs no ceremony and mints
         no material. */
      { kind: 'none' },
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_recovery_codes_rotate',
      'POST',
      '/wallets/recovery/rotate',
      'Replace a wallet recovery code set with freshly wrapped codes',
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_recovery_backup_acknowledge',
      'POST',
      '/wallets/recovery/acknowledge-backup',
      'Record that the owner saved their recovery codes',
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    publicRoute(
      'wallet_recovery_finalize',
      'POST',
      '/wallets/recovery/finalize',
      'Finalize an admitted wallet recovery and install its replacement credential',
      {
        plane: 'public',
        proof: 'recovery_proof',
        rationale:
          'Continues one Refactor 90 admitted recovery operation. The Gateway verifies the complete activation result and consumes the reserved code with the replacement envelope commit.',
      },
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    publicRoute(
      'wallet_recovery_prepare',
      'POST',
      '/wallets/recovery/prepare',
      'Authorize wallet recovery, reserve one code, and return its wrapped custody payload',
      {
        plane: 'public',
        proof: 'recovery_proof',
        rationale:
          'Fresh Email OTP evidence is admitted through Refactor 90. The recovery code remains a custody unwrap factor and is held until final activation commits.',
      },
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    publicRoute(
      'passkey_custody_envelope_retrieve',
      'POST',
      '/wallets/custody/envelope',
      'Retrieve a wallet custody envelope for a device that has none locally',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale:
          'The WebAuthn assertion is the gate: the response is ciphertext the server cannot open, and the KEK derives from a PRF result that never leaves the browser.',
      },
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    publicRoute(
      'wallet_registration_near_provisioning',
      'POST',
      '/wallets/register/near-provisioning',
      'Complete deferred NEAR provisioning for a registered wallet',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'NEAR provisioning is bound to a signed setup payload and a completed Yao activation.',
      },
      ROUTER_API_WALLET_REGISTRATION_SESSION_SERVICES,
    ),
    apiCredentialRoute(
      'wallet_add_signer_intent',
      'POST',
      '/wallets/:walletId/signers/intent',
      'Create a wallet add-signer intent',
      {
        plane: 'api_credentials',
        /* 94C: publishable key only, as registration setup already is. The
           add-signer ceremony and its journals are unchanged — only the
           admission credential moves off the stored managed grant. */
        credentials: ['publishable_key'],
        scopes: ['wallets.signers.create'],
        environmentBinding: 'required',
        originBinding: 'required',
      },
      { kind: 'none' },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
    ),
    publicRoute(
      'wallet_add_signer_start',
      'POST',
      '/wallets/:walletId/signers/start',
      'Start a wallet add-signer ceremony',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'Add-signer start is authorized by a wallet WebAuthn assertion or app-session signer-provisioning policy.',
      },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
    ),
    publicRoute(
      'wallet_add_signer_ecdsa_derivation_respond',
      'POST',
      '/wallets/:walletId/signers/derivation/respond',
      'Continue a wallet add-signer DERIVATION ceremony',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale: 'Add-signer DERIVATION respond is bound to an unexpired ceremony id.',
      },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
    ),
    publicRoute(
      'wallet_add_signer_ecdsa_activation',
      'POST',
      '/wallets/:walletId/signers/derivation/activate',
      'Activate a verified wallet add-signer ECDSA registration',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale: 'Add-signer activation is bound to one pending strict Router ceremony.',
      },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
    ),
    publicRoute(
      'wallet_add_signer_finalize',
      'POST',
      '/wallets/:walletId/signers/finalize',
      'Finalize a wallet add-signer ceremony',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale: 'Add-signer finalize is bound to completed ceremony protocol state.',
      },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
      { kind: 'none' },
    ),
    apiCredentialRoute(
      'wallet_add_auth_method_intent',
      'POST',
      '/wallets/:walletId/auth-methods/intent',
      'Create a wallet add-auth-method intent',
      {
        plane: 'api_credentials',
        credentials: ['publishable_key'],
        scopes: ['wallets.auth_methods.create'],
        environmentBinding: 'required',
        originBinding: 'required',
      },
      { kind: 'none' },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
    ),
    publicRoute(
      'wallet_add_auth_method_start',
      'POST',
      '/wallets/:walletId/auth-methods/start',
      'Start a wallet add-auth-method ceremony',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'Add-auth-method start is authorized by an active wallet authority and a new auth-method proof.',
      },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
    ),
    publicRoute(
      'wallet_add_auth_method_finalize',
      'POST',
      '/wallets/:walletId/auth-methods/finalize',
      'Finalize a wallet add-auth-method ceremony',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'Add-auth-method finalize is bound to a completed add-auth-method ceremony state.',
      },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
      { kind: 'none' },
    ),
    publicRoute(
      'wallet_revoke_auth_method',
      'POST',
      '/wallets/:walletId/auth-methods/revoke',
      'Revoke an active wallet auth method',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale: 'Auth-method revoke is authorized by an active wallet authority.',
      },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
      { kind: 'none' },
    ),
    sessionPrincipalRoute(
      'wallet_ecdsa_key_facts_inventory',
      'POST',
      '/wallets/:walletId/signers/ecdsa/key-facts/inventory',
      'Resolve wallet ECDSA key facts for explicit repair inventory',
      ROUTER_API_WALLET_REGISTRATION_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_near_implicit_account_fund',
      'POST',
      '/wallets/:walletId/near/implicit-account/fund',
      'Fund a wallet implicit NEAR account for local testing',
      ROUTER_API_WALLET_REGISTRATION_SESSION_SERVICES,
    ),
    publicRoute(
      'auth_provider_action',
      'POST',
      '/auth/:provider/:action',
      'Start or verify provider login',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'Provider login bootstrap and verification are intentionally public challenge-based routes.',
      },
      ROUTER_API_AUTH_PROVIDER_SERVICES,
    ),
    publicRoute(
      'sync_account_options',
      'POST',
      '/sync-account/options',
      'Create sync-account challenge options',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale:
          'Sync-account flows are public because they are challenge-driven WebAuthn entrypoints.',
      },
      ROUTER_API_SYNC_ACCOUNT_SERVICES,
    ),
    publicRoute(
      'sync_account_verify',
      'POST',
      '/sync-account/verify',
      'Verify sync-account response',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale: 'Sync-account verification is public because the WebAuthn proof is the gate.',
      },
      ROUTER_API_SYNC_ACCOUNT_SERVICES,
    ),
    publicRoute(
      'router_ab_ed25519_healthz',
      'GET',
      ROUTER_AB_ED25519_HEALTH_PATH,
      'Router A/B Ed25519 health probe',
      {
        plane: 'public',
        rationale: 'Router A/B health probes are intentionally public diagnostics.',
      },
      ROUTER_API_THRESHOLD_RUNTIME_SERVICES,
    ),
    publicRoute(
      'router_ab_ed25519_wallet_session',
      'POST',
      ROUTER_AB_ED25519_WALLET_SESSION_PATH,
      'Issue Router A/B Ed25519 Wallet Session',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale:
          'Router A/B Wallet Session issuance is intentionally public because it validates proof payloads.',
      },
      ROUTER_API_ED25519_WALLET_SESSION_SERVICES,
    ),
    capabilityGrantRoute(
      'router_ab_ed25519_sign_prepare',
      'POST',
      ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH,
      'Prepare Router A/B Ed25519 normal signing',
      'ed25519',
      ROUTER_API_NORMAL_SIGNING_PROXY_SERVICES,
    ),
    capabilityGrantRoute(
      'router_ab_ed25519_sign_finalize',
      'POST',
      ROUTER_AB_ED25519_NORMAL_SIGNING_PATH,
      'Finalize Router A/B Ed25519 normal signing',
      'ed25519',
      ROUTER_API_NORMAL_SIGNING_PROXY_SERVICES,
    ),
    publicRoute(
      'router_ab_ecdsa_derivation_healthz',
      'GET',
      ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH,
      'Router A/B ECDSA derivation health probe',
      {
        plane: 'public',
        rationale: 'Router A/B health probes are intentionally public diagnostics.',
      },
      ROUTER_API_THRESHOLD_RUNTIME_SERVICES,
    ),
    capabilityGrantRoute(
      'router_ab_ecdsa_derivation_export',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH,
      'Export authorized Router A/B ECDSA derivation material',
      'ecdsa',
      ROUTER_API_ECDSA_STRICT_LIFECYCLE_SERVICES,
    ),
    capabilityGrantRoute(
      'router_ab_ecdsa_derivation_recovery',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PATH,
      'Recover Router A/B ECDSA derivation material',
      'ecdsa',
      ROUTER_API_ECDSA_STRICT_LIFECYCLE_SERVICES,
    ),
    capabilityGrantRoute(
      'router_ab_ecdsa_derivation_refresh',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH,
      'Refresh Router A/B ECDSA derivation activation',
      'ecdsa',
      ROUTER_API_ECDSA_STRICT_LIFECYCLE_SERVICES,
    ),
    capabilityGrantRoute(
      'router_ab_ecdsa_derivation_session_activate',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_SESSION_ACTIVATION_PATH,
      'Activate Router A/B ECDSA normal-signing session',
      'ecdsa',
      ROUTER_API_THRESHOLD_SESSION_SERVICES,
    ),
    capabilityGrantRoute(
      'router_ab_ecdsa_derivation_sign_prepare',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH,
      'Prepare Router A/B ECDSA derivation normal signing',
      'ecdsa',
      ROUTER_API_NORMAL_SIGNING_PROXY_SERVICES,
    ),
    capabilityGrantRoute(
      'router_ab_ecdsa_derivation_sign_finalize',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH,
      'Finalize Router A/B ECDSA derivation normal signing',
      'ecdsa',
      ROUTER_API_NORMAL_SIGNING_PROXY_SERVICES,
    ),
    capabilityGrantRoute(
      'router_ab_ecdsa_derivation_presignature_pool_fill_init',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
      'Begin Router A/B ECDSA derivation presignature pool-fill session',
      'ecdsa',
      ROUTER_API_THRESHOLD_SESSION_SERVICES,
    ),
    capabilityGrantRoute(
      'router_ab_ecdsa_derivation_presignature_pool_fill_step',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
      'Continue Router A/B ECDSA derivation presignature pool-fill session',
      'ecdsa',
      ROUTER_API_THRESHOLD_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'webauthn_authenticators',
      'GET',
      '/webauthn/authenticators',
      'List registered WebAuthn authenticators',
      ROUTER_API_WEBAUTHN_AUTHENTICATOR_SERVICES,
    ),
    sessionPrincipalRoute(
      'near_public_keys',
      'GET',
      '/near/public-keys',
      'List NEAR public keys for current session',
      ROUTER_API_NEAR_PUBLIC_KEY_SERVICES,
    ),
    sessionPrincipalRoute(
      'session_state',
      'GET',
      sessionStatePath,
      'Read current session state',
      ['session'],
      sessionStateAliases,
    ),
    publicRoute(
      'session_exchange',
      'POST',
      '/session/exchange',
      'Exchange external assertion for app session',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'Session exchange is intentionally public because OIDC JWTs or passkey assertions are the gate.',
      },
      ROUTER_API_SESSION_EXCHANGE_SERVICES,
    ),
    sessionPrincipalRoute(
      'session_revoke',
      'POST',
      '/session/revoke',
      'Revoke current app session',
      ROUTER_API_SESSION_VERSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'session_refresh',
      'POST',
      '/session/refresh',
      'Refresh current app session',
      ROUTER_API_SESSION_VERSION_SERVICES,
    ),
    publicRoute(
      'wallet_unlock_challenge',
      'POST',
      '/wallet/unlock/challenge',
      'Create wallet unlock challenge',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale: 'Wallet unlock challenge issuance is intentionally public.',
      },
      ROUTER_API_WALLET_UNLOCK_SERVICES,
    ),
    publicRoute(
      'wallet_unlock_verify',
      'POST',
      '/wallet/unlock/verify',
      'Verify wallet unlock challenge',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'Wallet unlock verification is intentionally public because the challenge proof is the gate.',
      },
      ROUTER_API_WALLET_UNLOCK_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_registration_challenge',
      'POST',
      '/wallet/email-otp/registration/challenge',
      'Create Email OTP registration challenge for the current app session',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_registration_seal',
      'POST',
      '/wallet/email-otp/registration/seal',
      'Apply the Email OTP server seal for a new registration blob',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_registration_finalize',
      'POST',
      '/wallet/email-otp/registration/finalize',
      'Finalize Email OTP registration challenge for the current app session',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_login_challenge',
      'POST',
      '/wallet/email-otp/login/challenge',
      'Create Email OTP login challenge for the current app session',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_signing_session_challenge',
      'POST',
      '/wallet/email-otp/signing-session/challenge',
      'Create Email OTP operation challenge for a restored signing session',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_recovery_challenge',
      'POST',
      '/wallet/email-otp/recovery-challenge',
      'Create Email OTP recovery challenge for restoring device-local enrollment escrow',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_login_verify',
      'POST',
      '/wallet/email-otp/login/verify',
      'Verify Email OTP login challenge for the current app session',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_login_verify_and_unseal',
      'POST',
      '/wallet/email-otp/login/verify-and-unseal',
      'Verify Email OTP login challenge and remove the server seal in one request',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_recovery_wrapped_escrows',
      'POST',
      '/wallet/email-otp/recovery-wrapped-escrows',
      'Verify recovery challenge and return recovery-wrapped Email OTP enrollment escrows',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_recovery_key_consume',
      'POST',
      '/wallet/email-otp/recovery-key/consume',
      'Mark an Email OTP recovery key consumed after device-local enrollment escrow restore',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_recovery_key_status',
      'POST',
      '/wallet/email-otp/recovery-key/status',
      'Read non-secret Email OTP recovery-code backup status metadata',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_recovery_key_rotate',
      'POST',
      '/wallet/email-otp/recovery-key/rotate',
      'Replace active Email OTP recovery codes after fresh account authentication',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_recovery_key_attempt_failed',
      'POST',
      '/wallet/email-otp/recovery-key/attempt-failed',
      'Record a failed Email OTP recovery-key unwrap attempt for server-side rate limiting',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_signing_session_verify',
      'POST',
      '/wallet/email-otp/signing-session/verify',
      'Verify Email OTP operation challenge for a restored signing session',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_unseal',
      'POST',
      '/wallet/email-otp/unseal',
      'Remove the server Shamir seal after Email OTP authorization',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_signing_session_unseal',
      'POST',
      '/wallet/email-otp/signing-session/unseal',
      'Remove the server Shamir seal after signing-session Email OTP authorization',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    publicRoute(
      'wallet_email_otp_dev_cleanup_google_registration',
      'POST',
      '/wallet/email-otp/dev/cleanup-google-registration',
      'Clean stale Google Email OTP registration state in local development',
      {
        plane: 'public',
        proof: 'signed_payload',
        rationale:
          'This development-only cleanup path verifies a Google id token before touching stale local registration state.',
      },
      ROUTER_API_EMAIL_OTP_PUBLIC_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_email_otp_dev_otp_outbox',
      'GET',
      '/wallet/email-otp/dev/otp-outbox',
      'Read local development Email OTP outbox entry for the current app session',
      ROUTER_API_EMAIL_OTP_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_state',
      'GET',
      '/wallet/state',
      'Read wallet state',
      ROUTER_API_SESSION_VERSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'wallet_lock',
      'POST',
      '/wallet/lock',
      'Lock wallet',
      ROUTER_API_SESSION_VERSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'auth_identities',
      'GET',
      '/auth/identities',
      'List linked identities',
      ROUTER_API_AUTH_IDENTITY_SERVICES,
    ),
    sessionPrincipalRoute(
      'auth_link',
      'POST',
      '/auth/link',
      'Link an additional identity',
      ROUTER_API_AUTH_IDENTITY_SERVICES,
    ),
    sessionPrincipalRoute(
      'auth_unlink',
      'POST',
      '/auth/unlink',
      'Unlink an identity',
      ROUTER_API_AUTH_IDENTITY_SERVICES,
    ),
  );

  if (options.enableEmailRecoveryPrepare) {
    definitions.push(
      publicRoute(
        'email_recovery_prepare',
        'POST',
        '/email-recovery/prepare',
        'Prepare email recovery flow',
        {
          plane: 'public',
          proof: 'recovery_proof',
          rationale: 'Email recovery preparation is a public recovery bootstrap route.',
        },
        ROUTER_API_EMAIL_RECOVERY_AUTH_SERVICES,
      ),
    );
  }

  if (options.enableRecoverEmail) {
    definitions.push(
      publicRoute(
        'recover_email',
        'POST',
        '/recover-email',
        'Process email recovery ingress',
        {
          plane: 'public',
          rationale:
            'Recover-email remains auth-free for now and should be revisited if it starts incurring billable execution cost.',
        },
        ROUTER_API_RECOVER_EMAIL_SERVICES,
      ),
    );
  }

  if (options.enableSigningSessionSeal) {
    definitions.push(
      sessionPrincipalRoute(
        'signing_session_seal_apply_server_seal',
        'POST',
        buildSigningSessionSealApplyPath(signingSessionSealBasePath),
        'Apply signing session server seal',
        ['signingSessionSeal', 'session'],
      ),
      sessionPrincipalRoute(
        'signing_session_seal_remove_server_seal',
        'POST',
        buildSigningSessionSealRemovePath(signingSessionSealBasePath),
        'Remove signing session server seal',
        ['signingSessionSeal', 'session'],
      ),
    );
  }

  return definitions;
}
