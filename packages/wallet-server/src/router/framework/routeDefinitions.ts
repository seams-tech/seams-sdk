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
  enableHealthz?: boolean;
  enableSigningSessionSeal?: boolean;
  enableReadyz?: boolean;
  signingSessionSealBasePath?: string;
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
  'emailOtp',
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_WEBAUTHN_AUTHENTICATOR_SERVICES = [
  'webAuthn',
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_NEAR_PUBLIC_KEY_SERVICES = [
  'nearFunding',
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_PASSKEY_CUSTODY_SERVICES = [
  'passkeyCustody',
  'walletAuthMethods',
  'webAuthn',
  'emailOtp',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_LINKED_DEVICE_PASSKEY_SERVICES = [
  'publishableKeyAuth',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_WALLET_UNLOCK_SERVICES = [
  'walletUnlock',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_HOSTED_SESSION_EXCHANGE_SERVICES = [
  'session',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_EMAIL_OTP_PUBLIC_SERVICES = [
  'emailOtp',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_EMAIL_OTP_CHALLENGE_SERVICES = [
  'emailOtp',
  'walletAuthMethods',
] as const satisfies readonly CoreRouteServiceKey[];
const ROUTER_API_AUTH_IDENTITY_SERVICES = [
  'identity',
  'webAuthn',
  'emailOtp',
  'session',
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
    publicRoute(
      'wallet_custody_credentials_list',
      'POST',
      '/wallets/:walletId/custody/credentials',
      'List wallet passkey credentials and descriptive activity history',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale: 'Fresh operation-bound owner proof is required.',
      },
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    publicRoute(
      'wallet_custody_email_otp_challenge',
      'POST',
      '/wallets/custody/email-otp/challenge',
      'Issue one operation-bound Email OTP challenge for wallet custody administration',
      {
        plane: 'public',
        rationale:
          'The challenge is bound to the exact operation and Origin; verification supplies the fresh factor proof.',
      },
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    publicRoute(
      'wallet_custody_credential_label',
      'POST',
      '/wallets/:walletId/custody/credentials/label',
      'Rename one wallet passkey credential without changing custody',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale: 'Fresh operation-bound owner proof is required.',
      },
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
    apiCredentialRoute(
      'linked_device_target_preparation',
      'GET',
      '/wallet/device-linking/v1/sessions/:linkSessionId/target-preparation',
      'Prepare a linked-device target Passkey ceremony',
      {
        plane: 'api_credentials',
        credentials: ['publishable_key'],
        environmentBinding: 'required',
        originBinding: 'required',
      },
      { kind: 'none' },
      ROUTER_API_LINKED_DEVICE_PASSKEY_SERVICES,
    ),
    apiCredentialRoute(
      'linked_device_target_credential',
      'POST',
      '/wallet/device-linking/v1/sessions/:linkSessionId/credential',
      'Verify a linked-device target Passkey credential',
      {
        plane: 'api_credentials',
        credentials: ['publishable_key'],
        environmentBinding: 'required',
        originBinding: 'required',
      },
      { kind: 'none' },
      ROUTER_API_LINKED_DEVICE_PASSKEY_SERVICES,
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
    publicRoute(
      'wallet_recovery_status',
      'GET',
      '/wallets/:walletId/recovery/status',
      'Report how many recovery codes remain and whether the owner saved them',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale: 'Fresh operation-bound owner proof is required.',
      },
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    publicRoute(
      'wallet_recovery_codes_rotate',
      'POST',
      '/wallets/recovery/rotate',
      'Replace a wallet recovery code set with freshly wrapped codes',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale: 'Fresh operation-bound owner proof is required.',
      },
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    publicRoute(
      'wallet_recovery_codes_read',
      'POST',
      '/wallets/recovery/read',
      'Read the opaque wallet recovery envelope set for client-side rotation',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale: 'Fresh operation-bound owner proof is required.',
      },
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    publicRoute(
      'wallet_recovery_backup_acknowledge',
      'POST',
      '/wallets/recovery/acknowledge-backup',
      'Record that the owner saved their recovery codes',
      {
        plane: 'public',
        rationale:
          'Acknowledgement only clears backup-reminder state after the client displays its locally retained codes.',
      },
      ['passkeyCustody'],
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
      'wallet_recovery_google_verify',
      'POST',
      '/wallets/recovery/google/verify',
      'Verify the recovery-scoped Google identity and issue its Email OTP challenge',
      {
        plane: 'public',
        proof: 'recovery_proof',
        rationale:
          'The request continues a prepared recovery operation whose recovery code reservation and target are already bound server-side.',
      },
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    publicRoute(
      'wallet_recovery_email_otp_verify',
      'POST',
      '/wallets/recovery/email-otp/verify',
      'Verify the Email OTP issued for a recovery-scoped Google identity',
      {
        plane: 'public',
        proof: 'recovery_proof',
        rationale:
          'The OTP is checked against the prepared recovery operation and its server-issued challenge.',
      },
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    publicRoute(
      'wallet_recovery_email_otp_release',
      'POST',
      '/wallets/recovery/email-otp/release',
      'Release the verified recovery Email OTP factor for replacement enrollment',
      {
        plane: 'public',
        proof: 'recovery_proof',
        rationale:
          'Factor material is released only after the recovery operation records a verified Email OTP.',
      },
      ROUTER_API_PASSKEY_CUSTODY_SERVICES,
    ),
    publicRoute(
      'wallet_recovery_google_email_otp_finalize',
      'POST',
      '/wallets/recovery/google-email-otp/finalize',
      'Finalize an admitted Google/Email OTP wallet recovery',
      {
        plane: 'public',
        proof: 'recovery_proof',
        rationale:
          'Finalization resolves the verified Google/Email OTP recovery attempt by its server-issued operation and reservation identities.',
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
    sessionPrincipalRoute(
      'wallet_custody_envelope_ownership_upgrade',
      'POST',
      '/wallets/:walletId/custody/envelope/ownership',
      'Bind a pre-109C wallet custody envelope to the auth method that opened it',
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
          'Add-signer start is authorized by a wallet WebAuthn assertion or signer-provisioning policy.',
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
      'wallet_add_auth_method_email_otp_challenge',
      'POST',
      '/wallets/:walletId/auth-methods/email-otp/challenge',
      'Send the enrollment code for an Email OTP auth-method addition',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'The add-auth-method intent grant is the gate: the code is bound to that intent digest, delivered only to the address the intent already names.',
      },
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
      '/wallets/:walletId/auth-methods/:walletAuthMethodId/revoke',
      'Revoke an active wallet auth method',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale: 'Auth-method revoke is authorized by an active wallet authority.',
      },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
      { kind: 'none' },
    ),
    publicRoute(
      'wallet_ecdsa_key_facts_inventory',
      'POST',
      '/wallets/:walletId/signers/ecdsa/key-facts/inventory',
      'Resolve wallet ECDSA key facts for explicit repair inventory',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale: 'A WebAuthn assertion or opaque ECDSA Wallet Session authorizes inventory.',
      },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
    ),
    publicRoute(
      'wallet_near_implicit_account_fund',
      'POST',
      '/wallets/:walletId/near/implicit-account/fund',
      'Fund a wallet implicit NEAR account for local testing',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'An active owner or linked-device Ed25519 Wallet Session authorizes local NEAR funding.',
      },
      ROUTER_API_WALLET_REGISTRATION_SERVICES,
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
    sessionPrincipalRoute(
      'router_ab_ed25519_sign_prepare',
      'POST',
      ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH,
      'Prepare Router A/B Ed25519 normal signing',
      ROUTER_API_NORMAL_SIGNING_PROXY_SERVICES,
    ),
    sessionPrincipalRoute(
      'router_ab_ed25519_sign_finalize',
      'POST',
      ROUTER_AB_ED25519_NORMAL_SIGNING_PATH,
      'Finalize Router A/B Ed25519 normal signing',
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
    sessionPrincipalRoute(
      'router_ab_ecdsa_derivation_export',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH,
      'Export authorized Router A/B ECDSA derivation material',
      ROUTER_API_ECDSA_STRICT_LIFECYCLE_SERVICES,
    ),
    sessionPrincipalRoute(
      'router_ab_ecdsa_derivation_refresh',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH,
      'Refresh Router A/B ECDSA derivation activation',
      ROUTER_API_ECDSA_STRICT_LIFECYCLE_SERVICES,
    ),
    sessionPrincipalRoute(
      'router_ab_ecdsa_derivation_session_activate',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_SESSION_ACTIVATION_PATH,
      'Activate Router A/B ECDSA normal-signing session',
      ROUTER_API_THRESHOLD_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'router_ab_ecdsa_derivation_sign_prepare',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH,
      'Prepare Router A/B ECDSA derivation normal signing',
      ROUTER_API_NORMAL_SIGNING_PROXY_SERVICES,
    ),
    sessionPrincipalRoute(
      'router_ab_ecdsa_derivation_sign_finalize',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH,
      'Finalize Router A/B ECDSA derivation normal signing',
      ROUTER_API_NORMAL_SIGNING_PROXY_SERVICES,
    ),
    sessionPrincipalRoute(
      'router_ab_ecdsa_derivation_presignature_pool_fill_init',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
      'Begin Router A/B ECDSA derivation presignature pool-fill session',
      ROUTER_API_THRESHOLD_SESSION_SERVICES,
    ),
    sessionPrincipalRoute(
      'router_ab_ecdsa_derivation_presignature_pool_fill_step',
      'POST',
      ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
      'Continue Router A/B ECDSA derivation presignature pool-fill session',
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
      'wallet_session_exchange_issue',
      'POST',
      '/wallet/session/exchange/issue',
      'Issue a one-time origin-bound hosted-wallet exchange delivery',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale: 'An opaque Wallet Session bearer and exact app origin bind the handoff.',
      },
      ROUTER_API_HOSTED_SESSION_EXCHANGE_SERVICES,
    ),
    publicRoute(
      'wallet_session_exchange_redeem',
      'POST',
      '/wallet/session/exchange/redeem',
      'Redeem a one-time origin-bound hosted-wallet exchange delivery',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale: 'The one-time code, nonce, and wallet origin bind the handoff.',
      },
      ROUTER_API_HOSTED_SESSION_EXCHANGE_SERVICES,
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
    publicRoute(
      'wallet_email_otp_challenge',
      'POST',
      '/wallet/email-otp/challenge',
      'Create an operation-bound Email OTP challenge',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'The server binds challenge delivery to the active wallet owner authority and request Origin.',
      },
      ROUTER_API_EMAIL_OTP_CHALLENGE_SERVICES,
    ),
    publicRoute(
      'wallet_email_otp_factor_release',
      'POST',
      '/wallet/email-otp/factor-release',
      'Consume an operation-bound Email OTP grant and release factor material to a worker',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'The single-use Email OTP grant is bound to the active wallet owner identity and encrypted directly to the requesting worker.',
      },
      ROUTER_API_EMAIL_OTP_PUBLIC_SERVICES,
    ),
    publicRoute(
      'wallet_email_otp_registration_seal',
      'POST',
      '/wallet/email-otp/registration/seal',
      'Seal an Email OTP enrollment ciphertext with the server enrollment key',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'The input and output are opaque ciphertext; wallet authority is verified when registration commits the enrollment.',
      },
      ROUTER_API_EMAIL_OTP_PUBLIC_SERVICES,
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
    publicRoute(
      'wallet_email_otp_dev_outbox',
      'POST',
      '/wallet/email-otp/dev/otp-outbox',
      'Read an Email OTP from the local development outbox',
      {
        plane: 'public',
        proof: 'signed_payload',
        rationale:
          'The development-only outbox verifies a Google id token and remains disabled unless explicitly configured.',
      },
      ROUTER_API_EMAIL_OTP_PUBLIC_SERVICES,
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
