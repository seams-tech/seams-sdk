import type {
  ThresholdEcdsaSessionClaims,
  ThresholdEd25519SessionClaims,
} from '../core/ThresholdService/validation';
import type { ConsoleAuthClaims, ConsoleRole } from './console';
import type { RelayApiKeyPrincipal, SessionClaims } from './relay';

import { MACHINE_API_KEY_SCOPES } from '../../../shared/src/console/apiKeyScopes';

export type RouteAuthPlane =
  | 'console'
  | 'machine'
  | 'app_session'
  | 'threshold_session'
  | 'public'
  | 'internal';

export const MACHINE_CREDENTIAL_TYPES = [
  'publishable_key',
  'secret_key',
  'bootstrap_token',
] as const;
export type MachineCredentialType = (typeof MACHINE_CREDENTIAL_TYPES)[number];

export const MACHINE_ROUTE_SCOPES = MACHINE_API_KEY_SCOPES;
export type MachineRouteScope = (typeof MACHINE_ROUTE_SCOPES)[number];

export const PUBLIC_PROOF_TYPES = [
  'challenge_exchange',
  'recovery_proof',
  'signed_payload',
  'threshold_protocol_state',
  'webauthn',
] as const;
export type PublicProofType = (typeof PUBLIC_PROOF_TYPES)[number];

export const INTERNAL_AUTH_MECHANISMS = ['hmac', 'mtls', 'signed_token'] as const;
export type InternalAuthMechanism = (typeof INTERNAL_AUTH_MECHANISMS)[number];
export const THRESHOLD_SESSION_SCHEMES = ['any', 'ecdsa', 'ed25519'] as const;
export type ThresholdSessionScheme = (typeof THRESHOLD_SESSION_SCHEMES)[number];
export type ConsoleRouteRole = ConsoleRole;

export type RouteAuthPolicy =
  | {
      plane: 'console';
      roles?: ConsoleRouteRole[];
      forbiddenMessage?: string;
    }
  | {
      plane: 'machine';
      credentials: MachineCredentialType[];
      scopes?: MachineRouteScope[];
      environmentBinding?: 'required' | 'optional';
      originBinding?: 'required' | 'optional';
      ipBinding?: 'required' | 'optional';
    }
  | {
      plane: 'app_session';
    }
  | {
      plane: 'threshold_session';
      scheme?: ThresholdSessionScheme;
    }
  | {
      plane: 'public';
      proof?: PublicProofType;
      rationale: string;
    }
  | {
      plane: 'internal';
      mechanism: InternalAuthMechanism;
      rationale?: string;
    };

export type RoutePrincipal =
  | {
      kind: 'console';
      claims: ConsoleAuthClaims;
    }
  | {
      kind: 'machine';
      principal: RelayApiKeyPrincipal;
      credentialType: MachineCredentialType;
    }
  | {
      kind: 'app_session';
      claims: SessionClaims;
    }
  | {
      kind: 'threshold_session';
      claims: ThresholdEd25519SessionClaims | ThresholdEcdsaSessionClaims;
    }
  | {
      kind: 'public';
    }
  | {
      kind: 'internal';
      service: string;
    };

export type RoutePolicyFailureCode =
  | 'forbidden'
  | 'route_auth_not_configured'
  | 'service_not_configured'
  | 'unauthorized';
