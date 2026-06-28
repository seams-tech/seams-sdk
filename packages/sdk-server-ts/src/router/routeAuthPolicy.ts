import type {
  ThresholdEcdsaSessionClaims,
  ThresholdEd25519SessionClaims,
} from '../core/ThresholdService/validation';
import type { ConsoleAuthClaims, ConsoleRole } from './consoleAuth';
import type { RouterApiKeyPrincipal, SessionClaims } from './routerApi';

import { API_CREDENTIAL_SCOPES } from "@shared/console/apiKeyScopes";

export type RouteAuthPlane =
  | 'console'
  | 'api_credentials'
  | 'user_session'
  | 'threshold_session'
  | 'public';

export const API_CREDENTIAL_TYPES = [
  'publishable_key',
  'secret_key',
  'bootstrap_token',
] as const;
export type ApiCredentialType = (typeof API_CREDENTIAL_TYPES)[number];

export const API_CREDENTIAL_ROUTE_SCOPES = API_CREDENTIAL_SCOPES;
export type ApiCredentialRouteScope = (typeof API_CREDENTIAL_ROUTE_SCOPES)[number];

export const PUBLIC_PROOF_TYPES = [
  'challenge_exchange',
  'intent_grant',
  'recovery_proof',
  'signed_payload',
  'threshold_protocol_state',
  'webauthn',
] as const;
export type PublicProofType = (typeof PUBLIC_PROOF_TYPES)[number];

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
      plane: 'api_credentials';
      credentials: ApiCredentialType[];
      scopes?: ApiCredentialRouteScope[];
      environmentBinding?: 'required' | 'optional';
      originBinding?: 'required' | 'optional';
      ipBinding?: 'required' | 'optional';
    }
  | {
      plane: 'user_session';
    }
  | {
      plane: 'threshold_session';
      scheme?: ThresholdSessionScheme;
    }
  | {
      plane: 'public';
      proof?: PublicProofType;
      rationale: string;
    };

export type RoutePrincipal =
  | {
      kind: 'console';
      claims: ConsoleAuthClaims;
    }
  | {
      kind: 'api_credentials';
      principal: RouterApiKeyPrincipal;
      credentialType: ApiCredentialType;
    }
  | {
      kind: 'user_session';
      claims: SessionClaims;
    }
  | {
      kind: 'threshold_session';
      claims: ThresholdEd25519SessionClaims | ThresholdEcdsaSessionClaims;
    }
  | {
      kind: 'public';
    };

export type RoutePolicyFailureCode =
  | 'forbidden'
  | 'route_auth_not_configured'
  | 'service_not_configured'
  | 'unauthorized';
