import type {
  RouterAbEcdsaDerivationLinkedDeviceWalletSessionClaims,
  RouterAbEd25519LinkedDeviceWalletSessionClaims,
} from '../../core/ThresholdService/validation';
import type { RouterApiKeyPrincipal, SessionClaims } from './routerApi';
import { ROUTER_API_CREDENTIAL_SCOPES } from './apiCredentialPorts';

export type RouteAuthPlane =
  | 'api_credentials'
  | 'session_principal'
  | 'capability_grant'
  | 'public';

export const API_CREDENTIAL_TYPES = ['publishable_key', 'secret_key'] as const;
export type ApiCredentialType = (typeof API_CREDENTIAL_TYPES)[number];

export const API_CREDENTIAL_ROUTE_SCOPES = ROUTER_API_CREDENTIAL_SCOPES;
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

export type RouteAuthPolicy =
  | {
      plane: 'api_credentials';
      credentials: ApiCredentialType[];
      scopes?: ApiCredentialRouteScope[];
      environmentBinding?: 'required' | 'optional';
      originBinding?: 'required' | 'optional';
      ipBinding?: 'required' | 'optional';
    }
  | {
      plane: 'session_principal';
    }
  | {
      plane: 'capability_grant';
      scheme?: ThresholdSessionScheme;
    }
  | {
      plane: 'public';
      proof?: PublicProofType;
      rationale: string;
    };

export type RoutePrincipal =
  | {
      kind: 'api_credentials';
      principal: RouterApiKeyPrincipal;
      credentialType: ApiCredentialType;
    }
  | {
      kind: 'session_principal';
      claims: SessionClaims;
    }
  | {
      kind: 'capability_grant';
      claims:
        | RouterAbEd25519LinkedDeviceWalletSessionClaims
        | RouterAbEcdsaDerivationLinkedDeviceWalletSessionClaims;
    }
  | {
      kind: 'public';
    };

export type RoutePolicyFailureCode =
  | 'forbidden'
  | 'route_auth_not_configured'
  | 'service_not_configured'
  | 'unauthorized';
