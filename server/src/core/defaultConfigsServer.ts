// Server-only defaults and helpers.
//
// Keep this separate from `client/src/core/config/defaultConfigs.ts` so browser bundles don't
// accidentally pull in server-oriented defaults/config.

// Threshold node roles.
// Coordinator is the default because it exposes the public `/threshold-ed25519/sign/*` endpoints.
export const THRESHOLD_NODE_ROLE_COORDINATOR = 'coordinator' as const;
export const THRESHOLD_NODE_ROLE_DEFAULT = THRESHOLD_NODE_ROLE_COORDINATOR;

// Threshold Ed25519 store defaults (Cloudflare Workers + Durable Objects).
export const THRESHOLD_ED25519_DO_OBJECT_NAME_DEFAULT = 'threshold-ed25519-store' as const;

// Default base prefix for threshold keyspaces when a host does not specify any prefix variables.
// This matches the SDK's legacy prefix defaults (w3a:threshold-ed25519:*).
export const THRESHOLD_PREFIX_DEFAULT = 'w3a' as const;

// DKIM verifier contract used by server-side email recovery when no override is provided.
export const EMAIL_DKIM_VERIFIER_CONTRACT_DEFAULT = 'email-dkim-verifier-v1.testnet' as const;
