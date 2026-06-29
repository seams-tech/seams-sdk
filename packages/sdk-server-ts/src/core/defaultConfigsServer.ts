// Server-only defaults and helpers.
//
// Keep this separate from `client/src/core/config/defaultConfigs.ts` so browser bundles don't
// accidentally pull in server-oriented defaults/config.

// Threshold node roles.
// Coordinator is the default for public registration/session routes and Router A/B bridge handlers.
export const THRESHOLD_NODE_ROLE_COORDINATOR = 'coordinator' as const;
export const THRESHOLD_NODE_ROLE_DEFAULT = THRESHOLD_NODE_ROLE_COORDINATOR;

// Threshold store defaults (Cloudflare Workers + Durable Objects).
export const THRESHOLD_DO_OBJECT_NAME_DEFAULT = 'threshold-store' as const;

// Default base prefix for threshold keyspaces when a host does not specify any prefix variables.
// This matches the SDK's published prefix defaults (w3a:threshold-ed25519:*).
export const THRESHOLD_PREFIX_DEFAULT = 'w3a' as const;

// DKIM verifier contract used by server-side email recovery when no override is provided.
export const EMAIL_DKIM_VERIFIER_CONTRACT_DEFAULT = 'email-dkim-verifier-v1.testnet' as const;
