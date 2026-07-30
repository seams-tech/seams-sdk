# API credentials

Seams environments expose two credential kinds:

- `publishable_key` is browser-safe. It is bound to one project environment
  and an allowlist of web origins.
- `secret_key` is server-only. It must never be shipped in browser bundles or
  frontend configuration.

Both credentials are stored in the Console D1 `api_keys` table. Secret values
are shown once when created. The database retains only the verification
material and display-safe prefix.

## Browser registration

The browser sends its environment's `publishable_key` directly to
`POST /wallets/register/setup` as a bearer credential together with
`X-Seams-Environment-Id`. The Gateway validates the key, environment, origin,
scope, and project status before it creates the ceremony.

The remaining registration routes carry their own ceremony proofs:

1. `POST /wallets/register/setup`
2. `POST /wallets/register/respond`
3. `POST /wallets/register/activate`

Deferred NEAR provisioning completes through
`POST /wallets/register/near-provisioning` after the wallet is durable.

Add-signer and add-auth-method intent routes use the same publishable-key,
environment, and origin binding. Their later ceremony routes use the
request-specific wallet proof.

## Backend access

Backends use `secret_key` only on routes whose route definition explicitly
accepts it. A backend must pass the key as a bearer credential and keep it out
of browser-visible responses, logs, and build artifacts.

## Console behavior

The API keys page lets an authorized organization operator:

- create a publishable or secret key for the selected environment;
- set origin restrictions for a publishable key;
- view key kind, prefix, status, scopes, and timestamps;
- revoke a key without revealing its secret again.

Creating and revoking credentials are audited. Authorization failures do not
reveal whether a differently scoped credential exists.

## Security requirements

- Validate credentials once at the HTTP boundary.
- Require environment binding on browser credential routes.
- Require origin binding for publishable-key requests.
- Keep credential lifecycle state in Console D1.
- Keep wallet, signing, and custody state outside the credential store.
- Never infer authorization from a display prefix or client-supplied key kind.
