# Self-Hosted Cloudflare Signing Worker

Minimal Cloudflare Worker template for customer-operated threshold signing.

This template exposes only the self-host signing surface:

- health and readiness routes
- threshold Ed25519 routes
- threshold ECDSA routes
- `ThresholdStoreDurableObject` for threshold and signing-root state

It intentionally does not include hosted console, billing, webhooks, gas
sponsorship, policy, or hosted root-share provisioning code.

## Secrets

Configure these with `wrangler secret put`:

```sh
wrangler secret put RELAYER_ACCOUNT_ID
wrangler secret put RELAYER_PRIVATE_KEY
wrangler secret put SIGNING_ROOT_SECRET_SHARE_KEK_B64U
wrangler secret put SELF_HOST_ADMIN_TOKEN
```

Do not put `k_org` or plaintext signing-root shares in `wrangler.toml`.
Tenant-root shares should be imported through the authenticated self-host import
route.

## Project-Root Import

The default admin route uses `Authorization: Bearer $SELF_HOST_ADMIN_TOKEN`.

```sh
curl -X POST "$WORKER_URL/self-host/signing-root/import" \
  -H "authorization: Bearer $SELF_HOST_ADMIN_TOKEN" \
  -H "content-type: application/json" \
  --data @signing-root-bundle.json
```

Check import status:

```sh
curl "$WORKER_URL/self-host/signing-root/status?projectId=$PROJECT_ID&signingRootVersion=$ROOT_VERSION" \
  -H "authorization: Bearer $SELF_HOST_ADMIN_TOKEN"
```

## Local Shape

```sh
pnpm install
wrangler dev
```

`SIGNING_ROOT_SECRET_SHARE_KEK_B64U` is the customer-owned KEK used by this template to
decrypt imported sealed signing-root shares in memory. Production deployments
can replace that resolver with a customer KMS/HSM adapter without changing
wallet identity.
