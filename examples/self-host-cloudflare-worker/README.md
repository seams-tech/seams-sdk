# Self-Hosted Cloudflare Signing Worker

Minimal Cloudflare Worker template for customer-operated threshold signing.

This template exposes only the self-host signing surface:

- health and readiness routes
- threshold Ed25519 routes
- threshold ECDSA routes
- `ThresholdStoreDurableObject` for signing-session state

It intentionally does not include hosted console, billing, webhooks, gas
sponsorship, policy, or hosted root-share provisioning code.

## Secrets

Configure these with `wrangler secret put`:

```sh
wrangler secret put RELAYER_ACCOUNT_ID
wrangler secret put RELAYER_PRIVATE_KEY
```

Strict Router A/B root shares belong in their respective Deriver role secret
stores. This Router API worker does not accept signing-root imports.

## Local Shape

```sh
pnpm install
wrangler dev
```
