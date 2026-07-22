# Production Testnet Demo Readiness Patch

Date created: July 22, 2026

Status: implementation complete for configuration and delivery wiring; measurement and deployment validation pending

## Scope

This patch addresses three issues observed on `seams.sh`:

1. mixed-wallet registration remains on the `Creating...` step for roughly ten
   seconds for both passkey and Email OTP accounts;
2. implicit NEAR testnet account funding is disabled in the deployed Gateway;
3. Email OTP cannot be delivered because the production deployment selects an
   email-provider mode whose provider adapter is not configured.

The target is a production-quality deployment of the public live demo against
testnet. Mainnet deployments must reject every demo-only capability.

## Current Findings

### Registration latency

Passkey and Email OTP registration have different authentication steps, then
join the same mixed signer-provisioning path in
`packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`.

That shared path:

1. warms browser signing resources and obtains a managed registration grant;
2. starts the registration ceremony;
3. starts Ed25519 Yao work;
4. runs strict threshold ECDSA registration while Yao work is in flight;
5. waits for both branches;
6. finalizes server state, persists local material, and activates warm sessions.

The shared delay therefore points to signer provisioning, Worker/Wasm startup,
cross-Worker transport, or final persistence rather than passkey or OTP
collection. Ed25519 and ECDSA work is already overlapped; another parallel path
must only be added if timing evidence identifies independent serialized work.

The SDK already records detailed timing buckets and route diagnostics, including
registration start, ECDSA ceremony, finalize, local persistence, warm-session
sealing, and Worker startup. These summaries are currently emitted only when
`__SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS` is set in the page.

### NEAR testnet funding

The Gateway has all required funding inputs when `optional.nearRelayer` and
`RELAYER_PRIVATE_KEY` are configured. The renderer now derives
`ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING` from the validated runtime profile:
it is enabled only for `testnet_live_demo` and disabled for service and
mainnet profiles.

### Email OTP delivery

Fresh public staging and production target generation now selects the
`testnet_live_demo` profile, which requires the NEAR testnet relayer and uses
`demo_code_response` by default. Operators can explicitly select
`testnet_service` or `mainnet_service` when they are deploying a service-only
environment. The server-side `provider_and_demo_code` branch is available to
embeddings that supply a real email-provider adapter. Repository deployment
tooling rejects that mode until the deployed Gateway wires a provider.

`CloudflareD1EmailOtpDeliveryRuntime` rejects development delivery modes in
the deployed profiles. The public demo uses an explicit, origin-gated demo
branch instead of reusing `log` or `dev_d1_outbox`, which would either hide the
code from the browser or weaken the production guard.

## Configuration Model

Deployment target, chain network, and demo policy are independent dimensions.
Replace behavior derived from `target === 'production'` with one validated
profile in the Gateway deployment document:

```ts
type GatewayRuntimeProfile =
  | {
      kind: 'testnet_live_demo';
      nearFunding: {
        kind: 'implicit_account_relayer';
        network: 'near_testnet';
      };
      emailOtpDelivery: {
        kind: 'demo_code_response';
        allowedOrigins: readonly string[];
      };
    }
  | {
      kind: 'testnet_service';
      nearFunding: { kind: 'disabled' };
      emailOtpDelivery: { kind: 'email_provider' };
    }
  | {
      kind: 'mainnet_service';
      nearFunding: { kind: 'disabled' };
      emailOtpDelivery: { kind: 'email_provider' };
    };
```

The parser must reject:

- implicit test funding with a mainnet RPC or mainnet profile;
- demo OTP responses outside `testnet_live_demo`;
- demo OTP responses without an exact HTTPS origin allowlist;
- a configured NEAR relayer without its private key, RPC URL, account ID, and
  initial balance;
- `email_provider` without a configured provider once that adapter is added.

No optional booleans should control these core branches after parsing.

## Phase 0: Measure Registration Critical Path

1. Use the existing privacy-safe `registration_timing_summary_v1` diagnostic
   payload without wallet IDs, credential IDs, key material, JWTs, or OTP data.
   It remains opt-in during measurement and is not emitted as production
   telemetry by default.
2. Correlate the opt-in client summary with the `testnet_live_demo` deployment
   profile and an opaque registration trace ID during the measurement window.
3. Record cold and warm runs separately. Capture at least passkey and Email OTP
   samples for each condition.
4. Establish budgets for:
   - browser/Worker warmup;
   - registration start;
   - Ed25519 Yao;
   - strict ECDSA ceremony;
   - registration finalize;
   - local persistence and warm-session activation.

Acceptance:

- one timing record accounts for at least 90% of observed wall time;
- passkey and Email OTP runs identify the same shared bottleneck or show a
  measured auth-specific difference;
- production logs contain no auth secrets or wallet key material.

## Phase 1: Reduce Registration Latency

Implement only the optimizations justified by Phase 0:

1. Preserve the existing overlap between Ed25519 Yao and strict ECDSA
   registration and add a regression check that they remain concurrent.
2. If Worker/Wasm initialization dominates, initialize reusable modules at
   isolate startup and prewarm the browser worker while the user completes the
   authentication UI.
3. If cross-Worker transport dominates, remove duplicated serialization or
   repeated fetches while retaining service-binding isolation and every
   cryptographic verification.
4. If finalization dominates, combine related D1 writes into the existing
   transaction boundary and remove redundant read-backs that are not security
   postconditions.
5. If local sealing dominates, reuse the already-live worker and avoid repeated
   imports while keeping plaintext material inside the secure worker boundary.
6. Keep registration success atomic: the UI must not report success until both
   signer branches, durable state, and local custody records are committed.

Acceptance:

- warm and cold p50/p95 are reported before and after the change;
- the shared critical path is materially shorter;
- registered Ed25519 and ECDSA public identities are unchanged;
- passkey and Email OTP intended-behaviour registration matrices still pass.

## Phase 2: Enable Demo NEAR Testnet Funding

1. Add the `testnet_live_demo` runtime profile to the staging and production
   testnet deployment values used by `staging.seams.sh` and `seams.sh`.
2. Render implicit funding from the parsed profile instead of hard-coding
   `ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING=false`.
3. Continue sourcing `RELAYER_PRIVATE_KEY` from the protected
   `~/.seams/<target>-deployment.env` file and the target Gateway GitHub secret.
4. Keep the relayer account ID, public key, testnet RPC URL, and initial funding
   amount in `GATEWAY_DEPLOYMENT_CONFIG_JSON`.
5. Extend `wallet-core:deploy:env-update` so this operator-owned configuration
   can be uploaded without rotating Router A/B identities or other generated
   secrets.
6. Add a deployment preflight that verifies the RPC reports NEAR testnet and
   that the relayer account has enough balance. Never print the private key.
7. Add rate and amount limits for the public faucet path and retain the existing
   wallet-session authorization requirement.

Acceptance:

- a newly registered implicit NEAR account on the live demo receives the
  configured testnet amount and can submit its first transaction;
- repeated funding is denied or rate-limited according to policy;
- mainnet profiles cannot start with implicit test funding enabled;
- updating faucet configuration does not rotate deployment identities.

## Phase 3: Add Explicit Demo OTP Delivery

1. Add `demo_code_response` as a distinct server delivery mode available only
   in the `testnet_live_demo` profile.
2. Support `provider_and_demo_code` as the combined branch. It dispatches the
   configured provider and returns `otpCode` to the exact demo origin from the
   same challenge result.
3. Model challenge delivery as a discriminated union:

```ts
type EmailOtpChallengeDelivery =
  | {
      kind: 'provider';
      status: 'sent' | 'reused';
      emailHint: string;
    }
  | {
      kind: 'demo_code_response';
      status: 'sent' | 'reused';
      emailHint: string;
      otpCode: string;
    }
  | {
      kind: 'provider_and_demo_code';
      status: 'sent' | 'reused';
      emailHint: string;
      otpCode: string;
    };
```

4. Return `otpCode` only from the explicit demo branch and only when the request
   origin exactly matches the configured demo-origin allowlist.
5. Parse that branch once at the SDK RPC boundary. Emit a dedicated demo OTP
   event rather than placing the code in generic errors, diagnostics, or logs.
6. In `apps/seams-site`, show one toast such as `Demo email code: 123456` and
   replace it when the same challenge is reused. Do not persist the code in
   localStorage, URLs, analytics, or durable wallet records.
7. Preserve challenge expiry, attempt limits, resend throttling, wallet/user
   binding, and one-time verification semantics.
8. Keep `email_provider` as the only accepted delivery branch for
   `mainnet_service`.

Acceptance:

- the live testnet demo shows the six-digit code once per active challenge;
- disabled/demo-origin-mismatch responses never contain the OTP;
- reused challenges display the same still-active code without creating a
  second challenge;
- mainnet startup fails if `demo_code_response` is configured;
- server, browser, and telemetry logs do not contain demo OTP codes.

## Phase 4: Deployment Tooling and Documentation

1. Extend the Gateway deployment schema, renderer, environment generator, and
   external-values updater with the required runtime profile.
2. Keep demo policy inside the wallet-core/Gateway configuration group. Product
   Pages receive only the public origin and UI feature signal needed to render
   the toast.
3. Add dry-run output showing the selected profile, NEAR network, funding
   status, and OTP delivery kind. Redact all secrets and OTP values.
4. Document the update-only commands for staging and production testnet.
5. Document the future mainnet profile and its enforced prohibition of faucet
   funding and demo OTP exposure.

## Validation Matrix

- `staging.seams.sh`: testnet funding enabled, demo OTP enabled for exact
  staging origins.
- `seams.sh`: testnet funding enabled, demo OTP enabled for exact production
  demo origins.
- future mainnet deployment: test funding disabled, provider OTP required.
- passkey registration: timing captured, no behavior change.
- Email OTP registration and unlock: demo code toast, correct challenge
  verification, no code persistence.
- fresh NEAR account: funded once, transaction succeeds.
- malformed profile combinations: deployment render or Worker startup fails.

## Likely Files

- `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`
- `packages/sdk-server-ts/src/router/authServicePort.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpDeliveryRuntime.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthConfig.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService.ts`
- `packages/sdk-server-ts/src/router/emailOtpSessionRouteHelpers.ts`
- `packages/console-server-ts/scripts/gateway-deployment-config.mjs`
- `packages/console-server-ts/scripts/render-d1-gateway-config.mjs`
- `crates/router-ab-cloudflare/scripts/generate-github-env-values.mjs`
- `crates/router-ab-cloudflare/scripts/apply-github-external-values.mjs`
- `apps/seams-site/src/flows/demo/PasskeyLoginMenu.tsx`
- `.github/workflows/deploy-gateway.yml`
- `docs/deployment/tooling.md`

## Recommended Order

1. land Phase 0 and collect production timing evidence;
2. enable testnet funding through the typed profile;
3. add demo OTP delivery with mainnet startup guards;
4. optimize only the measured registration bottleneck;
5. deploy to staging, run the validation matrix, then update `seams.sh` without
   rotating Router A/B identities.
