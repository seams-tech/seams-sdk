# Registration Top-Up Plan

## Problem

Registration bootstrap grants currently stop at a fixed publishable-key quota before any billing balance is considered.

Observed local state:

- `free_registrations_v1` is configured as `maxIssued: 1_000`.
- `console_bootstrap_tokens` already has `1_000` issued rows for the active publishable key.
- The key has `payment_policy = {"mode":"disabled"}`.
- The org has a positive prepaid billing balance, but `/v1/registration/bootstrap-grants` does not read or reserve that balance.

That means topping up a project account does not unblock wallet registration. The user sees:

```json
{
  "ok": false,
  "code": "publishable_key_quota_exhausted",
  "message": "Quota bucket free_registrations_v1 exceeded"
}
```

This is the wrong product behavior. Free quota should be a grant tier, not a hard stop for funded projects.

## Target Behavior

Registration bootstrap should use a two-tier policy:

1. Use free quota first.
2. When free quota is exhausted, continue registration if the project/org has prepaid balance and the publishable key allows paid overage.

The intended API key policy is already represented by:

```json
{
  "quotaBucket": "free_registrations_v1",
  "paymentPolicy": {
    "mode": "quota_then_x402",
    "productId": "wallet_registration_v1"
  }
}
```

Under this policy:

- quota available: issue the grant without reserving balance
- quota exhausted and balance available: reserve paid registration spend, then issue the grant
- quota exhausted and balance unavailable: return `402 payment_required`
- quota exhausted and `paymentPolicy.mode === "disabled"`: return `429 publishable_key_quota_exhausted`

## Design

### Source of Truth

The quota source of truth stays in `console_bootstrap_tokens`:

- bucket limit is selected from `ConsoleApiKey.quotaBucket`
- current usage is `countIssued({ publishableKeyId })`
- issued grants remain auditable per key

The paid overage source of truth should be prepaid billing:

- posted balance from `ConsoleBillingService.getOverview(ctx).creditBalanceMinor`
- reserved balance from `ConsoleBillingPrepaidReservationService`
- reservation source id derived from the bootstrap grant request
- settlement on successful `/registration/bootstrap`
- release on failed registration or expired/rejected bootstrap token

Do not create a second registration-specific balance table. Use the existing prepaid reservation ledger so registrations and sponsored execution share one balance model.

### Product Pricing

Add an explicit registration pricing policy:

```ts
type RegistrationPricingQuote = {
  productId: 'wallet_registration_v1';
  estimatedSpendMinor: number;
  pricingVersion: string;
};
```

Start with a static operator-configured value for local/dev and production:

- env name: `REGISTRATION_PRODUCTS_PRICING_JSON`
- product id: `wallet_registration_v1`
- fields: `estimatedSpendMinor`, `pricingVersion`

Fail closed if paid overage is enabled but pricing is missing or malformed.

### Broker Flow

Extend `createRouterApiBootstrapGrantBroker(...)` with billing dependencies:

```ts
billing?: ConsoleBillingService | null;
prepaidReservations?: ConsoleBillingPrepaidReservationService | null;
registrationPricing?: RegistrationPricingService | null;
```

When quota is available, preserve current behavior.

When quota is exhausted:

1. Read `authenticatedApiKey.paymentPolicy`.
2. If mode is not `quota_then_x402`, return the current `429 publishable_key_quota_exhausted`.
3. Resolve the requested product id. Require `wallet_registration_v1`.
4. Quote registration spend.
5. Read current billing overview for the authenticated org.
6. Reserve spend with a deterministic source event id:

```ts
registration_bootstrap_grant:${apiKeyId}:${environmentId}:${newAccountId}
```

7. Create the bootstrap token with `paymentReference = reservation.sourceEventId`.
8. Return a normal bootstrap grant.

Reservation must happen before token creation. Token creation must include the payment reference. If token creation fails after reservation, release the reservation before returning the error.

### Registration Redemption Flow

When `/registration/bootstrap` redeems a bootstrap token:

- if the token has no `paymentReference`, preserve current behavior
- if registration succeeds, settle the reservation
- if registration fails, release the reservation

Settlement should include:

- `sourceEventId = token.paymentReference`
- `settledSpendMinor = quoted registration spend`
- `pricingVersion`
- `txOrExecutionRef = walletId` or a registration result id if one exists

Release should be idempotent and safe if the reservation was already released, settled, or expired.

### Expiry And Cleanup

Bootstrap tokens are short-lived. Paid reservations must not remain stuck if a grant is issued but never redeemed.

Add a cleanup path:

- when bootstrap token expiry is detected during redemption, release its reservation
- periodic reservation expiry already exists; ensure the reservation TTL is slightly longer than bootstrap token TTL
- add observability for stale paid registration reservations

## Implementation Plan

### Phase 1: Make The Policy Explicit

- [ ] Add a registration pricing service/type for `wallet_registration_v1`.
- [ ] Add env parsing for `REGISTRATION_PRODUCTS_PRICING_JSON`.
- [ ] Wire the pricing service into the example relay assembly.
- [ ] Add tests for missing pricing, malformed pricing, and valid static pricing.

### Phase 2: Add Paid Overage To Bootstrap Grants

- [ ] Extend `RouterApiBootstrapGrantBrokerOptions` with billing, prepaid reservation, and registration pricing dependencies.
- [ ] Read `paymentPolicy` after quota exhaustion.
- [ ] Keep `paymentPolicy.mode === "disabled"` returning `429 publishable_key_quota_exhausted`.
- [ ] For `quota_then_x402`, reserve prepaid balance before creating the token.
- [ ] Store `paymentReference` on the bootstrap token.
- [ ] Release the reservation if token creation fails.
- [ ] Return `402 payment_required` when balance is insufficient.

### Phase 3: Settle Or Release On Registration

- [ ] Thread `paymentReference` from redeemed bootstrap token into `handleRelayRegistrationBootstrap`.
- [ ] Settle the reservation only after `createAccountAndRegisterUser(...)` succeeds.
- [ ] Release the reservation when registration fails.
- [ ] Release the reservation when token redemption fails due to expiry.
- [ ] Preserve current free-quota behavior for tokens without `paymentReference`.

### Phase 4: Console And Local Dev Defaults

- [ ] Update the local seeded publishable key to use `paymentPolicy.mode = "quota_then_x402"` for registration testing.
- [ ] Ensure the dashboard API key UI makes the distinction clear:
  - free quota only
  - free quota, then prepaid balance
- [ ] Add an admin/dev reset command for bootstrap-token quota rows, but keep it separate from production code paths.

### Phase 5: Tests

- [ ] Broker test: quota available issues a free grant and does not reserve balance.
- [ ] Broker test: quota exhausted + disabled payment returns `429`.
- [ ] Broker test: quota exhausted + paid overage + enough balance reserves and issues grant.
- [ ] Broker test: quota exhausted + paid overage + insufficient balance returns `402`.
- [ ] Broker test: token creation failure releases the reservation.
- [ ] Registration test: paid token succeeds and settles reservation.
- [ ] Registration test: paid token registration failure releases reservation.
- [ ] Registration test: expired paid token releases reservation.
- [ ] Postgres test: `payment_reference` round-trips through `console_bootstrap_tokens`.
- [ ] E2E/dev test: top up balance after free quota exhaustion, then wallet unlock/registration succeeds.

## Acceptance Criteria

- A project with no remaining `free_registrations_v1` quota can still register wallets after topping up prepaid balance.
- A project with exhausted free quota and no balance receives a payment-required response, not a misleading quota-only failure.
- Free registration grants do not create prepaid reservations.
- Paid registration grants are fully auditable through `console_bootstrap_tokens.payment_reference` and prepaid reservation records.
- Failed or abandoned paid registration attempts do not leak reserved balance.
- Existing publishable keys with `paymentPolicy.mode = "disabled"` keep the current quota-only behavior.

## Immediate Local Unblock

For local development only, the current exhausted quota can be reset with:

```sql
DELETE FROM console_bootstrap_tokens
WHERE namespace = 'relay-console'
  AND publishable_key_id = 'ak_0cc9176910f88e99';
```

This is not the product fix. It only clears local dev quota history so testing can continue before paid registration overage is implemented.
