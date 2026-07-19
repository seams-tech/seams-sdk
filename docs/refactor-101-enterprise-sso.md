# Enterprise OIDC/SAML Login

Date updated: July 7, 2026

## Objective

Enable company-specific SSO for operators who manage wallet/MPC auth and agent
signing authority.

The authentication model is:

1. Company SSO authenticates the human operator.
2. Seams maps the SSO subject into an org member and role set.
3. Seams wallet/MPC policy decides which agent grants and signing actions the
   operator can authorize.
4. Agent signing sessions carry explicit scope, budget, expiry, org identity,
   wallet identity, and authorizing user identity.

SSO is the enterprise identity plane. Wallet/MPC policy is the signing authority
plane.

## Current Starting Point

The codebase already has the strongest building block for the OIDC path:

1. `POST /session/exchange` accepts `exchange.type = "oidc_jwt"`.
2. Generic OIDC exchange verifies issuer, audience, RS256 signature, JWKS key id,
   subject, and time claims.
3. OIDC success resolves a provider subject into a Seams user and mints an
   `app_session_v1`.
4. Wallet lock state is derived from valid app-session state.
5. Google SSO is implemented as a provider-specific OIDC lane.

Direct SAML is not an active first-class path today. It should enter as a
protocol adapter that normalizes SAML assertions into the same internal SSO
assertion model used by OIDC.

## Product Scope

### Supported Use Cases

1. A customer admin connects Okta, Google Workspace, Microsoft Entra, Auth0,
   WorkOS, or another enterprise IdP to a Seams org.
2. Employees sign in with company SSO to access org-scoped wallet and agent
   management.
3. Org roles or IdP groups allow selected operators to create, approve, revoke,
   and rotate agent signing grants.
4. Every agent grant records the SSO user who authorized it.
5. Revoking org membership or rotating app-session version blocks future
   privileged actions.

### Out Of Scope For The First Release

1. Full SCIM user lifecycle provisioning.
2. Publishing an Okta Integration Network app.
3. Acting as an IdP for third-party apps.
4. IdP-initiated SAML without a validated tenant binding.
5. Automatic revocation of already-issued agent grants unless the grant policy
   explicitly requires live membership checks.

## Protocol Strategy

### Phase 1: Enterprise OIDC

OIDC should be the first production implementation because it aligns with the
existing `oidc_jwt` exchange contract.

Supported initial modes:

1. Customer app obtains an IdP ID token and calls `POST /session/exchange`.
2. Seams-hosted console starts an OIDC Authorization Code + PKCE flow and mints
   the same app session after callback verification.

Both modes must normalize into one internal success object:

```ts
export type EnterpriseSsoAssertion = {
  kind: 'enterprise_sso_assertion_v1';
  protocol: 'oidc' | 'saml';
  orgId: OrgId;
  providerId: SsoProviderId;
  issuer: SsoIssuer;
  subject: SsoSubject;
  providerSubject: SsoProviderSubject;
  email: VerifiedEmail;
  displayName: DisplayName;
  groups: SsoGroup[];
  authenticatedAt: UnixTimeSeconds;
};
```

### Phase 2: Direct SAML

SAML should use the same internal assertion object after XML assertion
validation. Direct SAML adds service-provider endpoints, metadata handling,
certificate rollover, replay protection, and XML signature hardening.

Required SAML capabilities:

1. SP metadata endpoint per provider.
2. Assertion Consumer Service (ACS) endpoint per provider.
3. Signed assertion validation with audience, recipient, destination, issuer,
   subject, and time-window checks.
4. `InResponseTo` replay store for SP-initiated login.
5. IdP certificate rollover with active and next certificate sets.
6. Attribute mapping for email, display name, and groups.

## Domain Model

Use discriminated unions for provider configuration. Raw IdP configuration must
be parsed once at request/persistence boundaries before core auth logic receives
it.

```ts
export type EnterpriseSsoProvider =
  | EnterpriseOidcProvider
  | EnterpriseSamlProvider;

export type EnterpriseOidcProvider = {
  kind: 'oidc_provider_v1';
  orgId: OrgId;
  providerId: SsoProviderId;
  issuer: SsoIssuer;
  authorizationEndpoint: HttpsUrl;
  tokenEndpoint: HttpsUrl;
  jwksUrl: HttpsUrl;
  audiences: SsoAudience[];
  clientId: OidcClientId;
  encryptedClientSecret: EncryptedSecretRef;
  redirectUri: HttpsUrl;
  claimMapping: SsoClaimMapping;
  saml: never;
};

export type EnterpriseSamlProvider = {
  kind: 'saml_provider_v1';
  orgId: OrgId;
  providerId: SsoProviderId;
  idpEntityId: SamlEntityId;
  ssoUrl: HttpsUrl;
  spEntityId: SamlEntityId;
  acsUrl: HttpsUrl;
  signingCertificates: SamlSigningCertificateSet;
  attributeMapping: SsoAttributeMapping;
  oidc: never;
};
```

Provider state should be explicit:

```ts
export type EnterpriseSsoProviderLifecycle =
  | {
      kind: 'draft';
      provider: EnterpriseSsoProvider;
      verifiedAt: never;
      enabledAt: never;
    }
  | {
      kind: 'verified';
      provider: EnterpriseSsoProvider;
      verifiedAt: UnixTimeSeconds;
      enabledAt: never;
    }
  | {
      kind: 'enabled';
      provider: EnterpriseSsoProvider;
      verifiedAt: UnixTimeSeconds;
      enabledAt: UnixTimeSeconds;
    }
  | {
      kind: 'disabled';
      provider: EnterpriseSsoProvider;
      verifiedAt: UnixTimeSeconds;
      disabledAt: UnixTimeSeconds;
      enabledAt: never;
    };
```

## Persistence

Add or extend persistence around these concepts:

1. `org_sso_providers`
   - `org_id`
   - `provider_id`
   - `protocol`
   - `lifecycle`
   - normalized provider config
   - encrypted client secret or certificate references
   - created/updated audit fields

2. `org_sso_domains`
   - `org_id`
   - `domain`
   - verification state
   - routing policy

3. `org_sso_subject_bindings`
   - `org_id`
   - `provider_id`
   - `provider_subject`
   - `user_id`
   - first/last login timestamps

4. `org_sso_group_role_mappings`
   - `org_id`
   - `provider_id`
   - IdP group value
   - Seams org role

5. `sso_login_attempts`
   - nonce/state hash
   - provider id
   - org id
   - protocol
   - redirect target
   - expiry
   - consumed timestamp

Use a short retention window for login attempts. Store hashes for transient
state values.

## API Surface

### Admin Configuration

Initial console/admin routes:

1. `POST /console/orgs/:orgId/sso/providers`
2. `GET /console/orgs/:orgId/sso/providers`
3. `PATCH /console/orgs/:orgId/sso/providers/:providerId`
4. `POST /console/orgs/:orgId/sso/providers/:providerId/test`
5. `POST /console/orgs/:orgId/sso/providers/:providerId/enable`
6. `POST /console/orgs/:orgId/sso/providers/:providerId/disable`
7. `DELETE /console/orgs/:orgId/sso/providers/:providerId`

Admin APIs require an existing org admin session. Provider creation remains in
`draft` until a successful test login proves the IdP configuration works.

### OIDC Login

Hosted OIDC login routes:

1. `GET /sso/oidc/:providerId/start`
2. `GET /sso/oidc/:providerId/callback`

Callback flow:

1. Validate state/nonce from `sso_login_attempts`.
2. Exchange code for tokens.
3. Verify ID token against the provider config.
4. Normalize claims into `EnterpriseSsoAssertion`.
5. Resolve or create the org member according to org SSO policy.
6. Mint `app_session_v1`.
7. Redirect to the console or wallet management surface.

SDK/customer-app OIDC exchange remains:

```json
{
  "sessionKind": "cookie",
  "exchange": {
    "type": "oidc_jwt",
    "provider": "enterprise",
    "token": "eyJ..."
  },
  "projectEnvironmentId": "env_..."
}
```

The server must route enterprise OIDC exchange by issuer, audience, and explicit
org context. Email domain alone is useful for discovery, then the verified token
claims decide the binding.

### SAML Login

Hosted SAML routes:

1. `GET /sso/saml/:providerId/start`
2. `GET /sso/saml/:providerId/metadata`
3. `POST /sso/saml/:providerId/acs`

ACS flow:

1. Parse the SAML response at the route boundary.
2. Validate XML signature with wrapping-attack protections.
3. Validate issuer, audience, recipient, destination, subject, and time claims.
4. Validate and consume `InResponseTo` for SP-initiated login.
5. Normalize attributes into `EnterpriseSsoAssertion`.
6. Resolve or create the org member according to org SSO policy.
7. Mint `app_session_v1`.

IdP-initiated SAML should be accepted only when the provider URL already fixes
the org/provider binding and the assertion validates for that provider.

## Authorization For Wallet/MPC Agent Signing

SSO login grants an app session. Signing authority comes from policy.

Agent grant creation must require:

1. Valid `app_session_v1`.
2. Current org membership.
3. Required org role such as `agent_admin`, `wallet_admin`, or
   `grant_approver`.
4. Runtime policy allowing the requested wallet, chain, budget, expiry, and
   operation family.

Agent grants must record:

1. `orgId`
2. `projectId`
3. `environmentId`
4. `walletId`
5. `authorizingUserId`
6. `ssoProviderId`
7. `ssoProviderSubject`
8. `grantPolicyId`
9. `budget`
10. `expiresAt`
11. allowed operation set

Policy decides whether already-issued grants remain valid after a user loses
SSO access. High-risk orgs should use live membership checks or short grant
lifetimes.

## Security Requirements

1. Validate and normalize raw IdP payloads once at the auth boundary.
2. Core authorization must never accept raw JWT claims or raw SAML attributes.
3. Use exact issuer and audience matching.
4. Bind every login attempt to org id, provider id, nonce/state, redirect target,
   and expiry.
5. Store replay-sensitive state as hashes.
6. Keep provider configs org-scoped.
7. Keep app-session claims separate from threshold and signing-session claims.
8. Emit audit events for provider changes, login success/failure, group-role
   mapping changes, grant creation, grant revocation, and failed authorization.
9. Preserve Express and Cloudflare parity for every new route.
10. Use the provider lifecycle union to prevent draft or disabled providers from
    authenticating users.

## Testing Plan

### Unit Tests

OIDC:

1. Valid token verifies and maps to an `EnterpriseSsoAssertion`.
2. Wrong issuer fails.
3. Wrong audience fails.
4. Expired token fails.
5. Future `nbf` fails outside skew.
6. Unknown `kid` fails.
7. Bad signature fails.
8. Missing `sub` fails.
9. Missing verified email fails when org policy requires email.
10. Cross-org issuer/audience collision fails.

SAML:

1. Valid signed response verifies and maps to an `EnterpriseSsoAssertion`.
2. Wrong audience fails.
3. Wrong destination or recipient fails.
4. Expired assertion fails.
5. Unknown signing certificate fails.
6. Unsigned assertion fails.
7. XML signature wrapping fixture fails.
8. Replayed `InResponseTo` fails.
9. Missing NameID/subject fails.
10. Group attribute mapping is deterministic.

Type fixtures:

1. `EnterpriseOidcProvider` cannot carry SAML fields.
2. `EnterpriseSamlProvider` cannot carry OIDC fields.
3. Draft provider cannot be passed to login verification.
4. Disabled provider cannot be passed to login verification.
5. Agent grant builders require authorizing user and org identity.

### Integration Tests

1. Local fake OIDC provider with generated RS256 keys and JWKS.
2. JWKS rotation from old key to new key.
3. Local SAML IdP fixture with deterministic signing certs.
4. Express and Cloudflare parity for start/callback/ACS/session routes.
5. First-login provisioning for an invited user.
6. First-login rejection when org policy requires invitation.
7. Group claim maps to org role.
8. Removed group blocks privileged agent grant creation after session refresh.
9. Agent grant creation audit event includes SSO subject and provider id.
10. Revoked membership blocks new agent grants.

### Okta Sandbox Testing

Use an Okta Integrator Free Plan org as the developer sandbox. Okta documents
this plan as a free environment for building and testing integrations.

OIDC smoke test:

1. Create an Okta Integrator Free Plan org.
2. In Okta Admin Console, create an OIDC app integration.
3. Select Web Application for hosted callback testing.
4. Configure redirect URI:
   - local tunnel: `https://<tunnel-host>/sso/oidc/<providerId>/callback`
   - hosted dev: `https://<dev-host>/sso/oidc/<providerId>/callback`
5. Assign the app to a test user and test group.
6. Configure ID token claims for email, name, and groups.
7. Copy issuer, client id, client secret, and JWKS discovery data into the Seams
   provider config.
8. Start login from Seams and confirm an `app_session_v1` is minted.
9. Confirm the org member gets the expected role from group mapping.
10. Create a test agent signing grant and verify the audit trail.

SAML smoke test:

1. In Okta Admin Console, create a SAML 2.0 app integration.
2. Configure Single Sign-On URL:
   - local tunnel: `https://<tunnel-host>/sso/saml/<providerId>/acs`
   - hosted dev: `https://<dev-host>/sso/saml/<providerId>/acs`
3. Configure Audience URI / SP Entity ID from Seams provider metadata.
4. Add attribute statements for email, display name, and groups.
5. Assign the app to a test user and test group.
6. Copy IdP metadata URL or signing certificate into the Seams provider config.
7. Start SP-initiated login from Seams and confirm a session is minted.
8. Launch the app from Okta dashboard to test IdP-initiated login, if enabled.
9. Remove the user from the privileged group and verify grant creation is blocked
   after reauthentication or session refresh.

## Rollout Plan

### Phase 0: Spec And Inventory

1. Confirm current OIDC exchange behavior in Express and Cloudflare.
2. Identify existing org membership, role, and audit event primitives.
3. Decide invitation-only versus JIT provisioning for first login.
4. Decide grant behavior after SSO membership revocation.

### Phase 1: Enterprise OIDC Config

1. Add org-scoped provider persistence.
2. Add provider lifecycle state.
3. Add admin CRUD/test/enable routes.
4. Add claim mapping and group-role mapping.
5. Add type fixtures for invalid provider state.

### Phase 2: Hosted OIDC Login

1. Add start/callback routes.
2. Add login attempt state.
3. Add Authorization Code + PKCE verifier.
4. Normalize OIDC result into `EnterpriseSsoAssertion`.
5. Mint `app_session_v1`.
6. Add Okta OIDC smoke test guide.

### Phase 3: Agent Grant Authorization

1. Gate agent grant creation on org role and policy.
2. Add audit events tying grants to SSO identity.
3. Add revocation and role-removal tests.
4. Document operator-to-agent authority boundaries.

### Phase 4: Direct SAML

1. Add SAML provider config lifecycle.
2. Add metadata/start/ACS routes.
3. Add signed XML assertion validation.
4. Add replay store.
5. Add Okta SAML smoke test guide.

### Phase 5: SCIM And Enterprise Polish

1. Add optional SCIM provisioning.
2. Add certificate rollover UI and warnings.
3. Add IdP health checks.
4. Add OIN/marketplace packaging if customer demand warrants it.

## Definition Of Done

1. An Okta OIDC app can authenticate a test user into a Seams org.
2. The authenticated user can create an agent signing grant only when org policy
   allows it.
3. The grant audit event includes org id, provider id, provider subject,
   authorizing user id, wallet id, policy id, budget, and expiry.
4. Negative OIDC fixtures cover issuer, audience, signature, key id, subject, and
   time-claim failures.
5. Express and Cloudflare route behavior remains in parity.
6. Direct SAML has equivalent positive and negative coverage before GA.
7. Provider lifecycle state prevents draft and disabled providers from accepting
   logins.

## Open Decisions

1. Should first login require an invite, or can verified-domain users join by
   default?
2. Which roles are required for agent grant creation, approval, rotation, and
   revocation?
3. Should group membership be evaluated only at login/session refresh, or also at
   every high-risk action?
4. Should high-risk agent grants become invalid when the authorizing user loses
   org membership?
5. Do customers need direct SAML in the first enterprise release, or can an OIDC
   bridge cover initial SAML IdPs?

## External References

1. Okta Integrator Free Plan signup:
   `https://developer.okta.com/signup/`
2. Okta Integrator Free Plan org defaults:
   `https://developer.okta.com/docs/reference/org-defaults/`
3. Okta SSO overview:
   `https://developer.okta.com/docs/concepts/sso-overview/`
4. Okta OIDC app integration guide:
   `https://help.okta.com/oie/en-us/content/topics/apps/apps_app_integration_wizard_oidc.htm`
5. Okta SAML app integration guide:
   `https://help.okta.com/oie/en-us/content/topics/apps/apps_app_integration_wizard_saml.htm`
