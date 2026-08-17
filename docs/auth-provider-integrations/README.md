# Application Auth Provider Integrations

Auth providers authenticate users to your application. Their tokens are not
wallet credentials and must remain outside the wallet SDK.

The integration is provider-independent:

1. authenticate the application user;
2. look up that user's untrusted wallet locator in your application data;
3. open the wallet SDK with the locator;
4. complete the wallet's passkey or Email OTP owner ceremony.

The wallet server then issues an opaque, budgeted Wallet Session. It does not
exchange Auth0, Better Auth, Clerk, Firebase, Google, Okta, or Supabase tokens
for wallet authority.

See [Bring Your Own Application Authentication](../saas/bring-you-own-auth.md)
for the complete boundary. Customer-configured owner-verification webhooks are
deferred to a later refactor.
