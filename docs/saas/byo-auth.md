# BYO Auth

See [Bring Your Own Application Authentication](./bring-you-own-auth.md).

The wallet SDK has no application-session plane. Applications own their login
sessions, while wallet ownership is proven with passkey or Email OTP. External
owner-verification webhooks are deferred.
