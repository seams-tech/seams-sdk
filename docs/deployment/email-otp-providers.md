# Email OTP providers

Production Email OTP delivery supports Resend and Amazon SES behind one adapter. The active
provider is selected per backend lane in `deployment/targets.json`.

## Resend

Use this provider block:

```json
{
  "kind": "resend",
  "fromAddress": "confirm@seams.sh"
}
```

Set `RESEND_API_KEY` as a protected secret in each GitHub gateway environment that deploys a lane
using Resend. The sending domain must be verified in Resend before sending to arbitrary recipients.
The deployment renderer sets:

- `EMAIL_OTP_PROVIDER=resend`
- `EMAIL_OTP_FROM_ADDRESS=<provider.fromAddress>`

The adapter supplies `email-otp/<challengeId>` as the Resend idempotency key.

## Amazon SES

Use this provider block:

```json
{
  "kind": "amazon_ses",
  "region": "ap-southeast-2",
  "fromAddress": "confirm@seams.sh"
}
```

Set these protected secrets in each matching GitHub gateway environment:

- `EMAIL_OTP_SES_ACCESS_KEY_ID`
- `EMAIL_OTP_SES_SECRET_ACCESS_KEY`

The deployment renderer also sets `EMAIL_OTP_SES_REGION`. See [aws-ses.md](aws-ses.md) for sender
identity and IAM setup.

## Switching providers

1. Add the selected provider's protected secret to the target gateway environment.
2. Change only the lane's `emailOtpDelivery.provider` branch in `deployment/targets.json`.
3. Run `pnpm test:unit:scripts` or the focused deployment-target test.
4. Run the backend preflight and deploy the gateway.

Deployment preflight requires only the secret selected by the provider branch.
