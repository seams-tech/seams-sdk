# Amazon SES

This runbook records the Amazon SES configuration used for Seams Email OTP
delivery and the AWS budget action that limits continued sending after the
configured cost threshold is detected.

## Current configuration

Status recorded on August 10, 2026:

| Setting                      | Value                                                       |
| ---------------------------- | ----------------------------------------------------------- |
| AWS Region                   | `ap-southeast-2` (Asia Pacific, Sydney)                     |
| Sending identity             | `seams.sh`                                                  |
| From address                 | `Seams <confirm@seams.sh>`                                  |
| Custom MAIL FROM domain      | `confirm.seams.sh`                                          |
| Delivery API                 | SES v2 `SendEmail`                                          |
| Gateway IAM user             | `seams-production-ses-sender`                               |
| Production-access status     | More information needed; account remains in the SES sandbox |
| Controlled sandbox recipient | A separately verified test address owned by the operator    |

The `seams.sh` identity, Easy DKIM records, and custom MAIL FROM records are
verified in `ap-southeast-2`. SPF and DMARC are published through the
authoritative Cloudflare DNS zone. SES identity verification and sandbox status
are regional, so every console check and API request must use
`ap-southeast-2`.

While the account remains in the sandbox, SES can send only to verified
recipient identities. The controlled test recipient has been verified and has
successfully received wallet-unlock and key-export OTP messages. General-user
delivery remains blocked until AWS grants production access in this region.

## Gateway configuration

The production-testnet and production-mainnet Gateway environments use the same
SES sender identity and region. Store credentials independently in each
Gateway GitHub Environment; never commit their values.

Required Gateway values:

| Name                              | Storage              | Value or purpose      |
| --------------------------------- | -------------------- | --------------------- |
| `EMAIL_OTP_PROVIDER`              | Environment variable | `amazon_ses`          |
| `EMAIL_OTP_FROM_ADDRESS`          | Environment variable | `confirm@seams.sh`    |
| `EMAIL_OTP_SES_REGION`            | Environment variable | `ap-southeast-2`      |
| `EMAIL_OTP_SES_ACCESS_KEY_ID`     | Environment secret   | IAM access-key ID     |
| `EMAIL_OTP_SES_SECRET_ACCESS_KEY` | Environment secret   | IAM secret access key |

Production mainnet uses `EMAIL_OTP_DELIVERY_MODE=email_provider` and
`EMAIL_OTP_RUNTIME_PROFILE=mainnet_service`. Production testnet uses
`EMAIL_OTP_DELIVERY_MODE=provider_and_demo_code` and
`EMAIL_OTP_RUNTIME_PROFILE=testnet_live_demo`, which sends the OTP and also
discloses the same code in the live-demo toast.

The sender IAM policy permits only `ses:SendEmail` from
`confirm@seams.sh`. A broad identity resource is intentional because the SES
authorization request can include multiple identity resources. The From-address
condition retains the sender restriction.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSeamsOtpDelivery",
      "Effect": "Allow",
      "Action": "ses:SendEmail",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ses:FromAddress": "confirm@seams.sh"
        }
      }
    }
  ]
}
```

## Monthly cost guardrail

AWS Budget `My Monthly Cost Budget` is a monthly cost budget of **$50**. It is
currently healthy and has these actual-cost alerts:

| Threshold | Amount | Behavior                                    |
| --------- | -----: | ------------------------------------------- |
| 50%       | $25.00 | Email alert                                 |
| 75%       | $37.50 | Email alert                                 |
| 100%      | $50.00 | Email alert and automatic IAM policy action |

The automatic action is in `Standby` while the threshold has not been exceeded.
At 100%, AWS Budgets attaches the customer-managed policy
`SeamsDenySesSendEmailAtBudget` to the IAM user
`seams-production-ses-sender`.

The action target is SES-specific. The cost meter is account-wide unless
**Additional budget parameters** contains a Service filter for Amazon Simple
Email Service. With the default account-wide scope, any included AWS spending
can trigger the action and disable SES sending. Add the SES service filter if
the threshold should measure only SES charges.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenySeamsProductionSesSending",
      "Effect": "Deny",
      "Action": "ses:SendEmail",
      "Resource": "*"
    }
  ]
}
```

The action uses the service role `SeamsSesBudgetActionRole`, trusted by
`budgets.amazonaws.com`. Restrict the trust relationship to the owning AWS
account and that account's Budget resources.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "budgets.amazonaws.com"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "<AWS_ACCOUNT_ID>"
        },
        "ArnLike": {
          "aws:SourceArn": "arn:aws:budgets::<AWS_ACCOUNT_ID>:budget/*"
        }
      }
    }
  ]
}
```

The role needs permission to attach and detach only the deny policy on only the
SES sender user.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ToggleSeamsSesBudgetDenyPolicy",
      "Effect": "Allow",
      "Action": ["iam:AttachUserPolicy", "iam:DetachUserPolicy"],
      "Resource": "arn:aws:iam::<AWS_ACCOUNT_ID>:user/seams-production-ses-sender",
      "Condition": {
        "ArnEquals": {
          "iam:PolicyARN": "arn:aws:iam::<AWS_ACCOUNT_ID>:policy/SeamsDenySesSendEmailAtBudget"
        }
      }
    }
  ]
}
```

AWS billing data is delayed and AWS Budgets is updated according to that billing
refresh cadence. This action stops future sends after it runs; it is a cost
guardrail rather than a precise real-time $50 cap. Costs can exceed the
threshold before the deny policy is attached.

## Verification

After changing SES or budget configuration, verify all of the following:

1. In SES `ap-southeast-2`, the `seams.sh` identity, DKIM, and custom MAIL FROM
   statuses are successful.
2. The controlled recipient identity is verified while SES remains in the
   sandbox.
3. Wallet unlock, signing step-up, and key export each deliver an OTP to that
   recipient.
4. `My Monthly Cost Budget` is healthy and shows alerts at 50%, 75%, and 100%.
5. **Additional budget parameters** has the intended cost scope: account-wide
   or filtered to Amazon Simple Email Service.
6. The 100% alert shows one automatic IAM Policy action in `Standby` with:
   - policy `SeamsDenySesSendEmailAtBudget`;
   - target `seams-production-ses-sender`;
   - execution role `SeamsSesBudgetActionRole`.
7. The action role has one effective least-privilege permission path for the
   attach/detach operation. Remove duplicate inline policies.

## Recovery after a budget action

When the action completes, SES sends from the targeted IAM user fail because an
explicit deny overrides its allow policy. Review the cost event before restoring
delivery.

1. Open **Billing and Cost Management → Budgets → My Monthly Cost Budget**.
2. Open the 100% alert and review its action history.
3. Choose **Reverse completed action** to detach the deny policy.
4. Choose **Reset** only when AWS Budgets should evaluate and run the action
   again during the same budget period.
5. Confirm the deny policy is absent from `seams-production-ses-sender`, then
   perform one controlled OTP delivery test.

## References

- [Amazon SES identity creation](https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html)
- [Amazon SES sandbox restrictions](https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html)
- [Configuring an AWS Budget action](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-action-configure.html)
- [Setting up the AWS Budgets action role](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-action-role.html)
- [Reviewing and reversing a Budget action](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-action-review.html)
- [AWS Budgets billing-data delay](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html)
