# Remove deployment seeding and retire legacy staging D1 databases

Status: implementation in progress
Date: 2026-07-30

## Outcome

Staging and production use separate Cloudflare D1 databases. Backend
deployments apply schema migrations and deploy code without creating an
organization, project, environment, or API key. An administrator completes the
real console onboarding flow, creates a browser-safe API key, publishes its
project-environment ID and key as frontend variables, and redeploys the
frontend.

The unused pre-NRT staging databases can be deleted after their lack of active
bindings is proven and the retention decision is recorded.

## Verified resource split

| Lane                      | Console D1                                                           | Signer D1                                                           |
| ------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Staging                   | `seams-console-staging-nrt` (`572d772c-3e15-4f60-a03f-e7a82fd452e7`) | `seams-signer-staging-nrt` (`c68f90e9-9831-427e-87af-b08304cc7f8e`) |
| Production                | `seams-console` (`6d9ec624-7dc0-4619-ba67-af2e329ed5f1`)             | `seams-signer` (`3f9eab6f-99ee-4512-b09f-02d2bf931d62`)             |
| Legacy staging candidates | `seams-console-staging` (`a421e35a-cbf0-4be9-974a-71c65f5a8f95`)     | `seams-signer-staging` (`09fc2eec-a605-459d-9a23-aff9ff4b509c`)     |

The checked-in target binds the `-nrt` databases for staging. Production has
its own distinct pair.

## Implementation phases

### 1. Make backend deployment schema-only

- Remove `bootstrap` from the Gateway deployment configuration parser.
- Remove `d1Bootstrap` from the rendered deployment plan.
- Delete the tenant-seeding script and its obsolete fixture.
- Remove tenant seeding from the backend deployment order.
- Keep runtime tenant identifiers as explicit configuration consumed after
  administrator onboarding. They create no database rows.

Exit check: applying migrations and deploying twice to an empty test database
pair leaves organization, project, environment, and API-key tables empty.

### 2. Configure the frontend from administrator-created resources

1. Sign in as the designated administrator and complete console onboarding.
2. Create the organization, project, and project environment through the
   product flow.
3. Create a browser-safe publishable key with the exact app and wallet origins.
4. Store `SEAMS_ORG_ID`, `SEAMS_PROJECT_ID`, and `SEAMS_ENV_ID` as Gateway
   configuration. Store `VITE_SEAMS_PROJECT_ENVIRONMENT_ID` and
   `VITE_SEAMS_PUBLISHABLE_KEY` in the target frontend GitHub environment.
5. Redeploy the frontend and complete managed registration plus one signing
   operation.
6. Redeploy the backend and verify tenant and API-key row counts stay constant.

Run this acceptance sequence in staging first. Preserve production tenant data
and roll production forward only after staging succeeds.

### 3. Retire the legacy staging databases

Before deletion:

1. Search checked-in configuration and GitHub environment values for both
   legacy names and IDs.
2. Inspect current and recent staging Worker versions for D1 bindings.
3. Check recent D1 activity and decide whether an export is required.
4. Record the evidence, retention decision, reviewer, and deletion timestamp.

Delete exactly these resources, one at a time:

- `seams-console-staging` / `a421e35a-cbf0-4be9-974a-71c65f5a8f95`
- `seams-signer-staging` / `09fc2eec-a605-459d-9a23-aff9ff4b509c`

Run Gateway readiness, console login, managed registration, and signing smoke
checks after each deletion. Re-list D1 databases and retain the output as
completion evidence.

D1 deletion is destructive. Execution requires separate approval after the
inventory and retention evidence are assembled.

## Completion criteria

- Staging and production reference separate D1 resources.
- Backend migrations and deployments create no tenant or API-key rows.
- Both frontends use administrator-created project-environment IDs and keys.
- Staging onboarding, registration, and signing succeed from an unseeded state.
- Backend redeployment leaves tenant and key row counts unchanged.
- The two legacy staging D1 IDs are absent from active configuration and
  Cloudflare after approved deletion.
