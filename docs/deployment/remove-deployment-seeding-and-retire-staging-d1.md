# Remove deployment seeding and retire legacy staging D1 databases

Status: proposed  
Date: 2026-07-30

## Outcome

Staging and production keep separate Cloudflare D1 databases. Backend deployments apply schema migrations and deploy code without creating an organization, project, environment, or API key. An administrator completes the real console onboarding flow, creates a browser-safe API key, publishes its environment ID and key as frontend environment variables, and redeploys the frontend.

The two unused pre-NRT staging databases are exported if retention is required and then deleted after their lack of bindings is proven.

## Verified current state

| Lane | Console D1 | Signer D1 | Status |
| --- | --- | --- | --- |
| Staging | `seams-console-staging-nrt` (`572d772c-3e15-4f60-a03f-e7a82fd452e7`) | `seams-signer-staging-nrt` (`c68f90e9-9831-427e-87af-b08304cc7f8e`) | Bound to the deployed staging Gateway |
| Production | `seams-console` (`6d9ec624-7dc0-4619-ba67-af2e329ed5f1`) | `seams-signer` (`3f9eab6f-99ee-4512-b09f-02d2bf931d62`) | Bound to the deployed production Gateway |
| Legacy staging | `seams-console-staging` (`a421e35a-cbf0-4be9-974a-71c65f5a8f95`) | `seams-signer-staging` (`09fc2eec-a605-459d-9a23-aff9ff4b509c`) | Deletion candidates; absent from the current staging Gateway bindings |

The deployment currently calls `bootstrap-gateway-deployment.mjs`. Its generated SQL upserts the configured organization, project, environment, and deterministic publishable key. Live staging and production therefore contain deployment-created tenant records. This is deployment seeding and must be removed.

Console onboarding itself also creates data. The first authenticated administrator establishes the organization/owner context, the onboarding wizard creates the first project and its default environment, and the API-key page creates the publishable key. These are user-driven onboarding operations and remain supported.

The frontend requires both public build variables:

- `VITE_SEAMS_PROJECT_ENVIRONMENT_ID`
- `VITE_SEAMS_PUBLISHABLE_KEY`

## Scope and safety boundaries

This work deletes no active staging or production D1 database. It deletes no tenant rows until their foreign-key and operational dependencies have been inspected. The following resources are outside the legacy deletion scope:

- both `*-staging-nrt` databases;
- both production databases;
- custody-worker private D1 databases;
- any database ID found in a deployed Worker version, checked-in target, workflow, environment configuration, or recovery procedure.

PR #33 establishes `deployment/targets.json` as the reviewed source of Gateway resource configuration. The merged `dev` target names the active `-nrt` databases.

## Implementation

### 1. Make Gateway deployment schema-only

1. Remove `bootstrap` from the checked-in Gateway deployment configuration and its exact-key parser.
2. Remove `d1Bootstrap` from the rendered Gateway deployment plan.
3. Delete `packages/console-server-ts/scripts/bootstrap-gateway-deployment.mjs` and its bootstrap-only unit test.
4. Remove the bootstrap invocation and bootstrap step text from `scripts/deploy-backend.mjs`.
5. Update deployment documentation and generated-environment validation so they describe migrations followed by deployment.
6. Delete stale fixtures and source guards that require a deterministic deployment key or seeded tenant.

Exit check: run a backend migration and deployment twice against an empty test D1 pair. Organization, project, environment, and API-key table counts remain zero after both runs.

### 2. Remove fixed tenant identity from Gateway runtime configuration

The checked-in configuration currently carries `tenant.orgId`, `tenant.projectId`, and `tenant.environmentId`, which render as `SEAMS_STAGING_ORG_ID`, `SEAMS_STAGING_PROJECT_ID`, and `SEAMS_STAGING_ENV_ID`. Remove these fixed identities from the deployment target and Worker environment.

Resolve tenant scope once at request boundaries:

- console requests use the authenticated console session and organization membership;
- managed registration requests resolve organization, project, and environment from the validated publishable API key;
- server API-key requests resolve the same scope from the validated secret key;
- internal calls receive a required, already-validated tenant scope rather than global fallback IDs.

Keep only target-level storage partitioning that is genuinely required, such as the staging/production namespace. Update staging readiness, reconciliation, and resource-inventory scripts to accept an explicit organization or environment selector when their operation is tenant-specific.

Exit check: there is no fixed organization, project, environment, or publishable key in `deployment/targets.json`, rendered Wrangler configuration, or GitHub environment variables.

### 3. Exercise staging from an unseeded state

1. Export the active staging console and signer D1 databases and record a time-travel bookmark.
2. Inventory all rows related to `org_staging`, `project_staging`, environment `staging`, and the deterministic deployment API key. Check wallets, policies, billing, memberships, audit records, signer records, and other foreign-key references.
3. If the inventory contains only deployment-created test data, delete that complete dependency graph in a reviewed SQL transaction. If meaningful staging data exists, provision a clean staging D1 pair, apply migrations only, update the checked-in IDs, and deploy the Gateway against that pair.
4. Assert that the selected staging databases contain no organization, project, environment, or API key.
5. Sign in as the designated staging administrator and complete the console onboarding wizard. The organization and owner membership must arise from the authenticated onboarding path.
6. Create the first project and its default environment through the wizard.
7. Create a browser-safe publishable key with the staging site and wallet origins. Capture the key when it is shown.
8. Set `VITE_SEAMS_PROJECT_ENVIRONMENT_ID` and `VITE_SEAMS_PUBLISHABLE_KEY` in the `staging` GitHub environment and redeploy the staging frontend.
9. Complete managed wallet registration and one signing operation through the deployed frontend.
10. Redeploy the backend and prove that tenant and API-key row counts do not change.

This is the primary acceptance test for onboarding.

### 4. Roll production forward

1. Deploy the schema-only and request-scoped Gateway changes while retaining current production data.
2. Inventory the deployment-created production tenant and key before changing them. Preserve any record with live wallets, billing, audit, policy, or signer dependencies.
3. Create the intended production organization/project/environment through the administrator onboarding path. When an existing real tenant already represents that organization, validate onboarding with a new administrator or a controlled additional organization rather than erasing live data.
4. Create and securely record a new production publishable key with exact production origins.
5. Update the production frontend variables and redeploy the frontend.
6. Verify registration and signing, revoke the deterministic deployment key, then remove deployment-created tenant records only when the dependency inventory proves they are unused.
7. Redeploy the backend and confirm it creates no tenant records.

API keys are secrets even when browser-safe. Store the complete value only in the owning GitHub environment or approved secret system; logs and evidence should contain an ID or redacted prefix.

### 5. Delete the two legacy staging databases

Perform this phase only after the checked-in target correction is deployed and staging passes the onboarding test.

1. Search the repository and GitHub deployment configuration for both legacy names and IDs.
2. Inspect every current and recent staging Worker version and confirm no D1 binding references either legacy ID.
3. Check D1 activity and retention requirements. Export each database to restricted storage when recovery or audit retention is required.
4. Record the database name, ID, export location or approved no-retention decision, binding evidence, reviewer, and deletion timestamp.
5. Delete exactly these resources, one at a time:
   - `seams-console-staging` / `a421e35a-cbf0-4be9-974a-71c65f5a8f95`
   - `seams-signer-staging` / `09fc2eec-a605-459d-9a23-aff9ff4b509c`
6. After each deletion, run staging Gateway readiness, console login, managed registration, and signing smoke checks.
7. List D1 databases again and retain the output as completion evidence.

D1 deletion is destructive. Recreating a database from an export produces a new database ID and requires an explicit binding update and Gateway redeployment. Execution therefore requires a separate approval after the evidence above is assembled.

## Verification matrix

| Check | Staging | Production |
| --- | --- | --- |
| Distinct console/signer D1 IDs | Required | Required |
| Migration plus backend deploy leaves an empty tenant DB empty | Required | Test fixture evidence plus production no-new-row evidence |
| Administrator onboarding creates organization/owner | Required | Required |
| Wizard creates project and default environment | Required | Required |
| Admin-created publishable key works from allowed origins | Required | Required |
| Backend redeploy creates no tenant or key | Required | Required |
| Frontend build uses admin-created environment ID/key | Required | Required |
| Managed registration and signing smoke | Required | Required |

Run the narrow deployment-script tests first, followed by the authoritative onboarding and managed-registration contracts affected by the runtime scope change. Classify and remove bootstrap-only fixtures as obsolete rather than preserving deployment seeding for them.

## Completion criteria

- Staging and production use separate, explicitly identified D1 resources.
- Backend migrations and deployments never create an organization, project, environment, or API key.
- Gateway request handling contains no deployment-wide tenant identity fallback.
- Both frontends use administrator-created environment IDs and publishable keys.
- The deployed staging onboarding, registration, and signing flow succeeds from an empty tenant database.
- The deterministic deployment keys are revoked, and seeded tenant records are removed where dependency checks prove that removal is safe.
- The two legacy staging D1 database IDs are absent from Cloudflare and from all active configuration.
