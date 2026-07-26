# Refactor 93 staging custody rotation

Date: 2026-07-26

Scope: staging only. Production custody and deployment state are excluded.

## Reason

The frozen staging deployment admitted `root_share_epoch=epoch-1`. Persisted
Ed25519 role metadata still named `default`, while the ECDSA role metadata
required `epoch-1`. A dual-branch registration therefore could not complete
under one coherent signing-root scope.

## Authorized effect

The operator authorized replacement of staging custody material with the
understanding that existing staging wallets become unusable. The rotation
replaces this matched 2-of-2 pair:

- GitHub Environment `staging-deriver-a`, secret
  `DERIVER_A_ROOT_SHARE_WIRE_SECRET`;
- GitHub Environment `staging-deriver-b`, secret
  `DERIVER_B_ROOT_SHARE_WIRE_SECRET`.

The secrets must be generated and applied as one pair. Secret values never
belong in this repository, command logs, deployment receipts, or observability
records.

## Durable Object scope

The staging-only role-local root-share objects move to fresh scopes:

- `deriver-a-root-share-staging-r2` with key prefix
  `deriver-a-root-share-staging-r2/`;
- `deriver-b-root-share-staging-r2` with key prefix
  `deriver-b-root-share-staging-r2/`.

Production keeps the existing object names and prefixes. The old staging
objects remain unreachable after deployment and are retained until the
rotation is verified.

## Backup receipt

The matched pair was generated locally before any GitHub write:

- protected backup:
  `/Users/pta/.seams/backups/refactor-93-staging-custody-20260726/root-share-secrets.json`;
- directory mode: `0700`;
- file mode: `0600`;
- SHA-256:
  `751f76ff85dd2a30d088bb279c14a2cb9d343be0eba2690225dc861af30466b1`;
- generator policy: threshold 2, share count 2, Deriver A share 1,
  Deriver B share 2.

The checksum identifies the protected backup as a whole. It does not expose a
secret value.

## Execution state

- [x] Generate a matched pair and write the protected local backup.
- [x] Commit fresh staging-only Durable Object scopes.
- [x] Verify the protected backup under `~/.seams/backups` before any remote
      secret write.
- [x] Upload each share to its exact GitHub Environment. GitHub recorded the A
      update at `2026-07-25T20:47:53Z` and the B update at
      `2026-07-25T20:47:55Z`.
- [x] Deploy one frozen revision containing the new staging object scopes.
      Deployment workflow run
      [`30174308501`](https://github.com/seams-tech/seams-sdk/actions/runs/30174308501)
      completed successfully from frozen `dev` revision `bf3642dc4`.
- [x] Verify Deriver A, Deriver B, Router, SigningWorker, and Gateway readiness.
      The workflow smoke suite and an independent check returned HTTP 200 for
      `/readyz`, `/healthz`, the ceremony JWKS endpoint, and both Router A/B
      health endpoints. Cloudflare reported these version IDs:
  - Deriver A: `ad6aad41-68f9-4d5b-8db8-dd298d2d3375`;
  - Deriver B: `6b5ece4b-9125-4904-b4ba-82fcda73d9eb`;
  - SigningWorker: `d3867506-c277-4ab8-9a42-b2ba0bcf472e`;
  - Router: `bc2b4664-7007-435a-ace8-a2fa4271b596`;
  - Gateway: `93da5b8f-3714-4746-a092-4ddee0bc4815`.
- [ ] Run a fresh dual-branch registration under `root_share_epoch=epoch-1`.
- [ ] Record version IDs, workflow run, trace correlation ID, and result in
      `docs/refactor-93.md` without recording custody material.

Do not restore only one share. Rollback requires restoring the matched prior
pair and the prior object scopes together, followed by a coherent redeploy.
