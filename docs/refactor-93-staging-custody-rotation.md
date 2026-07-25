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
- [ ] Operator confirms the protected backup has been copied to durable secret
      storage.
- [ ] Upload each share to its exact GitHub Environment.
- [ ] Deploy one frozen revision containing the new staging object scopes.
- [ ] Verify Deriver A, Deriver B, Router, SigningWorker, and Gateway readiness.
- [ ] Run a fresh dual-branch registration under `root_share_epoch=epoch-1`.
- [ ] Record version IDs, workflow run, trace correlation ID, and result in
      `docs/refactor-93.md` without recording custody material.

Do not restore only one share. Rollback requires restoring the matched prior
pair and the prior object scopes together, followed by a coherent redeploy.
