# Refactor 82 D1/DO Staging Deployment Log

Status: template. Generate the active log only after
`pnpm --dir packages/sdk-server-ts run d1:staging:check` passes against copied
staging Wrangler configs.

```sh
pnpm --dir packages/sdk-server-ts run d1:staging:runbook -- \
  --output ../../docs/deployment/refactor-82-staging-log.md \
  --r2-bucket <staging-r2-backup-bucket> \
  --console-origin <console-staging-origin> \
  --router-api-origin <router-api-staging-origin>
```

Do not record secret values in this file. Record secret names, binding names,
Cloudflare resource IDs, command output summaries, object keys, bookmarks, and
pass/fail evidence only.

## Required Evidence

| Check | Result | Evidence location |
| --- | --- | --- |
| Staging readiness |  |  |
| Console migrations |  |  |
| Signer migrations |  |  |
| Time Travel before fixture import |  |  |
| Fixture import |  |  |
| Time Travel before route switch |  |  |
| Console `/readyz` |  |  |
| Router API `/readyz` |  |  |
| Dashboard reconciliation |  |  |
| Sponsored gas settlement and prepaid billing |  |  |
| Signer custody and KEK isolation |  |  |
| R2 export object keys |  |  |
| Restore drill integrity checks |  |  |

## Sign-Off

- [ ] Staging starts on D1/DO.
- [ ] No request path mixes D1/DO and Postgres.
- [ ] Console Worker has no signer D1, Durable Object, or KEK bindings.
- [ ] Time Travel bookmarks are captured before fixture import and before route
      traffic switch.
- [ ] R2 export and restore drill evidence is recorded.
- [ ] Dashboard reconciliation, sponsored gas settlement, and signer custody
      checks pass.
