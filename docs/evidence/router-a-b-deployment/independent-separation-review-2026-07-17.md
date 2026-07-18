# Router A/B Account and Operator Separation Review

Review date: 2026-07-17

Reviewed revision: `186e55d99f0a1df0f0229b44e6ceaf3aec00f013` on `dev`, including the current uncommitted working-tree changes.

## Conclusion

The repository enforces useful role-local runtime and secret boundaries. It does not currently contain a production deployment path that enforces independent Cloudflare accounts or operators. All nine items in the Production Release Evidence checklist remain open.

The checked-in Router A/B deployment workflow exposes `staging` only and retains `role=all`. The Deriver configs use mutual Service Bindings. Cloudflare documents that a Service Binding target must be on the caller's Cloudflare account, so these configs describe the same-account staging profile. Split filenames, Worker names, GitHub Environment names, secret names, and Durable Object class names express role intent. They do not prove independent administration.

The Yao deployment plan now records a claimed cross-account WebSocket run. No raw deployment receipt, operator attestation, Cloudflare version/account export, benchmark report, or B-role analytics export is present in the repository or configured through `YAOS_AB_DEPLOYMENT_RECEIPT_PATH`. The claim is therefore an unverified narrative for this review.

## Repository-enforced boundaries

- The workflow has separate staging GitHub Environment names for Router, SigningWorker, Deriver A, and Deriver B, and each deploy job references only its role's private material. `assert-release-ready.mjs` statically checks these source-level secret references.
- Router Wrangler configuration declares Router-owned Durable Objects and no Deriver root-share Durable Object. Deriver A and B declare different role-specific root-share classes. SigningWorker declares only its server-output class.
- Boundary parsers reject Router possession of Deriver private material, A possession of B private material, B possession of A private material, and Deriver possession of SigningWorker private material. Focused tests passed for 15 environment rejections, 13 binding rejections, and four role-scoped runtime storage-call builders.
- Source guards passed for ordinary Ed25519 signing and ECDSA signing prepare/finalize paths. Those paths forward to SigningWorker and contain no Deriver call. These are static source properties. A deployed trace has not been supplied.
- The deployment checker rejects `[env.production]` Wrangler branches and a production workflow option. Its successful `Router A/B release blockers clear` result certifies the current staging-only source boundary. It is not a production-separation attestation.
- The Yao benchmark environment parser requires different account IDs and different Wrangler profiles in two-account mode. Its ownership-receipt schema records account-ID commitments, artifact hashes, Worker tags, version IDs, targets, and deployment timestamps when an executed deployment supplies them. No completed receipt from the claimed run is available here.

## Gaps in the checked-in deployment assets

1. `.github/workflows/deploy-router-ab.yml` offers only `staging`, defaults to `role=all`, and can sequence all four role deployments from one workflow dispatch. It has no production environments, disjoint approver policy, disjoint OIDC subject, account-ID inequality check, deploy-principal identity check, or prohibition on a principal that can operate both A and B.
2. `wrangler.deriver-a.toml`, `wrangler.deriver-b.toml`, and `wrangler.router.toml` use Service Bindings on every A/B edge. This topology cannot represent the documented four-role separate-account deployment. Current Cloudflare documentation says the bound target Worker must be on the caller's account: <https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/>.
3. `generate-github-env-values.mjs` emits a single internal bearer secret into every staging role environment and leaves each Cloudflare account ID and API token as a manual placeholder. It checks neither account inequality nor token reachability. This is acceptable for the declared staging profile and cannot prove the production rule.
4. The checked-in configs have no production cross-account HTTPS endpoints, signed-request identity variables, account-bound manifests, storage namespace IDs, backup destinations, log sinks, audit exports, or deploy-principal IDs.
5. The release checker inspects source text and selected unit tests. It does not scan final Worker bundles or metafiles for opposite-role secret names/dependencies, and it does not bind a scan result to deployed Cloudflare version IDs.

## Yao WebSocket evidence integrity

`docs/yaos-ab-deployment.md` checks four Gate 1 items and names an A version, a B source commit, a deployment identity, timing summaries, and A trace summaries. The evidence needed to independently reproduce those facts is absent.

The current WebSocket fixtures and the receipt/evaluator path also disagree:

- `wrangler.a.cross-account.jsonc` fixes `BENCHMARK_TOPOLOGY` to `CROSS_ACCOUNT_WEBSOCKET` and reads `DERIVER_B_WEBSOCKET_ENDPOINT`.
- `deployment-env/two-account.env.example`, `deployment_boundary.mjs`, `plan_cloudflare_benchmark.mjs`, `deployment_receipt.mjs`, the Phase 13A evaluator, and their fixtures still use `DERIVER_B_HTTPS_ENDPOINT` and `cross-account-https`.
- `test:rendered-deployment-configs` passes because it still validates the HTTPS-era rendered variable. It does not validate the WebSocket endpoint used by the Worker fixture.
- `test:deployment-tooling` currently fails at `PHASE13A_REPORT_IDENTITY_MISMATCH: validated_inputs.file_count`.
- `test:phase13a-local-preflight` currently fails at `PHASE13A_LOCAL_ARTIFACT_DIGEST: crates/ed25519-yao-cloudflare-bench/tests/source_guards.rs`.

Until the boundary, planner, receipt schema, evaluator, fixtures, and local readiness bundle all describe the WebSocket topology and pass together, the repository cannot validate the new checkpoint through its canonical evidence chain.

A read-only HEAD request to `https://yaos-ab-benchmark.seams.sh/benchmark/activation` reached Cloudflare and returned HTTP 404. This establishes current hostname reachability only. It reveals no Worker version, account ID, route ownership, operator, or A/B independence.

## Production checklist disposition

| Checklist item | Status | Evidence available | Evidence still required |
| --- | --- | --- | --- |
| Independent deployment reviewer verifies account, CI, approver, credential, storage, backup, log, and audit separation | Open | Repository role names and split staging Environment references | Signed reviewer report over Cloudflare account membership exports, GitHub Environment protection/approver exports, OIDC subjects, token policies, DO namespace ownership, backup/log destinations, and audit-export ownership for A and B |
| Negative tests prove Router cannot access A/B stores and A/B cannot access the opposite resources | Open; partial local proof | Role/env parsers and runtime storage builders reject opposite-role scopes | Timestamped Cloudflare API/IAM denial receipts: product/Router principal denied A and B private stores; A principal denied B Worker/DO/secrets/backups/logs; B principal denied A equivalents; each result tied to principal ID and account ID without exposing credentials |
| Signed HTTPS negative tests cover peer, role, tampering, replay, expiry, sequence, duplicates, and stale epochs | Open | Some local role/key/replay checks exist | Release-candidate cross-account integration report for every listed case, bound to endpoint identities, deployment manifest digest, Worker version IDs, and operator signatures |
| Final role bundles scanned for opposite-role secrets and forbidden dependencies | Open; source checks only | Static source/config checks pass | Per-role final bundle plus metafile SBOM scan, secret-name/material scan, forbidden-dependency policy result, bundle SHA-256, and Cloudflare version mapping signed by the owning operator |
| Both operators reproduce and approve public digests independently | Open | No operator approvals found | Two independently signed approvals over identical source commit, protocol/circuit digest, A/B bundle digests, manifest digest, and deployed version IDs, with distinct verified operator identities |
| Cross-account performance/resource measurements pass | Open | Narrative 30-pair WebSocket summary and A-only trace summary | Canonical receipt-bound HTTP/WebSocket samples, A and B Cloudflare analytics exports, CPU/memory/outcome/error rows, retry/abort counts, payload/request counts, cost report, B operator export, and dated `go`/`stop` decision; evaluator must pass on the supplied artifacts |
| ECDSA bootstrap through signing vectors pass with zero Yao dependency | Open | Release checker and focused ECDSA source guards pass | Exact release-candidate test reports covering every named lifecycle, dependency scan, artifact digests, and deployed topology binding |
| Normal Ed25519 and ECDSA traces contain zero Deriver calls | Open; static source proof | Focused Ed25519 and ECDSA no-Deriver source tests pass | Deployed distributed trace exports for representative successful prepare/finalize operations, with Router and SigningWorker spans and zero A/B endpoint or Service Binding invocations, tied to version IDs |
| Rotation, restore, outage, and rollback drills pass | Open | No receipts found | Dated drill reports for credential rotation, peer-key rotation, restore under role-local authority, A outage, B outage, admission shutdown, and independently authorized rollback; include actors, account IDs, version/epoch transitions, logs, and reviewer sign-off |

## Minimum external evidence package

Each role operator should deliver a signed, timestamped package that exposes identifiers and policy metadata while excluding tokens and private keys:

1. Cloudflare account ID, Worker script name, Worker tag, version ID, deployment timestamp, route/custom-domain mapping, DO namespace IDs, and audit-log deploy event with deploy-principal ID.
2. A read-only `wrangler whoami --account ... --json` or equivalent API export proving the role principal reaches its own account, plus recorded authorization failures against the peer account. An independent reviewer must verify that neither principal appears in the peer account membership or token policy.
3. GitHub repository/environment export showing environment protection rules, reviewers, teams, deployment branch policy, OIDC subject, and secret inventory names. A/B reviewer and subject sets must be disjoint.
4. Backup destination, restore principal, log sink, and audit-export destination with account/project ownership. Include negative access results from the peer principal.
5. A shared public manifest signed separately by A and B operators. It should bind source commit, protocol/circuit digest, bundle and SBOM digests, public keys and epochs, endpoints, account IDs, storage namespace IDs, Worker versions, and evidence-schema version.
6. Receipt-bound benchmark, analytics, cost, deployed-trace, bundle-scan, and drill reports. The repository evaluator must accept the exact artifacts after its WebSocket schema transition is complete.

Distinct strings in manifests remain assertions until a Cloudflare/GitHub export or independent signed review binds them to external control-plane state.

## Commands and results

| Command | Result |
| --- | --- |
| `node crates/router-ab-cloudflare/scripts/assert-release-ready.mjs` | Pass: current staging-only source checks and four selected lifecycle tests passed |
| `cargo test ... --test bindings env_parser_rejects` | Pass: 15 tests |
| `cargo test ... --test bindings bindings_reject` | Pass: 13 tests |
| `cargo test ... --test bindings runtime_builds_only_` | Pass: 4 tests |
| `cargo test ... durable_object_call_rejects_router_access_to_signer_root_share -- --exact` | Pass: 1 test |
| `cargo test ... normal_signing_routes_do_not_invoke_ab_derivation_handlers -- --exact` | Pass: 1 test |
| `cargo test ... --test strict_router_route_boundaries router_ab_ecdsa_derivation_router_` | Pass: 2 tests |
| `pnpm -C crates/ed25519-yao-cloudflare-bench test:rendered-deployment-configs` | Pass; test remains aligned to the HTTPS-era planner |
| `pnpm -C crates/ed25519-yao-cloudflare-bench test:deployment-tooling` | Fail: local evidence bundle file-count mismatch |
| `pnpm -C crates/ed25519-yao-cloudflare-bench test:phase13a-local-preflight` | Fail: stale artifact digest for `tests/source_guards.rs` |
| Read-only HEAD request to the documented benchmark endpoint | Reachable through Cloudflare; HTTP 404; no account/operator inference available |

No deployed browser evidence test ran because all required `ROUTER_AB_DEPLOYED_*` inputs were unset. No deployment or cleanup command was executed.
