# Ed25519 HSS Benchmarks

Date updated: June 11, 2026

Current retained backend: `ddh_hss_backend_v4_ch_gated_select_root`

This document summarizes the product-visible HSS registration benchmark signals
after the optimization-6 refactor. Detailed experiment history remains in
`optimization-experiment-ledger.md`, and raw product smoke summaries remain in
`benchmarks/registration-flow/out/`.

## Product Smoke Sources

Scenario order in the compact tables below:

1. `passkey_ed25519_only_wallet_iframe`
2. `passkey_ed25519_and_ecdsa_wallet_iframe`
3. `passkey_ed25519_only_host_origin`
4. `passkey_ed25519_and_ecdsa_host_origin`

| Run | Backend / state | Source |
| --- | --- | --- |
| `20260610-152611Z` | pre-current retained product baseline after mixed shared-mask restoration | `benchmarks/registration-flow/out/20260610-152611Z/summary.md` |
| `20260610-170749Z` | retained A2B v2 BLAKE3-base carry-material root | `benchmarks/registration-flow/out/20260610-170749Z/summary.md` |
| `20260611-041314Z` | retained `Ch` gated-select root | `benchmarks/registration-flow/out/20260611-041314Z/summary.md` |

## Client Artifact Runtime

`ed25519EvaluationArtifactMs` is the product-facing HSS client artifact timing.
It is the main product keep gate for HSS kernel changes.

| Run | `ed25519EvaluationArtifactMs` p50 by scenario |
| --- | --- |
| `20260610-152611Z` | `503 / 506 / 505 / 505ms` |
| `20260610-170749Z` | `445 / 445 / 443 / 443ms` |
| `20260611-041314Z` | `430 / 431 / 422 / 420ms` |

Compared with `20260610-152611Z`, the current retained backend improves
artifact p50 by:

| Scenario | Before | Current | Delta | Improvement |
| --- | ---: | ---: | ---: | ---: |
| Ed25519 only, wallet iframe | `503ms` | `430ms` | `-73ms` | `14.5%` |
| Ed25519 plus ECDSA, wallet iframe | `506ms` | `431ms` | `-75ms` | `14.8%` |
| Ed25519 only, host origin | `505ms` | `422ms` | `-83ms` | `16.4%` |
| Ed25519 plus ECDSA, host origin | `505ms` | `420ms` | `-85ms` | `16.8%` |

Compared with the retained A2B v2 run, the `Ch` root adds a smaller retained
product win:

| Scenario | A2B v2 | Current | Delta | Improvement |
| --- | ---: | ---: | ---: | ---: |
| Ed25519 only, wallet iframe | `445ms` | `430ms` | `-15ms` | `3.4%` |
| Ed25519 plus ECDSA, wallet iframe | `445ms` | `431ms` | `-14ms` | `3.1%` |
| Ed25519 only, host origin | `443ms` | `422ms` | `-21ms` | `4.7%` |
| Ed25519 plus ECDSA, host origin | `443ms` | `420ms` | `-23ms` | `5.2%` |

## Worker Hidden-Eval Runtime

The HSS worker diagnostic `hiddenEvalTotalMs` moved in the same direction as
the product artifact timing.

| Run | `hiddenEvalTotalMs` p50 by scenario |
| --- | --- |
| `20260610-152611Z` | `461 / 464 / 470 / 476ms` |
| `20260610-170749Z` | `403 / 402 / 410 / 408ms` |
| `20260611-041314Z` | `385 / 385 / 385 / 384ms` |

Compared with `20260610-152611Z`, the current retained backend improves worker
hidden-eval p50 by:

| Scenario | Before | Current | Delta | Improvement |
| --- | ---: | ---: | ---: | ---: |
| Ed25519 only, wallet iframe | `461ms` | `385ms` | `-76ms` | `16.5%` |
| Ed25519 plus ECDSA, wallet iframe | `464ms` | `385ms` | `-79ms` | `17.0%` |
| Ed25519 only, host origin | `470ms` | `385ms` | `-85ms` | `18.1%` |
| Ed25519 plus ECDSA, host origin | `476ms` | `384ms` | `-92ms` | `19.3%` |

Compared with the retained A2B v2 run:

| Scenario | A2B v2 | Current | Delta | Improvement |
| --- | ---: | ---: | ---: | ---: |
| Ed25519 only, wallet iframe | `403ms` | `385ms` | `-18ms` | `4.5%` |
| Ed25519 plus ECDSA, wallet iframe | `402ms` | `385ms` | `-17ms` | `4.2%` |
| Ed25519 only, host origin | `410ms` | `385ms` | `-25ms` | `6.1%` |
| Ed25519 plus ECDSA, host origin | `408ms` | `384ms` | `-24ms` | `5.9%` |

## Server Registration Routes

Server-side registration HSS route p50 stayed in the same rough band. This
means the retained optimization-6 gain is primarily client artifact and worker
hidden-eval runtime.

| Run | Prepare p50 | Respond p50 | Finalize p50 | Sum of route p50s |
| --- | --- | --- | --- | --- |
| `20260610-152611Z` | `382 / 385 / 383 / 378ms` | `84 / 99 / 82 / 92ms` | `53 / 54 / 51 / 52ms` | `519 / 538 / 516 / 522ms` |
| `20260610-170749Z` | `386 / 384 / 378 / 381ms` | `85 / 99 / 81 / 91ms` | `54 / 54 / 50 / 52ms` | `525 / 537 / 509 / 524ms` |
| `20260611-041314Z` | `392 / 390 / 390 / 384ms` | `88 / 100 / 85 / 97ms` | `56 / 56 / 53 / 56ms` | `536 / 546 / 528 / 537ms` |

## Live Registration Log

A single manual registration log for `gorp55.w3a-server.testnet` showed:

| Step | Time |
| --- | ---: |
| Registration HSS prepare | `454ms` |
| Registration HSS respond | `106ms` |
| Registration HSS finalize | `76ms` |
| Registration HSS subtotal | `636ms` |
| NEAR account creation to `EXECUTED_OPTIMISTIC` | `1973ms` |
| Key visibility verification | `283ms` |
| Account creation subtotal | `2256ms` |
| Three server seal apply calls | `38ms` |
| Visible server subtotal | `2930ms` |

The same log included two later post-registration HSS cycles:

| Cycle | Prepare | Respond | Finalize | Total |
| --- | ---: | ---: | ---: | ---: |
| 1 | `388ms` | `78ms` | `71ms` | `537ms` |
| 2 | `392ms` | `104ms` | `76ms` | `572ms` |

The live log confirms the current server timings are in the expected product
smoke band. For end-to-end registration, the visible server-side cost is now
dominated by NEAR account creation rather than the HSS kernel.
