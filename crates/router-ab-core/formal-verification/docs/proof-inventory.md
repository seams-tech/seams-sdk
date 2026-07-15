# Fixed ECDSA Threshold-PRF Proof Inventory

| Claim | Evidence |
| --- | --- |
| Client opens only `x_client_base` | Verus model plus Rust anti-drift test |
| SigningWorker opens only `x_server_base` | Verus model plus Rust anti-drift test |
| Router observes no plaintext A/B partial | Verus role-view model |
| One role does not observe forbidden joined state | Verus and Lean event models |
| Production role labels match the model | Rust anti-drift test |
| Activation context is identical for A/B payloads | Rust anti-drift test |
| Fixed A=`1`, B=`2` policy | Rust constructors, role checks, negative tests; formal proof planned |
| Context/transcript field inclusion and order | Rust vectors; formal byte model planned |
| Root-epoch and recipient separation | Rust negative tests; formal proof planned |
| DLEQ and PRF security | External cryptographic assumptions |

Split-root, candidate selection, correctness levels, and generic t-of-n
selection are absent from the proof surface.
