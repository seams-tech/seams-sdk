# Signing Architecture (`client/src/core/signingEngine`)

This folder is the SDK signing runtime for NEAR, EVM, and Tempo flows. The
Refactor 33 layout is organized by call direction: public engine methods enter a
single operation module, operation modules call state/session/confirmation/
chain/threshold/worker modules, and child modules do not call back into
flows or `SigningEngine`.

## Public Entrypoints

- `index.ts`: public SDK signing-engine export surface.
- `SigningEngine.ts`: product-level facade. Public methods should delegate to
  one feature entry module within one hop and keep deeper composition inside
  `assembly/*`, `flows/*`, `session/public.ts`, `session/warmSigning/public.ts`,
  or other documented public boundary owners.
- `assembly/`: assembles runtime dependencies and operation ports for `SigningEngine`.

## Folder Roles

- `flows/`: vertical signing, registration, recovery, and email-OTP
  operation paths.
- `flows/shared/`: shared operation state machine, command ports, and
  confirmation command runner.
- `session/`: selected lane identity, available lanes, readiness, record
  normalization, restore, planning, budget, sealed persistence, and
  warm-session state.
- `session/planning/`: signing-operation planning, operation fingerprints, and
  operation-id binding.
- `session/budget/`: wallet signing-session budget reads, projection,
  reservation, and spend finalization.
- `sessionEmailOtp/`: Email OTP threshold-session provisioning, restoration,
  and warm-session status coordination.
- `stepUpConfirmation/`: confirmation contracts, email-OTP/passkey prompts, intent
  digest preparation, and channel message contracts.
- `chains/`: chain-specific payload, display, nonce, and WASM adaptor code.
- `threshold/`: threshold protocol clients and protocol material handling.
- `workers/` and `workerManager/`: worker operation dispatch, worker types, and
  host-side worker transport.
- `nonce/`: nonce reservation and lifecycle coordination.
- `walletAuth/`: higher-level wallet auth policy helpers and the remaining
  legacy auth-plan resolver path.
- `webauthnAuth/`: low-level WebAuthn/passkey browser primitives.
- `interfaces/accountAuthMetadata.ts`: neutral account-auth metadata
  normalized for step-up method selection and operation planning.
- `interfaces/`: shared public/runtime contracts and primitive cross-domain
  signing identifiers such as ECDSA chain targets.

Auth methods are symmetric at the prompt/auth-plan boundary:
`stepUpConfirmation/passkeyPrompt` and `stepUpConfirmation/otpPrompt` own method
prompt construction. Method session folders are introduced only for durable
cross-operation lifecycle ownership, which is why Email OTP has
`sessionEmailOtp/` and passkey currently has no `sessionPasskey/`. The ongoing
step-up adaptor refactor has already moved neutral account-auth metadata into
`interfaces/accountAuthMetadata.ts`, moved low-level WebAuthn
primitives into `webauthnAuth/`, and is shrinking `walletAuth/` toward the
remaining legacy resolver only.

## Import Direction

```mermaid
flowchart TD
  SP["SeamsPasskey / SDK"] --> SE["SigningEngine.ts"]
  SE --> INIT["assembly/"]
  SE --> OPS["flows/*"]
  INIT --> SESSION["session/"]
  INIT --> EMAILOTP["sessionEmailOtp/"]
  INIT --> CONF["stepUpConfirmation/"]
  INIT --> THRESHOLD["threshold/"]
  INIT --> CHAINS["chains/"]
  INIT --> WORKERS["workers/ + workerManager/"]
  INIT --> AUTH["walletAuth/"]
  INIT --> UI["uiConfirm/"]
  INIT --> NONCE["nonce/"]
  INIT --> IFACE["interfaces/"]
  INIT --> WEBAUTHN["webauthnAuth/"]
  OPS --> SESSION
  OPS --> EMAILOTP
  OPS --> CONF
  OPS --> THRESHOLD
  OPS --> CHAINS
  OPS --> WORKERS
  OPS --> NONCE
  CONF --> AUTH
  CONF --> WEBAUTHN
  CONF --> IFACE
  UI --> CONF
  UI --> WEBAUTHN
```

Rules enforced by Refactor 33 guards:

- `flows/*` must not import `SigningEngine` or assembly construction.
- Child folders must not import `flows/*`.
- New broad internal `index.ts` barrels are blocked.
- Deleted `api/`, `orchestration/`, `chainAdaptors/`, and `signers/` paths stay
  deleted.

## Operation Pipeline

```mermaid
sequenceDiagram
  participant SDK as "SDK caller"
  participant SE as "SigningEngine"
  participant OP as "flows/*"
  participant SS as "session/*"
  participant CF as "stepUpConfirmation/*"
  participant CH as "chains/*"
  participant TH as "threshold/*"
  participant WK as "workers/*"
  participant NC as "nonce/*"

  SDK->>SE: "sign / export / register"
  SE->>OP: "delegate to operation"
  OP->>SS: "select lane, restore, reserve budget"
  OP->>CF: "confirm passkey or email OTP"
  OP->>TH: "authorize/connect/sign threshold material"
  OP->>CH: "build payload/display/final tx"
  OP->>WK: "run signer/WASM worker command"
  OP->>NC: "reserve/commit nonce when required"
  OP-->>SE: "signed result"
  SE-->>SDK: "SDK response"
```

## Key State Shapes

- `SelectedLane` (`session/identity/laneIdentity.ts`): canonical selected
  signing lane. Its object construction is owned by
  `session/identity/laneIdentity.ts`.
- `LaneCandidate` (`session/identity/laneIdentity.ts`): concrete candidate derived from
  available lane or persisted session records before selection.
- `SelectedSigningSessionPlanningLane` (`session/signingSession/types.ts`):
  planning-layer extension for operation planning, storage source, retention,
  and backing material context.
- `SigningSessionPlan` (`session/planning/planner.ts`): planned operation
  identity bound to one selected lane before confirmation, signing, and budget
  stages execute.
- `WalletSigningBudgetReservation` (`session/budget/budget.ts`): budget
  reservation and spend identity that follows the selected lane through the
  finalization path.
- `ThresholdEcdsaSessionRecord` / `ThresholdEd25519SessionRecord`
  (`session/persistence/records.ts`): persistence records normalized at
  storage boundaries.
- `ThresholdEcdsaChainTarget` (`interfaces/ecdsaChainTarget.ts`): neutral EVM
  and Tempo chain target identity shared by session, prompt, threshold, and
  operation modules.
- `PreparedOperation`, `BudgetAdmittedOperation`, and `SignedOperation`
  (`flows/shared/operationState.ts`): monotonic operation state-machine
  states.

## EVM/Tempo Signing

```mermaid
flowchart LR
  SE["SigningEngine.signEvm/signTempo"] --> OP["flows/signEvmFamily/signEvmFamily.ts"]
  OP --> PREP["preparedSigning.ts"]
  PREP --> SELECT["session/identity/selectLane.ts"]
  SELECT --> ID["session/identity/laneIdentity.ts"]
  OP --> PLAN["session/planning/planner.ts"]
  OP --> BUDGET["session/budget/budget.ts"]
  OP --> AUTH["authPlanning.ts + stepUpConfirmation prompts"]
  OP --> TH["threshold/ecdsa/*"]
  OP --> CH["chains/evm + chains/tempo"]
  OP --> NONCE["nonce/"]
  OP --> FINAL["postSignFinalization.ts"]
```

EVM and Tempo share the ECDSA operation path. Chain differences are isolated in
`chains/evm`, `chains/tempo`, nonce lifecycle modules, and final transaction
encoding.

## NEAR Signing

```mermaid
flowchart LR
  SE["SigningEngine.signNear*"] --> OP["flows/signNear/signNear.ts"]
  OP --> TX["signTransactions.ts / signDelegate.ts / signNep413.ts"]
  TX --> SELECT["session/identity/selectLane.ts"]
  TX --> CONF["flows/shared/signingConfirmation.ts"]
  TX --> TH["threshold/ed25519/*"]
  TX --> CH["chains/near/*"]
  TX --> WK["workers/near signer"]
```

NEAR uses the same operation state-machine approach as EVM/Tempo, with Ed25519
threshold material and NEAR-specific payload/display assembly.
