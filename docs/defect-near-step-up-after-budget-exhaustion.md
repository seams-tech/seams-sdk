# Defect — NEAR signing throws instead of stepping up once the budget is spent

Date: August 25, 2026

Found while regression-checking the base unlock contracts at the close of
Refactor 109C. Not caused by R109C, and not fixed by it.

## Symptom

Three unmodified base contracts fail at the same point:

- `passkey.unlock.contract.test.ts` — "passkey unlock restores immediate export
  and shared-budget signing"
- `passkey.unlock.contract.test.ts` — "page refresh hydrates warm signing,
  one-use step-up, and key export"
- `email-otp.unlock.contract.test.ts` — "Email OTP registration and unlock
  lifecycle"

Each reaches the `step_up_required` stage - the shared signing budget is spent,
`remainingUses=0` - and the next NEAR signature fails instead of prompting:

    Intended action signNearTransaction failed:
      [SigningEngine][near] active Wallet Session is unavailable

The wallet iframe never opens a confirmation (`attempts:1, clicked:false`),
because the throw happens before the prompt.

## Cause

`BrowserSigningSurface.prepareMaterialIdentityNearEd25519YaoSigning`, at the
live-runtime fast path:

    if (activeMaterial && liveRuntime.kind === 'live') {
      const authorizationRead = await walletSessionAuthorizations.readActiveForWallet(...)
      ...
      const reusableSession = await this.readReusableWalletSessionState(args.walletId);
      if (
        reusableSession.kind !== 'active' ||
        reusableSession.walletSessionId !== authorizationRead.projection.walletSessionId ||
        reusableSession.authMethod !== authorizationRead.projection.authMethod
      ) {
        throw new Error('[SigningEngine][near] active Wallet Session is unavailable');
      }

A live Ed25519 runtime outlives the session budget, so after exhaustion the
branch is entered with `reusableSession.kind === 'exhausted'` and throws. There
is no fall-through to the step-up path that a spent session is supposed to take.
The condition reads as an invariant check, but exhaustion is an ordinary state,
not a violation.

## Why this is not R109C

- The throwing block, `readReusableWalletSessionState`, and the wallet-session
  authorization store are byte-identical to `dev` - `git diff dev..HEAD` over
  those files shows no change but an added comment. The block was introduced by
  `a4223287e` (R103E), which is on `dev`.
- Both failing contract files are unmodified on the branch.
- The failing wallet holds one auth method. Every R109C signing change is
  conditioned on siblings: the ECDSA lane collapse is a no-op with one lane, and
  `ownerAuthorityMatchesLane` narrows only for `email_otp`.

Not independently verified against a `dev`-built stack, which would mean
rebuilding over the dist the running local stack serves.

## Related

The same shape as the defect R109C closed in `cea648639`: a caller reading
wallet-session state back out of the store rather than consuming the state it
already holds. `readActiveForWallet` reads only the older active projection and
filters out exact V4/V5 rows, so anything that mints an exact row and then reads
it back finds nothing. Worth checking whether the step-up mint here writes the
row that this read cannot see.
