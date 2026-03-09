# Policy Draft Persistence Plan

Last updated: 2026-03-09
Status: implemented

## Goal

Prevent accidental loss of in-progress policy edits in the dashboard when:

- a modal is closed by mistake
- the user navigates away and comes back
- the page refreshes unexpectedly

This plan covers local draft persistence for the dashboard policy builders using `sessionStorage`.

## Why this is needed

Today, modal builders keep their draft state only in React component state.

That means:

- closing the modal discards unsaved edits
- refreshing the page discards unsaved edits
- switching away from the page discards unsaved edits

For complex builders like policy creation and gas sponsorship, that is bad UX and easy to lose work with.

## Product decision

We will persist drafts locally in the browser with `sessionStorage`.

We will not create server-side draft autosave in this phase.

This gives:

- restore on accidental close
- restore on accidental refresh
- isolation to the current browser tab/session
- no backend complexity

## Scope

In scope:

- dashboard modal builders that create or edit policy-like resources
- create and edit drafts
- restore by route, selected scope, and edit target
- explicit discard behavior
- automatic clear on successful save

Out of scope:

- cross-device sync
- sharing drafts across users
- backend-stored autosave
- version history for unsaved drafts
- preserving drafts forever after browser session end

## Initial rollout targets

First release routes (required together):

- `https://localhost/dashboard/gas-sponsorship` (`/dashboard/gas-sponsorship`)
- `https://localhost/dashboard/policy-engine` (`/dashboard/policy-engine`)

Draft persistence is not complete until both routes are wired and verified.

The design should stay reusable for later dashboard builders that use modal-driven forms.

## UX contract

### Create flow

When a user opens `Create policy`:

- if there is no saved draft for the current scope, start from normal defaults
- if there is a saved draft for the current scope, restore it automatically

When the user edits fields:

- save the draft to `sessionStorage` as they type

When the modal closes without saving:

- keep the draft
- reopening the same create flow restores the last in-progress values

When the user saves successfully:

- clear the saved draft

When the user explicitly chooses discard:

- clear the saved draft

### Edit flow

When a user opens `Edit` for an existing config or policy:

- if there is no saved draft for that specific resource, start from the server-backed values
- if there is a saved draft for that same resource, restore it automatically

Drafts for edit must be scoped to the resource being edited, not just the page.

When the modal closes without saving:

- keep the draft

When save succeeds:

- clear the draft for that edited resource

When discard is chosen:

- clear the draft and revert to the last saved server-backed state next time

### Refresh and navigation

If the page is refreshed:

- reopening the same modal in the same tab should restore the draft

If the selected org, project, or environment changes:

- do not restore a draft from a different scope

## Storage design

Use `sessionStorage`.

Reason:

- protects against accidental refresh and close-reopen within the same tab
- avoids long-lived stale drafts across separate browser sessions
- safer default than `localStorage` for admin console form state

### Draft key format

Draft keys should include:

- route
- org id
- project id
- environment id
- mode
- edited resource id where applicable
- schema version

Example shape:

```ts
type DraftStorageKeyParts = {
  version: 'v1';
  route: '/dashboard/policy-engine' | '/dashboard/gas-sponsorship';
  orgId: string;
  projectId: string;
  environmentId: string;
  mode: 'create' | 'edit';
  resourceId?: string;
};
```

Example serialized key:

```txt
dashboard-draft:v1:/dashboard/gas-sponsorship:org_123:proj_456:env_789:create
dashboard-draft:v1:/dashboard/gas-sponsorship:org_123:proj_456:env_789:edit:gs_abc
dashboard-draft:v1:/dashboard/policy-engine:org_123:proj_456:env_789:edit:policy_xyz
```

### Stored payload

Each stored draft should contain:

- serialized form state
- route
- mode
- resource id if editing
- scope identifiers
- timestamp
- schema version

Example:

```ts
type StoredDashboardDraft<TForm> = {
  version: 'v1';
  route: string;
  mode: 'create' | 'edit';
  resourceId: string | null;
  orgId: string;
  projectId: string;
  environmentId: string;
  savedAt: string;
  form: TForm;
};
```

## Restore rules

Restore should be strict and fail closed.

Only restore when all of these match:

- route matches
- mode matches
- scope matches
- resource id matches for edit mode
- payload version is supported
- payload shape is valid

If parsing or validation fails:

- ignore the draft
- remove the corrupt entry
- fall back to normal defaults

## Shared implementation shape

Introduce a small shared dashboard utility instead of route-local ad hoc code.

Suggested files:

- `examples/tatchi-site/src/pages/dashboard/drafts/sessionDraftStore.ts`
- `examples/tatchi-site/src/pages/dashboard/drafts/useSessionDraft.ts`

Suggested responsibilities:

- build deterministic storage keys
- read and validate stored drafts
- write drafts
- clear drafts
- expose a small hook for modal builders

Example hook contract:

```ts
type UseSessionDraftArgs<TForm> = {
  route: string;
  mode: 'create' | 'edit';
  orgId: string;
  projectId: string;
  environmentId: string;
  resourceId?: string;
  initialForm: TForm;
  isOpen: boolean;
};

type UseSessionDraftResult<TForm> = {
  form: TForm;
  setForm: React.Dispatch<React.SetStateAction<TForm>>;
  restoreState: 'default' | 'restored';
  clearDraft: () => void;
  resetToInitial: () => void;
};
```

The hook should:

- load once when the modal opens
- restore a saved draft if present
- persist after field edits
- expose explicit clear/reset helpers

## Route integration plan

### Gas sponsorship

Integrate draft persistence into:

- create modal
- edit modal

Behavior:

- opening create uses `create` draft key
- opening edit uses `edit:<configId>` draft key
- submit success clears the matching draft
- cancel should not discard by default
- provide a separate `Discard draft` action for explicit destructive clear

### Policy engine

Integrate draft persistence into:

- create policy modal
- edit policy modal

The same route has more draft state than gas sponsorship, so it should use the shared utility first and avoid duplicating storage logic inside the page component.

## UI behavior details

When a draft is restored:

- show a small notice like `Restored unsaved draft.`

When a draft is saved locally:

- do not show noisy toasts on every keystroke

When a user wants a clean start:

- provide an explicit `Discard draft` action
- confirm only if the draft differs from the initial state

The modal close button and backdrop close should not discard by default.

## Edge cases

- If the edit target no longer exists, clear that edit draft.
- If the selected scope changes while a modal is open, close the modal and keep the draft under the old scope key.
- If a saved draft references fields no longer supported by the form version, drop unsupported fields during validation or clear the draft entirely.
- If storage quota errors occur, fail silently for persistence and keep the in-memory form usable.
- If `sessionStorage` is unavailable, continue without persistence.

## Testing plan

### Unit tests

- draft key generation
- store/read/clear helpers
- invalid JSON handling
- version mismatch behavior
- scope mismatch behavior
- edit resource mismatch behavior

### UI tests

Gas sponsorship:

- open create modal, type values, close modal, reopen, values restored
- type values, refresh page, reopen modal, values restored
- save successfully, reopen modal, draft cleared
- edit existing config, change values, close modal, reopen same config, values restored
- edit one config, open a different config, wrong draft is not restored

Policy engine:

- create draft restore
- edit draft restore
- scope switch does not leak drafts across scope

## Phased todo list

Release gate: both Phase 2 and Phase 3 must be complete before this work can be marked done.

### Phase 0: Lock behavior

- [x] Confirm `sessionStorage` is the chosen persistence layer.
- [x] Confirm drafts are tab-local, not cross-browser persistent.
- [x] Confirm modal close keeps the draft.
- [x] Confirm successful save clears the draft.
- [x] Confirm explicit discard is the only destructive clear path besides successful save.

### Phase 1: Shared draft storage utility

- [x] Add a shared dashboard draft-key builder.
- [x] Add safe `sessionStorage` read/write/clear helpers.
- [x] Add runtime validation for stored draft payloads.
- [x] Add schema versioning for stored drafts.
- [x] Add unit tests for storage helpers.

### Phase 2: Gas sponsorship modal integration

- [x] Restore create drafts when opening `Create policy`.
- [x] Restore edit drafts when opening `Edit` for a config.
- [x] Persist draft changes while editing.
- [x] Clear drafts on successful create/update.
- [x] Add explicit `Discard draft` action.
- [x] Add restored-draft notice.

### Phase 3: Policy engine modal integration

- [x] Move policy-engine modal form state onto the shared draft utility.
- [x] Restore create drafts by selected scope.
- [x] Restore edit drafts by `policyId`.
- [x] Clear drafts on successful save.
- [x] Add explicit discard path without deleting on ordinary close.
- [x] Add restored-draft notice.

### Phase 4: Validation and cleanup

- [x] Add Playwright coverage for close/reopen restore and refresh restore.
- [x] Remove any route-local ad hoc draft persistence helpers.
- [x] Ensure both builders use the same shared storage utility.
- [x] Verify no stale drafts leak across scope changes.
- [x] Document the UX contract in page copy only where it helps, not as noisy boilerplate.

## Exit criteria

This work is complete when:

- closing a create or edit modal no longer loses work
- refreshing the page no longer loses work in the same tab
- drafts restore only for the exact matching route, scope, and edit target
- successful save clears the corresponding draft
- both gas sponsorship and policy engine use the same draft persistence approach

## Completed tasks (2026-03-09)

- [x] Shared dashboard draft storage utility added (`sessionDraftStore` + `useSessionDraft`).
- [x] Gas sponsorship create/edit modals wired to shared session draft persistence.
- [x] Policy engine create/edit modals wired to shared session draft persistence.
- [x] Restored-draft notice and explicit `Discard draft` actions added to both routes.
- [x] Successful save clears matching create/edit draft in both routes.
- [x] Unit coverage added for storage keying, payload validation, and cleanup behavior.
- [x] Route-targeted e2e coverage added for close/reopen restore, refresh restore, and clear-on-save.
- [x] Route-targeted e2e tests passed:
  - `gas sponsorship page wires create and validates scope requirements`
  - `policy-engine page schedules live policy changes through approvals`
- [x] Dashboard site production build passed (`pnpm -C examples/tatchi-site build`).

## Next steps

- [x] Reconcile full dashboard e2e selectors/assertions with current route and UI labels:
  - billing redirect assertion updated for `/dashboard/billing/account`
  - team-members action selectors updated (`Edit` / `Delete`)
  - audit filter interactions updated to current controls (no manual reload button)
  - ops cockpit and overview queue selectors updated to section-based panels
- [x] Re-run full `tests/e2e/dashboard.consoleConfigPages.apiWiring.test.ts`:
  - result: `30 passed`
- [ ] Optional hardening: add unit tests focused on `useSessionDraft` hook lifecycle behavior (open/close and identity switch transitions).
