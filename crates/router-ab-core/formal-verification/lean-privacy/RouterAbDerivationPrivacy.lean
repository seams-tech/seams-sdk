namespace RouterAbDerivationPrivacy

inductive Role where
  | router
  | deriverA
  | deriverB
  | client
  | signingWorker
deriving DecidableEq, Repr

inductive ForbiddenJoinedState where
  | joinedD
  | joinedA
  | joinedXClientBase
  | joinedYServer
  | joinedTauServer
deriving DecidableEq, Repr

inductive OpenedValueKind where
  | xClientBase
  | xServerBase
deriving DecidableEq, Repr

inductive MpcPrfPartialOwner where
  | deriverA
  | deriverB
deriving DecidableEq, Repr

inductive RoleViewEvent where
  | publicMetadata
  | ciphertext
  | deriverAMpcPrfPartialXClientBase
  | deriverAMpcPrfPartialXServerBase
  | deriverBMpcPrfPartialXClientBase
  | deriverBMpcPrfPartialXServerBase
  | clientOpenedXClientBase
  | signingWorkerOpenedXServerBase
  | joinedD
  | joinedA
  | joinedXClientBase
  | joinedYServer
  | joinedTauServer
deriving DecidableEq, Repr

def eventContainsForbiddenJoinedState
    (event : RoleViewEvent)
    (state : ForbiddenJoinedState) : Bool :=
  match event, state with
  | RoleViewEvent.joinedD, ForbiddenJoinedState.joinedD => true
  | RoleViewEvent.joinedA, ForbiddenJoinedState.joinedA => true
  | RoleViewEvent.joinedXClientBase, ForbiddenJoinedState.joinedXClientBase => true
  | RoleViewEvent.joinedYServer, ForbiddenJoinedState.joinedYServer => true
  | RoleViewEvent.joinedTauServer, ForbiddenJoinedState.joinedTauServer => true
  | _, _ => false

def roleMayObserveEvent
    (role : Role)
    (event : RoleViewEvent) : Bool :=
  match role, event with
  | _, RoleViewEvent.publicMetadata => true
  | _, RoleViewEvent.ciphertext => true
  | Role.deriverA, RoleViewEvent.deriverAMpcPrfPartialXClientBase => true
  | Role.deriverA, RoleViewEvent.deriverAMpcPrfPartialXServerBase => true
  | Role.deriverB, RoleViewEvent.deriverBMpcPrfPartialXClientBase => true
  | Role.deriverB, RoleViewEvent.deriverBMpcPrfPartialXServerBase => true
  | Role.client, RoleViewEvent.clientOpenedXClientBase => true
  | Role.signingWorker, RoleViewEvent.signingWorkerOpenedXServerBase => true
  | _, _ => false

def roleViewContainsForbiddenJoinedState
    (role : Role)
    (state : ForbiddenJoinedState)
    (event : RoleViewEvent) : Bool :=
  roleMayObserveEvent role event && eventContainsForbiddenJoinedState event state

def roleMayObserveMpcPrfPartial
    (role : Role)
    (owner : MpcPrfPartialOwner)
    (opened : OpenedValueKind) : Bool :=
  match role, owner, opened with
  | Role.deriverA, MpcPrfPartialOwner.deriverA, _ => true
  | Role.deriverB, MpcPrfPartialOwner.deriverB, _ => true
  | Role.client, _, OpenedValueKind.xClientBase => true
  | Role.signingWorker, _, OpenedValueKind.xServerBase => true
  | _, _, _ => false

theorem forbidden_joined_state_events_are_unobservable
    (role : Role)
    (state : ForbiddenJoinedState)
    (event : RoleViewEvent)
    (hContains : eventContainsForbiddenJoinedState event state = true) :
    roleMayObserveEvent role event = false := by
  cases role <;> cases state <;> cases event <;>
    simp [eventContainsForbiddenJoinedState, roleMayObserveEvent] at *

theorem server_side_roles_exclude_forbidden_joined_state
    (role : Role)
    (state : ForbiddenJoinedState)
    (event : RoleViewEvent)
    (hRole : role = Role.router ∨ role = Role.deriverA ∨ role = Role.deriverB ∨
      role = Role.signingWorker) :
    roleViewContainsForbiddenJoinedState
      role
      state
      event = false := by
  cases role <;> cases state <;> cases event <;>
    simp [
      roleViewContainsForbiddenJoinedState,
      roleMayObserveEvent,
      eventContainsForbiddenJoinedState
    ] at *

theorem client_view_excludes_forbidden_joined_material
    (event : RoleViewEvent) :
    roleViewContainsForbiddenJoinedState
      Role.client
      ForbiddenJoinedState.joinedD
      event = false ∧
    roleViewContainsForbiddenJoinedState
      Role.client
      ForbiddenJoinedState.joinedA
      event = false ∧
    roleViewContainsForbiddenJoinedState
      Role.client
      ForbiddenJoinedState.joinedYServer
      event = false ∧
    roleViewContainsForbiddenJoinedState
      Role.client
      ForbiddenJoinedState.joinedTauServer
      event = false := by
  cases event <;>
    simp [
      roleViewContainsForbiddenJoinedState,
      roleMayObserveEvent,
      eventContainsForbiddenJoinedState
    ]

theorem router_view_excludes_mpc_prf_plaintext_partial
    (owner : MpcPrfPartialOwner)
    (opened : OpenedValueKind) :
    roleMayObserveMpcPrfPartial Role.router owner opened = false := by
  cases owner <;> cases opened <;> simp [roleMayObserveMpcPrfPartial]

theorem client_observes_only_x_client_base_partials
    (owner : MpcPrfPartialOwner)
    (opened : OpenedValueKind)
    (hVisible : roleMayObserveMpcPrfPartial Role.client owner opened = true) :
    opened = OpenedValueKind.xClientBase := by
  cases owner <;> cases opened <;> simp [roleMayObserveMpcPrfPartial] at hVisible

theorem signing_worker_observes_only_x_server_base_partials
    (owner : MpcPrfPartialOwner)
    (opened : OpenedValueKind)
    (hVisible : roleMayObserveMpcPrfPartial Role.signingWorker owner opened = true) :
    opened = OpenedValueKind.xServerBase := by
  cases owner <;> cases opened <;> simp [roleMayObserveMpcPrfPartial] at hVisible

end RouterAbDerivationPrivacy
