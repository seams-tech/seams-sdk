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
  | joinedYRelayer
  | joinedTauRelayer
deriving DecidableEq, Repr

inductive OpenedValueKind where
  | xClientBase
  | xRelayerBase
deriving DecidableEq, Repr

inductive MpcPrfPartialOwner where
  | deriverA
  | deriverB
deriving DecidableEq, Repr

inductive RoleViewEvent where
  | publicMetadata
  | ciphertext
  | deriverAMpcPrfPartialXClientBase
  | deriverAMpcPrfPartialXRelayerBase
  | deriverBMpcPrfPartialXClientBase
  | deriverBMpcPrfPartialXRelayerBase
  | clientOpenedXClientBase
  | signingWorkerOpenedXRelayerBase
  | joinedD
  | joinedA
  | joinedXClientBase
  | joinedYRelayer
  | joinedTauRelayer
deriving DecidableEq, Repr

def eventContainsForbiddenJoinedState
    (event : RoleViewEvent)
    (state : ForbiddenJoinedState) : Bool :=
  match event, state with
  | RoleViewEvent.joinedD, ForbiddenJoinedState.joinedD => true
  | RoleViewEvent.joinedA, ForbiddenJoinedState.joinedA => true
  | RoleViewEvent.joinedXClientBase, ForbiddenJoinedState.joinedXClientBase => true
  | RoleViewEvent.joinedYRelayer, ForbiddenJoinedState.joinedYRelayer => true
  | RoleViewEvent.joinedTauRelayer, ForbiddenJoinedState.joinedTauRelayer => true
  | _, _ => false

def roleMayObserveEvent
    (role : Role)
    (event : RoleViewEvent) : Bool :=
  match role, event with
  | _, RoleViewEvent.publicMetadata => true
  | _, RoleViewEvent.ciphertext => true
  | Role.deriverA, RoleViewEvent.deriverAMpcPrfPartialXClientBase => true
  | Role.deriverA, RoleViewEvent.deriverAMpcPrfPartialXRelayerBase => true
  | Role.deriverB, RoleViewEvent.deriverBMpcPrfPartialXClientBase => true
  | Role.deriverB, RoleViewEvent.deriverBMpcPrfPartialXRelayerBase => true
  | Role.client, RoleViewEvent.clientOpenedXClientBase => true
  | Role.signingWorker, RoleViewEvent.signingWorkerOpenedXRelayerBase => true
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
  | Role.signingWorker, _, OpenedValueKind.xRelayerBase => true
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
      ForbiddenJoinedState.joinedYRelayer
      event = false ∧
    roleViewContainsForbiddenJoinedState
      Role.client
      ForbiddenJoinedState.joinedTauRelayer
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

theorem signing_worker_observes_only_x_relayer_base_partials
    (owner : MpcPrfPartialOwner)
    (opened : OpenedValueKind)
    (hVisible : roleMayObserveMpcPrfPartial Role.signingWorker owner opened = true) :
    opened = OpenedValueKind.xRelayerBase := by
  cases owner <;> cases opened <;> simp [roleMayObserveMpcPrfPartial] at hVisible

end RouterAbDerivationPrivacy
