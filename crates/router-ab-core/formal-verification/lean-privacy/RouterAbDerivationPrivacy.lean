namespace RouterAbDerivationPrivacy

inductive Role where
  | router
  | signerA
  | signerB
  | client
  | relayer
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
  | signerA
  | signerB
deriving DecidableEq, Repr

inductive SplitRootShareOwner where
  | signerA
  | signerB
deriving DecidableEq, Repr

def roleViewContainsForbiddenJoinedState
    (_role : Role)
    (_state : ForbiddenJoinedState) : Bool :=
  false

def roleMayObserveMpcPrfPartial
    (role : Role)
    (owner : MpcPrfPartialOwner)
    (opened : OpenedValueKind) : Bool :=
  match role, owner, opened with
  | Role.signerA, MpcPrfPartialOwner.signerA, _ => true
  | Role.signerB, MpcPrfPartialOwner.signerB, _ => true
  | Role.client, _, OpenedValueKind.xClientBase => true
  | Role.relayer, _, OpenedValueKind.xRelayerBase => true
  | _, _, _ => false

def roleMayObserveSplitRootOutputShare
    (role : Role)
    (owner : SplitRootShareOwner)
    (opened : OpenedValueKind) : Bool :=
  match role, owner, opened with
  | Role.signerA, SplitRootShareOwner.signerA, _ => true
  | Role.signerB, SplitRootShareOwner.signerB, _ => true
  | Role.client, _, OpenedValueKind.xClientBase => true
  | Role.relayer, _, OpenedValueKind.xRelayerBase => true
  | _, _, _ => false

def roleMayObserveSplitRootSecret
    (role : Role)
    (owner : SplitRootShareOwner) : Bool :=
  match role, owner with
  | Role.signerA, SplitRootShareOwner.signerA => true
  | Role.signerB, SplitRootShareOwner.signerB => true
  | _, _ => false

theorem server_side_roles_exclude_joined_x_client_base
    (role : Role)
    (hRole : role = Role.router ∨ role = Role.signerA ∨ role = Role.signerB) :
    roleViewContainsForbiddenJoinedState role ForbiddenJoinedState.joinedXClientBase = false := by
  cases hRole with
  | inl hRouter => simp [hRouter, roleViewContainsForbiddenJoinedState]
  | inr hRest =>
      cases hRest with
      | inl hA => simp [hA, roleViewContainsForbiddenJoinedState]
      | inr hB => simp [hB, roleViewContainsForbiddenJoinedState]

theorem client_view_excludes_joined_relayer_material :
    roleViewContainsForbiddenJoinedState Role.client ForbiddenJoinedState.joinedYRelayer = false ∧
    roleViewContainsForbiddenJoinedState Role.client ForbiddenJoinedState.joinedTauRelayer = false := by
  simp [roleViewContainsForbiddenJoinedState]

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

theorem relayer_observes_only_x_relayer_base_partials
    (owner : MpcPrfPartialOwner)
    (opened : OpenedValueKind)
    (hVisible : roleMayObserveMpcPrfPartial Role.relayer owner opened = true) :
    opened = OpenedValueKind.xRelayerBase := by
  cases owner <;> cases opened <;> simp [roleMayObserveMpcPrfPartial] at hVisible

theorem router_view_excludes_split_root_secret
    (owner : SplitRootShareOwner) :
    roleMayObserveSplitRootSecret Role.router owner = false := by
  cases owner <;> simp [roleMayObserveSplitRootSecret]

theorem router_view_excludes_split_root_plaintext_output_share
    (owner : SplitRootShareOwner)
    (opened : OpenedValueKind) :
    roleMayObserveSplitRootOutputShare Role.router owner opened = false := by
  cases owner <;> cases opened <;> simp [roleMayObserveSplitRootOutputShare]

theorem client_observes_only_x_client_base_split_root_shares
    (owner : SplitRootShareOwner)
    (opened : OpenedValueKind)
    (hVisible : roleMayObserveSplitRootOutputShare Role.client owner opened = true) :
    opened = OpenedValueKind.xClientBase := by
  cases owner <;> cases opened <;> simp [roleMayObserveSplitRootOutputShare] at hVisible

theorem relayer_observes_only_x_relayer_base_split_root_shares
    (owner : SplitRootShareOwner)
    (opened : OpenedValueKind)
    (hVisible : roleMayObserveSplitRootOutputShare Role.relayer owner opened = true) :
    opened = OpenedValueKind.xRelayerBase := by
  cases owner <;> cases opened <;> simp [roleMayObserveSplitRootOutputShare] at hVisible

end RouterAbDerivationPrivacy
