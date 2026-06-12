namespace RouterAbDerivation

inductive Role where
  | router
  | signerA
  | signerB
  | client
  | relayer
deriving DecidableEq, Repr

inductive OpenedValueKind where
  | xClientBase
  | xRelayerBase
deriving DecidableEq, Repr

def roleMayOpen : Role -> OpenedValueKind -> Bool
  | Role.client, OpenedValueKind.xClientBase => true
  | Role.relayer, OpenedValueKind.xRelayerBase => true
  | _, _ => false

theorem client_opens_only_x_client_base
    (opened : OpenedValueKind)
    (h : roleMayOpen Role.client opened = true) :
    opened = OpenedValueKind.xClientBase := by
  cases opened <;> simp [roleMayOpen] at h

theorem relayer_opens_only_x_relayer_base
    (opened : OpenedValueKind)
    (h : roleMayOpen Role.relayer opened = true) :
    opened = OpenedValueKind.xRelayerBase := by
  cases opened <;> simp [roleMayOpen] at h

end RouterAbDerivation
