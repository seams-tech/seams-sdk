namespace RouterAbDerivation

inductive Role where
  | router
  | deriverA
  | deriverB
  | client
  | signingWorker
deriving DecidableEq, Repr

inductive OpenedValueKind where
  | xClientBase
  | xServerBase
deriving DecidableEq, Repr

def roleMayOpen : Role -> OpenedValueKind -> Bool
  | Role.client, OpenedValueKind.xClientBase => true
  | Role.signingWorker, OpenedValueKind.xServerBase => true
  | _, _ => false

theorem client_opens_only_x_client_base
    (opened : OpenedValueKind)
    (h : roleMayOpen Role.client opened = true) :
    opened = OpenedValueKind.xClientBase := by
  cases opened <;> simp [roleMayOpen] at h

theorem signing_worker_opens_only_x_server_base
    (opened : OpenedValueKind)
    (h : roleMayOpen Role.signingWorker opened = true) :
    opened = OpenedValueKind.xServerBase := by
  cases opened <;> simp [roleMayOpen] at h

end RouterAbDerivation
