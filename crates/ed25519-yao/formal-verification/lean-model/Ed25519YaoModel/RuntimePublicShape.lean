-- This file is generated from production local-protocol executions.
-- Regenerate with UPDATE_ED25519_YAO_RUNTIME_PUBLIC_SHAPE=1 cargo yao-fv lean-check.

namespace Ed25519YaoModel

inductive RuntimeProtocolFamily where
| activation
| export
deriving DecidableEq, Repr

inductive RuntimeDeriverRole where
| deriverA
| deriverB
deriving DecidableEq, Repr

inductive RuntimeWireDirection where
| deriverAToDeriverB
| deriverBToDeriverA
deriving DecidableEq, Repr

inductive RuntimeWireMessageKind where
| baseOtOffer
| baseOtChoices
| directInputLabels
| otExtensionMatrix
| maskedInputLabels
| streamManifest
| tableFrame
| outputTranslation
| returnedOutputLabels
deriving DecidableEq, Repr

structure RuntimeMessageShape where
direction : RuntimeWireDirection
kind : RuntimeWireMessageKind
payloadBytes : Nat
deriving DecidableEq, Repr

structure RuntimeRoleView where
family : RuntimeProtocolFamily
role : RuntimeDeriverRole
sent : List RuntimeMessageShape
received : List RuntimeMessageShape
frameCount : Nat
deriving DecidableEq, Repr

def activationDeriverAView : RuntimeRoleView :=
  { family := .activation
    role := .deriverA
    sent :=
      [⟨.deriverAToDeriverB, .baseOtChoices, 4144⟩,
       ⟨.deriverAToDeriverB, .directInputLabels, 24732⟩,
       ⟨.deriverAToDeriverB, .maskedInputLabels, 49200⟩,
       ⟨.deriverAToDeriverB, .streamManifest, 248⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 7900⟩,
       ⟨.deriverAToDeriverB, .outputTranslation, 220⟩]
    received :=
      [⟨.deriverBToDeriverA, .baseOtOffer, 4144⟩,
       ⟨.deriverBToDeriverA, .otExtensionMatrix, 24624⟩,
       ⟨.deriverBToDeriverA, .returnedOutputLabels, 8348⟩]
    frameCount := 17 }

def activationDeriverBView : RuntimeRoleView :=
  { family := .activation
    role := .deriverB
    sent :=
      [⟨.deriverBToDeriverA, .baseOtOffer, 4144⟩,
       ⟨.deriverBToDeriverA, .otExtensionMatrix, 24624⟩,
       ⟨.deriverBToDeriverA, .returnedOutputLabels, 8348⟩]
    received :=
      [⟨.deriverAToDeriverB, .baseOtChoices, 4144⟩,
       ⟨.deriverAToDeriverB, .directInputLabels, 24732⟩,
       ⟨.deriverAToDeriverB, .maskedInputLabels, 49200⟩,
       ⟨.deriverAToDeriverB, .streamManifest, 248⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 131164⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 7900⟩,
       ⟨.deriverAToDeriverB, .outputTranslation, 220⟩]
    frameCount := 17 }

def exportDeriverAView : RuntimeRoleView :=
  { family := .export
    role := .deriverA
    sent :=
      [⟨.deriverAToDeriverB, .baseOtChoices, 4144⟩,
       ⟨.deriverAToDeriverB, .directInputLabels, 12444⟩,
       ⟨.deriverAToDeriverB, .maskedInputLabels, 24624⟩,
       ⟨.deriverAToDeriverB, .streamManifest, 248⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 40892⟩,
       ⟨.deriverAToDeriverB, .outputTranslation, 188⟩]
    received :=
      [⟨.deriverBToDeriverA, .baseOtOffer, 4144⟩,
       ⟨.deriverBToDeriverA, .otExtensionMatrix, 12336⟩,
       ⟨.deriverBToDeriverA, .returnedOutputLabels, 4252⟩]
    frameCount := 1 }

def exportDeriverBView : RuntimeRoleView :=
  { family := .export
    role := .deriverB
    sent :=
      [⟨.deriverBToDeriverA, .baseOtOffer, 4144⟩,
       ⟨.deriverBToDeriverA, .otExtensionMatrix, 12336⟩,
       ⟨.deriverBToDeriverA, .returnedOutputLabels, 4252⟩]
    received :=
      [⟨.deriverAToDeriverB, .baseOtChoices, 4144⟩,
       ⟨.deriverAToDeriverB, .directInputLabels, 12444⟩,
       ⟨.deriverAToDeriverB, .maskedInputLabels, 24624⟩,
       ⟨.deriverAToDeriverB, .streamManifest, 248⟩,
       ⟨.deriverAToDeriverB, .tableFrame, 40892⟩,
       ⟨.deriverAToDeriverB, .outputTranslation, 188⟩]
    frameCount := 1 }

def runtimeRoleView : RuntimeProtocolFamily → RuntimeDeriverRole → RuntimeRoleView
| .activation, .deriverA => activationDeriverAView
| .activation, .deriverB => activationDeriverBView
| .export, .deriverA => exportDeriverAView
| .export, .deriverB => exportDeriverBView

end Ed25519YaoModel
