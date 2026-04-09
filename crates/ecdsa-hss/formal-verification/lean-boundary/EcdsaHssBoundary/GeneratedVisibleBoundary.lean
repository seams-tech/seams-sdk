import EcdsaHss
import EcdsaHssBoundary.Scope

namespace EcdsaHssBoundary

open ecdsa_hss

abbrev GeneratedClientOutputV1 := client.ClientOutputV1
abbrev GeneratedServerEvalOperationV1 := wire.ServerEvalOperationV1
abbrev GeneratedAllowedOutputKindV1 := wire.AllowedOutputKindV1
abbrev GeneratedFinalizeEnvelopeV1 := wire.FinalizeEnvelopeV1
abbrev GeneratedRetainedServerStateV1 := server.RetainedServerStateV1
abbrev GeneratedFinalizedServerSessionV1 := server.FinalizedServerSessionV1
abbrev GeneratedRespondResponseV1 := server.RespondResponseV1
abbrev GeneratedVisibleOperationBoundaryV1 :=
  server.reference_boundary.VisibleOperationBoundaryV1
abbrev GeneratedVisibleNonExportBoundaryV1 :=
  server.reference_boundary.VisibleNonExportBoundaryV1
abbrev GeneratedVisibleExplicitExportBoundaryV1 :=
  server.reference_boundary.VisibleExplicitExportBoundaryV1
abbrev GeneratedVisibleClientBoundaryV1 :=
  server.reference_boundary.VisibleClientBoundaryV1
abbrev GeneratedVisibleFinalizeBoundaryV1 :=
  server.reference_boundary.VisibleFinalizeBoundaryV1
abbrev GeneratedVisibleRetainedServerStateBoundaryV1 :=
  server.reference_boundary.VisibleRetainedServerStateBoundaryV1
abbrev GeneratedVisibleRespondBoundaryV1 :=
  server.reference_boundary.VisibleRespondBoundaryV1

def toHandwrittenOperationBoundary
    (boundary : GeneratedVisibleOperationBoundaryV1) : OperationBoundaryModel :=
  {
    operation := boundary.operation
    allowedOutputKind := boundary.allowed_output_kind
  }

def toHandwrittenNonExportBoundary
    (boundary : GeneratedVisibleNonExportBoundaryV1) : NonExportBoundaryModel :=
  {
    xClient32 := boundary.x_client32
    clientPublicKey33 := boundary.client_public_key33
    thresholdPublicKey33 := boundary.threshold_public_key33
    thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
    retryCounter := boundary.retry_counter
  }

def toHandwrittenExplicitExportBoundary
    (boundary : GeneratedVisibleExplicitExportBoundaryV1) :
    ExplicitExportBoundaryModel :=
  {
    canonicalX32 := boundary.canonical_x32
    canonicalPublicKey33 := boundary.canonical_public_key33
    canonicalEthereumAddress20 := boundary.canonical_ethereum_address20
    xClient32 := boundary.x_client32
    clientPublicKey33 := boundary.client_public_key33
    thresholdPublicKey33 := boundary.threshold_public_key33
    thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
    retryCounter := boundary.retry_counter
  }

def toHandwrittenClientBoundary
    (boundary : GeneratedVisibleClientBoundaryV1) : ClientBoundaryModel :=
  match boundary with
  | GeneratedVisibleClientBoundaryV1.NonExport nonExport =>
    ClientBoundaryModel.nonExport (toHandwrittenNonExportBoundary nonExport)
  | GeneratedVisibleClientBoundaryV1.ExplicitExport explicitExport =>
    ClientBoundaryModel.explicitExport
      (toHandwrittenExplicitExportBoundary explicitExport)

def toHandwrittenFinalizeBoundary
    (boundary : GeneratedVisibleFinalizeBoundaryV1) : FinalizeBoundaryModel :=
  {
    operation := boundary.operation
    rawRootMaterialDropped := boundary.raw_root_material_dropped
    thresholdPublicKey33 := boundary.threshold_public_key33
    thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
    retryCounter := boundary.retry_counter
  }

def toHandwrittenRetainedStateBoundary
    (boundary : GeneratedVisibleRetainedServerStateBoundaryV1) :
    RetainedStateBoundaryModel :=
  {
    rawRootMaterialDropped := boundary.raw_root_material_dropped
    relayerThresholdShare32 := boundary.relayer_threshold_share32
    relayerPublicKey33 := boundary.relayer_public_key33
    thresholdPublicKey33 := boundary.threshold_public_key33
    thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
    retryCounter := boundary.retry_counter
  }

def toHandwrittenRespondBoundary
    (boundary : GeneratedVisibleRespondBoundaryV1) : RespondBoundaryModel :=
  {
    operation := toHandwrittenOperationBoundary boundary.operation
    clientOutput := toHandwrittenClientBoundary boundary.client_output
    finalize := toHandwrittenFinalizeBoundary boundary.finalize
    retained := toHandwrittenRetainedStateBoundary boundary.retained
  }

def generatedOperation
    (boundary : GeneratedVisibleOperationBoundaryV1) : GeneratedServerEvalOperationV1 :=
  boundary.operation

def generatedAllowedOutputKind
    (boundary : GeneratedVisibleOperationBoundaryV1) : GeneratedAllowedOutputKindV1 :=
  boundary.allowed_output_kind

def generatedNonExportThresholdPublicKey
    (boundary : GeneratedVisibleNonExportBoundaryV1) : Array UInt8 33#usize :=
  boundary.threshold_public_key33

def generatedExplicitExportCanonicalScalar
    (boundary : GeneratedVisibleExplicitExportBoundaryV1) : Array UInt8 32#usize :=
  boundary.canonical_x32

def generatedRetainedRawRootMaterialDropped
    (boundary : GeneratedVisibleRetainedServerStateBoundaryV1) : Bool :=
  boundary.raw_root_material_dropped

theorem operationBoundaryFromOperation_preservesOperation
    (operation : GeneratedServerEvalOperationV1) :
    generatedOperation
        (by
          simpa using
            (server.reference_boundary.operation_boundary_from_operation_v1 operation))
      = operation := by
  rfl

theorem operationBoundaryFromOperation_preservesAllowedOutputKind
    (operation : GeneratedServerEvalOperationV1) :
    generatedAllowedOutputKind
        (by
          simpa using
            (server.reference_boundary.operation_boundary_from_operation_v1 operation))
      = operation.allowed_output_kind := by
  rfl

theorem operationBoundaryFromOperation_matchesHandwrittenModel
    (operation : GeneratedServerEvalOperationV1) :
    toHandwrittenOperationBoundary
        (by
          simpa using
            (server.reference_boundary.operation_boundary_from_operation_v1 operation))
      =
      {
        operation := operation
        allowedOutputKind := expectedAllowedOutputKindForOperation operation
      } := by
  cases operation <;> rfl

theorem visibleClientBoundaryFromOutput_projectsNonExportThresholdPublicKey
    (output : client.NonExportClientOutputV1) :
    generatedNonExportThresholdPublicKey
        (by
          simpa using
            (server.reference_boundary.non_export_boundary_from_output_v1 output))
      = output.threshold_public_key33 := by
  rfl

theorem nonExportBoundaryFromOutput_matchesHandwrittenModel
    (output : client.NonExportClientOutputV1) :
    toHandwrittenNonExportBoundary
        (by
          simpa using
            (server.reference_boundary.non_export_boundary_from_output_v1 output))
      =
      {
        xClient32 := output.x_client32
        clientPublicKey33 := output.client_public_key33
        thresholdPublicKey33 := output.threshold_public_key33
        thresholdEthereumAddress20 := output.threshold_ethereum_address20
        retryCounter := output.retry_counter
      } := by
  rfl

theorem visibleClientBoundaryFromOutput_projectsExplicitExportCanonicalScalar
    (output : client.ExplicitExportClientOutputV1) :
    generatedExplicitExportCanonicalScalar
        (by
          simpa using
            (server.reference_boundary.explicit_export_boundary_from_output_v1 output))
      = output.canonical_x32 := by
  rfl

theorem explicitExportBoundaryFromOutput_matchesHandwrittenModel
    (output : client.ExplicitExportClientOutputV1) :
    toHandwrittenExplicitExportBoundary
        (by
          simpa using
            (server.reference_boundary.explicit_export_boundary_from_output_v1 output))
      =
      {
        canonicalX32 := output.canonical_x32
        canonicalPublicKey33 := output.canonical_public_key33
        canonicalEthereumAddress20 := output.canonical_ethereum_address20
        xClient32 := output.x_client32
        clientPublicKey33 := output.client_public_key33
        thresholdPublicKey33 := output.threshold_public_key33
        thresholdEthereumAddress20 := output.threshold_ethereum_address20
        retryCounter := output.retry_counter
      } := by
  rfl

theorem retainedStateBoundaryFromRetained_projectsDroppedFlag
    (retained : GeneratedRetainedServerStateV1) :
    generatedRetainedRawRootMaterialDropped
        (by
          simpa using
            (server.reference_boundary.retained_state_boundary_from_retained_v1 retained))
      = retained.raw_root_material_dropped := by
  rfl

theorem retainedStateBoundaryFromRetained_matchesHandwrittenModel
    (retained : GeneratedRetainedServerStateV1) :
    toHandwrittenRetainedStateBoundary
        (by
          simpa using
            (server.reference_boundary.retained_state_boundary_from_retained_v1 retained))
      =
      {
        rawRootMaterialDropped := retained.raw_root_material_dropped
        relayerThresholdShare32 := retained.relayer_threshold_share32
        relayerPublicKey33 := retained.relayer_public_key33
        thresholdPublicKey33 := retained.threshold_public_key33
        thresholdEthereumAddress20 := retained.threshold_ethereum_address20
        retryCounter := retained.retry_counter
      } := by
  rfl

theorem finalizeBoundaryFromEnvelope_matchesHandwrittenModel
    (finalize : GeneratedFinalizeEnvelopeV1) :
    toHandwrittenFinalizeBoundary
        (by
          simpa using
            (server.reference_boundary.visible_finalize_boundary_from_envelope_v1 finalize))
      =
      {
        operation := finalize.operation
        rawRootMaterialDropped := finalize.raw_root_material_dropped
        thresholdPublicKey33 := finalize.threshold_public_key33
        thresholdEthereumAddress20 := finalize.threshold_ethereum_address20
        retryCounter := finalize.retry_counter
      } := by
  rfl

theorem visibleRespondBoundary_matchesHandwrittenModel
    (boundary : GeneratedVisibleRespondBoundaryV1) :
    toHandwrittenRespondBoundary boundary
      =
      {
        operation := {
          operation := boundary.operation.operation
          allowedOutputKind := boundary.operation.allowed_output_kind
        }
        clientOutput :=
          match boundary.client_output with
          | GeneratedVisibleClientBoundaryV1.NonExport nonExport =>
            ClientBoundaryModel.nonExport {
              xClient32 := nonExport.x_client32
              clientPublicKey33 := nonExport.client_public_key33
              thresholdPublicKey33 := nonExport.threshold_public_key33
              thresholdEthereumAddress20 := nonExport.threshold_ethereum_address20
              retryCounter := nonExport.retry_counter
            }
          | GeneratedVisibleClientBoundaryV1.ExplicitExport explicitExport =>
            ClientBoundaryModel.explicitExport {
              canonicalX32 := explicitExport.canonical_x32
              canonicalPublicKey33 := explicitExport.canonical_public_key33
              canonicalEthereumAddress20 := explicitExport.canonical_ethereum_address20
              xClient32 := explicitExport.x_client32
              clientPublicKey33 := explicitExport.client_public_key33
              thresholdPublicKey33 := explicitExport.threshold_public_key33
              thresholdEthereumAddress20 := explicitExport.threshold_ethereum_address20
              retryCounter := explicitExport.retry_counter
            }
        finalize := {
          operation := boundary.finalize.operation
          rawRootMaterialDropped := boundary.finalize.raw_root_material_dropped
          thresholdPublicKey33 := boundary.finalize.threshold_public_key33
          thresholdEthereumAddress20 := boundary.finalize.threshold_ethereum_address20
          retryCounter := boundary.finalize.retry_counter
        }
        retained := {
          rawRootMaterialDropped := boundary.retained.raw_root_material_dropped
          relayerThresholdShare32 := boundary.retained.relayer_threshold_share32
          relayerPublicKey33 := boundary.retained.relayer_public_key33
          thresholdPublicKey33 := boundary.retained.threshold_public_key33
          thresholdEthereumAddress20 := boundary.retained.threshold_ethereum_address20
          retryCounter := boundary.retained.retry_counter
        }
      } := by
  cases boundary.client_output <;> rfl

end EcdsaHssBoundary
