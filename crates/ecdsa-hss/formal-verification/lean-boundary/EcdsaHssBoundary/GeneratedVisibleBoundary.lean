import EcdsaHss
import EcdsaHssBoundary.Scope

namespace EcdsaHssBoundary

open ecdsa_hss

abbrev GeneratedClientOutputV2 := client.ClientOutputV2
abbrev GeneratedServerEvalOperationV2 := wire.ServerEvalOperationV2
abbrev GeneratedAllowedOutputKindV2 := wire.AllowedOutputKindV2
abbrev GeneratedFinalizeEnvelopeV2 := wire.FinalizeEnvelopeV2
abbrev GeneratedRetainedServerStateV2 := server.RetainedServerStateV2
abbrev GeneratedFinalizedServerSessionV2 := server.FinalizedServerSessionV2
abbrev GeneratedRespondResponseV2 := server.RespondResponseV2
abbrev GeneratedVisibleOperationBoundaryV2 :=
  server.boundary.VisibleOperationBoundaryV2
abbrev GeneratedVisibleNonExportBoundaryV2 :=
  server.boundary.VisibleNonExportBoundaryV2
abbrev GeneratedVisibleExplicitExportBoundaryV2 :=
  server.boundary.VisibleExplicitExportBoundaryV2
abbrev GeneratedVisibleClientBoundaryV2 :=
  server.boundary.VisibleClientBoundaryV2
abbrev GeneratedVisibleFinalizeBoundaryV2 :=
  server.boundary.VisibleFinalizeBoundaryV2
abbrev GeneratedVisibleRetainedServerStateBoundaryV2 :=
  server.boundary.VisibleRetainedServerStateBoundaryV2
abbrev GeneratedVisibleRespondBoundaryV2 :=
  server.boundary.VisibleRespondBoundaryV2

def toHandwrittenOperationBoundary
    (boundary : GeneratedVisibleOperationBoundaryV2) : OperationBoundaryModel :=
  {
    operation := boundary.operation
    allowedOutputKind := boundary.allowed_output_kind
  }

def toHandwrittenNonExportBoundary
    (boundary : GeneratedVisibleNonExportBoundaryV2) : NonExportBoundaryModel :=
  {
    clientPublicKey33 := boundary.client_public_key33
    relayerPublicKey33 := boundary.relayer_public_key33
    thresholdPublicKey33 := boundary.threshold_public_key33
    thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
    clientShareRetryCounter := boundary.client_share_retry_counter
    relayerShareRetryCounter := boundary.relayer_share_retry_counter
  }

def toHandwrittenExplicitExportBoundary
    (boundary : GeneratedVisibleExplicitExportBoundaryV2) :
    ExplicitExportBoundaryModel :=
  {
    relayerExportShare32 := boundary.relayer_export_share32
    clientPublicKey33 := boundary.client_public_key33
    relayerPublicKey33 := boundary.relayer_public_key33
    thresholdPublicKey33 := boundary.threshold_public_key33
    thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
    clientShareRetryCounter := boundary.client_share_retry_counter
    relayerShareRetryCounter := boundary.relayer_share_retry_counter
  }

def toHandwrittenClientBoundary
    (boundary : GeneratedVisibleClientBoundaryV2) : ClientBoundaryModel :=
  match boundary with
  | server.boundary.VisibleClientBoundaryV2.NonExport nonExport =>
    ClientBoundaryModel.nonExport (toHandwrittenNonExportBoundary nonExport)
  | server.boundary.VisibleClientBoundaryV2.ExplicitExport explicitExport =>
    ClientBoundaryModel.explicitExport
      (toHandwrittenExplicitExportBoundary explicitExport)

def toHandwrittenFinalizeBoundary
    (boundary : GeneratedVisibleFinalizeBoundaryV2) : FinalizeBoundaryModel :=
  {
    operation := boundary.operation
    rawRootMaterialDropped := boundary.raw_root_material_dropped
    relayerKeyId := boundary.relayer_key_id
    clientPublicKey33 := boundary.client_public_key33
    relayerPublicKey33 := boundary.relayer_public_key33
    thresholdPublicKey33 := boundary.threshold_public_key33
    thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
    clientShareRetryCounter := boundary.client_share_retry_counter
    relayerShareRetryCounter := boundary.relayer_share_retry_counter
  }

def toHandwrittenRetainedStateBoundary
    (boundary : GeneratedVisibleRetainedServerStateBoundaryV2) :
    RetainedStateBoundaryModel :=
  {
    rawRootMaterialDropped := boundary.raw_root_material_dropped
    relayerKeyId := boundary.relayer_key_id
    relayerShare32 := boundary.relayer_share32
    clientPublicKey33 := boundary.client_public_key33
    relayerPublicKey33 := boundary.relayer_public_key33
    thresholdPublicKey33 := boundary.threshold_public_key33
    thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
    clientShareRetryCounter := boundary.client_share_retry_counter
    relayerShareRetryCounter := boundary.relayer_share_retry_counter
  }

def toHandwrittenRespondBoundary
    (boundary : GeneratedVisibleRespondBoundaryV2) : RespondBoundaryModel :=
  {
    operation := toHandwrittenOperationBoundary boundary.operation
    clientOutput := toHandwrittenClientBoundary boundary.client_output
    finalize := toHandwrittenFinalizeBoundary boundary.finalize
    retained := toHandwrittenRetainedStateBoundary boundary.retained
  }

theorem operationBoundary_matchesHandwrittenModel
    (boundary : GeneratedVisibleOperationBoundaryV2) :
    toHandwrittenOperationBoundary boundary =
      {
        operation := boundary.operation
        allowedOutputKind := boundary.allowed_output_kind
      } := by
  rfl

theorem nonExportBoundary_matchesHandwrittenModel
    (boundary : GeneratedVisibleNonExportBoundaryV2) :
    toHandwrittenNonExportBoundary boundary =
      {
        clientPublicKey33 := boundary.client_public_key33
        relayerPublicKey33 := boundary.relayer_public_key33
        thresholdPublicKey33 := boundary.threshold_public_key33
        thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
        clientShareRetryCounter := boundary.client_share_retry_counter
        relayerShareRetryCounter := boundary.relayer_share_retry_counter
      } := by
  rfl

theorem explicitExportBoundary_matchesHandwrittenModel
    (boundary : GeneratedVisibleExplicitExportBoundaryV2) :
    toHandwrittenExplicitExportBoundary boundary =
      {
        relayerExportShare32 := boundary.relayer_export_share32
        clientPublicKey33 := boundary.client_public_key33
        relayerPublicKey33 := boundary.relayer_public_key33
        thresholdPublicKey33 := boundary.threshold_public_key33
        thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
        clientShareRetryCounter := boundary.client_share_retry_counter
        relayerShareRetryCounter := boundary.relayer_share_retry_counter
      } := by
  rfl

theorem retainedStateBoundary_matchesHandwrittenModel
    (boundary : GeneratedVisibleRetainedServerStateBoundaryV2) :
    toHandwrittenRetainedStateBoundary boundary =
      {
        rawRootMaterialDropped := boundary.raw_root_material_dropped
        relayerKeyId := boundary.relayer_key_id
        relayerShare32 := boundary.relayer_share32
        clientPublicKey33 := boundary.client_public_key33
        relayerPublicKey33 := boundary.relayer_public_key33
        thresholdPublicKey33 := boundary.threshold_public_key33
        thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
        clientShareRetryCounter := boundary.client_share_retry_counter
        relayerShareRetryCounter := boundary.relayer_share_retry_counter
      } := by
  rfl

theorem respondBoundary_matchesHandwrittenModel
    (boundary : GeneratedVisibleRespondBoundaryV2) :
    toHandwrittenRespondBoundary boundary =
      {
        operation := toHandwrittenOperationBoundary boundary.operation
        clientOutput := toHandwrittenClientBoundary boundary.client_output
        finalize := toHandwrittenFinalizeBoundary boundary.finalize
        retained := toHandwrittenRetainedStateBoundary boundary.retained
      } := by
  rfl

end EcdsaHssBoundary
