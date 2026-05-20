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
  server.boundary.VisibleOperationBoundaryV1
abbrev GeneratedVisibleNonExportBoundaryV1 :=
  server.boundary.VisibleNonExportBoundaryV1
abbrev GeneratedVisibleExplicitExportBoundaryV1 :=
  server.boundary.VisibleExplicitExportBoundaryV1
abbrev GeneratedVisibleClientBoundaryV1 :=
  server.boundary.VisibleClientBoundaryV1
abbrev GeneratedVisibleFinalizeBoundaryV1 :=
  server.boundary.VisibleFinalizeBoundaryV1
abbrev GeneratedVisibleRetainedServerStateBoundaryV1 :=
  server.boundary.VisibleRetainedServerStateBoundaryV1
abbrev GeneratedVisibleRespondBoundaryV1 :=
  server.boundary.VisibleRespondBoundaryV1

def toHandwrittenOperationBoundary
    (boundary : GeneratedVisibleOperationBoundaryV1) : OperationBoundaryModel :=
  {
    operation := boundary.operation
    allowedOutputKind := boundary.allowed_output_kind
  }

def toHandwrittenNonExportBoundary
    (boundary : GeneratedVisibleNonExportBoundaryV1) : NonExportBoundaryModel :=
  {
    clientPublicKey33 := boundary.client_public_key33
    relayerPublicKey33 := boundary.relayer_public_key33
    thresholdPublicKey33 := boundary.threshold_public_key33
    thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
    clientShareRetryCounter := boundary.client_share_retry_counter
    relayerShareRetryCounter := boundary.relayer_share_retry_counter
  }

def toHandwrittenExplicitExportBoundary
    (boundary : GeneratedVisibleExplicitExportBoundaryV1) :
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
    (boundary : GeneratedVisibleClientBoundaryV1) : ClientBoundaryModel :=
  match boundary with
  | server.boundary.VisibleClientBoundaryV1.NonExport nonExport =>
    ClientBoundaryModel.nonExport (toHandwrittenNonExportBoundary nonExport)
  | server.boundary.VisibleClientBoundaryV1.ExplicitExport explicitExport =>
    ClientBoundaryModel.explicitExport
      (toHandwrittenExplicitExportBoundary explicitExport)

def toHandwrittenFinalizeBoundary
    (boundary : GeneratedVisibleFinalizeBoundaryV1) : FinalizeBoundaryModel :=
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
    (boundary : GeneratedVisibleRetainedServerStateBoundaryV1) :
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
    (boundary : GeneratedVisibleRespondBoundaryV1) : RespondBoundaryModel :=
  {
    operation := toHandwrittenOperationBoundary boundary.operation
    clientOutput := toHandwrittenClientBoundary boundary.client_output
    finalize := toHandwrittenFinalizeBoundary boundary.finalize
    retained := toHandwrittenRetainedStateBoundary boundary.retained
  }

theorem operationBoundary_matchesHandwrittenModel
    (boundary : GeneratedVisibleOperationBoundaryV1) :
    toHandwrittenOperationBoundary boundary =
      {
        operation := boundary.operation
        allowedOutputKind := boundary.allowed_output_kind
      } := by
  rfl

theorem nonExportBoundary_matchesHandwrittenModel
    (boundary : GeneratedVisibleNonExportBoundaryV1) :
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
    (boundary : GeneratedVisibleExplicitExportBoundaryV1) :
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
    (boundary : GeneratedVisibleRetainedServerStateBoundaryV1) :
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
    (boundary : GeneratedVisibleRespondBoundaryV1) :
    toHandwrittenRespondBoundary boundary =
      {
        operation := toHandwrittenOperationBoundary boundary.operation
        clientOutput := toHandwrittenClientBoundary boundary.client_output
        finalize := toHandwrittenFinalizeBoundary boundary.finalize
        retained := toHandwrittenRetainedStateBoundary boundary.retained
      } := by
  rfl

end EcdsaHssBoundary
