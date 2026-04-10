import EcdsaHssBoundary.GeneratedVisibleBoundary

namespace EcdsaHssBoundary

open ecdsa_hss

abbrev GeneratedHiddenEvalInputBoundaryV1 :=
  server.reference_boundary.HiddenEvalInputBoundaryV1
abbrev GeneratedHiddenEvalTransportBoundaryV1 :=
  server.reference_boundary.HiddenEvalTransportBoundaryV1
abbrev GeneratedHiddenEvalPersistedStateBoundaryV1 :=
  server.reference_boundary.HiddenEvalPersistedStateBoundaryV1
abbrev GeneratedHiddenEvalBoundaryV1 :=
  server.reference_boundary.HiddenEvalBoundaryV1

def toHandwrittenHiddenEvalInputBoundary
    (boundary : GeneratedHiddenEvalInputBoundaryV1) :
    HiddenEvalInputBoundaryModel :=
  {
    operation := boundary.operation
    allowedOutputKind := boundary.allowed_output_kind
    context := boundary.context
    yClient32Le := boundary.y_client32_le
    yRelayer32Le := boundary.y_relayer32_le
  }

def toHandwrittenHiddenEvalTransportBoundary
    (boundary : GeneratedHiddenEvalTransportBoundaryV1) :
    HiddenEvalTransportBoundaryModel :=
  {
    operation := toHandwrittenOperationBoundary boundary.operation
    clientOutput := toHandwrittenClientBoundary boundary.client_output
    finalize := toHandwrittenFinalizeBoundary boundary.finalize
  }

def toHandwrittenHiddenEvalPersistedStateBoundary
    (boundary : GeneratedHiddenEvalPersistedStateBoundaryV1) :
    HiddenEvalPersistedStateBoundaryModel :=
  {
    operation := boundary.operation
    rawRootMaterialDropped := boundary.raw_root_material_dropped
    relayerThresholdShare32 := boundary.relayer_threshold_share32
    relayerPublicKey33 := boundary.relayer_public_key33
    thresholdPublicKey33 := boundary.threshold_public_key33
    thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
    retryCounter := boundary.retry_counter
  }

def toHandwrittenHiddenEvalBoundary
    (boundary : GeneratedHiddenEvalBoundaryV1) : HiddenEvalBoundaryModel :=
  {
    input := toHandwrittenHiddenEvalInputBoundary boundary.input
    transport := toHandwrittenHiddenEvalTransportBoundary boundary.transport
    persisted := toHandwrittenHiddenEvalPersistedStateBoundary boundary.persisted
  }

theorem hiddenEvalInputBoundary_matchesHandwrittenModel
    (boundary : GeneratedHiddenEvalInputBoundaryV1) :
    toHandwrittenHiddenEvalInputBoundary boundary
      =
      {
        operation := boundary.operation
        allowedOutputKind := boundary.allowed_output_kind
        context := boundary.context
        yClient32Le := boundary.y_client32_le
        yRelayer32Le := boundary.y_relayer32_le
      } := by
  rfl

theorem hiddenEvalTransportBoundary_matchesHandwrittenModel
    (boundary : GeneratedHiddenEvalTransportBoundaryV1) :
    toHandwrittenHiddenEvalTransportBoundary boundary
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
      } := by
  cases boundary.client_output <;> rfl

theorem hiddenEvalPersistedStateBoundary_matchesHandwrittenModel
    (boundary : GeneratedHiddenEvalPersistedStateBoundaryV1) :
    toHandwrittenHiddenEvalPersistedStateBoundary boundary
      =
      {
        operation := boundary.operation
        rawRootMaterialDropped := boundary.raw_root_material_dropped
        relayerThresholdShare32 := boundary.relayer_threshold_share32
        relayerPublicKey33 := boundary.relayer_public_key33
        thresholdPublicKey33 := boundary.threshold_public_key33
        thresholdEthereumAddress20 := boundary.threshold_ethereum_address20
        retryCounter := boundary.retry_counter
      } := by
  rfl

theorem hiddenEvalBoundary_matchesHandwrittenModel
    (boundary : GeneratedHiddenEvalBoundaryV1) :
    toHandwrittenHiddenEvalBoundary boundary
      =
      {
        input := {
          operation := boundary.input.operation
          allowedOutputKind := boundary.input.allowed_output_kind
          context := boundary.input.context
          yClient32Le := boundary.input.y_client32_le
          yRelayer32Le := boundary.input.y_relayer32_le
        }
        transport := {
          operation := {
            operation := boundary.transport.operation.operation
            allowedOutputKind := boundary.transport.operation.allowed_output_kind
          }
          clientOutput :=
            match boundary.transport.client_output with
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
            operation := boundary.transport.finalize.operation
            rawRootMaterialDropped := boundary.transport.finalize.raw_root_material_dropped
            thresholdPublicKey33 := boundary.transport.finalize.threshold_public_key33
            thresholdEthereumAddress20 :=
              boundary.transport.finalize.threshold_ethereum_address20
            retryCounter := boundary.transport.finalize.retry_counter
          }
        }
        persisted := {
          operation := boundary.persisted.operation
          rawRootMaterialDropped := boundary.persisted.raw_root_material_dropped
          relayerThresholdShare32 := boundary.persisted.relayer_threshold_share32
          relayerPublicKey33 := boundary.persisted.relayer_public_key33
          thresholdPublicKey33 := boundary.persisted.threshold_public_key33
          thresholdEthereumAddress20 := boundary.persisted.threshold_ethereum_address20
          retryCounter := boundary.persisted.retry_counter
        }
      } := by
  cases boundary.transport.client_output <;> rfl

end EcdsaHssBoundary
