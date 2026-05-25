import EcdsaHssBoundary.GeneratedVisibleBoundary

namespace EcdsaHssBoundary

open ecdsa_hss

abbrev GeneratedHiddenEvalInputBoundaryV2 :=
  server.boundary.HiddenEvalInputBoundaryV2
abbrev GeneratedHiddenEvalTransportBoundaryV2 :=
  server.boundary.HiddenEvalTransportBoundaryV2
abbrev GeneratedHiddenEvalPersistedStateBoundaryV2 :=
  server.boundary.HiddenEvalPersistedStateBoundaryV2
abbrev GeneratedHiddenEvalBoundaryV2 :=
  server.boundary.HiddenEvalBoundaryV2

def toHandwrittenHiddenEvalInputBoundary
    (boundary : GeneratedHiddenEvalInputBoundaryV2) :
    HiddenEvalInputBoundaryModel :=
  {
    operation := boundary.operation
    allowedOutputKind := boundary.allowed_output_kind
    context := boundary.context
    relayerKeyId := boundary.relayer_key_id
    clientPublicKey33 := boundary.client_public_key33
    clientShareRetryCounter := boundary.client_share_retry_counter
    expectedRelayerKeyId := boundary.expected_relayer_key_id
    yRelayer32Le := boundary.y_relayer32_le
  }

def toHandwrittenHiddenEvalTransportBoundary
    (boundary : GeneratedHiddenEvalTransportBoundaryV2) :
    HiddenEvalTransportBoundaryModel :=
  {
    operation := toHandwrittenOperationBoundary boundary.operation
    clientOutput := toHandwrittenClientBoundary boundary.client_output
    finalize := toHandwrittenFinalizeBoundary boundary.finalize
  }

def toHandwrittenHiddenEvalPersistedStateBoundary
    (boundary : GeneratedHiddenEvalPersistedStateBoundaryV2) :
    HiddenEvalPersistedStateBoundaryModel :=
  {
    operation := boundary.operation
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

def toHandwrittenHiddenEvalBoundary
    (boundary : GeneratedHiddenEvalBoundaryV2) : HiddenEvalBoundaryModel :=
  {
    input := toHandwrittenHiddenEvalInputBoundary boundary.input
    transport := toHandwrittenHiddenEvalTransportBoundary boundary.transport
    persisted := toHandwrittenHiddenEvalPersistedStateBoundary boundary.persisted
  }

theorem hiddenEvalInputBoundary_matchesHandwrittenModel
    (boundary : GeneratedHiddenEvalInputBoundaryV2) :
    toHandwrittenHiddenEvalInputBoundary boundary =
      {
        operation := boundary.operation
        allowedOutputKind := boundary.allowed_output_kind
        context := boundary.context
        relayerKeyId := boundary.relayer_key_id
        clientPublicKey33 := boundary.client_public_key33
        clientShareRetryCounter := boundary.client_share_retry_counter
        expectedRelayerKeyId := boundary.expected_relayer_key_id
        yRelayer32Le := boundary.y_relayer32_le
      } := by
  rfl

theorem hiddenEvalPersistedStateBoundary_matchesHandwrittenModel
    (boundary : GeneratedHiddenEvalPersistedStateBoundaryV2) :
    toHandwrittenHiddenEvalPersistedStateBoundary boundary =
      {
        operation := boundary.operation
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

theorem hiddenEvalBoundary_matchesHandwrittenModel
    (boundary : GeneratedHiddenEvalBoundaryV2) :
    toHandwrittenHiddenEvalBoundary boundary =
      {
        input := toHandwrittenHiddenEvalInputBoundary boundary.input
        transport := toHandwrittenHiddenEvalTransportBoundary boundary.transport
        persisted := toHandwrittenHiddenEvalPersistedStateBoundary boundary.persisted
      } := by
  rfl

end EcdsaHssBoundary
