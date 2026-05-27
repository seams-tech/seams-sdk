import EcdsaHssBoundary.GeneratedVisibleBoundary

namespace EcdsaHssBoundary

open ecdsa_hss

abbrev GeneratedHiddenEvalInputBoundary :=
  server.boundary.HiddenEvalInputBoundary
abbrev GeneratedHiddenEvalTransportBoundary :=
  server.boundary.HiddenEvalTransportBoundary
abbrev GeneratedHiddenEvalPersistedStateBoundary :=
  server.boundary.HiddenEvalPersistedStateBoundary
abbrev GeneratedHiddenEvalBoundary :=
  server.boundary.HiddenEvalBoundary

def toHandwrittenHiddenEvalInputBoundary
    (boundary : GeneratedHiddenEvalInputBoundary) :
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
    (boundary : GeneratedHiddenEvalTransportBoundary) :
    HiddenEvalTransportBoundaryModel :=
  {
    operation := toHandwrittenOperationBoundary boundary.operation
    clientOutput := toHandwrittenClientBoundary boundary.client_output
    finalize := toHandwrittenFinalizeBoundary boundary.finalize
  }

def toHandwrittenHiddenEvalPersistedStateBoundary
    (boundary : GeneratedHiddenEvalPersistedStateBoundary) :
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
    (boundary : GeneratedHiddenEvalBoundary) : HiddenEvalBoundaryModel :=
  {
    input := toHandwrittenHiddenEvalInputBoundary boundary.input
    transport := toHandwrittenHiddenEvalTransportBoundary boundary.transport
    persisted := toHandwrittenHiddenEvalPersistedStateBoundary boundary.persisted
  }

theorem hiddenEvalInputBoundary_matchesHandwrittenModel
    (boundary : GeneratedHiddenEvalInputBoundary) :
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
    (boundary : GeneratedHiddenEvalPersistedStateBoundary) :
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
    (boundary : GeneratedHiddenEvalBoundary) :
    toHandwrittenHiddenEvalBoundary boundary =
      {
        input := toHandwrittenHiddenEvalInputBoundary boundary.input
        transport := toHandwrittenHiddenEvalTransportBoundary boundary.transport
        persisted := toHandwrittenHiddenEvalPersistedStateBoundary boundary.persisted
      } := by
  rfl

end EcdsaHssBoundary
