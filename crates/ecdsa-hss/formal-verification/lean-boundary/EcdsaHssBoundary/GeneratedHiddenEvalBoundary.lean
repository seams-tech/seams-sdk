import EcdsaHssBoundary.GeneratedVisibleBoundary

namespace EcdsaHssBoundary

open ecdsa_hss

abbrev GeneratedHiddenEvalInputBoundaryV1 :=
  server.boundary.HiddenEvalInputBoundaryV1
abbrev GeneratedHiddenEvalTransportBoundaryV1 :=
  server.boundary.HiddenEvalTransportBoundaryV1
abbrev GeneratedHiddenEvalPersistedStateBoundaryV1 :=
  server.boundary.HiddenEvalPersistedStateBoundaryV1
abbrev GeneratedHiddenEvalBoundaryV1 :=
  server.boundary.HiddenEvalBoundaryV1

def toHandwrittenHiddenEvalInputBoundary
    (boundary : GeneratedHiddenEvalInputBoundaryV1) :
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
    (boundary : GeneratedHiddenEvalBoundaryV1) : HiddenEvalBoundaryModel :=
  {
    input := toHandwrittenHiddenEvalInputBoundary boundary.input
    transport := toHandwrittenHiddenEvalTransportBoundary boundary.transport
    persisted := toHandwrittenHiddenEvalPersistedStateBoundary boundary.persisted
  }

theorem hiddenEvalInputBoundary_matchesHandwrittenModel
    (boundary : GeneratedHiddenEvalInputBoundaryV1) :
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
    (boundary : GeneratedHiddenEvalPersistedStateBoundaryV1) :
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
    (boundary : GeneratedHiddenEvalBoundaryV1) :
    toHandwrittenHiddenEvalBoundary boundary =
      {
        input := toHandwrittenHiddenEvalInputBoundary boundary.input
        transport := toHandwrittenHiddenEvalTransportBoundary boundary.transport
        persisted := toHandwrittenHiddenEvalPersistedStateBoundary boundary.persisted
      } := by
  rfl

end EcdsaHssBoundary
