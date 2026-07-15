export const ACTIVATION_128KIB_WIRE_PROFILE = Object.freeze({
  table_payload_bytes: 2_104_960,
  body_bytes: 2_106_524,
  frame_count: 17,
  table_framing_payload_bytes: 1_564,
  table_protocol_bytes: 2_106_772,
  ot_payload_bytes: 82_112,
  ot_message_count: 4,
  ot_sequential_round_count: 4,
  other_control_payload_bytes: 33_300,
  envelope_header_bytes: 400,
  table_transport_bytes: 2_107_060,
  control_transport_bytes: 115_524,
  deriver_a_to_b_transport_bytes: 2_185_420,
  deriver_b_to_a_transport_bytes: 37_164,
  total_ab_transport_bytes: 2_222_584,
  transport_message_count: 25,
  client_package_bytes: 216,
  signing_worker_package_bytes: 216,
});

export function mismatchedActivationWireField(result) {
  for (const [field, expected] of Object.entries(ACTIVATION_128KIB_WIRE_PROFILE)) {
    if (result[field] !== expected) {
      return field;
    }
  }
  if (
    result.total_outgoing_envelope_bytes !==
      ACTIVATION_128KIB_WIRE_PROFILE.deriver_a_to_b_transport_bytes ||
    result.total_incoming_body_bytes !==
      ACTIVATION_128KIB_WIRE_PROFILE.deriver_b_to_a_transport_bytes
  ) {
    return "directional_transport_bytes";
  }
  return null;
}
