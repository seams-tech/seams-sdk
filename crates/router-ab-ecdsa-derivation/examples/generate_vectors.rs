use router_ab_ecdsa_derivation::{
    context_binding, derive_client_share, derive_relayer_share_for_client_public, encode_context,
    RouterAbEcdsaDerivationStableKeyContext,
};
use serde_json::json;

fn main() {
    let context = RouterAbEcdsaDerivationStableKeyContext::new([0x42; 32]);
    let client_root32_le = [0x11; 32];
    let relayer_root32_le = [0x22; 32];
    let client_share =
        derive_client_share(&context, client_root32_le).expect("derive client share");
    let (_, identity) = derive_relayer_share_for_client_public(
        &context,
        relayer_root32_le,
        &client_share.derivation_client_share_public_key33,
        client_share.retry_counter,
    )
    .expect("derive relayer share and public identity");

    let fixture = json!({
        "format_version": 1,
        "protocol": "router_ab_ecdsa_derivation_v1",
        "context": {
            "application_binding_digest_hex": hex::encode(context.application_binding_digest),
            "encoding_hex": hex::encode(encode_context(&context).expect("encode context")),
            "binding32_hex": hex::encode(context_binding(&context).expect("context binding")),
        },
        "inputs": {
            "client_root32_le_hex": hex::encode(client_root32_le),
            "relayer_root32_le_hex": hex::encode(relayer_root32_le),
        },
        "identity": {
            "derivation_client_share_public_key33_hex":
                hex::encode(identity.derivation_client_share_public_key33),
            "relayer_public_key33_hex": hex::encode(identity.relayer_public_key33),
            "threshold_public_key33_hex": hex::encode(identity.threshold_public_key33),
            "threshold_ethereum_address20_hex":
                hex::encode(identity.threshold_ethereum_address20),
            "client_share_retry_counter": identity.client_share_retry_counter,
            "relayer_share_retry_counter": identity.relayer_share_retry_counter,
        },
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&fixture).expect("serialize fixture")
    );
}
