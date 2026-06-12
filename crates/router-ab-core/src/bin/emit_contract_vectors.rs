fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", router_ab_core::generated_contract_vectors_json_v1()?);
    Ok(())
}
