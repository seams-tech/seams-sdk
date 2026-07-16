use super::*;

const SESSION: [u8; 32] = [0x31; 32];
const TRANSCRIPT: [u8; 32] = [0x42; 32];
const RANDOM_CASES: usize = 512;

struct DeterministicGenerator(u64);

impl DeterministicGenerator {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn fill(&mut self, output: &mut [u8]) {
        for byte in output {
            *byte = self.next_u64() as u8;
        }
    }
}

fn encode_package(expected: ExpectedPackage, payload: &[u8]) -> Vec<u8> {
    let mut encoded = vec![0_u8; expected.total_bytes];
    encoded[..8].copy_from_slice(PACKAGE_MAGIC);
    encoded[8] = PACKAGE_VERSION;
    encoded[9] = expected.family_tag;
    encoded[10] = expected.role_tag;
    encoded[11] = expected.recipient_tag;
    encoded[12] = expected.output_kind;
    encoded[16..48].copy_from_slice(&SESSION);
    encoded[48..80].copy_from_slice(&expected.circuit_digest);
    encoded[80..112].copy_from_slice(&expected.schedule_digest);
    encoded[112..144].copy_from_slice(&TRANSCRIPT);
    encoded[144..148].copy_from_slice(&PACKAGE_ITEM_COUNT.to_be_bytes());
    encoded[148..152].copy_from_slice(&(expected.payload_bytes as u32).to_be_bytes());
    encoded[152..].copy_from_slice(payload);
    encoded
}

fn activation_package(role_tag: u8, scalar: Scalar) -> Vec<u8> {
    let mut payload = [0_u8; 64];
    payload[..32].copy_from_slice(&scalar.to_bytes());
    payload[32..].copy_from_slice((ED25519_BASEPOINT_POINT * scalar).compress().as_bytes());
    encode_package(activation_expected(role_tag), &payload)
}

fn export_package(role_tag: u8, share: [u8; 32]) -> Vec<u8> {
    encode_package(export_expected(role_tag), &share)
}

fn exercise_activation_pair(left: Vec<u8>, right: Vec<u8>) {
    let Ok(left) = ActivationDeriverAClientPackage::from_bytes(left) else {
        return;
    };
    let Ok(right) = ActivationDeriverBClientPackage::from_bytes(right) else {
        return;
    };
    let _ = combine_client_activation_packages(SESSION, TRANSCRIPT, left, right);
}

fn exercise_export_pair(left: Vec<u8>, right: Vec<u8>) {
    let Ok(left) = ExportDeriverAClientPackage::from_bytes(left) else {
        return;
    };
    let Ok(right) = ExportDeriverBClientPackage::from_bytes(right) else {
        return;
    };
    let _ = combine_export_packages(SESSION, TRANSCRIPT, left, right);
}

#[test]
fn deterministic_recipient_package_parser_fuzz_smoke() {
    let canonical_activation_a = activation_package(DERIVER_A_ROLE_TAG, Scalar::from(2_u64));
    let canonical_activation_b = activation_package(DERIVER_B_ROLE_TAG, Scalar::from(3_u64));
    for offset in 0..canonical_activation_a.len() {
        let mut mutated = canonical_activation_a.clone();
        mutated[offset] ^= 1_u8 << (offset % 8);
        exercise_activation_pair(mutated, canonical_activation_b.clone());
    }

    let canonical_export_a = export_package(DERIVER_A_ROLE_TAG, [0x17; 32]);
    let canonical_export_b = export_package(DERIVER_B_ROLE_TAG, [0x29; 32]);
    for offset in 0..PACKAGE_HEADER_BYTES {
        let mut mutated = canonical_export_a.clone();
        mutated[offset] ^= 1_u8 << (offset % 8);
        let left = ExportDeriverAClientPackage::from_bytes(mutated).expect("fixed width");
        let right = ExportDeriverBClientPackage::from_bytes(canonical_export_b.clone())
            .expect("fixed width");
        assert!(combine_export_packages(SESSION, TRANSCRIPT, left, right).is_err());
    }

    for malformed_length in [0, 1, 151, 152, 183, 185, 215, 217, 512] {
        assert!(ExportDeriverAClientPackage::from_bytes(vec![0; malformed_length]).is_err());
        assert!(ActivationDeriverAClientPackage::from_bytes(vec![0; malformed_length]).is_err());
    }

    let mut generator = DeterministicGenerator::new(0xbb67_ae85_84ca_a73b);
    for _ in 0..RANDOM_CASES {
        let mut activation_a = vec![0_u8; ACTIVATION_PACKAGE_BYTES];
        let mut activation_b = vec![0_u8; ACTIVATION_PACKAGE_BYTES];
        generator.fill(&mut activation_a);
        generator.fill(&mut activation_b);
        exercise_activation_pair(activation_a, activation_b);

        let mut export_a = vec![0_u8; EXPORT_PACKAGE_BYTES];
        let mut export_b = vec![0_u8; EXPORT_PACKAGE_BYTES];
        generator.fill(&mut export_a);
        generator.fill(&mut export_b);
        exercise_export_pair(export_a, export_b);

        let arbitrary_length = generator.next_u64() as usize % 257;
        let mut arbitrary = vec![0_u8; arbitrary_length];
        generator.fill(&mut arbitrary);
        let _ = ExportDeriverAClientPackage::from_bytes(arbitrary);
    }

    exercise_export_pair(canonical_export_a, canonical_export_b);
}
