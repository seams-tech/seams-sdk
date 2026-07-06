use sha2::{Digest, Sha256};

const FIELD_MODULUS: u64 = 2_305_843_009_213_693_951;
const RELATION_COUNT: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ToyBatchCheckBinding {
    backend_version: &'static str,
    operation_purpose: &'static str,
    context_binding: [u8; 32],
    left_root: [u8; 32],
    right_root: [u8; 32],
    output_commitment: [u8; 32],
}

fn toy_binding() -> ToyBatchCheckBinding {
    ToyBatchCheckBinding {
        backend_version: "covert_hss_backend_v1_experiment",
        operation_purpose: "registration",
        context_binding: [11u8; 32],
        left_root: [29u8; 32],
        right_root: [47u8; 32],
        output_commitment: [83u8; 32],
    }
}

fn derive_coefficient(binding: &ToyBatchCheckBinding, index: usize) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"ed25519-hss/covert-toy-batch-check/v1");
    hasher.update(binding.backend_version.as_bytes());
    hasher.update(binding.operation_purpose.as_bytes());
    hasher.update(binding.context_binding);
    hasher.update(binding.left_root);
    hasher.update(binding.right_root);
    hasher.update(binding.output_commitment);
    hasher.update((index as u64).to_le_bytes());
    let digest = hasher.finalize();

    let mut raw = [0u8; 8];
    raw.copy_from_slice(&digest[..8]);
    (u64::from_le_bytes(raw) % (FIELD_MODULUS - 1)) + 1
}

fn field_add(left: u64, right: u64) -> u64 {
    let sum = left as u128 + right as u128;
    (sum % FIELD_MODULUS as u128) as u64
}

fn field_mul(left: u64, right: u64) -> u64 {
    let product = left as u128 * right as u128;
    (product % FIELD_MODULUS as u128) as u64
}

fn field_sub(left: u64, right: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        FIELD_MODULUS - (right - left)
    }
}

fn field_pow(mut base: u64, mut exponent: u64) -> u64 {
    let mut accumulator = 1u64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            accumulator = field_mul(accumulator, base);
        }
        base = field_mul(base, base);
        exponent >>= 1;
    }
    accumulator
}

fn field_inverse(value: u64) -> u64 {
    assert_ne!(value, 0, "toy field inverse requires nonzero input");
    field_pow(value, FIELD_MODULUS - 2)
}

fn batch_relation_check(binding: &ToyBatchCheckBinding, residuals: &[u64]) -> bool {
    let mut accumulator = 0u64;
    for (index, residual) in residuals.iter().enumerate() {
        let coefficient = derive_coefficient(binding, index);
        accumulator = field_add(accumulator, field_mul(coefficient, *residual));
    }
    accumulator == 0
}

#[test]
fn covert_toy_batch_check_accepts_zero_residual_vector() {
    let binding = toy_binding();
    let residuals = vec![0u64; RELATION_COUNT];

    assert!(
        batch_relation_check(&binding, &residuals),
        "zero residuals must pass the toy batch check"
    );
}

#[test]
fn covert_toy_batch_check_rejects_single_nonzero_residuals() {
    let binding = toy_binding();

    for index in 0..RELATION_COUNT {
        let mut residuals = vec![0u64; RELATION_COUNT];
        residuals[index] = 1;

        assert!(
            !batch_relation_check(&binding, &residuals),
            "single nonzero residual at index {index} should fail"
        );
    }
}

#[test]
fn covert_toy_challenge_is_bound_to_roots_and_operation() {
    let binding = toy_binding();
    let mut changed_root = binding.clone();
    changed_root.left_root[0] ^= 1;
    let mut changed_purpose = binding.clone();
    changed_purpose.operation_purpose = "unlock";

    assert_ne!(
        derive_coefficient(&binding, 7),
        derive_coefficient(&changed_root, 7),
        "challenge coefficient should bind transcript roots"
    );
    assert_ne!(
        derive_coefficient(&binding, 7),
        derive_coefficient(&changed_purpose, 7),
        "challenge coefficient should bind operation purpose"
    );
}

#[test]
fn covert_toy_challenge_binds_all_context_fields() {
    let binding = toy_binding();
    let baseline = derive_coefficient(&binding, 11);

    let mut changed_backend = binding.clone();
    changed_backend.backend_version = "covert_hss_backend_v2_experiment";
    let mut changed_context = binding.clone();
    changed_context.context_binding[0] ^= 1;
    let mut changed_left_root = binding.clone();
    changed_left_root.left_root[0] ^= 1;
    let mut changed_right_root = binding.clone();
    changed_right_root.right_root[0] ^= 1;
    let mut changed_output = binding.clone();
    changed_output.output_commitment[0] ^= 1;
    let mut changed_purpose = binding.clone();
    changed_purpose.operation_purpose = "unlock";

    for changed in [
        changed_backend,
        changed_context,
        changed_left_root,
        changed_right_root,
        changed_output,
        changed_purpose,
    ] {
        assert_ne!(
            baseline,
            derive_coefficient(&changed, 11),
            "challenge coefficient must bind every transcript/context field"
        );
    }
}

#[test]
fn covert_toy_batch_check_is_unsound_if_residuals_are_chosen_after_challenge() {
    let binding = toy_binding();
    let coefficient_0 = derive_coefficient(&binding, 0);
    let coefficient_1 = derive_coefficient(&binding, 1);
    let canceling_residual = field_sub(0, field_mul(coefficient_0, field_inverse(coefficient_1)));
    let mut residuals = vec![0u64; RELATION_COUNT];
    residuals[0] = 1;
    residuals[1] = canceling_residual;

    assert!(
        batch_relation_check(&binding, &residuals),
        "adaptive residuals can cancel after the challenge; roots must commit residual families first"
    );

    let mut changed_output = binding.clone();
    changed_output.output_commitment[0] ^= 1;
    assert!(
        !batch_relation_check(&changed_output, &residuals),
        "the adaptive cancellation should be bound to the challenged transcript"
    );
}
