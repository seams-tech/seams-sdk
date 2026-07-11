#![no_std]

#[inline(never)]
#[no_mangle]
pub extern "C" fn ct_fixture_select(secret_bit: u8, left: u64, right: u64) -> u64 {
    let mask = 0_u64.wrapping_sub(u64::from(secret_bit & 1));
    (left & mask) | (right & !mask)
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn ct_fixture_secret_divide(secret: u64, divisor: u64) -> u64 {
    secret / (divisor | 1)
}
