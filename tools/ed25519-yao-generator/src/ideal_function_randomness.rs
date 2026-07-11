//! Branch-owned host-only ideal-function output randomness.
//!
//! These wrappers assign public synthetic fixture coins to exactly one ideal
//! lifecycle branch. They do not model entropy, protocol randomness, garbling,
//! oblivious transfer, output translation, or production security.

#![cfg_attr(not(test), allow(dead_code))]

use crate::{HostOnlyActivationOutputCoinsV1, HostOnlySeedOutputCoinV1};

/// Registration-owned ideal coins for two activation-family output shares.
pub struct HostOnlyRegistrationIdealCoinsV1(HostOnlyActivationOutputCoinsV1);

impl HostOnlyRegistrationIdealCoinsV1 {
    /// Assigns explicit public synthetic fixture coins to registration.
    pub const fn from_host_only_fixture(coins: HostOnlyActivationOutputCoinsV1) -> Self {
        Self(coins)
    }

    pub(crate) fn into_activation_output_coins(self) -> HostOnlyActivationOutputCoinsV1 {
        self.0
    }
}

/// Zero-coin witness for metadata-only activation continuation.
pub struct HostOnlyActivationNoIdealCoinsV1 {
    _private: (),
}

impl HostOnlyActivationNoIdealCoinsV1 {
    /// Creates the host-only zero-coin continuation witness.
    pub const fn from_host_only_fixture() -> Self {
        Self { _private: () }
    }

    pub(crate) fn into_zero_coin_witness(self) {}
}

/// Recovery-owned ideal coins for two activation-family output shares.
pub struct HostOnlyRecoveryIdealCoinsV1(HostOnlyActivationOutputCoinsV1);

impl HostOnlyRecoveryIdealCoinsV1 {
    /// Assigns explicit public synthetic fixture coins to recovery.
    pub const fn from_host_only_fixture(coins: HostOnlyActivationOutputCoinsV1) -> Self {
        Self(coins)
    }

    pub(crate) fn into_activation_output_coins(self) -> HostOnlyActivationOutputCoinsV1 {
        self.0
    }
}

/// Refresh-owned ideal coins for two activation-family output shares.
pub struct HostOnlyRefreshIdealCoinsV1(HostOnlyActivationOutputCoinsV1);

impl HostOnlyRefreshIdealCoinsV1 {
    /// Assigns explicit public synthetic fixture coins to refresh.
    pub const fn from_host_only_fixture(coins: HostOnlyActivationOutputCoinsV1) -> Self {
        Self(coins)
    }

    pub(crate) fn into_activation_output_coins(self) -> HostOnlyActivationOutputCoinsV1 {
        self.0
    }
}

/// Export-owned ideal coin for one seed output share.
pub struct HostOnlyExportIdealCoinV1(HostOnlySeedOutputCoinV1);

impl HostOnlyExportIdealCoinV1 {
    /// Assigns one explicit public synthetic fixture coin to authorized export.
    pub const fn from_host_only_fixture(coin: HostOnlySeedOutputCoinV1) -> Self {
        Self(coin)
    }

    pub(crate) fn into_seed_output_coin(self) -> HostOnlySeedOutputCoinV1 {
        self.0
    }
}
