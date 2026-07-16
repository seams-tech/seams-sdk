#![forbid(unsafe_code)]

use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SCALAR_SIZE: usize = 32;
pub const COMPRESSED_POINT_SIZE: usize = 33;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PairContextDigest([u8; 32]);

impl PairContextDigest {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SigningScopeDigest([u8; 32]);

impl SigningScopeDigest {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PresignPairContext {
    signing_scope: SigningScopeDigest,
    pair: PairContextDigest,
}

impl PresignPairContext {
    pub const fn new(signing_scope: SigningScopeDigest, pair: PairContextDigest) -> Self {
        Self {
            signing_scope,
            pair,
        }
    }

    pub const fn signing_scope(&self) -> SigningScopeDigest {
        self.signing_scope
    }

    pub const fn pair(&self) -> PairContextDigest {
        self.pair
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CompressedPointBytes([u8; COMPRESSED_POINT_SIZE]);

impl CompressedPointBytes {
    pub const fn new(bytes: [u8; COMPRESSED_POINT_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; COMPRESSED_POINT_SIZE] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ScalarBytes([u8; SCALAR_SIZE]);

impl ScalarBytes {
    pub const fn new(bytes: [u8; SCALAR_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn into_bytes(self) -> [u8; SCALAR_SIZE] {
        self.0
    }

    fn to_bytes(&self) -> [u8; SCALAR_SIZE] {
        self.0
    }
}

macro_rules! define_e_share_message {
    ($name:ident) => {
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name {
            #[zeroize(skip)]
            context: PresignPairContext,
            e_share: ScalarBytes,
        }

        impl $name {
            pub const fn new(context: PresignPairContext, e_share: ScalarBytes) -> Self {
                Self { context, e_share }
            }

            pub fn into_parts(self) -> (PresignPairContext, [u8; SCALAR_SIZE]) {
                (self.context, self.e_share.to_bytes())
            }
        }
    };
}

macro_rules! define_alpha_beta_message {
    ($name:ident) => {
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name {
            #[zeroize(skip)]
            context: PresignPairContext,
            alpha: ScalarBytes,
            beta: ScalarBytes,
        }

        impl $name {
            pub const fn new(
                context: PresignPairContext,
                alpha: ScalarBytes,
                beta: ScalarBytes,
            ) -> Self {
                Self {
                    context,
                    alpha,
                    beta,
                }
            }

            pub fn into_parts(self) -> (PresignPairContext, [u8; SCALAR_SIZE], [u8; SCALAR_SIZE]) {
                (self.context, self.alpha.to_bytes(), self.beta.to_bytes())
            }
        }
    };
}

define_e_share_message!(ClientEShareMessage);
define_e_share_message!(SigningWorkerEShareMessage);
define_alpha_beta_message!(ClientAlphaBetaMessage);
define_alpha_beta_message!(SigningWorkerAlphaBetaMessage);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_have_fixed_role_and_width() {
        let context = PresignPairContext::new(
            SigningScopeDigest::new([6; 32]),
            PairContextDigest::new([7; 32]),
        );
        let message = ClientEShareMessage::new(context, ScalarBytes::new([9; 32]));
        let (actual_context, scalar) = message.into_parts();

        assert_eq!(actual_context, context);
        assert_eq!(scalar, [9; 32]);
    }
}
