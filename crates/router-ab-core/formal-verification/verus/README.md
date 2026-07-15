# `router-ab-core` Verus Track

This Verus crate holds the abstract proof model for the fixed Router A/B ECDSA
threshold-PRF construction.

Initial scope:

- role model
- opened-value model
- forbidden joined-state model
- output visibility model
- context/transcript encoding model

The remaining work binds the fixed 2-of-2 share ids, context encoding, and
transcript fields to production Rust.
