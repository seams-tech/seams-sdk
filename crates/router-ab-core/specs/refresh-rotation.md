# Refresh And Rotation

Refresh must preserve the split-state invariant while rotating operational
material.

## Root Share Epochs

Every ceremony binds `root_share_epoch`. The epoch is part of the derivation
context and transcript digest. A/B derivers must reject mismatched epoch
requests before deriving outputs.

## Refresh Requirements

Refresh must:

- produce fresh A/B material
- avoid reconstructing joined roots
- bind old and new deriver identities
- bind old and new root epochs
- produce address verification evidence before activating the new epoch
- keep request-boundary compatibility isolated to the Router adapter

## Production Release Gate

Address verification is mandatory before production root rotation. A refresh
implementation can land behind tests, but production activation requires
vectors proving that old and new epochs derive the expected account public key
or verification relation.
