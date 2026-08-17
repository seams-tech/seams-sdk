---
title: Policies and mandates
description: Bind Seams signing and delegated authority to typed intent, scope, expiry, budget, and approval requirements.
---

# Policies and mandates

Start with [Signing](/examples/signing), then add policy checks around the
typed request. A policy decides whether an exact subject may perform an exact
operation. A mandate records authority granted to a delegated actor.

## Describe one operation

Include the action kind, subject, target, chain or account, expiry, nonce or
request identity, and any amount or budget the policy evaluates. Avoid generic
“sign anything” grants.

## Evaluate before signing

1. Validate the request at the application or service boundary.
2. Resolve the exact wallet session and signing subject.
3. Evaluate scope, freshness, budget, revocation, and step-up requirements.
4. Present the operation in human-readable form.
5. Sign and record the resulting decision and receipt.

Policy denial is a supported outcome. Explain the failing constraint and the
available recovery action without exposing private policy inputs.

Read the [policy model](/concepts/policy/) and [mandates](/concepts/policy/mandates)
for the full vocabulary.
