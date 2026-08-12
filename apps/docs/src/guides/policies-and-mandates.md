---
title: Policies and mandates
description: Bind Seams signing and delegated authority to typed intent, scope, expiry, budget, and approval requirements.
---

# Policies and mandates

A policy decides whether an exact subject may perform an exact operation. A
mandate records the authority granted to a delegated actor.

## Define the operation

Include the action kind, subject, target, chain or account, expiry, nonce or
request identity, and any amount or budget. Add risk context only when the
policy evaluates it. Avoid generic “sign anything” grants.

## Apply the decision

1. Validate the request at the application or service boundary.
2. Resolve the exact wallet session and signing subject.
3. Evaluate scope, freshness, budget, revocation, and step-up rules.
4. Present the operation in human-readable form.
5. Sign and record the resulting decision and receipt.

Policy denial is a supported outcome. Explain the failing constraint and the
available recovery action without leaking private policy inputs.

Read [policy model](/concepts/policy/) and [mandates](/concepts/policy/mandates).
