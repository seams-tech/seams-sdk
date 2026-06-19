# Router A/B Future Quorum Note

Date created: June 16, 2026

Status: future protocol-version note.

## Scope

Router A/B v1 ships as a strict 2-of-2 Deriver A plus Deriver B ceremony.
Generalized N-of-N and t-of-N deriver sets are future protocol work.

This note exists so the active Router A/B release plan can stay focused on the
current Cloudflare split-worker release: Router, Deriver A, Deriver B, and
SigningWorker.

## Future Shapes

- **N-of-N:** every configured deriver participates. This mainly changes request
  framing, transcript binding, deriver-set management, and operational liveness.
- **t-of-N:** an approved quorum participates, such as 2-of-3 or 3-of-5. This is
  a larger protocol change with threshold share indexing, quorum selection,
  transcript binding to the selected deriver set, replay handling, equivocation
  handling, commitments or verifying-share checks, and reviewed refresh or
  reshare semantics.

## Required Acceptance Criteria

- New durable protocol version and transcript labels.
- Fresh cross-language wire vectors.
- Fresh leakage and collusion review.
- New refresh and reshare semantics.
- Tests for duplicate deriver roles, wrong quorum, wrong deriver set, stale key
  epoch, replay, equivocation, and mixed recipient output.
- Cloudflare deployment and runtime evidence for the generalized role set.
