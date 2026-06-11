# VoiceID Spectral Baseline Evaluation

## Scope

- Adapter: `local-mfcc-stats-baseline`
- Fixture count: 30
- Embedding dimensions: 100
- Model class: local MFCC/log-mel statistics baseline
- Purpose: fixture sanity check and threshold-shape exploration before heavier pretrained models

## Fixture Notes

- Active owner enrollment clips use the laptop microphone and current 3500 ms recording path.
- Active owner verification clips now also use the laptop microphone and current 3500 ms recording path.
- Legacy short enrollment captures from the iPhone/Continuity microphone path were reclassified as `too_short`.
- Legacy owner verification captures from the unstable iPhone/Continuity microphone path were reclassified as `noisy`.
- Refreshed laptop-microphone wrong-phrase clips use rhyming but incorrect phrases.
- Refreshed laptop-microphone noisy clips include a cafe setting with the owner saying the target phrase.
- The laptop-mic same-speaker set gives clean baseline separation: no false rejects and no false accepts on the current owner-verification and different-speaker groups.
- Wrong-phrase clips are still the owner's voice, so high speaker scores are expected. Phrase correctness must be enforced by the transcript/phrase matcher.

## Threshold

- Selected threshold: 0.9773
- True accepts: 3
- False rejects: 0
- True rejects: 5
- False accepts: 0

## Score Ranges

- `different_speaker`: 0.8637 to 0.9381 (5 clips)
- `noisy`: 0.6602 to 0.9603 (9 clips)
- `owner_enrollment`: 0.9788 to 0.9869 (3 clips)
- `owner_verification`: 0.9773 to 0.9912 (3 clips)
- `too_short`: 0.5778 to 0.9316 (5 clips)
- `wrong_phrase`: 0.9369 to 0.9720 (5 clips)

## Latency

- Mean decode+embedding latency: about 50-55 ms on the local machine.
- P95 decode+embedding latency: about 65 ms on the local machine.

## Per-Fixture Scores

| Relation | Speaker | Score | Fixture |
| --- | --- | ---: | --- |
| `different_speaker` | `owner_high_pitch_variant` | 0.9201 | `fixture_061889228e85a45e79c21535117c0655` |
| `different_speaker` | `owner_raspy_variant` | 0.8958 | `fixture_4bc0685965d6a471dae493b021f3b076` |
| `different_speaker` | `synthetic_adam` | 0.8637 | `fixture_synthetic_adam_different_speaker` |
| `different_speaker` | `synthetic_roger` | 0.9381 | `fixture_synthetic_roger_different_speaker` |
| `different_speaker` | `synthetic_samantha` | 0.9120 | `fixture_synthetic_samantha_different_speaker` |
| `noisy` | `owner` | 0.9318 | `fixture_04559a02e254f271db221bfd8cd63edc` |
| `noisy` | `owner` | 0.8002 | `fixture_2d5efdda9b873a12656cf60ca94a1e17` |
| `noisy` | `owner` | 0.6602 | `fixture_322929a9b6567ec93cefda314a655cbe` |
| `noisy` | `owner` | 0.6672 | `fixture_3c62fc0f0cbc851fa8f15df9fb6ba912` |
| `noisy` | `owner` | 0.6900 | `fixture_679e3c5840a2cd226c6ad3ce40db3ac9` |
| `noisy` | `owner` | 0.8587 | `fixture_79937506d3c92575295e33ae996b6582` |
| `noisy` | `owner` | 0.9317 | `fixture_8b4371fc1146c233e67fdd09b0db3711` |
| `noisy` | `owner` | 0.9603 | `fixture_cf49ebcd704e2ef2fde56d327ba570d0` |
| `noisy` | `owner` | 0.8700 | `fixture_cfb535c3cb83d69dfde89c1b6aac819b` |
| `owner_enrollment` | `owner` | 0.9869 | `fixture_2faf4ab8e682ef7db2ccdcd82dd5048f` |
| `owner_enrollment` | `owner` | 0.9852 | `fixture_38ced3a2c620effca628d62686d6cd5e` |
| `owner_enrollment` | `owner` | 0.9788 | `fixture_d87fa7e2abf99eae0db3a231c9140013` |
| `owner_verification` | `owner` | 0.9785 | `fixture_3c47c377169809c97db22ba042a430f2` |
| `owner_verification` | `owner` | 0.9773 | `fixture_54f0efa5768a8dc5d0fd3154e3a2b037` |
| `owner_verification` | `owner` | 0.9912 | `fixture_8bd968c3eb6f7071be603d3f5ce336fb` |
| `too_short` | `owner` | 0.5778 | `fixture_0034e58d909d928b800c8f94772f3b4d` |
| `too_short` | `owner` | 0.9316 | `fixture_483c2f406153dc6a58c1e53e3286fd0a` |
| `too_short` | `owner` | 0.6201 | `fixture_79e47583e71ddca6c578ea4e8c7ab49f` |
| `too_short` | `owner` | 0.7969 | `fixture_9f89281ccb1e7bff2c2481d4c9a62df7` |
| `too_short` | `owner` | 0.8361 | `fixture_d4fd80084713bf25f684d9039381b666` |
| `wrong_phrase` | `owner` | 0.9720 | `fixture_3cb61dfd15f0acf4fc25cc2d2542a022` |
| `wrong_phrase` | `owner` | 0.9369 | `fixture_689bb8faa8575fc80285a44d9fd73e52` |
| `wrong_phrase` | `owner` | 0.9637 | `fixture_7008b7a9cbf78b06ea0cc8abf22c4502` |
| `wrong_phrase` | `owner` | 0.9516 | `fixture_9d6cb8eafc361d816b74b194a88b06d0` |
| `wrong_phrase` | `owner` | 0.9602 | `fixture_aefa1acb082b264a5445c8a0806d590d` |

## Decision

This baseline is useful for checking fixture wiring, score ranges, and approximate CPU latency. It is not the production speaker-verification model.

Next steps:

1. Compare a pretrained ECAPA/x-vector style model against the same manifest.
2. Use this report as the floor for latency and score separation.
3. Keep wrong-phrase acceptance tied to transcript/phrase verification, not speaker score.
4. Optionally re-record owner voice-variant clips with the laptop microphone if the pretrained model shows calibration ambiguity.
5. Collect independent human different-speaker clips before making stronger security claims.
