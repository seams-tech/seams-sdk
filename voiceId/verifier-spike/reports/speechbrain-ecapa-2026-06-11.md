# VoiceID SpeechBrain ECAPA Evaluation

## Scope

- Adapter: `speechbrain-ecapa-voxceleb`
- Model id: `speechbrain/spkrec-ecapa-voxceleb`
- Fixture count: 30
- Embedding dimensions: 192
- Model class: pretrained ECAPA-TDNN speaker embedding model
- Scoring: cosine similarity against the mean owner enrollment template

## Model Recommendation

Use `speechbrain/spkrec-ecapa-voxceleb` as the first pretrained verifier for
the MVP spike.

Reasons:

- The model is packaged for direct speaker verification and embedding
  extraction through SpeechBrain.
- The model card states it is trained on VoxCeleb 1 and VoxCeleb 2 training
  data.
- The API surface is small enough for a verifier spike: load
  `EncoderClassifier`, decode each clip to 16 kHz mono samples, extract one
  embedding, and score with cosine similarity.
- It is easier to wire into the current Python verifier boundary than pyannote
  or NVIDIA NeMo while still representing a modern ECAPA-style verifier.

Alternatives to keep open:

- `speechbrain/spkrec-xvect-voxceleb` as a classic x-vector comparison model.
- `pyannote/embedding` if pyannote access, licensing, and deployment weight are
  acceptable.
- `nvidia/speakerverification_en_titanet_large` if a heavier NeMo-based stack
  becomes attractive later.

Sources checked:

- https://huggingface.co/speechbrain/spkrec-ecapa-voxceleb
- https://huggingface.co/speechbrain/spkrec-xvect-voxceleb
- https://huggingface.co/pyannote/embedding
- https://huggingface.co/nvidia/speakerverification_en_titanet_large
- https://speechbrain.readthedocs.io/en/latest/tutorials/advanced/pre-trained-models-and-fine-tuning-with-huggingface.html

## Fixture Notes

- Active owner enrollment clips use the laptop microphone and current 3500 ms
  recording path.
- Active owner verification clips use the laptop microphone and current 3500 ms
  recording path.
- Wrong-phrase clips are owner speech with rhyming but incorrect phrases.
- Noisy clips include legacy unstable iPhone/Continuity microphone captures and
  refreshed laptop-microphone cafe captures.
- Different-speaker clips currently include synthetic voices plus owner
  high-pitch and raspy variants. Independent human different-speaker clips are
  still needed before making stronger claims.

## Threshold

- Selected threshold: 0.6352
- True accepts: 3
- False rejects: 0
- True rejects: 5
- False accepts: 0

The selected threshold is calibrated only against the current owner-verification
and different-speaker fixture groups. Noisy owner clips are intentionally
reported as a separate quality/calibration group rather than used as hard
acceptance fixtures.

## Score Ranges

- `different_speaker`: -0.0791 to 0.3117 (5 clips)
- `noisy`: 0.0525 to 0.6776 (9 clips)
- `owner_enrollment`: 0.8597 to 0.8893 (3 clips)
- `owner_verification`: 0.6352 to 0.6768 (3 clips)
- `too_short`: 0.0332 to 0.2092 (5 clips)
- `wrong_phrase`: 0.3651 to 0.6028 (5 clips)

## Latency

- First measured mean embedding latency: 20.2 ms
- First measured P95 embedding latency: 28.7 ms
- Follow-up validation mean embedding latency: 53.9 ms
- Follow-up validation P95 embedding latency: 183.5 ms

These measurements exclude initial model download/load time. They measure
embedding extraction after audio decode for each fixture on the local machine.
The score distribution was stable across runs, while local latency had outliers,
so use these numbers as early laptop measurements rather than a production
latency budget.

## Per-Fixture Scores

| Relation | Speaker | Score | Latency ms | Fixture |
| --- | --- | ---: | ---: | --- |
| `different_speaker` | `owner_high_pitch_variant` | 0.1893 | 21.8 | `fixture_061889228e85a45e79c21535117c0655` |
| `different_speaker` | `owner_raspy_variant` | 0.3117 | 21.4 | `fixture_4bc0685965d6a471dae493b021f3b076` |
| `different_speaker` | `synthetic_adam` | 0.0361 | 14.6 | `fixture_synthetic_adam_different_speaker` |
| `different_speaker` | `synthetic_roger` | -0.0791 | 16.5 | `fixture_synthetic_roger_different_speaker` |
| `different_speaker` | `synthetic_samantha` | 0.0417 | 16.0 | `fixture_synthetic_samantha_different_speaker` |
| `noisy` | `owner` | 0.2963 | 15.8 | `fixture_04559a02e254f271db221bfd8cd63edc` |
| `noisy` | `owner` | 0.0525 | 13.2 | `fixture_2d5efdda9b873a12656cf60ca94a1e17` |
| `noisy` | `owner` | 0.3146 | 24.1 | `fixture_322929a9b6567ec93cefda314a655cbe` |
| `noisy` | `owner` | 0.1343 | 25.0 | `fixture_3c62fc0f0cbc851fa8f15df9fb6ba912` |
| `noisy` | `owner` | 0.1481 | 25.9 | `fixture_679e3c5840a2cd226c6ad3ce40db3ac9` |
| `noisy` | `owner` | 0.3506 | 12.5 | `fixture_79937506d3c92575295e33ae996b6582` |
| `noisy` | `owner` | 0.1746 | 12.7 | `fixture_8b4371fc1146c233e67fdd09b0db3711` |
| `noisy` | `owner` | 0.6776 | 21.0 | `fixture_cf49ebcd704e2ef2fde56d327ba570d0` |
| `noisy` | `owner` | 0.1279 | 10.1 | `fixture_cfb535c3cb83d69dfde89c1b6aac819b` |
| `owner_enrollment` | `owner` | 0.8811 | 29.9 | `fixture_2faf4ab8e682ef7db2ccdcd82dd5048f` |
| `owner_enrollment` | `owner` | 0.8597 | 25.3 | `fixture_38ced3a2c620effca628d62686d6cd5e` |
| `owner_enrollment` | `owner` | 0.8893 | 27.2 | `fixture_d87fa7e2abf99eae0db3a231c9140013` |
| `owner_verification` | `owner` | 0.6768 | 23.4 | `fixture_3c47c377169809c97db22ba042a430f2` |
| `owner_verification` | `owner` | 0.6352 | 26.6 | `fixture_54f0efa5768a8dc5d0fd3154e3a2b037` |
| `owner_verification` | `owner` | 0.6531 | 24.1 | `fixture_8bd968c3eb6f7071be603d3f5ce336fb` |
| `too_short` | `owner` | 0.0655 | 9.5 | `fixture_0034e58d909d928b800c8f94772f3b4d` |
| `too_short` | `owner` | 0.2092 | 10.7 | `fixture_483c2f406153dc6a58c1e53e3286fd0a` |
| `too_short` | `owner` | 0.1705 | 35.4 | `fixture_79e47583e71ddca6c578ea4e8c7ab49f` |
| `too_short` | `owner` | 0.1088 | 10.8 | `fixture_9f89281ccb1e7bff2c2481d4c9a62df7` |
| `too_short` | `owner` | 0.0332 | 12.3 | `fixture_d4fd80084713bf25f684d9039381b666` |
| `wrong_phrase` | `owner` | 0.4607 | 22.0 | `fixture_3cb61dfd15f0acf4fc25cc2d2542a022` |
| `wrong_phrase` | `owner` | 0.4863 | 19.7 | `fixture_689bb8faa8575fc80285a44d9fd73e52` |
| `wrong_phrase` | `owner` | 0.3651 | 25.7 | `fixture_7008b7a9cbf78b06ea0cc8abf22c4502` |
| `wrong_phrase` | `owner` | 0.5549 | 25.5 | `fixture_9d6cb8eafc361d816b74b194a88b06d0` |
| `wrong_phrase` | `owner` | 0.6028 | 26.1 | `fixture_aefa1acb082b264a5445c8a0806d590d` |

## Decision

Proceed with `speechbrain/spkrec-ecapa-voxceleb` as the first real
speaker-embedding model behind the verifier boundary.

MVP threshold policy:

- Start with threshold `0.6352` only for this local fixture set.
- Treat low-quality/noisy audio as `uncertain` unless a separate quality layer
  accepts the capture.
- Keep wrong-phrase rejection in the transcript/phrase verifier. Speaker
  embeddings prove speaker similarity, not command correctness.
- Recalibrate after adding independent human different-speaker clips and more
  same-owner sessions across distance, device, and background conditions.
