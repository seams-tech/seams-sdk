# VoiceID Verifier Spike

Use this folder to compare pretrained speaker-verification models against
browser-recorded fixtures before replacing the fake verifier.

## Fixture Import

Capture fixtures in the browser demo, download the manifest and audio files,
then place them in the same directory. Validate the bundle before running model
comparisons:

```sh
python3 voiceId/verifier-spike/compare_models.py \
  --manifest voiceId/fixtures/voiceid-fixture-manifest.json
```

Use `--json` when a later model-comparison script needs a machine-readable
inventory.

Use `--report-template` to print the Markdown model-selection report scaffold
for the validated fixture set.

Run the local dependency-light spectral baseline before installing heavier model
packages:

```sh
pnpm -C voiceId fixtures:evaluate:spectral
```

The baseline decodes audio with `ffmpeg`, extracts MFCC/log-mel-style summary
embeddings with `numpy`, and scores each fixture against the owner enrollment
template with cosine similarity. It is a fixture and threshold sanity check, not
the production verifier model.

The recommended first pretrained model is SpeechBrain ECAPA-TDNN:

```sh
python3 -m pip install "speechbrain>=1.0.0" "torchaudio==2.6.*"
pnpm -C voiceId fixtures:evaluate:ecapa
```

Use `speechbrain/spkrec-ecapa-voxceleb` first because it has a simple embedding
API, is trained for speaker verification on VoxCeleb, and is lighter to wire
than pyannote or NeMo for this MVP spike.

The first ECAPA report is in `reports/speechbrain-ecapa-2026-06-11.md`.
Compare x-vector, pyannote, or NeMo only if ECAPA calibration, licensing, or
deployment constraints need another option.

The production-shaped verifier runtime now supports the same ECAPA model behind
the persistent Python HTTP sidecar boundary. Start that service with
`VOICEID_VERIFIER_BACKEND=ecapa`; browser and mobile clients remain capture-only
clients.

Fixture manifest fields:

- `schemaVersion`
- `createdAt`
- `fixtureId`
- `audioFileName`
- `speakerLabel`
- `phraseLabel`
- `expectedRelation`
- `captureDevice`
- `durationMs`
- `environmentNotes`
- `capturedAt`
- `byteLength`
- `mimeType`

The loader rejects malformed manifests, duplicate fixture ids, duplicate audio
file names, path-like audio file names, missing audio files, and byte-length
mismatches.

## Reproducible Benchmark Boundary

The browser fixture bundle is an input-collection aid. Gate C experiments use
the stricter `voice_id_benchmark_manifest_v1` boundary from `benchmark.py`. It
requires immutable media hashes, consent references, subject and session ids,
subject-disjoint partitions, case-specific metadata, expected intent,
challenge tokens, and complete capture profiles.

```sh
pnpm -C voiceId benchmark:test
pnpm -C voiceId benchmark:run
```

`benchmark:run` writes paired JSON and Markdown inventory reports. It fails
measurement readiness until development, calibration, and evaluation data cover
every required case and presentation-attack class.

## Model Comparison

After fixture validation, the report template records candidate model ids,
preprocessing requirements, embedding dimension notes, threshold policy, same-user
score distribution, different-user score distribution, false accepts, false
rejects, and expected CPU latency.

The first baseline report is in `reports/spectral-baseline-2026-06-10.md`.
