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
python3 -m pip install -e voiceId/verifier-spike
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
the stricter `voice_id_benchmark_manifest_v2` boundary from `benchmark.py`. It
requires immutable media hashes, an explicit provenance union for synthetic
generations or consented human captures, subject and session ids,
subject-disjoint partitions, case-specific metadata, expected intent,
challenge tokens, and complete capture profiles. Synthetic cohorts are reported
as fictional identities or owner-conditioned clones. Human FAR, FRR, and EER
stay suppressed until the evaluation partition contains a qualifying human
cohort.

```sh
pnpm -C voiceId benchmark:test
pnpm -C voiceId benchmark:run
```

`benchmark:run` writes paired JSON and Markdown inventory reports. It fails
measurement readiness until development, calibration, and evaluation data cover
every required case and presentation-attack class.

## Local model baselines

The approved local baseline manifest is
`voiceId/verifier-spike/model-manifest.json`. It records source revisions,
licenses, file sizes, per-file SHA-256 digests, and a canonical tree digest for
the Moonshine Tiny/Small F32 models, the native quantized Moonshine streaming
models, the closed-set intent model, SpeechBrain ECAPA, and the pinned upstream
AASIST source/config/checkpoint. Rebuild or verify
it against a model root with:

```sh
python3 voiceId/verifier-spike/model_manifest.py \
  --root /path/to/voiceid-models \
  --verify voiceId/verifier-spike/model-manifest.json
```

The native `moonshine-voice` runtime consumes the downloaded quantized
streaming directories. The Hugging Face F32 directories remain pinned and
verified in the manifest for a separate Transformers/ONNX comparison; passing
an F32 directory to the native runtime is rejected because its file format is
different.

The Python sidecar can use Moonshine over canonical mono 16 kHz float PCM. Set
`VOICEID_MOONSHINE_MODEL_PATH`,
`VOICEID_MOONSHINE_INTENT_MODEL_PATH`, and
`VOICEID_MOONSHINE_MODEL_ARCH=tiny_streaming` (benchmark Small only after Tiny
latency is measured). The sidecar route is
`POST /voice-id/verifier/analyze-speech`; it returns transcript, semantic
intent, and phrase decisions as separate fields. The production-shaped
verification path is `POST /voice-id/verifier/analyze-verification`, which
shares one canonical decode between Moonshine, speaker verification, and PAD.

## Synthetic corpus generation and freeze

`dia2-corpus-plan.json` and `elevenlabs-corpus-plan.json` are the concrete
subject-disjoint generation inputs. They include stable designed identities,
semantic approve/reject/cancel/repeat/unrelated cases, challenge errors,
generic synthesis, and owner-authorized conditioned attacks. Run them only in
the offline fixture pipeline:

```sh
pnpm -C voiceId corpus:generate:dia2 --help
pnpm -C voiceId corpus:generate:elevenlabs --help
pnpm -C voiceId corpus:import:consented --help
pnpm -C voiceId corpus:freeze --help
```

The Dia2 runner requires a durable state file and checkpoints each generated
fixture before moving to the next one. A rerun verifies completed WAV hashes
and resumes only from the next ordered job; an uncheckpointed final or pending
WAV stops the campaign for manual reconciliation:

```sh
pnpm -C voiceId corpus:generate:dia2 \
  --plan voiceId/verifier-spike/dia2-corpus-plan.json \
  --source-root /private/path/to/dia2 \
  --model-dir /private/path/to/Dia2-1B \
  --mimi-dir /private/path/to/mimi \
  --asset-dir /private/path/to/consented-assets \
  --output-dir /private/path/to/dia2-audio \
  --state /private/path/to/dia2-state.json \
  --manifest-out /private/path/to/dia2-manifest.json \
  --report-out /private/path/to/dia2-report.json
```

The ElevenLabs batch requires a durable `--state` file. A persistent campaign
binding prevents another state or plan from using the same output directory.
State writes are atomic and fsynced; generated audio uses a recoverable
pending-WAV protocol and a no-clobber final install. A rerun verifies every
completed artifact before skipping it:

```sh
python3 voiceId/verifier-spike/elevenlabs_batch.py \
  --plan voiceId/verifier-spike/elevenlabs-corpus-plan.json \
  --asset-dir /private/path/to/consented-assets \
  --output-dir /private/path/to/elevenlabs-audio \
  --state /private/path/to/elevenlabs-state.json \
  --manifest-out /private/path/to/elevenlabs-manifest.json \
  --report-out /private/path/to/elevenlabs-report.json
```

An ambiguous remote operation, such as a lost POST response, is recorded and
blocks automatic retry. Preserve the state and supporting account evidence; do
not delete or replace it. This runner has no audited adopt/abort operation for
a confirmed remote success or failure. The campaign therefore remains blocked
until such a recovery action is implemented. Starting another campaign can
duplicate paid work and requires an explicit operator decision.

The batch records resolved voice ids plus request/output hashes and emits
canonical 16 kHz WAV. The API key stays in the ignored root `.env.local`; the
runner reads `ELEVENLABS_API_KEY` from the process environment first and then
falls back to that file. Plans, state, and reports contain no API key.

The consented-capture importer copies a canonical owner WAV immutably and emits
one `consented_human_capture` manifest fragment. Corpus freezing validates each
fragment, copies audio with a second hash check, sorts partitions
deterministically, and emits a corpus tree digest.

For each of the three owner sessions, convert the recording to canonical mono
PCM16 at 16 kHz, then import it as a separate session and partition. Keep the
consent reference in the local manifest metadata; raw audio remains in the
private research corpus directory:

```sh
ffmpeg -i /private/path/session-1.m4a -ac 1 -ar 16000 -c:a pcm_s16le \
  /private/path/owner-corpus/session-1.wav

pnpm -C voiceId corpus:import:consented \
  --source-audio /private/path/owner-corpus/session-1.wav \
  --output-dir /private/path/owner-corpus/session-1 \
  --manifest-out /private/path/owner-corpus/session-1/manifest.json \
  --dataset-version voiceid-mvp1-v1 \
  --created-at 2026-07-31T00:00:00Z \
  --captured-at 2026-07-31T00:00:00Z \
  --fixture-id owner-session-1 \
  --audio-file-name owner-session-1.wav \
  --subject-id owner-1 \
  --session-id owner-session-1 \
  --partition development \
  --consent-reference owner-consent-2026-07-31 \
  --retention-class project-lifetime \
  --platform browser \
  --microphone macbook-pro-built-in \
  --room office \
  --distance-cm 60 \
  --language en \
  --accent en-jp \
  --noise-profile quiet
```

Repeat with unique session ids and capture dates for calibration and
evaluation. The importer rejects non-canonical audio and refuses to overwrite
an existing audio or manifest artifact. The owner sessions must contain the
same four guided prompts used by the enrollment ceremony; the stability input
is produced after the verifier has extracted its windows and embeddings.

The current Dia2 and ElevenLabs plans cover synthesis attacks. The dependency-free
augmentation runner adds deterministic replay, codec, noise, and room-response
variants from a validated source manifest. Each output is a canonical WAV with a
SHA-256 binding back to its source fixture in the transform report:

The pinned Dia2 1B path has one verified CUDA qualification run recorded in
`reports/dia2-one-job-2026-07-31.md`. That report is a generator and provenance
smoke result; it does not make the complete corpus measurement-ready.

```sh
pnpm -C voiceId corpus:augment \
  --manifest /path/to/source-manifest.json \
  --output-dir /path/to/transformed-audio \
  --manifest-out /path/to/transformed-audio/manifest.json \
  --report-out /path/to/transforms-report.json \
  --created-at 2026-07-31T00:00:00Z \
  --seed 1
```

These variants are deterministic fixture coverage for the MVP attack classes;
their reports remain labeled synthetic or transformed. Dedicated
voice-conversion, splice, relay, and broader digital-injection campaigns are
deferred from this plan.

Run measurements and calibration from the frozen manifest:

```sh
pnpm -C voiceId benchmark:moonshine --help
pnpm -C voiceId benchmark:calibrate:moonshine --help
pnpm -C voiceId benchmark:ecapa --help
pnpm -C voiceId benchmark:aasist --help
pnpm -C voiceId benchmark:suite --help
```

The Moonshine report compares exact matching with the hybrid
all-fresh-tokens/any-order policy and preserves top/runner-up intent scores.
Calibration selects threshold and winning margin on the calibration partition,
then chooses Tiny or Small using held-out accuracy and runtime budgets. ECAPA
reports FAR, FRR, EER, confidence intervals, latency, and clone-attack
acceptance separately. AASIST calibrates independent reject/uncertain/accept
regions and reports APCER/BPCER by attack class and capture profile.

`benchmark:suite` runs all three adapters from one validated corpus invocation
and writes paired JSON and Markdown outputs. It binds the corpus and local
model manifests by SHA-256 and embeds the complete component reports. Run
`pnpm -C voiceId benchmark:suite --help` for the required model paths and
output arguments.

After the suite and release-budget checker pass, freeze one calibration record
that binds the intent, speaker, PAD, capture-profile, and retry decisions to
the exact corpus and model manifests:

```sh
pnpm -C voiceId calibration:freeze \
  --corpus-manifest /path/to/frozen/voiceid-benchmark-manifest.json \
  --suite /path/to/benchmark-suite.json \
  --budgets /path/to/frozen-budgets.json \
  --budget-check /path/to/budget-check.json \
  --model-manifest /path/to/model-manifest.json \
  --created-at 2026-07-31T00:00:00Z \
  --output /path/to/calibration-record.json
```

The command fails closed unless inventory readiness and the release-budget
check are both true. It does not turn synthetic results into human population
claims.

Once the three owner sessions are processed by the verifier, measure their
cross-day template stability with the offline stability boundary:

```sh
pnpm -C voiceId enrollment:stability \
  --input /path/to/owner-enrollment-stability-input.json \
  --output /path/to/enrollment-stability-report.json
```

The input contains only the research-side session/window measurements and
embeddings; the report records the input hash, leave-one-out stability,
cross-session similarity, usable-speech gates, and shortest reliable duration.
It also requires complete four-prompt coverage before a session is marked
reliable and carries the one-quality-retry policy into the requirements.
It does not expose these measurements through the production API.

Check candidate adapters for repeated-input, cross-input, and
failure-recovery stability with:

```sh
pnpm -C voiceId benchmark:stability --help
```

The pinned Apple Silicon run is recorded in
[`reports/candidate-adapter-stability-2026-07-27.md`](reports/candidate-adapter-stability-2026-07-27.md).
Moonshine, ECAPA, and AASIST passed A-A-A, A-B-A, and post-inference A-FAIL-A.
The harness rejects empty Moonshine transcripts, malformed ECAPA embeddings,
unavailable AASIST decisions, indistinguishable A/B outputs, mutable model-tree
symlinks, and numeric tolerances above `1e-5`. This establishes deterministic
adapter behavior for those probes; it does not establish biometric accuracy or
PAD calibration.

Run the seeded malformed-media campaign separately from model benchmarks:

```sh
pnpm -C voiceId fuzz:media \
  --cases 64 \
  --seed 20260726 \
  --output /tmp/voiceid-media-fuzz.json
```

The campaign records only input hashes, sizes, outcomes, and latency. Expected
decoder rejections pass. Unexpected exceptions, duration-limit violations, or
p99 latency beyond the supplied budget fail the command.

After calibration freezes a dataset-specific budget file, enforce it against
the combined suite:

```sh
pnpm -C voiceId benchmark:check \
  --suite /path/to/benchmark-suite.json \
  --budgets /path/to/frozen-budgets.json \
  --output /tmp/voiceid-budget-check.json
```

The strict budget boundary binds the dataset and model-manifest digest, then
checks phrase accuracy, FAR/FRR/EER-derived speaker accuracy, APCER/BPCER,
uncertainty or retry rates, p95/p99 latency, memory, corpus readiness, and PAD
attack-class readiness.

## Model Comparison

After fixture validation, the report template records candidate model ids,
preprocessing requirements, embedding dimension notes, threshold policy, same-user
score distribution, different-user score distribution, false accepts, false
rejects, and expected CPU latency.

The first baseline report is in `reports/spectral-baseline-2026-06-10.md`.
