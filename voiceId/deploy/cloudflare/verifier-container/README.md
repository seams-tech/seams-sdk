# VoiceID Cloudflare Verifier Container

Status: speaker-component runtime; no E2 or signing authority.

Normative security requirements:
[VoiceID Signing Security Profile](../../../docs/voiceId-signing-security-profile.md).

This directory packages the Python VoiceID verifier as the heavy model runtime
for Cloudflare Containers. Cloudflare Workers call it through the existing
`python-http` verifier transport.

The combined verifier returns phrase, semantic-intent, speaker, quality, and
PAD component results from one canonical decode. ECAPA supplies speaker
matching, Moonshine supplies constrained speech analysis, and the optional
pinned AASIST adapter supplies research PAD evidence. These components cannot
establish trusted capture provenance, device proof, E2, authenticator UV, or
signing authorization.

The Worker must not import PyTorch, SpeechBrain, ffmpeg, or model weights. Those
dependencies live in this container image.

## Build

Run from `voiceId/`:

```sh
docker build \
  -f deploy/cloudflare/verifier-container/Dockerfile \
  -t voiceid-verifier:local \
  .
```

For deployment-like latency tests, bake the ECAPA model into the image to avoid
a slow first request:

```sh
docker build \
  -f deploy/cloudflare/verifier-container/Dockerfile \
  --build-arg PRELOAD_ECAPA_MODEL=1 \
  -t voiceid-verifier:ecapa \
  .
```

## Run Locally

Use the placeholder backend for quick container smoke tests:

```sh
docker run --rm \
  -p 8797:8797 \
  -e VOICEID_VERIFIER_BACKEND=placeholder \
  -e VOICEID_VERIFIER_MAX_CONCURRENT_INFERENCES=1 \
  -e VOICEID_VERIFIER_QUEUE_WAIT_MS=250 \
  voiceid-verifier:local
```

Use ECAPA for E0 speaker-verification research:

```sh
docker run --rm \
  -p 8797:8797 \
  -e VOICEID_VERIFIER_BACKEND=ecapa \
  -e VOICEID_VERIFIER_MAX_CONCURRENT_INFERENCES=1 \
  -e VOICEID_VERIFIER_QUEUE_WAIT_MS=250 \
  voiceid-verifier:ecapa
```

To exercise the research PAD path, mount the pinned AASIST source, checkpoint,
and config as read-only files. Supply an immutable calibration identifier and
thresholds produced by the held-out PAD benchmark:

```sh
docker run --rm \
  -p 8797:8797 \
  -v /path/to/pinned-aasist:/models/aasist:ro \
  -e VOICEID_VERIFIER_BACKEND=ecapa \
  -e VOICEID_PAD_AASIST_SOURCE_PATH=/models/aasist/AASIST.py \
  -e VOICEID_PAD_AASIST_CHECKPOINT_PATH=/models/aasist/AASIST.pth \
  -e VOICEID_PAD_AASIST_CONFIG_PATH=/models/aasist/AASIST.conf \
  -e VOICEID_PAD_REJECT_THRESHOLD=<calibrated-reject-threshold> \
  -e VOICEID_PAD_ACCEPT_THRESHOLD=<calibrated-accept-threshold> \
  -e VOICEID_PAD_CALIBRATION_VERSION=<immutable-calibration-id> \
  voiceid-verifier:ecapa
```

The adapter verifies the exact source, checkpoint, and config hashes before it
loads them. The model files stay outside the image and fixture corpus.

Health check:

```sh
curl http://127.0.0.1:8797/health
```

## Cloudflare Shape

The Cloudflare Worker entrypoint should use
`server/src/cloudflare.ts` and set:

```sh
VOICEID_PYTHON_VERIFIER_URL=https://<container-service>/voice-id/verifier/
VOICEID_ALLOWED_ORIGINS=https://<voice-capture-origin>
VOICEID_VERIFIER_TIMEOUT_MS=10000
# Local-development E0 threshold only; prohibited for E2.
VOICEID_SPEAKER_SCORE_THRESHOLD=0.6352
VOICEID_TRANSCRIPT_PROVIDER=cloudflare-workers-ai
VOICEID_CLOUDFLARE_ASR_MODEL=@cf/openai/whisper
```

The Moonshine combined-analysis profile runs speech analysis, ECAPA speaker
verification, and configured AASIST PAD in this container. The separate
Cloudflare Workers AI ASR mode remains available for E0 provider comparison.
Bind Workers AI as `AI` when that comparison profile is selected.
`VOICEID_SPEAKER_SCORE_THRESHOLD` defaults to `0.6352` for the Cloudflare
factory. This is an E0 local-development value. E2 must reject it and require an
approved speaker-disjoint calibration record for the exact model, preprocessing,
aggregation, threshold, capture profile, language cohort, and retry policy.

Worker-to-container transport must authenticate the Worker/service identity and
protect request integrity. Enforce media byte, decoded-duration, container,
timeout, concurrency, and rate limits before inference. Raw media remains
transient and is deleted after the operation. Worker, proxy, container, and
crash logs exclude audio, embeddings, templates, full transcripts, and raw model
responses.

The verifier exposes the atomic enrollment and component routes plus the
combined verification analysis:

- `POST /voice-id/verifier/build-enrollment-template`
- `POST /voice-id/verifier/verify-speaker`
- `POST /voice-id/verifier/analyze-speech`
- `POST /voice-id/verifier/analyze-verification`
- `GET /health`

`/health` reports warm runtime readiness and immutable model, adapter,
threshold, and template identifiers without exposing secrets. An approved
deployment must additionally bind the exact image digest and calibration
record. The deployment pins image and model artifacts by digest/checksum.

Keep raw fixture audio out of the build context. The root `.dockerignore`
excludes `fixtures`, `research`, `verifier-spike`, and local model caches.
