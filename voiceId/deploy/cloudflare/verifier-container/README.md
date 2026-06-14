# VoiceID Cloudflare Verifier Container

This directory packages the Python VoiceID verifier as the heavy model runtime
for Cloudflare Containers. Cloudflare Workers call it through the existing
`python-http` verifier transport.

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

For production-style images, bake the ECAPA model into the image to avoid a slow
first request:

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
  voiceid-verifier:local
```

Use ECAPA for real speaker verification:

```sh
docker run --rm \
  -p 8797:8797 \
  -e VOICEID_VERIFIER_BACKEND=ecapa \
  voiceid-verifier:ecapa
```

Health check:

```sh
curl http://127.0.0.1:8797/health
```

## Cloudflare Shape

The Cloudflare Worker entrypoint should use
`server/src/cloudflare.ts` and set:

```sh
VOICEID_PYTHON_VERIFIER_URL=https://<container-service>/voice-id/verifier/
VOICEID_VERIFIER_TIMEOUT_MS=10000
VOICEID_SPEAKER_SCORE_THRESHOLD=0.6352
VOICEID_TRANSCRIPT_PROVIDER=cloudflare-workers-ai
VOICEID_CLOUDFLARE_ASR_MODEL=@cf/openai/whisper
```

Bind Workers AI as `AI` in the Worker. ASR runs in the Worker through
Cloudflare Workers AI; ECAPA speaker verification runs in this container.
`VOICEID_SPEAKER_SCORE_THRESHOLD` defaults to `0.6352` for the Cloudflare
factory and should be recalibrated after independent human different-speaker
fixtures are collected.

The verifier exposes:

- `POST /voice-id/verifier/extract-enrollment-embedding`
- `POST /voice-id/verifier/build-template`
- `POST /voice-id/verifier/verify-speaker`
- `GET /health`

Keep raw fixture audio out of the build context. The root `.dockerignore`
excludes `fixtures`, `research`, `verifier-spike`, and local model caches.
