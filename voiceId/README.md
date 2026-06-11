# VoiceID MVP

Standalone browser-captured, server-verified speaker verification MVP.

Phase 1 keeps VoiceID isolated from wallet/auth code. The server accepts typed
audio samples, runs phrase, quality, and speaker checks through a verifier
boundary, and stores enrollment/verification state without persisting raw audio.

Commands:

```sh
pnpm -C voiceId type-check
pnpm -C voiceId test
pnpm -C voiceId dev:all
pnpm -C voiceId dev:server
pnpm -C voiceId dev
pnpm -C voiceId fixtures:validate
pnpm -C voiceId fixtures:validate:media
pnpm -C voiceId fixtures:report
pnpm -C voiceId fixtures:evaluate:spectral
pnpm -C voiceId fixtures:evaluate:ecapa
pnpm -C voiceId verifier:test
```

`dev:all` starts the API on `http://127.0.0.1:8787` and the browser demo on
`http://127.0.0.1:5173`.

Fixture capture exports should be placed in `voiceId/fixtures` with the manifest
named `voiceid-fixture-manifest.json`. Raw voice fixtures are local artifacts and
are ignored from git by default.

Use `fixtures:validate` for manifest and byte-length checks. Use
`fixtures:validate:media` when `ffprobe` is available and the fixture files
should be decoded enough to confirm they contain audio streams.

`fixtures:evaluate:ecapa` uses the optional SpeechBrain ECAPA-TDNN evaluator.
Install its Python dependencies before running it:

```sh
python3 -m pip install "speechbrain>=1.0.0" "torchaudio==2.6.*"
```

The first pretrained-model report is
`voiceId/verifier-spike/reports/speechbrain-ecapa-2026-06-11.md`.
