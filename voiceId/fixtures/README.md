# VoiceID Fixtures

This directory is for local browser-recorded fixture bundles used by the
verifier spike. Raw voice clips are biometric data, so this directory ignores
captured artifacts by default.

## Capture Checklist

1. Start the demo:

   ```sh
   pnpm -C voiceId dev:all
   ```

2. Open `http://127.0.0.1:5173`.
3. Use the Fixture Capture panel to record a small first set:
   - 3 owner enrollment clips
   - 3 owner verification clips
   - 2 different-speaker clips
   - 2 wrong-phrase clips
   - 1 noisy clip
   - 1 too-short clip
   Use 3500 ms or longer for normal phrase clips when using a phone or
   continuity microphone. The validator rejects header-only captures smaller
   than 1024 bytes.
4. Download the manifest and all audio files.
5. Place the files in this directory. The manifest should be named
   `voiceid-fixture-manifest.json`.
6. Validate the bundle:

   ```sh
   pnpm -C voiceId fixtures:validate
   ```

7. If `ffprobe` is installed, run the media-stream validator:

   ```sh
   pnpm -C voiceId fixtures:validate:media
   ```

Use `pnpm -C voiceId fixtures:validate:json` when a later model-comparison step
needs machine-readable fixture inventory.

Use `pnpm -C voiceId fixtures:report` to print the model-selection report
template for the validated fixture set.

## Retention

Keep fixture bundles local unless everyone recorded in the fixture set has
explicitly agreed to share them. Delete stale clips after model selection or
move approved fixtures into a separate encrypted storage process.
