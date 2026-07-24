# VoiceID Fixtures

This directory is for local browser-recorded fixture bundles used by the
verifier spike. Raw voice clips are biometric data, so this directory ignores
captured artifacts by default.

## Capture Checklist

1. Start the demo:

   ```sh
   pnpm -C voiceId dev:all
   ```

2. Open `http://127.0.0.1:5050`.
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

## PAD Evaluation Manifest

PAD experiments use a separate `voiceid-pad-evaluation.json` manifest. Each
entry records a subject, session, frozen development or evaluation partition,
bona-fide or attack presentation, exact attack class, capture profile, PAD
score, and latency. Bona-fide entries carry a null attack class. Attack entries
use one of:

```text
replay
synthesis
voice_conversion
splice
relay
digital_injection
```

The parser rejects subjects shared by development and evaluation partitions.
Run the dependency-free contract tests and evaluate frozen scores with:

```sh
pnpm -C voiceId pad:test
pnpm -C voiceId pad:evaluate
```

The report includes BPCER, overall APCER, uncertainty, 95% Wilson intervals,
APCER by attack class, APCER by capture profile, and missing attack species. A
manifest cannot report `releaseReady: true` until every required attack class
appears in the evaluation partition.

## Reproducible Benchmark Manifest

Gate C uses `voiceid-benchmark-manifest.json` as the frozen dataset boundary.
Each entry records an immutable audio SHA-256 digest, an explicit synthetic or
consented-human provenance branch, subject, session,
development/calibration/evaluation partition, case type, expected intent,
challenge tokens, and the complete capture profile. The parser
rejects a subject or zero-effort-impostor target that crosses partitions.
Every verification target must also have an enrollment entry in the same
partition, and presentation attacks identify their intended target explicitly.

Run the dependency-free contract tests with:

```sh
pnpm -C voiceId benchmark:test
```

Once the consented corpus is present, validate it and emit the machine-readable
inventory and human report from the same run:

```sh
pnpm -C voiceId benchmark:run
```

The report stays measurement-ineligible until all three partitions, all case
kinds, and every required presentation-attack class are represented. Raw audio
remains local or in the separately approved encrypted research store.

The solo MVP uses generated identities first. Synthetic entries carry their
generator, model revision, stable voice identity or seed, terms snapshot,
request hash, and optional conditioning consent. Generated cohorts support
engineering and attack measurements; reports suppress human population FAR,
FRR, and EER until a qualifying real-subject cohort is present.

For Cloudflare deployments, D1 stores the searchable manifest and report
metadata. Encrypted audio lives in a private R2 bucket. Research fixtures use
project-lifetime retention with explicit deletion and key revocation.

## Retention

Keep fixture bundles local unless everyone recorded in the fixture set has
explicitly agreed to share them. Delete stale clips after model selection or
move approved fixtures into a separate encrypted storage process.
