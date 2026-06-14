import {
  VoiceIdClient,
  VoiceIdRecorder,
  buildManifestFromCapturedVoiceIdFixtures,
  createCapturedVoiceIdFixture,
  downloadVoiceIdFixtureAudio,
  downloadVoiceIdFixtureManifest,
  type CapturedVoiceIdFixture,
} from '../../client/src/index.ts';
import {
  VOICE_ID_FIXTURE_EXPECTED_RELATIONS,
  buildVoiceIdSpokenIntentBinding,
  nowIsoDateTime,
  type VoiceIdAudioLivenessPolicy,
  type VoiceIdAudioLivenessSignals,
  type VoiceIdFixtureExpectedRelation,
  type VoiceIdLocalDeviceContext,
} from '../../shared/src/index.ts';

type DemoState =
  | { kind: 'idle'; message: string }
  | { kind: 'enrolling'; enrollmentId: string; acceptedSampleCount: number; message: string }
  | { kind: 'enrolled'; enrollmentId: string; message: string }
  | { kind: 'verifying'; enrollmentId: string; verificationId: string; phrase: string; intentDigest: string; message: string }
  | { kind: 'accepted'; enrollmentId: string; message: string }
  | { kind: 'rejected'; enrollmentId: string; reason: string; message: string }
  | { kind: 'uncertain'; enrollmentId: string; reason: string; message: string }
  | { kind: 'error'; message: string };

type ApiEnvelope =
  | {
      kind: 'ok';
      value: unknown;
    }
  | {
      kind: 'error';
      error: { kind: string; message: string };
    };

type DemoDiagnostics = {
  quality: string;
  phrase: string;
  speaker: string;
  finalResult: string;
};

type DemoRecordingSession =
  | { kind: 'none' }
  | {
      kind: 'enrollment' | 'verification' | 'fixture';
      title: string;
      detail: string;
      durationMs: number;
    };

type FixtureCaptureForm = {
  speakerLabel: string;
  phraseLabel: string;
  expectedRelation: VoiceIdFixtureExpectedRelation;
  captureDevice: string;
  durationMs: number;
  environmentNotes: string;
};

type CapturedFixtureView = {
  readonly fixture: CapturedVoiceIdFixture;
  readonly previewUrl: string;
};

type BrowserWritableFileStream = {
  write(data: Blob | string): Promise<void>;
  close(): Promise<void>;
};

type BrowserFileHandle = {
  createWritable(): Promise<BrowserWritableFileStream>;
};

type BrowserDirectoryHandle = {
  getFileHandle(fileName: string, options: { create: true }): Promise<BrowserFileHandle>;
};

type DirectoryPickerWindow = Window & {
  showDirectoryPicker?: () => Promise<BrowserDirectoryHandle>;
};

type VerificationApiResult =
  | {
      kind: 'accepted';
      checks: VerificationChecks;
    }
  | {
      kind: 'rejected';
      reason: string;
      checks: VerificationChecks;
    }
  | {
      kind: 'uncertain';
      reason: string;
      checks: VerificationChecks;
    };

type VerificationChecks = {
  quality: {
    kind: string;
    reason?: string;
    durationMs: number;
    signalScore?: number;
  };
  phrase: {
    kind: string;
    reason?: string;
    expectedNormalized: string;
    spokenNormalized: string;
    confidence: number;
  };
  speaker: {
    kind: string;
    reason?: string;
    score: number;
    threshold: number;
  };
};

const userId = 'demo-owner';
const phrase = 'Walking on clouds';
const demoSpokenIntentCommand = 'send 1 USDC to bob.near';
const demoIntentNonce = 'demo_nonce_123456';
const client = new VoiceIdClient({
  baseUrl: 'http://127.0.0.1:8787',
  fetch,
});
const recorder = new VoiceIdRecorder();
let state: DemoState = { kind: 'idle', message: 'Ready' };
let diagnostics: DemoDiagnostics = {
  quality: 'none',
  phrase: 'none',
  speaker: 'none',
  finalResult: 'none',
};
let activeRecording: DemoRecordingSession = { kind: 'none' };
let fixtureForm: FixtureCaptureForm = {
  speakerLabel: 'owner',
  phraseLabel: phrase,
  expectedRelation: 'owner_enrollment',
  captureDevice: 'browser microphone',
  durationMs: 3500,
  environmentNotes: 'quiet room',
};
let fixtureCaptureMessage = 'No fixtures captured';
let capturedFixtures: CapturedFixtureView[] = [];
let isSavingFixtureSet = false;
let enrollmentAttempts = 0;
let verificationAttempts = 0;

const app = document.querySelector<HTMLElement>('#app');
if (!app) {
  throw new Error('missing app root');
}
const appRoot = app;

render();

function render(): void {
  const controls = getDemoControls(state);
  const displayedPrompt = state.kind === 'verifying' ? state.phrase : phrase;
  appRoot.innerHTML = `
    <section class="shell">
      <header>
        <h1>VoiceID MVP</h1>
        <p>Browser speaker verification demo.</p>
      </header>
      <section class="panel voice-panel">
        <div class="voice-layout">
          <div class="prompt-block">
            <span class="eyebrow">Speak</span>
            <div class="prompt-text">${escapeHtml(displayedPrompt)}</div>
            <div class="sample-progress" aria-label="Enrollment samples accepted">
              ${renderSampleDots(getEnrollmentSampleCount(state))}
              <span>${getEnrollmentSampleCount(state)} / 3 enrollment samples</span>
            </div>
          </div>
          <dl class="status-grid">
            <div><dt>Status</dt><dd>${escapeHtml(formatStateKind(state.kind))}</dd></div>
            <div><dt>Message</dt><dd>${escapeHtml(state.message)}</dd></div>
            <div><dt>Quality</dt><dd>${escapeHtml(diagnostics.quality)}</dd></div>
            <div><dt>Phrase</dt><dd>${escapeHtml(diagnostics.phrase)}</dd></div>
            <div><dt>Speaker</dt><dd>${escapeHtml(diagnostics.speaker)}</dd></div>
            <div><dt>Final</dt><dd>${escapeHtml(diagnostics.finalResult)}</dd></div>
          </dl>
        </div>
        ${renderRecordingBanner()}
        <div class="action-groups">
          <div class="action-group">
            <span>Enrollment</span>
            <button id="start-enrollment" ${disabledAttribute(!controls.canStartEnrollment)}>Start</button>
            <button id="record-enrollment" ${disabledAttribute(!controls.canRecordEnrollment)}>Record sample</button>
            <button id="finalize-enrollment" ${disabledAttribute(!controls.canFinalizeEnrollment)}>Finalize</button>
          </div>
          <div class="action-group">
            <span>Verification</span>
            <button id="start-verification" ${disabledAttribute(!controls.canStartVerification)}>Start</button>
            <button id="record-verification" ${disabledAttribute(!controls.canRecordVerification)}>Record</button>
          </div>
        </div>
      </section>
      ${renderFixtureCapturePanel()}
    </section>
  `;

  document.querySelector('#start-enrollment')?.addEventListener('click', startEnrollment);
  document.querySelector('#record-enrollment')?.addEventListener('click', recordEnrollmentSample);
  document.querySelector('#finalize-enrollment')?.addEventListener('click', finalizeEnrollment);
  document.querySelector('#start-verification')?.addEventListener('click', startVerification);
  document.querySelector('#record-verification')?.addEventListener('click', recordVerificationSample);
  bindFixtureCaptureControls();
}

function renderFixtureCapturePanel(): string {
  const hasFixtures = capturedFixtures.length > 0;
  const canCaptureFixture = activeRecording.kind === 'none' && !isSavingFixtureSet;
  const canSaveFixtures = hasFixtures && activeRecording.kind === 'none' && !isSavingFixtureSet;
  return `
    <section class="panel fixture-panel">
      <div class="panel-heading">
        <div>
          <h2>Fixture Capture</h2>
          <p>Capture labeled clips for verifier evaluation.</p>
        </div>
        <span class="count-pill">${capturedFixtures.length} queued</span>
      </div>
      <div class="fixture-summary">
        <span class="eyebrow">Next clip</span>
        <strong>${escapeHtml(fixtureForm.phraseLabel)}</strong>
        <div class="fixture-summary-meta">
          <span>${escapeHtml(formatFixtureRelation(fixtureForm.expectedRelation))}</span>
          <span>${fixtureForm.durationMs}ms</span>
          <span>${escapeHtml(fixtureForm.captureDevice)}</span>
        </div>
      </div>
      <div class="fixture-grid">
        <label>
          <span>Speaker</span>
          <input id="fixture-speaker-label" value="${escapeHtml(fixtureForm.speakerLabel)}" />
        </label>
        <label>
          <span>Phrase</span>
          <input id="fixture-phrase-label" value="${escapeHtml(fixtureForm.phraseLabel)}" />
        </label>
        <label>
          <span>Relation</span>
          <select id="fixture-relation">
            ${VOICE_ID_FIXTURE_EXPECTED_RELATIONS.map(
              (relation) =>
                `<option value="${relation}" ${
                  fixtureForm.expectedRelation === relation ? 'selected' : ''
                }>${escapeHtml(formatFixtureRelation(relation))}</option>`,
            ).join('')}
          </select>
        </label>
        <label>
          <span>Device</span>
          <input id="fixture-capture-device" value="${escapeHtml(fixtureForm.captureDevice)}" />
        </label>
        <label>
          <span>Duration ms</span>
          <input id="fixture-duration-ms" type="number" min="400" max="10000" step="100" value="${fixtureForm.durationMs}" />
        </label>
        <label class="wide">
          <span>Notes</span>
          <textarea id="fixture-environment-notes" rows="2">${escapeHtml(fixtureForm.environmentNotes)}</textarea>
        </label>
      </div>
      <div class="actions fixture-actions">
        <button id="capture-fixture" ${disabledAttribute(!canCaptureFixture)}>Record fixture</button>
        <button id="save-fixture-set" ${disabledAttribute(!canSaveFixtures)}>Save set</button>
        <button id="download-fixture-manifest" class="secondary" ${disabledAttribute(!canSaveFixtures)}>Manifest</button>
        <button id="download-fixture-audio-all" class="secondary" ${disabledAttribute(!canSaveFixtures)}>Audio files</button>
        <button id="clear-fixtures" class="secondary" ${disabledAttribute(!canSaveFixtures)}>Clear</button>
      </div>
      <div class="fixture-status" aria-live="polite">${escapeHtml(fixtureCaptureMessage)}</div>
      <ol class="fixture-list">
        ${capturedFixtures.map(renderCapturedFixtureRow).join('')}
      </ol>
    </section>
  `;
}

function renderCapturedFixtureRow(capturedFixture: CapturedFixtureView, index: number): string {
  const fixture = capturedFixture.fixture;
  return `
    <li>
      <div class="fixture-row-main">
        <span class="relation-pill">${escapeHtml(formatFixtureRelation(fixture.entry.expectedRelation))}</span>
        <strong>${escapeHtml(fixture.entry.audioFileName)}</strong>
        <span>${escapeHtml(fixture.entry.speakerLabel)} · ${fixture.entry.durationMs}ms · ${formatBytes(fixture.entry.byteLength)} · ${escapeHtml(fixture.entry.captureDevice)}</span>
        <audio controls preload="metadata" src="${escapeHtml(capturedFixture.previewUrl)}"></audio>
      </div>
      <div class="fixture-row-actions">
        <button data-download-fixture="${index}">Download</button>
        <button class="secondary" data-remove-fixture="${index}">Remove</button>
      </div>
    </li>
  `;
}

function bindFixtureCaptureControls(): void {
  bindTextInput('fixture-speaker-label', (value) => {
    fixtureForm = { ...fixtureForm, speakerLabel: normalizeFixtureText(value, 'owner') };
  });
  bindTextInput('fixture-phrase-label', (value) => {
    fixtureForm = { ...fixtureForm, phraseLabel: normalizeFixtureText(value, phrase) };
  });
  bindTextInput('fixture-capture-device', (value) => {
    fixtureForm = {
      ...fixtureForm,
      captureDevice: normalizeFixtureText(value, 'browser microphone'),
    };
  });
  bindTextInput('fixture-environment-notes', (value) => {
    fixtureForm = { ...fixtureForm, environmentNotes: normalizeFixtureText(value, 'unspecified') };
  });

  const relation = document.querySelector<HTMLSelectElement>('#fixture-relation');
  relation?.addEventListener('change', () => {
    fixtureForm = {
      ...fixtureForm,
      expectedRelation: parseFixtureRelationSelection(relation.value),
    };
  });

  const duration = document.querySelector<HTMLInputElement>('#fixture-duration-ms');
  duration?.addEventListener('input', () => {
    fixtureForm = {
      ...fixtureForm,
      durationMs: normalizeFixtureDurationMs(duration.value),
    };
  });

  document.querySelector('#capture-fixture')?.addEventListener('click', captureFixture);
  document.querySelector('#save-fixture-set')?.addEventListener('click', saveFixtureSet);
  document.querySelector('#download-fixture-manifest')?.addEventListener('click', downloadManifest);
  document.querySelector('#download-fixture-audio-all')?.addEventListener('click', downloadAllAudio);
  document.querySelector('#clear-fixtures')?.addEventListener('click', clearFixtures);
  document.querySelectorAll<HTMLButtonElement>('[data-download-fixture]').forEach((button) => {
    button.addEventListener('click', () => {
      const index = Number(button.dataset.downloadFixture);
      const fixture = capturedFixtures[index];
      if (fixture) downloadVoiceIdFixtureAudio(fixture.fixture);
    });
  });
  document.querySelectorAll<HTMLButtonElement>('[data-remove-fixture]').forEach((button) => {
    button.addEventListener('click', () => {
      const index = Number(button.dataset.removeFixture);
      removeCapturedFixture(index);
    });
  });
}

function bindTextInput(elementId: string, update: (value: string) => void): void {
  const input = document.querySelector<HTMLInputElement | HTMLTextAreaElement>(`#${elementId}`);
  input?.addEventListener('input', () => update(input.value));
}

async function startEnrollment(): Promise<void> {
  const response = parseEnvelope(await client.startEnrollment({ userId, phrase }));
  if (response.kind === 'error') {
    setError(response.error.message);
    return;
  }

  const value = response.value as { record: { enrollmentId: string; acceptedSampleCount: number } };
  enrollmentAttempts = 0;
  resetDiagnostics();
  state = {
    kind: 'enrolling',
    enrollmentId: value.record.enrollmentId,
    acceptedSampleCount: value.record.acceptedSampleCount,
    message: 'Enrollment ready',
  };
  render();
}

async function recordEnrollmentSample(): Promise<void> {
  if (state.kind !== 'enrolling') {
    setError('Start enrollment first');
    return;
  }

  activeRecording = {
    kind: 'enrollment',
    title: 'Recording enrollment sample',
    detail: `Sample ${state.acceptedSampleCount + 1} of 3`,
    durationMs: 1800,
  };
  state = { ...state, message: 'Recording enrollment sample' };
  render();

  const recorded = await recorder.recordClip({
    durationMs: 1800,
    timeoutMs: 3000,
    fixtureSpeakerLabel: 'owner',
  });
  activeRecording = { kind: 'none' };
  if (recorded.kind !== 'recorded') {
    setError(recorded.kind === 'error' ? formatRecorderError(recorded.reason) : 'recording did not finish');
    return;
  }

  enrollmentAttempts += 1;
  const response = parseEnvelope(
    await client.uploadEnrollmentSample({
      blob: recorded.blob,
      metadata: recorder.buildMetadata({ fixtureSpeakerLabel: 'owner' }),
      userId,
      enrollmentId: state.enrollmentId,
      expectedPhrase: phrase,
      spokenPhrase: phrase,
      attemptNumber: enrollmentAttempts,
    }),
  );
  if (response.kind === 'error') {
    setError(response.error.message);
    return;
  }

  const value = response.value as {
    acceptedSampleCount: number;
    quality: VerificationChecks['quality'];
  };
  diagnostics = {
    ...diagnostics,
    quality: formatQuality(value.quality),
    finalResult: `enrollment samples accepted: ${value.acceptedSampleCount}`,
  };
  state = {
    ...state,
    acceptedSampleCount: value.acceptedSampleCount,
    message: `Accepted ${value.acceptedSampleCount} of 3 enrollment samples`,
  };
  render();
}

async function finalizeEnrollment(): Promise<void> {
  if (state.kind !== 'enrolling') {
    setError('Record enrollment samples first');
    return;
  }

  const response = parseEnvelope(
    await client.finalizeEnrollment({
      userId,
      enrollmentId: state.enrollmentId,
    }),
  );
  if (response.kind === 'error') {
    setError(response.error.message);
    return;
  }

  state = {
    kind: 'enrolled',
    enrollmentId: state.enrollmentId,
    message: 'Enrollment finalized',
  };
  render();
}

async function startVerification(): Promise<void> {
  const enrollmentId = getVerificationEnrollmentId(state);
  if (enrollmentId === null) {
    setError('Finalize enrollment first');
    return;
  }

  const binding = await buildVoiceIdSpokenIntentBinding({
    spokenCommand: demoSpokenIntentCommand,
    expiresAt: demoIntentExpiresAt(),
    nonce: demoIntentNonce,
  });
  const response = parseEnvelope(
    await client.startVerification({
      userId,
      enrollmentId,
      phrase: binding.spokenCommand,
      intentDigest: binding.intentDigest,
      intentExpiresAt: binding.intent.expiresAt,
      intentNonce: binding.intent.nonce,
    }),
  );
  if (response.kind === 'error') {
    setError(response.error.message);
    return;
  }

  const value = response.value as { record: { verificationId: string } };
  verificationAttempts = 0;
  diagnostics = {
    ...diagnostics,
    finalResult: 'verification ready',
  };
  state = {
    kind: 'verifying',
    enrollmentId,
    verificationId: value.record.verificationId,
    phrase: binding.spokenCommand,
    intentDigest: binding.intentDigest,
    message: 'Verification ready',
  };
  render();
}

async function recordVerificationSample(): Promise<void> {
  if (state.kind !== 'verifying') {
    setError('Start verification first');
    return;
  }

  activeRecording = {
    kind: 'verification',
    title: 'Recording verification sample',
    detail: state.phrase,
    durationMs: 1800,
  };
  state = { ...state, message: 'Recording verification sample' };
  render();

  const recorded = await recorder.recordClip({
    durationMs: 1800,
    timeoutMs: 3000,
    fixtureSpeakerLabel: 'owner',
  });
  activeRecording = { kind: 'none' };
  if (recorded.kind !== 'recorded') {
    setError(recorded.kind === 'error' ? formatRecorderError(recorded.reason) : 'recording did not finish');
    return;
  }

  verificationAttempts += 1;
  const response = parseEnvelope(
    await client.uploadVerificationSample({
      blob: recorded.blob,
      metadata: recorder.buildMetadata({ fixtureSpeakerLabel: 'owner' }),
      userId,
      enrollmentId: state.enrollmentId,
      verificationId: state.verificationId,
      expectedPhrase: state.phrase,
      spokenPhrase: state.phrase,
      attemptNumber: verificationAttempts,
    }),
  );
  if (response.kind === 'error') {
    setError(response.error.message);
    return;
  }

  const value = response.value as VerificationApiResult;
  const enrollmentId = state.enrollmentId;
  const verificationId = state.verificationId;
  const intentDigest = state.intentDigest;
  diagnostics = {
    quality: formatQuality(value.checks.quality),
    phrase: formatPhrase(value.checks.phrase),
    speaker: formatSpeaker(value.checks.speaker),
    finalResult: value.kind,
  };
  if (value.kind === 'accepted') {
    const authorization = parseEnvelope(
      await client.authorizeOwnerPresence({
        verificationId,
        intentDigest,
        useCase: 'wallet_mpc_signing',
        policyVersion: 'voiceid-wallet-policy-v1',
        audio: demoAudioLivenessSignals(),
        context: demoLocalDeviceContext(),
        policy: demoBrowserLivenessPolicy(),
      }),
    );
    if (authorization.kind === 'error') {
      setError(authorization.error.message);
      return;
    }
    const authorizationValue = authorization.value as { decision: { kind: string } };
    diagnostics = {
      ...diagnostics,
      finalResult: `verification accepted; policy ${authorizationValue.decision.kind}`,
    };
    state = { kind: 'accepted', enrollmentId, message: 'VoiceID accepted' };
  } else if (value.kind === 'rejected') {
    state = { kind: 'rejected', enrollmentId, reason: value.reason ?? 'rejected', message: 'VoiceID rejected' };
  } else {
    state = { kind: 'uncertain', enrollmentId, reason: value.reason ?? 'uncertain', message: 'VoiceID uncertain' };
  }
  render();
}

function demoIntentExpiresAt(): string {
  return new Date(Date.now() + 5 * 60 * 1000).toISOString();
}

function demoAudioLivenessSignals(): VoiceIdAudioLivenessSignals {
  const base = Date.now();
  return {
    kind: 'audio_liveness_signals_v1',
    promptOpenedAt: nowIsoDateTime(new Date(base - 2000)),
    speechStartedAt: nowIsoDateTime(new Date(base - 1400)),
    speechEndedAt: nowIsoDateTime(new Date(base - 100)),
    captureSource: {
      kind: 'unknown_microphone',
      reason: 'browser_device_label_unavailable',
    },
    replayRisk: { kind: 'low' },
  };
}

function demoLocalDeviceContext(): VoiceIdLocalDeviceContext {
  return {
    kind: 'local_device_context_v1',
    deviceId: 'browser-demo',
    sidecarId: 'browser-demo',
    captureStartedAt: nowIsoDateTime(new Date(Date.now() - 2500)),
    evaluatedAt: nowIsoDateTime(),
    localPolicyVersion: 'browser-mvp-policy-v1',
  };
}

function demoBrowserLivenessPolicy(): VoiceIdAudioLivenessPolicy {
  return {
    kind: 'audio_liveness_policy_v1',
    minSpeechDurationMs: 500,
    maxSpeechDurationMs: 5000,
    maxPromptToSpeechStartMs: 3000,
    requireTrustedMicrophone: false,
  };
}

async function captureFixture(): Promise<void> {
  readFixtureFormFromDom();
  activeRecording = {
    kind: 'fixture',
    title: 'Recording fixture',
    detail: `${formatFixtureRelation(fixtureForm.expectedRelation)} · ${fixtureForm.phraseLabel}`,
    durationMs: fixtureForm.durationMs,
  };
  fixtureCaptureMessage = 'Recording fixture';
  render();

  const recorded = await recorder.recordClip({
    durationMs: fixtureForm.durationMs,
    timeoutMs: fixtureForm.durationMs + 1500,
    fixtureSpeakerLabel: fixtureForm.speakerLabel,
  });
  activeRecording = { kind: 'none' };
  if (recorded.kind !== 'recorded') {
    fixtureCaptureMessage =
      recorded.kind === 'error'
        ? `Fixture recording failed: ${formatRecorderError(recorded.reason)}`
        : 'Fixture recording did not finish';
    render();
    return;
  }

  const metadata = recorder.buildMetadata({ fixtureSpeakerLabel: fixtureForm.speakerLabel });
  const fixture = createCapturedVoiceIdFixture({
    blob: recorded.blob,
    metadata,
    speakerLabel: fixtureForm.speakerLabel,
    phraseLabel: fixtureForm.phraseLabel,
    expectedRelation: fixtureForm.expectedRelation,
    captureDevice: fixtureForm.captureDevice,
    environmentNotes: fixtureForm.environmentNotes,
  });
  capturedFixtures = [
    ...capturedFixtures,
    {
      fixture,
      previewUrl: URL.createObjectURL(fixture.blob),
    },
  ];
  fixtureCaptureMessage = `Captured ${capturedFixtures.length} fixture${capturedFixtures.length === 1 ? '' : 's'}`;
  render();
}

function downloadManifest(): void {
  if (capturedFixtures.length === 0) return;
  const manifest = buildFixtureManifest();
  downloadVoiceIdFixtureManifest(manifest);
  fixtureCaptureMessage = `Manifest exported with ${manifest.entries.length} fixture${manifest.entries.length === 1 ? '' : 's'}`;
  render();
}

function downloadAllAudio(): void {
  if (capturedFixtures.length === 0) return;
  for (const capturedFixture of capturedFixtures) {
    downloadVoiceIdFixtureAudio(capturedFixture.fixture);
  }
  fixtureCaptureMessage = `Queued ${capturedFixtures.length} audio download${capturedFixtures.length === 1 ? '' : 's'}`;
  render();
}

async function saveFixtureSet(): Promise<void> {
  if (capturedFixtures.length === 0 || isSavingFixtureSet) return;
  const directoryPicker = (window as DirectoryPickerWindow).showDirectoryPicker;
  if (typeof directoryPicker !== 'function') {
    queueFixtureSetDownloads();
    fixtureCaptureMessage = `Folder save is unavailable; queued ${capturedFixtures.length} audio file${capturedFixtures.length === 1 ? '' : 's'} and the manifest`;
    render();
    return;
  }

  isSavingFixtureSet = true;
  fixtureCaptureMessage = 'Choose a folder for the fixture set';
  render();

  try {
    const directory = await directoryPicker.call(window);
    await writeFixtureFile(
      directory,
      'voiceid-fixture-manifest.json',
      new Blob([JSON.stringify(buildFixtureManifest(), null, 2)], { type: 'application/json' }),
    );
    for (const capturedFixture of capturedFixtures) {
      await writeFixtureFile(
        directory,
        capturedFixture.fixture.entry.audioFileName,
        capturedFixture.fixture.blob,
      );
    }
    fixtureCaptureMessage = `Saved ${capturedFixtures.length} fixture${capturedFixtures.length === 1 ? '' : 's'} and manifest`;
  } catch (error) {
    fixtureCaptureMessage =
      error instanceof DOMException && error.name === 'AbortError'
        ? 'Save canceled'
        : `Save failed: ${error instanceof Error ? error.message : 'unknown error'}`;
  } finally {
    isSavingFixtureSet = false;
    render();
  }
}

function clearFixtures(): void {
  for (const capturedFixture of capturedFixtures) {
    URL.revokeObjectURL(capturedFixture.previewUrl);
  }
  capturedFixtures = [];
  fixtureCaptureMessage = 'No fixtures captured';
  render();
}

function removeCapturedFixture(index: number): void {
  const capturedFixture = capturedFixtures[index];
  if (capturedFixture === undefined) return;
  URL.revokeObjectURL(capturedFixture.previewUrl);
  capturedFixtures = capturedFixtures.filter((_, fixtureIndex) => fixtureIndex !== index);
  fixtureCaptureMessage = `Removed fixture ${index + 1}`;
  render();
}

function queueFixtureSetDownloads(): void {
  const manifest = buildFixtureManifest();
  downloadVoiceIdFixtureManifest(manifest);
  for (const capturedFixture of capturedFixtures) {
    downloadVoiceIdFixtureAudio(capturedFixture.fixture);
  }
}

function buildFixtureManifest() {
  return buildManifestFromCapturedVoiceIdFixtures({
    fixtures: capturedFixtures.map((capturedFixture) => capturedFixture.fixture),
  });
}

async function writeFixtureFile(
  directory: BrowserDirectoryHandle,
  fileName: string,
  blob: Blob,
): Promise<void> {
  const fileHandle = await directory.getFileHandle(fileName, { create: true });
  const writable = await fileHandle.createWritable();
  await writable.write(blob);
  await writable.close();
}

function readFixtureFormFromDom(): void {
  const speakerLabel =
    document.querySelector<HTMLInputElement>('#fixture-speaker-label')?.value ?? fixtureForm.speakerLabel;
  const phraseLabel =
    document.querySelector<HTMLInputElement>('#fixture-phrase-label')?.value ?? fixtureForm.phraseLabel;
  const captureDevice =
    document.querySelector<HTMLInputElement>('#fixture-capture-device')?.value ??
    fixtureForm.captureDevice;
  const environmentNotes =
    document.querySelector<HTMLTextAreaElement>('#fixture-environment-notes')?.value ??
    fixtureForm.environmentNotes;
  const durationMs =
    document.querySelector<HTMLInputElement>('#fixture-duration-ms')?.value ??
    String(fixtureForm.durationMs);
  const expectedRelation =
    document.querySelector<HTMLSelectElement>('#fixture-relation')?.value ??
    fixtureForm.expectedRelation;

  fixtureForm = {
    speakerLabel: normalizeFixtureText(speakerLabel, 'owner'),
    phraseLabel: normalizeFixtureText(phraseLabel, phrase),
    expectedRelation: parseFixtureRelationSelection(expectedRelation),
    captureDevice: normalizeFixtureText(captureDevice, 'browser microphone'),
    durationMs: normalizeFixtureDurationMs(durationMs),
    environmentNotes: normalizeFixtureText(environmentNotes, 'unspecified'),
  };
}

function parseEnvelope(value: unknown): ApiEnvelope {
  return value as ApiEnvelope;
}

function setError(message: string): void {
  state = { kind: 'error', message };
  render();
}

function resetDiagnostics(): void {
  diagnostics = {
    quality: 'none',
    phrase: 'none',
    speaker: 'none',
    finalResult: 'none',
  };
}

function renderRecordingBanner(): string {
  if (activeRecording.kind === 'none') return '';
  return `
    <div class="recording-banner" role="status" aria-live="polite">
      <div>
        <span class="recording-dot"></span>
        <strong>${escapeHtml(activeRecording.title)}</strong>
        <span>${escapeHtml(activeRecording.detail)}</span>
      </div>
      <div class="recording-progress" style="--recording-duration-ms: ${activeRecording.durationMs}ms">
        <span></span>
      </div>
    </div>
  `;
}

function renderSampleDots(acceptedSampleCount: number): string {
  return Array.from({ length: 3 }, (_, index) => {
    const filled = index < acceptedSampleCount;
    return `<i class="${filled ? 'filled' : ''}" aria-hidden="true"></i>`;
  }).join('');
}

function getEnrollmentSampleCount(currentState: DemoState): number {
  switch (currentState.kind) {
    case 'enrolling':
      return currentState.acceptedSampleCount;
    case 'enrolled':
    case 'verifying':
    case 'accepted':
    case 'rejected':
    case 'uncertain':
      return 3;
    case 'idle':
    case 'error':
      return 0;
  }
}

function getDemoControls(currentState: DemoState): {
  canStartEnrollment: boolean;
  canRecordEnrollment: boolean;
  canFinalizeEnrollment: boolean;
  canStartVerification: boolean;
  canRecordVerification: boolean;
} {
  const isBusy = activeRecording.kind !== 'none' || isSavingFixtureSet;
  return {
    canStartEnrollment: !isBusy,
    canRecordEnrollment: !isBusy && currentState.kind === 'enrolling',
    canFinalizeEnrollment:
      !isBusy && currentState.kind === 'enrolling' && currentState.acceptedSampleCount >= 3,
    canStartVerification: !isBusy && getVerificationEnrollmentId(currentState) !== null,
    canRecordVerification: !isBusy && currentState.kind === 'verifying',
  };
}

function getVerificationEnrollmentId(currentState: DemoState): string | null {
  switch (currentState.kind) {
    case 'enrolled':
    case 'accepted':
    case 'rejected':
    case 'uncertain':
      return currentState.enrollmentId;
    case 'idle':
    case 'enrolling':
    case 'verifying':
    case 'error':
      return null;
  }
}

function formatStateKind(kind: DemoState['kind']): string {
  switch (kind) {
    case 'idle':
      return 'Idle';
    case 'enrolling':
      return 'Enrolling';
    case 'enrolled':
      return 'Enrolled';
    case 'verifying':
      return 'Verifying';
    case 'accepted':
      return 'Accepted';
    case 'rejected':
      return 'Rejected';
    case 'uncertain':
      return 'Uncertain';
    case 'error':
      return 'Error';
  }
}

function disabledAttribute(disabled: boolean): string {
  return disabled ? 'disabled aria-disabled="true"' : '';
}

function formatQuality(quality: VerificationChecks['quality']): string {
  if (quality.kind === 'accepted') {
    return `${quality.kind}; ${quality.durationMs}ms; signal ${formatNumber(quality.signalScore ?? 0)}`;
  }

  return `${quality.kind}; ${quality.reason ?? 'no reason'}; ${quality.durationMs}ms`;
}

function formatPhrase(phraseResult: VerificationChecks['phrase']): string {
  return `${phraseResult.kind}; ${phraseResult.spokenNormalized}; confidence ${formatNumber(phraseResult.confidence)}`;
}

function formatSpeaker(speaker: VerificationChecks['speaker']): string {
  return `${speaker.kind}; score ${formatNumber(speaker.score)} / threshold ${formatNumber(speaker.threshold)}`;
}

function formatRecorderError(reason: string): string {
  if (reason === 'empty_recording') {
    return 'no audio frames captured; use a stable microphone and start speaking after recording begins';
  }
  return reason;
}

function formatNumber(value: number): string {
  return value.toFixed(2);
}

function formatBytes(byteLength: number): string {
  if (byteLength < 1024) return `${byteLength} B`;
  const kibibytes = byteLength / 1024;
  if (kibibytes < 1024) return `${kibibytes.toFixed(1)} KB`;
  return `${(kibibytes / 1024).toFixed(1)} MB`;
}

function formatFixtureRelation(relation: VoiceIdFixtureExpectedRelation): string {
  switch (relation) {
    case 'owner_enrollment':
      return 'Owner enrollment';
    case 'owner_verification':
      return 'Owner verification';
    case 'different_speaker':
      return 'Different speaker';
    case 'wrong_phrase':
      return 'Wrong phrase';
    case 'noisy':
      return 'Noisy';
    case 'too_short':
      return 'Too short';
  }
}

function parseFixtureRelationSelection(value: string): VoiceIdFixtureExpectedRelation {
  if (
    VOICE_ID_FIXTURE_EXPECTED_RELATIONS.includes(value as VoiceIdFixtureExpectedRelation)
  ) {
    return value as VoiceIdFixtureExpectedRelation;
  }
  return 'owner_enrollment';
}

function normalizeFixtureText(value: string, fallback: string): string {
  const normalized = value.trim();
  return normalized.length > 0 ? normalized : fallback;
}

function normalizeFixtureDurationMs(value: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fixtureForm.durationMs;
  return Math.min(10_000, Math.max(400, Math.round(parsed)));
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const style = document.createElement('style');
style.textContent = `
  :root {
    color-scheme: light;
    --bg: #f4f6f5;
    --surface: #ffffff;
    --surface-muted: #eef4f1;
    --ink: #162027;
    --muted: #586875;
    --line: #d7e0df;
    --line-strong: #b8c7c4;
    --primary: #163832;
    --primary-hover: #102b27;
    --accent: #1c7c72;
    --accent-soft: #dcefeb;
    --warning: #a85f00;
    --danger: #a33a2f;
  }

  body {
    margin: 0;
    font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: var(--bg);
    color: var(--ink);
  }

  .shell {
    max-width: 980px;
    margin: 0 auto;
    padding: 36px 20px 48px;
  }

  h1 {
    margin: 0 0 8px;
    font-size: 36px;
    line-height: 1.05;
    letter-spacing: 0;
  }

  p {
    margin: 0;
    color: var(--muted);
  }

  .panel {
    border: 1px solid var(--line);
    border-radius: 8px;
    background: var(--surface);
    padding: 22px;
    box-shadow: 0 1px 2px rgb(22 32 39 / 4%);
  }

  .voice-panel {
    margin-top: 24px;
  }

  .fixture-panel {
    margin-top: 16px;
  }

  .voice-layout {
    display: grid;
    grid-template-columns: minmax(240px, 0.85fr) minmax(0, 1.15fr);
    gap: 24px;
    align-items: start;
  }

  .prompt-block {
    display: grid;
    gap: 12px;
    align-content: start;
  }

  .eyebrow {
    color: var(--muted);
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .prompt-text {
    border: 1px solid var(--line-strong);
    border-radius: 8px;
    background: var(--surface-muted);
    padding: 18px;
    color: var(--ink);
    font-size: 30px;
    font-weight: 750;
    line-height: 1.15;
    overflow-wrap: anywhere;
  }

  .sample-progress {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    color: var(--muted);
    font-size: 13px;
  }

  .sample-progress i {
    width: 22px;
    height: 8px;
    border-radius: 999px;
    background: #d5ddda;
  }

  .sample-progress i.filled {
    background: var(--accent);
  }

  .status-grid {
    margin: 0;
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
  }

  .status-grid div {
    min-width: 0;
    border-bottom: 1px solid #ecf0ef;
    padding-bottom: 10px;
  }

  h2 {
    margin: 0 0 4px;
    font-size: 18px;
    line-height: 1.2;
  }

  .panel-heading {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 16px;
  }

  .count-pill,
  .relation-pill {
    display: inline-flex;
    align-items: center;
    min-height: 24px;
    border-radius: 999px;
    background: var(--accent-soft);
    color: #185a53;
    padding: 0 10px;
    font-size: 12px;
    font-weight: 700;
    white-space: nowrap;
  }

  dt {
    margin-bottom: 3px;
    color: var(--muted);
    font-size: 12px;
    font-weight: 650;
  }

  dd {
    margin: 0;
    font-weight: 700;
    overflow-wrap: anywhere;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
  }

  .action-groups {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
    margin-top: 20px;
  }

  .action-group {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 10px;
  }

  .action-group > span {
    flex: 1 0 100%;
    color: var(--muted);
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  .recording-banner {
    display: grid;
    gap: 10px;
    border: 1px solid #f0cc98;
    border-radius: 8px;
    background: #fff7ea;
    margin-top: 20px;
    padding: 12px;
    color: var(--warning);
  }

  .recording-banner > div:first-child {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
  }

  .recording-banner strong {
    color: var(--ink);
  }

  .recording-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--danger);
    box-shadow: 0 0 0 4px rgb(163 58 47 / 12%);
  }

  .recording-progress {
    height: 6px;
    overflow: hidden;
    border-radius: 999px;
    background: #eadcc9;
  }

  .recording-progress span {
    display: block;
    height: 100%;
    width: 100%;
    border-radius: inherit;
    background: var(--warning);
    transform-origin: left center;
    animation: recording-progress var(--recording-duration-ms) linear forwards;
  }

  @keyframes recording-progress {
    from {
      transform: scaleX(0);
    }

    to {
      transform: scaleX(1);
    }
  }

  .fixture-summary {
    display: grid;
    gap: 8px;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: var(--surface-muted);
    margin-bottom: 16px;
    padding: 14px;
  }

  .fixture-summary strong {
    font-size: 24px;
    line-height: 1.15;
    overflow-wrap: anywhere;
  }

  .fixture-summary-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .fixture-summary-meta span {
    border: 1px solid var(--line-strong);
    border-radius: 999px;
    background: #fff;
    color: var(--muted);
    padding: 4px 8px;
    font-size: 12px;
  }

  .fixture-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
    margin-bottom: 14px;
  }

  label {
    display: grid;
    gap: 6px;
    color: var(--muted);
    font-size: 13px;
    font-weight: 650;
  }

  label.wide {
    grid-column: 1 / -1;
  }

  input,
  select,
  textarea {
    width: 100%;
    box-sizing: border-box;
    border: 1px solid var(--line-strong);
    border-radius: 6px;
    background: #fff;
    color: var(--ink);
    min-height: 36px;
    padding: 7px 9px;
    font: inherit;
  }

  textarea {
    resize: vertical;
  }

  .fixture-status {
    margin: 12px 0 0;
    color: var(--muted);
    font-size: 13px;
  }

  .fixture-actions {
    margin-top: 4px;
  }

  .fixture-list {
    list-style: none;
    padding: 0;
    margin: 16px 0 0;
    display: grid;
    gap: 10px;
  }

  .fixture-list li {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: start;
    justify-content: space-between;
    gap: 12px;
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 12px;
  }

  .fixture-row-main {
    min-width: 0;
    display: grid;
    gap: 6px;
  }

  .fixture-list strong,
  .fixture-list span {
    display: block;
    overflow-wrap: anywhere;
  }

  .fixture-list span {
    color: var(--muted);
    font-size: 13px;
  }

  .fixture-list audio {
    width: 100%;
    max-width: 520px;
    min-height: 36px;
  }

  .fixture-row-actions {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: 8px;
  }

  button {
    border: 1px solid var(--primary);
    border-radius: 6px;
    background: var(--primary);
    color: #fff;
    min-height: 40px;
    padding: 0 14px;
    font: inherit;
    font-weight: 700;
    cursor: pointer;
  }

  button:hover:not(:disabled) {
    background: var(--primary-hover);
  }

  button.secondary {
    border-color: var(--line-strong);
    background: #fff;
    color: var(--primary);
  }

  button.secondary:hover:not(:disabled) {
    background: var(--surface-muted);
  }

  button:disabled {
    background: #d6dde2;
    border-color: #c4cdd4;
    color: #687783;
    cursor: not-allowed;
  }

  header p,
  .panel-heading p {
    margin-bottom: 0;
  }

  input:focus,
  select:focus,
  textarea:focus,
  button:focus-visible {
    outline: 3px solid rgb(28 124 114 / 22%);
    outline-offset: 2px;
  }

  input:disabled,
  select:disabled,
  textarea:disabled {
    background: #edf1f2;
    color: #66747f;
  }

  @media (max-width: 640px) {
    .shell {
      padding: 24px 14px 36px;
    }

    h1 {
      font-size: 30px;
    }

    .voice-layout,
    .action-groups,
    .status-grid {
      grid-template-columns: 1fr;
    }

    .prompt-text {
      font-size: 24px;
    }

    .panel-heading {
      align-items: stretch;
      flex-direction: column;
    }

    .fixture-grid {
      grid-template-columns: 1fr;
    }

    .fixture-list li {
      align-items: stretch;
      grid-template-columns: 1fr;
    }

    .fixture-row-actions {
      justify-content: stretch;
    }

    .fixture-row-actions button,
    .fixture-actions button,
    .action-group button {
      flex: 1 1 140px;
    }
  }
`;
document.head.append(style);
