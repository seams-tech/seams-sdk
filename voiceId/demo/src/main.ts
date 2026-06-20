import {
  VoiceIdClient,
  VoiceIdRecorder,
} from '../../client/src/index.ts';
import {
  buildVoiceIdSpokenIntentBinding,
  nowIsoDateTime,
  parseVoiceIdAudioMetadata,
  type VoiceIdAudioLivenessPolicy,
  type VoiceIdAudioLivenessSignals,
  type VoiceIdAudioMetadata,
  type VoiceIdLocalDeviceContext,
} from '../../shared/src/index.ts';

type ApiEnvelope =
  | {
      kind: 'ok';
      value: unknown;
    }
  | {
      kind: 'error';
      error: { kind: string; message: string };
    };

type DemoState =
  | {
      kind: 'idle';
      enrollmentId: null;
      acceptedSampleCount: 0;
      verificationId: null;
      intentDigest: null;
      message: string;
    }
  | {
      kind: 'enrolling';
      enrollmentId: string;
      acceptedSampleCount: number;
      verificationId: null;
      intentDigest: null;
      message: string;
    }
  | {
      kind: 'enrolled';
      enrollmentId: string;
      acceptedSampleCount: 3;
      verificationId: null;
      intentDigest: string | null;
      message: string;
    }
  | {
      kind: 'accepted';
      enrollmentId: string;
      acceptedSampleCount: 3;
      verificationId: string;
      intentDigest: string;
      message: string;
    }
  | {
      kind: 'rejected';
      enrollmentId: string;
      acceptedSampleCount: 3;
      verificationId: string;
      intentDigest: string;
      reason: string;
      message: string;
    }
  | {
      kind: 'uncertain';
      enrollmentId: string;
      acceptedSampleCount: 3;
      verificationId: string;
      intentDigest: string;
      reason: string;
      message: string;
    }
  | {
      kind: 'error';
      enrollmentId: string | null;
      acceptedSampleCount: number;
      verificationId: string | null;
      intentDigest: string | null;
      message: string;
    };

type ActiveRecording =
  | { kind: 'none' }
  | {
      kind: 'preparing';
      title: string;
      detail: string;
    }
  | {
      kind: 'recording';
      title: string;
      detail: string;
      durationMs: number;
    }
  | {
      kind: 'submitting';
      title: string;
      detail: string;
    };

type HoldRecordingTarget = 'enrollment' | 'verification';

type EnrollmentSampleNumber = 1 | 2 | 3;

type RecordedClip = {
  blob: Blob;
  metadata: VoiceIdAudioMetadata;
  url: string;
  label: string;
  durationMs: number;
  byteLength: number;
  recordedAt: string;
};

type PersistedEnrollmentSampleRecord = {
  sampleNumber: EnrollmentSampleNumber;
  userId: string;
  phrase: string;
  blob: Blob;
  metadata: VoiceIdAudioMetadata;
  label: string;
  durationMs: number;
  byteLength: number;
  recordedAt: string;
  savedAt: string;
};

type EnrollmentSamplePersistenceMode = 'persist' | 'memory_only';

type EnrollmentSampleSlot =
  | { kind: 'empty'; sampleNumber: EnrollmentSampleNumber }
  | { kind: 'recorded'; sampleNumber: EnrollmentSampleNumber; clip: RecordedClip };

type EnrollmentSampleSlots = [EnrollmentSampleSlot, EnrollmentSampleSlot, EnrollmentSampleSlot];

type RecordingContext =
  | {
      kind: 'enrollment';
      enrollmentId: string;
      acceptedSampleCount: number;
      sampleNumber: EnrollmentSampleNumber;
      title: string;
      detail: string;
      label: string;
    }
  | {
      kind: 'enrollment_rebuild';
      sampleNumber: EnrollmentSampleNumber;
      title: string;
      detail: string;
      label: string;
    }
  | {
      kind: 'verification';
      enrollmentId: string;
      verificationId: string;
      intentDigest: string;
      title: string;
      detail: string;
      label: string;
    };

type HoldRecordingSession =
  | { kind: 'none' }
  | {
      kind: 'preparing';
      releaseRequested: boolean;
    }
  | {
      kind: 'recording';
      context: RecordingContext;
      startedAtMs: number;
      minimumTimer: number;
      autoStopTimer: number;
      canSubmit: boolean;
      browserAsr: BrowserAsrSession;
      session: Exclude<Awaited<ReturnType<VoiceIdRecorder['startRecording']>>, { kind: 'error' }>;
    }
  | {
      kind: 'submitting';
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

type EnrollmentSampleUploadResult = {
  acceptedSampleCount: number;
  quality: VerificationChecks['quality'];
};

type Diagnostics = {
  quality: string;
  phrase: string;
  speaker: string;
  policy: string;
};

type TranscriptMode = 'browser' | 'server' | 'fake';

type BrowserAsrResult =
  | {
      kind: 'transcript';
      transcript: string;
      confidence: number;
    }
  | {
      kind: 'unavailable';
      reason: string;
    };

type BrowserAsrSession =
  | { kind: 'inactive'; reason: string }
  | { kind: 'failed'; reason: string }
  | {
      kind: 'listening';
      stop(): Promise<BrowserAsrResult>;
      cancel(): void;
    };

type VerificationTranscriptEvidence =
  | {
      kind: 'browser_asr';
      spokenPhrase: string;
      confidence: number;
    }
  | {
      kind: 'server_asr';
      spokenPhrase: string;
    }
  | {
      kind: 'simulated';
      spokenPhrase: string;
    };

type BrowserSpeechRecognitionConstructor = new () => BrowserSpeechRecognition;

type BrowserSpeechRecognition = {
  continuous: boolean;
  interimResults: boolean;
  lang: string;
  maxAlternatives: number;
  onresult: ((event: BrowserSpeechRecognitionEvent) => void) | null;
  onerror: ((event: BrowserSpeechRecognitionErrorEvent) => void) | null;
  onend: (() => void) | null;
  start(): void;
  stop(): void;
  abort(): void;
};

type BrowserSpeechRecognitionEvent = Event & {
  readonly resultIndex: number;
  readonly results: BrowserSpeechRecognitionResultList;
};

type BrowserSpeechRecognitionErrorEvent = Event & {
  readonly error?: string;
  readonly message?: string;
};

type BrowserSpeechRecognitionResultList = {
  readonly length: number;
  item(index: number): BrowserSpeechRecognitionResult;
  readonly [index: number]: BrowserSpeechRecognitionResult;
};

type BrowserSpeechRecognitionResult = {
  readonly isFinal: boolean;
  readonly length: number;
  item(index: number): BrowserSpeechRecognitionAlternative;
  readonly [index: number]: BrowserSpeechRecognitionAlternative;
};

type BrowserSpeechRecognitionAlternative = {
  readonly transcript: string;
  readonly confidence: number;
};

type BrowserSpeechRecognitionWindow = Window & {
  readonly SpeechRecognition?: BrowserSpeechRecognitionConstructor;
  readonly webkitSpeechRecognition?: BrowserSpeechRecognitionConstructor;
};

type VerificationCommandPresetId =
  | 'send_50_usdc_bob'
  | 'send_10_usdc_alice'
  | 'approve_swap';

type VerificationCommandPreset = {
  id: VerificationCommandPresetId;
  label: string;
  command: string;
};

type VerificationCommandSelection =
  | { kind: 'preset'; preset: VerificationCommandPreset }
  | { kind: 'custom' }
  | { kind: 'invalid' };

const userId = 'demo-owner';
const enrollmentPromptPhrase = 'voice enrollment sample';
const verificationCommandPresets: VerificationCommandPreset[] = [
  {
    id: 'send_50_usdc_bob',
    label: 'Send 50 USDC',
    command: 'send 50 USDC to bob',
  },
  {
    id: 'send_10_usdc_alice',
    label: 'Send 10 USDC',
    command: 'send 10 USDC to alice',
  },
  {
    id: 'approve_swap',
    label: 'Approve swap',
    command: 'approve swapping 100 USDC for ETH',
  },
];
const defaultVerificationCommand = verificationCommandPresets[0].command;
const enrollmentRequiredSampleCount = 3;
const minimumRecordingDurationMs = 900;
const maximumRecordingDurationMs = 5000;
const recordingTimeoutMs = maximumRecordingDurationMs + 1500;
const samplePersistenceDatabaseName = 'voiceid-demo-enrollment-samples';
const samplePersistenceDatabaseVersion = 1;
const samplePersistenceStoreName = 'samples';
const serverAsrSpokenPhrasePlaceholder = 'server asr pending';

const client = new VoiceIdClient({
  baseUrl: 'http://127.0.0.1:5052',
  fetch,
});
const recorder = new VoiceIdRecorder();

let state: DemoState = {
  kind: 'idle',
  enrollmentId: null,
  acceptedSampleCount: 0,
  verificationId: null,
  intentDigest: null,
  message: 'Ready',
};
let activeRecording: ActiveRecording = { kind: 'none' };
let enrollmentSamples: EnrollmentSampleSlots = buildEmptyEnrollmentSamples();
let selectedEnrollmentSampleNumber: EnrollmentSampleNumber = 1;
let selectedVerificationCommand = defaultVerificationCommand;
let transcriptMode: TranscriptMode = defaultTranscriptMode();
let simulatedSpokenPhrase = '';
let commandRecording: RecordedClip | null = null;
let holdRecording: HoldRecordingSession = { kind: 'none' };
let activeHoldTarget: HoldRecordingTarget | null = null;
let enrollmentAttempts = 0;
let verificationAttempts = 0;
let diagnostics: Diagnostics = {
  quality: 'none',
  phrase: 'none',
  speaker: 'none',
  policy: 'none',
};

const app = document.querySelector<HTMLElement>('#app');
if (!app) {
  throw new Error('missing app root');
}
const appRoot = app;

render();
void restorePersistedEnrollmentSamples();

function render(): void {
  appRoot.innerHTML = `
    <section class="shell">
      <header class="hero">
        <div>
          <span class="eyebrow">VoiceID MVP</span>
          <h1>Confirm by voice</h1>
          <p>Enroll this browser, then verify the transaction command.</p>
        </div>
        <span class="device-pill">browser-demo</span>
      </header>

      <section class="workflow-section enrollment-section">
        <div class="section-header">
          <div>
            <span class="eyebrow">Enrollment</span>
            <strong>Voice samples</strong>
          </div>
          <span class="section-status">${escapeHtml(enrollmentSectionStatus())}</span>
        </div>
        <div class="sample-cards" aria-label="Enrollment samples">
          ${renderSampleCards()}
        </div>
        ${renderHoldRail('enrollment')}
        <p class="rail-status">${escapeHtml(recordingStatusText('enrollment'))}</p>
      </section>

      <section class="workflow-section verification-section">
        <div class="section-header">
          <div>
            <span class="eyebrow">Verification</span>
            <strong>Transaction command</strong>
          </div>
          <span class="section-status">${escapeHtml(verificationSectionStatus())}</span>
        </div>
        <div class="command-card">
          <div class="command-controls">
            <label for="verification-command-preset">Command</label>
            <select
              id="verification-command-preset"
              ${disabledAttribute(!canEditVerificationCommand())}
            >
              ${renderVerificationCommandPresetOptions()}
            </select>
          </div>
          <div class="command-meta">
            <span class="eyebrow">Say this phrase</span>
            <span class="digest-chip">${escapeHtml(formatIntentDigest(state.intentDigest))}</span>
          </div>
          <textarea
            id="verification-command-input"
            class="command-input"
            rows="2"
            spellcheck="false"
            ${disabledAttribute(!canEditVerificationCommand())}
          >${escapeHtml(selectedVerificationCommand)}</textarea>
          ${renderTranscriptControls()}
        </div>
        ${renderHoldRail('verification')}
        <p class="rail-status">${escapeHtml(recordingStatusText('verification'))}</p>
        <dl class="status-grid">
          <div><dt>Quality</dt><dd>${escapeHtml(diagnostics.quality)}</dd></div>
          <div><dt>Phrase</dt><dd>${escapeHtml(diagnostics.phrase)}</dd></div>
          <div><dt>Speaker</dt><dd>${escapeHtml(diagnostics.speaker)}</dd></div>
          <div><dt>Policy</dt><dd>${escapeHtml(diagnostics.policy)}</dd></div>
        </dl>
      </section>
    </section>
  `;

  bindHoldButton('enrollment');
  bindHoldButton('verification');
  bindSampleSelectors();
  bindDeleteSampleButtons();
  bindVerificationCommandControls();
  bindTranscriptControls();
}

function renderWaveBars(): string {
  return Array.from({ length: 17 }, (_, index) => {
    const height = 16 + Math.round(Math.abs(Math.sin(index * 0.9)) * 36);
    return `<i style="--bar-height: ${height}px"></i>`;
  }).join('');
}

function renderVerificationCommandPresetOptions(): string {
  const selectedPreset = selectedVerificationCommandPresetId();
  const presetOptions = verificationCommandPresets
    .map((preset) => `
      <option
        value="${escapeHtml(preset.id)}"
        ${selectedPreset === preset.id ? 'selected' : ''}
      >
        ${escapeHtml(preset.label)}
      </option>
    `)
    .join('');
  return `${presetOptions}<option value="custom" ${selectedPreset === null ? 'selected' : ''}>Custom</option>`;
}

function renderTranscriptControls(): string {
  return `
    <div class="transcript-controls">
      <label for="transcript-mode">Phrase check</label>
      <select
        id="transcript-mode"
        ${disabledAttribute(!canEditVerificationCommand())}
      >
        ${renderTranscriptModeOptions()}
      </select>
      ${renderSimulatedPhraseInput()}
      <p>${escapeHtml(transcriptModeHelpText())}</p>
    </div>
  `;
}

function renderTranscriptModeOptions(): string {
  const browserDisabled = browserSpeechRecognitionConstructor() === null ? 'disabled' : '';
  return `
    <option value="browser" ${transcriptMode === 'browser' ? 'selected' : ''} ${browserDisabled}>
      Browser speech recognition
    </option>
    <option value="server" ${transcriptMode === 'server' ? 'selected' : ''}>
      Server ASR
    </option>
    <option value="fake" ${transcriptMode === 'fake' ? 'selected' : ''}>
      Simulated phrase
    </option>
  `;
}

function renderSimulatedPhraseInput(): string {
  if (transcriptMode !== 'fake') return '';
  return `
    <input
      id="simulated-spoken-phrase"
      class="simulated-phrase-input"
      type="text"
      placeholder="Type the simulated spoken phrase"
      value="${escapeHtml(simulatedSpokenPhrase)}"
      ${disabledAttribute(!canEditVerificationCommand())}
    />
  `;
}

function transcriptModeHelpText(): string {
  switch (transcriptMode) {
    case 'browser':
      return browserSpeechRecognitionConstructor() === null
        ? 'Browser speech recognition is unavailable in this browser.'
        : 'Browser speech recognition transcribes the live microphone while recording.';
    case 'server':
      return 'Server ASR sends the audio to the VoiceID API. Configure Cloudflare Workers AI for real Whisper transcription.';
    case 'fake':
      return 'Simulated mode uses the typed phrase below. It does not read the microphone transcript.';
  }
}

function selectedVerificationCommandPresetId(): VerificationCommandPresetId | null {
  const preset = verificationCommandPresets.find(
    (candidate) => candidate.command === selectedVerificationCommand,
  );
  return preset?.id ?? null;
}

function recordingLimitLabel(): string {
  const seconds = Math.ceil(maximumRecordingDurationMs / 1000);
  return `00:${seconds.toString().padStart(2, '0')}`;
}

function renderHoldRail(target: HoldRecordingTarget): string {
  return `
    <div class="voice-rail ${escapeHtml(target)}-rail ${escapeHtml(holdRailStateClass(target))}" aria-live="polite">
      <div class="voice-card-status">
        <span class="voice-card-timer">${escapeHtml(recordingLimitLabel())}</span>
      </div>
      <div class="voice-orb" aria-hidden="true">
        <span></span>
      </div>
      <div class="voice-card-copy">
        <strong>VoiceID</strong>
        <span>${escapeHtml(voiceCardSubtitle(target))}</span>
        ${renderVoiceCardProgress(target)}
      </div>
      <div class="voice-control-strip">
        <div class="wave-strip" aria-hidden="true">
          ${renderWaveBars()}
        </div>
        <button
          id="${escapeHtml(holdButtonId(target))}"
          class="record-button"
          ${disabledAttribute(!canRecordForTarget(target))}
        >
          <span class="record-dot" aria-hidden="true"></span>
          <span>${escapeHtml(recordButtonLabel(target))}</span>
          <small>${escapeHtml(recordButtonHint(target))}</small>
        </button>
      </div>
      ${renderRecordingProgress(target)}
    </div>
  `;
}

function renderVoiceCardProgress(target: HoldRecordingTarget): string {
  switch (target) {
    case 'enrollment':
      return `
        <span class="voice-card-progress">
          ${displayedEnrollmentSampleCount()} / ${enrollmentRequiredSampleCount} samples
        </span>
      `;
    case 'verification':
      return '';
  }
}

function voiceCardSubtitle(target: HoldRecordingTarget): string {
  if (activeHoldTarget === target && activeRecording.kind !== 'none') {
    return activeRecording.detail;
  }

  switch (target) {
    case 'enrollment':
      return `Enrollment sample ${selectedEnrollmentSampleNumber}`;
    case 'verification':
      return 'Transaction confirmation';
  }
}

function holdRailStateClass(target: HoldRecordingTarget): string {
  if (activeHoldTarget === target && activeRecording.kind === 'recording') return 'recording-active';
  return 'recording-idle';
}

function holdButtonId(target: HoldRecordingTarget): string {
  switch (target) {
    case 'enrollment':
      return 'record-enrollment';
    case 'verification':
      return 'record-verification';
  }
}

function bindHoldButton(target: HoldRecordingTarget): void {
  const button = document.querySelector<HTMLButtonElement>(`#${holdButtonId(target)}`);
  if (!button) return;

  button.addEventListener('pointerdown', (event) => {
    if (event.button !== 0 || !canRecordForTarget(target)) return;
    event.preventDefault();
    button.setPointerCapture(event.pointerId);
    const finish = (): void => {
      void finishHoldRecording();
    };
    const cancel = (): void => {
      void cancelHoldRecording();
    };
    window.addEventListener('pointerup', finish, { once: true });
    window.addEventListener('pointercancel', cancel, { once: true });
    beginHoldRecording(target);
  });
  button.addEventListener('pointerup', (event) => {
    event.preventDefault();
    void finishHoldRecording();
  });
  button.addEventListener('pointercancel', (event) => {
    event.preventDefault();
    void cancelHoldRecording();
  });
  button.addEventListener('keydown', (event) => {
    if ((event.key !== ' ' && event.key !== 'Enter') || !canRecordForTarget(target)) return;
    if (holdRecording.kind !== 'none') return;
    event.preventDefault();
    beginHoldRecording(target);
  });
  button.addEventListener('keyup', (event) => {
    if (event.key !== ' ' && event.key !== 'Enter') return;
    event.preventDefault();
    void finishHoldRecording();
  });
  button.addEventListener('click', (event) => {
    event.preventDefault();
  });
}

function bindSampleSelectors(): void {
  document.querySelectorAll<HTMLButtonElement>('[data-sample-number]').forEach((button) => {
    button.addEventListener('click', () => {
      const sampleNumber = parseEnrollmentSampleNumber(button.dataset.sampleNumber ?? null);
      if (sampleNumber === null) return;
      selectedEnrollmentSampleNumber = sampleNumber;
      render();
    });
  });
}

function bindDeleteSampleButtons(): void {
  document.querySelectorAll<HTMLButtonElement>('[data-delete-sample-number]').forEach((button) => {
    button.addEventListener('click', () => {
      const sampleNumber = parseEnrollmentSampleNumber(button.dataset.deleteSampleNumber ?? null);
      if (sampleNumber === null) return;
      deleteEnrollmentSample(sampleNumber);
    });
  });
}

function bindVerificationCommandControls(): void {
  const presetSelect = document.querySelector<HTMLSelectElement>('#verification-command-preset');
  presetSelect?.addEventListener('change', () => {
    const selection = parseVerificationCommandSelection(presetSelect.value);
    switch (selection.kind) {
      case 'preset':
        updateVerificationCommand(selection.preset.command);
        return;
      case 'custom':
        focusVerificationCommandInput();
        return;
      case 'invalid':
        presetSelect.value = selectedVerificationCommandPresetId() ?? 'custom';
        return;
    }
  });

  const commandInput = document.querySelector<HTMLTextAreaElement>('#verification-command-input');
  commandInput?.addEventListener('change', () => {
    const command = normalizeVerificationCommandInput(commandInput.value);
    if (command === null) {
      commandInput.value = selectedVerificationCommand;
      return;
    }
    updateVerificationCommand(command);
  });
  commandInput?.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    commandInput.dispatchEvent(new Event('change', { bubbles: true }));
    commandInput.blur();
  });
}

function bindTranscriptControls(): void {
  const modeSelect = document.querySelector<HTMLSelectElement>('#transcript-mode');
  modeSelect?.addEventListener('change', () => {
    const parsed = parseTranscriptMode(modeSelect.value);
    if (parsed === null) {
      modeSelect.value = transcriptMode;
      return;
    }
    transcriptMode = parsed;
    resetVerificationForCommandChange();
    render();
  });

  const simulatedInput = document.querySelector<HTMLInputElement>('#simulated-spoken-phrase');
  simulatedInput?.addEventListener('input', () => {
    const previousOutcome = state.kind;
    const changed = updateSimulatedSpokenPhrase(simulatedInput.value);
    if (!changed) return;

    resetVerificationForCommandChange();
    switch (previousOutcome) {
      case 'accepted':
      case 'rejected':
      case 'uncertain':
      case 'error':
        render();
        return;
      case 'idle':
      case 'enrolling':
      case 'enrolled':
        updateHoldButton('verification');
        return;
    }
  });
  simulatedInput?.addEventListener('change', () => {
    const changed = updateSimulatedSpokenPhrase(simulatedInput.value);
    if (changed) {
      resetVerificationForCommandChange();
      render();
    }
  });
  simulatedInput?.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    simulatedInput.dispatchEvent(new Event('change', { bubbles: true }));
    simulatedInput.blur();
  });
}

function parseVerificationCommandSelection(value: string): VerificationCommandSelection {
  if (value === 'custom') return { kind: 'custom' };
  const preset = verificationCommandPresets.find((candidate) => candidate.id === value);
  if (preset !== undefined) return { kind: 'preset', preset };
  return { kind: 'invalid' };
}

function parseTranscriptMode(value: string): TranscriptMode | null {
  switch (value) {
    case 'browser':
      return 'browser';
    case 'server':
      return 'server';
    case 'fake':
      return 'fake';
    default:
      return null;
  }
}

function defaultTranscriptMode(): TranscriptMode {
  return browserSpeechRecognitionConstructor() === null ? 'fake' : 'browser';
}

function focusVerificationCommandInput(): void {
  document.querySelector<HTMLTextAreaElement>('#verification-command-input')?.focus();
}

function updateSimulatedSpokenPhrase(value: string): boolean {
  const normalized = value.trim().replace(/\s+/g, ' ');
  if (normalized === simulatedSpokenPhrase) return false;
  simulatedSpokenPhrase = normalized;
  return true;
}

function updateHoldButton(target: HoldRecordingTarget): void {
  const button = document.querySelector<HTMLButtonElement>(`#${holdButtonId(target)}`);
  if (!button) return;

  button.disabled = !canRecordForTarget(target);
  const label = button.querySelector<HTMLSpanElement>('span:not(.record-dot)');
  const hint = button.querySelector<HTMLElement>('small');
  if (label) label.textContent = recordButtonLabel(target);
  if (hint) hint.textContent = recordButtonHint(target);
}

function normalizeVerificationCommandInput(value: string): string | null {
  const normalized = value.trim().replace(/\s+/g, ' ');
  return normalized.length > 0 ? normalized : null;
}

function updateVerificationCommand(command: string): void {
  const normalized = normalizeVerificationCommandInput(command);
  if (normalized === null || normalized === selectedVerificationCommand) {
    render();
    return;
  }

  selectedVerificationCommand = normalized;
  resetVerificationForCommandChange();
  render();
}

function canEditVerificationCommand(): boolean {
  return activeRecording.kind === 'none' && holdRecording.kind === 'none';
}

function resetVerificationForCommandChange(): void {
  verificationAttempts = 0;
  clearCommandRecording();
  diagnostics = {
    quality: 'none',
    phrase: 'none',
    speaker: 'none',
    policy: 'none',
  };

  switch (state.kind) {
    case 'idle':
    case 'enrolling':
      state = {
        ...state,
        verificationId: null,
        intentDigest: null,
        message: 'Verification command updated',
      };
      return;
    case 'enrolled':
      state = {
        ...state,
        verificationId: null,
        intentDigest: null,
        message: 'Verification command updated',
      };
      return;
    case 'accepted':
    case 'rejected':
    case 'uncertain':
      state = {
        kind: 'enrolled',
        enrollmentId: state.enrollmentId,
        acceptedSampleCount: 3,
        verificationId: null,
        intentDigest: null,
        message: 'Verification command updated',
      };
      return;
    case 'error':
      state = {
        ...state,
        verificationId: null,
        intentDigest: null,
        message: 'Verification command updated',
      };
      return;
  }
}

function renderRecordingProgress(target: HoldRecordingTarget): string {
  if (activeRecording.kind !== 'recording' || activeHoldTarget !== target) return '';
  return `
    <div class="recording-progress" style="--recording-duration-ms: ${activeRecording.durationMs}ms" aria-hidden="true">
      <span></span>
    </div>
  `;
}

function renderSampleCards(): string {
  return enrollmentSamples
    .map((slot) => {
      const isSelected = slot.sampleNumber === selectedEnrollmentSampleNumber;
      const isRecorded = slot.kind === 'recorded';
      const classes = [
        'sample-card',
        isRecorded ? 'recorded' : 'empty',
        isSelected ? 'selected' : '',
      ].filter((value) => value.length > 0).join(' ');
      const label = `Sample ${slot.sampleNumber}${isRecorded ? ' recorded' : ' empty'}${isSelected ? ', selected' : ''}`;
      const status = isRecorded ? 'Recorded' : 'Empty';
      const detail = sampleCardDetail(slot);
      return `
        <article
          class="${escapeHtml(classes)}"
        >
          <button
            type="button"
            class="sample-card-select"
            data-sample-number="${slot.sampleNumber}"
            aria-label="${escapeHtml(label)}"
            aria-pressed="${isSelected}"
            ${disabledAttribute(activeRecording.kind !== 'none' || holdRecording.kind !== 'none')}
          >
            <span class="sample-card-title">Sample ${slot.sampleNumber}</span>
            <strong>${escapeHtml(status)}</strong>
            <span class="sample-card-detail">${escapeHtml(detail)}</span>
          </button>
          ${slot.kind === 'recorded' ? renderSampleCardRecording(slot) : ''}
        </article>
      `;
    })
    .join('');
}

function renderSampleCardRecording(slot: Extract<EnrollmentSampleSlot, { kind: 'recorded' }>): string {
  return `
    <div class="sample-card-recording">
      <audio controls preload="metadata" src="${escapeHtml(slot.clip.url)}"></audio>
      <button
        type="button"
        class="danger secondary sample-delete"
        data-delete-sample-number="${slot.sampleNumber}"
        ${disabledAttribute(activeRecording.kind !== 'none' || holdRecording.kind !== 'none')}
      >
        Delete
      </button>
    </div>
  `;
}

function sampleCardDetail(slot: EnrollmentSampleSlot): string {
  if (slot.kind === 'recorded') {
    return `${slot.clip.durationMs}ms - ${formatBytes(slot.clip.byteLength)}`;
  }
  if (slot.sampleNumber === selectedEnrollmentSampleNumber && selectedSampleNeedsEnrollmentRebuild()) {
    return 'Hold to rebuild';
  }
  return 'Hold to record';
}

async function startFreshEnrollment(): Promise<void> {
  const response = parseEnvelope(
    await client.startEnrollment({
      userId,
      phrase: enrollmentPromptPhrase,
    }),
  );
  if (response.kind === 'error') {
    setError(response.error.message);
    return;
  }

  const value = response.value as { record: { enrollmentId: string; acceptedSampleCount: number } };
  enrollmentAttempts = 0;
  verificationAttempts = 0;
  resetEnrollmentSamples();
  void clearPersistedEnrollmentSamples().catch(reportEnrollmentSamplePersistenceError);
  clearCommandRecording();
  diagnostics = {
    quality: 'none',
    phrase: 'none',
    speaker: 'none',
    policy: 'none',
  };
  state = {
    kind: 'enrolling',
    enrollmentId: value.record.enrollmentId,
    acceptedSampleCount: value.record.acceptedSampleCount,
    verificationId: null,
    intentDigest: null,
    message: 'Enrollment started',
  };
  render();
}

function beginHoldRecording(target: HoldRecordingTarget): void {
  if (!canRecordForTarget(target) || holdRecording.kind !== 'none') return;
  activeHoldTarget = target;
  holdRecording = { kind: 'preparing', releaseRequested: false };
  void prepareAndStartHoldRecording(target);
}

async function prepareAndStartHoldRecording(target: HoldRecordingTarget): Promise<void> {
  let context: RecordingContext | null;
  try {
    context = await prepareRecordingContext(target);
  } catch (error) {
    holdRecording = { kind: 'none' };
    activeHoldTarget = null;
    activeRecording = { kind: 'none' };
    setError(`Could not prepare recording: ${formatUnknownError(error)}`);
    return;
  }
  if (context === null) {
    holdRecording = { kind: 'none' };
    activeHoldTarget = null;
    return;
  }
  if (holdRecording.kind !== 'preparing') return;

  activeRecording = {
    kind: 'preparing',
    title: 'Preparing microphone',
    detail: context.detail,
  };
  render();

  const session = await recorder.startRecording({
    maxDurationMs: maximumRecordingDurationMs,
    timeoutMs: recordingTimeoutMs,
  });
  if (session.kind === 'error') {
    holdRecording = { kind: 'none' };
    activeHoldTarget = null;
    activeRecording = { kind: 'none' };
    setError(formatRecorderError(session.reason));
    return;
  }
  if (holdRecording.kind !== 'preparing') {
    await session.cancel();
    return;
  }

  const browserAsr = startBrowserAsrForContext(context);
  if (browserAsr.kind === 'failed') {
    await session.cancel();
    holdRecording = { kind: 'none' };
    activeHoldTarget = null;
    activeRecording = { kind: 'none' };
    setError(browserAsr.reason);
    return;
  }

  const releaseRequested =
    holdRecording.kind === 'preparing' ? holdRecording.releaseRequested : false;
  holdRecording = {
    kind: 'recording',
    context,
    session,
    browserAsr,
    startedAtMs: performance.now(),
    minimumTimer: window.setTimeout(() => {
      if (holdRecording.kind !== 'recording') return;
      holdRecording = { ...holdRecording, canSubmit: true };
      render();
    }, minimumRecordingDurationMs),
    autoStopTimer: window.setTimeout(() => {
      void finishHoldRecording();
    }, maximumRecordingDurationMs),
    canSubmit: false,
  };
  activeRecording = {
    kind: 'recording',
    title: context.title,
    detail: 'Hold down while speaking. Release to finish.',
    durationMs: maximumRecordingDurationMs,
  };
  render();

  if (releaseRequested) {
    void finishHoldRecording();
  }
}

async function prepareRecordingContext(target: HoldRecordingTarget): Promise<RecordingContext | null> {
  switch (target) {
    case 'enrollment':
      return await prepareEnrollmentRecordingContext();
    case 'verification':
      return await prepareVerificationRecordingContext();
  }
}

async function prepareEnrollmentRecordingContext(): Promise<RecordingContext | null> {
  if (selectedSampleNeedsEnrollmentRebuild()) {
    const sampleNumber = selectedEnrollmentSampleNumber;
    state = {
      ...state,
      message: `Hold down to re-record enrollment sample ${sampleNumber}`,
    };
    return {
      kind: 'enrollment_rebuild',
      sampleNumber,
      title: 'Recording voice',
      detail: `Enrollment sample ${sampleNumber} of ${enrollmentRequiredSampleCount}`,
      label: `Enrollment sample ${sampleNumber}`,
    };
  }

  if (state.kind === 'idle') {
    if (recordedEnrollmentSampleCount() > 0) {
      await rebuildEnrollmentFromLocalSamples({
        kind: 'enrollment_rebuild',
        sampleNumber: selectedEnrollmentSampleNumber,
        title: 'Restoring enrollment',
        detail: 'Saved enrollment samples',
        label: `Enrollment sample ${selectedEnrollmentSampleNumber}`,
      });
    } else {
      await startFreshEnrollment();
    }
  }

  if (state.kind === 'enrolling') {
    return preparePendingEnrollmentRecordingContext(state);
  }

  if (isCompletedEnrollmentState(state)) {
    const sampleNumber = selectedEnrollmentSampleNumber;
    state = {
      ...state,
      message: `Hold down to re-record enrollment sample ${sampleNumber}`,
    };
    return {
      kind: 'enrollment_rebuild',
      sampleNumber,
      title: 'Recording voice',
      detail: `Enrollment sample ${sampleNumber} of ${enrollmentRequiredSampleCount}`,
      label: `Enrollment sample ${sampleNumber}`,
    };
  }

  return null;
}

async function prepareVerificationRecordingContext(): Promise<RecordingContext | null> {
  if (
    readyEnrollmentId(state) === null &&
    state.kind === 'idle' &&
    recordedEnrollmentSampleCount() >= enrollmentRequiredSampleCount
  ) {
    await rebuildEnrollmentFromLocalSamples({
      kind: 'enrollment_rebuild',
      sampleNumber: selectedEnrollmentSampleNumber,
      title: 'Restoring enrollment',
      detail: 'Saved enrollment samples',
      label: `Enrollment sample ${selectedEnrollmentSampleNumber}`,
    });
  }

  const enrollmentId = readyEnrollmentId(state);
  if (enrollmentId === null) {
    setError('Complete enrollment first');
    return null;
  }

  return await prepareVerificationContext(enrollmentId);
}

function preparePendingEnrollmentRecordingContext(
  current: Extract<DemoState, { kind: 'enrolling' }>,
): RecordingContext {
  const sampleNumber = selectedEnrollmentSampleNumber;
  state = { ...current, message: `Hold down to record enrollment sample ${sampleNumber}` };
  return {
    kind: 'enrollment',
    enrollmentId: current.enrollmentId,
    acceptedSampleCount: current.acceptedSampleCount,
    sampleNumber,
    title: 'Recording voice',
    detail: `Enrollment sample ${sampleNumber} of ${enrollmentRequiredSampleCount}`,
    label: `Enrollment sample ${sampleNumber}`,
  };
}

async function prepareVerificationContext(
  enrollmentId: string,
): Promise<Extract<RecordingContext, { kind: 'verification' }> | null> {
  const binding = await buildVoiceIdSpokenIntentBinding({
    spokenCommand: selectedVerificationCommand,
    expiresAt: demoIntentExpiresAt(),
    nonce: demoIntentNonce(),
  });
  const verificationStart = parseEnvelope(
    await client.startVerification({
      userId,
      enrollmentId,
      phrase: binding.spokenCommand,
      intentDigest: binding.intentDigest,
      intentExpiresAt: binding.intent.expiresAt,
      intentNonce: binding.intent.nonce,
    }),
  );
  if (verificationStart.kind === 'error') {
    setError(verificationStart.error.message);
    return null;
  }

  const value = verificationStart.value as { record: { verificationId: string } };
  const verificationId = value.record.verificationId;
  const intentDigest = binding.intentDigest;
  state = {
    kind: 'enrolled',
    enrollmentId,
    acceptedSampleCount: 3,
    verificationId: null,
    intentDigest,
    message: 'Hold down to record transaction command',
  };

  return {
    kind: 'verification',
    enrollmentId,
    verificationId,
    intentDigest,
    title: 'Recording voice',
    detail: selectedVerificationCommand,
    label: 'Transaction command',
  };
}

async function finishHoldRecording(): Promise<void> {
  if (holdRecording.kind === 'preparing') {
    holdRecording = { ...holdRecording, releaseRequested: true };
    return;
  }
  if (holdRecording.kind !== 'recording') return;

  const current = holdRecording;
  window.clearTimeout(current.minimumTimer);
  window.clearTimeout(current.autoStopTimer);
  if (!current.canSubmit && performance.now() - current.startedAtMs < minimumRecordingDurationMs) {
    cancelBrowserAsr(current.browserAsr);
    await current.session.cancel();
    holdRecording = { kind: 'none' };
    activeHoldTarget = null;
    activeRecording = { kind: 'none' };
    setStateMessage('Hold a little longer before releasing');
    return;
  }

  holdRecording = { kind: 'submitting' };
  activeRecording = {
    kind: 'submitting',
    title: 'Submitting voice',
    detail: current.context.detail,
  };
  render();

  const browserAsrResultPromise = finishBrowserAsr(current.browserAsr);
  let recorded: Awaited<ReturnType<typeof current.session.stop>>;
  try {
    recorded = await current.session.stop();
  } catch (error) {
    setError(`Could not finish recording: ${formatUnknownError(error)}`);
    return;
  }
  if (recorded.kind !== 'recorded') {
    holdRecording = { kind: 'none' };
    activeHoldTarget = null;
    activeRecording = { kind: 'none' };
    setError(
      recorded.kind === 'error'
        ? formatRecorderError(recorded.reason)
        : 'recording did not finish',
    );
    return;
  }
  const browserAsrResult = await browserAsrResultPromise;

  setRecordingForContext(current.context, {
    blob: recorded.blob,
    durationMs: recorded.durationMs,
  });
  try {
    await submitRecording(current.context, {
      blob: recorded.blob,
      durationMs: recorded.durationMs,
    }, browserAsrResult);
  } catch (error) {
    setError(`Could not submit recording: ${formatUnknownError(error)}`);
    return;
  }
  holdRecording = { kind: 'none' };
  activeHoldTarget = null;
  activeRecording = { kind: 'none' };
  render();
}

async function cancelHoldRecording(): Promise<void> {
  if (holdRecording.kind === 'preparing') {
    holdRecording = { kind: 'none' };
    activeHoldTarget = null;
    activeRecording = { kind: 'none' };
    render();
    return;
  }
  if (holdRecording.kind !== 'recording') return;

  const current = holdRecording;
  window.clearTimeout(current.minimumTimer);
  window.clearTimeout(current.autoStopTimer);
  cancelBrowserAsr(current.browserAsr);
  await current.session.cancel();
  holdRecording = { kind: 'none' };
  activeHoldTarget = null;
  activeRecording = { kind: 'none' };
  render();
}

function startBrowserAsrForContext(context: RecordingContext): BrowserAsrSession {
  if (context.kind !== 'verification' || transcriptMode !== 'browser') {
    return { kind: 'inactive', reason: 'browser ASR not requested' };
  }

  const SpeechRecognition = browserSpeechRecognitionConstructor();
  if (SpeechRecognition === null) {
    return { kind: 'failed', reason: 'Browser speech recognition is unavailable in this browser' };
  }

  const recognition = new SpeechRecognition();
  recognition.continuous = false;
  recognition.interimResults = true;
  recognition.lang = 'en-US';
  recognition.maxAlternatives = 1;

  let bestTranscript = '';
  let bestConfidence = 0;
  let errorReason: string | null = null;
  let resolved = false;
  let resolveResult: (result: BrowserAsrResult) => void = () => {};
  const result = new Promise<BrowserAsrResult>((resolve) => {
    resolveResult = resolve;
  });

  const finish = (): void => {
    if (resolved) return;
    resolved = true;
    const transcript = bestTranscript.trim();
    if (transcript.length > 0) {
      resolveResult({
        kind: 'transcript',
        transcript,
        confidence: bestConfidence,
      });
      return;
    }
    resolveResult({
      kind: 'unavailable',
      reason: errorReason ?? 'no browser transcript captured',
    });
  };

  recognition.onresult = (event) => {
    for (let index = event.resultIndex; index < event.results.length; index += 1) {
      const resultItem = speechRecognitionResultAt(event.results, index);
      const alternative = speechRecognitionAlternativeAt(resultItem, 0);
      if (alternative.transcript.trim().length === 0) continue;
      bestTranscript = alternative.transcript;
      bestConfidence = Number.isFinite(alternative.confidence) ? alternative.confidence : 0;
      if (resultItem.isFinal) {
        bestTranscript = alternative.transcript;
        bestConfidence = Number.isFinite(alternative.confidence) ? alternative.confidence : bestConfidence;
      }
    }
  };
  recognition.onerror = (event) => {
    errorReason = event.error ?? event.message ?? 'speech recognition error';
  };
  recognition.onend = finish;

  try {
    recognition.start();
  } catch (error) {
    return { kind: 'failed', reason: `Could not start browser speech recognition: ${formatUnknownError(error)}` };
  }

  return {
    kind: 'listening',
    async stop() {
      try {
        recognition.stop();
      } catch {
        finish();
      }
      return await withBrowserAsrTimeout(result);
    },
    cancel() {
      resolved = true;
      try {
        recognition.abort();
      } catch {
        // Ignore abort races; the recording session is already being cancelled.
      }
    },
  };
}

function finishBrowserAsr(session: BrowserAsrSession): Promise<BrowserAsrResult> {
  switch (session.kind) {
    case 'inactive':
      return Promise.resolve({ kind: 'unavailable', reason: session.reason });
    case 'failed':
      return Promise.resolve({ kind: 'unavailable', reason: session.reason });
    case 'listening':
      return session.stop();
  }
}

function cancelBrowserAsr(session: BrowserAsrSession): void {
  if (session.kind === 'listening') {
    session.cancel();
  }
}

function withBrowserAsrTimeout(result: Promise<BrowserAsrResult>): Promise<BrowserAsrResult> {
  return new Promise((resolve) => {
    const timer = window.setTimeout(() => {
      resolve({ kind: 'unavailable', reason: 'browser speech recognition timed out' });
    }, 1500);
    void result.then((value) => {
      window.clearTimeout(timer);
      resolve(value);
    });
  });
}

function browserSpeechRecognitionConstructor(): BrowserSpeechRecognitionConstructor | null {
  const browserWindow = window as BrowserSpeechRecognitionWindow;
  return browserWindow.SpeechRecognition ?? browserWindow.webkitSpeechRecognition ?? null;
}

function speechRecognitionResultAt(
  results: BrowserSpeechRecognitionResultList,
  index: number,
): BrowserSpeechRecognitionResult {
  return typeof results.item === 'function' ? results.item(index) : results[index];
}

function speechRecognitionAlternativeAt(
  result: BrowserSpeechRecognitionResult,
  index: number,
): BrowserSpeechRecognitionAlternative {
  return typeof result.item === 'function' ? result.item(index) : result[index];
}

async function submitRecording(
  context: RecordingContext,
  recorded: { blob: Blob; durationMs: number },
  browserAsrResult: BrowserAsrResult,
): Promise<void> {
  switch (context.kind) {
    case 'enrollment':
      await submitEnrollmentSample(context, recorded);
      return;
    case 'enrollment_rebuild':
      await rebuildEnrollmentFromLocalSamples(context);
      return;
    case 'verification':
      await submitCommandVerification(context, recorded, browserAsrResult);
      return;
  }
}

async function submitEnrollmentSample(
  context: Extract<RecordingContext, { kind: 'enrollment' }>,
  recorded: { blob: Blob; durationMs: number },
): Promise<void> {
  void recorded.durationMs;

  const value = await uploadEnrollmentClip({
    enrollmentId: context.enrollmentId,
    blob: recorded.blob,
    metadata: recorder.buildMetadata({ fixtureSpeakerLabel: 'owner' }),
  });
  if (value === null) return;

  diagnostics = {
    ...diagnostics,
    quality: formatQuality(value.quality),
  };

  if (value.acceptedSampleCount >= enrollmentRequiredSampleCount) {
    await finalizeEnrollment(context.enrollmentId);
    return;
  }

  state = {
    kind: 'enrolling',
    enrollmentId: context.enrollmentId,
    acceptedSampleCount: value.acceptedSampleCount,
    verificationId: null,
    intentDigest: null,
    message: `Accepted ${value.acceptedSampleCount} of ${enrollmentRequiredSampleCount} enrollment samples`,
  };
  selectedEnrollmentSampleNumber =
    firstEmptyEnrollmentSampleNumber() ?? nextEnrollmentSampleNumber(value.acceptedSampleCount);
  render();
}

async function rebuildEnrollmentFromLocalSamples(
  context: Extract<RecordingContext, { kind: 'enrollment_rebuild' }>,
): Promise<void> {
  const started = parseEnvelope(
    await client.startEnrollment({
      userId,
      phrase: enrollmentPromptPhrase,
    }),
  );
  if (started.kind === 'error') {
    setError(started.error.message);
    return;
  }

  const startedValue = started.value as { record: { enrollmentId: string; acceptedSampleCount: number } };
  const enrollmentId = startedValue.record.enrollmentId;
  enrollmentAttempts = 0;
  verificationAttempts = 0;
  clearCommandRecording();
  diagnostics = {
    quality: 'none',
    phrase: 'none',
    speaker: 'none',
    policy: 'none',
  };

  let acceptedSampleCount = startedValue.record.acceptedSampleCount;
  for (const sample of enrollmentSamples) {
    if (sample.kind === 'empty') continue;
    const value = await uploadEnrollmentClip({
      enrollmentId,
      blob: sample.clip.blob,
      metadata: sample.clip.metadata,
    });
    if (value === null) return;
    acceptedSampleCount = value.acceptedSampleCount;
    diagnostics = {
      ...diagnostics,
      quality: formatQuality(value.quality),
    };
  }

  if (acceptedSampleCount >= enrollmentRequiredSampleCount) {
    await finalizeEnrollment(enrollmentId);
    return;
  }

  state = {
    kind: 'enrolling',
    enrollmentId,
    acceptedSampleCount,
    verificationId: null,
    intentDigest: null,
    message: `Rebuilt enrollment with ${acceptedSampleCount} of ${enrollmentRequiredSampleCount} samples`,
  };
  selectedEnrollmentSampleNumber = firstEmptyEnrollmentSampleNumber() ?? context.sampleNumber;
  render();
}

async function uploadEnrollmentClip(input: {
  enrollmentId: string;
  blob: Blob;
  metadata: VoiceIdAudioMetadata;
}): Promise<EnrollmentSampleUploadResult | null> {
  enrollmentAttempts += 1;
  const response = parseEnvelope(
    await client.uploadEnrollmentSample({
      blob: input.blob,
      metadata: input.metadata,
      userId,
      enrollmentId: input.enrollmentId,
      expectedPhrase: enrollmentPromptPhrase,
      spokenPhrase: enrollmentPromptPhrase,
      attemptNumber: enrollmentAttempts,
    }),
  );
  if (response.kind === 'error') {
    setError(response.error.message);
    return null;
  }

  return response.value as EnrollmentSampleUploadResult;
}

async function finalizeEnrollment(enrollmentId: string): Promise<void> {
  const response = parseEnvelope(
    await client.finalizeEnrollment({
      userId,
      enrollmentId,
    }),
  );
  if (response.kind === 'error') {
    setError(response.error.message);
    return;
  }

  state = {
    kind: 'enrolled',
    enrollmentId,
    acceptedSampleCount: 3,
    verificationId: null,
    intentDigest: null,
    message: 'Enrollment complete',
  };
  render();
}

async function submitCommandVerification(
  context: Extract<RecordingContext, { kind: 'verification' }>,
  recorded: { blob: Blob; durationMs: number },
  browserAsrResult: BrowserAsrResult,
): Promise<void> {
  void recorded.durationMs;
  const transcriptEvidence = verificationTranscriptEvidence(context, browserAsrResult);
  if (transcriptEvidence === null) return;
  verificationAttempts += 1;
  const verification = parseEnvelope(
    await client.uploadVerificationSample({
      blob: recorded.blob,
      metadata: recorder.buildMetadata({ fixtureSpeakerLabel: 'owner' }),
      userId,
      enrollmentId: context.enrollmentId,
      verificationId: context.verificationId,
      expectedPhrase: selectedVerificationCommand,
      spokenPhrase: transcriptEvidence.spokenPhrase,
      attemptNumber: verificationAttempts,
    }),
  );
  if (verification.kind === 'error') {
    setError(verification.error.message);
    return;
  }

  const result = verification.value as VerificationApiResult;
  diagnostics = {
    quality: formatQuality(result.checks.quality),
    phrase: formatPhrase(result.checks.phrase, transcriptEvidence),
    speaker: formatSpeaker(result.checks.speaker),
    policy: formatVerificationPolicy(result),
  };

  switch (result.kind) {
    case 'accepted':
      await authorizeOwnerPresence({
        enrollmentId: context.enrollmentId,
        verificationId: context.verificationId,
        intentDigest: context.intentDigest,
      });
      return;
    case 'rejected':
      state = {
        kind: 'rejected',
        enrollmentId: context.enrollmentId,
        acceptedSampleCount: 3,
        verificationId: context.verificationId,
        intentDigest: context.intentDigest,
        reason: result.reason ?? 'rejected',
        message: `Rejected: ${result.reason ?? 'voice mismatch'}`,
      };
      render();
      return;
    case 'uncertain':
      state = {
        kind: 'uncertain',
        enrollmentId: context.enrollmentId,
        acceptedSampleCount: 3,
        verificationId: context.verificationId,
        intentDigest: context.intentDigest,
        reason: result.reason ?? 'uncertain',
        message: `Uncertain: ${result.reason ?? 'try again'}`,
      };
      render();
      return;
  }
}

function verificationTranscriptEvidence(
  context: Extract<RecordingContext, { kind: 'verification' }>,
  browserAsrResult: BrowserAsrResult,
): VerificationTranscriptEvidence | null {
  switch (transcriptMode) {
    case 'browser':
      if (browserAsrResult.kind === 'transcript') {
        return {
          kind: 'browser_asr',
          spokenPhrase: browserAsrResult.transcript,
          confidence: browserAsrResult.confidence,
        };
      }
      diagnostics = {
        ...diagnostics,
        phrase: `browser ASR unavailable; ${browserAsrResult.reason}`,
      };
      state = {
        kind: 'uncertain',
        enrollmentId: context.enrollmentId,
        acceptedSampleCount: 3,
        verificationId: context.verificationId,
        intentDigest: context.intentDigest,
        reason: 'browser_asr_unavailable',
        message: `Uncertain: browser ASR unavailable (${browserAsrResult.reason})`,
      };
      render();
      return null;
    case 'server':
      return {
        kind: 'server_asr',
        spokenPhrase: serverAsrSpokenPhrasePlaceholder,
      };
    case 'fake': {
      const simulated = normalizeVerificationCommandInput(simulatedSpokenPhrase);
      if (simulated === null) {
        setError('Type a simulated spoken phrase before using fake phrase mode');
        return null;
      }
      return {
        kind: 'simulated',
        spokenPhrase: simulated,
      };
    }
  }
}

async function authorizeOwnerPresence(input: {
  enrollmentId: string;
  verificationId: string;
  intentDigest: string;
}): Promise<void> {
  const authorization = parseEnvelope(
    await client.authorizeOwnerPresence({
      verificationId: input.verificationId,
      intentDigest: input.intentDigest,
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

  const value = authorization.value as { decision: { kind: string; reason?: string } };
  diagnostics = {
    ...diagnostics,
    policy: value.decision.kind,
  };
  state = {
    kind: 'accepted',
    enrollmentId: input.enrollmentId,
    acceptedSampleCount: 3,
    verificationId: input.verificationId,
    intentDigest: input.intentDigest,
    message: `Accepted: policy ${value.decision.kind}`,
  };
  render();
}

function setRecordingForContext(
  context: RecordingContext,
  input: { blob: Blob; durationMs: number },
): void {
  const clip = {
    blob: input.blob,
    metadata: recorder.buildMetadata({ fixtureSpeakerLabel: 'owner' }),
    url: URL.createObjectURL(input.blob),
    label: context.label,
    durationMs: input.durationMs,
    byteLength: input.blob.size,
    recordedAt: new Date().toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }),
  };

  switch (context.kind) {
    case 'enrollment':
    case 'enrollment_rebuild':
      setEnrollmentSampleClip(context.sampleNumber, clip, 'persist');
      return;
    case 'verification':
      clearCommandRecording();
      commandRecording = clip;
      return;
  }
}

function deleteEnrollmentSample(sampleNumber: EnrollmentSampleNumber): void {
  const sample = enrollmentSamples[enrollmentSampleIndex(sampleNumber)];
  if (sample.kind === 'empty') return;
  URL.revokeObjectURL(sample.clip.url);
  enrollmentSamples[enrollmentSampleIndex(sample.sampleNumber)] = {
    kind: 'empty',
    sampleNumber: sample.sampleNumber,
  };
  void deletePersistedEnrollmentSample(sample.sampleNumber).catch(reportEnrollmentSamplePersistenceError);
  recorder.clearRecording();
  if (isCompletedEnrollmentState(state)) {
    clearCommandRecording();
    diagnostics = {
      quality: 'none',
      phrase: 'none',
      speaker: 'none',
      policy: 'none',
    };
    state = {
      kind: 'enrolled',
      enrollmentId: state.enrollmentId,
      acceptedSampleCount: 3,
      verificationId: null,
      intentDigest: null,
      message: `Sample ${sample.sampleNumber} deleted. Hold to re-record and rebuild enrollment.`,
    };
  } else if (state.kind === 'enrolling' && recordedEnrollmentSampleCount() < state.acceptedSampleCount) {
    state = {
      kind: 'enrolling',
      enrollmentId: state.enrollmentId,
      acceptedSampleCount: state.acceptedSampleCount,
      verificationId: null,
      intentDigest: null,
      message: `Sample ${sample.sampleNumber} deleted. Hold to re-record and rebuild enrollment.`,
    };
  }
  render();
}

function selectedEnrollmentSampleSlot(): EnrollmentSampleSlot {
  return enrollmentSamples[enrollmentSampleIndex(selectedEnrollmentSampleNumber)];
}

function setEnrollmentSampleClip(
  sampleNumber: EnrollmentSampleNumber,
  clip: RecordedClip,
  persistenceMode: EnrollmentSamplePersistenceMode,
): void {
  const index = enrollmentSampleIndex(sampleNumber);
  const current = enrollmentSamples[index];
  if (current.kind === 'recorded') {
    URL.revokeObjectURL(current.clip.url);
  }
  enrollmentSamples[index] = {
    kind: 'recorded',
    sampleNumber,
    clip,
  };

  if (persistenceMode === 'persist') {
    void persistEnrollmentSampleClip(sampleNumber, clip).catch(reportEnrollmentSamplePersistenceError);
  }
}

function resetEnrollmentSamples(): void {
  for (const sample of enrollmentSamples) {
    if (sample.kind === 'recorded') {
      URL.revokeObjectURL(sample.clip.url);
    }
  }
  enrollmentSamples = buildEmptyEnrollmentSamples();
  selectedEnrollmentSampleNumber = 1;
}

async function restorePersistedEnrollmentSamples(): Promise<void> {
  const records = await loadPersistedEnrollmentSamples().catch((error: unknown) => {
    reportEnrollmentSamplePersistenceError(error);
    return [];
  });
  if (records.length === 0) return;
  if (state.kind !== 'idle' || activeRecording.kind !== 'none' || recordedEnrollmentSampleCount() > 0) {
    return;
  }

  for (const record of records) {
    setEnrollmentSampleClip(record.sampleNumber, buildRecordedClipFromPersistedSample(record), 'memory_only');
  }

  selectedEnrollmentSampleNumber = firstEmptyEnrollmentSampleNumber() ?? 1;
  const restoredCount = recordedEnrollmentSampleCount();
  state = {
    kind: 'idle',
    enrollmentId: null,
    acceptedSampleCount: 0,
    verificationId: null,
    intentDigest: null,
    message: persistedSampleRestoreMessage(restoredCount),
  };
  render();
}

function persistedSampleRestoreMessage(restoredCount: number): string {
  if (restoredCount >= enrollmentRequiredSampleCount) {
    return 'Loaded saved enrollment samples. Restore enrollment to continue.';
  }
  if (restoredCount === 1) {
    return 'Loaded 1 saved enrollment sample. Resume enrollment to continue.';
  }
  return `Loaded ${restoredCount} saved enrollment samples. Resume enrollment to continue.`;
}

function buildRecordedClipFromPersistedSample(record: PersistedEnrollmentSampleRecord): RecordedClip {
  return {
    blob: record.blob,
    metadata: record.metadata,
    url: URL.createObjectURL(record.blob),
    label: record.label,
    durationMs: record.durationMs,
    byteLength: record.byteLength,
    recordedAt: record.recordedAt,
  };
}

async function persistEnrollmentSampleClip(
  sampleNumber: EnrollmentSampleNumber,
  clip: RecordedClip,
): Promise<void> {
  if (!supportsEnrollmentSamplePersistence()) return;

  const database = await openEnrollmentSampleDatabase();
  try {
    const transaction = database.transaction(samplePersistenceStoreName, 'readwrite');
    const transactionDone = waitForIdbTransaction(transaction);
    transaction.objectStore(samplePersistenceStoreName).put({
      sampleNumber,
      userId,
      phrase: enrollmentPromptPhrase,
      blob: clip.blob,
      metadata: clip.metadata,
      label: clip.label,
      durationMs: clip.durationMs,
      byteLength: clip.byteLength,
      recordedAt: clip.recordedAt,
      savedAt: nowIsoDateTime(),
    });
    await transactionDone;
  } finally {
    database.close();
  }
}

async function loadPersistedEnrollmentSamples(): Promise<PersistedEnrollmentSampleRecord[]> {
  if (!supportsEnrollmentSamplePersistence()) return [];

  const database = await openEnrollmentSampleDatabase();
  try {
    const transaction = database.transaction(samplePersistenceStoreName, 'readonly');
    const transactionDone = waitForIdbTransaction(transaction);
    const values = await waitForIdbRequest<unknown[]>(
      transaction.objectStore(samplePersistenceStoreName).getAll(),
    );
    await transactionDone;

    const records: PersistedEnrollmentSampleRecord[] = [];
    for (const value of values) {
      const record = parsePersistedEnrollmentSampleRecord(value);
      if (record === null) continue;
      if (record.userId !== userId || record.phrase !== enrollmentPromptPhrase) continue;
      records.push(record);
    }

    return records.sort((left, right) => left.sampleNumber - right.sampleNumber);
  } finally {
    database.close();
  }
}

async function deletePersistedEnrollmentSample(sampleNumber: EnrollmentSampleNumber): Promise<void> {
  if (!supportsEnrollmentSamplePersistence()) return;

  const database = await openEnrollmentSampleDatabase();
  try {
    const transaction = database.transaction(samplePersistenceStoreName, 'readwrite');
    const transactionDone = waitForIdbTransaction(transaction);
    transaction.objectStore(samplePersistenceStoreName).delete(sampleNumber);
    await transactionDone;
  } finally {
    database.close();
  }
}

async function clearPersistedEnrollmentSamples(): Promise<void> {
  if (!supportsEnrollmentSamplePersistence()) return;

  const database = await openEnrollmentSampleDatabase();
  try {
    const transaction = database.transaction(samplePersistenceStoreName, 'readwrite');
    const transactionDone = waitForIdbTransaction(transaction);
    transaction.objectStore(samplePersistenceStoreName).clear();
    await transactionDone;
  } finally {
    database.close();
  }
}

function openEnrollmentSampleDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(samplePersistenceDatabaseName, samplePersistenceDatabaseVersion);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(samplePersistenceStoreName)) {
        database.createObjectStore(samplePersistenceStoreName, { keyPath: 'sampleNumber' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('failed to open sample database'));
    request.onblocked = () => reject(new Error('sample database upgrade blocked'));
  });
}

function waitForIdbRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('sample database request failed'));
  });
}

function waitForIdbTransaction(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error('sample database transaction failed'));
    transaction.onabort = () => reject(transaction.error ?? new Error('sample database transaction aborted'));
  });
}

function supportsEnrollmentSamplePersistence(): boolean {
  return typeof indexedDB !== 'undefined';
}

function parsePersistedEnrollmentSampleRecord(value: unknown): PersistedEnrollmentSampleRecord | null {
  if (!isJsonObject(value)) return null;

  const sampleNumber = parsePersistedEnrollmentSampleNumber(value.sampleNumber);
  const userIdValue = parsePersistedString(value.userId);
  const phrase = parsePersistedString(value.phrase);
  const blob = parsePersistedBlob(value.blob);
  const metadata = parsePersistedAudioMetadata(value.metadata);
  const label = parsePersistedString(value.label);
  const durationMs = parsePersistedPositiveNumber(value.durationMs);
  const byteLength = parsePersistedPositiveInteger(value.byteLength);
  const recordedAt = parsePersistedString(value.recordedAt);
  const savedAt = parsePersistedString(value.savedAt);

  if (
    sampleNumber === null ||
    userIdValue === null ||
    phrase === null ||
    blob === null ||
    metadata === null ||
    label === null ||
    durationMs === null ||
    byteLength === null ||
    recordedAt === null ||
    savedAt === null
  ) {
    return null;
  }
  if (blob.size !== byteLength || metadata.byteLength !== byteLength) return null;

  return {
    sampleNumber,
    userId: userIdValue,
    phrase,
    blob,
    metadata,
    label,
    durationMs,
    byteLength,
    recordedAt,
    savedAt,
  };
}

function parsePersistedAudioMetadata(value: unknown): VoiceIdAudioMetadata | null {
  try {
    return parseVoiceIdAudioMetadata(value);
  } catch {
    return null;
  }
}

function parsePersistedEnrollmentSampleNumber(value: unknown): EnrollmentSampleNumber | null {
  switch (value) {
    case 1:
      return 1;
    case 2:
      return 2;
    case 3:
      return 3;
    default:
      return null;
  }
}

function parsePersistedString(value: unknown): string | null {
  if (typeof value !== 'string' || value.trim().length === 0) return null;
  return value;
}

function parsePersistedPositiveNumber(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return null;
  return value;
}

function parsePersistedPositiveInteger(value: unknown): number | null {
  const parsed = parsePersistedPositiveNumber(value);
  if (parsed === null || !Number.isInteger(parsed)) return null;
  return parsed;
}

function parsePersistedBlob(value: unknown): Blob | null {
  if (value instanceof Blob) return value;
  return null;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function reportEnrollmentSamplePersistenceError(error: unknown): void {
  console.warn('VoiceID enrollment sample persistence failed', error);
  if (state.kind === 'error') return;
  state = { ...state, message: `Saved samples unavailable: ${formatUnknownError(error)}` };
  render();
}

function clearCommandRecording(): void {
  if (commandRecording === null) return;
  URL.revokeObjectURL(commandRecording.url);
  commandRecording = null;
}

function buildEmptyEnrollmentSamples(): EnrollmentSampleSlots {
  return [
    { kind: 'empty', sampleNumber: 1 },
    { kind: 'empty', sampleNumber: 2 },
    { kind: 'empty', sampleNumber: 3 },
  ];
}

function selectedSampleNeedsEnrollmentRebuild(): boolean {
  if (selectedEnrollmentSampleSlot().kind !== 'empty') return false;
  if (isCompletedEnrollmentState(state)) return true;
  if (state.kind !== 'enrolling') return false;
  return recordedEnrollmentSampleCount() < state.acceptedSampleCount;
}

function displayedEnrollmentSampleCount(): number {
  if (state.kind === 'idle') return recordedEnrollmentSampleCount();
  if (isCompletedEnrollmentState(state)) return recordedEnrollmentSampleCount();
  if (state.kind === 'enrolling' && recordedEnrollmentSampleCount() < state.acceptedSampleCount) {
    return recordedEnrollmentSampleCount();
  }
  return state.acceptedSampleCount;
}

function recordedEnrollmentSampleCount(): number {
  return enrollmentSamples.filter((sample) => sample.kind === 'recorded').length;
}

function isCompletedEnrollmentState(
  current: DemoState,
): current is Extract<DemoState, { kind: 'enrolled' | 'accepted' | 'rejected' | 'uncertain' }> {
  switch (current.kind) {
    case 'enrolled':
    case 'accepted':
    case 'rejected':
    case 'uncertain':
      return true;
    case 'idle':
    case 'enrolling':
    case 'error':
      return false;
  }
}

function firstEmptyEnrollmentSampleNumber(): EnrollmentSampleNumber | null {
  for (const sample of enrollmentSamples) {
    if (sample.kind === 'empty') return sample.sampleNumber;
  }
  return null;
}

function nextEnrollmentSampleNumber(acceptedSampleCount: number): EnrollmentSampleNumber {
  if (acceptedSampleCount <= 0) return 1;
  if (acceptedSampleCount === 1) return 2;
  return 3;
}

function enrollmentSampleIndex(sampleNumber: EnrollmentSampleNumber): 0 | 1 | 2 {
  switch (sampleNumber) {
    case 1:
      return 0;
    case 2:
      return 1;
    case 3:
      return 2;
  }
}

function parseEnrollmentSampleNumber(value: string | null): EnrollmentSampleNumber | null {
  switch (value) {
    case '1':
      return 1;
    case '2':
      return 2;
    case '3':
      return 3;
    case null:
    default:
      return null;
  }
}

function canRecordForTarget(target: HoldRecordingTarget): boolean {
  if (activeRecording.kind !== 'none' || holdRecording.kind !== 'none') return false;

  switch (target) {
    case 'enrollment':
      return state.kind !== 'error';
    case 'verification':
      return (
        recordedEnrollmentSampleCount() >= enrollmentRequiredSampleCount &&
        (readyEnrollmentId(state) !== null || state.kind === 'idle') &&
        verificationTranscriptReady()
      );
  }
}

function recordButtonLabel(target: HoldRecordingTarget): string {
  if (activeHoldTarget === target) {
    switch (activeRecording.kind) {
      case 'recording':
        return 'Release to finish';
      case 'preparing':
        return 'Preparing mic';
      case 'submitting':
        return 'Submitting';
      case 'none':
        break;
    }
  }

  switch (target) {
    case 'enrollment':
      return 'Hold to speak';
    case 'verification':
      return 'Hold to speak';
  }
}

function recordButtonHint(target: HoldRecordingTarget): string {
  if (activeHoldTarget === target) {
    switch (activeRecording.kind) {
      case 'recording':
        return 'Release to finish';
      case 'preparing':
        return 'Allow microphone access';
      case 'submitting':
        return 'Checking voice';
      case 'none':
        break;
    }
  }

  switch (target) {
    case 'enrollment': {
      const selectedSample = selectedEnrollmentSampleSlot();
      if (state.kind === 'idle' && recordedEnrollmentSampleCount() > 0) return 'Restores saved samples';
      if (selectedSample.kind === 'recorded') return `Replace sample ${selectedSample.sampleNumber}`;
      return `Record sample ${selectedSample.sampleNumber}`;
    }
    case 'verification':
      if (!verificationTranscriptReady()) return verificationTranscriptBlockingReason();
      if (readyEnrollmentId(state) !== null) return selectedVerificationCommand;
      if (recordedEnrollmentSampleCount() >= enrollmentRequiredSampleCount) return 'Restores then verifies';
      return 'Complete enrollment first';
  }
}

function recordingStatusText(target: HoldRecordingTarget): string {
  if (activeHoldTarget === target) {
    switch (activeRecording.kind) {
      case 'recording':
        return activeRecording.detail;
      case 'preparing':
        return `Preparing ${activeRecording.detail}`;
      case 'submitting':
        return `Submitting ${activeRecording.detail}`;
      case 'none':
        break;
    }
  }

  switch (target) {
    case 'enrollment':
      return enrollmentRecordingStatusText();
    case 'verification':
      return verificationRecordingStatusText();
  }
}

function enrollmentSectionStatus(): string {
  if (recordedEnrollmentSampleCount() >= enrollmentRequiredSampleCount && readyEnrollmentId(state) !== null) {
    return 'Ready';
  }
  if (recordedEnrollmentSampleCount() >= enrollmentRequiredSampleCount) {
    return 'Saved';
  }
  if (state.kind === 'enrolling') return 'Enrolling';
  return 'Needs samples';
}

function verificationSectionStatus(): string {
  switch (state.kind) {
    case 'accepted':
      return 'Accepted';
    case 'rejected':
      return 'Rejected';
    case 'uncertain':
      return 'Uncertain';
    case 'enrolled':
      return 'Ready';
    case 'idle':
      return recordedEnrollmentSampleCount() >= enrollmentRequiredSampleCount ? 'Restore ready' : 'Waiting';
    case 'enrolling':
      return 'Waiting';
    case 'error':
      return 'Error';
  }
}

function enrollmentRecordingStatusText(): string {
  if (state.kind === 'error') return state.message;
  if (state.kind === 'idle' && recordedEnrollmentSampleCount() > 0) return state.message;
  if (selectedSampleNeedsEnrollmentRebuild()) {
    return `Sample ${selectedEnrollmentSampleNumber} is missing. Hold to rebuild enrollment.`;
  }
  const selectedSample = selectedEnrollmentSampleSlot();
  if (selectedSample.kind === 'recorded') {
    return `Sample ${selectedSample.sampleNumber} selected. Hold to replace it.`;
  }
  return `Sample ${selectedSample.sampleNumber} selected. Hold to record it.`;
}

function verificationRecordingStatusText(): string {
  if (state.kind === 'error') return state.message;
  if (!verificationTranscriptReady()) return verificationTranscriptBlockingReason();
  if (readyEnrollmentId(state) !== null) return verificationTranscriptReadyText();
  if (recordedEnrollmentSampleCount() >= enrollmentRequiredSampleCount) {
    return 'Hold to restore saved enrollment and verify the command.';
  }
  return 'Complete all three enrollment samples first.';
}

function verificationTranscriptReady(): boolean {
  switch (transcriptMode) {
    case 'browser':
      return browserSpeechRecognitionConstructor() !== null;
    case 'server':
      return true;
    case 'fake':
      return simulatedSpokenPhrase.trim().length > 0;
  }
}

function verificationTranscriptBlockingReason(): string {
  switch (transcriptMode) {
    case 'browser':
      return 'Browser speech recognition is unavailable. Use Server ASR or Simulated phrase.';
    case 'server':
      return 'Server ASR is ready.';
    case 'fake':
      return 'Type a simulated spoken phrase before recording.';
  }
}

function verificationTranscriptReadyText(): string {
  switch (transcriptMode) {
    case 'browser':
      return 'Hold while saying the transaction command. Browser ASR will transcribe it.';
    case 'server':
      return 'Hold while saying the transaction command. Server ASR will transcribe it.';
    case 'fake':
      return 'Hold to record voice. Phrase check uses the typed simulated phrase.';
  }
}

function readyEnrollmentId(current: DemoState): string | null {
  switch (current.kind) {
    case 'enrolled':
    case 'accepted':
    case 'rejected':
    case 'uncertain':
      return current.enrollmentId;
    case 'idle':
    case 'enrolling':
    case 'error':
      return null;
  }
}

function parseEnvelope(value: unknown): ApiEnvelope {
  return value as ApiEnvelope;
}

function setError(message: string): void {
  state = {
    kind: 'error',
    enrollmentId: state.enrollmentId,
    acceptedSampleCount: state.acceptedSampleCount,
    verificationId: state.verificationId,
    intentDigest: state.intentDigest,
    message,
  };
  holdRecording = { kind: 'none' };
  activeRecording = { kind: 'none' };
  activeHoldTarget = null;
  render();
}

function setStateMessage(message: string): void {
  state = { ...state, message };
  render();
}

function demoIntentExpiresAt(): string {
  return new Date(Date.now() + 5 * 60 * 1000).toISOString();
}

function demoIntentNonce(): string {
  return `demo_${Date.now()}_${verificationAttempts + 1}`;
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

function formatIntentDigest(intentDigest: string | null): string {
  if (intentDigest === null) return 'Digest none';
  return `Digest ${shortIntentDigest(intentDigest)}`;
}

function shortIntentDigest(intentDigest: string): string {
  if (intentDigest.length <= 18) return intentDigest;
  return `${intentDigest.slice(0, 8)}...${intentDigest.slice(-6)}`;
}

function formatQuality(quality: VerificationChecks['quality']): string {
  if (quality.kind === 'accepted') {
    return `${quality.kind}; ${quality.durationMs}ms; signal ${formatNumber(quality.signalScore ?? 0)}`;
  }

  return `${quality.kind}; ${quality.reason ?? 'no reason'}; ${quality.durationMs}ms`;
}

function formatPhrase(
  phraseResult: VerificationChecks['phrase'],
  evidence: VerificationTranscriptEvidence | null = null,
): string {
  const source = phraseSourceLabel(evidence);
  return `${source}${phraseResult.kind}; ${phraseResult.spokenNormalized}; confidence ${formatNumber(phraseResult.confidence)}`;
}

function phraseSourceLabel(evidence: VerificationTranscriptEvidence | null): string {
  if (evidence === null) return '';
  switch (evidence.kind) {
    case 'browser_asr':
      return `browser ASR ${formatNumber(evidence.confidence)}; `;
    case 'server_asr':
      return 'server ASR; ';
    case 'simulated':
      return 'simulated; ';
  }
}

function formatSpeaker(speaker: VerificationChecks['speaker']): string {
  return `${speaker.kind}; score ${formatNumber(speaker.score)} / threshold ${formatNumber(speaker.threshold)}`;
}

function formatVerificationPolicy(result: VerificationApiResult): string {
  switch (result.kind) {
    case 'accepted':
      return 'verification accepted; checking owner-presence policy';
    case 'rejected':
      return `rejected; ${formatVerificationReason(result.reason)}`;
    case 'uncertain':
      return `uncertain; ${formatVerificationReason(result.reason)}`;
  }
}

function formatVerificationReason(reason: string): string {
  switch (reason) {
    case 'phrase_mismatch':
      return 'phrase mismatch';
    case 'speaker_mismatch':
      return 'speaker mismatch';
    case 'low_audio_quality':
      return 'low audio quality';
    case 'too_many_attempts':
      return 'too many attempts';
    case 'expired':
      return 'verification expired';
    case 'noisy_audio':
      return 'noisy audio';
    case 'too_short':
      return 'recording too short';
    case 'model_low_confidence':
      return 'model confidence below threshold';
    case 'verifier_unavailable':
      return 'verifier unavailable';
    default:
      return reason.replaceAll('_', ' ');
  }
}

function formatRecorderError(reason: string): string {
  if (reason === 'recording_cancelled') {
    return 'recording cancelled';
  }
  if (reason === 'empty_recording') {
    return 'no audio frames captured';
  }
  return reason;
}

function formatUnknownError(error: unknown): string {
  if (error instanceof Error && error.message.trim().length > 0) return error.message;
  if (typeof error === 'string' && error.trim().length > 0) return error;
  return 'unknown error';
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

function disabledAttribute(disabled: boolean): string {
  return disabled ? 'disabled aria-disabled="true"' : '';
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
    --bg: #f5f7f6;
    --surface: #ffffff;
    --surface-muted: #f0f6f3;
    --ink: #162027;
    --muted: #586875;
    --line: #d7e0df;
    --line-strong: #b8c7c4;
    --primary: #163832;
    --primary-hover: #102b27;
    --accent: #1c7c72;
    --accent-soft: #dcefeb;
    --sky-soft: #e8f0fb;
    --sky: #37658c;
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
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    align-items: start;
    gap: 20px;
    max-width: 1180px;
    margin: 0 auto;
    padding: 34px 20px 48px;
  }

  .hero {
    grid-column: 1 / -1;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    gap: 18px;
  }

  h1 {
    margin: 3px 0 8px;
    font-size: 42px;
    line-height: 1;
    letter-spacing: 0;
  }

  h2 {
    margin: 0 0 4px;
    font-size: 20px;
    line-height: 1.2;
  }

  p {
    margin: 0;
    color: var(--muted);
  }

  .device-pill,
  .digest-chip {
    border: 1px solid var(--line);
    border-radius: 8px;
  }

  .device-pill {
    display: inline-flex;
    align-items: center;
    min-height: 30px;
    padding: 0 11px;
    color: #2d4d60;
    background: var(--sky-soft);
    font-size: 13px;
    font-weight: 700;
    white-space: nowrap;
  }

  .status-pill {
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

  .workflow-section {
    display: grid;
    gap: 12px;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: #fff;
    padding: 16px;
    box-shadow: 0 10px 26px rgb(22 32 39 / 6%);
  }

  .workflow-section + .workflow-section {
    margin-top: 0;
  }

  .section-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 14px;
  }

  .section-header > div:first-child {
    display: grid;
    gap: 4px;
  }

  .section-header strong {
    font-size: 18px;
    line-height: 1.15;
  }

  .section-status {
    display: inline-flex;
    align-items: center;
    min-height: 26px;
    border-radius: 999px;
    background: var(--accent-soft);
    color: #185a53;
    padding: 0 10px;
    font-size: 12px;
    font-weight: 700;
    white-space: nowrap;
  }

  .command-card {
    display: grid;
    gap: 12px;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: var(--surface-muted);
    padding: 16px 18px 18px;
  }

  .command-controls {
    display: grid;
    gap: 6px;
  }

  .command-controls label,
  .transcript-controls label {
    color: var(--muted);
    font-size: 12px;
    font-weight: 700;
    line-height: 1.2;
  }

  .command-controls select,
  .command-input,
  .transcript-controls select,
  .simulated-phrase-input {
    width: 100%;
    border: 1px solid var(--line-strong);
    border-radius: 8px;
    background: #fff;
    color: var(--ink);
    font: inherit;
  }

  .command-controls select {
    min-height: 42px;
    padding: 0 12px;
    font-size: 14px;
    font-weight: 700;
  }

  .transcript-controls {
    display: grid;
    grid-template-columns: minmax(180px, 0.75fr) minmax(220px, 1fr);
    gap: 8px 10px;
    align-items: end;
  }

  .transcript-controls label,
  .transcript-controls p {
    grid-column: 1 / -1;
  }

  .transcript-controls select,
  .simulated-phrase-input {
    min-height: 38px;
    padding: 0 12px;
    font-size: 13px;
    font-weight: 700;
  }

  .transcript-controls p {
    margin: 0;
    color: var(--muted);
    font-size: 12px;
    line-height: 1.35;
  }

  .command-meta {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .command-input {
    min-height: 92px;
    padding: 12px 14px;
    color: var(--ink);
    font-size: 28px;
    font-weight: 800;
    line-height: 1.15;
    overflow-wrap: anywhere;
    resize: none;
  }

  .command-controls select:disabled,
  .command-input:disabled,
  .transcript-controls select:disabled,
  .simulated-phrase-input:disabled {
    cursor: not-allowed;
    background: #edf3f2;
    color: var(--muted);
  }

  .command-controls select:focus-visible,
  .command-input:focus-visible,
  .transcript-controls select:focus-visible,
  .simulated-phrase-input:focus-visible {
    outline: 3px solid rgb(28 124 114 / 22%);
    outline-offset: 2px;
  }

  .digest-chip {
    display: inline-flex;
    align-items: center;
    min-height: 26px;
    padding: 0 10px;
    background: #fff;
    color: var(--muted);
    font-size: 13px;
    font-weight: 700;
    overflow-wrap: anywhere;
  }

  .eyebrow {
    color: var(--muted);
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .voice-rail {
    display: grid;
    grid-template-rows: auto auto auto 1fr auto;
    justify-items: center;
    gap: 14px;
    min-height: 380px;
    border: 1px solid rgb(224 232 232 / 82%);
    border-radius: 34px;
    margin-top: 12px;
    padding: 24px 22px 20px;
    background:
      radial-gradient(circle at 50% 35%, rgb(223 241 255 / 70%) 0%, rgb(223 241 255 / 30%) 18%, transparent 34%),
      linear-gradient(180deg, rgb(255 255 255 / 98%), rgb(255 255 255 / 92%)),
      #fff;
    box-shadow:
      0 28px 70px rgb(22 32 39 / 10%),
      inset 0 1px 0 rgb(255 255 255 / 90%);
  }

  .voice-card-status {
    display: flex;
    justify-content: center;
    width: 100%;
    min-height: 24px;
  }

  .voice-card-timer {
    color: var(--muted);
    font-size: 24px;
    font-weight: 600;
    line-height: 1;
    font-variant-numeric: tabular-nums;
  }

  .voice-orb {
    display: grid;
    place-items: center;
    width: 104px;
    height: 104px;
    border: 1px solid #dae5ec;
    border-radius: 50%;
    background:
      radial-gradient(circle at 45% 38%, #c8e4ff 0%, #dcedff 42%, rgb(247 252 255 / 78%) 72%),
      #f8fbff;
    box-shadow:
      0 0 0 9px rgb(217 237 255 / 28%),
      0 0 0 20px rgb(217 237 255 / 14%),
      0 14px 42px rgb(89 151 206 / 18%),
      inset 0 0 18px rgb(255 255 255 / 82%);
  }

  .voice-orb span {
    width: 68px;
    height: 68px;
    border-radius: inherit;
    background: radial-gradient(circle at 45% 42%, #b9dcff, #dbedff 68%, rgb(255 255 255 / 45%));
    filter: blur(0.2px);
  }

  .voice-rail.recording-active .voice-orb {
    box-shadow:
      0 0 0 12px rgb(217 237 255 / 22%),
      0 0 0 24px rgb(92 166 229 / 12%),
      0 16px 48px rgb(89 151 206 / 18%),
      inset 0 0 18px rgb(255 255 255 / 82%);
  }

  .voice-card-copy {
    display: grid;
    justify-items: center;
    gap: 3px;
    text-align: center;
  }

  .voice-card-copy strong {
    color: var(--ink);
    font-size: 28px;
    line-height: 1.05;
  }

  .voice-card-copy span {
    color: var(--muted);
    font-size: 17px;
    line-height: 1.25;
    overflow-wrap: anywhere;
  }

  .voice-card-copy .voice-card-progress {
    margin-top: 4px;
    color: var(--ink);
    font-size: 13px;
    font-weight: 700;
  }

  .voice-control-strip {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    gap: 12px;
    align-self: end;
    width: 100%;
    min-height: 66px;
    border: 1px solid rgb(220 229 229 / 88%);
    border-radius: 999px;
    padding: 8px 10px 8px 20px;
    background: rgb(255 255 255 / 94%);
    box-shadow:
      0 14px 34px rgb(22 32 39 / 8%),
      inset 0 1px 0 rgb(255 255 255 / 92%);
  }

  .rail-status {
    min-height: 20px;
    margin-top: 8px;
    text-align: center;
    font-size: 14px;
  }

  .wave-strip {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    min-height: 42px;
    min-width: 0;
    width: 100%;
  }

  .wave-strip i {
    display: block;
    width: 5px;
    height: var(--bar-height);
    border-radius: 999px;
    background: #d6e0de;
  }

  .wave-strip i:nth-child(-n + 4) {
    background: #9aa7a6;
  }

  .wave-strip i:nth-child(n + 12) {
    background: #e4e9e8;
  }

  .voice-rail.recording-active .wave-strip i {
    background: var(--accent);
    animation: voice-wave 780ms ease-in-out infinite alternate;
  }

  .voice-rail.recording-active .wave-strip i:nth-child(2n) {
    animation-delay: 120ms;
  }

  .voice-rail.recording-active .wave-strip i:nth-child(3n) {
    animation-delay: 240ms;
  }

  @keyframes voice-wave {
    from {
      height: 14px;
    }

    to {
      height: var(--bar-height);
    }
  }

  .sample-cards {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
  }

  .sample-card {
    display: grid;
    gap: 10px;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: #fff;
    color: var(--ink);
    padding: 10px;
  }

  .sample-card.selected {
    border-color: var(--accent);
    background: var(--accent-soft);
    box-shadow: 0 0 0 3px rgb(28 124 114 / 14%);
  }

  .sample-card-select {
    display: grid;
    align-content: start;
    gap: 6px;
    min-height: 74px;
    border: 0;
    border-radius: 6px;
    background: transparent;
    color: var(--ink);
    padding: 4px;
    text-align: left;
  }

  .sample-card-select:hover:not(:disabled) {
    border-color: var(--line-strong);
    background: var(--surface-muted);
  }

  .sample-card-select:disabled {
    background: transparent;
    color: var(--ink);
    cursor: not-allowed;
  }

  .sample-card-title,
  .sample-card-detail {
    color: var(--muted);
    font-size: 12px;
    font-weight: 700;
  }

  .sample-card-title {
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .sample-card strong {
    font-size: 18px;
    line-height: 1.1;
    overflow-wrap: anywhere;
  }

  .sample-card-detail {
    overflow-wrap: anywhere;
  }

  .sample-card.recorded .sample-card-detail {
    color: #2f635e;
  }

  .sample-card-recording {
    display: grid;
    gap: 8px;
  }

  .sample-card-recording audio {
    width: 100%;
    min-height: 36px;
  }

  .sample-delete {
    width: 100%;
  }

  button {
    border: 1px solid var(--primary);
    border-radius: 6px;
    background: var(--primary);
    color: #fff;
    min-height: 42px;
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

  button.record-button {
    display: grid;
    grid-template-columns: auto 1fr;
    grid-template-areas:
      "dot label"
      "dot hint";
    column-gap: 9px;
    align-items: center;
    min-width: 164px;
    min-height: 50px;
    border-radius: 999px;
    padding: 0 16px;
    text-align: left;
    touch-action: none;
    user-select: none;
  }

  button.record-button small {
    grid-area: hint;
    color: rgb(255 255 255 / 76%);
    font-size: 11px;
    font-weight: 650;
  }

  button.record-button > span:nth-child(2) {
    grid-area: label;
    font-size: 18px;
  }

  .record-dot {
    grid-area: dot;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: #f4fffb;
    box-shadow: inset 0 0 0 4px var(--accent);
  }

  button.record-button:disabled .record-dot {
    background: #edf1f3;
    box-shadow: inset 0 0 0 4px #87949e;
  }

  .voice-rail.recording-active button.record-button .record-dot {
    display: grid;
    place-items: center;
    background: var(--danger);
    box-shadow: 0 0 0 8px rgb(163 58 47 / 10%);
  }

  .voice-rail.recording-active button.record-button .record-dot::after {
    content: "";
    width: 6px;
    height: 6px;
    border-radius: 2px;
    background: #fff;
  }

  .voice-rail.recording-active button.record-button {
    border-color: #f2c3bb;
    background: #ffe2de;
    color: var(--danger);
  }

  .voice-rail.recording-active button.record-button small {
    color: rgb(163 58 47 / 72%);
  }

  button.danger {
    border-color: #d8b6b1;
    color: var(--danger);
  }

  button.danger:hover:not(:disabled) {
    background: #fff1ef;
  }

  button:disabled {
    background: #d6dde2;
    border-color: #c4cdd4;
    color: #687783;
    cursor: not-allowed;
  }

  button.sample-card-select:disabled {
    background: transparent;
    border-color: transparent;
    color: var(--ink);
  }

  .status-grid {
    margin: 0;
    display: grid;
    align-content: start;
    grid-template-columns: 1fr;
    gap: 0;
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 14px;
  }

  .status-grid div {
    min-width: 0;
    border-bottom: 1px solid #ecf0ef;
    padding: 0 0 10px;
    margin-bottom: 10px;
  }

  .status-grid div:last-child {
    border-bottom: 0;
    margin-bottom: 0;
    padding-bottom: 0;
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

  .recording-progress {
    grid-column: 1 / -1;
    height: 6px;
    width: 100%;
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

  button:focus-visible {
    outline: 3px solid rgb(28 124 114 / 22%);
    outline-offset: 2px;
  }

  @media (max-width: 980px) {
    .shell {
      grid-template-columns: 1fr;
    }
  }

  @media (max-width: 640px) {
    .shell {
      padding: 24px 14px 36px;
    }

    .hero {
      align-items: flex-start;
      flex-direction: column;
      gap: 12px;
    }

    h1 {
      font-size: 34px;
    }

    .command-meta {
      align-items: stretch;
      flex-direction: column;
    }

    .command-input {
      min-height: 84px;
      font-size: 23px;
    }

    .voice-rail {
      min-height: 360px;
      border-radius: 28px;
      gap: 12px;
      padding: 22px 16px 16px;
    }

    .voice-orb {
      width: 86px;
      height: 86px;
    }

    .voice-orb span {
      width: 56px;
      height: 56px;
    }

    .voice-card-copy strong {
      font-size: 24px;
    }

    .voice-card-copy span {
      font-size: 15px;
    }

    .voice-control-strip {
      grid-template-columns: 1fr;
      border-radius: 24px;
      padding: 10px;
    }

    .wave-strip {
      min-height: 46px;
      gap: 4px;
      padding-left: 0;
    }

    .wave-strip i {
      width: 4px;
    }

    button.record-button {
      min-width: 100%;
    }

    .status-grid,
    .sample-cards {
      grid-template-columns: 1fr;
      width: 100%;
    }

    .section-header {
      align-items: stretch;
      flex-direction: column;
    }
  }
`;
document.head.append(style);
