import type {
  PythonBuildTemplateRequest,
  PythonExtractEnrollmentEmbeddingRequest,
  PythonVerifySpeakerRequest,
  PythonVoiceIdVerifierTransport,
} from './PythonVoiceIdVerifier.ts';

export type PythonHttpVoiceIdVerifierFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export type PythonHttpVoiceIdVerifierPaths = {
  readonly extractEnrollmentEmbedding: string;
  readonly buildTemplate: string;
  readonly verifySpeaker: string;
};

export type PythonHttpVoiceIdVerifierTransportConfig = {
  readonly baseUrl: string | URL;
  readonly fetchJson?: PythonHttpVoiceIdVerifierFetch;
  readonly paths?: PythonHttpVoiceIdVerifierPaths;
  readonly timeoutMs?: number;
};

export class PythonHttpVoiceIdVerifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PythonHttpVoiceIdVerifierError';
  }
}

export class PythonHttpVoiceIdVerifierTransport implements PythonVoiceIdVerifierTransport {
  private readonly baseUrl: URL;
  private readonly fetchJson: PythonHttpVoiceIdVerifierFetch;
  private readonly paths: PythonHttpVoiceIdVerifierPaths;
  private readonly timeoutMs: number;

  constructor(config: PythonHttpVoiceIdVerifierTransportConfig) {
    this.baseUrl = normalizeBaseUrl(config.baseUrl);
    this.fetchJson = config.fetchJson ?? ((input, init) => fetch(input, init));
    this.paths = config.paths ?? defaultPythonHttpVoiceIdVerifierPaths();
    this.timeoutMs = config.timeoutMs ?? 10_000;
  }

  extractEnrollmentEmbedding(request: PythonExtractEnrollmentEmbeddingRequest): Promise<unknown> {
    return this.postJson(this.paths.extractEnrollmentEmbedding, request);
  }

  buildTemplate(request: PythonBuildTemplateRequest): Promise<unknown> {
    return this.postJson(this.paths.buildTemplate, request);
  }

  verifySpeaker(request: PythonVerifySpeakerRequest): Promise<unknown> {
    return this.postJson(this.paths.verifySpeaker, request);
  }

  private async postJson(path: string, request: unknown): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
    }, this.timeoutMs);

    try {
      const response = await this.fetchJson(endpointUrl(this.baseUrl, path), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
        signal: controller.signal,
      });
      const responseText = await response.text();
      if (!response.ok) {
        throw new PythonHttpVoiceIdVerifierError(
          `Python verifier sidecar returned HTTP ${response.status}${responseText.length > 0 ? `: ${responseText}` : ''}`,
        );
      }
      try {
        return JSON.parse(responseText);
      } catch (error) {
        throw new PythonHttpVoiceIdVerifierError(
          `Python verifier sidecar returned invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    } catch (error) {
      if (error instanceof PythonHttpVoiceIdVerifierError) {
        throw error;
      }
      if (isAbortError(error)) {
        throw new PythonHttpVoiceIdVerifierError(
          `Python verifier sidecar timed out after ${this.timeoutMs}ms`,
        );
      }
      throw new PythonHttpVoiceIdVerifierError(
        `Python verifier sidecar request failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      clearTimeout(timeout);
    }
  }
}

export function defaultPythonHttpVoiceIdVerifierPaths(): PythonHttpVoiceIdVerifierPaths {
  return {
    extractEnrollmentEmbedding: 'extract-enrollment-embedding',
    buildTemplate: 'build-template',
    verifySpeaker: 'verify-speaker',
  };
}

function normalizeBaseUrl(baseUrl: string | URL): URL {
  const url = new URL(baseUrl);
  if (url.pathname.endsWith('/')) {
    return url;
  }
  url.pathname = `${url.pathname}/`;
  return url;
}

function endpointUrl(baseUrl: URL, path: string): URL {
  const relativePath = path.startsWith('/') ? path.slice(1) : path;
  return new URL(relativePath, baseUrl);
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}
