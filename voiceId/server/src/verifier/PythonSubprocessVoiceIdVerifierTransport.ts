import { spawn } from 'node:child_process';
import { delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  PythonBuildEnrollmentTemplateRequest,
  PythonVerifySpeakerRequest,
  PythonVoiceIdVerifierTransport,
} from './PythonVoiceIdVerifier.ts';

type PythonVerifierOperation =
  | {
      kind: 'build_enrollment_template';
      request: PythonBuildEnrollmentTemplateRequest;
    }
  | {
      kind: 'verify_speaker';
      request: PythonVerifySpeakerRequest;
    };

export type PythonSubprocessVoiceIdVerifierTransportConfig = {
  readonly pythonExecutable?: string;
  readonly appScriptPath?: string;
  readonly verifierPackagePath?: string;
  readonly cwd?: string;
  readonly env?: Readonly<Record<string, string>>;
  readonly timeoutMs?: number;
};

export class PythonSubprocessVoiceIdVerifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PythonSubprocessVoiceIdVerifierError';
  }
}

export class PythonSubprocessVoiceIdVerifierTransport implements PythonVoiceIdVerifierTransport {
  private readonly pythonExecutable: string;
  private readonly appScriptPath: string;
  private readonly verifierPackagePath: string;
  private readonly cwd: string;
  private readonly env: Readonly<Record<string, string>>;
  private readonly timeoutMs: number;

  constructor(config: PythonSubprocessVoiceIdVerifierTransportConfig = {}) {
    this.pythonExecutable = config.pythonExecutable ?? 'python3';
    this.appScriptPath = config.appScriptPath ?? defaultPythonVerifierAppPath();
    this.verifierPackagePath = config.verifierPackagePath ?? defaultPythonVerifierPackagePath();
    this.cwd = config.cwd ?? defaultVoiceIdWorkspacePath();
    this.env = config.env ?? {};
    this.timeoutMs = config.timeoutMs ?? 10_000;
  }

  buildEnrollmentTemplate(request: PythonBuildEnrollmentTemplateRequest): Promise<unknown> {
    return this.runOperation({ kind: 'build_enrollment_template', request });
  }

  verifySpeaker(request: PythonVerifySpeakerRequest): Promise<unknown> {
    return this.runOperation({ kind: 'verify_speaker', request });
  }

  private runOperation(operation: PythonVerifierOperation): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.pythonExecutable, [this.appScriptPath, operation.kind], {
        cwd: this.cwd,
        env: this.buildEnv(),
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      let timedOut = false;
      const timeout = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
      }, this.timeoutMs);

      child.stdout.on('data', (chunk: Buffer) => {
        stdoutChunks.push(chunk);
      });
      child.stderr.on('data', (chunk: Buffer) => {
        stderrChunks.push(chunk);
      });
      child.on('error', (error) => {
        clearTimeout(timeout);
        reject(new PythonSubprocessVoiceIdVerifierError(`failed to start Python verifier: ${error.message}`));
      });
      child.on('close', (code) => {
        clearTimeout(timeout);
        const stderr = Buffer.concat(stderrChunks).toString('utf8').trim();
        if (timedOut) {
          reject(new PythonSubprocessVoiceIdVerifierError(`Python verifier timed out after ${this.timeoutMs}ms`));
          return;
        }
        if (code !== 0) {
          reject(
            new PythonSubprocessVoiceIdVerifierError(
              `Python verifier exited with code ${code}${stderr.length > 0 ? `: ${stderr}` : ''}`,
            ),
          );
          return;
        }
        const stdout = Buffer.concat(stdoutChunks).toString('utf8').trim();
        try {
          resolve(JSON.parse(stdout));
        } catch (error) {
          reject(
            new PythonSubprocessVoiceIdVerifierError(
              `Python verifier returned invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
            ),
          );
        }
      });
      child.stdin.end(JSON.stringify(operation.request));
    });
  }

  private buildEnv(): NodeJS.ProcessEnv {
    return {
      ...process.env,
      ...this.env,
      PYTHONPATH: mergePythonPath(this.verifierPackagePath, this.env.PYTHONPATH ?? process.env.PYTHONPATH),
    };
  }
}

function mergePythonPath(requiredPath: string, existingPath: string | undefined): string {
  if (existingPath === undefined || existingPath.length === 0) {
    return requiredPath;
  }
  return `${requiredPath}${delimiter}${existingPath}`;
}

function defaultVoiceIdWorkspacePath(): string {
  return fileURLToPath(new URL('../../../', import.meta.url));
}

function defaultPythonVerifierPackagePath(): string {
  return fileURLToPath(new URL('../../../verifier', import.meta.url));
}

function defaultPythonVerifierAppPath(): string {
  return fileURLToPath(new URL('../../../verifier/voiceid_verifier/app.py', import.meta.url));
}
