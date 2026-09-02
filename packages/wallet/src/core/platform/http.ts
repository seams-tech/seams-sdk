
export type PlatformResult<Ok, Code extends string> =
  | {
      ok: true;
      value: Ok;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      code: Code;
      message: string;
      value?: never;
    };

export type HttpTransport = {
  kind: 'http_transport';
  request(input: {
    method: 'GET' | 'POST';
    url: string;
    headers?: Record<string, string>;
    body?: unknown;
    timeoutMs?: number;
  }): Promise<PlatformResult<{ status: number; body: unknown }, 'network_error' | 'timeout'>>;
};
