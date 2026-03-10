declare module 'express' {
  export interface Request {
    headers?: Record<string, string | string[] | undefined>;
    method?: string;
    body?: any;
    query?: any;
  }
  export interface Response {
    status: (code: number) => Response;
    json: (body: any) => Response;
    send: (body?: any) => Response;
    set: {
      (name: string, value: any): Response;
      (headers: Record<string, any>): Response;
    };
    sendStatus?: (code: number) => void;
  }
  export interface Router {
    use: (...args: any[]) => Router;
    get: (...args: any[]) => Router;
    post: (...args: any[]) => Router;
    put: (...args: any[]) => Router;
    patch: (...args: any[]) => Router;
    delete: (...args: any[]) => Router;
    options: (...args: any[]) => Router;
  }
  export function Router(): Router;
}
