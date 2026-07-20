/* global IdentityTransformStream */

class RpcIdentityBytePipe {
  constructor() {
    const pipe = new IdentityTransformStream();
    this.readable = pipe.readable;
    this.writable = pipe.writable;
    this.writer = null;
  }

  requireWriter() {
    if (this.writer === null) {
      this.writer = this.writable.getWriter();
    }
    return this.writer;
  }

  write(chunk) {
    if (!(chunk instanceof Uint8Array)) {
      throw new TypeError('Yao RPC pipe requires byte chunks');
    }
    return this.requireWriter().write(chunk.slice());
  }

  close() {
    return this.requireWriter().close();
  }

  abort(reason) {
    return this.requireWriter().abort(new Error(reason));
  }
}

export function createRpcIdentityBytePipe() {
  return new RpcIdentityBytePipe();
}
