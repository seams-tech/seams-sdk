const [expectation, expectedCode] = process.argv.slice(2);
const response = await fetch("http://127.0.0.1:8787/benchmark/activation", {
  method: "POST",
  signal: AbortSignal.timeout(20_000),
});
const body = await response.json();

if (expectation === "success") {
  if (response.status !== 200 || body.ok !== true) {
    throw new Error(`expected successful fault benchmark, received ${response.status} ${JSON.stringify(body)}`);
  }
  if (body.injected_outgoing_fragment_count === 0 || body.max_injected_outgoing_fragment_bytes > 4096) {
    throw new Error(`missing deterministic A fragmentation metrics: ${JSON.stringify(body)}`);
  }
} else if (expectation === "failure") {
  if (response.status !== 500 || body.ok !== false || body.error_code !== expectedCode) {
    throw new Error(`expected ${expectedCode}, received ${response.status} ${JSON.stringify(body)}`);
  }
} else {
  throw new Error("usage: assert_fault_response.mjs success | failure ERROR_CODE");
}

console.log(JSON.stringify({ status: response.status, body }));
