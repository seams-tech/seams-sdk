# Router A/B ECDSA registration client

This browser-only Wasm package owns the ECDSA role-local prepare and finalize
operations required during registration and session bootstrap. Recovery,
export, refresh, presigning, online signing, and server APIs remain outside its
dependency and export surface.
