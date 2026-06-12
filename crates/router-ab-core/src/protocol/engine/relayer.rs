/// Platform-agnostic relayer activation engine wrapper.
#[derive(Debug, Clone)]
pub struct RelayerEngine<H> {
    host: H,
}

impl<H> RelayerEngine<H> {
    /// Creates a relayer engine over a host implementation.
    pub fn new(host: H) -> Self {
        Self { host }
    }

    /// Returns the host implementation.
    pub fn host(&self) -> &H {
        &self.host
    }
}
