/// Platform-agnostic Router engine wrapper.
#[derive(Debug, Clone)]
pub struct RouterEngine<H> {
    host: H,
}

impl<H> RouterEngine<H> {
    /// Creates a Router engine over a host implementation.
    pub fn new(host: H) -> Self {
        Self { host }
    }

    /// Returns the host implementation.
    pub fn host(&self) -> &H {
        &self.host
    }
}
