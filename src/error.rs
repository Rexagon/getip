/// An error produced while attempting to resolve.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No or invalid IP address string found.
    #[error("no or invalid IP address string found")]
    Addr,
    /// IP version not requested was returned.
    #[error("IP version not requested was returned")]
    Version,
    /// DNS resolver error.
    #[error("dns resolver: {0}")]
    Dns(#[from] hickory_client::proto::ProtoError),
}
