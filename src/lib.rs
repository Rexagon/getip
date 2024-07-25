use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::StreamExt;

pub use self::error::Error;

mod dns;
mod error;

/// The version of IP address to resolve.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AddrVersion {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
    /// Any version of IP address.
    Any,
}

impl AddrVersion {
    /// Returns `true` if the provided IP address's version matches `self`.
    #[must_use]
    pub fn matches(self, addr: IpAddr) -> bool {
        self == AddrVersion::Any
            || (self == AddrVersion::V4 && addr.is_ipv4())
            || (self == AddrVersion::V6 && addr.is_ipv6())
    }
}

pub async fn addr() -> Result<IpAddr, Error> {
    resolve(AddrVersion::Any).await
}

pub async fn addr_v4() -> Result<Ipv4Addr, Error> {
    Ok(match resolve(AddrVersion::V4).await? {
        IpAddr::V4(addr) => addr,
        IpAddr::V6(_) => unreachable!(),
    })
}

pub async fn addr_v6() -> Result<Ipv6Addr, Error> {
    Ok(match resolve(AddrVersion::V6).await? {
        IpAddr::V4(_) => unreachable!(),
        IpAddr::V6(addr) => addr,
    })
}

pub async fn resolve(version: AddrVersion) -> Result<IpAddr, Error> {
    let mut last_err = Error::Addr;

    for resolver in dns::ALL {
        let mut stream = resolver.resolve(version);
        while let Some(res) = stream.next().await {
            match res {
                Ok(addr) if version.matches(addr) => return Ok(addr),
                Ok(_) => return Err(Error::Version),
                Err(err) => last_err = err,
            }
        }
    }

    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_my() {
        let public = addr().await.unwrap();
        println!("{public:?}");
    }
}
