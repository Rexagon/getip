use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use futures_util::{future, ready, stream, FutureExt, Stream, StreamExt};
use hickory_client::client::AsyncClient;
use hickory_client::op::Query;
use hickory_client::proto::error::{ProtoError, ProtoErrorKind};
use hickory_client::proto::xfer::{DnsHandle, DnsRequestOptions, DnsResponse};
use hickory_client::rr::{Name, RData, RecordType};
use hickory_client::udp::UdpClientStream;

use crate::error::Error;
use crate::AddrVersion;

const DEFAULT_DNS_PORT: u16 = 53;

pub const ALL: &[&Resolver<'static>] = &[OPENDNS_V4, OPENDNS_V6, GOOGLE_V4, GOOGLE_V6];

pub const OPENDNS_V4: &Resolver<'static> = &Resolver::new_static(
    "myip.opendns.com",
    &[
        IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
        IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220)),
        IpAddr::V4(Ipv4Addr::new(208, 67, 222, 220)),
        IpAddr::V4(Ipv4Addr::new(208, 67, 220, 222)),
    ],
    DEFAULT_DNS_PORT,
    QueryMethod::A,
);

pub const OPENDNS_V6: &Resolver<'static> = &Resolver::new_static(
    "myip.opendns.com",
    &[
        // 2620:0:ccc::2
        IpAddr::V6(Ipv6Addr::new(9760, 0, 3276, 0, 0, 0, 0, 2)),
        // 2620:0:ccd::2
        IpAddr::V6(Ipv6Addr::new(9760, 0, 3277, 0, 0, 0, 0, 2)),
    ],
    DEFAULT_DNS_PORT,
    QueryMethod::AAAA,
);

pub const GOOGLE_V4: &Resolver<'static> = &Resolver::new_static(
    "o-o.myaddr.l.google.com",
    &[
        IpAddr::V4(Ipv4Addr::new(216, 239, 32, 10)),
        IpAddr::V4(Ipv4Addr::new(216, 239, 34, 10)),
        IpAddr::V4(Ipv4Addr::new(216, 239, 36, 10)),
        IpAddr::V4(Ipv4Addr::new(216, 239, 38, 10)),
    ],
    DEFAULT_DNS_PORT,
    QueryMethod::TXT,
);

pub const GOOGLE_V6: &Resolver<'static> = &Resolver::new_static(
    "o-o.myaddr.l.google.com",
    &[
        // 2001:4860:4802:32::a
        IpAddr::V6(Ipv6Addr::new(8193, 18528, 18434, 50, 0, 0, 0, 10)),
        // 2001:4860:4802:34::a
        IpAddr::V6(Ipv6Addr::new(8193, 18528, 18434, 52, 0, 0, 0, 10)),
        // 2001:4860:4802:36::a
        IpAddr::V6(Ipv6Addr::new(8193, 18528, 18434, 54, 0, 0, 0, 10)),
        // 2001:4860:4802:38::a
        IpAddr::V6(Ipv6Addr::new(8193, 18528, 18434, 56, 0, 0, 0, 10)),
    ],
    DEFAULT_DNS_PORT,
    QueryMethod::TXT,
);

/// Method used to query an IP address from a DNS server
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
enum QueryMethod {
    /// The first queried `A` name record is extracted as our IP address.
    A,
    /// The first queried `AAAA` name record is extracted as our IP address.
    AAAA,
    /// The first `TXT` record is extracted and parsed as our IP address.
    TXT,
}

/// Options to build a DNS resolver.
#[derive(Debug)]
pub struct Resolver<'r> {
    port: u16,
    name: Cow<'r, str>,
    servers: Cow<'r, [IpAddr]>,
    method: QueryMethod,
}

impl Resolver<'static> {
    #[must_use]
    const fn new_static(
        name: &'static str,
        servers: &'static [IpAddr],
        port: u16,
        method: QueryMethod,
    ) -> Self {
        Self {
            port,
            name: Cow::Borrowed(name),
            servers: Cow::Borrowed(servers),
            method,
        }
    }
}

impl<'r> Resolver<'r> {
    pub fn resolve(&self, version: AddrVersion) -> BoxStream<'static, Result<IpAddr, Error>> {
        let port = self.port;
        let method = self.method;
        let name = match Name::from_ascii(self.name.as_ref()) {
            Ok(name) => name,
            Err(err) => return Box::pin(stream::once(future::ready(Err(Error::Dns(err))))),
        };

        let mut servers: Vec<_> = self
            .servers
            .iter()
            .copied()
            .filter(|addr| version.matches(*addr))
            .collect();

        let first_server = match servers.pop() {
            Some(server) => server,
            None => return Box::pin(stream::empty()),
        };

        let record_type = match self.method {
            QueryMethod::A => RecordType::A,
            QueryMethod::AAAA => RecordType::AAAA,
            QueryMethod::TXT => RecordType::TXT,
        };

        let query = Query::query(name, record_type);
        let fut = resolve(first_server, port, query.clone(), method);

        Box::pin(DnsResolutions {
            port,
            query,
            method,
            servers,
            fut: Some(Box::pin(fut)),
        })
    }
}

struct DnsResolutions {
    port: u16,
    query: Query,
    method: QueryMethod,
    servers: Vec<IpAddr>,
    fut: Option<ResolutionFut>,
}

impl Stream for DnsResolutions {
    type Item = Result<IpAddr, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        while self.fut.is_some() {
            if let Some(fut) = &mut self.fut {
                let res = ready!(fut.poll_unpin(cx));
                self.fut = None;
                return Poll::Ready(Some(res));
            }

            if let Some(server) = self.servers.pop() {
                let fut = resolve(server, self.port, self.query.clone(), self.method);
                self.fut = Some(Box::pin(fut));
            }
        }

        Poll::Ready(None)
    }
}

type ResolutionFut = BoxFuture<'static, Result<IpAddr, Error>>;

async fn resolve(
    server: IpAddr,
    port: u16,
    query: Query,
    method: QueryMethod,
) -> Result<IpAddr, Error> {
    let server = SocketAddr::new(server, port);
    let mut query_opts = DnsRequestOptions::default();
    query_opts.use_edns = true;
    let response = dns_query(server, query, query_opts).await?;
    parse_dns_response(response, method)
}

async fn dns_query(
    server: SocketAddr,
    query: Query,
    query_opts: DnsRequestOptions,
) -> Result<DnsResponse, ProtoError> {
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(server);
    let (client, bg) = AsyncClient::connect(stream).await?;
    tokio::spawn(bg);

    client
        .lookup(query, query_opts)
        .next()
        .await
        .transpose()?
        .ok_or_else(|| ProtoErrorKind::Message("expected a response").into())
}

fn parse_dns_response(response: DnsResponse, method: QueryMethod) -> Result<IpAddr, Error> {
    let answer = match response.into_message().take_answers().into_iter().next() {
        Some(answer) => answer,
        None => return Err(Error::Addr),
    };

    match answer.into_data() {
        Some(RData::A(addr)) if method == QueryMethod::A => Ok(IpAddr::V4(addr.0)),
        Some(RData::AAAA(addr)) if method == QueryMethod::AAAA => Ok(IpAddr::V6(addr.0)),
        Some(RData::TXT(txt)) if method == QueryMethod::TXT => {
            let Some(addr_bytes) = txt.iter().next() else {
                return Err(Error::Addr);
            };

            let Ok(addr) = std::str::from_utf8(&addr_bytes[..]) else {
                return Err(Error::Addr);
            };

            addr.parse().map_err(|_| Error::Addr)
        }
        _ => Err(ProtoError::from(ProtoErrorKind::Message("invalid response")).into()),
    }
}
