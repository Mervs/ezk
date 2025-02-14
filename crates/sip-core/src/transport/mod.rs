use self::resolver::{Resolver, SystemResolver};
use crate::{Endpoint, Error, Request, Response, Result, WithStatus};
use anyhow::anyhow;
use bytes::Bytes;
use parking_lot::Mutex;
use sip_types::host::Host;
use sip_types::msg::MessageLine;
use sip_types::print::AppendCtx;
use sip_types::uri::{Uri, UriInfo};
use sip_types::{Code, Headers};
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::mem::take;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::SystemTime;
use std::{fmt, io};

pub mod resolver;
pub mod streaming;
pub mod udp;

/// Abstraction over a transport factory.
///
/// It is used to created connection oriented transports
#[async_trait::async_trait]
pub trait Factory: Send + Sync + 'static {
    /// Must return the name of the transport this factory produces. (e.g. UDP, TCP, TLS ...)
    fn name(&self) -> &'static str;

    /// Checks if the factory is eligible for the transport specified inside an uri.
    /// Needs overridable behavior since some transports (like TLS) must accept the `tcp`-string.
    fn matches_transport_param(&self, name: &str) -> bool {
        self.name().eq_ignore_ascii_case(name)
    }

    /// Indicated if the created transport is secure
    fn secure(&self) -> bool;

    /// Create a transport from an `endpoint` and a list of (resolved) addresses.
    ///
    /// Returns the created transport and address used to connect the transport
    async fn create(
        &self,
        endpoint: Endpoint,
        addrs: &[SocketAddr],
    ) -> io::Result<(TpHandle, SocketAddr)>;
}

/// Abstraction over a transport
#[async_trait::async_trait]
pub trait Transport: Debug + Display + Send + Sync + 'static {
    /// Must return the name of the transport. (e.g. UDP, TCP, TLS ...)
    fn name(&self) -> &'static str;

    /// Checks if the transport is eligible for the transport specified inside an uri.
    /// Needs overridable behavior since some transports (like TLS) must accept the `tcp`-string.
    fn matches_transport_param(&self, name: &str) -> bool {
        self.name().eq_ignore_ascii_case(name)
    }

    /// Indicates if the transport is a secure connection (e.g. TLS)
    fn secure(&self) -> bool;

    /// Is the transport reliable, changes how retransmissions in transactions are handled.
    fn reliable(&self) -> bool;

    /// The local address of the transport
    fn bound(&self) -> SocketAddr;

    /// The sent-by address of the transport. This address is where peers can reach this endpoint
    /// from. (e.g. the listener address of a tcp stream)
    fn sent_by(&self) -> SocketAddr;

    /// The direction of the transport
    fn direction(&self) -> Direction;

    /// Use the given transport to send `message` to `target`.
    ///
    /// Connection oriented transports may discard the `target` parameter.
    async fn send(&self, message: &[u8], target: SocketAddr) -> io::Result<()>;
}

/// Thin wrapper over a transport to add some convenience functions
#[derive(Debug, Clone)]
pub struct TpHandle(Arc<dyn Transport>);

impl Deref for TpHandle {
    type Target = dyn Transport;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl fmt::Display for TpHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.direction() {
            Direction::None => write!(f, "{}", self.0),
            Direction::Outgoing(_) => write!(f, "outgoing:{}", self.0),
            Direction::Incoming(_) => write!(f, "incoming:{}", self.0),
        }
    }
}

impl TpHandle {
    pub fn new<T: Transport>(transport: T) -> Self {
        Self(Arc::new(transport))
    }

    pub fn key(&self) -> TpKey {
        TpKey {
            name: self.0.name(),
            bound: self.0.bound(),
            direction: self.0.direction(),
        }
    }
}

/// Direction of a transport
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Direction {
    /// No direction because it is datagram based (e.g. UDP)
    None,

    /// A connection oriented transport which has been established by this endpoint
    Outgoing(SocketAddr),

    /// A connection oriented transport which was accepted by this endpoint
    Incoming(SocketAddr),
}

/// Transport related info for a message
#[derive(Debug)]
pub struct MessageTpInfo {
    /// Timestamp the messages was received at
    pub timestamp: SystemTime,

    /// Source address
    pub source: SocketAddr,

    /// The complete buffer containing the message.
    /// Must be truncated to fit the message
    pub buffer: Bytes,

    /// Handle to the transport the messages was received from
    pub transport: TpHandle,
}

/// Message received directly from a transport
pub struct ReceivedMessage {
    /// transport info about the message
    pub tp_info: MessageTpInfo,

    /// Leading line of the message. Notates if the message is a request or response
    pub line: MessageLine,

    /// All headers found inside the message, neither parsed nor validated
    pub headers: Headers,

    /// Body part of the messages as raw bytes
    pub body: Bytes,
}

impl fmt::Display for ReceivedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.line.default_print_ctx())
    }
}

impl ReceivedMessage {
    pub fn new(
        source: SocketAddr,
        buffer: Bytes,
        transport: TpHandle,
        line: MessageLine,
        headers: Headers,
        body: Bytes,
    ) -> Self {
        Self {
            tp_info: MessageTpInfo {
                timestamp: SystemTime::now(),
                source,
                buffer,
                transport,
            },
            line,
            headers,
            body,
        }
    }
}

#[derive(Debug)]
pub struct OutgoingResponse {
    pub msg: Response,
    pub parts: OutgoingParts,
}

#[derive(Debug)]
pub struct OutgoingRequest {
    pub msg: Request,
    pub parts: OutgoingParts,
}

#[derive(Debug)]
pub struct OutgoingParts {
    /// Transport the message will be sent with
    pub transport: TpHandle,

    /// One or more addresses the message will be sent to
    pub destination: Vec<SocketAddr>,

    /// Buffer the message got printed into
    pub buffer: Bytes,
}

/// Key used to identify and store transports
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct TpKey {
    /// Name of the transport (taken from [`Transport::name`])
    pub name: &'static str,
    /// Local address of the transport
    pub bound: SocketAddr,
    /// Direction of the transport
    pub direction: Direction,
}

pub(crate) struct Transports {
    unmanaged: Box<[TpHandle]>,
    factories: Box<[Arc<dyn Factory>]>,
    transports: Mutex<HashMap<TpKey, TpHandle>>,

    resolver: Box<dyn Resolver>,
}

impl Transports {
    pub async fn resolve(&self, name: &str) -> Result<Vec<SocketAddr>> {
        self.resolver.resolve(name).await
    }

    pub async fn resolve_host_port(&self, host: &Host, port: u16) -> Result<Vec<SocketAddr>> {
        match host {
            Host::IP6(ip) => Ok(vec![SocketAddr::from((*ip, port))]),
            Host::IP4(ip) => Ok(vec![SocketAddr::from((*ip, port))]),
            Host::Name(n) => self.resolve(n).await,
        }
    }

    pub async fn resolve_uri(&self, info: &UriInfo<'_>) -> Result<Vec<SocketAddr>> {
        let port = match info.host_port.port {
            Some(port) => port,
            None if info.secure => 5061,
            None => 5060,
        };

        self.resolve_host_port(&info.host_port.host, port).await
    }

    /// Will try to find or create a suitable transport the given Uri
    #[tracing::instrument(name = "select_transport", level = "trace", skip(self, endpoint))]
    pub(crate) async fn select(
        &self,
        endpoint: &Endpoint,
        uri: &dyn Uri,
    ) -> Result<(TpHandle, Vec<SocketAddr>)> {
        log::trace!("select transport for {:?}", uri);

        let info = uri.info();

        // Resolve host_port to possible remote addresses
        let addresses = self.resolve_uri(&info).await.status(Code::BAD_GATEWAY)?;

        log::trace!("resolved addresses: {:?}", addresses);

        // Try to find a fitting connectionless transport
        if let Some(transport) = self.unmanaged.iter().find(|tp| {
            let tp_allowed = info
                .transport
                .as_ref()
                .map(|tp_name| tp.matches_transport_param(tp_name))
                .unwrap_or(true);

            tp_allowed && info.allows_security_level(tp.secure())
        }) {
            log::trace!("selected connectionless: {}", transport);

            return Ok((transport.clone(), addresses));
        }

        // Try to find any idling transport to use
        {
            let transports = self.transports.lock();

            for (_, transport) in transports.iter() {
                let remote = match transport.direction() {
                    Direction::None => unreachable!(),
                    Direction::Incoming(_) => continue,
                    Direction::Outgoing(remote) => remote,
                };

                if let Some(tp_name) = &info.transport {
                    if !transport.matches_transport_param(tp_name) {
                        continue;
                    }
                }

                if !addresses.contains(&remote) {
                    continue;
                }

                if !info.allows_security_level(transport.secure()) {
                    continue;
                }

                log::trace!("selected transport: {}", transport);

                return Ok((transport.clone(), vec![remote]));
            }
        }

        let mut last_err = io::Error::new(
            io::ErrorKind::Other,
            "no suitable transport or factory found",
        );

        // Try to build new transport with a factory
        for factory in self.factories.iter() {
            if let Some(tp_name) = &info.transport {
                if !factory.matches_transport_param(tp_name) {
                    continue;
                }
            }

            if !info.allows_security_level(factory.secure()) {
                continue;
            }

            match factory.create(endpoint.clone(), &addresses).await {
                Ok((transport, remote)) => {
                    log::trace!("created new transport {}", transport);

                    return Ok((transport, vec![remote]));
                }
                Err(e) => {
                    last_err = e;
                }
            }
        }

        Err(last_err.into())
    }

    /// Try to claim a transport with that key from the endpoint.
    /// Sometimes a transport might still be in use from a previous transaction,
    /// this will wait until the transport is released again.
    #[tracing::instrument(skip(self))]
    pub async fn claim(&self, key: &TpKey) -> Option<TpHandle> {
        match key.direction {
            Direction::None => {
                let transport = self
                    .unmanaged
                    .iter()
                    .find(|t| t.name() == key.name && t.bound() == key.bound)?;

                log::trace!("claimed transport {}", transport);

                Some(transport.clone())
            }
            Direction::Incoming(_) | Direction::Outgoing(_) => {
                let transports = self.transports.lock();
                transports.get(key).cloned()
            }
        }
    }

    pub fn drop_transport(&self, tp_key: &TpKey) {
        log::trace!("drop transport {:?}", tp_key);

        self.transports.lock().remove(tp_key);
    }
}

#[derive(Default)]
pub(crate) struct TransportsBuilder {
    unmanaged: Vec<TpHandle>,
    factories: Vec<Arc<dyn Factory>>,
    resolver: Option<Box<dyn Resolver>>,
}

impl TransportsBuilder {
    pub fn insert_unmanaged<T>(&mut self, transport: T)
    where
        T: Transport,
    {
        assert_eq!(transport.direction(), Direction::None);

        self.unmanaged.push(TpHandle::new(transport));
    }

    pub fn insert_factory(&mut self, factory: Arc<dyn Factory>) {
        self.factories.push(factory);
    }

    pub fn build(&mut self) -> Transports {
        Transports {
            unmanaged: take(&mut self.unmanaged).into_boxed_slice(),
            factories: take(&mut self.factories).into_boxed_slice(),
            transports: Default::default(),
            resolver: self
                .resolver
                .take()
                .unwrap_or_else(|| Box::new(SystemResolver)),
        }
    }
}

fn parse_line(src: &Bytes, line: &str, headers: &mut Headers) -> Result<()> {
    use sip_types::msg::Line;

    match Line::parse(src)(line) {
        Ok((_, line)) => {
            headers.insert(line.name, line.value);

            Ok(())
        }
        Err(_) => Err(Error {
            status: Code::BAD_REQUEST,
            error: Some(anyhow!("Invalid Header Line")),
        }),
    }
}
