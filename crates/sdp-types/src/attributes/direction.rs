//! Media direction attribute (`a=sendrecv`, `a=recvonly`, `a=sendonly`, `a=inactive`)

use std::fmt;

/// Media direction attribute
///
/// Session and Media Level attribute.  
/// If the direction is specified at the session level but not as media level
/// the direction of the session is used for the media
///
/// > If not specified at all `sendrecv` is assumed by default
///
/// [RFC8866](https://www.rfc-editor.org/rfc/rfc8866.html#section-6.7)
#[derive(Debug, Copy, Clone)]
pub enum Direction {
    /// Send and receive media data
    SendRecv,

    /// Only receive media data
    RecvOnly,

    /// Only send media data
    SendOnly,

    /// Media is inactive not sending any data
    Inactive,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::SendRecv => "sendrecv",
            Direction::RecvOnly => "recvonly",
            Direction::SendOnly => "sendonly",
            Direction::Inactive => "inactive",
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a={}", self.as_str())
    }
}

impl Default for Direction {
    fn default() -> Self {
        Direction::SendRecv
    }
}
