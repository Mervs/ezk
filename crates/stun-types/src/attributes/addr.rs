use super::{Attribute, Error};
use crate::{MessageBuilder, ParsedAttr, ParsedMessage, COOKIE, NE};
use byteorder::ReadBytesExt;
use bytes::{BufMut, Bytes, BytesMut};
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

const XOR16: u16 = (COOKIE & 0xFFFF) as u16;

fn decode_addr(buf: &Bytes, xor16: u16, xor32: u32, xor128: u128) -> Result<SocketAddr, Error> {
    let mut cursor = Cursor::new(buf);

    if cursor.read_u8()? != 0 {
        return Err(Error::InvalidData("first byte must be zero"));
    }

    let family = cursor.read_u8()?;
    let port = cursor.read_u16::<NE>()? ^ xor16;

    let addr = match family {
        1 => {
            let ip = cursor.read_u32::<NE>()? ^ xor32;
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
        }
        2 => {
            let ip = cursor.read_u128::<NE>()? ^ xor128;
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0))
        }
        _ => {
            return Err(Error::InvalidData("invalid address family"));
        }
    };

    Ok(addr)
}

fn encode_addr(addr: SocketAddr, buf: &mut BytesMut, xor16: u16, xor32: u32, xor128: u128) {
    buf.put_u8(0);

    match addr {
        SocketAddr::V4(addr) => {
            buf.put_u8(1);
            buf.put_u16(addr.port() ^ xor16);

            let ip = u32::from_ne_bytes(addr.ip().octets());
            let ip = ip ^ xor32;

            buf.put_u32(ip);
        }
        SocketAddr::V6(addr) => {
            buf.put_u8(2);
            buf.put_u16(addr.port() ^ xor16);

            let ip = u128::from_ne_bytes(addr.ip().octets());
            let ip = ip ^ xor128;

            buf.put_u128(ip);
        }
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.1)
pub struct MappedAddress(pub SocketAddr);

impl Attribute for MappedAddress {
    type Context = ();

    const TYPE: u16 = 0x0001;

    fn decode(_: Self::Context, _: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        decode_addr(&attr.value, 0, 0, 0).map(Self)
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        encode_addr(self.0, builder.buffer(), 0, 0, 0);
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        match self.0 {
            SocketAddr::V4(_) => Ok(64),
            SocketAddr::V6(_) => Ok(160),
        }
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.3)
pub struct XorMappedAddress(pub SocketAddr);

impl Attribute for XorMappedAddress {
    type Context = ();
    const TYPE: u16 = 0x0020;

    fn decode(_: Self::Context, msg: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        let xor128 = msg.id().0;
        decode_addr(&attr.value, XOR16, COOKIE, xor128).map(Self)
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        let xor128 = builder.id().0;
        encode_addr(self.0, builder.buffer(), XOR16, COOKIE, xor128);
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        match self.0 {
            SocketAddr::V4(_) => Ok(64),
            SocketAddr::V6(_) => Ok(160),
        }
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.15)
pub struct AlternateServer(pub SocketAddr);

impl Attribute for AlternateServer {
    type Context = ();
    const TYPE: u16 = 0x8023;

    fn decode(_: Self::Context, _: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        decode_addr(&attr.value, 0, 0, 0).map(Self)
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        encode_addr(self.0, builder.buffer(), 0, 0, 0);
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        match self.0 {
            SocketAddr::V4(_) => Ok(64),
            SocketAddr::V6(_) => Ok(160),
        }
    }
}
