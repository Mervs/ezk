use super::{Attribute, Error};
use crate::{MessageBuilder, ParsedAttr, ParsedMessage};
use bitfield::bitfield;
use bytes::BufMut;
use bytesstr::BytesStr;
use std::convert::TryFrom;
use std::io;

bitfield! {
    struct ErrorCodeHead(u32);
    number, set_number: 7, 0;
    class, set_class: 11, 8;
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.8)
pub struct ErrorCode {
    pub number: u32,
    pub reason: BytesStr,
}

impl Attribute for ErrorCode {
    type Context = ();
    const TYPE: u16 = 0x0009;

    fn decode(_: Self::Context, _: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        if attr.value.len() < 4 {
            return Err(Error::InvalidData("error code must be at least 4 bytes"));
        }

        let head = u32::from_ne_bytes([attr.value[0], attr.value[1], attr.value[2], attr.value[3]]);
        let head = ErrorCodeHead(head);

        let reason = if attr.value.len() > 4 {
            BytesStr::from_utf8_bytes(attr.value.slice(4..))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        } else {
            BytesStr::empty()
        };

        Ok(Self {
            number: head.class() * 100 + head.number(),
            reason,
        })
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        let class = self.number / 100;
        let number = self.number % 100;

        let mut head = ErrorCodeHead(0);

        head.set_class(class);
        head.set_number(number);

        builder.buffer().put_u32(head.0);
        builder.buffer().extend_from_slice(self.reason.as_ref());

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(4 + self.reason.len())?)
    }
}
