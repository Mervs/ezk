use super::{Attribute, Error, NE};
use crate::{padding_usize, MessageBuilder, ParsedAttr, ParsedMessage};
use byteorder::ReadBytesExt;
use bytes::{Buf, BufMut, Bytes};
use std::convert::TryFrom;
use std::io::Cursor;

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.11)
pub struct PasswordAlgorithms {
    algorithms: Vec<(u16, Bytes)>,
}

impl Attribute for PasswordAlgorithms {
    type Context = ();
    const TYPE: u16 = 0x8002;

    fn decode(_: Self::Context, _: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        let mut cursor = Cursor::new(&attr.value);

        let mut algorithms = vec![];

        while cursor.has_remaining() {
            let alg = cursor.read_u16::<NE>()?;
            let len = usize::from(cursor.read_u16::<NE>()?);

            let pos = usize::try_from(cursor.position())?;

            if attr.value.len() < pos + len {
                return Err(Error::InvalidData("invalid algorithm len"));
            }

            let params = attr.value.slice(pos..pos + len);

            algorithms.push((alg, params));
        }

        Ok(Self { algorithms })
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        for (alg, params) in &self.algorithms {
            let padding = padding_usize(params.len());

            builder.buffer().put_u16(*alg);
            builder.buffer().put_u16(u16::try_from(params.len())?);
            builder.buffer().extend_from_slice(params);
            builder.buffer().extend((0..padding).map(|_| 0));
        }

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        let mut len = 0;

        for (_, params) in &self.algorithms {
            len += 4;
            len += params.len();
            len += padding_usize(params.len());
        }

        Ok(u16::try_from(len)?)
    }
}
