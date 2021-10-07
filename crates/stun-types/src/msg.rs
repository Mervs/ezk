use super::padding_usize;
use super::COOKIE;
use super::NE;
use crate::attributes::{Attribute, Error};
use crate::padding_u16;
use bitfield::bitfield;
use byteorder::ReadBytesExt;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::Cursor;

bitfield! {
    pub struct MessageHead(u32);

    u8;
    z, _: 31, 30;

    u16;
    typ, set_typ: 29, 16;
    len, set_len: 15, 0;
}

bitfield! {
    pub struct MessageId(u128);

    u32;
    cookie, set_cookie: 127,  96;

    u128;
    tsx_id, set_tsx_id: 95, 0;
}

impl MessageId {
    pub(crate) fn new() -> Self {
        let mut new = Self(0);
        new.set_cookie(COOKIE);
        new
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Class {
    Request,
    Indication,
    Success,
    Error,
}

impl Class {
    const MASK: u16 = 0x110;

    const REQUEST: u16 = 0x000;
    const INDICATION: u16 = 0x010;
    const SUCCESS: u16 = 0x100;
    const ERROR: u16 = 0x110;

    pub fn set(&self, typ: &mut u16) {
        *typ &= Method::MASK;

        match self {
            Class::Request => *typ |= Self::REQUEST,
            Class::Indication => *typ |= Self::INDICATION,
            Class::Success => *typ |= Self::SUCCESS,
            Class::Error => *typ |= Self::ERROR,
        }
    }
}

impl TryFrom<u16> for Class {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Error> {
        match value & Self::MASK {
            Self::REQUEST => Ok(Self::Request),
            Self::INDICATION => Ok(Self::Indication),
            Self::SUCCESS => Ok(Self::Success),
            Self::ERROR => Ok(Self::Error),
            _ => Err(Error::InvalidData("unknown class")),
        }
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Method {
    Binding,
}

impl Method {
    const MASK: u16 = 0x3EEF;

    const BINDING: u16 = 0x1;

    pub fn set(&self, typ: &mut u16) {
        *typ &= Class::MASK;

        match self {
            Method::Binding => *typ |= Self::BINDING,
        }
    }
}

impl TryFrom<u16> for Method {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value & Self::MASK {
            Self::BINDING => Ok(Self::Binding),
            _ => Err(Error::InvalidData("unknown method")),
        }
    }
}

type BuilderFn<'a> = dyn FnOnce(&mut MessageBuilder) -> Result<(), Error> + 'a;

#[derive(Default)]
pub struct AttrInsertQueue<'a> {
    attrs_len: u16,
    builder: Vec<Box<BuilderFn<'a>>>,
}

impl<'a> AttrInsertQueue<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_attr<A>(&mut self, attr: &'a A)
    where
        A: Attribute<Context = ()> + 'a,
    {
        self.add_attr_with(attr, ());
    }

    pub fn add_attr_with<A>(&mut self, attr: &'a A, ctx: A::Context)
    where
        A: Attribute + 'a,
        A::Context: 'a,
    {
        let enc_len = attr.encode_len().expect("Failed to get encode_len");
        let padding = padding_u16(enc_len);

        let f = move |builder: &mut MessageBuilder| -> Result<(), Error> {
            builder.buffer.put_u16(A::TYPE);
            builder.buffer.put_u16(enc_len + padding);

            attr.encode(ctx, builder)?;

            builder
                .buffer
                .extend((0..padding_usize(usize::from(enc_len))).map(|_| 0));

            Ok(())
        };

        self.builder.push(Box::new(f));
        self.attrs_len += 4 + enc_len + padding;
    }
}

pub struct MessageBuilder {
    head: MessageHead,
    id: MessageId,

    buffer: BytesMut,
}

impl MessageBuilder {
    pub fn new(class: Class, method: Method, tsx_id: u128) -> Self {
        let mut typ = 0;
        method.set(&mut typ);
        class.set(&mut typ);

        let mut head = MessageHead(0);
        head.set_typ(typ);

        let mut id = MessageId::new();
        id.set_tsx_id(tsx_id);

        Self {
            head,
            id,
            buffer: BytesMut::new(),
        }
    }

    pub fn finish(mut self, attrs: AttrInsertQueue<'_>) -> Result<Bytes, Error> {
        self.head.set_len(attrs.attrs_len);
        self.buffer.put_u32(self.head.0);
        self.buffer.put_u128(self.id.0);

        for builder in attrs.builder {
            builder(&mut self)?;
        }

        Ok(self.buffer.freeze())
    }

    pub fn head(&self) -> &MessageHead {
        &self.head
    }

    pub fn id(&self) -> &MessageId {
        &self.id
    }

    pub fn buffer(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }
}

pub fn check_if_stun_message(i: &[u8]) -> bool {
    if i.len() < 20 {
        return false;
    }

    let head = i[0..4].try_into().unwrap();
    let head = u32::from_ne_bytes(head);
    let head = MessageHead(head);

    if head.z() != 0 {
        return false;
    }

    let id = i[4..20].try_into().unwrap();
    let id = u128::from_ne_bytes(id);
    let id = MessageId(id);

    if id.cookie() != COOKIE {
        return false;
    }

    false
}

#[derive(Debug)]
pub struct ParsedAttr {
    /// Index where the attribute begins
    pub attr_idx: usize,
    /// Attribute type id
    pub typ: u16,
    /// Attribute value field
    pub value: Bytes,
}

pub struct ParsedMessage {
    buffer: Bytes,

    head: MessageHead,
    id: MessageId,

    pub class: Class,
    pub method: Method,
    pub tsx_id: u128,

    pub attributes: Vec<ParsedAttr>,
}

impl ParsedMessage {
    pub fn parse(input: &Bytes) -> Result<Option<ParsedMessage>, Error> {
        let mut cursor = Cursor::new(input);

        let head = cursor.read_u32::<NE>()?;
        let head = MessageHead(head);

        if head.z() != 0 {
            return Ok(None);
        }

        let id = cursor.read_u128::<NE>()?;
        let id = MessageId(id);

        if id.cookie() != COOKIE {
            return Ok(None);
        }

        let class = Class::try_from(head.typ()).unwrap();
        let method = Method::try_from(head.typ()).unwrap();

        let mut attributes = vec![];

        while cursor.has_remaining() {
            let attr_typ = cursor.read_u16::<NE>()?;
            let attr_len = usize::from(cursor.read_u16::<NE>()?);
            let padding = padding_usize(attr_len);

            let value_begin = usize::try_from(cursor.position())?;
            let value_end = value_begin + attr_len;
            let padding_end = value_end + padding;

            if padding_end > input.len() {
                return Err(Error::InvalidData(
                    "Invalid attribute length in STUN message",
                ));
            }

            let value = input.slice(value_begin..value_end);

            let attr = ParsedAttr {
                attr_idx: value_begin - 4,
                typ: attr_typ,
                value,
            };

            attributes.push(attr);

            cursor.set_position(u64::try_from(padding_end)?);
        }

        let tsx_id = id.tsx_id();

        Ok(Some(ParsedMessage {
            buffer: input.clone(),
            head,
            id,
            class,
            method,
            tsx_id,
            attributes,
        }))
    }

    pub fn get_attr<A>(&self) -> Option<Result<A, Error>>
    where
        A: Attribute<Context = ()>,
    {
        self.get_attr_with(())
    }

    pub fn get_attr_with<A>(&self, ctx: A::Context) -> Option<Result<A, Error>>
    where
        A: Attribute,
    {
        println!("{:X?}", self.attributes);
        let attr = self.attributes.iter().find(|attr| attr.typ == A::TYPE)?;

        Some(A::decode(ctx, self, attr))
    }

    pub fn buffer(&self) -> &Bytes {
        &self.buffer
    }

    pub fn head(&self) -> &MessageHead {
        &self.head
    }

    pub fn id(&self) -> &MessageId {
        &self.id
    }
}
