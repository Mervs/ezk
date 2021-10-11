use crate::attributes::Attribute;
use crate::header::{Class, MessageHead, MessageId, Method};
use crate::{padding_u16, padding_usize, Error};
use bytes::{BufMut, Bytes, BytesMut};
use std::convert::TryFrom;

pub struct MessageBuilder {
    head: MessageHead,
    id: MessageId,

    padding_in_value_len: bool,

    buffer: BytesMut,
}

impl MessageBuilder {
    pub fn new(class: Class, method: Method, tsx_id: u128) -> Self {
        let mut buffer = BytesMut::new();

        let mut typ = 0;
        method.set(&mut typ);
        class.set(&mut typ);

        let mut head = MessageHead(0);
        head.set_typ(typ);
        buffer.put_u32(head.0);

        let mut id = MessageId::new();
        id.set_tsx_id(tsx_id);
        buffer.put_u128(id.0);

        Self {
            head,
            padding_in_value_len: true,
            id,
            buffer,
        }
    }

    pub fn padding_in_value_len(&mut self, b: bool) {
        self.padding_in_value_len = b;
    }

    pub fn id(&self) -> &MessageId {
        &self.id
    }

    fn set_len(&mut self, len: u16) {
        self.head.set_len(len);

        let [b0, b1, b2, b3] = u32::to_ne_bytes(self.head.0);

        self.buffer[0] = b3;
        self.buffer[1] = b2;
        self.buffer[2] = b1;
        self.buffer[3] = b0;
    }

    pub fn add_attr<'a, A>(&mut self, attr: &A) -> Result<(), Error>
    where
        A: Attribute<'a, Context = ()>,
    {
        self.add_attr_with(attr, ())
    }

    pub fn add_attr_with<'a, A>(&mut self, attr: &A, ctx: A::Context) -> Result<(), Error>
    where
        A: Attribute<'a>,
    {
        let enc_len = attr.encode_len().expect("Failed to get encode_len");
        let padding = padding_u16(enc_len);

        self.buffer.put_u16(A::TYPE);

        if self.padding_in_value_len {
            self.buffer.put_u16(enc_len + padding);
        } else {
            self.buffer.put_u16(enc_len);
        }

        // set len before each encode for integrity attributes
        self.set_len(u16::try_from(self.buffer.len() - 20)? + enc_len + padding);

        attr.encode(ctx, self)?;

        let padding_bytes = std::iter::repeat(0).take(padding_usize(usize::from(enc_len)));
        self.buffer.extend(padding_bytes);

        Ok(())
    }

    pub fn finish(self) -> Bytes {
        self.buffer.freeze()
    }

    pub fn buffer(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }
}
