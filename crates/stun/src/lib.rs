use bytes::Bytes;
use std::net::SocketAddr;
use stun_types::attributes::{
    MessageIntegrity, MessageIntegrityKey, MessageIntegritySha256, Realm, Software, Username,
};
use stun_types::builder::MessageBuilder;
use stun_types::header::{Class, Method};
use stun_types::{transaction_id, Error};

mod uri;

pub enum StunCredential {
    ShortTerm {
        username: String,
        password: String,
    },
    LongTerm {
        realm: String,
        username: String,
        password: String,
    },
}

impl StunCredential {
    fn auth_msg(&mut self, mut msg: MessageBuilder) -> Result<(), Error> {
        match &*self {
            StunCredential::ShortTerm { username, password } => {
                msg.add_attr(&Username::new(username))?;
                msg.add_attr_with(
                    &MessageIntegritySha256::default(),
                    MessageIntegrityKey::new_short_term(password),
                )?;
                msg.add_attr_with(
                    &MessageIntegrity::default(),
                    MessageIntegrityKey::new_short_term(password),
                )?;

                todo!()
            }
            StunCredential::LongTerm {
                realm,
                username,
                password,
            } => {
                msg.add_attr(&Realm::new(realm))?;
                msg.add_attr(&Username::new(username))?;

                todo!()
            }
        }
    }
}

pub struct StunCredentials {
    realm: Option<String>,
    username: String,
    password: String,
    nonce: Option<String>,
}

pub struct StunServer {
    addr: SocketAddr,
}

impl StunServer {
    pub fn new(addr: SocketAddr) -> StunServer {
        Self { addr }
    }
}

pub struct Client {
    server: StunServer,
}

impl Client {
    pub fn new(server: StunServer) -> Self {
        Self { server }
    }

    fn binding_request(&self) -> Bytes {
        let mut message = MessageBuilder::new(Class::Request, Method::Binding, transaction_id());

        message.add_attr(&Software::new("ezk-stun")).unwrap();

        message.finish()
    }
}

#[cfg(test)]
mod test {

    use bytes::BytesMut;
    use stun_types::parse::ParsedMessage;
    use tokio::net::{lookup_host, UdpSocket};

    use super::*;

    #[tokio::test]
    async fn test() {
        let addr = lookup_host("stun.sipgate.net:3478")
            .await
            .unwrap()
            .next()
            .unwrap();

        let client = Client::new(StunServer { addr });

        let binding_request = client.binding_request();
        println!("{:02X?}", &binding_request[..]);

        let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();

        udp.send_to(&binding_request, addr).await.unwrap();

        let mut buf = BytesMut::new();
        buf.resize(65535, 0);

        let (len, remote) = udp.recv_from(&mut buf).await.unwrap();

        buf.truncate(len);

        ParsedMessage::parse(buf).unwrap().unwrap();
    }
}
