use bytes::Bytes;
use bytesstr::BytesStr;
use std::net::SocketAddr;
use stun_types::{
    attributes::Software, transaction_id, AttrInsertQueue, Class, MessageBuilder, Method,
};

mod uri;

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
        let message = MessageBuilder::new(Class::Request, Method::Binding, transaction_id());
        let software = Software(BytesStr::from_static("ezk-stun"));

        let mut attrs = AttrInsertQueue::new();
        attrs.add_attr(&software);

        message.finish(attrs).unwrap()
    }
}

#[cfg(test)]
mod test {

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

        let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();

        udp.send_to(&binding_request, addr).await.unwrap();

        let mut buf = vec![0; 65535];
        let (len, remote) = udp.recv_from(&mut buf).await.unwrap();

        println!("{:02X?}", &buf[..len]);
    }
}
