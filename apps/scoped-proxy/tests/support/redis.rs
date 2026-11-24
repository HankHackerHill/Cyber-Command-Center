use std::net::SocketAddr;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use uuid::Uuid;

const CHANNEL: &str = "redops:killswitch";
const SETUP_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) struct MockRedis(TcpListener);

impl MockRedis {
    pub(crate) async fn start() -> Self {
        Self(TcpListener::bind(("127.0.0.1", 0)).await.unwrap())
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.0.local_addr().unwrap()
    }

    pub(crate) async fn accept_subscription(&self) -> Subscription {
        timeout(SETUP_TIMEOUT, async {
            let (socket, _) = self.0.accept().await.unwrap();
            socket.set_nodelay(true).unwrap();
            let mut conn = BufReader::new(socket);
            loop {
                let count = read_length(&mut conn, '*').await;
                let mut command = Vec::with_capacity(count);
                for _ in 0..count {
                    let size = read_length(&mut conn, '$').await;
                    let mut bulk = vec![0; size + 2];
                    conn.read_exact(&mut bulk).await.unwrap();
                    assert_eq!(&bulk[size..], b"\r\n");
                    bulk.truncate(size);
                    command.push(String::from_utf8(bulk).unwrap());
                }
                match command[0].to_ascii_uppercase().as_str() {
                    // Redis clients can pipeline CLIENT SETINFO during RESP2 setup.
                    "CLIENT" => {
                        assert!(command[1].eq_ignore_ascii_case("SETINFO"));
                        conn.get_mut().write_all(b"+OK\r\n").await.unwrap();
                    }
                    "PING" => conn.get_mut().write_all(b"+PONG\r\n").await.unwrap(),
                    "SUBSCRIBE" => {
                        assert_eq!(&command[1..], &[CHANNEL]);
                        let ack = format!(
                            "*3\r\n$9\r\nsubscribe\r\n${}\r\n{CHANNEL}\r\n:1\r\n",
                            CHANNEL.len()
                        );
                        conn.get_mut().write_all(ack.as_bytes()).await.unwrap();
                        return Subscription(conn.into_inner());
                    }
                    _ => panic!("unexpected mock Redis command: {command:?}"),
                }
            }
        })
        .await
        .expect("mock Redis did not receive SUBSCRIBE")
    }
}

async fn read_length(conn: &mut BufReader<TcpStream>, prefix: char) -> usize {
    let mut line = String::new();
    conn.read_line(&mut line).await.unwrap();
    line.strip_prefix(prefix)
        .unwrap()
        .strip_suffix("\r\n")
        .unwrap()
        .parse()
        .unwrap()
}

pub(crate) struct Subscription(TcpStream);

impl Subscription {
    pub(crate) async fn send_halt(&mut self, id: Uuid) {
        let payload =
            json!({ "engagement_id": id.to_string(), "state": "HALTED_KILLSWITCH" }).to_string();
        let message = format!(
            "*3\r\n$7\r\nmessage\r\n${}\r\n{CHANNEL}\r\n${}\r\n{payload}\r\n",
            CHANNEL.len(),
            payload.len()
        );
        self.0.write_all(message.as_bytes()).await.unwrap();
    }
}
