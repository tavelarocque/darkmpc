//! Mutually authenticated TLS 1.3 links between the three servers (rustls,
//! ring provider).
//!
//! Each ordered pair of servers gets its own connection: server i connects
//! to j to *send* to j, and accepts j's connection to *receive* from j. A
//! sending half is a writer thread fed by a queue, so a send never blocks the
//! protocol. Every certificate is signed by a deployment CA made by `setup`.
//! On top of CA verification (and the server-name check rustls does on the
//! connecting side), each side pins the peer's exact certificate, so a
//! connection is only accepted as "server j" if it presents server j's
//! certificate.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use darkmpc_mpc::prf::Key;
use darkmpc_mpc::{Net, NetModel, RecvHalf, SendHalf};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};

/// Create ca.der and server{i}.der / server{i}.key for i = 0, 1, 2.
pub fn setup(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    fs::write(dir.join("ca.der"), ca_cert.der()).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    for i in 0..3 {
        let mut p = CertificateParams::new(vec![format!("server{i}")]).unwrap();
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        let key = KeyPair::generate().unwrap();
        let cert = p.signed_by(&key, &issuer).unwrap();
        fs::write(dir.join(format!("server{i}.der")), cert.der()).unwrap();
        fs::write(dir.join(format!("server{i}.key")), key.serialize_der()).unwrap();
    }
    println!("wrote a deployment CA and three server certificates to {}", dir.display());
}

type InStream = StreamOwned<ServerConnection, TcpStream>;
type OutStream = StreamOwned<ClientConnection, TcpStream>;

/// The four halves of one server's links, before they become a `Net`.
pub struct Links {
    id: usize,
    send: [Option<Box<dyn SendHalf>>; 3],
    recv: [Option<Box<dyn RecvHalf>>; 3],
    writers: Vec<JoinHandle<()>>,
}

struct TlsSend(Sender<Vec<u64>>);
impl SendHalf for TlsSend {
    fn send(&mut self, msg: Vec<u64>) {
        self.0.send(msg).expect("writer thread gone");
    }
}

struct TlsRecv(InStream);
impl RecvHalf for TlsRecv {
    fn recv(&mut self) -> Vec<u64> {
        let mut len = [0u8; 8];
        self.0.read_exact(&mut len).expect("peer closed the connection");
        let n = u64::from_le_bytes(len) as usize;
        let mut buf = vec![0u8; 8 * n];
        self.0.read_exact(&mut buf).expect("peer closed the connection");
        buf.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
    }
}

/// ENOBUFS: the kernel is temporarily out of buffer space. macOS returns it
/// on loopback under heavy traffic; it is transient, not a broken link.
#[cfg(target_os = "macos")]
const ENOBUFS: i32 = 55;
#[cfg(not(target_os = "macos"))]
const ENOBUFS: i32 = 105; // Linux

fn transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) || e.raw_os_error() == Some(ENOBUFS)
}

/// Write all of `buf` in 64 KiB pieces and flush, retrying transient errors
/// for up to 60 s. Safe with rustls: `write` either fails before consuming
/// any bytes or consumes them and reports transport errors on the next call,
/// and `flush` consumes nothing (rustls 0.23 src/stream.rs), so a retry never
/// sends data twice.
pub(crate) fn write_all_retrying<W: Write>(w: &mut W, mut buf: &[u8]) -> std::io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    let pause = || std::thread::sleep(Duration::from_millis(1));
    while !buf.is_empty() {
        let piece = &buf[..buf.len().min(64 * 1024)];
        match w.write(piece) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => buf = &buf[n..],
            Err(e) if transient(&e) && Instant::now() < deadline => pause(),
            Err(e) => return Err(e),
        }
    }
    loop {
        match w.flush() {
            Ok(()) => return Ok(()),
            Err(e) if transient(&e) && Instant::now() < deadline => pause(),
            Err(e) => return Err(e),
        }
    }
}

fn spawn_writer(mut stream: OutStream) -> (TlsSend, JoinHandle<()>) {
    let (tx, rx) = channel::<Vec<u64>>();
    let h = std::thread::spawn(move || {
        for msg in rx {
            let mut buf = Vec::with_capacity(8 * (msg.len() + 1));
            buf.extend_from_slice(&(msg.len() as u64).to_le_bytes());
            for w in &msg {
                buf.extend_from_slice(&w.to_le_bytes());
            }
            write_all_retrying(&mut stream, &buf).expect("send failed");
        }
        stream.conn.send_close_notify();
        let _ = write_all_retrying(&mut stream, &[]);
    });
    (TlsSend(tx), h)
}

/// Establish all four connections for server `id`.
pub fn connect(dir: &Path, id: usize, addrs: &[String]) -> Links {
    let read = |name: String| fs::read(dir.join(&name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    let peer_der: Vec<Vec<u8>> = (0..3).map(|i| read(format!("server{i}.der"))).collect();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(read("ca.der".into()))).unwrap();
    let roots = Arc::new(roots);
    let chain = vec![CertificateDer::from(peer_der[id].clone())];
    let key = || PrivateKeyDer::from(PrivatePkcs8KeyDer::from(read(format!("server{id}.key"))));
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut server_cfg = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone()).build().unwrap(),
        )
        .with_single_cert(chain.clone(), key())
        .unwrap();
    // No session tickets: the connecting side never reads after the
    // handshake, and unread tickets make its close a TCP reset, which can
    // destroy data still queued at the peer.
    server_cfg.send_tls13_tickets = 0;
    let server_cfg = Arc::new(server_cfg);
    let client_cfg = Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key())
            .unwrap(),
    );

    // Accept the two inbound connections in the background.
    let listener = TcpListener::bind(&addrs[id]).unwrap_or_else(|e| panic!("bind {}: {e}", addrs[id]));
    let peers_in = peer_der.clone();
    let acceptor = std::thread::spawn(move || {
        let mut got: [Option<InStream>; 3] = [None, None, None];
        for _ in 0..2 {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_nodelay(true).unwrap();
            let mut conn = ServerConnection::new(server_cfg.clone()).unwrap();
            while conn.is_handshaking() {
                conn.complete_io(&mut sock).expect("TLS handshake failed");
            }
            let presented = conn.peer_certificates().and_then(|c| c.first()).expect("no client certificate");
            let j = (0..3)
                .find(|&j| j != id && presented.as_ref() == peers_in[j].as_slice())
                .expect("client certificate is not a pinned peer certificate");
            assert!(got[j].is_none(), "server {j} connected twice");
            got[j] = Some(StreamOwned::new(conn, sock));
        }
        got
    });

    // Connect out to both peers, retrying while they start up.
    let mut send: [Option<Box<dyn SendHalf>>; 3] = [None, None, None];
    let mut writers = Vec::new();
    for j in (0..3).filter(|&j| j != id) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut sock = loop {
            match TcpStream::connect(&addrs[j]) {
                Ok(s) => break s,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => panic!("connect to server {j} at {}: {e}", addrs[j]),
            }
        };
        sock.set_nodelay(true).unwrap();
        let name = ServerName::try_from(format!("server{j}")).unwrap();
        let mut conn = ClientConnection::new(client_cfg.clone(), name).unwrap();
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).expect("TLS handshake failed");
        }
        let presented = conn.peer_certificates().and_then(|c| c.first()).expect("no server certificate");
        assert_eq!(presented.as_ref(), peer_der[j].as_slice(), "server {j} presented an unpinned certificate");
        let (half, h) = spawn_writer(StreamOwned::new(conn, sock));
        send[j] = Some(Box::new(half));
        writers.push(h);
    }

    let got = acceptor.join().expect("accept thread panicked");
    let recv = got.map(|s| s.map(|s| Box::new(TlsRecv(s)) as Box<dyn RecvHalf>));
    Links { id, send, recv, writers }
}

/// Agree the pairwise PRF keys over the links, then build the `Net`.
/// Server i holds k_i (shared with i-1) and k_{i+1} (shared with i+1): it
/// draws k_{i+1} itself, sends it to i+1, and receives k_i from i-1.
pub fn into_net(mut l: Links, model: Option<NetModel>) -> (Net, Key, Key, Vec<JoinHandle<()>>) {
    let (n, p) = ((l.id + 1) % 3, (l.id + 2) % 3);
    let mut to_next = l.send[n].take().unwrap();
    let to_prev = l.send[p].take().unwrap();
    let from_next = l.recv[n].take().unwrap();
    let mut from_prev = l.recv[p].take().unwrap();

    let k_next = darkmpc_mpc::prf::random_key();
    to_next.send(vec![
        u64::from_le_bytes(k_next[..8].try_into().unwrap()),
        u64::from_le_bytes(k_next[8..].try_into().unwrap()),
    ]);
    let w = from_prev.recv();
    let mut k_own = [0u8; 16];
    k_own[..8].copy_from_slice(&w[0].to_le_bytes());
    k_own[8..].copy_from_slice(&w[1].to_le_bytes());

    let net = Net::new(to_next, to_prev, from_next, from_prev, model);
    (net, k_own, k_next, l.writers)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that fails with ENOBUFS every other call, like a congested
    /// loopback socket, and accepts at most 1000 bytes per write.
    struct Flaky {
        got: Vec<u8>,
        calls: u32,
    }
    impl Write for Flaky {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.calls.is_multiple_of(2) {
                return Err(std::io::Error::from_raw_os_error(ENOBUFS));
            }
            let n = b.len().min(1000);
            self.got.extend_from_slice(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.calls += 1;
            if self.calls.is_multiple_of(2) { Err(std::io::Error::from_raw_os_error(ENOBUFS)) } else { Ok(()) }
        }
    }

    #[test]
    fn transient_errors_deliver_every_byte_exactly_once() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7) as u8).collect();
        let mut f = Flaky { got: Vec::new(), calls: 0 };
        write_all_retrying(&mut f, &data).unwrap();
        assert_eq!(f.got, data);
    }

    #[test]
    fn permanent_errors_are_not_retried() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(write_all_retrying(&mut Broken, b"x").is_err());
    }
}
