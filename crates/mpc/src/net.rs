//! Point-to-point links between the three parties.
//!
//! A party talks to its two neighbours through a sending half and a
//! receiving half per neighbour. The protocol code only sees [`Net`]; what
//! carries the bytes is pluggable: in-memory channels for tests
//! ([`Net::triangle`]) or TLS connections between processes (the
//! `darkmpc-server` crate). Sends never block the protocol (each sending half
//! queues), which is what keeps three parties that all send before they
//! receive from deadlocking on full socket buffers.
//!
//! Every send is counted, so tests can assert the communication cost of each
//! operation, and every received message can be recorded so leakage tests
//! can inspect a party's view.
//!
//! [`NetModel`] optionally simulates a network: each link behaves like a pipe
//! with a fixed one-way latency and bandwidth. The sender stamps each message
//! with the time it would finish arriving; the receiver waits until then.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Bytes this party has sent (payload only, excluding simulation stamps).
    pub bytes_sent: u64,
    /// Communication rounds this party has taken part in.
    pub rounds: u64,
}

/// The sending half of a link. Must not block on the peer.
pub trait SendHalf: Send {
    fn send(&mut self, msg: Vec<u64>);
}

/// The receiving half of a link. Blocks until a whole message has arrived.
pub trait RecvHalf: Send {
    fn recv(&mut self) -> Vec<u64>;
}

impl SendHalf for Sender<Vec<u64>> {
    fn send(&mut self, msg: Vec<u64>) {
        Sender::send(self, msg).expect("peer hung up");
    }
}

impl RecvHalf for Receiver<Vec<u64>> {
    fn recv(&mut self) -> Vec<u64> {
        Receiver::recv(self).expect("peer hung up")
    }
}

/// A simulated link: one-way latency plus a bandwidth cap per direction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NetModel {
    pub one_way_latency: Duration,
    /// Bytes per second; f64::INFINITY for no cap.
    pub bandwidth: f64,
}

impl NetModel {
    /// Round-trip time and bandwidth in megabits per second.
    pub fn new(rtt: Duration, mbps: f64) -> Self {
        NetModel { one_way_latency: rtt / 2, bandwidth: mbps * 1e6 / 8.0 }
    }
}

fn now_ns() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock before 1970").as_nanos()
}

/// Wraps a sending half: models the pipe and prepends the arrival time.
struct ModelSend {
    inner: Box<dyn SendHalf>,
    model: NetModel,
    free_at_ns: u128,
}

impl SendHalf for ModelSend {
    fn send(&mut self, mut msg: Vec<u64>) {
        let bytes = 8.0 * msg.len() as f64;
        let depart = now_ns().max(self.free_at_ns);
        let transmit = if self.model.bandwidth.is_finite() { (bytes / self.model.bandwidth * 1e9) as u128 } else { 0 };
        self.free_at_ns = depart + transmit;
        let arrive = self.free_at_ns + self.model.one_way_latency.as_nanos();
        msg.push((arrive >> 64) as u64);
        msg.push(arrive as u64);
        self.inner.send(msg);
    }
}

/// Wraps a receiving half: waits until the stamped arrival time.
struct ModelRecv {
    inner: Box<dyn RecvHalf>,
}

impl RecvHalf for ModelRecv {
    fn recv(&mut self) -> Vec<u64> {
        let mut msg = self.inner.recv();
        let lo = msg.pop().expect("missing stamp") as u128;
        let hi = msg.pop().expect("missing stamp") as u128;
        let arrive = (hi << 64) | lo;
        let now = now_ns();
        if arrive > now {
            std::thread::sleep(Duration::from_nanos((arrive - now) as u64));
        }
        msg
    }
}

fn wrap_send(h: Box<dyn SendHalf>, model: Option<NetModel>) -> Box<dyn SendHalf> {
    match model {
        None => h,
        Some(m) => Box::new(ModelSend { inner: h, model: m, free_at_ns: 0 }),
    }
}

fn wrap_recv(h: Box<dyn RecvHalf>, model: Option<NetModel>) -> Box<dyn RecvHalf> {
    match model {
        None => h,
        Some(_) => Box::new(ModelRecv { inner: h }),
    }
}

pub struct Net {
    to_next: Box<dyn SendHalf>,
    to_prev: Box<dyn SendHalf>,
    from_next: Box<dyn RecvHalf>,
    from_prev: Box<dyn RecvHalf>,
    pub stats: Stats,
    /// If set, every received message is appended here (the party's view).
    pub transcript: Option<Vec<Vec<u64>>>,
}

impl Net {
    /// Build from the four halves. With a model, every link is simulated;
    /// all three parties must use the same setting.
    pub fn new(
        to_next: Box<dyn SendHalf>,
        to_prev: Box<dyn SendHalf>,
        from_next: Box<dyn RecvHalf>,
        from_prev: Box<dyn RecvHalf>,
        model: Option<NetModel>,
    ) -> Net {
        let to_next = wrap_send(to_next, model);
        let to_prev = wrap_send(to_prev, model);
        let from_next = wrap_recv(from_next, model);
        let from_prev = wrap_recv(from_prev, model);
        Net { to_next, to_prev, from_next, from_prev, stats: Stats::default(), transcript: None }
    }

    /// Three connected in-memory endpoints; endpoint i is party i.
    pub fn triangle() -> [Net; 3] {
        Self::triangle_with(None)
    }

    /// Three in-memory endpoints with an optional simulated network.
    pub fn triangle_with(model: Option<NetModel>) -> [Net; 3] {
        // tx[a][b] / rx[a][b] carry messages from party a to party b.
        let mut tx: Vec<Vec<Option<Sender<Vec<u64>>>>> = (0..3).map(|_| (0..3).map(|_| None).collect()).collect();
        let mut rx: Vec<Vec<Option<Receiver<Vec<u64>>>>> = (0..3).map(|_| (0..3).map(|_| None).collect()).collect();
        for a in 0..3 {
            for b in 0..3 {
                if a != b {
                    let (s, r) = channel();
                    tx[a][b] = Some(s);
                    rx[a][b] = Some(r);
                }
            }
        }
        [0, 1, 2].map(|i| {
            let (n, p) = ((i + 1) % 3, (i + 2) % 3);
            Net::new(
                Box::new(tx[i][n].take().unwrap()),
                Box::new(tx[i][p].take().unwrap()),
                Box::new(rx[n][i].take().unwrap()),
                Box::new(rx[p][i].take().unwrap()),
                model,
            )
        })
    }

    fn record(&mut self, m: &[u64]) {
        if let Some(t) = self.transcript.as_mut() {
            t.push(m.to_vec());
        }
    }

    /// One round: send `msg` to the previous party, receive from the next.
    /// (The resharing step of multiplication.)
    pub fn to_prev_from_next(&mut self, msg: Vec<u64>) -> Vec<u64> {
        self.stats.rounds += 1;
        self.send_prev(msg);
        self.recv_next()
    }

    /// One round: send `msg` to the next party, receive from the previous.
    /// (Opening: each party forwards the summand its successor lacks.)
    pub fn to_next_from_prev(&mut self, msg: Vec<u64>) -> Vec<u64> {
        self.stats.rounds += 1;
        self.send_next(msg);
        self.recv_prev()
    }

    /// One-way send to the next party (counts bytes, not rounds).
    pub fn send_next(&mut self, msg: Vec<u64>) {
        self.stats.bytes_sent += 8 * msg.len() as u64;
        self.to_next.send(msg);
    }

    /// One-way send to the previous party (counts bytes, not rounds).
    pub fn send_prev(&mut self, msg: Vec<u64>) {
        self.stats.bytes_sent += 8 * msg.len() as u64;
        self.to_prev.send(msg);
    }

    pub fn recv_next(&mut self) -> Vec<u64> {
        let m = self.from_next.recv();
        self.record(&m);
        m
    }

    pub fn recv_prev(&mut self) -> Vec<u64> {
        let m = self.from_prev.recv();
        self.record(&m);
        m
    }
}
