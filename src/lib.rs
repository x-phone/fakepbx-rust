//! In-process SIP server (UAS) for testing.
//!
//! Wraps a UDP socket to create a real SIP server bound to `127.0.0.1` on an
//! ephemeral port. Tests get full programmatic control over SIP call flows
//! — REGISTER, INVITE, BYE, CANCEL, REFER, OPTIONS, INFO, MESSAGE, SUBSCRIBE —
//! without Docker, external processes, or hardcoded ports.
//!
//! # Basic usage
//!
//! ```no_run
//! use fakepbx::{FakePBX, sdp};
//!
//! let pbx = FakePBX::new(&[]);
//! pbx.on_invite(|inv| {
//!     inv.trying();
//!     inv.ringing();
//!     inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
//! });
//! // Point your SIP UA at pbx.addr() and dial pbx.uri("1002")
//! // The server stops when the FakePBX is dropped.
//! ```

pub mod handlers;
pub mod recorded;
pub mod sdp;
pub mod sip;

use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use parking_lot::Mutex;

pub use handlers::*;
pub use recorded::RecordedRequest;

use recorded::Recorder;

/// Configuration option for FakePBX.
pub enum Opt {
    /// Sets the expected digest auth credentials.
    Auth { username: String, password: String },
}

/// Creates an `Opt::Auth` option.
pub fn with_auth(username: &str, password: &str) -> Opt {
    Opt::Auth {
        username: username.to_string(),
        password: password.to_string(),
    }
}

type HandlerFn<T> = Arc<dyn Fn(&T) + Send + Sync>;

struct Handlers {
    on_register: Option<HandlerFn<Register>>,
    on_invite: Option<HandlerFn<Invite>>,
    on_bye: Option<HandlerFn<Bye>>,
    on_cancel: Option<HandlerFn<Cancel>>,
    on_ack: Option<HandlerFn<Ack>>,
    on_refer: Option<HandlerFn<Refer>>,
    on_options: Option<HandlerFn<Options>>,
    on_info: Option<HandlerFn<Info>>,
    on_message: Option<HandlerFn<Message>>,
    on_subscribe: Option<HandlerFn<Subscribe>>,
}

/// An in-process SIP UAS for testing.
pub struct FakePBX {
    #[allow(dead_code)]
    socket: Arc<UdpSocket>,
    addr: String,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    handlers: Arc<Mutex<Handlers>>,
    recorder: Arc<Recorder>,
    #[allow(dead_code)]
    auth_username: String,
    #[allow(dead_code)]
    auth_password: String,
    #[allow(dead_code)]
    auth_nonces: Arc<Mutex<HashMap<String, bool>>>,
    /// Tracks active INVITE transactions by Via branch for CANCEL matching.
    #[allow(dead_code)]
    invite_cancels: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

impl FakePBX {
    /// Creates and starts a FakePBX on `127.0.0.1:0` (ephemeral port).
    pub fn new(opts: &[Opt]) -> Self {
        let mut auth_username = String::new();
        let mut auth_password = String::new();
        for opt in opts {
            match opt {
                Opt::Auth { username, password } => {
                    auth_username = username.clone();
                    auth_password = password.clone();
                }
            }
        }

        let socket = UdpSocket::bind("127.0.0.1:0").expect("fakepbx: failed to bind UDP socket");
        let addr = socket.local_addr().unwrap().to_string();
        let socket = Arc::new(socket);

        let handlers = Arc::new(Mutex::new(Handlers {
            on_register: None,
            on_invite: None,
            on_bye: None,
            on_cancel: None,
            on_ack: None,
            on_refer: None,
            on_options: None,
            on_info: None,
            on_message: None,
            on_subscribe: None,
        }));

        let recorder = Arc::new(Recorder::new());
        let running = Arc::new(AtomicBool::new(true));
        let auth_nonces = Arc::new(Mutex::new(HashMap::new()));
        let invite_cancels: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let thread = {
            let socket = Arc::clone(&socket);
            let handlers = Arc::clone(&handlers);
            let recorder = Arc::clone(&recorder);
            let running = Arc::clone(&running);
            let auth_nonces = Arc::clone(&auth_nonces);
            let invite_cancels = Arc::clone(&invite_cancels);
            let auth_user = auth_username.clone();
            let auth_pass = auth_password.clone();
            let local_addr = addr.clone();

            std::thread::spawn(move || {
                let _ = socket.set_read_timeout(Some(std::time::Duration::from_millis(100)));
                let mut buf = [0u8; 65535];
                while running.load(Ordering::SeqCst) {
                    let (n, remote) = match socket.recv_from(&mut buf) {
                        Ok(r) => r,
                        Err(_) => continue, // timeout, check running flag
                    };

                    let msg = match sip::parse(&buf[..n]) {
                        Some(m) if m.is_request() => m,
                        _ => continue,
                    };

                    recorder.record(&msg.method, msg.clone());

                    let method = msg.method.clone();
                    let h = handlers.lock();

                    match method.as_str() {
                        "REGISTER" => {
                            let reg = Register {
                                req: msg,
                                socket: Arc::clone(&socket),
                                remote,
                                responded: AtomicBool::new(false),
                            };
                            if let Some(ref handler) = h.on_register {
                                let handler = Arc::clone(handler);
                                drop(h);
                                handler(&reg);
                            } else if !auth_user.is_empty() {
                                drop(h);
                                handle_auth_register(&reg, &auth_user, &auth_pass, &auth_nonces);
                            } else {
                                drop(h);
                                reg.accept();
                            }
                        }
                        "INVITE" => {
                            let cancel_flag = Arc::new(AtomicBool::new(false));
                            // Track by Via branch for CANCEL matching.
                            if let Some(branch) = msg.via_branch() {
                                invite_cancels
                                    .lock()
                                    .insert(branch, Arc::clone(&cancel_flag));
                            }
                            let inv = Invite {
                                req: msg,
                                socket: Arc::clone(&socket),
                                remote,
                                local_addr: local_addr.clone(),
                                responded_final: AtomicBool::new(false),
                                cancel_flag,
                                to_tag: Mutex::new(None),
                            };
                            if let Some(ref handler) = h.on_invite {
                                let handler = Arc::clone(handler);
                                drop(h);
                                handler(&inv);
                            } else {
                                drop(h);
                                // Default: auto-answer.
                                inv.trying();
                                let default_sdp = sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]);
                                inv.answer(&default_sdp);
                            }
                        }
                        "ACK" => {
                            let ack = Ack { req: msg };
                            if let Some(ref handler) = h.on_ack {
                                let handler = Arc::clone(handler);
                                drop(h);
                                handler(&ack);
                            } else {
                                drop(h);
                            }
                        }
                        "BYE" => {
                            let bye = Bye {
                                req: msg,
                                socket: Arc::clone(&socket),
                                remote,
                                responded: AtomicBool::new(false),
                            };
                            if let Some(ref handler) = h.on_bye {
                                let handler = Arc::clone(handler);
                                drop(h);
                                handler(&bye);
                            } else {
                                drop(h);
                                bye.accept();
                            }
                        }
                        "CANCEL" => {
                            // Auto-respond 200 OK to CANCEL.
                            let resp = sip::new_response(&msg, 200, "OK");
                            let _ = socket.send_to(&resp.to_bytes(), remote);

                            // Signal the matching INVITE's cancel_flag.
                            if let Some(branch) = msg.via_branch() {
                                if let Some(flag) = invite_cancels.lock().remove(&branch) {
                                    flag.store(true, Ordering::SeqCst);
                                }
                            }

                            // Also send 487 Request Terminated for the INVITE.
                            let mut term = sip::new_response(&msg, 487, "Request Terminated");
                            // Fix CSeq method to INVITE (CANCEL CSeq has method CANCEL).
                            if let Some(cseq) = msg.cseq_num() {
                                term.set_header("CSeq", &format!("{} INVITE", cseq));
                            }
                            let _ = socket.send_to(&term.to_bytes(), remote);

                            let cancel = Cancel { req: msg };
                            if let Some(ref handler) = h.on_cancel {
                                let handler = Arc::clone(handler);
                                drop(h);
                                handler(&cancel);
                            } else {
                                drop(h);
                            }
                        }
                        "REFER" => {
                            let refer = Refer {
                                req: msg,
                                socket: Arc::clone(&socket),
                                remote,
                                responded: AtomicBool::new(false),
                            };
                            if let Some(ref handler) = h.on_refer {
                                let handler = Arc::clone(handler);
                                drop(h);
                                handler(&refer);
                            } else {
                                drop(h);
                                refer.accept();
                            }
                        }
                        "OPTIONS" => {
                            let opt = Options {
                                req: msg,
                                socket: Arc::clone(&socket),
                                remote,
                                responded: AtomicBool::new(false),
                            };
                            if let Some(ref handler) = h.on_options {
                                let handler = Arc::clone(handler);
                                drop(h);
                                handler(&opt);
                            } else {
                                drop(h);
                                opt.accept();
                            }
                        }
                        "INFO" => {
                            let info = Info {
                                req: msg,
                                socket: Arc::clone(&socket),
                                remote,
                                responded: AtomicBool::new(false),
                            };
                            if let Some(ref handler) = h.on_info {
                                let handler = Arc::clone(handler);
                                drop(h);
                                handler(&info);
                            } else {
                                drop(h);
                                info.accept();
                            }
                        }
                        "MESSAGE" => {
                            let message = Message {
                                req: msg,
                                socket: Arc::clone(&socket),
                                remote,
                                responded: AtomicBool::new(false),
                            };
                            if let Some(ref handler) = h.on_message {
                                let handler = Arc::clone(handler);
                                drop(h);
                                handler(&message);
                            } else {
                                drop(h);
                                message.accept();
                            }
                        }
                        "SUBSCRIBE" => {
                            let sub = Subscribe {
                                req: msg,
                                socket: Arc::clone(&socket),
                                remote,
                                responded: AtomicBool::new(false),
                            };
                            if let Some(ref handler) = h.on_subscribe {
                                let handler = Arc::clone(handler);
                                drop(h);
                                handler(&sub);
                            } else {
                                drop(h);
                                sub.accept();
                            }
                        }
                        _ => {
                            drop(h);
                            // Unknown method — respond 501.
                            let resp = sip::new_response(&msg, 501, "Not Implemented");
                            let _ = socket.send_to(&resp.to_bytes(), remote);
                        }
                    }
                }
            })
        };

        Self {
            socket,
            addr,
            running,
            thread: Some(thread),
            handlers,
            recorder,
            auth_username,
            auth_password,
            auth_nonces,
            invite_cancels,
        }
    }

    /// Returns the bound address (e.g. `"127.0.0.1:12345"`).
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Returns a SIP URI for an extension: `"sip:1002@127.0.0.1:12345"`.
    pub fn uri(&self, extension: &str) -> String {
        format!("sip:{}@{}", extension, self.addr)
    }

    /// Stops the server.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }

    // --- Handler setters ---

    pub fn on_register<F: Fn(&Register) + Send + Sync + 'static>(&self, f: F) {
        self.handlers.lock().on_register = Some(Arc::new(f));
    }

    pub fn on_invite<F: Fn(&Invite) + Send + Sync + 'static>(&self, f: F) {
        self.handlers.lock().on_invite = Some(Arc::new(f));
    }

    pub fn on_bye<F: Fn(&Bye) + Send + Sync + 'static>(&self, f: F) {
        self.handlers.lock().on_bye = Some(Arc::new(f));
    }

    pub fn on_cancel<F: Fn(&Cancel) + Send + Sync + 'static>(&self, f: F) {
        self.handlers.lock().on_cancel = Some(Arc::new(f));
    }

    pub fn on_ack<F: Fn(&Ack) + Send + Sync + 'static>(&self, f: F) {
        self.handlers.lock().on_ack = Some(Arc::new(f));
    }

    pub fn on_refer<F: Fn(&Refer) + Send + Sync + 'static>(&self, f: F) {
        self.handlers.lock().on_refer = Some(Arc::new(f));
    }

    pub fn on_options<F: Fn(&Options) + Send + Sync + 'static>(&self, f: F) {
        self.handlers.lock().on_options = Some(Arc::new(f));
    }

    pub fn on_info<F: Fn(&Info) + Send + Sync + 'static>(&self, f: F) {
        self.handlers.lock().on_info = Some(Arc::new(f));
    }

    pub fn on_message<F: Fn(&Message) + Send + Sync + 'static>(&self, f: F) {
        self.handlers.lock().on_message = Some(Arc::new(f));
    }

    pub fn on_subscribe<F: Fn(&Subscribe) + Send + Sync + 'static>(&self, f: F) {
        self.handlers.lock().on_subscribe = Some(Arc::new(f));
    }

    // --- Convenience methods ---

    /// Auto-answer all INVITEs with: 100 → 180 → 200 OK + SDP.
    pub fn auto_answer(&self, sdp_body: &str) {
        let sdp_body = sdp_body.to_string();
        self.on_invite(move |inv| {
            inv.trying();
            inv.ringing();
            inv.answer(&sdp_body);
        });
    }

    /// Auto-reject all INVITEs with: 100 → 486 Busy Here.
    pub fn auto_busy(&self) {
        self.on_invite(|inv| {
            inv.trying();
            inv.reject(486, "Busy Here");
        });
    }

    /// Auto-reject all INVITEs with the given code and reason.
    pub fn auto_reject(&self, code: u16, reason: &str) {
        let reason = reason.to_string();
        self.on_invite(move |inv| {
            inv.trying();
            inv.reject(code, &reason);
        });
    }

    // --- Recording / inspection ---

    pub fn requests(&self, method: &str) -> Vec<RecordedRequest> {
        self.recorder.requests(method)
    }

    pub fn register_count(&self) -> usize {
        self.recorder.count("REGISTER")
    }

    pub fn invite_count(&self) -> usize {
        self.recorder.count("INVITE")
    }

    pub fn bye_count(&self) -> usize {
        self.recorder.count("BYE")
    }

    pub fn cancel_count(&self) -> usize {
        self.recorder.count("CANCEL")
    }

    pub fn ack_count(&self) -> usize {
        self.recorder.count("ACK")
    }

    pub fn refer_count(&self) -> usize {
        self.recorder.count("REFER")
    }

    pub fn options_count(&self) -> usize {
        self.recorder.count("OPTIONS")
    }

    pub fn info_count(&self) -> usize {
        self.recorder.count("INFO")
    }

    pub fn message_count(&self) -> usize {
        self.recorder.count("MESSAGE")
    }

    pub fn subscribe_count(&self) -> usize {
        self.recorder.count("SUBSCRIBE")
    }

    pub fn last_invite(&self) -> Option<RecordedRequest> {
        self.recorder.last("INVITE")
    }

    pub fn last_register(&self) -> Option<RecordedRequest> {
        self.recorder.last("REGISTER")
    }

    pub fn wait_for_register(&self, n: usize, timeout: std::time::Duration) -> bool {
        self.recorder.wait_for("REGISTER", n, timeout)
    }

    pub fn wait_for_invite(&self, n: usize, timeout: std::time::Duration) -> bool {
        self.recorder.wait_for("INVITE", n, timeout)
    }

    pub fn wait_for_bye(&self, n: usize, timeout: std::time::Duration) -> bool {
        self.recorder.wait_for("BYE", n, timeout)
    }

    pub fn wait_for_cancel(&self, n: usize, timeout: std::time::Duration) -> bool {
        self.recorder.wait_for("CANCEL", n, timeout)
    }

    pub fn wait_for_ack(&self, n: usize, timeout: std::time::Duration) -> bool {
        self.recorder.wait_for("ACK", n, timeout)
    }
}

impl Drop for FakePBX {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Default digest auth handler for REGISTER when `with_auth()` is configured.
fn handle_auth_register(
    reg: &Register,
    expected_user: &str,
    expected_pass: &str,
    nonces: &Arc<Mutex<HashMap<String, bool>>>,
) {
    let auth_header = reg.req.header("Authorization");
    if auth_header.is_none() {
        // No credentials — send challenge.
        let nonce = generate_nonce();
        nonces.lock().insert(nonce.clone(), true);
        reg.challenge("fakepbx", &nonce);
        return;
    }

    let auth_val = auth_header.unwrap();
    let username = sip::extract_digest_param(auth_val, "username").unwrap_or_default();
    let realm = sip::extract_digest_param(auth_val, "realm").unwrap_or_default();
    let nonce = sip::extract_digest_param(auth_val, "nonce").unwrap_or_default();
    let uri = sip::extract_digest_param(auth_val, "uri").unwrap_or_default();
    let response = sip::extract_digest_param(auth_val, "response").unwrap_or_default();

    // Verify nonce is one we issued (single-use).
    let valid_nonce = {
        let mut lock = nonces.lock();
        lock.remove(&nonce).unwrap_or(false)
    };

    if !valid_nonce || realm != "fakepbx" {
        reg.reject(403, "Forbidden");
        return;
    }

    // RFC 2617 digest verification.
    let ha1 = md5_hex(&format!("{}:{}:{}", username, realm, expected_pass));
    let ha2 = md5_hex(&format!("REGISTER:{}", uri));
    let expected = md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2));

    if username == expected_user && response == expected {
        reg.accept();
    } else {
        reg.reject(403, "Forbidden");
    }
}

fn generate_nonce() -> String {
    let mut buf = [0u8; 16];
    let _ = getrandom::getrandom(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn md5_hex(input: &str) -> String {
    use md5::{Digest, Md5};
    let result = Md5::digest(input.as_bytes());
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Duration;

    /// Helper: send a raw SIP message to the PBX and read the response.
    fn send_recv(pbx_addr: &str, msg: &[u8]) -> sip::SipMessage {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let addr: SocketAddr = pbx_addr.parse().unwrap();
        sock.send_to(msg, addr).unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        sip::parse(&buf[..n]).unwrap()
    }

    fn build_register(pbx_addr: &str) -> Vec<u8> {
        let branch = sip::generate_branch();
        format!(
            "REGISTER sip:{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:9999;branch={}\r\n\
             From: <sip:test@127.0.0.1>;tag=reg1\r\n\
             To: <sip:test@127.0.0.1>\r\n\
             Call-ID: reg-test-1\r\n\
             CSeq: 1 REGISTER\r\n\
             Contact: <sip:test@127.0.0.1:9999>\r\n\
             Content-Length: 0\r\n\
             \r\n",
            pbx_addr, branch
        )
        .into_bytes()
    }

    #[test]
    fn register_no_auth() {
        let pbx = FakePBX::new(&[]);
        let resp = send_recv(pbx.addr(), &build_register(pbx.addr()));
        assert_eq!(resp.status_code, 200);
        assert_eq!(pbx.register_count(), 1);
    }

    #[test]
    fn register_with_auth() {
        let pbx = FakePBX::new(&[with_auth("alice", "secret")]);

        // First request: should get 401 challenge.
        let resp = send_recv(pbx.addr(), &build_register(pbx.addr()));
        assert_eq!(resp.status_code, 401);

        // Extract nonce from WWW-Authenticate.
        let www_auth = resp.header("WWW-Authenticate").unwrap();
        let nonce = sip::extract_digest_param(www_auth, "nonce").unwrap();

        // Compute digest response.
        let ha1 = md5_hex("alice:fakepbx:secret");
        let uri = format!("sip:{}", pbx.addr());
        let ha2 = md5_hex(&format!("REGISTER:{}", uri));
        let digest_response = md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2));

        // Second request with Authorization.
        let branch = sip::generate_branch();
        let auth_register = format!(
            "REGISTER sip:{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:9999;branch={}\r\n\
             From: <sip:alice@127.0.0.1>;tag=reg2\r\n\
             To: <sip:alice@127.0.0.1>\r\n\
             Call-ID: reg-test-2\r\n\
             CSeq: 2 REGISTER\r\n\
             Contact: <sip:alice@127.0.0.1:9999>\r\n\
             Authorization: Digest username=\"alice\", realm=\"fakepbx\", nonce=\"{}\", \
             uri=\"{}\", response=\"{}\"\r\n\
             Content-Length: 0\r\n\
             \r\n",
            pbx.addr(),
            branch,
            nonce,
            uri,
            digest_response
        );
        let resp = send_recv(pbx.addr(), auth_register.as_bytes());
        assert_eq!(resp.status_code, 200);
    }

    #[test]
    fn invite_default_auto_answer() {
        let pbx = FakePBX::new(&[]);
        let branch = sip::generate_branch();
        let invite = format!(
            "INVITE sip:1002@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:9999;branch={}\r\n\
             From: <sip:alice@127.0.0.1>;tag=inv1\r\n\
             To: <sip:1002@127.0.0.1>\r\n\
             Call-ID: call-1\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:alice@127.0.0.1:9999>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: 0\r\n\
             \r\n",
            pbx.addr(),
            branch
        );

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let addr: SocketAddr = pbx.addr().parse().unwrap();
        sock.send_to(invite.as_bytes(), addr).unwrap();

        // Should get 100 Trying first, then 200 OK.
        let mut buf = [0u8; 4096];
        let mut got_trying = false;
        let mut got_ok = false;
        for _ in 0..5 {
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                if let Some(msg) = sip::parse(&buf[..n]) {
                    if msg.status_code == 100 {
                        got_trying = true;
                    }
                    if msg.status_code == 200 {
                        got_ok = true;
                        // Should have SDP body.
                        assert!(msg.body.contains("m=audio"));
                        break;
                    }
                }
            }
        }
        assert!(got_trying, "never received 100 Trying");
        assert!(got_ok, "never received 200 OK");
        assert_eq!(pbx.invite_count(), 1);
    }

    #[test]
    fn invite_custom_handler() {
        let pbx = FakePBX::new(&[]);
        pbx.on_invite(|inv| {
            inv.trying();
            inv.ringing();
            inv.answer(&sdp::sdp("127.0.0.1", 30000, &[sdp::PCMA]));
        });

        let branch = sip::generate_branch();
        let invite = format!(
            "INVITE sip:1002@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:9999;branch={}\r\n\
             From: <sip:alice@127.0.0.1>;tag=inv2\r\n\
             To: <sip:1002@127.0.0.1>\r\n\
             Call-ID: call-2\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:alice@127.0.0.1:9999>\r\n\
             Content-Length: 0\r\n\
             \r\n",
            pbx.addr(),
            branch
        );

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let addr: SocketAddr = pbx.addr().parse().unwrap();
        sock.send_to(invite.as_bytes(), addr).unwrap();

        let mut buf = [0u8; 4096];
        let mut codes = Vec::new();
        for _ in 0..5 {
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                if let Some(msg) = sip::parse(&buf[..n]) {
                    codes.push(msg.status_code);
                    if msg.status_code == 200 {
                        assert!(msg.body.contains("PCMA"));
                        break;
                    }
                }
            }
        }
        assert!(codes.contains(&100));
        assert!(codes.contains(&180));
        assert!(codes.contains(&200));
    }

    #[test]
    fn auto_busy() {
        let pbx = FakePBX::new(&[]);
        pbx.auto_busy();

        let branch = sip::generate_branch();
        let invite = format!(
            "INVITE sip:1002@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:9999;branch={}\r\n\
             From: <sip:alice@127.0.0.1>;tag=inv3\r\n\
             To: <sip:1002@127.0.0.1>\r\n\
             Call-ID: call-3\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\
             \r\n",
            pbx.addr(),
            branch
        );

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let addr: SocketAddr = pbx.addr().parse().unwrap();
        sock.send_to(invite.as_bytes(), addr).unwrap();

        let mut buf = [0u8; 4096];
        let mut got_486 = false;
        for _ in 0..5 {
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                if let Some(msg) = sip::parse(&buf[..n]) {
                    if msg.status_code == 486 {
                        got_486 = true;
                        break;
                    }
                }
            }
        }
        assert!(got_486);
    }

    #[test]
    fn bye_default_accept() {
        let pbx = FakePBX::new(&[]);
        let branch = sip::generate_branch();
        let bye = format!(
            "BYE sip:1002@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:9999;branch={}\r\n\
             From: <sip:alice@127.0.0.1>;tag=bye1\r\n\
             To: <sip:1002@127.0.0.1>;tag=xyz\r\n\
             Call-ID: call-bye-1\r\n\
             CSeq: 2 BYE\r\n\
             Content-Length: 0\r\n\
             \r\n",
            pbx.addr(),
            branch
        );
        let resp = send_recv(pbx.addr(), bye.as_bytes());
        assert_eq!(resp.status_code, 200);
        assert_eq!(pbx.bye_count(), 1);
    }

    #[test]
    fn options_default_accept() {
        let pbx = FakePBX::new(&[]);
        let branch = sip::generate_branch();
        let options = format!(
            "OPTIONS sip:{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:9999;branch={}\r\n\
             From: <sip:alice@127.0.0.1>;tag=opt1\r\n\
             To: <sip:server@127.0.0.1>\r\n\
             Call-ID: opt-1\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: 0\r\n\
             \r\n",
            pbx.addr(),
            branch
        );
        let resp = send_recv(pbx.addr(), options.as_bytes());
        assert_eq!(resp.status_code, 200);
    }

    #[test]
    fn wait_for_methods() {
        let pbx = FakePBX::new(&[]);
        // No requests yet — should timeout fast.
        assert!(!pbx.wait_for_bye(1, Duration::from_millis(50)));

        // Send a BYE.
        let branch = sip::generate_branch();
        let bye = format!(
            "BYE sip:1002@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:9999;branch={}\r\n\
             From: <sip:alice@127.0.0.1>;tag=w1\r\n\
             To: <sip:1002@127.0.0.1>;tag=w2\r\n\
             Call-ID: wait-1\r\n\
             CSeq: 1 BYE\r\n\
             Content-Length: 0\r\n\
             \r\n",
            pbx.addr(),
            branch
        );
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr: SocketAddr = pbx.addr().parse().unwrap();
        sock.send_to(bye.as_bytes(), addr).unwrap();

        assert!(pbx.wait_for_bye(1, Duration::from_secs(2)));
    }

    #[test]
    fn refer_handler() {
        let pbx = FakePBX::new(&[]);

        let got_refer = Arc::new(Mutex::new(None::<String>));
        let got_refer2 = Arc::clone(&got_refer);
        pbx.on_refer(move |r| {
            *got_refer2.lock() = r.refer_to();
            r.accept();
        });

        let branch = sip::generate_branch();
        let refer = format!(
            "REFER sip:1002@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:9999;branch={}\r\n\
             From: <sip:alice@127.0.0.1>;tag=ref1\r\n\
             To: <sip:1002@127.0.0.1>;tag=ref2\r\n\
             Call-ID: refer-1\r\n\
             CSeq: 1 REFER\r\n\
             Refer-To: <sip:1003@127.0.0.1>\r\n\
             Content-Length: 0\r\n\
             \r\n",
            pbx.addr(),
            branch
        );
        let resp = send_recv(pbx.addr(), refer.as_bytes());
        assert_eq!(resp.status_code, 202);

        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(got_refer.lock().as_deref(), Some("sip:1003@127.0.0.1"));
    }
}
