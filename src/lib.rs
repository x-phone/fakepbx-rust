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
    /// Sets a custom User-Agent header value (default: `"FakePBX/test"`).
    UserAgent(String),
    /// Sets the transport parameter (default: `"udp"`).
    Transport(String),
}

/// Creates an `Opt::Auth` option.
pub fn with_auth(username: &str, password: &str) -> Opt {
    Opt::Auth {
        username: username.to_string(),
        password: password.to_string(),
    }
}

/// Creates an `Opt::UserAgent` option.
pub fn with_user_agent(ua: &str) -> Opt {
    Opt::UserAgent(ua.to_string())
}

/// Creates an `Opt::Transport` option.
pub fn with_transport(transport: &str) -> Opt {
    Opt::Transport(transport.to_string())
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
    transport: String,
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
    #[allow(dead_code)]
    user_agent: String,
    /// Tracks active INVITE transactions by Via branch for CANCEL matching.
    #[allow(dead_code)]
    invite_cancels: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

impl FakePBX {
    /// Creates and starts a FakePBX on `127.0.0.1:0` (ephemeral port).
    pub fn new(opts: &[Opt]) -> Self {
        let mut auth_username = String::new();
        let mut auth_password = String::new();
        let mut user_agent = "FakePBX/test".to_string();
        let mut transport = "udp".to_string();
        for opt in opts {
            match opt {
                Opt::Auth { username, password } => {
                    auth_username = username.clone();
                    auth_password = password.clone();
                }
                Opt::UserAgent(ua) => {
                    user_agent = ua.clone();
                }
                Opt::Transport(t) => {
                    transport = t.clone();
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
                            let branch_key = msg.via_branch();
                            if let Some(ref branch) = branch_key {
                                invite_cancels
                                    .lock()
                                    .insert(branch.clone(), Arc::clone(&cancel_flag));
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
                            // Clean up cancel tracking entry.
                            if let Some(branch) = branch_key {
                                invite_cancels.lock().remove(&branch);
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
            transport,
            running,
            thread: Some(thread),
            handlers,
            recorder,
            auth_username,
            auth_password,
            user_agent,
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

    /// Returns the SIP address with transport parameter: `"127.0.0.1:12345;transport=udp"`.
    pub fn sip_addr(&self) -> String {
        format!("{};transport={}", self.addr, self.transport)
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

    // --- UAC (outbound) methods ---

    /// Initiates an outbound INVITE to the given SIP URI with the provided SDP.
    ///
    /// Blocks until a final response is received. On 2xx, sends ACK
    /// automatically and returns an `OutboundCall` for in-dialog control.
    pub fn send_invite(&self, target: &str, sdp_body: &str) -> Result<OutboundCall, String> {
        // Dedicated socket for this outbound transaction (avoids racing the server loop).
        let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind failed: {e}"))?;
        let local_addr = sock
            .local_addr()
            .map_err(|e| format!("local_addr failed: {e}"))?
            .to_string();
        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();

        let call_id = sip::generate_tag();
        let from_tag = sip::generate_tag();
        let branch = sip::generate_branch();

        let from = format!("<sip:fakepbx@{}>;tag={}", self.addr, from_tag);
        let to = format!("<{}>", target);
        let via = format!("SIP/2.0/UDP {};branch={}", local_addr, branch);

        let mut req = sip::new_dialog_request("INVITE", target, &call_id, &from, &to, &via, 1);
        req.add_header("Contact", &format!("<sip:{}>", self.addr));
        if !sdp_body.is_empty() {
            req.add_header("Content-Type", "application/sdp");
            req.body = sdp_body.to_string();
        }

        let target_addr =
            parse_sip_host_port(target).ok_or_else(|| format!("invalid SIP URI: {target}"))?;

        sock.send_to(&req.to_bytes(), &target_addr)
            .map_err(|e| format!("send failed: {e}"))?;

        // Wait for final response, skipping provisionals.
        let mut buf = [0u8; 4096];
        loop {
            let (n, _) = sock
                .recv_from(&mut buf)
                .map_err(|e| format!("recv timeout: {e}"))?;
            let msg = match sip::parse(&buf[..n]) {
                Some(m) if !m.is_request() => m,
                _ => continue,
            };
            if msg.status_code < 200 {
                continue; // skip 1xx provisionals
            }
            if msg.status_code >= 300 {
                // RFC 3261: ACK must be sent for all final INVITE responses.
                let ack_via = format!(
                    "SIP/2.0/UDP {};branch={}",
                    local_addr,
                    sip::generate_branch()
                );
                let ack_to = msg.header("To").unwrap_or("").to_string();
                let mut ack =
                    sip::new_dialog_request("ACK", target, &call_id, &from, &ack_to, &ack_via, 1);
                ack.add_header("Contact", &format!("<sip:{}>", self.addr));
                let _ = sock.send_to(&ack.to_bytes(), &target_addr);
                return Err(format!("{} {}", msg.status_code, msg.reason));
            }
            // 2xx — send ACK and build OutboundCall.
            let ack_via = format!(
                "SIP/2.0/UDP {};branch={}",
                local_addr,
                sip::generate_branch()
            );
            let ack_to = msg.header("To").unwrap_or("").to_string();
            let mut ack =
                sip::new_dialog_request("ACK", target, &call_id, &from, &ack_to, &ack_via, 1);
            ack.add_header("Contact", &format!("<sip:{}>", self.addr));
            let _ = sock.send_to(&ack.to_bytes(), &target_addr);

            let remote_contact = msg.contact().unwrap_or(target.to_string());
            let sock = Arc::new(sock);
            let remote_addr = target_addr
                .parse()
                .map_err(|e| format!("parse addr: {e}"))?;

            return Ok(OutboundCall::new(
                sock,
                remote_addr,
                self.addr.clone(),
                call_id,
                from,
                ack_to,
                remote_contact,
                2, // CSeq 1 was used for INVITE/ACK
                req,
                msg,
            ));
        }
    }

    /// Sends an out-of-dialog MESSAGE request.
    /// Returns the response status code.
    pub fn send_message(
        &self,
        target: &str,
        content_type: &str,
        body: &str,
    ) -> Result<u16, String> {
        self.send_ood_request("MESSAGE", target, |req| {
            req.add_header("Content-Type", content_type);
            req.body = body.to_string();
        })
    }

    /// Sends an out-of-dialog OPTIONS request.
    /// Returns the response status code.
    pub fn send_options(&self, target: &str) -> Result<u16, String> {
        self.send_ood_request("OPTIONS", target, |_| {})
    }

    /// Sends an out-of-dialog request and waits for the response.
    fn send_ood_request<F>(&self, method: &str, target: &str, customize: F) -> Result<u16, String>
    where
        F: FnOnce(&mut sip::SipMessage),
    {
        let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind failed: {e}"))?;
        let local_addr = sock
            .local_addr()
            .map_err(|e| format!("local_addr failed: {e}"))?
            .to_string();
        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();

        let call_id = sip::generate_tag();
        let from_tag = sip::generate_tag();
        let branch = sip::generate_branch();

        let from = format!("<sip:fakepbx@{}>;tag={}", self.addr, from_tag);
        let to = format!("<{}>", target);
        let via = format!("SIP/2.0/UDP {};branch={}", local_addr, branch);

        let mut req = sip::new_dialog_request(method, target, &call_id, &from, &to, &via, 1);
        req.add_header("Contact", &format!("<sip:{}>", self.addr));
        customize(&mut req);

        let target_addr =
            parse_sip_host_port(target).ok_or_else(|| format!("invalid SIP URI: {target}"))?;

        sock.send_to(&req.to_bytes(), &target_addr)
            .map_err(|e| format!("send failed: {e}"))?;

        let mut buf = [0u8; 4096];
        loop {
            let (n, _) = sock
                .recv_from(&mut buf)
                .map_err(|e| format!("recv timeout: {e}"))?;
            if let Some(msg) = sip::parse(&buf[..n]) {
                if !msg.is_request() && msg.status_code >= 200 {
                    return Ok(msg.status_code);
                }
                // Skip requests and 1xx provisionals.
            }
        }
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

/// Extracts `host:port` from a SIP URI like `sip:user@host:port`.
/// Defaults to port 5060 if not specified.
fn parse_sip_host_port(uri: &str) -> Option<String> {
    let rest = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))?;
    let host_part = match rest.find('@') {
        Some(idx) => &rest[idx + 1..],
        None => rest,
    };
    // Strip URI parameters (;transport=udp etc.) and headers (?...).
    let host_part = host_part.split(';').next()?;
    let host_part = host_part.split('?').next()?;
    if host_part.is_empty() {
        return None;
    }
    if host_part.contains(':') {
        Some(host_part.to_string())
    } else {
        Some(format!("{host_part}:5060"))
    }
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

    /// Helper: send an INVITE from a "remote" socket, consume responses up to
    /// and including the final 2xx, then return the socket for further dialog
    /// interaction. The handler runs in the PBX server thread so any
    /// in-dialog requests it sends will arrive on this socket after the 200 OK.
    fn invite_and_answer(pbx_addr: &str, call_id: &str, from_tag: &str) -> UdpSocket {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let addr: SocketAddr = pbx_addr.parse().unwrap();
        let local = sock.local_addr().unwrap();
        let branch = sip::generate_branch();
        let invite = format!(
            "INVITE sip:1002@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {};branch={}\r\n\
             From: <sip:alice@127.0.0.1>;tag={}\r\n\
             To: <sip:1002@127.0.0.1>\r\n\
             Call-ID: {}\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:alice@{}>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: 0\r\n\
             \r\n",
            pbx_addr, local, branch, from_tag, call_id, local
        );
        sock.send_to(invite.as_bytes(), addr).unwrap();

        // Drain provisional + 200 OK.
        let mut buf = [0u8; 4096];
        loop {
            let (n, _) = sock.recv_from(&mut buf).unwrap();
            if let Some(msg) = sip::parse(&buf[..n]) {
                if msg.status_code >= 200 {
                    break;
                }
            }
        }
        sock
    }

    #[test]
    fn active_call_send_refer_accepted() {
        let pbx = FakePBX::new(&[]);
        let result = Arc::new(Mutex::new(None::<Result<u16, String>>));
        let result2 = Arc::clone(&result);
        pbx.on_invite(move |inv| {
            inv.trying();
            let ac = inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
            if let Some(ac) = ac {
                *result2.lock() = Some(ac.send_refer("<sip:1003@127.0.0.1>"));
            }
        });

        let sock = invite_and_answer(pbx.addr(), "refer-ac-1", "rac1");

        // Read the REFER request from PBX.
        let mut buf = [0u8; 4096];
        let (n, from_addr) = sock.recv_from(&mut buf).unwrap();
        let refer_req = sip::parse(&buf[..n]).unwrap();
        assert!(refer_req.is_request());
        assert_eq!(refer_req.method, "REFER");
        assert_eq!(
            refer_req.header("Refer-To").unwrap(),
            "<sip:1003@127.0.0.1>"
        );

        // Respond 202 Accepted.
        let resp = sip::new_response(&refer_req, 202, "Accepted");
        sock.send_to(&resp.to_bytes(), from_addr).unwrap();

        // Wait for handler to finish.
        std::thread::sleep(Duration::from_millis(100));
        let r = result.lock().take().expect("handler did not run");
        assert_eq!(r.unwrap(), 202);
    }

    #[test]
    fn active_call_send_refer_rejected() {
        let pbx = FakePBX::new(&[]);
        let result = Arc::new(Mutex::new(None::<Result<u16, String>>));
        let result2 = Arc::clone(&result);
        pbx.on_invite(move |inv| {
            inv.trying();
            let ac = inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
            if let Some(ac) = ac {
                *result2.lock() = Some(ac.send_refer("<sip:1003@127.0.0.1>"));
            }
        });

        let sock = invite_and_answer(pbx.addr(), "refer-ac-2", "rac2");

        // Read the REFER request from PBX.
        let mut buf = [0u8; 4096];
        let (n, from_addr) = sock.recv_from(&mut buf).unwrap();
        let refer_req = sip::parse(&buf[..n]).unwrap();
        assert_eq!(refer_req.method, "REFER");

        // Respond 603 Decline.
        let resp = sip::new_response(&refer_req, 603, "Decline");
        sock.send_to(&resp.to_bytes(), from_addr).unwrap();

        std::thread::sleep(Duration::from_millis(100));
        let r = result.lock().take().expect("handler did not run");
        assert_eq!(r.unwrap(), 603);
    }

    #[test]
    fn active_call_send_bye() {
        let pbx = FakePBX::new(&[]);
        let result = Arc::new(Mutex::new(None::<Result<u16, String>>));
        let result2 = Arc::clone(&result);
        pbx.on_invite(move |inv| {
            inv.trying();
            let ac = inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
            if let Some(ac) = ac {
                *result2.lock() = Some(ac.send_bye());
            }
        });

        let sock = invite_and_answer(pbx.addr(), "bye-ac-1", "bac1");

        // Read the BYE request from PBX.
        let mut buf = [0u8; 4096];
        let (n, from_addr) = sock.recv_from(&mut buf).unwrap();
        let bye_req = sip::parse(&buf[..n]).unwrap();
        assert_eq!(bye_req.method, "BYE");

        // Respond 200 OK.
        let resp = sip::new_response(&bye_req, 200, "OK");
        sock.send_to(&resp.to_bytes(), from_addr).unwrap();

        std::thread::sleep(Duration::from_millis(100));
        let r = result.lock().take().expect("handler did not run");
        assert_eq!(r.unwrap(), 200);
    }

    #[test]
    fn active_call_send_reinvite() {
        let pbx = FakePBX::new(&[]);
        let result = Arc::new(Mutex::new(None::<Result<u16, String>>));
        let result2 = Arc::clone(&result);
        pbx.on_invite(move |inv| {
            inv.trying();
            let ac = inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
            if let Some(ac) = ac {
                let hold_sdp =
                    sdp::sdp_with_direction("127.0.0.1", 20000, "sendonly", &[sdp::PCMU]);
                *result2.lock() = Some(ac.send_reinvite(&hold_sdp));
            }
        });

        let sock = invite_and_answer(pbx.addr(), "reinv-ac-1", "ria1");

        // Read the re-INVITE from PBX.
        let mut buf = [0u8; 4096];
        let (n, from_addr) = sock.recv_from(&mut buf).unwrap();
        let reinv_req = sip::parse(&buf[..n]).unwrap();
        assert_eq!(reinv_req.method, "INVITE");
        assert!(reinv_req.body.contains("sendonly"));

        // Respond 200 OK.
        let resp = sip::new_response(&reinv_req, 200, "OK");
        sock.send_to(&resp.to_bytes(), from_addr).unwrap();

        std::thread::sleep(Duration::from_millis(100));
        let r = result.lock().take().expect("handler did not run");
        assert_eq!(r.unwrap(), 200);
    }

    #[test]
    fn active_call_send_notify() {
        let pbx = FakePBX::new(&[]);
        let result = Arc::new(Mutex::new(None::<Result<u16, String>>));
        let result2 = Arc::clone(&result);
        pbx.on_invite(move |inv| {
            inv.trying();
            let ac = inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
            if let Some(ac) = ac {
                *result2.lock() = Some(ac.send_notify("refer", "SIP/2.0 200 OK"));
            }
        });

        let sock = invite_and_answer(pbx.addr(), "notify-ac-1", "nac1");

        // Read the NOTIFY from PBX.
        let mut buf = [0u8; 4096];
        let (n, from_addr) = sock.recv_from(&mut buf).unwrap();
        let notify_req = sip::parse(&buf[..n]).unwrap();
        assert_eq!(notify_req.method, "NOTIFY");
        assert_eq!(notify_req.header("Event").unwrap(), "refer");
        assert_eq!(notify_req.body, "SIP/2.0 200 OK");

        // Respond 200 OK.
        let resp = sip::new_response(&notify_req, 200, "OK");
        sock.send_to(&resp.to_bytes(), from_addr).unwrap();

        std::thread::sleep(Duration::from_millis(100));
        let r = result.lock().take().expect("handler did not run");
        assert_eq!(r.unwrap(), 200);
    }

    #[test]
    fn active_call_cseq_increments() {
        let pbx = FakePBX::new(&[]);
        let result = Arc::new(Mutex::new(Vec::<Result<u16, String>>::new()));
        let result2 = Arc::clone(&result);
        pbx.on_invite(move |inv| {
            inv.trying();
            let ac = inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
            if let Some(ac) = ac {
                let hold = sdp::sdp_with_direction("127.0.0.1", 20000, "sendonly", &[sdp::PCMU]);
                let r1 = ac.send_reinvite(&hold);
                let r2 = ac.send_notify("refer", "SIP/2.0 100 Trying");
                let r3 = ac.send_bye();
                result2.lock().extend([r1, r2, r3]);
            }
        });

        let sock = invite_and_answer(pbx.addr(), "cseq-ac-1", "csq1");
        let mut buf = [0u8; 4096];
        let mut cseqs = Vec::new();

        // Read 3 requests and respond to each.
        for _ in 0..3 {
            let (n, from_addr) = sock.recv_from(&mut buf).unwrap();
            let req = sip::parse(&buf[..n]).unwrap();
            assert!(req.is_request());
            cseqs.push(req.cseq_num().unwrap());
            let resp = sip::new_response(&req, 200, "OK");
            sock.send_to(&resp.to_bytes(), from_addr).unwrap();
        }

        // CSeq should be strictly increasing.
        assert!(cseqs[0] < cseqs[1], "CSeq not increasing: {:?}", cseqs);
        assert!(cseqs[1] < cseqs[2], "CSeq not increasing: {:?}", cseqs);

        std::thread::sleep(Duration::from_millis(100));
        let results = result.lock();
        assert_eq!(results.len(), 3);
        for r in results.iter() {
            assert_eq!(r.as_ref().unwrap(), &200);
        }
    }

    #[test]
    fn invite_early_media() {
        let pbx = FakePBX::new(&[]);
        pbx.on_invite(|inv| {
            inv.trying();
            inv.early_media(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
            inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
        });

        let branch = sip::generate_branch();
        let invite = format!(
            "INVITE sip:1002@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:9999;branch={}\r\n\
             From: <sip:alice@127.0.0.1>;tag=em1\r\n\
             To: <sip:1002@127.0.0.1>\r\n\
             Call-ID: early-1\r\n\
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
                    if msg.status_code == 183 {
                        assert!(msg.body.contains("m=audio"));
                    }
                    codes.push(msg.status_code);
                    if msg.status_code >= 200 {
                        break;
                    }
                }
            }
        }
        assert!(codes.contains(&100));
        assert!(codes.contains(&183));
        assert!(codes.contains(&200));
    }

    // NOTE: CANCEL during ringing doesn't work yet because the INVITE handler
    // runs in the server thread, blocking the loop from reading the CANCEL.
    // The Go version uses goroutines per handler — we need to spawn the INVITE
    // handler in a separate thread to fix this. Tracked separately.

    // -----------------------------------------------------------------------
    // Outbound INVITE (UAC) tests
    // -----------------------------------------------------------------------

    /// Helper: a minimal "remote UA" that accepts an INVITE and returns 200 OK.
    /// Returns the socket for further in-dialog interaction.
    fn spawn_remote_ua_accept(sdp_body: &str) -> (String, std::thread::JoinHandle<UdpSocket>) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        let sdp_body = sdp_body.to_string();
        let handle = std::thread::spawn(move || {
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 4096];
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            let invite = sip::parse(&buf[..n]).unwrap();
            assert_eq!(invite.method, "INVITE");

            // Send 100 Trying.
            let trying = sip::new_response(&invite, 100, "Trying");
            sock.send_to(&trying.to_bytes(), from).unwrap();

            // Send 200 OK with SDP.
            let mut ok = sip::new_response(&invite, 200, "OK");
            let local = sock.local_addr().unwrap();
            ok.add_header("Contact", &format!("<sip:{}>", local));
            ok.add_header("Content-Type", "application/sdp");
            ok.body = sdp_body;
            sock.send_to(&ok.to_bytes(), from).unwrap();

            // Read ACK.
            let (n, _) = sock.recv_from(&mut buf).unwrap();
            let ack = sip::parse(&buf[..n]).unwrap();
            assert_eq!(ack.method, "ACK");

            sock
        });
        (addr, handle)
    }

    /// Helper: a minimal "remote UA" that rejects an INVITE.
    fn spawn_remote_ua_reject(code: u16, reason: &str) -> (String, std::thread::JoinHandle<()>) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        let reason = reason.to_string();
        let handle = std::thread::spawn(move || {
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 4096];
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            let invite = sip::parse(&buf[..n]).unwrap();
            assert_eq!(invite.method, "INVITE");

            let resp = sip::new_response(&invite, code, &reason);
            sock.send_to(&resp.to_bytes(), from).unwrap();
        });
        (addr, handle)
    }

    #[test]
    fn send_invite_basic() {
        let pbx = FakePBX::new(&[]);
        let remote_sdp = sdp::sdp("127.0.0.1", 30000, &[sdp::PCMA]);
        let (remote_addr, handle) = spawn_remote_ua_accept(&remote_sdp);
        let target = format!("sip:1002@{}", remote_addr);

        let offer_sdp = sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]);
        let oc = pbx.send_invite(&target, &offer_sdp).unwrap();

        // Verify OutboundCall fields.
        assert_eq!(oc.request().method, "INVITE");
        assert_eq!(oc.response().status_code, 200);
        assert!(oc.response().body.contains("PCMA"));

        handle.join().unwrap();
    }

    #[test]
    fn send_invite_rejected() {
        let pbx = FakePBX::new(&[]);
        let (remote_addr, handle) = spawn_remote_ua_reject(486, "Busy Here");
        let target = format!("sip:1002@{}", remote_addr);

        let result = pbx.send_invite(&target, &sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("486"));

        handle.join().unwrap();
    }

    #[test]
    fn send_invite_invalid_uri() {
        let pbx = FakePBX::new(&[]);
        let result = pbx.send_invite("not-a-sip-uri", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid SIP URI"));
    }

    #[test]
    fn outbound_call_send_bye() {
        let pbx = FakePBX::new(&[]);
        let remote_sdp = sdp::sdp("127.0.0.1", 30000, &[sdp::PCMU]);
        let (remote_addr, handle) = spawn_remote_ua_accept(&remote_sdp);
        let target = format!("sip:1002@{}", remote_addr);

        let oc = pbx
            .send_invite(&target, &sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]))
            .unwrap();
        let remote_sock = handle.join().unwrap();

        // Remote UA reads BYE and responds.
        let remote_handle = std::thread::spawn(move || {
            remote_sock
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 4096];
            let (n, from) = remote_sock.recv_from(&mut buf).unwrap();
            let bye = sip::parse(&buf[..n]).unwrap();
            assert_eq!(bye.method, "BYE");
            let resp = sip::new_response(&bye, 200, "OK");
            remote_sock.send_to(&resp.to_bytes(), from).unwrap();
        });

        let code = oc.send_bye().unwrap();
        assert_eq!(code, 200);
        remote_handle.join().unwrap();
    }

    #[test]
    fn outbound_call_send_reinvite() {
        let pbx = FakePBX::new(&[]);
        let remote_sdp = sdp::sdp("127.0.0.1", 30000, &[sdp::PCMU]);
        let (remote_addr, handle) = spawn_remote_ua_accept(&remote_sdp);
        let target = format!("sip:1002@{}", remote_addr);

        let oc = pbx
            .send_invite(&target, &sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]))
            .unwrap();
        let remote_sock = handle.join().unwrap();

        // Remote reads re-INVITE, responds 200 OK.
        let remote_handle = std::thread::spawn(move || {
            remote_sock
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 4096];
            let (n, from) = remote_sock.recv_from(&mut buf).unwrap();
            let reinv = sip::parse(&buf[..n]).unwrap();
            assert_eq!(reinv.method, "INVITE");
            assert!(reinv.body.contains("sendonly"));
            let resp = sip::new_response(&reinv, 200, "OK");
            remote_sock.send_to(&resp.to_bytes(), from).unwrap();
        });

        let hold_sdp = sdp::sdp_with_direction("127.0.0.1", 20000, "sendonly", &[sdp::PCMU]);
        let code = oc.send_reinvite(&hold_sdp).unwrap();
        assert_eq!(code, 200);
        remote_handle.join().unwrap();
    }

    #[test]
    fn outbound_call_send_refer() {
        let pbx = FakePBX::new(&[]);
        let remote_sdp = sdp::sdp("127.0.0.1", 30000, &[sdp::PCMU]);
        let (remote_addr, handle) = spawn_remote_ua_accept(&remote_sdp);
        let target = format!("sip:1002@{}", remote_addr);

        let oc = pbx
            .send_invite(&target, &sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]))
            .unwrap();
        let remote_sock = handle.join().unwrap();

        // Remote reads REFER, responds 202 Accepted.
        let remote_handle = std::thread::spawn(move || {
            remote_sock
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 4096];
            let (n, from) = remote_sock.recv_from(&mut buf).unwrap();
            let refer = sip::parse(&buf[..n]).unwrap();
            assert_eq!(refer.method, "REFER");
            assert_eq!(refer.header("Refer-To").unwrap(), "<sip:1003@127.0.0.1>");
            let resp = sip::new_response(&refer, 202, "Accepted");
            remote_sock.send_to(&resp.to_bytes(), from).unwrap();
        });

        let code = oc.send_refer("<sip:1003@127.0.0.1>").unwrap();
        assert_eq!(code, 202);
        remote_handle.join().unwrap();
    }

    #[test]
    fn outbound_call_cseq_increments() {
        let pbx = FakePBX::new(&[]);
        let remote_sdp = sdp::sdp("127.0.0.1", 30000, &[sdp::PCMU]);
        let (remote_addr, handle) = spawn_remote_ua_accept(&remote_sdp);
        let target = format!("sip:1002@{}", remote_addr);

        let oc = pbx
            .send_invite(&target, &sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]))
            .unwrap();
        let remote_sock = handle.join().unwrap();

        // Remote reads 3 requests and responds to each, collecting CSeqs.
        let remote_handle = std::thread::spawn(move || {
            remote_sock
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 4096];
            let mut cseqs = Vec::new();
            for _ in 0..3 {
                let (n, from) = remote_sock.recv_from(&mut buf).unwrap();
                let req = sip::parse(&buf[..n]).unwrap();
                assert!(req.is_request());
                cseqs.push(req.cseq_num().unwrap());
                let resp = sip::new_response(&req, 200, "OK");
                remote_sock.send_to(&resp.to_bytes(), from).unwrap();
            }
            cseqs
        });

        let hold = sdp::sdp_with_direction("127.0.0.1", 20000, "sendonly", &[sdp::PCMU]);
        oc.send_reinvite(&hold).unwrap();
        oc.send_notify("refer", "SIP/2.0 100 Trying").unwrap();
        oc.send_bye().unwrap();

        let cseqs = remote_handle.join().unwrap();
        assert!(cseqs[0] < cseqs[1], "CSeq not increasing: {:?}", cseqs);
        assert!(cseqs[1] < cseqs[2], "CSeq not increasing: {:?}", cseqs);
    }

    #[test]
    fn send_invite_concurrent() {
        let pbx = FakePBX::new(&[]);
        let remote_sdp1 = sdp::sdp("127.0.0.1", 30000, &[sdp::PCMU]);
        let remote_sdp2 = sdp::sdp("127.0.0.1", 30002, &[sdp::PCMA]);
        let (addr1, h1) = spawn_remote_ua_accept(&remote_sdp1);
        let (addr2, h2) = spawn_remote_ua_accept(&remote_sdp2);

        let target1 = format!("sip:1002@{}", addr1);
        let target2 = format!("sip:1003@{}", addr2);

        let offer = sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]);
        let oc1 = pbx.send_invite(&target1, &offer).unwrap();
        let oc2 = pbx.send_invite(&target2, &offer).unwrap();

        assert_eq!(oc1.response().status_code, 200);
        assert_eq!(oc2.response().status_code, 200);

        h1.join().unwrap();
        h2.join().unwrap();
    }

    // -----------------------------------------------------------------------
    // Out-of-dialog MESSAGE tests
    // -----------------------------------------------------------------------

    /// Helper: spawn a remote UA that receives any SIP request and responds.
    fn spawn_remote_ua_respond(
        code: u16,
        reason: &str,
    ) -> (String, std::thread::JoinHandle<sip::SipMessage>) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        let reason = reason.to_string();
        let handle = std::thread::spawn(move || {
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 4096];
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            let req = sip::parse(&buf[..n]).unwrap();
            let resp = sip::new_response(&req, code, &reason);
            sock.send_to(&resp.to_bytes(), from).unwrap();
            req
        });
        (addr, handle)
    }

    #[test]
    fn send_message_basic() {
        let pbx = FakePBX::new(&[]);
        let (remote_addr, handle) = spawn_remote_ua_respond(200, "OK");
        let target = format!("sip:alice@{}", remote_addr);

        let code = pbx.send_message(&target, "text/plain", "hello").unwrap();
        assert_eq!(code, 200);

        let req = handle.join().unwrap();
        assert_eq!(req.method, "MESSAGE");
        assert_eq!(req.header("Content-Type").unwrap(), "text/plain");
        assert_eq!(req.body, "hello");
    }

    #[test]
    fn send_message_rejected() {
        let pbx = FakePBX::new(&[]);
        let (remote_addr, handle) = spawn_remote_ua_respond(403, "Forbidden");
        let target = format!("sip:alice@{}", remote_addr);

        let code = pbx.send_message(&target, "text/plain", "hello").unwrap();
        assert_eq!(code, 403);

        handle.join().unwrap();
    }

    #[test]
    fn send_message_invalid_uri() {
        let pbx = FakePBX::new(&[]);
        let result = pbx.send_message("not-a-uri", "text/plain", "hi");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid SIP URI"));
    }

    // -----------------------------------------------------------------------
    // Out-of-dialog OPTIONS tests
    // -----------------------------------------------------------------------

    #[test]
    fn send_options_basic() {
        let pbx = FakePBX::new(&[]);
        let (remote_addr, handle) = spawn_remote_ua_respond(200, "OK");
        let target = format!("sip:server@{}", remote_addr);

        let code = pbx.send_options(&target).unwrap();
        assert_eq!(code, 200);

        let req = handle.join().unwrap();
        assert_eq!(req.method, "OPTIONS");
    }

    #[test]
    fn send_options_rejected() {
        let pbx = FakePBX::new(&[]);
        let (remote_addr, handle) = spawn_remote_ua_respond(405, "Method Not Allowed");
        let target = format!("sip:server@{}", remote_addr);

        let code = pbx.send_options(&target).unwrap();
        assert_eq!(code, 405);

        handle.join().unwrap();
    }

    #[test]
    fn send_options_invalid_uri() {
        let pbx = FakePBX::new(&[]);
        let result = pbx.send_options("bad-uri");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid SIP URI"));
    }

    // -----------------------------------------------------------------------
    // Configuration options tests
    // -----------------------------------------------------------------------

    #[test]
    fn sip_addr_default_transport() {
        let pbx = FakePBX::new(&[]);
        let sip_addr = pbx.sip_addr();
        assert!(sip_addr.ends_with(";transport=udp"));
        assert!(sip_addr.starts_with("127.0.0.1:"));
    }

    #[test]
    fn sip_addr_custom_transport() {
        let pbx = FakePBX::new(&[with_transport("tcp")]);
        assert!(pbx.sip_addr().ends_with(";transport=tcp"));
    }

    #[test]
    fn with_user_agent_option() {
        // Just verifies the option is accepted without panic.
        let _pbx = FakePBX::new(&[with_user_agent("MyUA/1.0")]);
    }

    // -----------------------------------------------------------------------
    // Invite::respond tests
    // -----------------------------------------------------------------------

    #[test]
    fn invite_respond_custom_provisional() {
        let pbx = FakePBX::new(&[]);
        pbx.on_invite(|inv| {
            inv.trying();
            inv.respond(182, "Queued", &[("X-Queue-Position", "3")]);
            inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
        });

        let branch = sip::generate_branch();
        let invite = format!(
            "INVITE sip:1002@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:9999;branch={}\r\n\
             From: <sip:alice@127.0.0.1>;tag=rsp1\r\n\
             To: <sip:1002@127.0.0.1>\r\n\
             Call-ID: respond-1\r\n\
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
        let mut got_182 = false;
        let mut got_queue_header = false;
        let mut got_200 = false;
        for _ in 0..10 {
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                if let Some(msg) = sip::parse(&buf[..n]) {
                    if msg.status_code == 182 {
                        got_182 = true;
                        if msg.header("X-Queue-Position") == Some("3") {
                            got_queue_header = true;
                        }
                    }
                    if msg.status_code == 200 {
                        got_200 = true;
                        break;
                    }
                }
            }
        }
        assert!(got_182, "never received 182 Queued");
        assert!(got_queue_header, "missing X-Queue-Position header");
        assert!(got_200, "never received 200 OK");
    }

    #[test]
    fn invite_respond_final_only_once() {
        let pbx = FakePBX::new(&[]);
        pbx.on_invite(|inv| {
            inv.respond(200, "OK", &[("Content-Type", "application/sdp")]);
            // Second final response should be ignored.
            inv.respond(200, "OK", &[]);
        });

        let branch = sip::generate_branch();
        let invite = format!(
            "INVITE sip:1002@{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:9999;branch={}\r\n\
             From: <sip:alice@127.0.0.1>;tag=rsp2\r\n\
             To: <sip:1002@127.0.0.1>\r\n\
             Call-ID: respond-2\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:alice@127.0.0.1:9999>\r\n\
             Content-Length: 0\r\n\
             \r\n",
            pbx.addr(),
            branch
        );

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let addr: SocketAddr = pbx.addr().parse().unwrap();
        sock.send_to(invite.as_bytes(), addr).unwrap();

        let mut buf = [0u8; 4096];
        let mut ok_count = 0;
        for _ in 0..5 {
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                if let Some(msg) = sip::parse(&buf[..n]) {
                    if msg.status_code == 200 {
                        ok_count += 1;
                    }
                }
            }
        }
        assert_eq!(ok_count, 1, "should only receive one 200 OK");
    }
}
