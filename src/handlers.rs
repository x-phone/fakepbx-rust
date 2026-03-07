//! SIP request handler types for FakePBX.
//!
//! Each handler type wraps an incoming SIP request and the UDP socket/address
//! needed to send responses. Response methods use `Once` guards to prevent
//! sending multiple final responses.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::sip::{self, SipMessage};

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

/// Handle for an incoming REGISTER request.
pub struct Register {
    pub(crate) req: SipMessage,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) remote: SocketAddr,
    pub(crate) responded: AtomicBool,
}

impl Register {
    /// Returns the original REGISTER request.
    pub fn request(&self) -> &SipMessage {
        &self.req
    }

    /// Sends 200 OK.
    pub fn accept(&self) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, 200, "OK");
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }

    /// Sends 401 Unauthorized with a WWW-Authenticate challenge.
    pub fn challenge(&self, realm: &str, nonce: &str) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut resp = sip::new_response(&self.req, 401, "Unauthorized");
        resp.add_header(
            "WWW-Authenticate",
            &format!(
                "Digest realm=\"{}\", nonce=\"{}\", algorithm=MD5",
                realm, nonce
            ),
        );
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }

    /// Sends a non-2xx final response.
    pub fn reject(&self, code: u16, reason: &str) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, code, reason);
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }
}

// ---------------------------------------------------------------------------
// Invite
// ---------------------------------------------------------------------------

/// Handle for an incoming INVITE request.
pub struct Invite {
    pub(crate) req: SipMessage,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) remote: SocketAddr,
    pub(crate) local_addr: String,
    pub(crate) responded_final: AtomicBool,
    pub(crate) cancel_flag: Arc<AtomicBool>,
    /// The To-tag assigned by the first provisional/final response.
    pub(crate) to_tag: Mutex<Option<String>>,
}

impl Invite {
    /// Returns the original INVITE request.
    pub fn request(&self) -> &SipMessage {
        &self.req
    }

    /// Returns the From URI.
    pub fn from(&self) -> Option<String> {
        self.req.header("From").map(|s| s.to_string())
    }

    /// Returns the To URI.
    pub fn to(&self) -> Option<String> {
        self.req.header("To").map(|s| s.to_string())
    }

    /// Returns the SDP body from the INVITE.
    pub fn sdp(&self) -> &str {
        &self.req.body
    }

    /// Sends 100 Trying.
    pub fn trying(&self) {
        let resp = sip::new_response(&self.req, 100, "Trying");
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }

    /// Sends 180 Ringing.
    pub fn ringing(&self) {
        let mut resp = self.build_provisional(180, "Ringing");
        resp.add_header("Contact", &format!("<sip:{}>", self.local_addr));
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }

    /// Sends 183 Session Progress with SDP (early media).
    pub fn early_media(&self, sdp_body: &str) {
        let mut resp = self.build_provisional(183, "Session Progress");
        resp.add_header("Contact", &format!("<sip:{}>", self.local_addr));
        resp.add_header("Content-Type", "application/sdp");
        resp.body = sdp_body.to_string();
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }

    /// Sends 200 OK with SDP and returns an `ActiveCall` handle for in-dialog actions.
    pub fn answer(&self, sdp_body: &str) -> Option<ActiveCall> {
        self.answer_with_code(200, sdp_body)
    }

    /// Sends a 2xx response with SDP and returns an `ActiveCall`.
    pub fn answer_with_code(&self, code: u16, sdp_body: &str) -> Option<ActiveCall> {
        if self.responded_final.swap(true, Ordering::SeqCst) {
            return None;
        }
        let mut resp = self.build_response(code, "OK");
        resp.add_header("Contact", &format!("<sip:{}>", self.local_addr));
        resp.add_header("Content-Type", "application/sdp");
        resp.body = sdp_body.to_string();
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);

        // Build ActiveCall for in-dialog requests.
        Some(ActiveCall::new(
            Arc::clone(&self.socket),
            self.remote,
            self.local_addr.clone(),
            self.req.header("Call-ID").unwrap_or("").to_string(),
            // From/To are swapped for PBX-initiated requests.
            resp.header("To").unwrap_or("").to_string(), // PBX is "From" in dialog
            resp.header("From").unwrap_or("").to_string(), // Remote is "To" in dialog
            self.req.contact().unwrap_or(self.req.uri.clone()),
        ))
    }

    /// Sends a non-2xx final response (e.g. 486 Busy Here).
    pub fn reject(&self, code: u16, reason: &str) {
        if self.responded_final.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = self.build_response(code, reason);
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }

    /// Blocks until a CANCEL is received for this INVITE, or the timeout expires.
    pub fn wait_for_cancel(&self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if self.cancel_flag.load(Ordering::SeqCst) {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    fn build_provisional(&self, code: u16, reason: &str) -> SipMessage {
        let mut resp = sip::new_response(&self.req, code, reason);
        // Ensure consistent To-tag across provisionals.
        let mut tag_lock = self.to_tag.lock();
        if tag_lock.is_none() {
            *tag_lock = Some(sip::generate_tag());
        }
        if let Some(to) = self.req.header("To") {
            if crate::sip::extract_digest_param(to, "tag").is_none() {
                resp.set_header("To", &format!("{};tag={}", to, tag_lock.as_ref().unwrap()));
            }
        }
        resp
    }

    fn build_response(&self, code: u16, reason: &str) -> SipMessage {
        let mut resp = sip::new_response(&self.req, code, reason);
        // Ensure consistent To-tag.
        let mut tag_lock = self.to_tag.lock();
        if tag_lock.is_none() {
            *tag_lock = Some(sip::generate_tag());
        }
        if let Some(ref tag) = *tag_lock {
            if let Some(to) = self.req.header("To") {
                if crate::sip::extract_digest_param(to, "tag").is_none() {
                    resp.set_header("To", &format!("{};tag={}", to, tag));
                }
            }
        }
        resp
    }
}

// ---------------------------------------------------------------------------
// ActiveCall
// ---------------------------------------------------------------------------

/// Handle for an established call, returned by `Invite::answer()`.
///
/// Allows the PBX to send in-dialog requests (BYE, re-INVITE, NOTIFY).
pub struct ActiveCall {
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    local_addr: String,
    call_id: String,
    from: String, // PBX's From (was the To in the original INVITE)
    to: String,   // Remote's To (was the From in the original INVITE)
    remote_contact: String,
    cseq: AtomicU32,
}

impl ActiveCall {
    fn new(
        socket: Arc<UdpSocket>,
        remote: SocketAddr,
        local_addr: String,
        call_id: String,
        from: String,
        to: String,
        remote_contact: String,
    ) -> Self {
        Self {
            socket,
            remote,
            local_addr,
            call_id,
            from,
            to,
            remote_contact,
            cseq: AtomicU32::new(1000),
        }
    }

    /// Sends BYE to hang up the call from the PBX side.
    /// Returns the response status code, or an error.
    pub fn send_bye(&self) -> Result<u16, String> {
        let cseq = self.cseq.fetch_add(1, Ordering::SeqCst);
        let via = format!(
            "SIP/2.0/UDP {};branch={}",
            self.local_addr,
            sip::generate_branch()
        );
        let mut req = sip::new_dialog_request(
            "BYE",
            &self.remote_contact,
            &self.call_id,
            &self.from,
            &self.to,
            &via,
            cseq,
        );
        req.add_header("Contact", &format!("<sip:{}>", self.local_addr));

        self.send_and_wait_response(&req)
    }

    /// Sends a re-INVITE with new SDP (e.g. for hold).
    pub fn send_reinvite(&self, sdp_body: &str) -> Result<u16, String> {
        let cseq = self.cseq.fetch_add(1, Ordering::SeqCst);
        let via = format!(
            "SIP/2.0/UDP {};branch={}",
            self.local_addr,
            sip::generate_branch()
        );
        let mut req = sip::new_dialog_request(
            "INVITE",
            &self.remote_contact,
            &self.call_id,
            &self.from,
            &self.to,
            &via,
            cseq,
        );
        req.add_header("Contact", &format!("<sip:{}>", self.local_addr));
        req.add_header("Content-Type", "application/sdp");
        req.body = sdp_body.to_string();

        self.send_and_wait_response(&req)
    }

    /// Sends a NOTIFY request (e.g. for REFER progress).
    pub fn send_notify(&self, event: &str, body: &str) -> Result<u16, String> {
        let cseq = self.cseq.fetch_add(1, Ordering::SeqCst);
        let via = format!(
            "SIP/2.0/UDP {};branch={}",
            self.local_addr,
            sip::generate_branch()
        );
        let mut req = sip::new_dialog_request(
            "NOTIFY",
            &self.remote_contact,
            &self.call_id,
            &self.from,
            &self.to,
            &via,
            cseq,
        );
        req.add_header("Event", event);
        req.add_header("Contact", &format!("<sip:{}>", self.local_addr));
        if !body.is_empty() {
            req.body = body.to_string();
        }

        self.send_and_wait_response(&req)
    }

    fn send_and_wait_response(&self, req: &SipMessage) -> Result<u16, String> {
        self.socket
            .send_to(&req.to_bytes(), self.remote)
            .map_err(|e| format!("send failed: {}", e))?;

        // Wait for response with timeout.
        let mut buf = [0u8; 4096];
        self.socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((n, _)) => {
                    if let Some(msg) = sip::parse(&buf[..n]) {
                        if !msg.is_request() {
                            return Ok(msg.status_code);
                        }
                        // Skip requests (e.g. incoming BYE crossing), keep waiting.
                    }
                }
                Err(e) => return Err(format!("recv timeout: {}", e)),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bye
// ---------------------------------------------------------------------------

/// Handle for an incoming BYE request.
pub struct Bye {
    pub(crate) req: SipMessage,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) remote: SocketAddr,
    pub(crate) responded: AtomicBool,
}

impl Bye {
    pub fn request(&self) -> &SipMessage {
        &self.req
    }

    pub fn accept(&self) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, 200, "OK");
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }

    pub fn reject(&self, code: u16, reason: &str) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, code, reason);
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }
}

// ---------------------------------------------------------------------------
// Cancel
// ---------------------------------------------------------------------------

/// Handle for an incoming CANCEL request (notification-only).
pub struct Cancel {
    pub(crate) req: SipMessage,
}

impl Cancel {
    pub fn request(&self) -> &SipMessage {
        &self.req
    }
}

// ---------------------------------------------------------------------------
// Ack
// ---------------------------------------------------------------------------

/// Handle for an incoming ACK request.
pub struct Ack {
    pub(crate) req: SipMessage,
}

impl Ack {
    pub fn request(&self) -> &SipMessage {
        &self.req
    }

    pub fn sdp(&self) -> &str {
        &self.req.body
    }
}

// ---------------------------------------------------------------------------
// Refer
// ---------------------------------------------------------------------------

/// Handle for an incoming REFER request.
pub struct Refer {
    pub(crate) req: SipMessage,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) remote: SocketAddr,
    pub(crate) responded: AtomicBool,
}

impl Refer {
    pub fn request(&self) -> &SipMessage {
        &self.req
    }

    /// Returns the Refer-To URI (angle brackets stripped).
    pub fn refer_to(&self) -> Option<String> {
        let val = self.req.header("Refer-To")?;
        let val = val.trim();
        if val.starts_with('<') && val.ends_with('>') {
            Some(val[1..val.len() - 1].to_string())
        } else {
            Some(val.to_string())
        }
    }

    pub fn accept(&self) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, 202, "Accepted");
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }

    pub fn reject(&self, code: u16, reason: &str) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, code, reason);
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Handle for an incoming OPTIONS request.
pub struct Options {
    pub(crate) req: SipMessage,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) remote: SocketAddr,
    pub(crate) responded: AtomicBool,
}

impl Options {
    pub fn request(&self) -> &SipMessage {
        &self.req
    }

    pub fn accept(&self) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, 200, "OK");
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }

    pub fn reject(&self, code: u16, reason: &str) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, code, reason);
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }
}

// ---------------------------------------------------------------------------
// Info
// ---------------------------------------------------------------------------

/// Handle for an incoming INFO request.
pub struct Info {
    pub(crate) req: SipMessage,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) remote: SocketAddr,
    pub(crate) responded: AtomicBool,
}

impl Info {
    pub fn request(&self) -> &SipMessage {
        &self.req
    }

    pub fn body(&self) -> &str {
        &self.req.body
    }

    pub fn accept(&self) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, 200, "OK");
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }

    pub fn reject(&self, code: u16, reason: &str) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, code, reason);
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// Handle for an incoming MESSAGE request.
pub struct Message {
    pub(crate) req: SipMessage,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) remote: SocketAddr,
    pub(crate) responded: AtomicBool,
}

impl Message {
    pub fn request(&self) -> &SipMessage {
        &self.req
    }

    pub fn body(&self) -> &str {
        &self.req.body
    }

    pub fn accept(&self) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, 200, "OK");
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }

    pub fn reject(&self, code: u16, reason: &str) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, code, reason);
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }
}

// ---------------------------------------------------------------------------
// Subscribe
// ---------------------------------------------------------------------------

/// Handle for an incoming SUBSCRIBE request.
pub struct Subscribe {
    pub(crate) req: SipMessage,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) remote: SocketAddr,
    pub(crate) responded: AtomicBool,
}

impl Subscribe {
    pub fn request(&self) -> &SipMessage {
        &self.req
    }

    pub fn event(&self) -> Option<&str> {
        self.req.header("Event")
    }

    pub fn accept(&self) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, 200, "OK");
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }

    pub fn reject(&self, code: u16, reason: &str) {
        if self.responded.swap(true, Ordering::SeqCst) {
            return;
        }
        let resp = sip::new_response(&self.req, code, reason);
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
    }
}
