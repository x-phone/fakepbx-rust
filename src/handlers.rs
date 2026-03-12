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

    /// Sends an arbitrary response with optional extra headers.
    ///
    /// Provisional responses (1xx) can be sent multiple times.
    /// Final responses (2xx+) can only be sent once.
    pub fn respond(&self, code: u16, reason: &str, headers: &[(&str, &str)]) {
        if code >= 200 {
            if self.responded_final.swap(true, Ordering::SeqCst) {
                return;
            }
        } else if self.responded_final.load(Ordering::SeqCst) {
            // Don't send provisionals after a final response.
            return;
        }
        let mut resp = self.build_response(code, reason);
        resp.add_header("Contact", &format!("<sip:{}>", self.local_addr));
        for (name, value) in headers {
            resp.add_header(name, value);
        }
        let _ = self.socket.send_to(&resp.to_bytes(), self.remote);
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
// DialogCall — shared base for in-dialog requests (ActiveCall, OutboundCall)
// ---------------------------------------------------------------------------

/// Shared state and methods for an established SIP dialog.
///
/// Both [`ActiveCall`] (UAS-side) and [`OutboundCall`] (UAC-side) delegate
/// in-dialog request methods (BYE, re-INVITE, REFER, NOTIFY) to this type.
pub struct DialogCall {
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    local_addr: String,
    call_id: String,
    from: String,
    to: String,
    remote_contact: String,
    cseq: AtomicU32,
}

impl DialogCall {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        socket: Arc<UdpSocket>,
        remote: SocketAddr,
        local_addr: String,
        call_id: String,
        from: String,
        to: String,
        remote_contact: String,
        initial_cseq: u32,
    ) -> Self {
        Self {
            socket,
            remote,
            local_addr,
            call_id,
            from,
            to,
            remote_contact,
            cseq: AtomicU32::new(initial_cseq),
        }
    }

    /// Sends BYE to hang up the call.
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

    /// Sends a REFER request for call transfer.
    pub fn send_refer(&self, refer_to: &str) -> Result<u16, String> {
        let cseq = self.cseq.fetch_add(1, Ordering::SeqCst);
        let via = format!(
            "SIP/2.0/UDP {};branch={}",
            self.local_addr,
            sip::generate_branch()
        );
        let mut req = sip::new_dialog_request(
            "REFER",
            &self.remote_contact,
            &self.call_id,
            &self.from,
            &self.to,
            &via,
            cseq,
        );
        req.add_header("Refer-To", refer_to);
        req.add_header("Contact", &format!("<sip:{}>", self.local_addr));

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

        // Save and restore the read timeout to avoid mutating the shared socket.
        let prev_timeout = self.socket.read_timeout().ok().flatten();
        self.socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        let mut buf = [0u8; 4096];
        let result = loop {
            match self.socket.recv_from(&mut buf) {
                Ok((n, _)) => {
                    if let Some(msg) = sip::parse(&buf[..n]) {
                        if !msg.is_request() {
                            break Ok(msg.status_code);
                        }
                        // Skip requests (e.g. incoming BYE crossing), keep waiting.
                    }
                }
                Err(e) => break Err(format!("recv timeout: {}", e)),
            }
        };
        self.socket.set_read_timeout(prev_timeout).ok();
        result
    }
}

// ---------------------------------------------------------------------------
// ActiveCall
// ---------------------------------------------------------------------------

/// Handle for an established call, returned by `Invite::answer()`.
///
/// Allows the PBX to send in-dialog requests (BYE, re-INVITE, REFER, NOTIFY).
pub struct ActiveCall {
    inner: DialogCall,
}

impl ActiveCall {
    pub(crate) fn new(
        socket: Arc<UdpSocket>,
        remote: SocketAddr,
        local_addr: String,
        call_id: String,
        from: String,
        to: String,
        remote_contact: String,
    ) -> Self {
        Self {
            inner: DialogCall::new(
                socket,
                remote,
                local_addr,
                call_id,
                from,
                to,
                remote_contact,
                1000,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// OutboundCall
// ---------------------------------------------------------------------------

/// Handle for an outbound call initiated by `FakePBX::send_invite()`.
///
/// Allows the PBX to send in-dialog requests (BYE, re-INVITE, REFER, NOTIFY)
/// on a call that the PBX originated.
pub struct OutboundCall {
    inner: DialogCall,
    request: SipMessage,
    response: SipMessage,
}

impl OutboundCall {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        socket: Arc<UdpSocket>,
        remote: SocketAddr,
        local_addr: String,
        call_id: String,
        from: String,
        to: String,
        remote_contact: String,
        initial_cseq: u32,
        request: SipMessage,
        response: SipMessage,
    ) -> Self {
        Self {
            inner: DialogCall::new(
                socket,
                remote,
                local_addr,
                call_id,
                from,
                to,
                remote_contact,
                initial_cseq,
            ),
            request,
            response,
        }
    }

    /// Returns the original INVITE request that was sent.
    pub fn request(&self) -> &SipMessage {
        &self.request
    }

    /// Returns the 2xx response received from the remote.
    pub fn response(&self) -> &SipMessage {
        &self.response
    }
}

impl std::ops::Deref for OutboundCall {
    type Target = DialogCall;
    fn deref(&self) -> &DialogCall {
        &self.inner
    }
}

impl std::fmt::Debug for OutboundCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundCall")
            .field("request", &self.request.method)
            .field("response", &self.response.status_code)
            .finish()
    }
}

impl std::ops::Deref for ActiveCall {
    type Target = DialogCall;
    fn deref(&self) -> &DialogCall {
        &self.inner
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
