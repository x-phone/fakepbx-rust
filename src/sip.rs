//! Minimal SIP message parsing and building for FakePBX.
//!
//! This is intentionally minimal — just enough for a test UAS.
//! Not a general-purpose SIP library.

/// A parsed SIP message (request or response).
#[derive(Debug, Clone)]
pub struct SipMessage {
    /// For requests: method (e.g. "INVITE"). For responses: empty.
    pub method: String,
    /// For requests: Request-URI. For responses: empty.
    pub uri: String,
    /// For responses: status code. For requests: 0.
    pub status_code: u16,
    /// For responses: reason phrase. For requests: empty.
    pub reason: String,
    /// Headers (case-preserved keys, multiple values per key).
    pub headers: Vec<(String, String)>,
    /// Message body.
    pub body: String,
}

impl SipMessage {
    /// Returns true if this is a SIP request.
    pub fn is_request(&self) -> bool {
        !self.method.is_empty()
    }

    /// Returns the first header value matching the name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Returns all header values matching the name (case-insensitive).
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Sets (replaces) a header. Removes existing headers with the same name.
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// Adds a header (does not remove existing).
    pub fn add_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// Returns the Via branch parameter.
    pub fn via_branch(&self) -> Option<String> {
        let via = self.header("Via")?;
        for part in via.split(';') {
            let part = part.trim();
            if let Some(val) = part.strip_prefix("branch=") {
                return Some(val.to_string());
            }
        }
        None
    }

    /// Returns the From tag.
    pub fn from_tag(&self) -> Option<String> {
        extract_tag(self.header("From")?)
    }

    /// Returns the To tag.
    pub fn to_tag(&self) -> Option<String> {
        extract_tag(self.header("To")?)
    }

    /// Returns the Call-ID.
    pub fn call_id(&self) -> Option<&str> {
        self.header("Call-ID")
    }

    /// Returns the CSeq number.
    pub fn cseq_num(&self) -> Option<u32> {
        let cseq = self.header("CSeq")?;
        cseq.split_whitespace().next()?.parse().ok()
    }

    /// Returns the CSeq method.
    pub fn cseq_method(&self) -> Option<&str> {
        let cseq = self.header("CSeq")?;
        cseq.split_whitespace().nth(1)
    }

    /// Returns the Contact URI.
    pub fn contact(&self) -> Option<String> {
        let contact = self.header("Contact")?;
        // Strip angle brackets and params.
        if let Some(start) = contact.find('<') {
            if let Some(end) = contact.find('>') {
                return Some(contact[start + 1..end].to_string());
            }
        }
        Some(contact.split(';').next()?.trim().to_string())
    }

    /// Serializes the message to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        if self.is_request() {
            out.push_str(&format!("{} {} SIP/2.0\r\n", self.method, self.uri));
        } else {
            out.push_str(&format!("SIP/2.0 {} {}\r\n", self.status_code, self.reason));
        }
        for (k, v) in &self.headers {
            if k.eq_ignore_ascii_case("Content-Length") {
                continue; // We'll add it ourselves.
            }
            out.push_str(&format!("{}: {}\r\n", k, v));
        }
        out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        out.push_str("\r\n");
        out.push_str(&self.body);
        out.into_bytes()
    }
}

/// Builds a SIP response from a request.
pub fn new_response(req: &SipMessage, code: u16, reason: &str) -> SipMessage {
    let mut resp = SipMessage {
        method: String::new(),
        uri: String::new(),
        status_code: code,
        reason: reason.to_string(),
        headers: Vec::new(),
        body: String::new(),
    };
    // Copy Via, From, To, Call-ID, CSeq from request.
    for name in &["Via", "From", "Call-ID", "CSeq"] {
        for val in req.header_values(name) {
            resp.add_header(name, val);
        }
    }
    // Copy To header, add tag if not present for non-100.
    if let Some(to) = req.header("To") {
        resp.set_header("To", to);
        if code > 100 && extract_tag(to).is_none() {
            let tag = generate_tag();
            resp.set_header("To", &format!("{};tag={}", to, tag));
        }
    }
    resp
}

/// Builds an in-dialog SIP request.
pub fn new_dialog_request(
    method: &str,
    request_uri: &str,
    call_id: &str,
    from: &str,
    to: &str,
    via: &str,
    cseq: u32,
) -> SipMessage {
    let mut msg = SipMessage {
        method: method.to_string(),
        uri: request_uri.to_string(),
        status_code: 0,
        reason: String::new(),
        headers: Vec::new(),
        body: String::new(),
    };
    msg.add_header("Via", via);
    msg.add_header("From", from);
    msg.add_header("To", to);
    msg.add_header("Call-ID", call_id);
    msg.add_header("CSeq", &format!("{} {}", cseq, method));
    msg.add_header("Max-Forwards", "70");
    msg
}

/// Parses a raw SIP message from bytes.
pub fn parse(data: &[u8]) -> Option<SipMessage> {
    let text = std::str::from_utf8(data).ok()?;
    let (head, body) = if let Some(pos) = text.find("\r\n\r\n") {
        (&text[..pos], &text[pos + 4..])
    } else {
        (text, "")
    };

    let mut lines = head.lines();
    let first_line = lines.next()?;

    let mut msg = if first_line.starts_with("SIP/2.0") {
        // Response: "SIP/2.0 200 OK"
        let mut parts = first_line.splitn(3, ' ');
        parts.next()?; // "SIP/2.0"
        let code: u16 = parts.next()?.parse().ok()?;
        let reason = parts.next().unwrap_or("").to_string();
        SipMessage {
            method: String::new(),
            uri: String::new(),
            status_code: code,
            reason,
            headers: Vec::new(),
            body: String::new(),
        }
    } else {
        // Request: "INVITE sip:1002@127.0.0.1:5060 SIP/2.0"
        let mut parts = first_line.splitn(3, ' ');
        let method = parts.next()?.to_string();
        let uri = parts.next()?.to_string();
        SipMessage {
            method,
            uri,
            status_code: 0,
            reason: String::new(),
            headers: Vec::new(),
            body: String::new(),
        }
    };

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            msg.headers
                .push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    msg.body = body.to_string();
    Some(msg)
}

/// Extracts `tag=xxx` from a From/To header value.
fn extract_tag(header_val: &str) -> Option<String> {
    for part in header_val.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("tag=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Generates a random tag for SIP headers.
pub fn generate_tag() -> String {
    let mut buf = [0u8; 8];
    let _ = getrandom::getrandom(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Generates a random branch ID for Via headers.
pub fn generate_branch() -> String {
    let mut buf = [0u8; 12];
    let _ = getrandom::getrandom(&mut buf);
    let hex: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    format!("z9hG4bK{}", hex)
}

/// Extracts a quoted parameter from a Digest auth header.
/// e.g. extractDigestParam("Digest username=\"bob\"", "username") -> "bob"
pub fn extract_digest_param(header: &str, param: &str) -> Option<String> {
    let prefix = format!("{}=\"", param);
    let idx = header.find(&prefix)?;
    let start = idx + prefix.len();
    let end = header[start..].find('"')?;
    Some(header[start..start + end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request() {
        let raw = b"REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n\
            Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK776\r\n\
            From: <sip:alice@127.0.0.1>;tag=abc123\r\n\
            To: <sip:alice@127.0.0.1>\r\n\
            Call-ID: call-1@127.0.0.1\r\n\
            CSeq: 1 REGISTER\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = parse(raw).unwrap();
        assert!(msg.is_request());
        assert_eq!(msg.method, "REGISTER");
        assert_eq!(msg.header("Call-ID").unwrap(), "call-1@127.0.0.1");
        assert_eq!(msg.from_tag().unwrap(), "abc123");
        assert!(msg.to_tag().is_none());
        assert_eq!(msg.cseq_num().unwrap(), 1);
        assert_eq!(msg.cseq_method().unwrap(), "REGISTER");
    }

    #[test]
    fn parse_response() {
        let raw = b"SIP/2.0 200 OK\r\n\
            Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK776\r\n\
            From: <sip:alice@127.0.0.1>;tag=abc123\r\n\
            To: <sip:alice@127.0.0.1>;tag=xyz789\r\n\
            Call-ID: call-1@127.0.0.1\r\n\
            CSeq: 1 REGISTER\r\n\
            Content-Length: 0\r\n\
            \r\n";
        let msg = parse(raw).unwrap();
        assert!(!msg.is_request());
        assert_eq!(msg.status_code, 200);
        assert_eq!(msg.reason, "OK");
    }

    #[test]
    fn new_response_copies_headers() {
        let raw = b"INVITE sip:1002@127.0.0.1 SIP/2.0\r\n\
            Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK776\r\n\
            From: <sip:alice@127.0.0.1>;tag=abc123\r\n\
            To: <sip:bob@127.0.0.1>\r\n\
            Call-ID: inv-1\r\n\
            CSeq: 1 INVITE\r\n\
            \r\n";
        let req = parse(raw).unwrap();
        let resp = new_response(&req, 200, "OK");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.header("Call-ID").unwrap(), "inv-1");
        // To should have a tag added.
        assert!(resp.to_tag().is_some());
    }

    #[test]
    fn roundtrip_serialize() {
        let raw = b"REGISTER sip:127.0.0.1 SIP/2.0\r\n\
            Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK776\r\n\
            From: <sip:alice@127.0.0.1>;tag=abc\r\n\
            To: <sip:alice@127.0.0.1>\r\n\
            Call-ID: c1\r\n\
            CSeq: 1 REGISTER\r\n\
            \r\n";
        let msg = parse(raw).unwrap();
        let bytes = msg.to_bytes();
        let msg2 = parse(&bytes).unwrap();
        assert_eq!(msg2.method, "REGISTER");
        assert_eq!(msg2.header("Call-ID").unwrap(), "c1");
    }

    #[test]
    fn digest_param_extraction() {
        let hdr = r#"Digest username="alice", realm="fakepbx", nonce="abc123", uri="sip:127.0.0.1", response="deadbeef""#;
        assert_eq!(extract_digest_param(hdr, "username").unwrap(), "alice");
        assert_eq!(extract_digest_param(hdr, "realm").unwrap(), "fakepbx");
        assert_eq!(extract_digest_param(hdr, "nonce").unwrap(), "abc123");
        assert!(extract_digest_param(hdr, "missing").is_none());
    }
}
