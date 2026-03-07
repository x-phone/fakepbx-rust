//! Request recording and inspection for FakePBX.

use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::sip::SipMessage;

/// A recorded SIP request with timestamp.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub request: SipMessage,
    pub timestamp: Instant,
}

/// Thread-safe request recorder.
pub struct Recorder {
    inner: Mutex<RecorderInner>,
}

struct RecorderInner {
    requests: Vec<(String, RecordedRequest)>, // (method, record)
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}

impl Recorder {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RecorderInner {
                requests: Vec::new(),
            }),
        }
    }

    /// Records a request.
    pub fn record(&self, method: &str, req: SipMessage) {
        self.inner.lock().requests.push((
            method.to_string(),
            RecordedRequest {
                request: req,
                timestamp: Instant::now(),
            },
        ));
    }

    /// Returns all recorded requests for the given method.
    pub fn requests(&self, method: &str) -> Vec<RecordedRequest> {
        self.inner
            .lock()
            .requests
            .iter()
            .filter(|(m, _)| m == method)
            .map(|(_, r)| r.clone())
            .collect()
    }

    /// Returns the count of recorded requests for the given method.
    pub fn count(&self, method: &str) -> usize {
        self.inner
            .lock()
            .requests
            .iter()
            .filter(|(m, _)| m == method)
            .count()
    }

    /// Returns the most recent request for the given method, or None.
    pub fn last(&self, method: &str) -> Option<RecordedRequest> {
        self.inner
            .lock()
            .requests
            .iter()
            .rev()
            .find(|(m, _)| m == method)
            .map(|(_, r)| r.clone())
    }

    /// Blocks until at least `n` requests of the given method have been recorded,
    /// or the timeout expires. Returns true if the condition was met.
    pub fn wait_for(&self, method: &str, n: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.count(method) >= n {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_msg(method: &str) -> SipMessage {
        SipMessage {
            method: method.to_string(),
            uri: "sip:test@127.0.0.1".to_string(),
            status_code: 0,
            reason: String::new(),
            headers: Vec::new(),
            body: String::new(),
        }
    }

    #[test]
    fn record_and_count() {
        let rec = Recorder::new();
        rec.record("REGISTER", dummy_msg("REGISTER"));
        rec.record("INVITE", dummy_msg("INVITE"));
        rec.record("REGISTER", dummy_msg("REGISTER"));
        assert_eq!(rec.count("REGISTER"), 2);
        assert_eq!(rec.count("INVITE"), 1);
        assert_eq!(rec.count("BYE"), 0);
    }

    #[test]
    fn last_returns_most_recent() {
        let rec = Recorder::new();
        let mut msg1 = dummy_msg("INVITE");
        msg1.uri = "sip:first@test".to_string();
        let mut msg2 = dummy_msg("INVITE");
        msg2.uri = "sip:second@test".to_string();
        rec.record("INVITE", msg1);
        rec.record("INVITE", msg2);
        assert_eq!(rec.last("INVITE").unwrap().request.uri, "sip:second@test");
    }

    #[test]
    fn wait_for_immediate() {
        let rec = Recorder::new();
        rec.record("BYE", dummy_msg("BYE"));
        assert!(rec.wait_for("BYE", 1, Duration::from_millis(100)));
    }

    #[test]
    fn wait_for_timeout() {
        let rec = Recorder::new();
        assert!(!rec.wait_for("BYE", 1, Duration::from_millis(50)));
    }
}
