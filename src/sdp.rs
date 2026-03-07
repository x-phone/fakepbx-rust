//! SDP helpers for FakePBX test scenarios.

/// An RTP codec description.
#[derive(Debug, Clone, Copy)]
pub struct Codec {
    pub payload_type: u8,
    pub name: &'static str,
    pub clock_rate: u32,
}

/// G.711 mu-law (payload type 0).
pub const PCMU: Codec = Codec {
    payload_type: 0,
    name: "PCMU",
    clock_rate: 8000,
};

/// G.711 A-law (payload type 8).
pub const PCMA: Codec = Codec {
    payload_type: 8,
    name: "PCMA",
    clock_rate: 8000,
};

/// G.722 (payload type 9).
pub const G722: Codec = Codec {
    payload_type: 9,
    name: "G722",
    clock_rate: 8000,
};

/// RFC 2833 DTMF events (payload type 101).
pub const TELEPHONE_EVENT: Codec = Codec {
    payload_type: 101,
    name: "telephone-event",
    clock_rate: 8000,
};

/// Builds a minimal valid SDP body with `sendrecv` direction.
///
/// If no codecs are specified, defaults to PCMU.
pub fn sdp(ip: &str, port: u16, codecs: &[Codec]) -> String {
    sdp_with_direction(ip, port, "sendrecv", codecs)
}

/// Builds a minimal valid SDP body with the given direction attribute.
///
/// Direction can be `"sendrecv"`, `"sendonly"`, `"recvonly"`, or `"inactive"`.
pub fn sdp_with_direction(ip: &str, port: u16, direction: &str, codecs: &[Codec]) -> String {
    let codecs = if codecs.is_empty() { &[PCMU] } else { codecs };

    let mut s = String::new();
    s.push_str("v=0\r\n");
    s.push_str(&format!("o=fakepbx 0 0 IN IP4 {}\r\n", ip));
    s.push_str("s=-\r\n");
    s.push_str(&format!("c=IN IP4 {}\r\n", ip));
    s.push_str("t=0 0\r\n");

    // m= line
    s.push_str(&format!("m=audio {} RTP/AVP", port));
    for c in codecs {
        s.push_str(&format!(" {}", c.payload_type));
    }
    s.push_str("\r\n");

    // a=rtpmap lines
    for c in codecs {
        s.push_str(&format!(
            "a=rtpmap:{} {}/{}\r\n",
            c.payload_type, c.name, c.clock_rate
        ));
        if c.payload_type == 101 {
            s.push_str("a=fmtp:101 0-16\r\n");
        }
    }

    // Direction attribute.
    if !direction.is_empty() {
        s.push_str(&format!("a={}\r\n", direction));
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_sdp() {
        let s = sdp("127.0.0.1", 20000, &[]);
        assert!(s.contains("m=audio 20000 RTP/AVP 0"));
        assert!(s.contains("a=rtpmap:0 PCMU/8000"));
        assert!(s.contains("a=sendrecv"));
    }

    #[test]
    fn sdp_with_pcma() {
        let s = sdp("127.0.0.1", 30000, &[PCMA]);
        assert!(s.contains("m=audio 30000 RTP/AVP 8"));
        assert!(s.contains("a=rtpmap:8 PCMA/8000"));
    }

    #[test]
    fn sdp_with_direction_sendonly() {
        let s = sdp_with_direction("127.0.0.1", 20000, "sendonly", &[PCMU]);
        assert!(s.contains("a=sendonly"));
        assert!(!s.contains("a=sendrecv"));
    }

    #[test]
    fn sdp_multiple_codecs() {
        let s = sdp("127.0.0.1", 20000, &[PCMU, PCMA, TELEPHONE_EVENT]);
        assert!(s.contains("m=audio 20000 RTP/AVP 0 8 101"));
        assert!(s.contains("a=fmtp:101 0-16"));
    }
}
