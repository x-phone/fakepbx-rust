# fakepbx

[![CI](https://github.com/x-phone/fakepbx-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/x-phone/fakepbx-rust/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/fakepbx.svg)](https://crates.io/crates/fakepbx)
[![docs.rs](https://docs.rs/fakepbx/badge.svg)](https://docs.rs/fakepbx)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

In-process SIP server (UAS + UAC) for testing — no Docker, no external processes, no hardcoded ports.

Rust port of [github.com/x-phone/fakepbx](https://github.com/x-phone/fakepbx).

## Usage

```rust
use fakepbx::{FakePBX, sdp, with_auth};

// Start a PBX on 127.0.0.1 with an ephemeral port.
let pbx = FakePBX::new(&[with_auth("alice", "secret")]);

// Program the call flow.
pbx.on_invite(|inv| {
    inv.trying();
    inv.ringing();
    inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
});

// Point your SIP UA at pbx.addr() and dial.
println!("PBX listening on {}", pbx.addr());
println!("Dial: {}", pbx.uri("1002"));

// The server stops automatically when `pbx` is dropped.
```

## Supported Methods

| Method | Default Behavior | Handler |
|-----------|------------------------------|----------------------|
| REGISTER | 200 OK (or digest auth) | `on_register()` |
| INVITE | 100 + 200 OK with SDP | `on_invite()` |
| BYE | 200 OK | `on_bye()` |
| CANCEL | 200 OK + 487 to INVITE | `on_cancel()` |
| ACK | — | `on_ack()` |
| REFER | 202 Accepted | `on_refer()` |
| OPTIONS | 200 OK | `on_options()` |
| INFO | 200 OK | `on_info()` |
| MESSAGE | 200 OK | `on_message()` |
| SUBSCRIBE | 200 OK | `on_subscribe()` |

## Digest Authentication

```rust
let pbx = FakePBX::new(&[with_auth("alice", "secret")]);
// First REGISTER gets 401 with challenge, second with valid credentials gets 200.
```

## INVITE Handlers

```rust
// Auto-answer all calls.
pbx.auto_answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMA]));

// Auto-reject with 486 Busy.
pbx.auto_busy();

// Custom flow with early media.
pbx.on_invite(|inv| {
    inv.trying();
    inv.early_media(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
    std::thread::sleep(std::time::Duration::from_secs(1));
    inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
});

// Wait for CANCEL (e.g. caller hangs up before answer).
pbx.on_invite(|inv| {
    inv.trying();
    inv.ringing();
    if inv.wait_for_cancel(std::time::Duration::from_secs(10)) {
        // Caller cancelled — nothing to do, SIP stack already sent 487.
    } else {
        inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]));
    }
});
```

## ActiveCall (In-Dialog Actions)

```rust
pbx.on_invite(|inv| {
    inv.trying();
    inv.ringing();
    let ac = inv.answer(&sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU])).unwrap();

    // PBX hangs up after 2 seconds.
    std::thread::sleep(std::time::Duration::from_secs(2));
    ac.send_bye().unwrap();

    // Or: hold, transfer, notify.
    // ac.send_reinvite(&sdp::sdp_with_direction("127.0.0.1", 20000, "sendonly", &[sdp::PCMU]));
    // ac.send_refer("<sip:1003@127.0.0.1>");
    // ac.send_notify("refer", "SIP/2.0 200 OK");
});
```

## Outbound INVITE (UAC)

```rust
// PBX initiates a call to a remote SIP UA.
let oc = pbx.send_invite("sip:1002@127.0.0.1:5060", &sdp::sdp("127.0.0.1", 20000, &[sdp::PCMU]))
    .unwrap();

// Access the sent request and received response.
assert_eq!(oc.response().status_code, 200);

// In-dialog actions work the same as ActiveCall.
oc.send_bye().unwrap();
```

## Out-of-Dialog Requests

```rust
// Send a MESSAGE.
let code = pbx.send_message("sip:alice@127.0.0.1:5060", "text/plain", "hello").unwrap();
assert_eq!(code, 200);

// Send an OPTIONS ping.
let code = pbx.send_options("sip:server@127.0.0.1:5060").unwrap();
assert_eq!(code, 200);
```

## Request Inspection

```rust
// Count received requests.
assert_eq!(pbx.register_count(), 1);
assert_eq!(pbx.invite_count(), 1);

// Wait for a BYE with timeout.
assert!(pbx.wait_for_bye(1, std::time::Duration::from_secs(2)));

// Inspect the last INVITE.
let inv = pbx.last_invite().unwrap();
println!("From: {:?}", inv.request.header("From"));
```

## SDP Helpers

```rust
use fakepbx::sdp::{self, PCMU, PCMA, G722, TELEPHONE_EVENT};

// Minimal SDP with PCMU.
let s = sdp::sdp("127.0.0.1", 20000, &[PCMU]);

// Multiple codecs.
let s = sdp::sdp("127.0.0.1", 20000, &[PCMA, PCMU, TELEPHONE_EVENT]);

// With direction (hold).
let s = sdp::sdp_with_direction("127.0.0.1", 20000, "sendonly", &[PCMU]);
```

## License

MIT
