# fakepbx-rust v0.2.0 — Feature Parity Plan

Tracking feature parity with the Go `fakepbx` v0.2.0 release.
The Go v0.2.0 added UAC (User Agent Client) capabilities — the PBX can now **initiate** calls and send out-of-dialog requests, not just respond to them.

---

## Phase 1: Shared Dialog Base (Refactor)

The Go version extracted a `dialogCall` base shared by both `ActiveCall` (UAS) and `OutboundCall` (UAC). This avoids duplicating in-dialog request logic.

- [x] Extract shared dialog fields/methods from `ActiveCall` into a `DialogCall` base struct (socket, remote, local_addr, call_id, from, to, remote_contact, cseq)
- [x] Reimplement `ActiveCall` as a wrapper around `DialogCall`
- [x] Move `send_bye`, `send_reinvite`, `send_notify` to `DialogCall`
- [x] Ensure existing tests pass after refactor

## Phase 2: In-Dialog REFER (`send_refer`)

Go v0.2.0 added `SendRefer()` on both call types. Currently missing from Rust `ActiveCall`.

- [x] Add `send_refer(refer_to: &str) -> Result<u16, String>` to `DialogCall`
- [x] Add test: PBX answers INVITE, then sends REFER to transfer the call
- [x] Add test: REFER rejected by remote

## Phase 3: Outbound INVITE (UAC) — `send_invite`

Core v0.2.0 feature: FakePBX can initiate calls to a remote SIP UA.

- [x] Add `OutboundCall` struct wrapping `DialogCall` (+ stores the 2xx response)
- [x] Add `OutboundCall::response()` to access the 2xx response
- [x] Add `FakePBX::send_invite(target: &str, sdp_body: &str) -> Result<OutboundCall, String>`
  - Builds INVITE with proper headers (From with tag, To, Via with branch, Call-ID, CSeq, Contact, Content-Type, SDP body)
  - Sends via UDP, waits for responses
  - Handles provisional (1xx) responses (skip/log)
  - On 2xx: sends ACK automatically, returns `OutboundCall`
  - On non-2xx final: returns error with status code
- [x] Direction-aware From/To in `DialogCall` (UAS: From=remote/To=local; UAC: From=local/To=remote)
- [x] Add test: basic outbound INVITE answered by remote → `OutboundCall` returned
- [x] Add test: outbound INVITE rejected by remote
- [x] Add test: outbound INVITE to invalid URI → error
- [x] Add test: `OutboundCall::send_bye()` hangs up
- [x] Add test: `OutboundCall::send_reinvite()` (hold/resume)
- [x] Add test: `OutboundCall::send_refer()` (transfer)
- [x] Add test: CSeq increments correctly across multiple in-dialog requests
- [x] Add test: concurrent outbound INVITEs

## Phase 4: Out-of-Dialog MESSAGE — `send_message`

- [x] Add `FakePBX::send_message(target: &str, content_type: &str, body: &str) -> Result<u16, String>`
  - Builds MESSAGE request, sends, waits for response
- [x] Add test: basic send_message → 200 OK
- [x] Add test: send_message rejected
- [x] Add test: send_message to invalid URI → error

## Phase 5: Out-of-Dialog OPTIONS — `send_options`

- [x] Add `FakePBX::send_options(target: &str) -> Result<u16, String>`
  - Builds OPTIONS request, sends, waits for response
- [x] Add test: basic send_options → 200 OK
- [x] Add test: send_options rejected
- [x] Add test: send_options to invalid URI → error

## Phase 6: Configuration Options Parity

Go has `WithTransport()` and `WithUserAgent()` options not yet in Rust.

- [x] Add `Opt::UserAgent(String)` — custom User-Agent header (default: `"FakePBX/test"`)
- [x] Add `Opt::Transport(String)` — transport parameter (currently hardcoded UDP)
- [x] Add `FakePBX::sip_addr()` → `"127.0.0.1:PORT;transport=udp"`

## Phase 7: Invite Handler — Generic `respond`

Go's `Invite` has a `Respond(code, reason, hdrs...)` for sending arbitrary provisional/final responses with custom headers.

- [x] Add `Invite::respond(code: u16, reason: &str, headers: &[(&str, &str)])` to Invite handler
- [x] Add test: send custom provisional response with extra headers
- [x] Add test: final response only sent once

---

## Summary

| Feature                     | Go v0.2.0 | Rust | Phase |
|-----------------------------|-----------|------|-------|
| Shared dialog base          | ✅        | ✅   | 1     |
| `send_refer` (in-dialog)   | ✅        | ✅   | 2     |
| `send_invite` (UAC)        | ✅        | ✅   | 3     |
| `OutboundCall` type         | ✅        | ✅   | 3     |
| Direction-aware From/To     | ✅        | ✅   | 3     |
| `send_message` (OOD)       | ✅        | ✅   | 4     |
| `send_options` (OOD)       | ✅        | ✅   | 5     |
| `WithUserAgent` option      | ✅        | ✅   | 6     |
| `WithTransport` option      | ✅        | ✅   | 6     |
| `sip_addr()` method         | ✅        | ✅   | 7     |
| `Invite::respond` (generic) | ✅        | ✅   | 7     |
