# FIX Protocol Stack — Build Specification

## Project Overview

Build a minimal but functional FIX protocol stack simulating a full round-trip order flow between a client and an exchange. The project demonstrates: FIX session management, message serialisation/parsing, a security layer (TLS + optional AES), TCP transport, and a basic exchange simulator that processes orders and sends back execution reports.

This is an educational/portfolio project. Correctness and clean layering matter more than throughput.

---

## Architecture

The stack has two sides — sender and receiver — connected over TCP with TLS.

```
[ FIX Simulator ]          <- generates NewOrderSingle, cancel/replace, etc.
        ↓
[ FIX Engine — Sender ]    <- session state, sequence numbers, serialise to tag=value
        ↓
[ Security Layer ]         <- TLS (transport), optional AES-256-GCM (payload)
        ↓
[ TCP Transport ]          <- raw socket, connect/listen
        ↓
--------- NETWORK ---------
        ↓
[ TCP Transport ]          <- accept connection, recv bytes
        ↓
[ Security Layer ]         <- TLS termination, optional AES decrypt
        ↓
[ FIX Engine — Receiver ]  <- deserialise, validate checksum/length, session handling
        ↓
[ Exchange Simulator ]     <- match/reject orders, emit ExecutionReports
```

Each layer is a distinct module with a defined interface. Layers must not reach past their immediate neighbour.

---

## Technology Choice

Pick one language and stick to it. Recommended options:

- **Python** — fastest to prototype, good for learning. Use `ssl` stdlib for TLS, `socket` for TCP, `cryptography` library for AES-GCM.
- **Java** — closest to production FIX (QuickFIX/J). Use `javax.net.ssl` for TLS, `javax.crypto` for AES.
- **Go** — clean concurrency model, good for TCP servers. Use `crypto/tls`, `crypto/aes`.

Do not use an existing FIX library (QuickFIX, etc.) — the point is to implement the protocol yourself.

---

## Module Specifications

### 1. FIX Simulator

Generates a stream of FIX messages to drive the sender side.

**Behaviour:**
- On startup, establish a FIX session (send Logon).
- Send a configurable number of `NewOrderSingle` messages with randomised symbol, quantity, side (buy/sell), and order type (market/limit).
- Optionally send `OrderCancelRequest` for a random subset of sent orders.
- On shutdown, send `Logout`.
- Print a summary of messages sent and execution reports received.

**Configuration (via config file or CLI flags):**
- `target_comp_id`, `sender_comp_id`
- `message_count` (default: 10)
- `host`, `port`

---

### 2. FIX Engine

Handles the FIX session layer and message codec. This is the most complex module.

#### Session State Machine

States: `DISCONNECTED → LOGON_SENT → ACTIVE → LOGOUT_SENT → DISCONNECTED`

Transitions:
- Send Logon → `LOGON_SENT`
- Receive Logon ACK → `ACTIVE`
- Send/receive Logout → `LOGOUT_SENT` → `DISCONNECTED`

**Sequence number tracking:**
- Maintain `MsgSeqNum` (outbound) and expected incoming seq num.
- On gap detected (incoming seq num > expected): send `ResendRequest`.
- On duplicate detected (incoming seq num < expected): send `SequenceReset` or log and drop.
- Heartbeat: send `Heartbeat` every N seconds (default 30). If no message received in 2×N seconds, send `TestRequest`. If no response, disconnect.

#### Codec

FIX tag=value format: `tag=value<SOH>` where SOH = byte `0x01`.

**Serialiser:** Given a dict of `{tag: value}` pairs, produce a FIX byte string. Rules:
- BeginString (8), BodyLength (9), and MsgType (35) always first in that order.
- CheckSum (10) always last.
- BodyLength = byte count from tag 9's SOH (exclusive) to tag 10's SOH (exclusive).
- CheckSum = sum of all bytes mod 256, formatted as 3-digit zero-padded string.

**Parser:** Given a FIX byte string, produce a dict of `{tag: value}`. Rules:
- Split on SOH.
- Validate BodyLength and CheckSum; raise/return error on mismatch.
- Expose `get(tag)` and `get_required(tag)` helpers.

#### Message Types to Support

| MsgType | Name |
|---------|------|
| A | Logon |
| 5 | Logout |
| 0 | Heartbeat |
| 1 | TestRequest |
| 2 | ResendRequest |
| 4 | SequenceReset |
| D | NewOrderSingle |
| F | OrderCancelRequest |
| 8 | ExecutionReport |
| 3 | Reject |

#### Key FIX Tags (minimum required)

| Tag | Field Name | Type |
|-----|-----------|------|
| 8 | BeginString | String (e.g. `FIX.4.2`) |
| 9 | BodyLength | Int |
| 35 | MsgType | String |
| 49 | SenderCompID | String |
| 56 | TargetCompID | String |
| 34 | MsgSeqNum | Int |
| 52 | SendingTime | UTCTimestamp |
| 10 | CheckSum | String (3 digits) |
| 11 | ClOrdID | String |
| 55 | Symbol | String |
| 54 | Side | Char (1=Buy, 2=Sell) |
| 38 | OrderQty | Decimal |
| 40 | OrdType | Char (1=Market, 2=Limit) |
| 44 | Price | Decimal (for limit only) |
| 37 | OrderID | String |
| 39 | OrdStatus | Char |
| 150 | ExecType | Char |
| 17 | ExecID | String |
| 14 | CumQty | Decimal |
| 151 | LeavesQty | Decimal |

---

### 3. Security Layer

Two sub-components: TLS (mandatory) and application-level AES-GCM (optional, toggled by config).

#### TLS

- Server generates a self-signed certificate on first run (or load from file).
- Client loads the server cert and verifies it (no CA chain needed for dev).
- All FIX bytes flow inside the TLS tunnel.
- Use TLS 1.2 minimum; TLS 1.3 preferred.

#### AES-256-GCM (optional)

When enabled, encrypt the FIX message body (everything between the SOH after tag 9 and the SOH of tag 10, i.e. the payload that BodyLength covers) before handing to TLS.

Framing: prepend a 12-byte nonce to the ciphertext. The receiver strips the nonce before decryption.

Key management: for this project, a shared 256-bit key loaded from a config file (hex-encoded). Document clearly that this is a simplified scheme — in production you'd use a KDF or key exchange.

**Interface contract:**

```
encrypt(plaintext: bytes) -> bytes   # nonce || ciphertext || tag
decrypt(ciphertext: bytes) -> bytes  # strips nonce, returns plaintext
```

---

### 4. TCP Transport

Thin wrapper around OS sockets.

**Sender side:**
- Connect to `host:port`.
- Expose `send(data: bytes)`.
- Handle reconnect with exponential backoff (max 5 retries).

**Receiver side:**
- Listen on `host:port`.
- Accept one connection (for simplicity; no connection pool needed).
- Expose `recv() -> bytes` that reads a complete FIX message. FIX messages are not length-prefixed in the transport, so read until a complete tag-10 field is found (scan for `10=xxx<SOH>` pattern).

---

### 5. Exchange Simulator

Receives parsed FIX messages and generates ExecutionReports.

**Order handling:**

| Input | Response |
|-------|----------|
| `NewOrderSingle` (market) | Immediate fill: `ExecType=F (Trade)`, `OrdStatus=2 (Filled)` |
| `NewOrderSingle` (limit) | Acknowledge: `ExecType=0 (New)`, `OrdStatus=0 (New)`. 50% chance of fill after 100ms. |
| `OrderCancelRequest` | Cancel if order exists and not filled: `ExecType=4 (Canceled)`. Reject otherwise: `ExecType=8 (Rejected)`. |
| Logon | Send Logon back. |
| Logout | Send Logout back, close. |

**State:** Maintain a dict of `{ClOrdID: order_state}` in memory. No persistence required.

**OrderID generation:** UUID or auto-incrementing integer, unique per session.

---

## File Structure

```
fix_stack/
├── config/
│   ├── client.cfg          # SenderCompID, TargetCompID, host, port, aes_key, etc.
│   └── server.cfg
├── certs/
│   └── server.pem          # self-signed cert (generated on first run)
├── fix/
│   ├── codec.py            # serialiser + parser
│   ├── session.py          # state machine, seq nums, heartbeat
│   └── messages.py         # message builder helpers (build_new_order, etc.)
├── security/
│   ├── tls.py              # TLS wrap/unwrap helpers
│   └── aes.py              # AES-GCM encrypt/decrypt
├── transport/
│   └── tcp.py              # send/recv, reconnect
├── simulator/
│   ├── client.py           # FIX Simulator (order generator)
│   └── exchange.py         # Exchange Simulator
├── main_client.py          # entry point: runs client simulator
├── main_server.py          # entry point: runs exchange
├── requirements.txt
└── README.md
```

---

## Configuration File Format

Use INI or YAML. Minimum fields:

```ini
[session]
begin_string = FIX.4.2
sender_comp_id = CLIENT1
target_comp_id = EXCHANGE
heartbeat_interval = 30

[network]
host = 127.0.0.1
port = 9878

[security]
tls_enabled = true
aes_enabled = false
aes_key = <64 hex chars>
cert_path = certs/server.pem

[simulator]
message_count = 20
```

---

## Error Handling

- **Checksum mismatch:** send `Reject (35=3)` with `Text` field describing the error, then drop the message.
- **Sequence gap:** send `ResendRequest`; if unresolved after 3 seconds, disconnect and log.
- **TLS handshake failure:** log and exit. Do not silently fall back to plaintext.
- **AES auth tag failure:** log `[SECURITY] AES-GCM authentication failed`, drop the message, send `Reject`.
- **Unknown MsgType:** send `Reject` with `SessionRejectReason=11 (InvalidMsgType)`.

---

## Testing

Write tests for at minimum:

1. **Codec round-trip:** serialise a `NewOrderSingle`, parse it back, assert all fields match.
2. **Checksum validation:** corrupt one byte, assert parser raises/returns error.
3. **BodyLength validation:** same.
4. **AES round-trip:** encrypt a known plaintext, decrypt, assert equality. Assert that a tampered ciphertext fails.
5. **Session sequence numbers:** send messages 1–5, simulate a gap (send 7), assert `ResendRequest` is emitted.
6. **Exchange simulator:** send a market order, assert `ExecutionReport` with `OrdStatus=2`.

Use the standard test framework for your chosen language (pytest / JUnit / Go test).

---

## What to Demonstrate / Deliverables

1. **Running demo:** start server, start client, observe Logon → orders → ExecutionReports → Logout in the console.
2. **Wireshark capture (optional):** show TLS-encrypted bytes on the wire; show that without TLS the FIX plaintext is visible.
3. **README** covering: setup, how to run, design decisions (why tag=value vs binary, what AES adds on top of TLS, how sequence recovery works).

---

## Known Simplifications (document these)

- No real matching engine; fills are synthetic.
- Single-client server (no concurrency).
- Shared AES key loaded from config (not a real key exchange).
- Self-signed TLS cert (no CA).
- No persistent session store (sequence numbers reset on restart).
- FIX 4.2 only; no repeating groups.
