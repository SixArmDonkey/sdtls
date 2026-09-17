Here is the converted and formatted Markdown document.

---

# SDTLS 1.0 (Sprocket Datagram Transport Layer Security)
### L4 Datagram Ingest Gatekeeper
**Zero-Allocation UDP Datagram TLS Protocol for Cyber-Physical Systems**

---

This class is the primary ingress pipeline for the Sprocket C2 physical combat network. It decodes, authenticates, and routes raw UDP frames from tamper-resistant ESP32 edge devices.

## Execution Profile

This handler executes directly on Netty's high-priority `epoll`/`kqueue` I/O threads. **Heap allocation in this class is forbidden.**

1. **Thread-Pinned Buffers:** Cryptographic buffers (AAD, Decrypt) are pinned to `ThreadLocal` storage via `ByteArrayLocal`.
2. **Asymmetric Crypto Offloading:** Heavy asymmetric cryptographic operations (ECDH/ECDSA) are strictly forbidden on the I/O thread. Type 01 (Challenge Response) packets are written to pre-allocated, lock-free struct-like objects from `ChallengeResponsePool` and handed off to a disruptive queue.
3. **Off-Heap Direct Memory:** Byte manipulation is done using primitive bitwise operations directly off off-heap `DirectByteBuf` memory via Netty. Zero array copies.
4. **Predictable Branching:** Packet magic numbers and fast-fail validation checks are executed sequentially before any expensive state lookups.

---

## Threat Model & High-Level State Machine

This handler enforces the Sprocket Datagram Transport Layer Security (SDTLS v1) protocol:

- **`[TYPE 00]` Stateless Challenge:** Anti-amplification enforced. The server allocates **zero** memory for inbound requests. Computes an HMAC over a generated challenge and returns it.
- **`[TYPE 01]` Asymmetric Handshake:** The client responds with an ECDSA signature of the running transcript hash and an ephemeral ECDH public key (`secp256r1`). Memory exhaustion attacks are mitigated by strict length checks and offloading validation to worker threads.
- **`[TYPE 02]` Symmetric Verification (Client Finished):** AES-GCM verification of the final transcript hash. Master secrets are derived via HKDF-Extract/Expand.
- **`[TYPE 03+]` Authorized Payload:** Hot-path data. Sequence numbers are verified against a 64-packet sliding window bitmask to prevent replay attacks. The payload is decrypted in-place using ACCP (Amazon Corretto Crypto Provider) bound to AES-NI CPU instructions.

---

## Cryptographic Workflow & State Machine Specification

Designed explicitly for hostile physical environments, strict zero-allocation memory profiles on the C2 server, and microsecond telemetry.

### Phase 0: Cryptographic Provisioning (Offline / Root of Trust)
1. **Firmware Keypair:** Generated offline for secure boot and OTA signatures.
2. **Master C2 Keypair:** ECDSA keypair. Public key is flashed to edge devices. Private key is locked to the C2 Server's hardware TPM/Network-bound disk.
3. **Edge Provisioning:** Unique `secp256r1` ECDSA keypair + 8-byte Device ID (random `long`, collision-checked). Private key is burned to BBRAM on the edge device (wiped on physical tamper). Public key is registered in the C2 database.

### Phase 1: Stateless Challenge [Packet Type `0x00`]
*Goal: Mitigate UDP amplification and C2 memory-exhaustion.*

4. **Request:** Client sends Magic Number, Length, Version (`0x01`), and Device ID.
   - **Constraint:** Client **must** pad this payload (~80 bytes) to be larger than the server's response.
5. **Stateless Cookie:** Server validates version/ID and generates a 256-bit challenge. 
   - Server allocates **zero** memory.
   - Computes:
     $$\text{HMAC-SHA256}(\text{Server\_Secret}, \text{Timestamp} + \text{Challenge} + \text{DeviceID})$$
   - Returns Challenge, Timestamp, and Cookie.

### Phase 2: Asymmetric Authentication [Packet Type `0x01`]
*Goal: Prove identity and establish Perfect Forward Secrecy (PFS).*

6. **Client Ephemeral:** Client generates a fresh `secp256r1` ECDH keypair.
7. **Client Auth:** Client computes the running SHA-256 Transcript Hash (raw bytes) and signs:
   $$\text{ECDSA}_{\text{BBRAM}}(\text{"SPROCKET-CLIENT-AUTH-v1"} + \text{Transcript Hash})$$
   Sends plaintext ECDH PubKey + Signature. (Hardware enforces a 500ms IP rate limit).
8. **Server Verify:** C2 server re-computes the HMAC from Step 5 to verify the challenge, validates the timestamp, verifies the ECDSA signature, and drops duplicates.
9. **Server Ephemeral:** Server generates a fresh `secp256r1` ECDH keypair.
10. **Server Auth:** Server signs:
    $$\text{ECDSA}_{\text{Master}}(\text{"SPROCKET-SERVER-AUTH-v1"} + \text{Transcript Hash})$$
    Sends ECDH PubKey + Signature to client.

### Phase 3: Key Derivation & Verification [Packet Type `0x02`]
*Goal: Compute symmetric AEAD keys, verify transcripts, and scorch memory.*

11. **Client HKDF:** Computes Master Secret ($\text{Client ECDH Priv} + \text{Server ECDH Pub}$). Executes a 2-step HKDF (Extract, then Expand with `"sprocket-key-expansion-v1"`).
    - **Outputs 56-byte Key Block:**
      - `[00–15]` Client Write Key
      - `[16–31]` Server Write Key
      - `[32–43]` Client IV
      - `[44–55]` Server IV
12. **Client Finish:** AES-GCM encrypts final Transcript Hash. Sends to Server.
13. **Server HKDF:** Computes Master Secret and executes the exact same 56-byte HKDF.
14. **Server Verify:** AES-GCM decrypts Step 12, performs constant-time match against internal Transcript Hash.
15. **Fast-Path Downgrade:** Server swaps heavy 8-byte Device ID for a fast 2-byte Source ID. Encrypts Source ID + Transcript Hash and sends to client.
16. **Client Final:** Decrypts and verifies server's Finished transcript.
17. **[Mesh Key Distribution] Shared Grid STS Provisioning:**
    - To eliminate decentralized key-rotation race conditions across UWB mesh nodes, the C2 server acts as a centralized Key Distribution Center (KDC).
    - The Server generates a Shared Scrambled Timestamp Sequence (STS) initialization key for a specific physical grid square.
    - Packaged into an outbound event envelope (`ServerAction.SHARED_STS_PROVISION`).
    - Encrypted via the client's unique AES-GCM session key (from Step 13).
    - Ensures synchronized ranging initialization across the cluster without timing-based key rotation vulnerabilities.
18. **Off-Heap Sanitization [CRITICAL]:** Both sides instantly zero ECDH private keys. The server **must** call ACCP `destroy()` to clear C-level native memory.

### Phase 4: The Hot Path [Packet Types `0x03+`]
*Goal: Microsecond execution, in-place decryption, replay-attack prevention.*

19. **Symmetric Framing:** 
    - Sender pads internal 8-byte Sequence Number to 12 bytes and XORs it against the 12-byte Base IV.
    - Transmits **only** the 8-byte Sequence Number.
    - Receiver reverses the XOR to derive the exact packet IV. The Base IV never crosses the wire.
20. **Replay Bitmask:** Receiver enforces a 64-packet sliding window bitmask.
    - If $\text{Sequence} < (\text{Max\_Received} - 64)$, drop immediately.
    - If inside window, check the bitmask.
    - Decrypt and advance window **only** upon successful AEAD authentication.
21. **Update AAD:** Cipher AAD is fed the exact raw packet header (Bytes 0–17 for client, 0–13 for server), binding the payload to the specific packet logic.

---

## System Architecture Constraints

- **Transcript Hashing:** Must strictly encompass raw byte arrays. Retransmitted or duplicate bytes must not enter the hash state, or ECDSA validation will fail.
- **Connection Sweeper:** A background disruptor/thread must prune half-open Type 00/01 handshakes after a few seconds, calling `destroy()` on all keys to prevent native RAM exhaustion.
- **Deterministic Memory Boundary & Strict Session Isolation:**
  - *Per-Session Dedicated Pools:* Off-heap `DirectByteBuf` memory is statically allocated into fixed-size, rotating pools strictly bound to individual client sessions. Pools are never shared. A DoS flood against one session can only exhaust that client's pool, mathematically guaranteeing availability for all other edge devices.
  - *Native JNI Execution:* The JNI boundary passes pinned, session-isolated memory addresses to the native ACCP engine for zero-copy, in-place cryptographic processing.
  - *Immediate Cryptographic Sanitization:* Upon payload routing completion, buffers are explicitly zeroed before being released back to the client's pool, preventing use-after-free vulnerabilities.
- **Autonomic Defense & Behavioral Trust Scoring:**
  - Edge devices maintain a dynamic Trust Score based on application-layer heuristics.
  - Anomalous behavior (sequencing violations, malformed packet floods, authentication failures) rapidly degrades this score.
  - If the score reaches zero, the C2 server terminates the session, wipes all cryptographic state, and destroys its isolated memory pool to quarantine the node.

---

## Packet Layout Specifications

> **Note:** Only payloads are encrypted. Encrypted payloads have an appended 16-byte authentication tag.

### 1. Inbound Challenge Request & Response Envelopes (Types `0x00`, `0x01`)

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `00–03` | Magic | `int` | 4 bytes | `0xD6D6D6D6` |
| `04–05` | Length | `short` | 2 bytes | Covers bytes 6–N (excludes these 2 bytes) |
| `06–07` | Type | `short` | 2 bytes | Packet type identifier |
| `08–15` | Device ID | `long` | 8 bytes | Unique edge device identifier |
| `16+` | Payload | `byte[]` | N bytes | Cleartext payload |

### 2. Outbound Server Challenge Request Payload

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `00–07` | Challenge | `long` | 8 bytes | Server-generated random challenge |
| `08–15` | Timestamp | `long` | 8 bytes | Server timestamp |
| `16–47` | HMAC Cookie | `byte[]` | 32 bytes | HMAC-SHA256 stateless validation token |

### 3. Inbound Client Challenge Response Payload (Type `0x01`)

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `00–07` | Challenge | `long` | 8 bytes | Echoed challenge |
| `08–15` | Timestamp | `long` | 8 bytes | Echoed timestamp |
| `16–17` | Sig Length | `short` | 2 bytes | Length of signed cookie ($N$) |
| `18..(18+N-1)` | Signed Cookie | `byte[]` | $N$ bytes | Cookie signed with client ECDSA private key |
| `(18+N)..(19+N)` | PubKey Len | `short` | 2 bytes | Length of ephemeral public key ($M$) |
| `(20+N)..(20+N+M-1)` | PubKey | `byte[]` | $M$ bytes | Ephemeral client ECDSA/ECDH public key |

### 4. Inbound Client Finished Envelope (Type `0x02`)

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `00–03` | Magic | `int` | 4 bytes | `0xD6D6D6D6` |
| `04–05` | Length | `short` | 2 bytes | Covers bytes 6–N (excludes these 2 bytes) |
| `06–07` | Type | `short` | 2 bytes | Packet type identifier (`0x02`) |
| `08–15` | Device ID | `long` | 8 bytes | Unique edge device identifier |
| `16–23` | IV Sequence | `long` | 8 bytes | Sequence number for IV XOR derivation |
| `24+` | Payload | `byte[]` | N bytes | Encrypted payload |
| `N-16` | Auth Tag | `byte[]` | 16 bytes | Last 16 bytes of payload (AES-GCM tag) |

### 5. Authorized Inbound Envelope (Types `0x03+`)

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `00–03` | Magic | `int` | 4 bytes | `0xD6D6D6D6` |
| `04–05` | Length | `short` | 2 bytes | Covers bytes 6–N (excludes these 2 bytes) |
| `06–07` | Type | `short` | 2 bytes | Packet handler type |
| `08–15` | Source ID | `long` | 8 bytes | Stores the 2-byte Local Session ID |
| `16–23` | IV Sequence | `long` | 8 bytes | Sequence number for IV derivation |
| `24+` | Payload | `byte[]` | N bytes | Encrypted payload |
| `N-16` | Auth Tag | `byte[]` | 16 bytes | Last 16 bytes of payload (AES-GCM tag) |

### 6. Standard Inbound Decrypted Data Structure

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `00` | Action | `byte` | 1 byte | Command action byte |
| `01` | Generation | `byte` | 1 byte | 4-bit generation index (values `0–15`) |
| `02–03` | Flags | `short` | 2 bytes | Action flags |
| `04–07` | Reserved | `byte[]` | 4 bytes | Padding / reserved bytes |
| `08–15` | Time | `long` | 8 bytes | Controller synchronized timestamp |
| `16–23` | Max Sequence | `long` | 8 bytes | Highest sequence number seen from server |
| `24–31` | ACK Mask | `long` | 8 bytes | Bitmask for last 64 packets ($\text{Max} - 64$) |
| `32+` | Data | `byte[]` | N bytes | Command-specific payload |

### 7. Game Handler: Event Packet Payload

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `00–01` | Entity ID | `short` | 2 bytes | Entity identifier |
| `02–03` | Target ID | `short` | 2 bytes | Target identifier |
| `04–07` | Tick | `int` | 4 bytes | Game engine tick counter |
| `08` | Action | `byte` | 1 byte | Action identifier (*TODO: migrate to short*) |
| `09` | Generation | `byte` | 1 byte | 4-bit generation index (`0–15`) |
| `10–11` | Flags | `short` | 2 bytes | Configuration flags |
| `12–15` | *Padding* | `byte[]` | 4 bytes | Aligns Max Sequence to 8-byte boundary (*Unimplemented*) |
| `12–19` | Max Sequence | `long` | 8 bytes | Highest sequence number received from server |
| `20–27` | ACK Mask | `long` | 8 bytes | Sliding ACK mask ($\text{Max} - 64$) |
| `28+` | Value | `byte[]` | N bytes | Event parameters |

### 8. Plaintext Inbound Clock Synchronization (`TYPE_CLOCK_SYNC`)

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `00–03` | Magic | `int` | 4 bytes | `0xD6D6D6D6` |
| `04–05` | Length | `short` | 2 bytes | Covers bytes 6–N (excludes these 2 bytes) |
| `06–07` | Type | `short` | 2 bytes | Packet type |
| **Payload** | | | | |
| `08–15` | Clock ID | `long` | 8 bytes | Identifier from `ClockSyncTempStorage.startClockSync` |
| `16–23` | Rx Timestamp | `long` | 8 bytes | Inbound receipt timestamp |
| `24–27` | Unix Time | `int` | 4 bytes | ESP32 current time via `gettimeofday()` |
| `28–31` | Microseconds | `int` | 4 bytes | ESP32 current microsecond offset |

---

## Outbound Packet Envelopes

### Outbound Packet (Cleartext)

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `00–03` | Magic | `int` | 4 bytes | `0xD6D6D6D6` |
| `04–05` | Length | `short` | 2 bytes | Covers bytes 6–N (excludes these 2 bytes) |
| `06–07` | Type | `short` | 2 bytes | Target packet type |
| `08+` | Payload | `byte[]` | N bytes | Cleartext data |

### Outbound Packet (Encrypted)

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `00–03` | Magic | `int` | 4 bytes | `0xD6D6D6D6` |
| `04–05` | Length | `short` | 2 bytes | Covers bytes 6–N (excludes these 2 bytes) |
| `06–07` | Type | `short` | 2 bytes | Always `0xFFFF` to signify encryption |
| `08–15` | IV Sequence | `long` | 8 bytes | Initialization vector sequence counter |
| `16+` | Payload | `byte[]` | N bytes | Ciphertext payload |
| `N-16` | Auth Tag | `byte[]` | 16 bytes | Appended AES-GCM authentication tag |

### Outbound Encrypted Data Payload Structure

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `00` | Action | `byte` | 1 byte | Action ID (`0–255`); `0` = Server Tick / Heartbeat |
| `01–07` | Reserved | `byte[]` | 7 bytes | Reserved / 8-byte alignment padding |
| `08–15` | Tick | `long` | 8 bytes | Server tick timestamp |
| `16–23` | Max Sequence | `long` | 8 bytes | Highest sequence number received from client |
| `24–31` | ACK Mask | `long` | 8 bytes | Sliding ACK mask ($\text{Max} - 64$) |
| `32+` | Data | `byte[]` | N bytes | Action-specific payload data |

### Handshake Complete Payload (Session Initiation)

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `00–01` | Session ID | `short` | 2 bytes | Session ID replacing the 8-byte Device ID |
| `02–03` | Device Type | `short` | 2 bytes | Mapped in `config.toml` (`deviceToTypeMap`), else `0` |
| `04–07` | Reserved | `byte[]` | 4 bytes | Reserved padding |
| `08–39` | Hash | `byte[]` | 32 bytes | Final SHA-256 transcript hash |
