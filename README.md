# SDTLS 1.0 (SPROCKET DATAGRAM TRANSPORT LAYER SECURITY) 
## L4 Datagram Ingest Gatekeeper 
### Zero-Allocation UDP Datagram TLS Protocol for Cyber-Physical Systems

This class is the primary ingress pipeline for the Sprocket C2 physical combat network. 
It decodes, authenticates, and routes raw UDP frames from tamper-resistant ESP32 edge devices.

## EXECUTION PROFILE
This handler executes directly on Netty's high-priority epoll/kqueue I/O threads. 
Heap allocation in this class is forbidden.

1. Cryptographic buffers (AAD, Decrypt) are pinned to ThreadLocals via `ByteArrayLocal`.
2. Heavy asymmetric cryptographic operations (ECDH/ECDSA) are strictly forbidden on the I/O thread. 
   Type 01 (Challenge Response) packets are written to pre-allocated, lock-free struct-like 
   objects from `ChallengeResponsePool` and handed off to a disruptive queue.
3. Byte manipulation is done using primitive bitwise operations directly off off-heap 
   DirectByteBuf memory via Netty. Zero array copies.
4. Branching is kept predictable: Packet magic numbers and fast-fail validation checks 
   are executed sequentially before any expensive state lookups.

## THREAT MODEL & SDTLS 1.0 STATE MACHINE
This handler enforces the Sprocket Datagram Transport Layer Security (SDTLS v1) protocol:

- [TYPE 00] Stateless Challenge: Anti-amplification enforced. The server allocates ZERO memory 
  for inbound requests. We compute an HMAC over a generated challenge and return it.

- [TYPE 01] Asymmetric Handshake: The client responds with an ECDSA signature of the running 
  transcript hash and an ephemeral ECDH public key (secp256r1). Memory exhaustion attacks are 
  mitigated by strict length checks and offloading validation to worker threads.

- [TYPE 02] Symmetric Verification (Client Finished): AES-GCM verification of the final 
  transcript hash. Master secrets are derived via HKDF-Extract/Expand.

- [TYPE 03+] Authorized Payload: Hot-path data. Sequence numbers are verified against a 
  64-packet sliding window bitmask to prevent replay attacks. The payload is decrypted 
  in-place using ACCP (Amazon Corretto Crypto Provider) bound to AES-NI CPU instructions.


# SDTLS 1.0 (SPROCKET DATAGRAM TRANSPORT LAYER SECURITY) STATE MACHINE
This defines the exact cryptographic workflow and state machine for SDTLS v1.
The protocol is explicitly designed for hostile physical environments, strict
zero-allocation memory profiles on the C2 server, and microsecond telemetry.

### PHASE 0: Cryptographic Provisioning (Offline / Root of Trust)
1. Firmware Keypair: Generated offline for secure boot and OTA signatures.
2. Master C2 Keypair: ECDSA keypair. Public key is flashed to edge devices.
   Private key is locked to the C2 Server's hardware TPM/Network-bound disk.
3. Edge Provisioning: Unique secp256r1 ECDSA keypair + 8-byte Device ID
   (random long, collision-checked). Private key burned to BBRAM on the 
   edge device (wiped on physical tamper). Public key registered in C2 DB.

### PHASE 1: Stateless Challenge [Packet Type 0x00]
Goal: Mitigate UDP amplification and C2 memory-exhaustion.
4. Request: Client sends Magic Number, Length, Version (0x01), and Device ID.
   [CONSTRAINT] Client MUST pad this payload (~80 bytes) to be larger than 
   the server's response.
5. Stateless Cookie: Server validates version/ID, generates 256-bit challenge.
   Server allocates ZERO memory. Computes HMAC-SHA256(Server_Secret, 
   Timestamp + Challenge + Device_ID). Returns Challenge, Timestamp, and Cookie.

### PHASE 2: Asymmetric Authentication [Packet Type 0x01]
Goal: Prove identity and establish Perfect Forward Secrecy (PFS).
6. Client Ephemeral: Client generates fresh secp256r1 ECDH keypair.
7. Client Auth: Client computes running SHA-256 Transcript Hash (raw bytes).
   Signs ("SPROCKET-CLIENT-AUTH-v1" + Transcript Hash) with BBRAM ECDSA key.
   Sends plaintext ECDH PubKey + Signature. (Hardware enforces 500ms IP limit).
8. Server Verify: C2 server re-computes HMAC from Step 5 to verify challenge.
   Validates timestamp. Verifies ECDSA signature. Drops duplicates.
9. Server Ephemeral: Server generates fresh secp256r1 ECDH keypair.
10. Server Auth: Server signs ("SPROCKET-SERVER-AUTH-v1" + Transcript Hash)
    with Master C2 ECDSA key. Sends ECDH PubKey + Signature to client.

### PHASE 3: Key Derivation & Verification [Packet Type 0x02]
Goal: Compute symmetric AEAD keys, verify transcripts, and scorch memory.
11. Client HKDF: Computes Master Secret (Client ECDH Priv + Server ECDH Pub).
    Executes 2-step HKDF (Extract, Expand with "sprocket-key-expansion-v1").
    Outputs 56-byte Key Block: 
    [0-15] Client Write | [16-31] Server Write | [32-43] Client IV | [44-55] Server IV
12. Client Finish: AES-GCM encrypts final Transcript Hash. Sends to Server.
13. Server HKDF: Computes Master Secret, executes exact same 56-byte HKDF.
14. Server Verify: AES-GCM decrypts Step 12, performs constant-time match 
    against internal Transcript Hash.
15. Fast-Path Downgrade: Server swaps heavy 8-byte Device ID for a fast 
    2-byte Source ID. Encrypts Source ID + Transcript Hash, sends to client.
16. Client Final: Decrypts and verifies server's Finished transcript.

17. [MESH KEY DISTRIBUTION] Shared Grid STS Provisioning:
    To eliminate decentralized key-rotation race conditions across UWB mesh nodes, the 
    C2 server acts as a centralized Key Distribution Center (KDC).
    The Server generates a Shared Scrambled Timestamp Sequence (STS) initialization key 
    for a specific physical grid square.
    This Shared STS Key is packaged into a standard outbound event envelope 
    (ServerAction.SHARED_STS_PROVISION).
    The envelope is encrypted using the client's unique AES-GCM session key 
    (derived from the unique HKDF output in Step 13).
    Because 3/4 of the clients in a grid square cannot derive this shared key independently, 
    this mechanism safely securely distributes the shared STS state, guaranteeing synchronous 
    ranging initialization across the cluster without timing-based key rotation vulnerabilities.

18. [CRITICAL] OFF-HEAP SANITIZATION: Both sides instantly zero ECDH private 
    keys. Server MUST call ACCP `destroy()` to clear C-level native memory.

### PHASE 4: The Hot Path [Packet] Type 0x03+]
Goal: Microsecond execution, in-place decryption, replay-attack prevention.
18. Symmetric Framing: Sender pads internal 8-byte Sequence Number to 12 bytes,
    XORs against the 12-byte Base IV. Transmits ONLY the 8-byte Sequence Number.
    Receiver reverses the XOR to derive the exact packet IV. Base IV never 
    crosses the wire.
19. Replay Bitmask: Receiver enforces a 64-packet sliding window bitmask.
    If Sequence is less than (Max_Received - 64), drop immediately. If inside window,
    check bitmask. Decrypt and slide window ONLY on successful AEAD auth.
20. UpdateAAD: Cipher AAD is fed the exact raw packet header (Bytes 0-17 for
    client, 0-13 for server) binding the payload to the specific packet logic.

### SYSTEM ARCHITECTURE CONSTRAINTS:
- Transcript Hashing: MUST strictly encompass raw byte arrays. Retransmitted
  or duplicate bytes MUST NOT enter the hash state, or ECDSA validation fails.
- Connection Sweeper: A background disruptor/thread must prune half-open 
  Type 00/01 handshakes after a few seconds, calling `destroy()` on all keys 
  to prevent C-level RAM exhaustion.

- Deterministic Memory Boundary & Strict Session Isolation:
  To guarantee microsecond latency and eliminate C-level memory leaks, SDTLS strictly 
  forbids dynamic memory allocation during runtime. Furthermore, to protect against 
  cross-client data leakage and resource-exhaustion attacks, memory is strictly partitioned:
  Per-Session Dedicated Pools: Off-heap DirectByteBuf memory is statically allocated into 
  fixed-size, rotating pools strictly bound to individual client sessions. Pools are never
  shared across clients. A denial-of-service (DoS) flood against one session can only 
  exhaust that specific client's pool, mathematically guaranteeing availability for all 
  other edge devices on the C2 network.
  Native JNI Execution: The JNI boundary simply passes pinned, session-isolated memory 
  addresses to the native ACCP engine for zero-copy, in-place cryptographic processing.
  Immediate Cryptographic Sanitization: Immediately upon completion of payload routing, 
  the buffer is explicitly zeroed before being released back to the client's local pool. 
  This prevents use-after-free vulnerabilities and ensures transient cryptographic state 
  is destroyed instantly.

- Autonomic Defense & Behavioral Trust Scoring:
  While volumetric network attacks are handled at the switch level, SDTLS incorporates 
  application-layer behavioral heuristics. Every edge device maintains a dynamic Trust Score. 
  Anomalous behavior—such as sequencing violations, malformed packet floods, or excessive 
  authentication failures—rapidly degrades this score. If the Trust Score drops to zero, 
  the C2 server actively terminates the session, immediately wiping the client's 
  cryptographic state and destroying its isolated memory pool, effectively quarantining 
  the compromised node from the cyber-physical mesh.


UDP Packet design is as follows:

Only payload is encrypted and it will have the 16 byte auth tag appended 

Inbound challenge request and challenge response packet envelope (Type 00, Type 01)
```text
Offset   Field         Type    Size
0-3      Magic         int     4 bytes  (0xD6D6D6D6)
4-5      Length        short   2 bytes  (covers bytes 6-N - does NOT include the 2 length bytes)
6-7      Type          short   2 bytes
8-15     Device ID     long    8 bytes
16+      Payload       byte[]  N bytes
```

Outbound Server Challenge Request Payload
```text
Offset   Field    Type    Length
00       Challenge     long    8 bytes
08       Timestamp     long    8 bytes 
16       HMAC Cookie   byte[]  32 bytes  
```

Inbound Client Challenge Response Payload (Type 01) 
```text
Offset   Field         Type    Size
00       Challenge     long    8 bytes 
08       Timestamp     long    8 bytes
16       Sig Length    short   2 bytes  (The length of the cookie signed with the new ECDSA private key excluding the 2 byte length)
18-N     Signed Cookie byte[]  N bytes  
N+1-N+2  Pub key Len   short   2 bytes  (The newly generated ECDSA public key length excluding the 2 byte length)
N+3-M    Pub key       byte[]  M bytes  
```

Inbound Client Finished envelope (Type 02) 
```text
Offset   Field         Type    Size
0-3      Magic         int     4 bytes  (0xD6D6D6D6)
4-5      Length        short   2 bytes  (covers bytes 6-N - does NOT include the 2 length bytes)
6-7      Type          short   2 bytes
8-15     Device ID     long    8 bytes
16-23    IV sequence   long    8 bytes
24+      Payload       byte[]  N bytes  (encrypted)
```

Inbound Client Challenge Response Payload (Type 02) This is encrypted 
```text
Offset   Field         Type    Size 
0-16     Auth Tag      byte[]  16 bytes (last 16 bytes of payload is the auth tag)
```

Authorized inbound envelope (Types 03+)
```text
Offset   Field         Type    Size
00       Magic         int     4 bytes  (0xD6D6D6D6)
04       Length        short   2 bytes  (covers bytes 6-N - does NOT include the 2 length bytes)
06       Type          short   2 bytes  Packet handler type
08       Source ID     long    8 bytes  authenticated sessions will be sending the 2 byte local id in this 8 byte slot
16       IV sequence   long    8 bytes
24+      Payload       byte[]  N bytes  (encrypted)
N-16     Auth Tag      byte[]  16 bytes (last 16 bytes of payload is the auth tag)
```

STANDARD INBOUND PACKET:
```text
Offset   Field         Type    Size
00       Action        byte    1 byte   What the client wants to do 
01       Generation    byte    1 byte   This only uses the first 4 bits for 0-15 - max value is 15
02       Flags         short   2 bytes  Flags for whatever 
04       Reserved      byte[]  4 bytes
08       Time          long    8 bytes  The controller local time (use the sprocket synchronized time, not gettimeofday)
16       Max Sequence  long    8 bytes  The maximum sequence number received from the server
24       ACK Mask      long    8 bytes  A mask representing ACK for the last 64 packets received from the client (max sequence - 64)
32       Data          byte[]  N bytes  Whatever payload this action wants to send 
```

Game handler: Event Packet Payload 
```text
Offset   Field         Type    Size
00       Entity ID     short   2 bytes
00       Target ID     short   2 bytes
04       Tick          int     4 bytes
8        Action        byte    1 byte   (255 possible actions) @todo make this a short 
9        Generation    byte    1 byte   (this only uses the first 4 bits for 0-15 - max value is 15)
10-11    Flags         short   2 bytes 
12-15    Padding       byte[]  4 bytes  Pushes the Max Sequence to an 8 byte boundary  ****** THIS IS NOT SUPPORTED BY THIS HANDLER YET ******
12-19    Max Sequence  long    8 bytes  (The maximum sequence number received from the server)
20-27    ACK Mask      long    8 bytes  (A mask representing ACK for the last 64 packets received from the client (max sequence - 64))
28+      Value         byte[]  N bytes  
```

Plain text inbound (TYPE_CLOCK_SYNC)
```text
Offset   Field         Type    Size
00       Magic         int     4 bytes  (0xD6D6D6D6)gy
04       Length        short   2 bytes  (covers bytes 6-N - does NOT include the 2 length bytes)
06       Type          short   2 bytes
PAYLOAD STARTS HERE 
08       Clock Id      long    8 bytes  Packed id returned by ClockSyncTempStorage.startClockSync
00       Rx Timestamp  long    8 bytes
04       Unixtime      int     4 bytes  This is what the esp32 sends.  Use gettimeofday()
08       Microseconds  int     4 bytes  
```

**Outbound Packet (Clear Text):**
```text
Offset   Field         Type    Length    Description
-----------------------------------------------------------------------------------
00       Magic         int     4 bytes   0xD6D6D6D6 (Packet header)
04       Length        short   2 bytes   Covers bytes 6-N (Does NOT include these 2 bytes)
06       Type          short   2 bytes   The packet type
08       Payload       byte[]  N bytes   Clear text data
```

**Outbound Packet (Encrypted):**
```text
Offset   Field         Type    Length    Description
-----------------------------------------------------------------------------------
00       Magic         int     4 bytes   0xD6D6D6D6 (Packet header)
04       Length        short   2 bytes   Covers bytes 6-N (Does NOT include these 2 bytes)
06       Type          short   2 bytes   Always 0xFFFF to denote an encrypted packet
08       IV sequence   long    8 bytes   Initialization Vector sequence
16+      Payload       byte[]  N bytes   Encrypted data payload
N-16     Auth Tag      byte[]  16 bytes  Last 16 bytes of payload is the AES-GCM auth tag
```

**Outbound Encrypted Data Payload Structure:**
```text
Offset   Field         Type    Length    Description
-----------------------------------------------------------------------------------
00       Action        byte    1 byte    Action ID (0-255). 0 = server tick / heartbeat
01       Reserved      byte[]  7 bytes   Reserved padding
08       Tick          long    8 bytes   Server tick timestamp
16       Max Sequence  long    8 bytes   Maximum sequence number received from the client
24       ACK Mask      long    8 bytes   Bitmask representing ACKs for the last 64 packets received from the client
32+      Data          byte[]  N bytes   Action-specific payload data
``` 

**Handshake complete; send session data**
```text
Offset   Field         Type    Length    Description
-----------------------------------------------------------------------------------
00       Session Id    short   2 bytes   This is sent back in place of device id
02       Device Type   short   2 bytes   The device type stored in config.toml deviceToTypeMap
                                         or zero if not listed 
04       Reserved      byte[]  4 bytes 
08       Hash          byte[]  32 bytes  The final transcript hash
```
