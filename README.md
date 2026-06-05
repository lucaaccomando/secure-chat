# secure-chat

Terminal-based end-to-end encrypted chat over TCP. A central server routes encrypted blobs between clients but never sees plaintext, private keys, or shared secrets.

## Setup

```bash
python -m venv venv
venv\Scripts\activate   # Windows
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

Run the server, then each client in a separate terminal:

```bash
python server.py
python client.py
```

Default: `127.0.0.1:65432`. Requires Python 3.8+.

## How it works

Each client generates two ephemeral keypairs on startup: RSA-2048 (for signing) and ECDH over P-256 (for key agreement). Both public keys are registered with the server and distributed to all connected clients.

**Key agreement (ECDHE):** To send a message to Bob, Alice computes a shared secret using her ECDH private key and Bob's ECDH public key. Bob can compute the same secret independently. A 32-byte AES key is derived from this secret using HKDF-SHA256. No RSA key is involved in encryption. Since the ECDH keypairs are ephemeral (generated fresh each session, never written to disk), past sessions can't be decrypted even if a long-term RSA key is later compromised.

**Message encryption:** AES-256-GCM with a fresh 12-byte nonce per message. The 16-byte authentication tag catches ciphertext tampering before any decryption happens.

**Sender authentication:** The sender signs the ciphertext (not the plaintext) with their RSA private key using PSS/SHA-256. The receiver verifies against the sender's synced public key and drops the message if verification fails. Signing the ciphertext prevents a decryption oracle.

**Key fingerprints:** On each key sync, a SHA-256 fingerprint of each peer's RSA public key is printed in SSH colon-hex format. Lets you verify out-of-band that the server isn't swapping keys.

## Files

```
secure-chat/
├── client.py        # keygen, ECDHE key agreement, encrypt/sign, threaded I/O
├── server.py        # registration, key sync, message routing
├── crypto_utils.py  # RSA, AES-GCM/CBC, PSS, ECDHE, HKDF
└── requirements.txt
```

## Security properties

| Property | v1 (CBC) | v2 (GCM + PSS) | v3 (+ ECDHE) |
|---|---|---|---|
| Confidentiality | AES-256-CBC | AES-256-GCM | AES-256-GCM |
| Integrity | no | GCM auth tag | GCM auth tag |
| Sender authentication | no | RSA-PSS | RSA-PSS |
| Forward secrecy | no | no | yes (ephemeral ECDH) |

v1 to v2 added integrity and authentication while reducing end-to-end latency by ~24% (GCM is faster than CBC and the PSS signing cost is outweighed by GCM's speed). v3 adds forward secrecy by replacing RSA key-wrapping with ECDHE + HKDF.

## Known gaps

- No PKI: fingerprints are printed but there's no TOFU or pinning, so a compromised server can MITM by substituting ECDH public keys.
- No replay protection: messages carry no sequence numbers or timestamps.
- No group chat.
