# Cryptix GhostGate Net

<img width="1024" height="1024" alt="ghostgate" src="https://github.com/user-attachments/assets/5346fc2a-d136-445c-a171-88ee6da377b6" />


Cryptix GhostGate Net is a stealth, crypto-attested peer mesh network.  
Nodes join only with cryptographic proof and operate inside encrypted space.

## Key Features
- Cryptographic attestation; only authorized nodes can join  
- Lightweight P2P mesh using UDP with NAT hole-punching  
- Secure sessions via X25519 ECDH, HKDF, and NaCl SecretBox  
- Replay and DoS protections through rate-limits and replay caches  
- Designed as a foundational layer for private overlay and routing systems  

## Components
- **Node** — secure peer agent with encrypted UDP communication  
- **Seed Server** — verified peer directory and UDP reflexive address registration  
- **Attestation Server** — issues short-lived HMAC-signed admission tokens  

## Purpose
A controlled-access encrypted mesh for trusted peers.  
No blockchain. No public gossip.  
A clean low-level base for private overlays and higher-layer anonymity systems.

### Join by proof. Communicate quietly. Be a Ghost.


Please note that the public release of the v1 base version is not a final system, but rather a foundation for developers to build their own network. Any further development of the Crypix Ghost Network will not be public, in order to protect our network.

MIT license - do with it what you want. Military use prohibited.


Whitepaper & more:
https://cryptix-network.org/cryptix-ghostgate
