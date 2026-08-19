# Cipher — Client-Side Text Encryption

A secure, zero-knowledge, client-side web application for text encryption and decryption. Built as a multi-file static web project designed specifically for zero-configuration hosting on **GitHub Pages** or any static web host.

---

## 🔒 Cryptographic Architecture

Cipher utilizes audited, modern cryptographic primitives provided by [libsodium](https://libsodium.gitbook.io/):

1. **Symmetric Authenticated Encryption (AEAD)**:
   - **Algorithm**: `XChaCha20-Poly1305-IETF`
   - **Key Size**: 256 bits (32 bytes)
   - **Nonce Size**: 192 bits (24 bytes extended random nonce, eliminating nonce-reuse risks)
   - **Authentication Tag**: 128-bit Poly1305 MAC tag (ensuring tamper detection and ciphertext integrity)

2. **Password-Based Key Derivation (KDF)**:
   - **Algorithm**: `Argon2id v1.3`
   - **Parameters**: 2 passes (`opslimit = 2`), 64 MiB RAM (`memlimit = 65,536 KiB`), 128-bit unique random salt per encryption operation.
   - **Defense**: Memory-hard key derivation maximizes resistance against GPU, FPGA, and ASIC-accelerated offline brute-force attacks.

3. **Compact Binary Envelope Format**:
   Encrypted outputs are formatted into a versioned binary structure and encoded as URL-safe Base64 (RFC 4648 `Base64url` without padding). No human-readable algorithm tags are exposed.

   ```
   [0]       - Format Version (0x01) [1 byte]
   [1]       - Cipher Suite ID (0x01: Argon2id + XChaCha20-Poly1305) [1 byte]
   [2..5]    - Argon2id OpsLimit (uint32 big-endian) [4 bytes]
   [6..9]    - Argon2id MemLimit in KiB (uint32 big-endian) [4 bytes]
   [10..25]  - Random Cryptographic Salt [16 bytes]
   [26..49]  - Random Extended Nonce [24 bytes]
   [50..end] - Ciphertext Body + 16-byte Poly1305 MAC Tag
   ```

---

## 🛡️ Security Model & Privacy Guarantees

- **Zero-Knowledge & Client-Side Execution**: All key derivation, encryption, decryption, and MAC verification operations run strictly inside your browser's local WebAssembly / JavaScript execution context.
- **No Network Transmission**: Plaintext, ciphertexts, passwords, derived keys, salts, and nonces are never sent over any network, backend server, API, telemetry, or analytics endpoint.
- **In-Memory Hygiene**: Derived cryptographic keys are actively zeroized (`sodium.memzero`) from memory immediately after encryption or decryption completes.
- **No Persistent Secrets**: No passwords, keys, or decrypted data are stored in `localStorage`, `sessionStorage`, `cookies`, `IndexedDB`, or URL query parameters.
- **Strict Tamper Detection**: Poly1305 MAC verification guarantees that modifying even a single bit of the ciphertext envelope will fail authentication and prevent any decryption.
- **Safe Portability**: The Base64url ciphertext can safely be copied, emailed, stored, or transmitted over untrusted channels, provided your password remains private.

> ⚠️ **Important Warning:**
> Your password is never stored or recoverable. If you lose or forget the password, the encrypted data cannot be decrypted by anyone. There is no backdoor, reset link, or recovery key.

### Technical Disclaimer
> "With a strong password and a correct implementation, recovering the plaintext by breaking the cryptographic primitives is designed to be computationally infeasible with currently known practical attacks."

---

## 📁 Project Structure

This project is organized as a clean, multi-file static web application:

```
/
├── index.html          # Main HTML entry point (relative resource links)
├── css/
│   └── style.css       # Handcrafted, accessible responsive styles (Dark & Light mode)
├── js/
│   ├── app.js          # UI controller, event listeners, clipboard & theme management
│   ├── crypto.js       # Core cryptographic routines, KDF, envelope parsing & self-tests
│   └── utils.js        # Password entropy estimation, stats, clipboard & file helpers
└── README.md           # Documentation & GitHub Pages deployment guide
```

---

## 🚀 GitHub Pages Deployment Guide

This project is 100% static and requires **no build step, no Node.js backend, and no npm installation** for deployment.

1. **Create a GitHub Repository**:
   - Go to [github.com/new](https://github.com/new) and create a public or private repository (e.g., `Cipher`).

2. **Upload the Project Files**:
   - Upload the entire directory structure (`index.html`, `css/`, `js/`, `README.md`) to the root of your repository.
   - Ensure `index.html` is in the repository's root directory.

3. **Enable GitHub Pages**:
   - In your repository, click **Settings** (gear icon) → **Pages** (in the left sidebar).
   - Under **Build and deployment** → **Source**, select **Deploy from a branch**.
   - Under **Branch**, select `main` (or `master`) and folder `/(root)`.
   - Click **Save**.

4. **Access Your Live App**:
   - Within 1–2 minutes, GitHub Pages will deploy your site to:
     `https://<your-username>.github.io/<repository-name>/`
   - All relative asset paths (`./css/style.css`, `./js/app.js`) work seamlessly on subpaths.

---

## 🧪 Built-In Self-Test Suite

Cipher includes an automated in-browser verification suite accessible via the footer ("Run Cryptographic Self-Test Suite"). It validates:
1. **Roundtrip Integrity**: Plaintext is restored with exact parity.
2. **Wrong Password Rejection**: Decryption with mismatched passwords fails securely.
3. **AEAD Bit-Flip Detection**: Modifying a single character of ciphertext triggers MAC authentication rejection.
4. **Nonce & Salt Freshness**: Re-encrypting identical plaintext produces unique ciphertexts.
5. **Envelope Validation**: Damaged headers or unsupported protocol versions are rejected.

---

## 📄 License
MIT License. Free and open source.
