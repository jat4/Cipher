/**
 * Cipher - Cryptographic Module
 * 
 * Implements authenticated client-side encryption and decryption using:
 * - Primary Cipher: XChaCha20-Poly1305 (IETF AEAD, 192-bit nonce, 256-bit key)
 * - Key Derivation Function (KDF): Argon2id v1.3 (Memory-hard password hashing)
 * - Packaging: Compact versioned binary envelope encoded with Base64url
 * 
 * Relying on audited libsodium (libsodium-wrappers v0.7.15).
 * All operations execute locally in the client browser.
 */

// Cryptographic Format Constants
export const FORMAT_VERSION = 0x01;
export const CIPHER_ID_ARGON2ID_XCHACHA20 = 0x01;

// Recommended interactive Argon2id parameters (balanced for mobile and desktop browsers)
export const DEFAULT_OPSLIMIT = 2;              // 2 iterations
export const DEFAULT_MEMLIMIT_KIB = 65536;      // 64 MiB in KiB (67,108,864 bytes)

// Strict security bounds for parsing KDF parameters (prevent memory-exhaustion or zero-work attacks)
export const MIN_OPSLIMIT = 1;
export const MAX_OPSLIMIT = 10;
export const MIN_MEMLIMIT_KIB = 8192;           // 8 MiB minimum
export const MAX_MEMLIMIT_KIB = 131072;         // 128 MiB maximum

// Buffer dimensions
export const SALT_BYTES = 16;                   // 128 bits
export const NONCE_BYTES = 24;                  // 192 bits (XChaCha20)
export const KEY_BYTES = 32;                    // 256 bits
export const TAG_BYTES = 16;                    // 128 bits (Poly1305 MAC)
export const HEADER_BYTES = 1 + 1 + 4 + 4 + SALT_BYTES + NONCE_BYTES; // 50 bytes
export const MIN_ENVELOPE_BYTES = HEADER_BYTES + TAG_BYTES; // 66 bytes (header + 0-byte payload + tag)

export const GENERIC_DECRYPT_ERROR = 'Decryption failed. The password may be incorrect or the encrypted data may be invalid or damaged.';

/**
 * Ensures libsodium is initialized and ready.
 * @returns {Promise<object>} The initialized sodium object
 */
export async function getSodium() {
  if (typeof window === 'undefined' || !window.sodium) {
    throw new Error('Sodium cryptographic library is not loaded. Please check your network connection.');
  }
  await window.sodium.ready;
  return window.sodium;
}

/**
 * Encodes a Uint8Array to RFC 4648 Base64url (URL-safe, no padding).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toBase64Url(bytes) {
  if (window.sodium && window.sodium.to_base64) {
    return window.sodium.to_base64(bytes, window.sodium.base64_variants.URLSAFE_NO_PADDING);
  }
  // Standard fallback
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decodes an RFC 4648 Base64url string to Uint8Array.
 * @param {string} base64UrlStr
 * @returns {Uint8Array}
 */
export function fromBase64Url(base64UrlStr) {
  if (!base64UrlStr || typeof base64UrlStr !== 'string') {
    throw new Error('Invalid Base64url input');
  }

  const clean = base64UrlStr.trim();
  if (window.sodium && window.sodium.from_base64) {
    try {
      return window.sodium.from_base64(clean, window.sodium.base64_variants.URLSAFE_NO_PADDING);
    } catch (e) {
      // also try standard or padded variants if copied with padding
      try {
        return window.sodium.from_base64(clean, window.sodium.base64_variants.URLSAFE);
      } catch (err2) {
        throw new Error('Invalid Base64url string');
      }
    }
  }

  // Standard fallback
  let base64 = clean.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encrypts plaintext string using XChaCha20-Poly1305 with Argon2id KDF.
 * 
 * @param {string} plaintext - The UTF-8 string to encrypt
 * @param {string} password - The user's secret password
 * @param {object} options - Optional KDF tuning
 * @returns {Promise<{ ciphertext: string, saltHex: string, nonceHex: string, totalBytes: number }>}
 */
export async function encryptText(plaintext, password, options = {}) {
  if (typeof plaintext !== 'string') {
    throw new Error('Plaintext must be a string');
  }
  if (!password || typeof password !== 'string') {
    throw new Error('A password is required for encryption');
  }

  const sodium = await getSodium();

  const opslimit = options.opslimit || DEFAULT_OPSLIMIT;
  const memlimitKiB = options.memlimitKiB || DEFAULT_MEMLIMIT_KIB;
  const memlimitBytes = memlimitKiB * 1024;

  // 1. Generate fresh cryptographically secure random salt and nonce
  const salt = sodium.randombytes_buf(SALT_BYTES);
  const nonce = sodium.randombytes_buf(NONCE_BYTES);

  let key = null;
  try {
    // 2. Derive 256-bit key using Argon2id
    key = sodium.crypto_pwhash(
      KEY_BYTES,
      password,
      salt,
      opslimit,
      memlimitBytes,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );

    // 3. Convert plaintext to UTF-8 bytes
    const messageBytes = sodium.from_string(plaintext);

    // 4. Encrypt with XChaCha20-Poly1305 (produces ciphertext + 16-byte Poly1305 MAC tag)
    const encryptedBody = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      messageBytes,
      null, // Additional authenticated data
      null, // Secret nonce
      nonce,
      key
    );

    // 5. Construct binary envelope:
    // [0] Version (1 byte)
    // [1] CipherSuite ID (1 byte)
    // [2..5] OpsLimit (4 bytes, uint32 BE)
    // [6..9] MemLimit in KiB (4 bytes, uint32 BE)
    // [10..25] Salt (16 bytes)
    // [26..49] Nonce (24 bytes)
    // [50..end] Ciphertext + Auth Tag (N + 16 bytes)
    const totalLength = HEADER_BYTES + encryptedBody.length;
    const envelope = new Uint8Array(totalLength);
    const view = new DataView(envelope.buffer);

    envelope[0] = FORMAT_VERSION;
    envelope[1] = CIPHER_ID_ARGON2ID_XCHACHA20;
    view.setUint32(2, opslimit, false); // Big-Endian
    view.setUint32(6, memlimitKiB, false); // Big-Endian

    envelope.set(salt, 10);
    envelope.set(nonce, 26);
    envelope.set(encryptedBody, HEADER_BYTES);

    // 6. Encode envelope to Base64url
    const ciphertextBase64Url = toBase64Url(envelope);

    return {
      ciphertext: ciphertextBase64Url,
      saltHex: sodium.to_hex(salt),
      nonceHex: sodium.to_hex(nonce),
      totalBytes: totalLength,
      version: FORMAT_VERSION,
      cipher: 'XChaCha20-Poly1305',
      kdf: 'Argon2id'
    };
  } finally {
    // 7. Strictly wipe derived key from memory
    if (key && sodium.memzero) {
      sodium.memzero(key);
    }
  }
}

/**
 * Decrypts a Base64url ciphertext envelope using XChaCha20-Poly1305 and Argon2id.
 * 
 * @param {string} ciphertextBase64Url - The Base64url encoded ciphertext envelope
 * @param {string} password - The user's secret password
 * @returns {Promise<string>} The decrypted UTF-8 plaintext string
 */
export async function decryptText(ciphertextBase64Url, password) {
  if (!ciphertextBase64Url || typeof ciphertextBase64Url !== 'string') {
    throw new Error('Please enter ciphertext to decrypt.');
  }
  if (!password || typeof password !== 'string') {
    throw new Error('Please enter the password.');
  }

  const sodium = await getSodium();

  let envelopeBytes;
  try {
    envelopeBytes = fromBase64Url(ciphertextBase64Url);
  } catch (err) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  // Validate minimum envelope length (header 50 bytes + 16 bytes Poly1305 MAC = 66 bytes)
  if (!envelopeBytes || envelopeBytes.length < MIN_ENVELOPE_BYTES) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  const view = new DataView(envelopeBytes.buffer, envelopeBytes.byteOffset, envelopeBytes.byteLength);

  // Validate format version
  const version = envelopeBytes[0];
  if (version !== FORMAT_VERSION) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  // Validate cipher suite
  const cipherId = envelopeBytes[1];
  if (cipherId !== CIPHER_ID_ARGON2ID_XCHACHA20) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  // Extract and validate KDF parameters
  const opslimit = view.getUint32(2, false);
  const memlimitKiB = view.getUint32(6, false);

  if (opslimit < MIN_OPSLIMIT || opslimit > MAX_OPSLIMIT) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  if (memlimitKiB < MIN_MEMLIMIT_KIB || memlimitKiB > MAX_MEMLIMIT_KIB) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }

  const memlimitBytes = memlimitKiB * 1024;

  // Extract salt and nonce
  const salt = envelopeBytes.slice(10, 10 + SALT_BYTES);
  const nonce = envelopeBytes.slice(26, 26 + NONCE_BYTES);
  const encryptedBody = envelopeBytes.slice(HEADER_BYTES);

  let key = null;
  try {
    // Derive key using Argon2id
    key = sodium.crypto_pwhash(
      KEY_BYTES,
      password,
      salt,
      opslimit,
      memlimitBytes,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );

    // Decrypt and verify Poly1305 MAC tag
    const decryptedBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, // Message length output pointer
      encryptedBody,
      null, // Additional authenticated data
      nonce,
      key
    );

    // Convert UTF-8 bytes back to string
    return sodium.to_string(decryptedBytes);
  } catch (err) {
    // Always fail securely with generic message to avoid oracle side-channels
    throw new Error(GENERIC_DECRYPT_ERROR);
  } finally {
    // Strictly zeroize key in memory
    if (key && sodium.memzero) {
      sodium.memzero(key);
    }
  }
}

/**
 * Runs a 5-point automated cryptographic self-test.
 * Verifies correctness, tamper resistance, and security guarantees.
 * 
 * @returns {Promise<{ success: boolean, results: Array<{ id: string, name: string, passed: boolean, description: string }> }>}
 */
export async function runCryptoSelfTests() {
  const sodium = await getSodium();
  const testPassword = 'TestPassword!987#XChaCha';
  const testPlaintext = 'The quick brown fox jumps over the lazy dog 🔒 12345! Multilingual: 日本語 • Español • 中文';
  const results = [];

  // Test 1: Roundtrip encryption and decryption
  try {
    const encResult = await encryptText(testPlaintext, testPassword);
    const decrypted = await decryptText(encResult.ciphertext, testPassword);
    const passed = decrypted === testPlaintext;
    results.push({
      id: 'roundtrip',
      name: 'Roundtrip Integrity',
      passed,
      description: 'Encrypting plaintext and decrypting with the matching password restores the exact original text.'
    });
  } catch (e) {
    results.push({
      id: 'roundtrip',
      name: 'Roundtrip Integrity',
      passed: false,
      description: 'Failed: ' + e.message
    });
  }

  // Test 2: Wrong password rejection
  try {
    const encResult = await encryptText(testPlaintext, testPassword);
    let failedCleanly = false;
    try {
      await decryptText(encResult.ciphertext, 'IncorrectPassword-999');
    } catch (e) {
      failedCleanly = e.message === GENERIC_DECRYPT_ERROR;
    }
    results.push({
      id: 'wrong_password',
      name: 'Wrong Password Authentication Failure',
      passed: failedCleanly,
      description: 'Decrypting with an incorrect password is safely rejected without leaking internal errors.'
    });
  } catch (e) {
    results.push({
      id: 'wrong_password',
      name: 'Wrong Password Authentication Failure',
      passed: false,
      description: 'Unexpected failure: ' + e.message
    });
  }

  // Test 3: Bit-flip / Tamper detection
  try {
    const encResult = await encryptText(testPlaintext, testPassword);
    const rawEnvelope = fromBase64Url(encResult.ciphertext);
    
    // Corrupt one byte in the ciphertext body
    const corruptIndex = rawEnvelope.length - 5;
    rawEnvelope[corruptIndex] ^= 0x01;
    const corruptedBase64 = toBase64Url(rawEnvelope);

    let rejected = false;
    try {
      await decryptText(corruptedBase64, testPassword);
    } catch (e) {
      rejected = e.message === GENERIC_DECRYPT_ERROR;
    }

    results.push({
      id: 'tamper_detection',
      name: 'Tamper & Modification Detection (AEAD)',
      passed: rejected,
      description: 'Flipping a single bit in the ciphertext causes Poly1305 MAC validation to reject the message.'
    });
  } catch (e) {
    results.push({
      id: 'tamper_detection',
      name: 'Tamper & Modification Detection (AEAD)',
      passed: false,
      description: 'Unexpected failure: ' + e.message
    });
  }

  // Test 4: Randomization check (Salt & Nonce freshness)
  try {
    const enc1 = await encryptText(testPlaintext, testPassword);
    const enc2 = await encryptText(testPlaintext, testPassword);
    const passed = enc1.ciphertext !== enc2.ciphertext && enc1.nonceHex !== enc2.nonceHex && enc1.saltHex !== enc2.saltHex;
    results.push({
      id: 'fresh_randomization',
      name: 'Salt & Nonce Freshness',
      passed,
      description: 'Encrypting the identical plaintext with the same password generates distinct salts, nonces, and ciphertexts.'
    });
  } catch (e) {
    results.push({
      id: 'fresh_randomization',
      name: 'Salt & Nonce Freshness',
      passed: false,
      description: 'Unexpected failure: ' + e.message
    });
  }

  // Test 5: Corrupted header rejection
  try {
    const encResult = await encryptText(testPlaintext, testPassword);
    const rawEnvelope = fromBase64Url(encResult.ciphertext);
    rawEnvelope[0] = 0x99; // Unknown version
    const corruptedVersionBase64 = toBase64Url(rawEnvelope);

    let rejected = false;
    try {
      await decryptText(corruptedVersionBase64, testPassword);
    } catch (e) {
      rejected = e.message === GENERIC_DECRYPT_ERROR;
    }

    results.push({
      id: 'header_validation',
      name: 'Envelope Header & Version Validation',
      passed: rejected,
      description: 'Corrupted format headers or unsupported protocol versions are safely rejected.'
    });
  } catch (e) {
    results.push({
      id: 'header_validation',
      name: 'Envelope Header & Version Validation',
      passed: false,
      description: 'Unexpected failure: ' + e.message
    });
  }

  const success = results.every(r => r.passed);
  return { success, results };
}
