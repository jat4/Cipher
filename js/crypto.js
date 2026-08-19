/*
 * Cipher cryptographic core.
 * XChaCha20-Poly1305-IETF + Argon2id via libsodium.js.
 * Argon2id is exposed by the SUMO browser distribution.
 */

export const FORMAT_VERSION = 1;
export const CIPHER_ID_ARGON2ID_XCHACHA20 = 1;
export const DEFAULT_OPSLIMIT = 2;
export const DEFAULT_MEMLIMIT_KIB = 65536;
export const MIN_OPSLIMIT = 1;
export const MAX_OPSLIMIT = 10;
export const MIN_MEMLIMIT_KIB = 8192;
export const MAX_MEMLIMIT_KIB = 131072;
export const SALT_BYTES = 16;
export const NONCE_BYTES = 24;
export const KEY_BYTES = 32;
export const TAG_BYTES = 16;
export const HEADER_BYTES = 50;
export const MIN_ENVELOPE_BYTES = HEADER_BYTES + TAG_BYTES;
export const GENERIC_DECRYPT_ERROR = 'Decryption failed. The password may be incorrect or the encrypted data may be invalid or damaged.';

const SODIUM_CDN = 'https://cdn.jsdelivr.net/npm/libsodium-wrappers-sumo@0.7.15/dist/browsers-sumo/sodium.js';
let sodiumPromise = null;

function hasRequiredSodium(s) {
  return !!(
    s &&
    s.crypto_pwhash &&
    s.crypto_aead_xchacha20poly1305_ietf_encrypt &&
    s.crypto_aead_xchacha20poly1305_ietf_decrypt
  );
}

async function waitForSodiumReady(s) {
  if (!s || !s.ready) {
    throw new Error('libsodium failed to initialize');
  }
  await s.ready;
  if (!hasRequiredSodium(s)) {
    throw new Error('Required libsodium cryptographic functions are unavailable');
  }
  return s;
}

function loadSodiumScript() {
  return new Promise((resolve, reject) => {
    const existingScript = document.querySelector('script[data-cipher-sodium="sumo"]');

    // The index page normally loads SUMO before app.js. In that case the
    // script's load event has already fired, so wait directly on sodium.ready
    // instead of registering a listener that would never run.
    if (existingScript && window.sodium) {
      waitForSodiumReady(window.sodium).then(resolve).catch(reject);
      return;
    }

    if (existingScript) {
      const finish = () => {
        waitForSodiumReady(window.sodium).then(resolve).catch(reject);
      };
      existingScript.addEventListener('load', finish, { once: true });
      existingScript.addEventListener('error', () => reject(new Error('Unable to load the cryptographic engine')), { once: true });
      return;
    }

    const script = document.createElement('script');
    script.src = SODIUM_CDN;
    script.async = false;
    script.dataset.cipherSodium = 'sumo';
    script.onload = () => {
      waitForSodiumReady(window.sodium).then(resolve).catch(reject);
    };
    script.onerror = () => reject(new Error('Unable to load the cryptographic engine'));
    document.head.appendChild(script);
  });
}

export function getSodium() {
  if (sodiumPromise) return sodiumPromise;

  sodiumPromise = (async () => {
    try {
      // Prefer the already-loaded SUMO instance.
      if (window.sodium) {
        return await waitForSodiumReady(window.sodium);
      }

      // Fallback for deployments where the HTML script was not loaded.
      return await loadSodiumScript();
    } catch (error) {
      sodiumPromise = null;
      throw error;
    }
  })();

  return sodiumPromise;
}

export function toBase64Url(bytes) {
  const sodium = window.sodium;
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function fromBase64Url(value) {
  if (typeof value !== 'string' || !value.trim()) throw new Error('Invalid ciphertext');
  const clean = value.trim();
  if (!/^[A-Za-z0-9_-]+$/.test(clean)) throw new Error('Invalid ciphertext');
  return window.sodium.from_base64(clean, window.sodium.base64_variants.URLSAFE_NO_PADDING);
}

function makeEnvelope(sodium, opslimit, memlimitKiB, salt, nonce, encryptedBody) {
  const envelope = new Uint8Array(HEADER_BYTES + encryptedBody.length);
  const view = new DataView(envelope.buffer);
  envelope[0] = FORMAT_VERSION;
  envelope[1] = CIPHER_ID_ARGON2ID_XCHACHA20;
  view.setUint32(2, opslimit, false);
  view.setUint32(6, memlimitKiB, false);
  envelope.set(salt, 10);
  envelope.set(nonce, 26);
  envelope.set(encryptedBody, HEADER_BYTES);
  return toBase64Url(envelope);
}

export async function encryptText(plaintext, password, options = {}) {
  if (typeof plaintext !== 'string' || plaintext.length === 0) throw new Error('Please enter text to encrypt.');
  if (typeof password !== 'string' || password.length === 0) throw new Error('Please provide a password.');

  const sodium = await getSodium();
  const opslimit = options.opslimit || DEFAULT_OPSLIMIT;
  const memlimitKiB = options.memlimitKiB || DEFAULT_MEMLIMIT_KIB;
  const salt = sodium.randombytes_buf(SALT_BYTES);
  const nonce = sodium.randombytes_buf(NONCE_BYTES);
  let key = null;

  try {
    key = sodium.crypto_pwhash(KEY_BYTES, password, salt, opslimit, memlimitKiB * 1024, sodium.crypto_pwhash_ALG_ARGON2ID13);
    const message = sodium.from_string(plaintext);
    const body = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(message, null, null, nonce, key);
    const ciphertext = makeEnvelope(sodium, opslimit, memlimitKiB, salt, nonce, body);
    return { ciphertext, totalBytes: HEADER_BYTES + body.length, saltHex: sodium.to_hex(salt), nonceHex: sodium.to_hex(nonce), version: FORMAT_VERSION, cipher: 'XChaCha20-Poly1305', kdf: 'Argon2id' };
  } finally {
    if (key) sodium.memzero(key);
  }
}

export async function decryptText(ciphertext, password) {
  if (typeof ciphertext !== 'string' || !ciphertext.trim()) throw new Error('Please enter ciphertext to decrypt.');
  if (typeof password !== 'string' || password.length === 0) throw new Error('Please enter the password.');

  try {
    const sodium = await getSodium();
    const envelope = fromBase64Url(ciphertext);
    if (envelope.length < MIN_ENVELOPE_BYTES) throw new Error('invalid');

    const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
    if (envelope[0] !== FORMAT_VERSION || envelope[1] !== CIPHER_ID_ARGON2ID_XCHACHA20) throw new Error('invalid');

    const opslimit = view.getUint32(2, false);
    const memlimitKiB = view.getUint32(6, false);
    if (opslimit < MIN_OPSLIMIT || opslimit > MAX_OPSLIMIT || memlimitKiB < MIN_MEMLIMIT_KIB || memlimitKiB > MAX_MEMLIMIT_KIB) throw new Error('invalid');

    const salt = envelope.slice(10, 26);
    const nonce = envelope.slice(26, 50);
    const body = envelope.slice(50);
    let key = null;

    try {
      key = sodium.crypto_pwhash(KEY_BYTES, password, salt, opslimit, memlimitKiB * 1024, sodium.crypto_pwhash_ALG_ARGON2ID13);
      const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, body, null, nonce, key);
      return sodium.to_string(plaintext);
    } finally {
      if (key) sodium.memzero(key);
    }
  } catch (_) {
    throw new Error(GENERIC_DECRYPT_ERROR);
  }
}

export async function runCryptoSelfTests() {
  const password = 'TestPassword!987#XChaCha';
  const plaintext = 'The quick brown fox jumps over the lazy dog 🔒 12345';
  const results = [];
  const add = (id, name, passed, description) => results.push({ id, name, passed, description });

  try { const a = await encryptText(plaintext, password); const b = await decryptText(a.ciphertext, password); add('roundtrip', 'Roundtrip Integrity', b === plaintext, 'Encrypt/decrypt restores the exact original text.'); } catch (_) { add('roundtrip', 'Roundtrip Integrity', false, 'Crypto self-test failed.'); }
  try { const a = await encryptText(plaintext, password); let rejected = false; try { await decryptText(a.ciphertext, 'WrongPassword-123'); } catch (e) { rejected = e.message === GENERIC_DECRYPT_ERROR; } add('wrong_password', 'Wrong Password Rejection', rejected, 'Incorrect passwords are rejected.'); } catch (_) { add('wrong_password', 'Wrong Password Rejection', false, 'Crypto self-test failed.'); }
  try { const a = await encryptText(plaintext, password); const raw = fromBase64Url(a.ciphertext); raw[raw.length - 1] ^= 1; let rejected = false; try { await decryptText(toBase64Url(raw), password); } catch (e) { rejected = e.message === GENERIC_DECRYPT_ERROR; } add('tamper', 'Tamper Detection', rejected, 'A modified ciphertext fails authentication.'); } catch (_) { add('tamper', 'Tamper Detection', false, 'Crypto self-test failed.'); }
  try { const a = await encryptText(plaintext, password); const b = await encryptText(plaintext, password); add('freshness', 'Salt & Nonce Freshness', a.ciphertext !== b.ciphertext && a.saltHex !== b.saltHex && a.nonceHex !== b.nonceHex, 'Repeated encryption produces fresh random values.'); } catch (_) { add('freshness', 'Salt & Nonce Freshness', false, 'Crypto self-test failed.'); }
  try { const a = await encryptText(plaintext, password); const raw = fromBase64Url(a.ciphertext); raw[0] = 255; let rejected = false; try { await decryptText(toBase64Url(raw), password); } catch (e) { rejected = e.message === GENERIC_DECRYPT_ERROR; } add('format', 'Envelope Validation', rejected, 'Unsupported protocol versions are rejected.'); } catch (_) { add('format', 'Envelope Validation', false, 'Crypto self-test failed.'); }

  return { success: results.every(r => r.passed), results };
}
