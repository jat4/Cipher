/**
 * Cipher - Utilities Module
 * Safe UI helpers, password strength estimation, clipboard management,
 * and text measurement tools.
 *
 * All functions operate strictly in-memory.
 */

/**
 * Calculates password entropy and strength metrics.
 * @param {string} password
 * @returns {object} Strength details including score (0-4), label, entropy, feedback
 */
export function calculatePasswordStrength(password) {
  if (!password || password.length === 0) {
    return {
      score: 0,
      label: 'Empty',
      color: 'neutral',
      entropy: 0,
      crackTimeDisplay: 'Instant',
      feedback: 'Enter a strong password to protect your data.',
      percent: 0
    };
  }

  const length = password.length;
  let poolSize = 0;

  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigits = /[0-9]/.test(password);
  const hasSymbols = /[^a-zA-Z0-9\s]/.test(password);
  const hasSpaces = /\s/.test(password);

  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasDigits) poolSize += 10;
  if (hasSymbols) poolSize += 33;
  if (hasSpaces) poolSize += 1;

  if (poolSize === 0) poolSize = 1;

  // Shannon entropy approximation (bits)
  const entropy = Math.floor(length * (Math.log2(poolSize)));

  let score = 0;
  let label = 'Very Weak';
  let color = 'error';
  let percent = 20;
  let crackTimeDisplay = 'Seconds';
  let feedback = 'Very weak password. Easily crackable.';

  if (length < 8) {
    score = 0;
    label = 'Very Weak';
    color = 'error';
    percent = 15;
    crackTimeDisplay = '< 1 second';
    feedback = 'Too short. Minimum 12-16 characters recommended.';
  } else if (entropy < 40 || length < 10) {
    score = 1;
    label = 'Weak';
    color = 'warning';
    percent = 35;
    crackTimeDisplay = 'Minutes to hours';
    feedback = 'Weak. Combine uppercase, lowercase, numbers, and symbols.';
  } else if (entropy < 60 || length < 12) {
    score = 2;
    label = 'Fair';
    color = 'warning';
    percent = 60;
    crackTimeDisplay = 'Days to months';
    feedback = 'Fair. Lengthening the passphrase will significantly improve security.';
  } else if (entropy < 80 || length < 16) {
    score = 3;
    label = 'Strong';
    color = 'success';
    percent = 85;
    crackTimeDisplay = 'Centuries (with Argon2id)';
    feedback = 'Strong password. Resistant to modern brute-force attacks.';
  } else {
    score = 4;
    label = 'Very Strong';
    color = 'success';
    percent = 100;
    crackTimeDisplay = 'Astronomical';
    feedback = 'Excellent passphrase. Exceptional resistance to offline attacks.';
  }

  return {
    score,
    label,
    color,
    percent,
    entropy,
    length,
    crackTimeDisplay,
    feedback,
    hasLower,
    hasUpper,
    hasDigits,
    hasSymbols
  };
}

/**
 * Counts characters, bytes (UTF-8), words, and lines in a given text string.
 * @param {string} text
 * @returns {object}
 */
export function getTextStats(text) {
  if (!text) {
    return { characters: 0, bytes: 0, words: 0, lines: 0 };
  }
  const characters = text.length;
  const bytes = new TextEncoder().encode(text).length;
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;
  const lines = text.split('\n').length;

  return { characters, bytes, words, lines };
}

/**
 * Formats byte size into human readable string (B, KB, MB).
 * @param {number} bytes
 * @returns {string}
 */
export function formatByteSize(bytes) {
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Safe clipboard copy with fallback.
 * @param {string} text
 * @returns {Promise<boolean>}
 */
export async function copyToClipboard(text) {
  if (!text) return false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (err) {
    // fallback below
  }

  try {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    const successful = document.execCommand('copy');
    document.body.removeChild(textArea);
    return successful;
  } catch (err) {
    return false;
  }
}

/**
 * Safe clipboard paste.
 * @returns {Promise<string|null>}
 */
export async function readFromClipboard() {
  try {
    if (navigator.clipboard && navigator.clipboard.readText) {
      const text = await navigator.clipboard.readText();
      return text;
    }
  } catch (err) {
    // Permission denied or unsupported
  }
  return null;
}

/**
 * Triggers a client-side file download for plaintext or ciphertext without server contact.
 * @param {string} filename
 * @param {string} content
 * @param {string} mimeType
 */
export function downloadFile(filename, content, mimeType = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
}

/**
 * Reads the text content of a user-selected File object.
 * @param {File} file
 * @returns {Promise<string>}
 */
export function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}
