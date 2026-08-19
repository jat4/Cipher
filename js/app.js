/**
 * Cipher - Application UI Controller
 * Manages mode switching, DOM events, input validation, clipboard,
 * theme management, and self-testing UI.
 */

import { encryptText, decryptText, runCryptoSelfTests, getSodium } from './crypto.js';
import {
  calculatePasswordStrength,
  getTextStats,
  formatByteSize,
  copyToClipboard,
  readFromClipboard,
  downloadFile,
  readFileAsText
} from './utils.js';

// Application State
let currentMode = 'encrypt'; // 'encrypt' | 'decrypt'
let isProcessing = false;
let sodiumReady = false;

// DOM Elements Cache
const elements = {};

function initDOMElements() {
  // Navigation & Mode
  elements.btnModeEncrypt = document.getElementById('btn-mode-encrypt');
  elements.btnModeDecrypt = document.getElementById('btn-mode-decrypt');
  elements.panelEncrypt = document.getElementById('panel-encrypt');
  elements.panelDecrypt = document.getElementById('panel-decrypt');
  elements.themeToggle = document.getElementById('theme-toggle');

  // Modals & Triggers
  elements.btnOpenSecurity = document.getElementById('btn-open-security');
  elements.btnOpenSelfTest = document.getElementById('btn-open-selftest');
  elements.modalSecurity = document.getElementById('modal-security');
  elements.modalSelfTest = document.getElementById('modal-selftest');
  elements.btnCloseSecurity = document.getElementById('btn-close-security');
  elements.btnCloseSelfTest = document.getElementById('btn-close-selftest');
  elements.btnRunSelfTest = document.getElementById('btn-run-selftest');
  elements.selfTestResultsList = document.getElementById('selftest-results-list');
  elements.selfTestSummaryBadge = document.getElementById('selftest-summary-badge');

  // Encrypt Form
  elements.encryptPlaintext = document.getElementById('encrypt-plaintext');
  elements.encryptPassword = document.getElementById('encrypt-password');
  elements.encryptConfirmPassword = document.getElementById('encrypt-confirm-password');
  elements.encryptTogglePassword = document.getElementById('encrypt-toggle-password');
  elements.encryptToggleConfirmPassword = document.getElementById('encrypt-toggle-confirm-password');
  elements.btnEncrypt = document.getElementById('btn-encrypt');
  elements.encryptOutput = document.getElementById('encrypt-output');
  elements.encryptOutputContainer = document.getElementById('encrypt-output-container');
  elements.encryptStatus = document.getElementById('encrypt-status');

  // Encrypt Helpers & Actions
  elements.btnPastePlaintext = document.getElementById('btn-paste-plaintext');
  elements.btnClearPlaintext = document.getElementById('btn-clear-plaintext');
  elements.btnUploadPlaintextFile = document.getElementById('btn-upload-plaintext-file');
  elements.inputUploadPlaintext = document.getElementById('input-upload-plaintext');
  elements.btnCopyCiphertext = document.getElementById('btn-copy-ciphertext');
  elements.btnDownloadCiphertext = document.getElementById('btn-download-ciphertext');
  elements.btnClearEncryptOutput = document.getElementById('btn-clear-encrypt-output');

  // Password Strength Elements
  elements.strengthBar = document.getElementById('password-strength-bar');
  elements.strengthLabel = document.getElementById('password-strength-label');
  elements.strengthFeedback = document.getElementById('password-strength-feedback');
  elements.passwordMatchWarning = document.getElementById('password-match-warning');

  // Text Stats
  elements.plaintextStats = document.getElementById('plaintext-stats');
  elements.ciphertextStats = document.getElementById('ciphertext-stats');

  // Decrypt Form
  elements.decryptCiphertext = document.getElementById('decrypt-ciphertext');
  elements.decryptPassword = document.getElementById('decrypt-password');
  elements.decryptTogglePassword = document.getElementById('decrypt-toggle-password');
  elements.btnDecrypt = document.getElementById('btn-decrypt');
  elements.decryptOutput = document.getElementById('decrypt-output');
  elements.decryptOutputContainer = document.getElementById('decrypt-output-container');
  elements.decryptStatus = document.getElementById('decrypt-status');

  // Decrypt Helpers & Actions
  elements.btnPasteCiphertext = document.getElementById('btn-paste-ciphertext');
  elements.btnClearCiphertext = document.getElementById('btn-clear-ciphertext');
  elements.btnUploadCiphertextFile = document.getElementById('btn-upload-ciphertext-file');
  elements.inputUploadCiphertext = document.getElementById('input-upload-ciphertext');
  elements.btnCopyPlaintext = document.getElementById('btn-copy-plaintext');
  elements.btnDownloadPlaintext = document.getElementById('btn-download-plaintext');
  elements.btnClearDecryptOutput = document.getElementById('btn-clear-decrypt-output');
  elements.decryptCiphertextStats = document.getElementById('decrypt-ciphertext-stats');
  elements.decryptOutputStats = document.getElementById('decrypt-output-stats');

  // Toast Container
  elements.toastContainer = document.getElementById('toast-container');
}

/**
 * Displays a non-intrusive toast alert.
 * @param {string} message 
 * @param {'success'|'error'|'info'} type 
 */
function showToast(message, type = 'info') {
  if (!elements.toastContainer) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.setAttribute('role', 'alert');
  toast.textContent = message;

  elements.toastContainer.appendChild(toast);

  // Trigger entrance transition
  requestAnimationFrame(() => {
    toast.classList.add('toast-visible');
  });

  setTimeout(() => {
    toast.classList.remove('toast-visible');
    setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 300);
  }, 3200);
}

/**
 * Updates plaintext statistics display.
 */
function updatePlaintextStats() {
  const text = elements.encryptPlaintext.value || '';
  const stats = getTextStats(text);
  elements.plaintextStats.textContent = `${stats.characters.toLocaleString()} chars · ${formatByteSize(stats.bytes)} · ${stats.words.toLocaleString()} words`;
}

/**
 * Updates encrypt output stats display.
 */
function updateEncryptOutputStats() {
  const text = elements.encryptOutput.value || '';
  const stats = getTextStats(text);
  elements.ciphertextStats.textContent = `${stats.characters.toLocaleString()} chars · ${formatByteSize(stats.bytes)}`;
}

/**
 * Updates decrypt input stats display.
 */
function updateDecryptInputStats() {
  const text = elements.decryptCiphertext.value || '';
  const stats = getTextStats(text);
  elements.decryptCiphertextStats.textContent = `${stats.characters.toLocaleString()} chars · ${formatByteSize(stats.bytes)}`;
}

/**
 * Updates decrypt output stats display.
 */
function updateDecryptOutputStats() {
  const text = elements.decryptOutput.value || '';
  const stats = getTextStats(text);
  elements.decryptOutputStats.textContent = `${stats.characters.toLocaleString()} chars · ${formatByteSize(stats.bytes)} · ${stats.words.toLocaleString()} words`;
}

/**
 * Updates the password strength widget.
 */
function updatePasswordStrength() {
  const password = elements.encryptPassword.value || '';
  const confirm = elements.encryptConfirmPassword.value || '';
  const strength = calculatePasswordStrength(password);

  elements.strengthBar.style.width = `${strength.percent}%`;
  elements.strengthBar.className = `strength-fill strength-${strength.color}`;
  elements.strengthLabel.textContent = strength.label;
  elements.strengthLabel.className = `strength-badge badge-${strength.color}`;
  elements.strengthFeedback.textContent = strength.feedback;

  // Password confirmation check
  if (confirm.length > 0) {
    if (password !== confirm) {
      elements.passwordMatchWarning.textContent = 'Passwords do not match.';
      elements.passwordMatchWarning.classList.remove('hidden');
    } else {
      elements.passwordMatchWarning.classList.add('hidden');
    }
  } else {
    elements.passwordMatchWarning.classList.add('hidden');
  }
}

/**
 * Sets the active application mode.
 * @param {'encrypt'|'decrypt'} mode 
 */
function switchMode(mode) {
  currentMode = mode;
  if (mode === 'encrypt') {
    elements.btnModeEncrypt.classList.add('active');
    elements.btnModeDecrypt.classList.remove('active');
    elements.btnModeEncrypt.setAttribute('aria-selected', 'true');
    elements.btnModeDecrypt.setAttribute('aria-selected', 'false');
    elements.panelEncrypt.classList.remove('hidden');
    elements.panelDecrypt.classList.add('hidden');
  } else {
    elements.btnModeDecrypt.classList.add('active');
    elements.btnModeEncrypt.classList.remove('active');
    elements.btnModeDecrypt.setAttribute('aria-selected', 'true');
    elements.btnModeEncrypt.setAttribute('aria-selected', 'false');
    elements.panelDecrypt.classList.remove('hidden');
    elements.panelEncrypt.classList.add('hidden');
  }
}

/**
 * Toggles password field visibility between text and password.
 * @param {HTMLInputElement} inputEl 
 * @param {HTMLButtonElement} btnEl 
 */
function togglePasswordVisibility(inputEl, btnEl) {
  const isPassword = inputEl.type === 'password';
  inputEl.type = isPassword ? 'text' : 'password';
  btnEl.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
  
  const icon = btnEl.querySelector('svg');
  if (icon) {
    if (isPassword) {
      // Eye-off icon
      icon.innerHTML = `<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24m-3.53-7.77a9 9 0 0 1 8.41 5.65 9 9 0 0 1-2.18 3.12m-4.52 2.12A9 9 0 0 1 2 12a9 9 0 0 1 3.59-4.88M1 1l22 22"/>`;
    } else {
      // Eye icon
      icon.innerHTML = `<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>`;
    }
  }
}

/**
 * Handles Encrypt Action.
 */
async function handleEncrypt() {
  if (isProcessing) return;

  const plaintext = elements.encryptPlaintext.value;
  const password = elements.encryptPassword.value;
  const confirmPassword = elements.encryptConfirmPassword.value;

  if (!plaintext || plaintext.trim().length === 0) {
    showStatus(elements.encryptStatus, 'Please enter plaintext text to encrypt.', 'error');
    elements.encryptPlaintext.focus();
    return;
  }

  if (!password) {
    showStatus(elements.encryptStatus, 'Please provide a password.', 'error');
    elements.encryptPassword.focus();
    return;
  }

  if (password !== confirmPassword) {
    showStatus(elements.encryptStatus, 'Passwords do not match. Please verify your password.', 'error');
    elements.encryptConfirmPassword.focus();
    return;
  }

  try {
    isProcessing = true;
    setButtonLoading(elements.btnEncrypt, true, 'Deriving Key (Argon2id) & Encrypting...');
    showStatus(elements.encryptStatus, 'Computing Argon2id memory-hard key derivation and XChaCha20-Poly1305 encryption...', 'info');

    // Yield to UI thread to render spinner
    await new Promise(r => setTimeout(r, 40));

    const result = await encryptText(plaintext, password);

    elements.encryptOutput.value = result.ciphertext;
    elements.encryptOutputContainer.classList.remove('hidden');
    updateEncryptOutputStats();
    showStatus(elements.encryptStatus, `Encryption successful (${formatByteSize(result.totalBytes)} authenticated package).`, 'success');
    showToast('Encrypted successfully!', 'success');

    // Smooth scroll to output on mobile
    if (window.innerWidth < 768) {
      elements.encryptOutputContainer.scrollIntoView({ behavior: 'smooth' });
    }
  } catch (err) {
    showStatus(elements.encryptStatus, err.message || 'Encryption failed.', 'error');
    showToast('Encryption failed', 'error');
  } finally {
    isProcessing = false;
    setButtonLoading(elements.btnEncrypt, false, 'Encrypt Text');
  }
}

/**
 * Handles Decrypt Action.
 */
async function handleDecrypt() {
  if (isProcessing) return;

  const ciphertext = elements.decryptCiphertext.value.trim();
  const password = elements.decryptPassword.value;

  if (!ciphertext) {
    showStatus(elements.decryptStatus, 'Please enter ciphertext to decrypt.', 'error');
    elements.decryptCiphertext.focus();
    return;
  }

  if (!password) {
    showStatus(elements.decryptStatus, 'Please enter the decryption password.', 'error');
    elements.decryptPassword.focus();
    return;
  }

  try {
    isProcessing = true;
    setButtonLoading(elements.btnDecrypt, true, 'Deriving Key & Verifying MAC...');
    showStatus(elements.decryptStatus, 'Deriving key with Argon2id and authenticating Poly1305 tag...', 'info');

    // Yield to UI thread to render spinner
    await new Promise(r => setTimeout(r, 40));

    const decryptedPlaintext = await decryptText(ciphertext, password);

    elements.decryptOutput.value = decryptedPlaintext;
    elements.decryptOutputContainer.classList.remove('hidden');
    updateDecryptOutputStats();
    showStatus(elements.decryptStatus, 'Decryption and authentication successful. Plaintext restored.', 'success');
    showToast('Decrypted and verified successfully!', 'success');

    if (window.innerWidth < 768) {
      elements.decryptOutputContainer.scrollIntoView({ behavior: 'smooth' });
    }
  } catch (err) {
    showStatus(elements.decryptStatus, err.message || 'Decryption failed.', 'error');
    showToast('Decryption failed', 'error');
    elements.decryptOutput.value = '';
    elements.decryptOutputContainer.classList.add('hidden');
  } finally {
    isProcessing = false;
    setButtonLoading(elements.btnDecrypt, false, 'Decrypt & Verify');
  }
}

/**
 * Helper to update status boxes safely.
 */
function showStatus(containerEl, message, type = 'info') {
  if (!containerEl) return;
  containerEl.className = `status-banner status-${type}`;
  containerEl.textContent = message;
  containerEl.classList.remove('hidden');
}

/**
 * Updates button loading state.
 */
function setButtonLoading(btn, isLoading, text) {
  if (!btn) return;
  btn.disabled = isLoading;
  const labelSpan = btn.querySelector('.btn-label');
  const spinner = btn.querySelector('.btn-spinner');
  
  if (labelSpan) labelSpan.textContent = text;
  if (spinner) {
    if (isLoading) spinner.classList.remove('hidden');
    else spinner.classList.add('hidden');
  }
}

/**
 * Runs crypto self tests and populates the test results modal.
 */
async function executeSelfTests() {
  if (!elements.selfTestResultsList) return;
  
  elements.btnRunSelfTest.disabled = true;
  elements.selfTestResultsList.innerHTML = `
    <div class="test-loading">
      <div class="spinner"></div>
      <p>Running in-browser cryptographic verification suite...</p>
    </div>
  `;

  // Yield to UI
  await new Promise(r => setTimeout(r, 100));

  const { success, results } = await runCryptoSelfTests();

  elements.selfTestResultsList.innerHTML = '';
  results.forEach(test => {
    const item = document.createElement('div');
    item.className = `selftest-item ${test.passed ? 'test-pass' : 'test-fail'}`;
    item.innerHTML = `
      <div class="selftest-item-header">
        <span class="selftest-icon">${test.passed ? '✓' : '✗'}</span>
        <strong class="selftest-name"></strong>
        <span class="selftest-badge ${test.passed ? 'badge-success' : 'badge-error'}">${test.passed ? 'PASSED' : 'FAILED'}</span>
      </div>
      <p class="selftest-desc"></p>
    `;
    item.querySelector('.selftest-name').textContent = test.name;
    item.querySelector('.selftest-desc').textContent = test.description;
    elements.selfTestResultsList.appendChild(item);
  });

  if (elements.selfTestSummaryBadge) {
    elements.selfTestSummaryBadge.textContent = success ? 'All 5 Tests Passed' : 'Test Failure Detected';
    elements.selfTestSummaryBadge.className = `badge ${success ? 'badge-success' : 'badge-error'}`;
  }

  elements.btnRunSelfTest.disabled = false;
  showToast(success ? 'Cryptographic suite verified' : 'Self-tests failed', success ? 'success' : 'error');
}

/**
 * Theme initialization and toggling.
 */
function initTheme() {
  const storedTheme = window.localStorage ? localStorage.getItem('cipher_theme') : null;
  const systemPrefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  
  const theme = storedTheme || (systemPrefersDark ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', theme);
  updateThemeIcon(theme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  if (window.localStorage) {
    try {
      localStorage.setItem('cipher_theme', next);
    } catch (e) {}
  }
  updateThemeIcon(next);
}

function updateThemeIcon(theme) {
  if (!elements.themeToggle) return;
  const icon = elements.themeToggle.querySelector('svg');
  if (!icon) return;
  if (theme === 'dark') {
    // Sun icon
    icon.innerHTML = `<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>`;
  } else {
    // Moon icon
    icon.innerHTML = `<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>`;
  }
}

/**
 * Event Listeners Setup.
 */
function attachEventListeners() {
  // Mode Switchers
  elements.btnModeEncrypt.addEventListener('click', () => switchMode('encrypt'));
  elements.btnModeDecrypt.addEventListener('click', () => switchMode('decrypt'));

  // Theme Toggle
  elements.themeToggle.addEventListener('click', toggleTheme);

  // Modals
  elements.btnOpenSecurity.addEventListener('click', () => {
    elements.modalSecurity.classList.remove('hidden');
    elements.modalSecurity.setAttribute('aria-hidden', 'false');
  });
  elements.btnCloseSecurity.addEventListener('click', () => {
    elements.modalSecurity.classList.add('hidden');
    elements.modalSecurity.setAttribute('aria-hidden', 'true');
  });

  elements.btnOpenSelfTest.addEventListener('click', () => {
    elements.modalSelfTest.classList.remove('hidden');
    elements.modalSelfTest.setAttribute('aria-hidden', 'false');
    executeSelfTests();
  });
  elements.btnCloseSelfTest.addEventListener('click', () => {
    elements.modalSelfTest.classList.add('hidden');
    elements.modalSelfTest.setAttribute('aria-hidden', 'true');
  });
  elements.btnRunSelfTest.addEventListener('click', executeSelfTests);

  // Close modals on clicking backdrop
  [elements.modalSecurity, elements.modalSelfTest].forEach(modal => {
    if (modal) {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          modal.classList.add('hidden');
          modal.setAttribute('aria-hidden', 'true');
        }
      });
    }
  });

  // Close modal on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      elements.modalSecurity.classList.add('hidden');
      elements.modalSelfTest.classList.add('hidden');
    }
  });

  // Password Visibility Toggles
  elements.encryptTogglePassword.addEventListener('click', () => {
    togglePasswordVisibility(elements.encryptPassword, elements.encryptTogglePassword);
  });
  elements.encryptToggleConfirmPassword.addEventListener('click', () => {
    togglePasswordVisibility(elements.encryptConfirmPassword, elements.encryptToggleConfirmPassword);
  });
  elements.decryptTogglePassword.addEventListener('click', () => {
    togglePasswordVisibility(elements.decryptPassword, elements.decryptTogglePassword);
  });

  // Live input stats & strength
  elements.encryptPlaintext.addEventListener('input', updatePlaintextStats);
  elements.encryptPassword.addEventListener('input', updatePasswordStrength);
  elements.encryptConfirmPassword.addEventListener('input', updatePasswordStrength);
  elements.decryptCiphertext.addEventListener('input', updateDecryptInputStats);

  // Action Buttons
  elements.btnEncrypt.addEventListener('click', handleEncrypt);
  elements.btnDecrypt.addEventListener('click', handleDecrypt);

  // Clipboard & Helpers - Encrypt Panel
  elements.btnPastePlaintext.addEventListener('click', async () => {
    const text = await readFromClipboard();
    if (text) {
      elements.encryptPlaintext.value = text;
      updatePlaintextStats();
      showToast('Pasted from clipboard', 'info');
    } else {
      showToast('Clipboard access denied or empty', 'error');
    }
  });

  elements.btnClearPlaintext.addEventListener('click', () => {
    elements.encryptPlaintext.value = '';
    updatePlaintextStats();
    elements.encryptPlaintext.focus();
  });

  elements.btnUploadPlaintextFile.addEventListener('click', () => {
    elements.inputUploadPlaintext.click();
  });

  elements.inputUploadPlaintext.addEventListener('change', async (e) => {
    const file = e.target.files && e.target.files[0];
    if (file) {
      try {
        const content = await readFileAsText(file);
        elements.encryptPlaintext.value = content;
        updatePlaintextStats();
        showToast(`Loaded ${file.name}`, 'info');
      } catch (err) {
        showToast('Failed to load file', 'error');
      }
      e.target.value = '';
    }
  });

  elements.btnCopyCiphertext.addEventListener('click', async () => {
    const text = elements.encryptOutput.value;
    if (text) {
      const ok = await copyToClipboard(text);
      if (ok) showToast('Ciphertext copied to clipboard!', 'success');
      else showToast('Failed to copy', 'error');
    }
  });

  elements.btnDownloadCiphertext.addEventListener('click', () => {
    const text = elements.encryptOutput.value;
    if (text) {
      downloadFile('encrypted-message.cipher', text, 'text/plain;charset=utf-8');
      showToast('Ciphertext downloaded', 'info');
    }
  });

  elements.btnClearEncryptOutput.addEventListener('click', () => {
    elements.encryptOutput.value = '';
    elements.encryptOutputContainer.classList.add('hidden');
    elements.encryptStatus.classList.add('hidden');
  });

  // Clipboard & Helpers - Decrypt Panel
  elements.btnPasteCiphertext.addEventListener('click', async () => {
    const text = await readFromClipboard();
    if (text) {
      elements.decryptCiphertext.value = text.trim();
      updateDecryptInputStats();
      showToast('Pasted ciphertext from clipboard', 'info');
    } else {
      showToast('Clipboard access denied or empty', 'error');
    }
  });

  elements.btnClearCiphertext.addEventListener('click', () => {
    elements.decryptCiphertext.value = '';
    updateDecryptInputStats();
    elements.decryptCiphertext.focus();
  });

  elements.btnUploadCiphertextFile.addEventListener('click', () => {
    elements.inputUploadCiphertext.click();
  });

  elements.inputUploadCiphertext.addEventListener('change', async (e) => {
    const file = e.target.files && e.target.files[0];
    if (file) {
      try {
        const content = await readFileAsText(file);
        elements.decryptCiphertext.value = content.trim();
        updateDecryptInputStats();
        showToast(`Loaded ${file.name}`, 'info');
      } catch (err) {
        showToast('Failed to load file', 'error');
      }
      e.target.value = '';
    }
  });

  elements.btnCopyPlaintext.addEventListener('click', async () => {
    const text = elements.decryptOutput.value;
    if (text) {
      const ok = await copyToClipboard(text);
      if (ok) showToast('Decrypted plaintext copied!', 'success');
      else showToast('Failed to copy', 'error');
    }
  });

  elements.btnDownloadPlaintext.addEventListener('click', () => {
    const text = elements.decryptOutput.value;
    if (text) {
      downloadFile('decrypted-message.txt', text, 'text/plain;charset=utf-8');
      showToast('Plaintext downloaded', 'info');
    }
  });

  elements.btnClearDecryptOutput.addEventListener('click', () => {
    elements.decryptOutput.value = '';
    elements.decryptOutputContainer.classList.add('hidden');
    elements.decryptStatus.classList.add('hidden');
  });
}

/**
 * Application Entry Point.
 */
async function initApp() {
  initTheme();
  initDOMElements();
  attachEventListeners();
  updatePlaintextStats();
  updatePasswordStrength();

  try {
    await getSodium();
    sodiumReady = true;
  } catch (err) {
    showToast('Failed to initialize cryptographic engine', 'error');
    showStatus(elements.encryptStatus, 'Cryptographic engine failed to load. Please ensure JavaScript and WebAssembly are enabled.', 'error');
  }
}

// Bootstrap when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}
