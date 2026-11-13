// ===== Client-Side Encryption and Decryption =====
// Uses the browser's built-in Web Crypto API (AES-GCM) with a key
// derived from the user's passphrase via PBKDF2.
// Encrypted data is saved to localStorage so it can be retrieved
// and decrypted later, even after a page refresh.

const textInput = document.getElementById('textInput');
const keyInput = document.getElementById('keyInput');
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const output = document.getElementById('output');

const STORAGE_KEY = 'cse_encrypted_payload';
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

function showOutput(message, type) {
  output.textContent = message;
  output.classList.remove('success', 'error');
  if (type) output.classList.add(type);
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToBuffer(base64) {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function deriveKey(passphrase, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptAndSave() {
  const text = textInput.value;
  const passphrase = keyInput.value;

  if (!text.trim()) {
    showOutput('Please enter some text to encrypt.', 'error');
    return;
  }
  if (!passphrase.trim()) {
    showOutput('Please enter an encryption key.', 'error');
    return;
  }

  try {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const key = await deriveKey(passphrase, salt);

    const enc = new TextEncoder();
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      enc.encode(text)
    );

    const payload = {
      salt: bufferToBase64(salt),
      iv: bufferToBase64(iv),
      data: bufferToBase64(ciphertext)
    };

    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));

    showOutput(
      'Encrypted and saved successfully.\n\nCipher (base64):\n' + payload.data,
      'success'
    );
  } catch (err) {
    showOutput('Encryption failed: ' + err.message, 'error');
  }
}

async function retrieveAndDecrypt() {
  const passphrase = keyInput.value;

  if (!passphrase.trim()) {
    showOutput('Please enter the encryption key used to encrypt the data.', 'error');
    return;
  }

  const stored = localStorage.getItem(STORAGE_KEY);
  if (!stored) {
    showOutput('No encrypted data found. Encrypt and save something first.', 'error');
    return;
  }

  try {
    const payload = JSON.parse(stored);
    const salt = base64ToBuffer(payload.salt);
    const iv = base64ToBuffer(payload.iv);
    const data = base64ToBuffer(payload.data);

    const key = await deriveKey(passphrase, new Uint8Array(salt));

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv) },
      key,
      data
    );

    const dec = new TextDecoder();
    const plaintext = dec.decode(decrypted);

    showOutput('Decrypted text:\n\n' + plaintext, 'success');
  } catch (err) {
    showOutput('Decryption failed. Wrong key, or data is corrupted.', 'error');
  }
}

encryptBtn.addEventListener('click', encryptAndSave);
decryptBtn.addEventListener('click', retrieveAndDecrypt);
