/* ============================================================
   script.js  –  all logic
   ============================================================ */

(function() {
    'use strict';

    // ── DOM refs ──
    const inputEl = document.getElementById('inputText');
    const outputEl = document.getElementById('outputText');
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const copyBtn = document.getElementById('copyBtn');
    const statusEl = document.getElementById('statusMsg');

    // ── Constants ──
    const PASSPHRASE = 'SHA256';
    const SALT = new TextEncoder().encode('EncryptionSalt2024');
    const ITERATIONS = 100000;
    const KEY_LENGTH = 256;          // AES-GCM 256-bit
    const IV_LENGTH = 12;            // recommended for AES-GCM

    // ── State ──
    let isBusy = false;

    // ── Helpers ──
    function setStatus(msg, type) {
        statusEl.innerHTML = '';
        const span = document.createElement('span');
        span.textContent = msg;
        statusEl.appendChild(span);
        statusEl.className = 'status-msg' + (type ? ' ' + type : '');
    }

    function setBusy(busy) {
        isBusy = busy;
        encryptBtn.disabled = busy;
        decryptBtn.disabled = busy;
        copyBtn.disabled = busy;
        if (busy) {
            statusEl.innerHTML = '<span class="spinner"></span> Working…';
            statusEl.className = 'status-msg';
        }
    }

    function base64ToUint8Array(b64) {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    function uint8ArrayToBase64(arr) {
        let binary = '';
        const chunk = 8192;
        for (let i = 0; i < arr.length; i += chunk) {
            const slice = arr.subarray(i, i + chunk);
            binary += String.fromCharCode.apply(null, slice);
        }
        return btoa(binary);
    }

    // ── Derive AES key from passphrase using PBKDF2 ──
    async function deriveKey() {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            enc.encode(PASSPHRASE),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        return crypto.subtle.deriveKey({
                name: 'PBKDF2',
                salt: SALT,
                iterations: ITERATIONS,
                hash: 'SHA-256'
            },
            keyMaterial, {
                name: 'AES-GCM',
                length: KEY_LENGTH
            },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // ── Encrypt ──
    async function encryptText(plaintext) {
        if (!plaintext) throw new Error('Input is empty.');
        const key = await deriveKey();
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        const encoded = new TextEncoder().encode(plaintext);
        const ciphertext = await crypto.subtle.encrypt({
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encoded
        );
        // Combine IV + ciphertext
        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(ciphertext), iv.length);
        return uint8ArrayToBase64(combined);
    }

    // ── Decrypt ──
    async function decryptText(ciphertextB64) {
        if (!ciphertextB64) throw new Error('Input is empty.');
        let combined;
        try {
            combined = base64ToUint8Array(ciphertextB64);
        } catch (_) {
            throw new Error('Invalid base64 input.');
        }
        if (combined.length < IV_LENGTH) {
            throw new Error('Data too short – missing IV.');
        }
        const iv = combined.slice(0, IV_LENGTH);
        const ciphertext = combined.slice(IV_LENGTH);
        if (ciphertext.length === 0) {
            throw new Error('No ciphertext data.');
        }
        const key = await deriveKey();
        const plaintext = await crypto.subtle.decrypt({
                name: 'AES-GCM',
                iv: iv
            },
            key,
            ciphertext
        );
        return new TextDecoder().decode(plaintext);
    }

    // ── ═══════════════════════════════════════════════════════ ──
    // ──  updateOutput  –  central function to set output & status ──
    // ──  Called by both encrypt and decrypt handlers           ──
    // ── ═══════════════════════════════════════════════════════ ──
    function updateOutput(result, success, message) {
        if (success) {
            outputEl.value = result;
            setStatus(message, 'success');
        } else {
            outputEl.value = '';
            setStatus(message, 'error');
        }
    }

    // ── Action handlers ──
    async function handleEncrypt() {
        if (isBusy) return;
        const input = inputEl.value;
        if (!input.trim()) {
            updateOutput('', false, 'Please enter some text to encrypt.');
            return;
        }
        try {
            setBusy(true);
            const result = await encryptText(input);
            updateOutput(result, true, '✓ Encrypted successfully. Use Decrypt to revert.');
        } catch (err) {
            updateOutput('', false, '✗ Encryption failed: ' + err.message);
        } finally {
            setBusy(false);
        }
    }

    async function handleDecrypt() {
        if (isBusy) return;
        const input = inputEl.value;
        if (!input.trim()) {
            updateOutput('', false, 'Please enter encrypted text to decrypt.');
            return;
        }
        try {
            setBusy(true);
            const result = await decryptText(input);
            updateOutput(result, true, '✓ Decrypted successfully.');
        } catch (err) {
            updateOutput('', false, '✗ Decryption failed: ' + err.message);
        } finally {
            setBusy(false);
        }
    }

    function handleCopy() {
        const text = outputEl.value;
        if (!text) {
            setStatus('Nothing to copy – output is empty.', 'error');
            return;
        }
        navigator.clipboard.writeText(text).then(() => {
            setStatus('✓ Copied to clipboard!', 'success');
        }).catch(() => {
            // Fallback
            outputEl.select();
            document.execCommand('copy');
            setStatus('✓ Copied!', 'success');
        });
    }

    // ── Wire events ──
    encryptBtn.addEventListener('click', handleEncrypt);
    decryptBtn.addEventListener('click', handleDecrypt);
    copyBtn.addEventListener('click', handleCopy);

    // Ctrl+Enter in input triggers Encrypt
    inputEl.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            handleEncrypt();
        }
    });

    // ── Initial status ──
    setStatus('Ready — enter text and click Encrypt or Decrypt.', '');

})();