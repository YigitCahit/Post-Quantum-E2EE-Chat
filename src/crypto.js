/**
 * Post-Quantum Cryptography Module
 * ─────────────────────────────────
 * ML-KEM-1024 (CRYSTALS-Kyber) — NIST FIPS 203
 * AES-256-GCM (symmetric encryption)
 * HKDF-SHA256 (key derivation)
 *
 * Hybrid per-message encryption:
 *   1. KEM encapsulation → shared secret
 *   2. HKDF derives AES-256 key from shared secret
 *   3. AES-256-GCM encrypts the plaintext
 */

import { ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

const HKDF_INFO = 'pqc-e2ee-chat-v2';

// ─── Key Generation ────────────────────────────────────────

/**
 * Generate an ML-KEM-1024 keypair.
 * Public key: 1568 bytes, Secret key: 3168 bytes.
 */
export function generateKeypair() {
  const { publicKey, secretKey } = ml_kem1024.keygen();
  return { publicKey, secretKey };
}

// ─── Encryption ────────────────────────────────────────────

/**
 * Encrypt a plaintext message for a recipient.
 *
 * @param {Uint8Array} recipientPublicKey - ML-KEM-1024 public key (1568 bytes)
 * @param {string} plaintext - message to encrypt
 * @returns {Promise<{kemCiphertext: string, iv: string, ciphertext: string}>}
 */
export async function encryptMessage(recipientPublicKey, plaintext) {
  // Step 1: KEM encapsulation — produces shared secret + KEM ciphertext
  const { cipherText: kemCiphertext, sharedSecret } = ml_kem1024.encapsulate(recipientPublicKey);

  // Step 2: Derive AES-256 key via HKDF-SHA256
  const aesKeyBytes = hkdf(sha256, sharedSecret, undefined, HKDF_INFO, 32);

  // Step 3: Import key for Web Crypto AES-GCM
  const aesKey = await crypto.subtle.importKey(
    'raw',
    aesKeyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );

  // Step 4: Encrypt with AES-256-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoded);

  return {
    kemCiphertext: uint8ToBase64(kemCiphertext),
    iv: uint8ToBase64(iv),
    ciphertext: uint8ToBase64(new Uint8Array(encrypted)),
  };
}

// ─── Decryption ────────────────────────────────────────────

/**
 * Decrypt a received message payload.
 *
 * @param {Uint8Array} secretKey - Our ML-KEM-1024 secret key (3168 bytes)
 * @param {{kemCiphertext: string, iv: string, ciphertext: string}} payload
 * @returns {Promise<string>} decrypted plaintext
 */
export async function decryptMessage(secretKey, payload) {
  // Step 1: KEM decapsulation — recover shared secret
  const kemCiphertext = base64ToUint8(payload.kemCiphertext);
  const sharedSecret = ml_kem1024.decapsulate(kemCiphertext, secretKey);

  // Step 2: Derive same AES-256 key
  const aesKeyBytes = hkdf(sha256, sharedSecret, undefined, HKDF_INFO, 32);

  const aesKey = await crypto.subtle.importKey(
    'raw',
    aesKeyBytes,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );

  // Step 3: Decrypt AES-256-GCM
  const iv = base64ToUint8(payload.iv);
  const ciphertext = base64ToUint8(payload.ciphertext);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);

  return new TextDecoder().decode(decrypted);
}

// ─── Fingerprint ───────────────────────────────────────────

/**
 * Compute a short SHA-256 fingerprint of a public key for visual verification.
 * Returns format like "A3:F1:9B:04:7C:DE:82:10"
 */
export async function getFingerprint(publicKey) {
  const hash = await crypto.subtle.digest('SHA-256', publicKey);
  const bytes = new Uint8Array(hash);
  return Array.from(bytes.slice(0, 8))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':')
    .toUpperCase();
}

// ─── Base64 Utilities ──────────────────────────────────────

export function uint8ToBase64(uint8) {
  let binary = '';
  for (let i = 0; i < uint8.length; i++) {
    binary += String.fromCharCode(uint8[i]);
  }
  return btoa(binary);
}

export function base64ToUint8(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
