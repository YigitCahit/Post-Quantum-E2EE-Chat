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
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
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

// ─── ML-DSA-65 Signing (FIPS 204) ─────────────────────

/**
 * Generate an ML-DSA-65 signing keypair.
 * Public key: 1952 bytes, Secret key: 4032 bytes.
 */
export function generateSigningKeypair() {
  const { publicKey, secretKey } = ml_dsa65.keygen();
  return { publicKey, secretKey };
}

/**
 * Sign a message payload with ML-DSA-65.
 * Signs the canonical string: kemCiphertext:iv:ciphertext
 */
export function signPayload(signingSecretKey, payload) {
  const canonical = `${payload.kemCiphertext}:${payload.iv}:${payload.ciphertext}`;
  const encoded = new TextEncoder().encode(canonical);
  const signature = ml_dsa65.sign(signingSecretKey, encoded);
  return uint8ToBase64(signature);
}

/**
 * Verify a payload signature with ML-DSA-65.
 */
export function verifyPayloadSignature(signingPublicKey, payload, signatureB64) {
  try {
    const canonical = `${payload.kemCiphertext}:${payload.iv}:${payload.ciphertext}`;
    const encoded = new TextEncoder().encode(canonical);
    const signature = base64ToUint8(signatureB64);
    return ml_dsa65.verify(signingPublicKey, encoded, signature);
  } catch {
    return false;
  }
}

// ─── Safety Number ─────────────────────────────────────

/**
 * Generate a safety number for verifying two users' identities out-of-band.
 * Both parties compute the same number from their combined keys.
 * Format: 6 groups of 5 digits (e.g., "12345 67890 11223 44556 67890 12345")
 *
 * @param {string} user1 - First username
 * @param {{kem: Uint8Array, dsa: Uint8Array}} keys1 - First user's public keys
 * @param {string} user2 - Second username
 * @param {{kem: Uint8Array, dsa: Uint8Array}} keys2 - Second user's public keys
 */
export async function generateSafetyNumber(user1, keys1, user2, keys2) {
  const [first, second] = user1 < user2
    ? [{ name: user1, ...keys1 }, { name: user2, ...keys2 }]
    : [{ name: user2, ...keys2 }, { name: user1, ...keys1 }];

  const parts = [
    new TextEncoder().encode(first.name + '\x00'),
    first.kem,
    first.dsa,
    new TextEncoder().encode(second.name + '\x00'),
    second.kem,
    second.dsa,
  ];

  let totalLen = 0;
  for (const p of parts) totalLen += p.length;
  const combined = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    combined.set(p, offset);
    offset += p.length;
  }

  const hash1 = await crypto.subtle.digest('SHA-256', combined);
  const hash2 = await crypto.subtle.digest('SHA-256', hash1);
  const bytes = new Uint8Array(hash2);

  let number = '';
  for (let i = 0; i < 30; i += 5) {
    const val = ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
    number += String(val % 100000).padStart(5, '0');
    if (i + 5 < 30) number += ' ';
  }
  return number;
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
