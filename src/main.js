/**
 * PQC E2EE Chat — Client Entry
 * ─────────────────────────────
 * Handles UI, Socket.IO communication, and PQC encryption calls.
 */

import { io } from 'socket.io-client';
import {
  generateKeypair,
  generateSigningKeypair,
  encryptMessage,
  decryptMessage,
  signPayload,
  verifyPayloadSignature,
  generateSafetyNumber,
  uint8ToBase64,
  base64ToUint8,
  getFingerprint,
} from './crypto.js';
import './style.css';

// ─── State ─────────────────────────────────────────────────

const socket = io();

let myKeypair = null;
let mySigningKeypair = null;
let myName = null;
let selectedUser = null;
const userList = {};

// ─── DOM References ────────────────────────────────────────

const $ = (id) => document.getElementById(id);
const elUsername = $('username');
const elBtnRegister = $('btnRegister');
const elUsers = $('users');
const elLog = $('log');
const elMessage = $('message');
const elBtnSend = $('btnSend');
const elStatus = $('status');
const elFingerprint = $('fingerprint');
const elRegisterBar = $('registerBar');
const elSafetyModal = $('safetyModal');
const elSafetyNumber = $('safetyNumber');
const elSafetyUser = $('safetyUser');
const elBtnVerifyKey = $('btnVerifyKey');
const elCloseSafetyModal = $('closeSafetyModal');

// ─── Logging ───────────────────────────────────────────────

function log(html, type = 'info') {
  // Remove welcome message on first real log
  const welcome = elLog.querySelector('.log-welcome');
  if (welcome) welcome.remove();

  const div = document.createElement('div');
  div.className = `log-entry log-${type}`;

  const time = new Date().toLocaleTimeString('tr-TR', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  div.innerHTML = `<span class="log-time">${time}</span> ${html}`;
  elLog.appendChild(div);
  elLog.scrollTop = elLog.scrollHeight;
}

function setStatus(text, type = 'info') {
  elStatus.textContent = text;
  elStatus.className = `status status-${type}`;
}

function escapeHtml(text) {
  const d = document.createElement('div');
  d.textContent = text;
  return d.innerHTML;
}

// ─── Key Pinning (TOFU — Trust On First Use) ──────────

const KEY_STORE_NAME = 'pqc_trusted_keys';

function getKeyStore() {
  try { return JSON.parse(localStorage.getItem(KEY_STORE_NAME) || '{}'); }
  catch { return {}; }
}

function saveKeyStore(store) {
  localStorage.setItem(KEY_STORE_NAME, JSON.stringify(store));
}

/**
 * Check trust status of a user's keys.
 * Returns: { status: 'new' | 'trusted' | 'verified' | 'changed', ... }
 */
function checkKeyTrust(username, kemFp, dsaFp) {
  const store = getKeyStore();
  const entry = store[username];

  if (!entry) {
    store[username] = { kemFp, dsaFp, firstSeen: Date.now(), verified: false };
    saveKeyStore(store);
    return { status: 'new' };
  }

  if (entry.kemFp === kemFp && entry.dsaFp === dsaFp) {
    return { status: entry.verified ? 'verified' : 'trusted' };
  }

  return { status: 'changed', oldKemFp: entry.kemFp, oldDsaFp: entry.dsaFp };
}

function markKeyVerified(username) {
  const store = getKeyStore();
  if (store[username]) {
    store[username].verified = true;
    saveKeyStore(store);
  }
}

function acceptChangedKey(username, kemFp, dsaFp) {
  const store = getKeyStore();
  store[username] = { kemFp, dsaFp, firstSeen: Date.now(), verified: false };
  saveKeyStore(store);
}

// ─── Safety Number ─────────────────────────────────────

async function showSafetyNumber(username) {
  const user = userList[username];
  if (!user || !myKeypair || !mySigningKeypair) return;

  const myKeys = { kem: myKeypair.publicKey, dsa: mySigningKeypair.publicKey };
  const theirKeys = {
    kem: base64ToUint8(user.publicKey),
    dsa: base64ToUint8(user.signingKey),
  };

  const safetyNum = await generateSafetyNumber(myName, myKeys, username, theirKeys);
  elSafetyNumber.textContent = safetyNum;
  elSafetyUser.textContent = username;
  elSafetyModal.style.display = 'flex';
}

// ─── Registration ──────────────────────────────────────────

elBtnRegister.addEventListener('click', async () => {
  const name = elUsername.value.trim();
  if (!name) {
    elUsername.focus();
    return;
  }

  setStatus('ML-KEM-1024 + ML-DSA-65 anahtar çiftleri üretiliyor…', 'warning');
  elBtnRegister.disabled = true;

  try {
    // Generate post-quantum keypairs (KEM + DSA)
    myKeypair = generateKeypair();
    mySigningKeypair = generateSigningKeypair();
    myName = name;

    const pubKeyB64 = uint8ToBase64(myKeypair.publicKey);
    const sigKeyB64 = uint8ToBase64(mySigningKeypair.publicKey);
    socket.emit('register', { username: myName, publicKey: pubKeyB64, signingKey: sigKeyB64 });

    const kemFp = await getFingerprint(myKeypair.publicKey);
    const dsaFp = await getFingerprint(mySigningKeypair.publicKey);
    elFingerprint.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
      KEM: <code>${kemFp}</code> · DSA: <code>${dsaFp}</code>
    `;

    log(
      `<strong>${escapeHtml(myName)}</strong> olarak kayıt olundu — ML-KEM-1024 + ML-DSA-65 anahtar çiftleri üretildi.`,
      'success',
    );
    setStatus('Bağlı — Kuantum Sonrası Şifreleme + İmzalama Aktif ✓', 'success');

    // Lock registration, enable chat
    elUsername.disabled = true;
    elBtnRegister.style.display = 'none';
    elRegisterBar.classList.add('registered');
    elMessage.disabled = false;
    elBtnSend.disabled = false;
    elMessage.focus();
  } catch (e) {
    console.error(e);
    setStatus('Anahtar üretimi başarısız!', 'error');
    log('Anahtar üretimi başarısız: ' + escapeHtml(e.message), 'error');
    elBtnRegister.disabled = false;
  }
});

// Enter to register
elUsername.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    elBtnRegister.click();
  }
});

// ─── Socket Events ─────────────────────────────────────────

socket.on('connect', () => {
  log('Sunucuya bağlanıldı.', 'info');
  setStatus('Bağlandı — Kayıt olun', 'info');
});

socket.on('disconnect', () => {
  log('Sunucu bağlantısı kesildi!', 'error');
  setStatus('Bağlantı kesildi', 'error');
});

socket.on('user_list', async (list) => {
  for (const key of Object.keys(userList)) delete userList[key];
  elUsers.innerHTML = '';

  let count = 0;
  for (const u of list) {
    if (u.username === myName) continue;

    userList[u.username] = { publicKey: u.publicKey, signingKey: u.signingKey };
    count++;

    const pubKeyBytes = base64ToUint8(u.publicKey);
    const kemFp = await getFingerprint(pubKeyBytes);

    let dsaFp = '';
    let trust = { status: 'new' };
    if (u.signingKey) {
      const sigKeyBytes = base64ToUint8(u.signingKey);
      dsaFp = await getFingerprint(sigKeyBytes);
      trust = checkKeyTrust(u.username, kemFp, dsaFp);
    }

    let trustBadge = '';
    let trustClass = '';
    switch (trust.status) {
      case 'new':
        trustBadge = '🟡 Yeni';
        trustClass = 'trust-new';
        break;
      case 'trusted':
        trustBadge = '🔵 Bilinen';
        trustClass = 'trust-known';
        break;
      case 'verified':
        trustBadge = '✅ Doğrulanmış';
        trustClass = 'trust-verified';
        break;
      case 'changed':
        trustBadge = '🔴 ANAHTAR DEĞİŞTİ!';
        trustClass = 'trust-changed';
        log(
          `⚠️ <strong>${escapeHtml(u.username)}</strong> kullanıcısının anahtarı değişti! ` +
          `Olası MITM saldırısı. Eski parmak izi: <code>${trust.oldKemFp}</code>`,
          'error',
        );
        break;
    }

    const div = document.createElement('div');
    div.className = 'user' + (selectedUser === u.username ? ' selected' : '') +
                    (trust.status === 'changed' ? ' user-key-changed' : '');
    div.innerHTML = `
      <div class="user-header">
        <span class="user-name">${escapeHtml(u.username)}</span>
        <span class="trust-badge ${trustClass}">${trustBadge}</span>
      </div>
      <div class="user-fp">KEM: ${kemFp}</div>
      ${dsaFp ? `<div class="user-fp">DSA: ${dsaFp}</div>` : ''}
      <button class="btn-safety" title="Güvenlik Numarası">🔐</button>
    `;

    div.querySelector('.btn-safety').addEventListener('click', (e) => {
      e.stopPropagation();
      showSafetyNumber(u.username);
    });

    div.addEventListener('click', () => {
      document.querySelectorAll('.user').forEach((x) => x.classList.remove('selected'));
      div.classList.add('selected');
      selectedUser = u.username;
    });
    elUsers.appendChild(div);
  }

  if (count === 0) {
    elUsers.innerHTML = '<div class="no-users">Başka çevrimiçi kullanıcı yok</div>';
  }
});

socket.on('private_message', async (data) => {
  if (!myKeypair) return;
  try {
    // Verify ML-DSA-65 signature before decrypting
    let signatureValid = false;
    const sender = userList[data.from];
    if (sender && sender.signingKey && data.signature) {
      const sigPubKey = base64ToUint8(sender.signingKey);
      signatureValid = verifyPayloadSignature(sigPubKey, data.payload, data.signature);
    }

    const decrypted = await decryptMessage(myKeypair.secretKey, data.payload);

    const sigBadge = signatureValid
      ? '<span class="sig-valid" title="ML-DSA-65 imzası doğrulandı">✓ İmzalı</span>'
      : '<span class="sig-invalid" title="İmza doğrulanamadı!">⚠️ İmzasız</span>';

    log(
      `<span class="msg-from">${escapeHtml(data.from)}</span> ${sigBadge} ${escapeHtml(decrypted)}`,
      'message',
    );

    if (!signatureValid) {
      log('⚠️ Bu mesajın dijital imzası doğrulanamadı — mesaj sahte olabilir!', 'warning');
    }
  } catch (e) {
    log(`<span class="msg-from">${escapeHtml(data.from)}</span> <em>Mesaj çözülemedi</em>`, 'error');
    console.error(e);
  }
});

socket.on('error', (data) => {
  log('Hata: ' + escapeHtml(data.msg), 'error');
});

// ─── Send Message ──────────────────────────────────────────

async function sendMessage() {
  const msg = elMessage.value.trim();
  if (!msg) return;
  if (!selectedUser) {
    log('Lütfen sol panelden bir alıcı seçin.', 'warning');
    return;
  }

  const recipient = userList[selectedUser];
  if (!recipient) {
    log('Alıcının açık anahtarı bulunamadı.', 'error');
    return;
  }

  try {
    const recipientPubKey = base64ToUint8(recipient.publicKey);
    const payload = await encryptMessage(recipientPubKey, msg);
    const signature = signPayload(mySigningKeypair.secretKey, payload);

    socket.emit('send_message', {
      to: selectedUser,
      from: myName,
      payload,
      signature,
    });

    log(
      `<span class="msg-to">Sen → ${escapeHtml(selectedUser)}</span> <span class="sig-valid">✓ İmzalı</span> ${escapeHtml(msg)}`,
      'sent',
    );
    elMessage.value = '';
    elMessage.focus();
  } catch (e) {
    console.error(e);
    log('Şifreleme hatası: ' + escapeHtml(e.message), 'error');
  }
}

elBtnSend.addEventListener('click', sendMessage);
elMessage.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    sendMessage();
  }
});

// ─── Safety Number Modal ───────────────────────────────

elCloseSafetyModal.addEventListener('click', () => {
  elSafetyModal.style.display = 'none';
});

elSafetyModal.addEventListener('click', (e) => {
  if (e.target === elSafetyModal) elSafetyModal.style.display = 'none';
});

elBtnVerifyKey.addEventListener('click', () => {
  if (!selectedUser) return;
  markKeyVerified(selectedUser);
  log(`✅ <strong>${escapeHtml(selectedUser)}</strong> kullanıcısının anahtarı doğrulanmış olarak işaretlendi.`, 'success');
  elSafetyModal.style.display = 'none';
  socket.emit('request_user_list');
});
