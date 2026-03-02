/**
 * PQC E2EE Chat — Client Entry
 * ─────────────────────────────
 * Handles UI, Socket.IO communication, and PQC encryption calls.
 */

import { io } from 'socket.io-client';
import {
  generateKeypair,
  encryptMessage,
  decryptMessage,
  uint8ToBase64,
  base64ToUint8,
  getFingerprint,
} from './crypto.js';
import './style.css';

// ─── State ─────────────────────────────────────────────────

const socket = io();

let myKeypair = null;
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

// ─── Registration ──────────────────────────────────────────

elBtnRegister.addEventListener('click', async () => {
  const name = elUsername.value.trim();
  if (!name) {
    elUsername.focus();
    return;
  }

  setStatus('ML-KEM-1024 anahtar çifti üretiliyor…', 'warning');
  elBtnRegister.disabled = true;

  try {
    // Generate post-quantum keypair
    myKeypair = generateKeypair();
    myName = name;

    const pubKeyB64 = uint8ToBase64(myKeypair.publicKey);
    socket.emit('register', { username: myName, publicKey: pubKeyB64 });

    const fp = await getFingerprint(myKeypair.publicKey);
    elFingerprint.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
      Anahtar Parmak İzi: <code>${fp}</code>
    `;

    log(
      `<strong>${escapeHtml(myName)}</strong> olarak kayıt olundu — ML-KEM-1024 anahtar çifti üretildi.`,
      'success',
    );
    setStatus('Bağlı — Kuantum Sonrası Şifreleme Aktif ✓', 'success');

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
  // Clear old state
  for (const key of Object.keys(userList)) delete userList[key];
  elUsers.innerHTML = '';

  let count = 0;
  for (const u of list) {
    if (u.username === myName) continue;

    userList[u.username] = { publicKey: u.publicKey };
    count++;

    const pubKeyBytes = base64ToUint8(u.publicKey);
    const fp = await getFingerprint(pubKeyBytes);

    const div = document.createElement('div');
    div.className = 'user' + (selectedUser === u.username ? ' selected' : '');
    div.innerHTML = `
      <div class="user-name">${escapeHtml(u.username)}</div>
      <div class="user-fp">${fp}</div>
    `;
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
    const decrypted = await decryptMessage(myKeypair.secretKey, data.payload);
    log(
      `<span class="msg-from">${escapeHtml(data.from)}</span> ${escapeHtml(decrypted)}`,
      'message',
    );
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

    socket.emit('send_message', {
      to: selectedUser,
      from: myName,
      payload,
    });

    log(
      `<span class="msg-to">Sen → ${escapeHtml(selectedUser)}</span> ${escapeHtml(msg)}`,
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
