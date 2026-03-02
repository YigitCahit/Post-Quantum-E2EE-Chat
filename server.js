import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { cors: { origin: '*' } });

const PORT = process.env.PORT || 4000;
const users = new Map();

// Serve built frontend
app.use(express.static(path.join(__dirname, 'dist')));
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

io.on('connection', (socket) => {
  console.log(`[+] Socket connected: ${socket.id}`);

  socket.on('register', (data) => {
    const { username, publicKey, signingKey } = data;
    if (!username || !publicKey) {
      socket.emit('error', { msg: 'username and publicKey required' });
      return;
    }

    // Prevent duplicate usernames (different socket)
    const existing = users.get(username);
    if (existing && existing.sid !== socket.id) {
      socket.emit('error', { msg: 'Bu kullanıcı adı zaten kullanılıyor' });
      return;
    }

    users.set(username, { sid: socket.id, publicKey, signingKey });
    broadcastUserList();
    console.log(`[+] Registered: ${username}  (ML-KEM-1024 + ML-DSA-65)`);
  });

  socket.on('send_message', (data) => {
    const { to, from, payload, signature } = data;
    if (!to || !payload) {
      socket.emit('error', { msg: 'to and payload required' });
      return;
    }
    const recipient = users.get(to);
    if (!recipient) {
      socket.emit('error', { msg: 'Alıcı bulunamadı' });
      return;
    }
    // Server only relays — it cannot decrypt or forge (PQC encryption + ML-DSA signatures)
    io.to(recipient.sid).emit('private_message', { from, payload, signature });
    console.log(`[>] Relayed PQC-encrypted+signed message: ${from} → ${to}`);
  });

  socket.on('request_user_list', () => {
    broadcastUserList();
  });

  socket.on('disconnect', () => {
    for (const [username, info] of users.entries()) {
      if (info.sid === socket.id) {
        users.delete(username);
        console.log(`[-] Disconnected: ${username}`);
        broadcastUserList();
        break;
      }
    }
  });
});

function broadcastUserList() {
  const list = [];
  for (const [username, info] of users.entries()) {
    list.push({ username, publicKey: info.publicKey, signingKey: info.signingKey });
  }
  io.emit('user_list', list);
}

httpServer.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║   🛡️  PQC E2EE Chat Server                         ║');
  console.log('║   Post-Quantum: ML-KEM-1024 + AES-256-GCM          ║');
  console.log(`║   Running on: http://localhost:${PORT}                  ║`);
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log('');
});
