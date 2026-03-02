# 🛡️ Post-Quantum E2EE Chat

**Kuantum Sonrası Uçtan Uca Şifreli Sohbet Uygulaması**

Kuantum bilgisayarlara dayanıklı, tarayıcı tabanlı uçtan uca şifreli (E2EE) sohbet uygulaması. Sunucu yalnızca şifreli verileri iletir — özel anahtarlar ve düz metin mesajlar sunucuya **asla** ulaşmaz.

---

## Şifreleme Mimarisi

| Katman | Algoritma | Standart | Açıklama |
|--------|-----------|----------|----------|
| **Anahtar Kapsülleme** | ML-KEM-1024 (Kyber) | NIST FIPS 203 | Kuantum sonrası anahtar değişimi |
| **Simetrik Şifreleme** | AES-256-GCM | NIST SP 800-38D | Mesaj şifreleme (Web Crypto API) |
| **Anahtar Türetme** | HKDF-SHA256 | RFC 5869 | KEM shared secret → AES anahtarı |

### Mesaj Şifreleme Akışı

```
Gönderen                         Sunucu                        Alıcı
────────                         ──────                        ──────
ML-KEM-1024 encapsulate(pubKey)                                ML-KEM-1024 keypair
  → kemCiphertext + sharedSecret
HKDF(sharedSecret) → aesKey
AES-256-GCM encrypt(msg)
  → {kemCipher, iv, cipher} ────► relay (opak veri) ────────► decapsulate(kemCipher, secKey)
                                                               HKDF(sharedSecret) → aesKey
                                                               AES-256-GCM decrypt → msg
```

Her mesaj için **yeni bir KEM kapsülleme** yapılır — her mesajın benzersiz bir simetrik anahtarı vardır.

---

## Proje Yapısı

```
├── server.js          # Node.js + Express + Socket.IO sunucusu
├── index.html         # Vite entry point
├── vite.config.js     # Vite build yapılandırması
├── package.json
├── src/
│   ├── crypto.js      # PQC şifreleme modülü (ML-KEM-1024 + AES-256-GCM)
│   ├── main.js        # İstemci mantığı (Socket.IO + UI)
│   └── style.css      # Koyu temalı modern arayüz
└── dist/              # Vite build çıktısı (sunucu buradan servis eder)
```

---

## Gereksinimler

- Node.js 18+
- Modern tarayıcı (Web Crypto API desteği)

---

## Kurulum & Çalıştırma

```bash
# Bağımlılıkları yükle
npm install

# Frontend'i derle
npm run build

# Sunucuyu başlat
npm start
```

Tarayıcıda `http://localhost:4000` adresini açın. Birden fazla sekme/pencere ile farklı kullanıcıları simüle edebilirsiniz.

### Geliştirme Modu

```bash
# İlk terminalde — backend
npm start

# İkinci terminalde — Vite dev server (HMR)
npm run dev
```

Vite dev server `http://localhost:5173` üzerinden çalışır ve Socket.IO isteklerini backend'e proxy'ler.

---

## Kullanım

1. **Kullanıcı adı** girin ve **Kayıt Ol & Anahtar Üret** butonuna tıklayın.
   - Tarayıcınızda ML-KEM-1024 anahtar çifti üretilir
   - Açık anahtar sunucuya gönderilir
   - Özel anahtar **asla** tarayıcıdan çıkmaz
2. Sol panelden bir **kullanıcı** seçin
3. Mesajınızı yazıp **Gönder** butonuna veya **Enter**'a basın
   - Mesaj alıcının açık anahtarı ile KEM kapsülleme + AES-256-GCM ile şifrelenir
   - Sunucu yalnızca şifreli veriyi iletir
   - Alıcı kendi özel anahtarı ile çözer

---

## Neden Kuantum Sonrası?

Geleneksel RSA ve ECC tabanlı şifreleme, gelecekteki kuantum bilgisayarlar tarafından **Shor algoritması** ile kırılabilir. ML-KEM (CRYSTALS-Kyber), NIST tarafından 2024'te standardize edilen **kafes tabanlı** (lattice-based) bir anahtar kapsülleme mekanizmasıdır ve kuantum saldırılarına karşı dayanıklıdır.

| Algoritma | Kuantum Güvenliği |
|-----------|-------------------|
| RSA-2048 | ❌ Shor ile kırılır |
| ECDH (P-256) | ❌ Shor ile kırılır |
| **ML-KEM-1024** | ✅ Kuantum dayanıklı |

---

## Güvenlik Notları

- Bu bir **demo** uygulamasıdır — production kullanımı için ek güvenlik önlemleri gerekir
- Sunucu MITM saldırısı yapabilir (sahte public key iletebilir) — gerçek uygulamada anahtar parmak izi doğrulaması gerekir
- Özel anahtarlar yalnızca bellekte tutulur — sayfa yenilenince kaybolur
- Perfect Forward Secrecy her mesaj için yeni KEM kapsülleme ile sağlanır

---

## Lisans

MIT License
