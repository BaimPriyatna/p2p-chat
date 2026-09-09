# UI/UX Implementation Plan — peerc

> Disesuaikan dari dokumen desain sebelumnya. Perubahan di versi ini: nama
> proyek diganti ke **peerc**, dan bagian Device ID / Fingerprint (§6–§8)
> diperjelas bahwa nilai yang ditampilkan berasal dari **SHA-256 atas
> Ed25519 public key** — bukan UUID, bukan IP/MAC, bukan hardware serial
> (lihat `BUG_REPORT.md` BUG-003 untuk alasan penolakan alternatif lain).

## 1. Konsep UI utama

Targetnya bukan TUI yang penuh widget seperti desktop app, tetapi
terminal-native file sharing app yang cepat dipahami.

Inspirasi UX:

```
┌──────────────────────────────────────────────────────────────┐
│ peerc                                          ● LAN Connected │
├───────────────┬──────────────────────────────────────────────┤
│ DEVICES       │ CHAT                                         │
│               │                                              │
│ ● Laptop      │ You                                           │
│   Trusted     │ Hello!                                       │
│               │                                              │
│ ● Android     │ Android                                      │
│   Trusted     │ Here's the file.                             │
│               │                                              │
│ ? PC-Room     │                                              │
│   New Device  │                                              │
├───────────────┴──────────────────────────────────────────────┤
│ [Message...................................................] │
├──────────────────────────────────────────────────────────────┤
│ 3 devices • Secure • 1 transfer                              │
└──────────────────────────────────────────────────────────────┘
```

Fokus:

- device-centric
- security status selalu terlihat
- transfer progress jelas
- keyboard-first
- mouse optional
- tidak terlalu banyak border/dekorasi

---

## 2. Struktur navigasi

Jangan membuat semuanya menjadi satu screen.

Gunakan beberapa view:

```
Main
├── Chat
├── Devices
├── Transfers
├── History
└── Settings
```

Navigation:

```
Tab / 1-5
```

Contoh:

```
1 Chat
2 Devices
3 Transfers
4 History
5 Settings
```

Dan:

```
q → quit
? → help
Esc → back
```

---

## 3. Main Screen

Chat menjadi default screen.

Layout:

```
┌───────────────────────────────────────────────┐
│ peerc                             ● Secure LAN │
├──────────────┬────────────────────────────────┤
│ DEVICES      │ CHAT                           │
│              │                                │
│ ● Laptop     │ Baim                           │
│ ● Android    │ Hello                          │
│ ? Desktop    │                                │
│              │ Android                        │
│              │ 📎 photo.jpg                   │
│              │                                │
├──────────────┴────────────────────────────────┤
│ > Type a message...                           │
├───────────────────────────────────────────────┤
│ Enter Send   Ctrl+F File   Tab Switch   ? Help│
└───────────────────────────────────────────────┘
```

---

## 4. Device sidebar

Ini salah satu bagian paling penting.

Device ditampilkan berdasarkan status.

```
DEVICES

● Laptop
  Trusted
  192.168.1.10

● Android
  Trusted
  192.168.1.20

? PC-ROOM
  New device

✕ Old Laptop
  Revoked
```

Status jangan hanya mengandalkan warna.

Gunakan icon:

```
●  online
○  offline
?  pending
✓  trusted
!  warning
✕  revoked
```

Jadi terminal tanpa warna pun tetap readable.

---

## 5. Security indicator

Header:

```
● Secure
```

bisa berubah menjadi:

```
● Secure
! Verification required
✕ Connection insecure
```

Tetapi jangan menampilkan jargon crypto kepada user biasa.

Misalnya ketika device trusted:

```
✓ Trusted device
```

Detail fingerprint hanya ketika user membuka detail.

---

## 6. Device Detail

Tekan:

```
Enter
```

pada device.

Muncul:

```
┌─────────────────────────────────────┐
│ Device                              │
├─────────────────────────────────────┤
│ Name        Android                 │
│ Status      ● Online                │
│ Trust       ✓ Trusted               │
│ Address     192.168.1.20:5656       │
│                                     │
│ Device ID                           │
│ 91C3 7A42 8F21 ...                  │
│                                     │
│ Fingerprint                         │
│ A82F 19C3 77B1 ...                  │
│                                     │
│ Last seen   2 minutes ago           │
│                                     │
│ [Send File] [Chat] [Revoke]         │
└─────────────────────────────────────┘
```

**Catatan implementasi:** `Device ID` dan `Fingerprint` di atas **bukan**
dua nilai independen yang perlu digenerate terpisah — keduanya berasal dari
Ed25519 public key milik device tersebut:

```
Ed25519 public key
        ↓ SHA-256
   device_id (dipakai internal, mis. di peer registry)
        ↓ format hex berkelompok, mis. "A8 2F 19 C3 ..."
   fingerprint (yang ditampilkan ke user untuk verifikasi manual)
```

Karena berasal dari public key, nilai ini **tidak pernah berubah** selama
private key device tidak diganti — beda dengan IP/MAC yang bisa berubah
kapan saja, dan beda dengan UUID acak yang tidak bisa dibuktikan
kepemilikannya. Lihat `BUG_REPORT.md` BUG-003 untuk alasan lengkap kenapa
IP/MAC/hostname/hardware-serial ditolak sebagai basis identity.

---

## 7. New Device UX

Saat device baru ditemukan:

```
┌──────────────────────────────────────────┐
│ New device detected                      │
├──────────────────────────────────────────┤
│                                          │
│ Android                                  │
│                                          │
│ Fingerprint                              │
│ A82F 19C3 77B1 9D20                     │
│                                          │
│ This device is not trusted yet.          │
│                                          │
│ [T] Trust        [R] Reject              │
│                                          │
└──────────────────────────────────────────┘
```

Jangan otomatis trust device hanya karena ditemukan melalui discovery.

---

## 8. Key Change Warning

Ini harus menjadi UX khusus.

Jika public key device berubah — misalnya karena device di-reset dan
generate keypair baru (lihat Implementation_plan.md Phase 24, key
rotation):

```
┌──────────────────────────────────────────┐
│ ⚠ SECURITY WARNING                       │
├──────────────────────────────────────────┤
│ Android has changed its identity.        │
│                                          │
│ Previous                                │
│ A82F 19C3 77B1                          │
│                                          │
│ Current                                 │
│ 71AC 44E1 9320                          │
│                                          │
│ This may mean:                           │
│ • the device was reinstalled             │
│ • its identity was rotated               │
│ • the device may be compromised          │
│                                          │
│ [Reject]       [Trust New Identity]      │
└──────────────────────────────────────────┘
```

Ini jauh lebih berguna daripada hanya:

```
AUTH_FAILED
```

---

## 9. Chat UX

Chat jangan seperti terminal biasa:

```
Alice: hello
Bob: hi
```

Buat lebih readable:

```
Baim
14:32
Hello!

Android
14:33
Hi, sending the file.
```

Tetapi jangan terlalu banyak whitespace agar terminal kecil tetap nyaman.

---

## 10. File attachment

Chat dapat menampilkan:

```
Android

┌───────────────────────────────┐
│ 📎 photo.jpg                  │
│ 12.4 MB                       │
│                               │
│ ✓ Received                    │
└───────────────────────────────┘
```

Untuk transfer aktif:

```
photo.jpg
██████████████░░░░░░  67%
8.3 / 12.4 MB
↓ 18.4 MB/s
ETA 00:04
```

---

## 11. Transfers View

Semua transfer aktif dikumpulkan di sini.

```
TRANSFERS

↓ photo.jpg
  Android
  ███████████░░░ 72%
  8.9 / 12.4 MB
  18.2 MB/s
  ETA 00:02

↑ archive.zip
  Laptop
  ██████░░░░░░░░ 41%
  410 / 1000 MB
  32.1 MB/s
  ETA 00:18
```

Keyboard:

```
p  Pause
r  Resume
c  Cancel
Enter  Details
```

---

## 12. Transfer Details

```
Transfer

File
ubuntu.iso

Size
4.2 GB

From
Laptop

Status
Transferring

Progress
63%

Speed
42.3 MB/s

ETA
00:31

Integrity
SHA-256 pending

Encryption
✓ Secure session

[Pause] [Cancel]
```

---

## 13. Transfer completion

Jangan hanya:

```
Done
```

Tampilkan:

```
✓ Transfer complete

ubuntu.iso
4.2 GB

From: Laptop
Time: 01:42
SHA-256: Verified

Saved to:
~/Downloads/ubuntu.iso
```

---

## 14. Error UX

Jangan expose traceback ke UI normal.

Buruk:

```
ConnectionResetError: [Errno 104] ...
```

Lebih baik:

```
✕ Transfer failed

ubuntu.iso

The connection was interrupted.

The transfer can be resumed when the device reconnects.

[Resume] [Close]
```

Detail teknis bisa:

```
d → Show technical details
```

---

## 15. Chat dengan multiple devices

Jangan memaksa satu global chat.

Sidebar:

```
DEVICES

● Android
  2 unread

● Laptop
  0 unread

● Desktop
  5 unread
```

Klik Android:

```
CHAT — ANDROID
```

Kemudian Laptop:

```
CHAT — LAPTOP
```

---

## 16. Multi-device transfer

Nantinya:

```
Ctrl+F
```

muncul:

```
Send File

Select device:

> Android
  Laptop
  Desktop
```

Kemudian file picker terminal.

Kalau belum mau membuat native file picker, MVP cukup:

```
/send ~/Pictures/photo.jpg
```

TUI tetap dapat memanggil command tersebut.

---

## 17. Command palette

Ini menurut saya penting.

Tekan:

```
Ctrl+P
```

atau:

```
:
```

Muncul:

```
┌──────────────────────────────────────────┐
│ > send                                   │
├──────────────────────────────────────────┤
│ Send file                                │
│ Send clipboard                           │
│ Open device                               │
│ Revoke device                             │
│ Settings                                  │
└──────────────────────────────────────────┘
```

Jadi user tidak perlu menghafal semua shortcut.

---

## 18. CLI tetap tersedia

TUI adalah interface utama:

```
peerc
```

Tetapi CLI:

```
peerc send ./photo.jpg --device <id>
peerc devices
peerc trust <id>
peerc revoke <id>
peerc history
```

Ini berguna untuk:

- scripting
- automation
- SSH
- headless machine
- debugging

---

## 19. Responsive terminal

Karena terminal bisa:

```
80x24
120x40
200x60
```

UI harus adaptive.

80 columns

```
┌──────────────────────────────┐
│ Chat                         │
│                              │
│ Messages                     │
│                              │
│                              │
│ > message                    │
└──────────────────────────────┘
```

Sidebar bisa disembunyikan.

120+

```
┌─────────────┬───────────────────────────┐
│ Devices     │ Chat                      │
└─────────────┴───────────────────────────┘
```

160+

```
┌────────────┬────────────────────┬───────┐
│ Devices    │ Chat               │ Info  │
│            │                    │       │
│            │                    │       │
└────────────┴────────────────────┴───────┘
```

---

## 20. Theme

Saya sarankan dark-first, karena terminal environment.

Tetapi jangan hardcode warna.

Buat theme:

```
theme/
├── dark.tcss
└── light.tcss
```

Gunakan semantic colors:

```
success
warning
error
muted
accent
primary
```

Bukan:

```
green
red
blue
```

di seluruh code.

---

## 21. Accessibility

Jangan mengandalkan warna.

Contoh buruk:

```
🟢 = trusted
🔴 = revoked
```

Lebih baik:

```
✓ Trusted
✕ Revoked
! Warning
```

Dan:

```
NO_COLOR=1
```

tetap harus readable.

---

## 22. Keyboard-first

Semua operasi penting harus bisa dilakukan tanpa mouse.

```
Tab       next widget
Shift+Tab previous
Enter     select
Esc       back
Ctrl+P    command palette
Ctrl+F    send file
Ctrl+L    focus chat
Ctrl+R    refresh
?         help
q         quit
```

---

## 23. Help screen

Tekan `?`.

```
KEYBOARD SHORTCUTS

Navigation
  Tab       Move focus
  Enter     Select
  Esc       Back

Chat
  Ctrl+L    Focus message
  Ctrl+F    Send file

Transfers
  p         Pause
  r         Resume
  c         Cancel

Devices
  t         Trust
  x         Revoke

General
  Ctrl+P    Command palette
  Ctrl+R    Refresh
  ?         Help
  q         Quit
```

---

## 24. Notification system

Jangan membuat popup untuk semuanya.

Gunakan notification/toast:

```
✓ File received

⚠ New device detected

✕ Transfer failed
```

Level:

```
INFO
SUCCESS
WARNING
ERROR
SECURITY
```

Security event harus lebih menonjol.

---

## 25. Status bar

Bagian bawah:

```
3 devices • 1 transfer • ✓ Secure
```

atau:

```
3 devices • 1 transfer • ! Verification required
```

Jadi user selalu tahu kondisi aplikasi.

---

## 26. Settings

Jangan terlalu banyak setting di awal.

```
SETTINGS

General
  Device name
  Download directory
  Start minimized

Network
  TCP port
  Discovery
  mDNS

Security
  Trusted devices
  Key management
  Require approval

Transfers
  Max concurrent transfers
  Auto resume
  Max incoming file size

Appearance
  Theme
  Compact mode
```

---

## 27. Arsitektur UI

Karena kamu menggunakan Python + Textual, akan dibuat:

```
ui/
├── app.py
├── screens/
│   ├── main.py
│   ├── devices.py
│   ├── transfers.py
│   ├── history.py
│   ├── settings.py
│   └── help.py
│
├── widgets/
│   ├── device_list.py
│   ├── device_card.py
│   ├── chat_view.py
│   ├── message_input.py
│   ├── transfer_item.py
│   ├── progress_bar.py
│   ├── security_badge.py
│   ├── notification.py
│   └── command_palette.py
│
├── dialogs/
│   ├── trust_device.py
│   ├── revoke_device.py
│   ├── transfer_details.py
│   └── security_warning.py
│
└── styles/
    ├── dark.tcss
    └── light.tcss
```

---

## 28. UI jangan mengakses network langsung

Ini penting.

Jangan:

```
UI
 ↓
socket
 ↓
TCP
```

Tetapi:

```
┌── ChatService
             │
UI → AppState ├── TransferService
             │
             ├── DeviceService
             │
             └── SecurityService
```

UI hanya mengamati state.

---

## 29. App State

Buat central state:

```
AppState
```

isinya:

```
devices
connections
active_chat
messages
transfers
notifications
security_events
```

Misalnya:

```
DeviceState
{
    id,
    name,
    address,
    status,
    trust_status,
    fingerprint
}
```

UI melakukan render berdasarkan state tersebut.

---

## 30. Event architecture

Network menghasilkan:

```
PeerDiscovered
PeerConnected
PeerDisconnected

TrustRequired
SecurityWarning

MessageReceived
MessageSent

TransferStarted
TransferProgress
TransferPaused
TransferCompleted
TransferFailed
```

Kemudian:

```
Event
 ↓
AppState
 ↓
UI refresh
```

Ini akan menghilangkan masalah handler chaining dari implementasi sekarang
(lihat `BUG_REPORT.md` ARCH-001).

---

## 31. UX flow final

Pertama kali menjalankan

```
peerc
      ↓
Generate device identity
      ↓
Main TUI
      ↓
Discover devices
```

User melihat:

```
? Android
  New device
```

Tekan Enter:

```
Fingerprint
A82F 19C3 ...

[T] Trust
```

Trust.

Kemudian:

```
✓ Android
  Trusted
```

---

Mengirim file

```
Ctrl+F
 ↓
Select device
 ↓
Select file
 ↓
FILE_OFFER
 ↓
Receiver accepts
 ↓
Progress
 ↓
SHA-256 verification
 ↓
✓ Complete
```

---

Device dicurigai

```
⚠ Identity changed
```

User:

```
Reject
```

Device menjadi:

```
✕ Revoked
```

---

## 32. Implementation order

Urutan pengerjaan UI:

```
1. App shell
      ↓
2. Main screen
      ↓
3. Device sidebar
      ↓
4. Chat view
      ↓
5. Transfer view
      ↓
6. Notifications
      ↓
7. Device detail
      ↓
8. Trust/revoke dialogs
      ↓
9. Security warning
      ↓
10. Command palette
      ↓
11. Settings
      ↓
12. History
      ↓
13. Responsive layout
      ↓
14. Theme
      ↓
15. Accessibility
      ↓
16. CLI integration
```

## Target akhirnya

```
PEERC

       ┌─────── Main ───────┐
       │                    │
       │  Devices            │
       │  ──────────────     │
       │  ✓ Android          │
       │  ✓ Laptop           │
       │  ? Desktop          │
       │                    │
       │  Chat               │
       │  ──────────────     │
       │  Hello              │
       │  📎 photo.jpg       │
       │                    │
       │  Transfers          │
       │  ███████░ 72%       │
       │                    │
       └────────────────────┘

       ✓ Secure • 3 Devices
```

Intinya: TUI ini sebaiknya terasa seperti aplikasi desktop yang kebetulan
berjalan di terminal, bukan seperti kumpulan command yang diberi warna.
Textual cocok untuk itu. Dan karena security menjadi fitur utama project,
Trust/Identity/Security Warning harus menjadi bagian first-class dari UI,
bukan sesuatu yang tersembunyi di log.
