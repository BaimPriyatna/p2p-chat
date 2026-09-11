# File Viewer Architecture & Integration Design — peerc

> **Status:** Designed / Planned  
> **Terkait dengan:** `SECURE_STORAGE_DESIGN.md` §10 (Viewer Cache Mitigation), `DESIGN.md` §35-37 (Tab File UI), dan `ROADMAP.md`.

---

## 1. Motivasi & Prinsip Desain

Dalam aplikasi P2P terminal modern (`peerc`), user sering mengirim dan menerima file. Membuka file langsung ke viewer eksternal OS memiliki dua kelemahan besar:
1. **Mengganggu alur kerja terminal:** User harus berpindah jendela dari terminal ke aplikasi GUI desktop.
2. **Celah Keamanan Cache File (Viewer Cache Problem):**  
   Sebagaimana diidentifikasi dalam `SECURE_STORAGE_DESIGN.md` §10, jika file terenkripsi dari *Secure Storage* didekripsi ke storage disk biasa agar bisa dibaca oleh viewer eksternal, aplikasi eksternal atau OS (recent files list, thumbnail cache, temporary directory) dapat menyimpan salinan plaintext tanpa batas waktu di luar kendali `peerc`.

### Prinsip Utama File Viewer `peerc`

1. **In-Memory Streaming (Prioritas Tertinggi):**  
   Viewer sedapat mungkin merender langsung dari `bytes` di memori (RAM). Plaintext tidak pernah menyentuh disk storage lokal.
2. **Graceful Fallback & Modular Dependencies:**  
   Fitur dasar (teks, markdown, kode, tabel) menggunakan pustaka yang sudah menjadi dependensi utama `peerc` (`Textual` dan `Rich`). Ekstra viewer (PDF, gambar resolusi tinggi, audio) bersifat modular (`peerc[viewer]`) atau mendeteksi tools CLI open-source yang terpasang di sistem user.
3. **Zero Leaks pada External Tools:**  
   Jika memanggil CLI open-source eksternal (seperti `bat`, `mpv`, `chafa`), data dialirkan melalui **`stdin` pipe** (`cat file | tool -`), bukan file disk permanen.

---

## 2. Tiga Kategori File Viewer & Open-Source Stack

```
                     ┌─────────────────────────────────────────┐
                     │          peerc File Viewer              │
                     │          (In-Memory Stream)             │
                     └────────────────────┬────────────────────┘
                                          │
         ┌────────────────────────────────┼────────────────────────────────┐
         ▼                                ▼                                ▼
   [1. Text & Code]                  [2. Media]                      [3. Document]
  - Rich Syntax (Pygments)         - Pillow + Chafa / Half-blocks  - PyMuPDF (fitz)
  - Textual MarkdownViewer         - Kitty / Sixel Protocol        - Visual Page & Text Mode
  - Textual DataTable (CSV)        - mpv --no-video (Audio stream) - VisiData / openpyxl (XLSX)
  - bat / moar (stdin pipe)        - miniaudio (In-memory audio)   - zathura (External viewer)
```

---

### Kategori 1: Text & Code (`.txt`, `.py`, `.md`, `.json`, `.csv`, `.log`, `.rs`, `.go`, dll.)

Kategori ini sepenuhnya dapat dirender secara native di dalam TUI `peerc` tanpa menambah dependensi berat baru.

| Tipe File | Tool / Engine | Mekanisme Rendering |
|:---|:---|:---|
| **Markdown** (`.md`) | Textual `MarkdownViewer` | Native widget Textual. Dilengkapi automatic table of contents (TOC), heading links, blockquote styling, dan syntax highlighting code fence. |
| **Source Code** (`.py`, `.rs`, `.js`, dll.) | `rich.syntax.Syntax` + Pygments | Render kode dengan nomor baris (line numbers), tema warna yang konsisten dengan tema `peerc`, dan scroll bar interaktif ala btop. |
| **Structured Data** (`.json`, `.yaml`) | Textual `Tree` / `Pretty` | Collapsible tree view untuk JSON/YAML memudahkan eksplorasi data bertingkat. |
| **Tabular Data** (`.csv`, `.tsv`) | Textual `DataTable` | Tabel grid dengan header baris/kolom, navigasi cursor sel, dan sorting kolom. |
| *External CLI Fallback* | `bat` (Rust open-source) | Jika user memilih membuka di pager eksternal, dipanggil via `bat --paging=always -` melalui `stdin`. |

---

### Kategori 2: Media (Image, Audio, Video)

Kategori ini memungkinkan preview visual dan audio di terminal dengan proteksi memori.

#### A. Image (`.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.svg`)
* **In-App Viewer**:
  * **Engine**: `Pillow` (PIL) memuat gambar dari `io.BytesIO(decrypted_bytes)`.
  * **Rendering Terminal**:
    1. **Modern Protocols (Kitty Graphics Protocol / Sixel / iTerm2)**: Mengirim raster graphics langsung ke emulator terminal yang mendukungnya untuk kualitas 1:1 pixel.
    2. **Universal ANSI Half-block Fallback (`▀`, `▄`)**: Menghasilkan 24-bit truecolor text cells. Dapat ditampilkan di terminal apa pun (Windows Terminal, Alacritty, tmux, Linux console).
  * **Pustaka Open-Source**:
    * Integrasi pola widget Textual seperti `textual-imageview` atau binding C/Python [`chafa.py`](https://hpjansson.org/chafa/). `chafa` secara otomatis mendeteksi protokol terbaik terminal dan melakukan downsampling yang sangat halus.
* **External CLI Fallback**:
  * [`chafa -`](https://github.com/hpjansson/chafa) atau [`viu -`](https://github.com/atanunq/viu) via `stdin`.

#### B. Audio (`.mp3`, `.wav`, `.ogg`, `.flac`)
* **In-App Streaming / Player**:
  * **Pilihan 1 — Python `miniaudio`**: Pustaka open-source berbasis satu file C yang sangat ringan. Dapat mendekode audio langsung dari `bytes` di RAM dan memutarnya ke output audio sistem tanpa subprocess eksternal.
  * **Pilihan 2 — [`mpv`](https://mpv.io)**: Headless CLI media player open-source paling tangguh dan lintas platform. Dipanggil dengan argumen:
    ```bash
    mpv --no-video --no-terminal --input-ipc-server=/tmp/peerc-mpv.sock -
    ```
    Audio bytes di-stream langsung ke `stdin`. Status playback (durasi, progress, volume) dapat dipantau dan dikontrol melalui IPC socket.
* **UI di `peerc`**: Mini-player widget di bar transfer/status yang menampilkan progress bar durasi dan tombol Play/Pause/Stop.

#### C. Video (`.mp4`, `.mkv`, `.webm`)
* **Thumbnail / Preview Frame**: Ekstraksi frame pertama di memori untuk ditampilkan sebagai poster gambar di terminal.
* **Playback**:
  * Membuka subprocess `mpv -` (streaming dari `stdin`). User mendapatkan hardware-accelerated playback tanpa meninggalkan file fisik di disk.

---

### Kategori 3: Document (`.pdf`, `.epub`, `.docx`, `.xlsx`)

Membaca isi dokumen tanpa memerlukan software office desktop berat.

#### A. PDF & EPUB (`.pdf`, `.epub`, `.xps`)
* **Engine Rekomendasi Utama: [`PyMuPDF`](https://github.com/pymupdf/PyMuPDF) (MuPDF / `fitz`)**:
  * Sangat cepat, open-source (AGPL/Commercial), ditulis dalam C dengan binding Python matang.
  * **Mendukung in-memory loading murni**:
    ```python
    doc = fitz.open(stream=decrypted_bytes, filetype="pdf")
    ```
  * **Dual-Mode Rendering**:
    1. **Mode A — Text & Layout Mode**:
       Mengekstrak teks halaman terformat (`page.get_text("markdown")` atau `page.get_text("text")`). Teks dimasukkan ke dalam Textual reader lengkap dengan nomor halaman dan navigasi bab. Sangat hemat bandwidth dan ringan.
    2. **Mode B — Visual Page Rendering**:
       Merender halaman ke raster pixmap in-memory (`page.get_pixmap()`), menghasilkan PNG bytes yang langsung diteruskan ke Engine Image (Chafa / Half-blocks) untuk menampilkan diagram, tabel, dan layout asli PDF.
* **External TUI/CLI Reader**:
  * [`zathura`](https://pwmt.org/projects/zathura/) (PDF viewer minimalis berbasis keyboard) atau `pdftotext`.

#### B. Spreadsheet & Office (`.xlsx`, `.docx`)
* **Spreadsheet (`.xlsx`, `.csv`)**:
  * **In-App**: `openpyxl` membaca stream dari memory -> di-render ke Textual `DataTable`.
  * **Power Tool**: [`VisiData`](https://www.visidata.org/) — TUI spreadsheet serbaguna open-source Python.
* **Word Document (`.docx`)**:
  * Ekstraksi paragraf dan heading via `python-docx` -> ditampilkan sebagai Markdown di Textual viewer.

---

## 3. Arsitektur Komponen & API Dispatcher

Modul viewer direncanakan berada di `core/viewer/` dengan arsitektur extensibilitas berbasis MIME-type:

```
core/viewer/
├── __init__.py
├── dispatcher.py       # Menentukan viewer berdasarkan ekstensi / magic bytes
├── protocol.py         # Base interface: BaseFileViewer
├── text_viewer.py      # Rich Syntax, Markdown, Textual DataTable
├── image_viewer.py     # Pillow, Chafa, ANSI half-block canvas
├── audio_player.py     # In-memory miniaudio & mpv subprocess controller
└── doc_viewer.py       # PyMuPDF text/pixmap extraction
```

### Interface `BaseFileViewer`

```python
from abc import ABC, abstractmethod
from typing import Optional
from textual.widget import Widget

class BaseFileViewer(ABC):
    @abstractmethod
    def can_handle(self, mime_type: str, filename: str) -> bool:
        """Cek apakah viewer ini dapat menangani format file tersebut."""
        pass

    @abstractmethod
    def render_in_app(self, data: bytes, filename: str) -> Widget:
        """Buat widget Textual yang siap di-mount ke layar modal/screen."""
        pass

    @abstractmethod
    async def open_external(self, data: bytes, filename: str) -> None:
        """Stream data ke tool eksternal via stdin pipe tanpa menulis file ke disk."""
        pass
```

---

## 4. Keamanan & Mitigasi Cache (Alinyemen dengan Phase 39)

| Skenario | Risiko | Solusi di `peerc` |
|:---|:---|:---|
| **In-App Preview** | Data tersimpan di swap/disk | `bytes` disimpan murni di heap memory. Saat modal ditutup, referensi dihapus (`del data`) dan garbage collection dipanggil. Disk I/O = **0 bytes**. |
| **External CLI (`bat`, `chafa`, `mpv`)** | File sementara bocor di `/tmp` | Menggunakan **anonymous pipe (`stdin`)**: subprocess membaca dari `sys.stdin` `peerc`. Tidak ada path file di filesystem. |
| **External App yang Memaksa Path File** | File tersimpan di recent items/disk | Jika user memaksa membuka dengan OS default GUI (misal Adobe Reader / MS Word):<br>1. Berikan **Security Warning Modal** menjelaskan risiko cache.<br>2. Tulis ke volatile RAM disk (`/dev/shm` di Linux) atau secure temporary file dengan atribut tersembunyi.<br>3. Monitor PID proses eksternal; begitu jendela ditutup, lakukan overwrite/shred dan hapus file segera. |

---

## 5. UI/UX Interaction di Terminal

1. **Akses dari Tab File**:
   - Di daftar file bersama per-peer (atau Secure Vault):
     - Tekan `Enter` atau `Space` pada file item -> Membuka `FileViewerModal`.
     - Klik tombol `[Preview]` dengan mouse.
2. **Navigasi di dalam Viewer**:
   - `Esc` atau `q`: Tutup viewer dan kembali ke tab file / chat.
   - `j` / `k` / `Scroll Wheel`: Scroll konten.
   - `n` / `p` (pada Dokumen/PDF): Halaman berikutnya / sebelumnya.
   - `Space`: Toggle Play/Pause untuk audio.
   - `Ctrl+O`: Opsi buka dengan external tool via safe pipe.
3. **Responsive Breakpoint Layout**:
   - Menyesuaikan dengan breakpoint hybrid (§40 di `DESIGN.md`):
     - Ukuran < 100 cols: Viewer ditampilkan full-screen overlay.
     - Ukuran ≥ 120 cols: Viewer dapat dibuka split di samping chat panel.

---

## 6. Rencana Integrasi & Roadmap

Integrasi ini dipetakan ke dalam Roadmap proyek:
* **Fase A (Built-in Text & Code)**: Menggunakan stack Rich/Textual yang sudah ada. Zero external dependency.
* **Fase B (Image & Document Preview)**: Menambahkan modul `pymupdf` dan `pillow`/`chafa` sebagai extra package `peerc[viewer]`.
* **Fase C (Streaming Audio & External Pipe Controller)**: Integrasi kontroler `mpv` dan `miniaudio`.

---

## 7. Pertimbangan Mobile & Headless (Mengapa Wajib TUI-First)

Mengapa tidak membuat jendela pop-up GUI / desktop window terpisah?

1. **Kendala Permission & Arsitektur di Android (Termux)**:
   - Di Android/Termux, tidak terdapat display server (X11/Wayland/Win32) secara native.
   - Memunculkan window GUI di mobile membutuhkan dependensi rumit seperti Termux-X11, VNC server, atau Android overlay permission (`SYSTEM_ALERT_WINDOW`). Ini sangat merusak kemudahan penggunaan (*user friction* tinggi).
2. **Sesi SSH & Headless Server**:
   - Jika user menjalankan `peerc` melalui remote SSH di server atau Raspberry Pi, window GUI tidak dapat dibuka tanpa X11/Wayland forwarding.
3. **Touch Friendly di HP**:
   - Terminal emulator modern di Android (Termux, JuiceSSH) secara otomatis menerjemahkan gestur jari menjadi mouse click dan scroll events.
   - Textual memiliki dukungan mouse native: tombol `[Tutup]`, `[Next Page]`, dan scrollbar di TUI dapat langsung di-tap dan digeser menggunakan jari di layar HP.
4. **Keamanan Tanpa Kompromi**:
   - Window eksternal hampir selalu membutuhkan file fisik di storage agar proses lain dapat membaca kontennya.
   - Full TUI menjamin seluruh data terdekripsi **100% berada di RAM**, tidak membutuhkan disk I/O, dan hilang seketika saat viewer ditutup.

Oleh karena itu, **arsitektur viewer `peerc` ditetapkan 100% TUI-First** di dalam terminal yang sama.
