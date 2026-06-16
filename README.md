
=====================================================================
 1. PERSIAPAN LINGKUNGAN & PUSTAKA
=====================================================================
cd ~/Downloads && rm -rf solve.py README.md .gitignore .git 2>/dev/null
pip3 install pycryptodome --user --break-system-packages
=====================================================================
 2. MEMBUAT FILE OTOMASI PEMECAH SANDI (solve.py)
=====================================================================
cat << 'EOF' > solve.py
#!/usr/bin/env python3
import ast
import binascii
from Crypto.Cipher import AES

# 1. MEMBACA DATA LANGSUNG DARI FILE OUTPUT.TXT
state_raw = None
taps_raw = None
ciphertext_hex = None

with open("output.txt", "r") as f:
    lines = f.readlines()
    for i, line in enumerate(lines):
        if "LFSR Initial State:" in line:
            # Mengambil baris berikutnya yang berisi list STATE
            state_raw = lines[i+1].strip()
        elif "LFSR Taps:" in line:
            # Mengambil baris berikutnya yang berisi list TAPS
            taps_raw = lines[i+1].strip()
        elif "Encrypted Flag:" in line:
            # Mengambil baris berikutnya yang berisi CIPHERTEXT
            ciphertext_hex = lines[i+1].strip()

# Konversi string teks dari file menjadi tipe data List dan String asli Python
STATE = ast.literal_eval(state_raw)
TAPS = ast.literal_eval(taps_raw)
CIPHERTEXT_HEX = ciphertext_hex

# 2. LOGIKA GENERATOR LFSR
def lfsr_next_bit(state, taps):
    feedback = 0
    for tap in taps:
        feedback ^= state[tap]
    output_bit = state[0]
    new_state = state[1:] + [feedback]
    return output_bit, new_state

# 3. REKONSTRUKSI KUNCI AES-128
key_bits = []
current_state = STATE.copy()

for _ in range(128):
    bit, current_state = lfsr_next_bit(current_state, TAPS)
    key_bits.append(bit)

key_string = "".join(map(str, key_bits))
key_bytes = int(key_string, 2).to_bytes(16, byteorder='big')

# 4. PROSES DEKRIPSI AES
ciphertext = binascii.unhexlify(CIPHERTEXT_HEX)

try:
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    print(decrypted.decode('utf-8', errors='ignore').strip())
except Exception as e:
    print("Gagal melakukan dekripsi:", e)
EOF
chmod +x solve.py

# =====================================================================
# 3. MEMBUAT FILE FILTER SAMPAH GIT (.gitignore)
# =====================================================================
cat << 'EOF' > .gitignore
__pycache__/
*.pyc
.DS_Store
.venv/
EOF

# =====================================================================
# 4. MEMBUAT LAPORAN UTAMA DENGAN STYLE TEKS PROPORSIONAL (README.md)
# =====================================================================
cat << 'EOF' > README.md
### Laporan Teknis Kriptografi: Analisis dan Penyelesaian Cryptomaze

Dokumen ini memuat laporan teknis mengenai metodologi pembalikan enkripsi pada tantangan **cryptomaze**. Solusi dikembangkan menggunakan bahasa pemrograman Python 3 dengan merekonstruksi aliran bit *Linear Feedback Shift Register* (LFSR) untuk memulihkan kunci simetris pada cipher blok *Advanced Encryption Standard* (AES-128) dengan modus operasi *Electronic Codebook* (ECB).

---

#### 1. Parameter Masukan Sistem
Berkas instrumen `solve.py` dirancang untuk melakukan pembacaan data secara dinamis dari log `output.txt`. Ringkasan parameter matematis yang digunakan dalam perhitungan adalah sebagai berikut:

| Nama Parameter | Deskripsi Teknis |
| :--- | :--- |
| **LFSR Initial State** | Kondisi awal (*seed*) register geser internal sepanjang 64-bit. |
| **LFSR Taps Index** | Posisi bit (`63, 61, 60, 58`) yang diekstraksi untuk operasi umpan balik. |
| **Encrypted Flag** | Data sandi (*ciphertext*) heksadesimal dengan panjang total 48 byte. |

---

#### 2. Metodologi Perhitungan dan Alur Solusi

> **Siklus Generator LFSR** > Fungsi internal mensimulasikan pergeseran bit secara berurutan. Pada setiap detak, bit-bit pada indeks pengetukan (*taps*) dihitung menggunakan operasi logika XOR ($\oplus$). Hasil operasi tersebut bertindak sebagai bit umpan balik (*feedback bit*) yang dimasukkan ke ujung kanan register, sedangkan bit pertama (`state[0]`) dikeluarkan sebagai *output stream*.

> **Rekonstruksi Kunci Simetris** > Mengingat arsitektur AES-128 membutuhkan fondasi kunci sepanjang 16 byte (128-bit), perulangan generator LFSR dijalankan secara konsisten sebanyak tepat 128 siklus. Runtunan bit biner yang terkumpul kemudian dikonversi ke dalam representasi data *raw bytes*.

> **Dekripsi Blok Cipher** > Setelah array byte kunci berhasil dipulihkan, *ciphertext* dieksekusi menggunakan fungsi dekriptor AES modus ECB. Teks sandi dibalikkan secara utuh ke bentuk string teks biasa (*plaintext*).

---

#### 3. Implementasi Kode Program (`solve.py`)
Berikut adalah implementasi kode otomasi pemecahan sandi yang digunakan:

```python
#!/usr/bin/env python3
import ast
import binascii
from Crypto.Cipher import AES

# 1. Pembacaan komponen log secara dinamis
state_raw, taps_raw, ciphertext_hex = None, None, None
with open("output.txt", "r") as f:
    lines = f.readlines()
    for i, line in enumerate(lines):
        if "LFSR Initial State:" in line:
            state_raw = lines[i+1].strip()
        elif "LFSR Taps:" in line:
            taps_raw = lines[i+1].strip()
        elif "Encrypted Flag:" in line:
            ciphertext_hex = lines[i+1].strip()

STATE = ast.literal_eval(state_raw)
TAPS = ast.literal_eval(taps_raw)
CIPHERTEXT_HEX = ciphertext_hex

# 2. Logika pergeseran bit LFSR
def lfsr_next_bit(state, taps):
    feedback = 0
    for tap in taps:
        feedback ^= state[tap]
    output_bit = state[0]
    new_state = state[1:] + [feedback]
    return output_bit, new_state

# 3. Pengumpulan 128-bit stream kunci
key_bits = []
current_state = STATE.copy()
for _ in range(128):
    bit, current_state = lfsr_next_bit(current_state, TAPS)
    key_bits.append(bit)

key_string = "".join(map(str, key_bits))
key_bytes = int(key_string, 2).to_bytes(16, byteorder='big')

# 4. Operasi balik cipher AES-ECB
ciphertext = binascii.unhexlify(CIPHERTEXT_HEX)
try:
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    print(decrypted.decode('utf-8', errors='ignore').strip())
except Exception as e:
    print("Kegagalan dekripsi:", e)

```

---

#### 4. Validasi Hasil Akhir (Flag)

Eksekusi instrumen pemecahan sandi di lingkungan Kali Linux berhasil memulihkan string data rahasia secara presisi:

```text
picoCTF{scr8mbledt_flvg_42186d25}

```

#### 5. Bukti Eksekusi Sistem (Screenshot)

Berikut adalah lampiran tangkapan layar sebagai validasi bahwa skrip telah berhasil berjalan dengan sukses di terminal lokal:

---

*Laporan Analisis Teknis Keamanan Informasi — Analis: kumosora_*
EOF

# =====================================================================

# 5. SELESAI

# =====================================================================

echo ""
echo "====================================================================="
echo "[+] PROSES INJEK DATA BERHASIL!"
echo "[+] Berkas 'solve.py', '.gitignore', dan 'README.md' selesai diperbarui."
echo "[+] Flag resmi 'picoCTF{scr8mbledt_flvg_42186d25}' telah dikunci di dalam laporan."
echo "====================================================================="
<img width="982" height="216" alt="image" src="https://github.com/user-attachments/assets/d5b974bc-47ef-4574-9c66-13971117e747" />

```

### Langkah Terakhir Anda di Git GUI/Desktop:
1. Pastikan file gambar terminal Anda ditaruh di folder ini dengan nama **`screenshot.png`**.
2. Buka aplikasi Git GUI Anda kembali. Berkas `solve.py`, `.gitignore`, `README.md`, dan `screenshot.png` akan otomatis terdeteksi dengan format barunya.
3. Masukkan semuanya ke *Staged Files*, lakukan **Commit**, dan klik **Push** ke GitHub. Portofolio profesional Anda kini sudah terunggah sempurna di internet!
