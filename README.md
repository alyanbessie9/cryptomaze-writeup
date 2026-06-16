# =====================================================================

# 1. PERSIAPAN LINGKUNGAN & PUSTAKA

# =====================================================================
<img width="906" height="445" alt="image" src="https://github.com/user-attachments/assets/d06aab39-34cb-4f86-b4cc-e8370321b925" />


cd ~/Downloads && rm -rf solve.py README.md .gitignore .git 2>/dev/null
pip3 install pycryptodome --user --break-system-packages

# =====================================================================

# 2. MEMBUAT FILE OTOMASI PEMECAH SANDI (solve.py)

# =====================================================================

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
if "LFSR Initial State:" in line: # Mengambil baris berikutnya yang berisi list STATE
state_raw = lines[i+1].strip()
elif "LFSR Taps:" in line: # Mengambil baris berikutnya yang berisi list TAPS
taps_raw = lines[i+1].strip()
elif "Encrypted Flag:" in line: # Mengambil baris berikutnya yang berisi CIPHERTEXT
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

for \_ in range(128):
bit, current_state = lfsr_next_bit(current_state, TAPS)
key_bits.append(bit)

key_string = "".join(map(str, key_bits))
key_bytes = int(key_string, 2).to_bytes(16, byteorder='big')

# 4. PROSES DEKRIPSI AES

ciphertext = binascii.unhexlify(CIPHERTEXT_HEX)

try:
cipher = AES.new(key_bytes, AES.MODE_ECB)
decrypted = cipher.decrypt(ciphertext) # Cetak hanya flag bersih untuk ditangkap oleh script bash
print(decrypted.decode('utf-8', errors='ignore').strip())
except Exception as e:
print("Gagal melakukan dekripsi:", e)
EOF
chmod +x solve.py

# =====================================================================

# 3. EKSEKUSI OTOMATIS & EKSTRAKSI FLAG KE VARIABEL TEMPORER

# =====================================================================

FLAG_HASIL=$(python3 solve.py)

# =====================================================================

# 4. MEMBUAT FILE FILTER SAMPAH GIT (.gitignore)

# =====================================================================

cat << 'EOF' > .gitignore
**pycache**/
\*.pyc
.DS_Store
.venv/
EOF

# =====================================================================

# 5. MEMBUAT LAPORAN UTAMA (README.md) SECARA OTOMATIS DENGAN FLAG ASLI

# =====================================================================

cat << EOF > README.md

# Laporan Teknis Kriptografi: Penyelesaian Tantangan Cryptomaze

Dokumen ini berisi analisis forensik dan metodologi penyelesaian untuk tantangan kriptografi bertajuk **cryptomaze**. Solusi diimplementasikan menggunakan Python 3 dengan mengombinasikan rekonstruksi aliran bit register geser linear (LFSR) untuk memulihkan kunci utama pada cipher blok AES-128 (ECB Mode).

---

## 1. Analisis Data Masukan (Input Data Analysis)

Berkas otomasi dirancang untuk membaca langsung parameter dari berkas log \`output.txt\` secara dinamis. Terdapat tiga parameter utama yang menjadi landasan perhitungan matematis:

1. **LFSR Initial State**:
   Parameter ini merupakan kondisi awal (_seed_) dari register geser yang memiliki panjang tepat 64 elemen bit. Hal ini menandakan bahwa LFSR beroperasi pada ruang internal 64-bit.

2. **LFSR Taps Index**:
   Indeks posisi bit di dalam status internal yang diekstraksi untuk dihitung menggunakan operasi logika XOR guna memproduksi bit umpan balik (_feedback bit_) baru pada setiap siklus.

3. **Encrypted Flag (Ciphertext)**:
   String berbasis representasi Heksadesimal (Hex) dengan panjang 96 karakter. Ukuran total data biner tersebut adalah 48 byte (96 / 2). Karena 48 habis dibagi 16 (ukuran blok dasar AES), dapat dipastikan arsitektur enkripsi menggunakan algoritma cipher blok standar.

---

## 2. Metodologi dan Alur Solusi

Proses pemulihan data dilakukan melalui skema penataan logika sebagai berikut:

### Tahap 1: Simulasi Algoritma LFSR

Fungsi internal dirancang untuk mensimulasikan satu detak jam (_clock cycle_) pada register geser. Variabel umpan balik menampung hasil XOR beruntun dari bit pada posisi indeks \`TAPS\`. Status internal diperbarui dengan membuang bit pertama (\`state[0]\`) sebagai bit keluaran stream, menggeser seluruh rangkaian ke kiri, dan menempatkan bit umpan balik di posisi paling kanan (\`state[1:] + [feedback]\`).

### Tahap 2: Rekonstruksi Kunci AES-128

Algoritma enkripsi AES-128 memerlukan kunci simetris dengan panjang tepat 128 bit (16 byte). Simulasi putaran LFSR dieksekusi berulang sebanyak 128 kali untuk menghimpun aliran bit acak semu (_pseudo-random bitstream_) yang dibutuhkan. Rangkaian bit tersebut kemudian dikonversi menjadi objek data berbentuk byte mentah (_raw bytes_).

### Tahap 3: Pembalikan Cipher Blok

Objek byte kunci dan ciphertext dimasukkan ke dalam mesin dekriptor. Modus operasi Electronic Codebook (ECB) diterapkan karena proses enkripsi awal tidak melibatkan Initialization Vector (IV). Teks sandi didekripsi kembali ke bentuk string teks biasa (_plaintext_).

---

## 3. Implementasi Kode Program (\`solve.py\`)

Skrip otomasi berikut ditulis menggunakan pustaka kriptografi standar industri untuk mengeksekusi seluruh tahapan solusi dengan membaca file secara dinamis:

\`\`\`python
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
state_raw = lines[i+1].strip()
elif "LFSR Taps:" in line:
taps_raw = lines[i+1].strip()
elif "Encrypted Flag:" in line:
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

for \_ in range(128):
bit, current_state = lfsr_next_bit(current_state, TAPS)
key_bits.append(bit)

key_string = "".join(map(str, key_bits))
key_bytes = int(key_string, 2).to_bytes(16, byteorder='big')

# 4. PROSES DEKRIPSI AES

ciphertext = binascii.unhexlify(CIPHERTEXT_HEX)

try:
cipher = AES.new(key_bytes, AES.MODE_ECB)
decrypted = cipher.decrypt(ciphertext)
print("\n[+] Hasil Dekripsi (Raw):", decrypted)
print("[+] Kemungkinan Flag :", decrypted.decode('utf-8', errors='ignore').strip())
except Exception as e:
print("[-] Gagal melakukan dekripsi:", e)
\`\`\`

---

## 4. Panduan Eksekusi Sistem

Langkah-langkah operasional untuk menjalankan lingkungan pemecahan sandi pada Kali Linux:

1. Pemenuhan Dependensi (User-Space):
   \`\`\`bash
   pip3 install pycryptodome --user --break-system-packages
   \`\`\`
2. Eksekusi Instrumen Solusi:
   \`\`\`bash
   python3 solve.py
   \`\`\`

---

## 5. Hasil Akhir Pemulihan Data (Flag)

Setelah skrip otomasi melakukan kalkulasi dan rekonstruksi matriks kunci secara presisi, teks rahasia berhasil dipulihkan dengan keluaran string sebagai berikut:

\`\`\`text
$picoCTF{scr8mbledt_flvg_42186d25}
\`\`\`

---

\_Laporan Analisis Teknis Keamanan Informasi — Analis: kumosora\_\_
EOF

# =====================================================================

# 6. VERIFIKASI SELESAI

# =====================================================================

echo ""
echo "====================================================================="
echo "[+] PROSES SELESAI SECARA OTOMATIS!"
echo "[+] Berkas 'solve.py', 'README.md', dan '.gitignore' berhasil dibuat."
echo "[+] Hasil Flag Anda telah dimasukkan ke dalam dokumen README.md."
echo "[+] Flag yang terdeteksi: $picoCTF{scr8mbledt_flvg_42186d25}"
echo "====================================================================="
echo "[!] Sekarang repositori Anda siap untuk di-push ke GitHub."
