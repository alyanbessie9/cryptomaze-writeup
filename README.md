# Cryptomaze Writeup

## Deskripsi

Repositori ini berisi solusi untuk challenge **Cryptomaze** yang menggunakan kombinasi **Linear Feedback Shift Register (LFSR)** dan **AES-128 ECB**.

Tujuan challenge adalah merekonstruksi kunci AES dari output LFSR yang diberikan, kemudian mendekripsi ciphertext untuk memperoleh flag.

---

## Struktur File

```
.
├── output.txt      # Data challenge
├── solve.py        # Script solver
├── README.md
└── .gitignore
```

---

## Metodologi

### 1. Analisis Data

File `output.txt` menyediakan tiga komponen utama:

- **LFSR Initial State** → kondisi awal register
- **LFSR Taps** → posisi feedback bit
- **Encrypted Flag** → ciphertext dalam format hexadecimal

### 2. Rekonstruksi Kunci

Script menjalankan simulasi LFSR sebanyak **128 siklus** untuk menghasilkan stream bit yang digunakan sebagai:

- AES Key (128-bit)
- Konversi bit stream → 16 byte

### 3. Dekripsi AES

Setelah kunci diperoleh, ciphertext didekripsi menggunakan:

- Algoritma: AES-128
- Mode: ECB

---

## Instalasi

Install dependency:

```bash
pip3 install pycryptodome --user --break-system-packages
```

---

## Menjalankan Solver

Pastikan file `output.txt` berada pada direktori yang sama dengan `solve.py`.

```bash
python3 solve.py
```

---

## Hasil

Flag berhasil dipulihkan:

```text
picoCTF{scr8mbledt_flvg_42186d25}
```

---

## Bukti Eksekusi

<img width="982" height="216" alt="image" src="https://github.com/user-attachments/assets/d5b974bc-47ef-4574-9c66-13971117e747" />

---

## Teknologi

- Python 3
- PyCryptodome
- AES-128 ECB
- LFSR Analysis

---

## Catatan

Proyek ini dibuat untuk tujuan pembelajaran kriptografi dan dokumentasi penyelesaian challenge CTF.
