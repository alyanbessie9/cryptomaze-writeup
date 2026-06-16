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
    print("\n[+] Hasil Dekripsi (Raw):", decrypted)
    print("[+] Kemungkinan Flag   :", decrypted.decode('utf-8', errors='ignore').strip())
except Exception as e:
    print("[-] Gagal melakukan dekripsi:", e)