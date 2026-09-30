"""
Implementasi Playfair Cipher
Tugas 1 Mata Kuliah Kriptografi
Program Studi Informatika, Universitas Siliwangi
"""

from typing import List, Tuple, Dict, Any

GROUP_NAME = "Kriptografi"
GROUP_MEMBERS = [
    ("Arya Achmad Caesar", "237006093"),
    ("Andi Rafiyan", "237006074"),
]


def build_playfair_matrix(key: str, omit_j: bool = True) -> List[List[str]]:
    """
    Membangun matriks Playfair 5x5 dari kata kunci.
    
    Aturan:
    - Berdasarkan slide materi perkuliahan (Slide 3-Kriptografi Klasik (2) hal. 37):
      Huruf J dibuang dari kunci dan alfabet.
    - Jika omit_j=True: Huruf J pada kunci diabaikan.
    - Jika omit_j=False: Huruf J pada kunci diubah menjadi I.
    - Huruf berulang pada kunci dibuang (hanya kemunculan pertama yang dipakai).
    - Sisa sel diisi dengan huruf alfabet A-Z (tanpa J) yang belum terpakai secara berurutan.
    """
    key_upper = key.upper()
    used_chars = set()
    matrix_chars: List[str] = []

    if omit_j:
        used_chars.add('J')
    else:
        key_upper = key_upper.replace('J', 'I')

    # Masukkan huruf dari kunci
    for ch in key_upper:
        if 'A' <= ch <= 'Z' and ch not in used_chars:
            if omit_j and ch == 'J':
                continue
            used_chars.add(ch)
            matrix_chars.append(ch)

    # Isi sisa sel dari alfabet standar A-Z (tanpa J)
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for ch in alphabet:
        if ch not in used_chars:
            used_chars.add(ch)
            matrix_chars.append(ch)

    # Bentuk matriks 5x5
    return [matrix_chars[i * 5:(i + 1) * 5] for i in range(5)]


def format_matrix_display(matrix: List[List[str]]) -> str:
    """Mengembalikan representasi string rapi dari matriks 5x5."""
    lines = []
    lines.append("    +---+---+---+---+---+")
    for row in matrix:
        lines.append("    | " + " | ".join(row) + " |")
        lines.append("    +---+---+---+---+---+")
    return "\n".join(lines)


def get_char_positions(matrix: List[List[str]]) -> Dict[str, Tuple[int, int]]:
    """Memetakan setiap karakter ke koordinat (baris, kolom) pada matriks."""
    pos = {}
    for r in range(5):
        for c in range(5):
            pos[matrix[r][c]] = (r, c)
    return pos


def prepare_playfair_text(text: str) -> List[Tuple[str, str]]:
    """
    Normalisasi plaintext sesuai kaidah Playfair Cipher (Slide hal. 38):
    1. Huruf kapital, hilangkan spasi dan tanda baca non-alfabet.
    2. Ganti huruf J dengan I.
    3. Tulis pesan dalam pasangan huruf (bigram).
    4. Jika terdapat pasangan huruf yang sama (kembar), sisipkan huruf pemisah:
       - Umumnya disisipkan 'X'.
       - Jika huruf kembar adalah 'X', disisipkan 'Z' untuk mencegah duplikasi X.
    5. Jika panjang huruf ganjil sehingga huruf terakhir sendirian:
       - Tambahkan padding 'X' di akhir.
       - Jika huruf terakhir adalah 'X', tambahkan padding 'Z'.
    """
    clean_text = [ch for ch in text.upper().replace('J', 'I') if 'A' <= ch <= 'Z']
    bigrams: List[Tuple[str, str]] = []
    
    i = 0
    while i < len(clean_text):
        c1 = clean_text[i]
        if i + 1 < len(clean_text):
            c2 = clean_text[i + 1]
            if c1 == c2:
                # Huruf kembar pada pasangan: sisipkan pemisah
                separator = 'Z' if c1 == 'X' else 'X'
                bigrams.append((c1, separator))
                i += 1  # c2 belum dipakai, akan diproses pada iterasi berikutnya
            else:
                bigrams.append((c1, c2))
                i += 2
        else:
            # Karakter terakhir sendirian (panjang ganjil): tambahkan padding
            pad = 'Z' if c1 == 'X' else 'X'
            bigrams.append((c1, pad))
            i += 1

    return bigrams


def encrypt_bigram(c1: str, c2: str, matrix: List[List[str]], pos: Dict[str, Tuple[int, int]]) -> Tuple[str, str, str]:
    """
    Enkripsi satu pasangan huruf (bigram) berdasarkan 3 aturan Playfair:
    1. Satu baris: geser ke kanan secara siklik (mod 5).
    2. Satu kolom: geser ke bawah secara siklik (mod 5).
    3. Persegi panjang: tukar kolom (baris tetap, kolom bertukar).
    """
    r1, c1_col = pos[c1]
    r2, c2_col = pos[c2]

    if r1 == r2:
        # Aturan 1: Baris yang sama -> geser kanan
        rule = "Baris Sama (geser kanan)"
        enc_c1 = matrix[r1][(c1_col + 1) % 5]
        enc_c2 = matrix[r2][(c2_col + 1) % 5]
    elif c1_col == c2_col:
        # Aturan 2: Kolom yang sama -> geser bawah
        rule = "Kolom Sama (geser bawah)"
        enc_c1 = matrix[(r1 + 1) % 5][c1_col]
        enc_c2 = matrix[(r2 + 1) % 5][c2_col]
    else:
        # Aturan 3: Persegi panjang -> tukar kolom
        rule = "Persegi Panjang (tukar kolom)"
        enc_c1 = matrix[r1][c2_col]
        enc_c2 = matrix[r2][c1_col]

    return enc_c1, enc_c2, rule


def decrypt_bigram(c1: str, c2: str, matrix: List[List[str]], pos: Dict[str, Tuple[int, int]]) -> Tuple[str, str, str]:
    """
    Dekripsi satu pasangan ciphertext (kebalikan dari aturan enkripsi):
    1. Satu baris: geser ke kiri secara siklik ((col - 1) % 5).
    2. Satu kolom: geser ke atas secara siklik ((row - 1) % 5).
    3. Persegi panjang: tukar kolom (baris tetap, kolom bertukar).
    """
    r1, c1_col = pos[c1]
    r2, c2_col = pos[c2]

    if r1 == r2:
        # Aturan 1: Baris yang sama -> geser kiri
        rule = "Baris Sama (geser kiri)"
        dec_c1 = matrix[r1][(c1_col - 1) % 5]
        dec_c2 = matrix[r2][(c2_col - 1) % 5]
    elif c1_col == c2_col:
        # Aturan 2: Kolom yang sama -> geser atas
        rule = "Kolom Sama (geser atas)"
        dec_c1 = matrix[(r1 - 1) % 5][c1_col]
        dec_c2 = matrix[(r2 - 1) % 5][c2_col]
    else:
        # Aturan 3: Persegi panjang -> tukar kolom
        rule = "Persegi Panjang (tukar kolom)"
        dec_c1 = matrix[r1][c2_col]
        dec_c2 = matrix[r2][c1_col]

    return dec_c1, dec_c2, rule


def playfair_encrypt(plaintext: str, key: str, omit_j: bool = True) -> Dict[str, Any]:
    """Menjalankan proses enkripsi Playfair secara utuh dan mengembalikan detail komputasi."""
    matrix = build_playfair_matrix(key, omit_j=omit_j)
    pos = get_char_positions(matrix)
    bigrams = prepare_playfair_text(plaintext)
    
    cipher_bigrams = []
    steps = []
    
    for c1, c2 in bigrams:
        enc1, enc2, rule = encrypt_bigram(c1, c2, matrix, pos)
        cipher_bigrams.append((enc1, enc2))
        steps.append({
            "plain_pair": c1 + c2,
            "pos1": pos[c1],
            "pos2": pos[c2],
            "rule": rule,
            "cipher_pair": enc1 + enc2
        })

    ciphertext = "".join(c1 + c2 for c1, c2 in cipher_bigrams)
    processed_plain = "".join(c1 + c2 for c1, c2 in bigrams)

    return {
        "plaintext_asli": plaintext,
        "processed_plain": processed_plain,
        "key": key,
        "matrix": matrix,
        "bigrams": bigrams,
        "cipher_bigrams": cipher_bigrams,
        "steps": steps,
        "ciphertext": ciphertext
    }


def playfair_decrypt(ciphertext: str, key: str, omit_j: bool = True) -> Dict[str, Any]:
    """Menjalankan proses dekripsi Playfair secara utuh."""
    matrix = build_playfair_matrix(key, omit_j=omit_j)
    pos = get_char_positions(matrix)
    clean_cipher = list(ciphertext.upper())
    if any(ch not in 'ABCDEFGHIKLMNOPQRSTUVWXYZ' for ch in clean_cipher):
        raise ValueError("Ciphertext Playfair harus berisi huruf A-Z tanpa J.")
    if len(clean_cipher) % 2:
        raise ValueError("Panjang ciphertext Playfair harus genap.")
    
    cipher_bigrams = []
    for i in range(0, len(clean_cipher), 2):
        if i + 1 < len(clean_cipher):
            cipher_bigrams.append((clean_cipher[i], clean_cipher[i + 1]))
            
    dec_bigrams = []
    steps = []
    
    for c1, c2 in cipher_bigrams:
        dec1, dec2, rule = decrypt_bigram(c1, c2, matrix, pos)
        dec_bigrams.append((dec1, dec2))
        steps.append({
            "cipher_pair": c1 + c2,
            "pos1": pos[c1],
            "pos2": pos[c2],
            "rule": rule,
            "plain_pair": dec1 + dec2
        })

    raw_decrypted = "".join(c1 + c2 for c1, c2 in dec_bigrams)
    return {
        "ciphertext": ciphertext,
        "key": key,
        "matrix": matrix,
        "cipher_bigrams": cipher_bigrams,
        "dec_bigrams": dec_bigrams,
        "steps": steps,
        "raw_decrypted": raw_decrypted
    }


def run_single_demo(title: str, plaintext: str, key: str, omit_j: bool = True):
    """Mencetak demo pengujian lengkap untuk satu skenario uji."""
    print("=" * 70)
    print(f" DEMO: {title}")
    print("=" * 70)
    print(f"Plaintext Asli      : {plaintext}")
    print(f"Kunci               : {key}")
    print(f"Kebijakan Huruf J   : {'Dibuang dari kunci/alfabet (Slide 37)' if omit_j else 'Diubah jadi I'}")
    
    # 1. Enkripsi
    enc_res = playfair_encrypt(plaintext, key, omit_j=omit_j)
    matrix = enc_res["matrix"]
    bigrams = enc_res["bigrams"]
    ciphertext = enc_res["ciphertext"]
    processed_plain = enc_res["processed_plain"]
    
    print("\nMatriks Kunci 5x5:")
    print(format_matrix_display(matrix))
    
    print(f"\nPlaintext Terproses : {processed_plain}")
    print(f"Bentuk Bigram       : {' '.join(c1 + c2 for c1, c2 in bigrams)}")
    
    print("\nRincian Langkah Enkripsi:")
    print(f"  {'No':<3} | {'Bigram':<8} | {'Posisi Matriks':<18} | {'Aturan':<30} | {'Cipher'}")
    print("  " + "-" * 68)
    for idx, s in enumerate(enc_res["steps"], start=1):
        pos_str = f"({s['pos1'][0]},{s['pos1'][1]}) & ({s['pos2'][0]},{s['pos2'][1]})"
        print(f"  {idx:<3} | {s['plain_pair']:<8} | {pos_str:<18} | {s['rule']:<30} | {s['cipher_pair']}")
        
    print(f"\nCiphertext Hasil    : {ciphertext}")
    print(f"Ciphertext (Bigram) : {' '.join(c1 + c2 for c1, c2 in enc_res['cipher_bigrams'])}")
    
    # 2. Dekripsi
    dec_res = playfair_decrypt(ciphertext, key, omit_j=omit_j)
    raw_dec = dec_res["raw_decrypted"]
    print(f"\nHasil Dekripsi Mentah: {raw_dec}")
    
    # Evaluasi kecocokan
    match = (raw_dec == processed_plain)
    assert match, "Dekripsi Playfair tidak sesuai plaintext terproses."
    print(f"Kecocokan dg Plaintext Terproses: {'COCOK (100% IDENTIK)' if match else 'TIDAK COCOK'}")
    
    # Penjelasan padding dan rekonstruksi
    if raw_dec != plaintext.upper().replace(' ', ''):
        print("Catatan Pemulihan:")
        print(f"  Teks asli sebelum padding : {plaintext.upper().replace(' ', '')}")
        print(f"  Teks dekripsi mentah       : {raw_dec}")
        diff = []
        if len(raw_dec) > len(plaintext.upper().replace(' ', '')):
            pad_count = len(raw_dec) - len(plaintext.upper().replace(' ', ''))
            print(f"  Terdeteksi penambahan {pad_count} karakter pemisah/padding (X/Z).")
            print("  Sesuai kaidah Playfair, padding akhir dilepas berdasarkan konteks makna.")
    print()


def main():
    print("#" * 70)
    print(f"# PROGRAM IMPLEMENTASI PLAYFAIR CIPHER")
    print(f"# Kelompok : {GROUP_NAME}")
    for name, npm in GROUP_MEMBERS:
        print(f"# Anggota  : {name} ({npm})")
    print("#" * 70)
    print()

    # Skenario 1: Demo Utama Kelompok (Plaintext STREAMING, Kunci BAGUS)
    run_single_demo(
        title="UJI 1 — STREAMING dengan Kunci BAGUS (Demo Utama Kelompok)",
        plaintext="STREAMING",
        key="BAGUS",
        omit_j=True
    )

    # Skenario 2: Demo Contoh Materi Perkuliahan (Slide 3-Kriptografi Klasik (2) hal. 37-44)
    run_single_demo(
        title="UJI 2 — Contoh Materi Kuliah (Slide 37-44)",
        plaintext="temui ibu nanti malam",
        key="JALAN GANESHA SEPULUH",
        omit_j=True
    )

    # Skenario 3: Kasus Huruf Berulang, Karakter Ganjil, Huruf J dan X
    run_single_demo(
        title="UJI 3 — Uji Huruf Kembar ('II'), Huruf 'J', Huruf 'X', dan Ganjil",
        plaintext="JALAN MAJU XX MENUJU TITIK",
        key="KRIPTOGRAFI",
        omit_j=True
    )


if __name__ == "__main__":
    main()
