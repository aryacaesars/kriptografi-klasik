"""Hill Cipher 2x2, tanpa library tambahan.

A=0 sampai Z=25. Setiap pasangan huruf adalah vektor kolom: C = K * P mod 26.
Plaintext dinormalisasi menjadi huruf ASCII kapital saja (spasi dihapus).
Tambahkan X bila panjangnya ganjil. Dekripsi mempertahankan padding karena
huruf X asli tidak bisa dibedakan dari padding tanpa informasi tambahan.
"""

from math import gcd


def normalize_plaintext(text):
    """Ambil huruf A-Z saja, lalu ubah menjadi kapital."""
    return ''.join(c.upper() for c in text if 'A' <= c <= 'Z' or 'a' <= c <= 'z')


def inverse_key(key):
    """Validasi matriks 2x2 dan hitung inversnya dalam modulo 26."""
    if (not isinstance(key, (list, tuple)) or len(key) != 2
            or any(not isinstance(row, (list, tuple)) or len(row) != 2 for row in key)
            or any(type(value) is not int for row in key for value in row)):
        raise ValueError("Kunci harus berupa matriks 2x2 berisi bilangan bulat.")

    (a, b), (c, d) = key
    determinant = a * d - b * c
    if gcd(determinant, 26) != 1:
        raise ValueError("Determinan kunci harus relatif prima terhadap 26.")
    inverse_determinant = pow(determinant, -1, 26)
    return [
        [(inverse_determinant * d) % 26, (-inverse_determinant * b) % 26],
        [(-inverse_determinant * c) % 26, (inverse_determinant * a) % 26],
    ]


def transform_blocks(text, matrix):
    """Kalikan tiap pasangan huruf kapital dengan matriks modulo 26."""
    result = []
    for index in range(0, len(text), 2):
        first = ord(text[index]) - ord('A')
        second = ord(text[index + 1]) - ord('A')
        for row in matrix:
            value = (row[0] * first + row[1] * second) % 26
            result.append(chr(value + ord('A')))
    return ''.join(result)


def encrypt_hill(plaintext, key):
    """Normalisasi, tambah padding jika perlu, kemudian enkripsi."""
    inverse_key(key)  # Tolak kunci yang tidak bisa didekripsi.
    prepared = normalize_plaintext(plaintext)
    if len(prepared) % 2:
        prepared += 'X'
    return transform_blocks(prepared, key)


def decrypt_hill(ciphertext, key):
    """Dekripsi ciphertext huruf saja; padding tetap dipertahankan."""
    matrix = inverse_key(key)
    if any(not ('A' <= c <= 'Z' or 'a' <= c <= 'z') for c in ciphertext):
        raise ValueError("Ciphertext harus berisi huruf A-Z saja.")
    if len(ciphertext) % 2:
        raise ValueError("Panjang ciphertext harus genap.")
    return transform_blocks(ciphertext.upper(), matrix)


def main():
    # Silakan ganti plaintext dan matriks kunci yang valid.
    plaintext = "STREAMING"
    key = [[3, 3], [2, 5]]
    normalized = normalize_plaintext(plaintext)
    padding_count = len(normalized) % 2
    prepared = normalized + 'X' * padding_count

    ciphertext = encrypt_hill(plaintext, key)
    decrypted = decrypt_hill(ciphertext, key)
    assert decrypted == prepared, "Dekripsi tidak sesuai plaintext dengan padding."
    # Panjang padding diketahui dari persiapan demo, bukan ditebak dari huruf X.
    recovered = decrypted[:-padding_count] if padding_count else decrypted

    print("\n=== HILL CIPHER 2x2 ===")
    print(f"Plaintext          : {plaintext}")
    print(f"Normalisasi        : {normalized}")
    print(f"Jumlah padding X   : {padding_count}")
    print(f"Plaintext diproses : {prepared}")
    print(f"Kunci              : {key}")
    print(f"Ciphertext         : {ciphertext}")
    print(f"Dekripsi mentah    : {decrypted}")
    print(f"Tanpa padding demo : {recovered}")
    print(f"Status             : {'SESUAI' if recovered == normalized else 'TIDAK SESUAI'}")


if __name__ == "__main__":
    main()
