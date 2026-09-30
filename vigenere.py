"""Demo Vigenere Cipher
"""
GROUP_NAME = "Kriptografi"
GROUP_MEMBERS = [
    ("Arya Achmad Caesar", "237006093"),
    ("Andi Rafiyan", "237006074"),
]


def vigenere(text, key, decrypt=False):
    """Geser huruf dengan kunci berulang; kurangi untuk dekripsi."""
    if not key or any(not ('A' <= c <= 'Z' or 'a' <= c <= 'z') for c in key):
        raise ValueError("Kunci harus berisi huruf A-Z saja dan tidak boleh kosong.")

    key = key.upper()
    result = []
    key_index = 0
    direction = -1 if decrypt else 1

    for char in text:
        if 'A' <= char <= 'Z' or 'a' <= char <= 'z':
            value = ord(char.upper()) - ord('A')
            shift = ord(key[key_index % len(key)]) - ord('A')
            # Enkripsi: (P + K) mod 26; dekripsi: (C - K) mod 26.
            result.append(chr((value + direction * shift) % 26 + ord('A')))
            key_index += 1
        else:
            result.append(char)

    return ''.join(result)


def encrypt_vigenere(plaintext, key):
    """Menghasilkan ciphertext dari plaintext dan kunci."""
    return vigenere(plaintext, key)


def decrypt_vigenere(ciphertext, key):
    """Mengembalikan ciphertext menggunakan kunci yang sama."""
    return vigenere(ciphertext, key, decrypt=True)


def main():
    plaintext = "STREAMING"
    key = "BAGUS"
    ciphertext = encrypt_vigenere(plaintext, key)
    decrypted = decrypt_vigenere(ciphertext, key)

    normalized = ''.join(c.upper() if 'a' <= c <= 'z' else c for c in plaintext)
    assert decrypted == normalized, "Hasil dekripsi tidak sesuai plaintext."

    print(f"Kelompok: {GROUP_NAME}")
    for number, (name, nim) in enumerate(GROUP_MEMBERS, start=1):
        print(f"Anggota {number}: {name} - {nim}")

    print("\n=== VIGENERE CIPHER ===")
    print(f"Plaintext      : {plaintext}")
    print(f"Kunci          : {key}")
    print(f"Ciphertext     : {ciphertext}")
    print(f"Hasil dekripsi : {decrypted}")
    print(f"Status         : {'SESUAI' if decrypted == normalized else 'TIDAK SESUAI'}")


if __name__ == "__main__":
    main()
