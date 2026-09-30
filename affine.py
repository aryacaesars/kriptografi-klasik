"""Demo Affine Cipher dengan A=0 sampai Z=25.

Huruf ASCII diproses sebagai kapital. Karakter lain dipertahankan.
Enkripsi: C = (a * P + b) mod 26.
Dekripsi: P = invers_a * (C - b) mod 26.
"""

from math import gcd



def affine(text, a, b, decrypt=False):
    """Transformasi Affine dengan dua parameter bilangan bulat."""
    if type(a) is not int or type(b) is not int:
        raise ValueError("Parameter a dan b harus bilangan bulat.")
    if gcd(a, 26) != 1:
        raise ValueError("Parameter a harus relatif prima terhadap 26, misalnya 5.")

    inverse_a = pow(a, -1, 26) if decrypt else None
    result = []
    for char in text:
        if 'A' <= char <= 'Z' or 'a' <= char <= 'z':
            value = ord(char.upper()) - ord('A')
            if decrypt:
                transformed = (inverse_a * (value - b)) % 26
            else:
                transformed = (a * value + b) % 26
            result.append(chr(transformed + ord('A')))
        else:
            result.append(char)
    return ''.join(result)


def encrypt_affine(plaintext, a, b):
    """Menghasilkan ciphertext dari plaintext dan parameter a, b."""
    return affine(plaintext, a, b)


def decrypt_affine(ciphertext, a, b):
    """Mengembalikan ciphertext dengan parameter a, b yang sama."""
    return affine(ciphertext, a, b, decrypt=True)


def main():
    # Parameter a dapat dipilih dari bilangan bulat yang relatif prima terhadap 26,
    # (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, atau 25).
    plaintext = "STREAMING"
    a = 17
    b = 9
    ciphertext = encrypt_affine(plaintext, a, b)
    decrypted = decrypt_affine(ciphertext, a, b)
    normalized = ''.join(c.upper() if 'a' <= c <= 'z' else c for c in plaintext)
    assert decrypted == normalized, "Hasil dekripsi tidak sesuai plaintext."

    print("\n=== AFFINE CIPHER ===")
    print(f"Plaintext      : {plaintext}")
    print(f"Kunci          : a = {a}, b = {b}")
    print(f"Ciphertext     : {ciphertext}")
    print(f"Hasil dekripsi : {decrypted}")
    print(f"Status         : {'SESUAI' if decrypted == normalized else 'TIDAK SESUAI'}")


if __name__ == "__main__":
    main()
