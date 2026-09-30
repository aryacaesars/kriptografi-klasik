"""
Implementasi Simulasi Enigma Cipher (Model Enigma M3)
Tugas 1 Mata Kuliah Kriptografi
Program Studi Informatika, Universitas Siliwangi
"""

from typing import List, Tuple, Dict, Any, Optional

GROUP_NAME = "Kriptografi"
GROUP_MEMBERS = [
    ("Arya Achmad Caesar", "237006093"),
    ("Andi Rafiyan", "237006074"),
]


class EnigmaM3:
    """
    Simulasi Mesin Enigma M3 (Standar Wehrmacht / Kriegsmarine 3-Rotor).
    
    Fitur Komponen:
    1. 5 Pilihan Rotor Historis (I sampai V) dengan kabel substitusi dan turnover notch otentik.
    2. 2 Pilihan Reflektor Historis (UKW-B dan UKW-C).
    3. Papan Steker (Plugboard / Steckerbrett) untuk pertukaran pasangan huruf dua arah.
    4. Pengaturan Cincin (Ringstellung / Ring Setting) independen untuk tiap rotor.
    5. Posisi Awal Rotor (Grundstellung) yang terlihat pada jendela mesin.
    6. Mekanisme pergerakan rotor mekanik otentik termasuk anomali 'double-stepping' pada rotor tengah.
    7. Sifat simetris: enkripsi dan dekripsi menggunakan mesin dan konfigurasi awal yang identik.
    """

    # Spesifikasi kabel substitusi rotor (A-Z) dan posisi turnover notch
    # Sumber: https://www.cryptomuseum.com/crypto/enigma/wiring.htm
    ROTOR_DEFINITIONS = {
        'I':   {'wiring': 'EKMFLGDQVZNTOWYHXUSPAIBRCJ', 'notch': 'Q'},
        'II':  {'wiring': 'AJDKSIRUXBLHWTMCQGZNPYFVOE', 'notch': 'E'},
        'III': {'wiring': 'BDFHJLCPRTXVZNYEIWGAKMUSQO', 'notch': 'V'},
        'IV':  {'wiring': 'ESOVPZJAYQUIRHXLNFTGKDCMWB', 'notch': 'J'},
        'V':   {'wiring': 'VZBRGITYUPSDNHLXAWMJQOFECK', 'notch': 'Z'},
    }

    # Spesifikasi kabel reflektor (Umkehrwalze)
    REFLECTOR_DEFINITIONS = {
        'B': 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
        'C': 'FVPJIAOYEDRZXWGCTKUQSBNMHL',
    }

    def __init__(
        self,
        rotor_order: Tuple[str, str, str] = ('I', 'II', 'III'),
        reflector: str = 'B',
        init_positions: Tuple[str, str, str] = ('A', 'A', 'A'),
        ring_settings: Tuple[Any, Any, Any] = (1, 1, 1),
        plugboard_pairs: str = ""
    ):
        """
        Inisialisasi konfigurasi Enigma M3.
        
        :param rotor_order: Susunan rotor (kiri, tengah, kanan), misal ('I', 'II', 'III')
        :param reflector: Tipe reflektor ('B' atau 'C')
        :param init_positions: Posisi awal rotor (kiri, tengah, kanan), misal ('A', 'A', 'A')
        :param ring_settings: Pengaturan cincin rotor (1-26 atau A-Z), misal (1, 1, 1)
        :param plugboard_pairs: Pasangan steker, misal "BQ CR DI"
        """
        if (len(rotor_order) != 3 or any(r.upper() not in self.ROTOR_DEFINITIONS for r in rotor_order)
                or len({r.upper() for r in rotor_order}) != 3):
            raise ValueError("Pilih tiga rotor berbeda dari I, II, III, IV, V.")
        if reflector.upper() not in self.REFLECTOR_DEFINITIONS:
            raise ValueError("Reflektor harus B atau C.")
        if len(init_positions) != 3 or any(len(c) != 1 or not 'A' <= c.upper() <= 'Z' for c in init_positions):
            raise ValueError("Posisi awal harus tiga huruf A-Z.")
        if len(ring_settings) != 3 or any(not (
            (type(r) is int and 1 <= r <= 26) or
            (isinstance(r, str) and len(r) == 1 and 'A' <= r.upper() <= 'Z')
        ) for r in ring_settings):
            raise ValueError("Ring setting harus tiga nilai 1-26 atau A-Z.")
        pairs = plugboard_pairs.upper().split()
        if (len(pairs) > 10 or any(len(p) != 2 or any(not 'A' <= c <= 'Z' for c in p) for p in pairs)
                or len(set(''.join(pairs))) != 2 * len(pairs)):
            raise ValueError("Plugboard maksimal 10 pasangan A-Z; setiap huruf hanya boleh dipakai sekali.")

        self.rotor_order = [r.upper() for r in rotor_order]
        self.reflector_name = reflector.upper()
        self.reflector = self.REFLECTOR_DEFINITIONS[self.reflector_name]
        
        # Simpan posisi awal untuk keperluan reset/dekripsi
        self.init_positions = [ord(c.upper()) - ord('A') for c in init_positions]
        self.pos = list(self.init_positions)
        
        # Konversi ring setting (mendukung angka 1-26 maupun huruf A-Z)
        self.ring_settings_raw = ring_settings
        self.ring = []
        for r in ring_settings:
            if isinstance(r, int):
                self.ring.append((r - 1) % 26)
            elif isinstance(r, str) and r.isalpha():
                self.ring.append(ord(r.upper()) - ord('A'))
            else:
                self.ring.append(0)

        # Kabel internal dan notch
        self.rotors = [self.ROTOR_DEFINITIONS[r]['wiring'] for r in self.rotor_order]
        self.notches = [ord(self.ROTOR_DEFINITIONS[r]['notch']) - ord('A') for r in self.rotor_order]

        # Inisialisasi Plugboard (Steckerbrett)
        self.plugboard_pairs_str = plugboard_pairs.strip()
        self.plugboard = {i: i for i in range(26)}
        if self.plugboard_pairs_str:
            pairs = self.plugboard_pairs_str.upper().split()
            for pair in pairs:
                if len(pair) == 2 and pair[0].isalpha() and pair[1].isalpha():
                    p1 = ord(pair[0]) - ord('A')
                    p2 = ord(pair[1]) - ord('A')
                    self.plugboard[p1] = p2
                    self.plugboard[p2] = p1

    def reset(self):
        """Mengembalikan posisi rotor ke posisi awal (Grundstellung)."""
        self.pos = list(self.init_positions)

    def set_positions(self, positions: Tuple[str, str, str]):
        """Mengatur posisi rotor saat ini secara manual."""
        if len(positions) != 3 or any(len(c) != 1 or not 'A' <= c.upper() <= 'Z' for c in positions):
            raise ValueError("Posisi rotor harus tiga huruf A-Z.")
        self.pos = [ord(c.upper()) - ord('A') for c in positions]

    def get_positions_str(self) -> str:
        """Mengembalikan posisi rotor saat ini sebagai string 3 huruf."""
        return "".join(chr(p + ord('A')) for p in self.pos)

    def step(self):
        """
        Mekanisme pergerakan rotor mekanik otentik (pawl & ratchet).
        
        Indeks rotor: 0 = Kiri (Wheel 1), 1 = Tengah (Wheel 2), 2 = Kanan (Wheel 3).
        Aturan pergerakan:
        1. Anomali Double-Stepping: Jika rotor tengah berada pada posisi notch-nya,
           maka pawl rotor tengah mengait roda gigi rotor kiri dan mendorong
           rotor kiri maju 1 langkah, sekaligus memajukan rotor tengah itu sendiri!
        2. Turnover Normal: Jika rotor kanan berada pada notch-nya, rotor tengah maju 1 langkah.
        3. Rotor kanan (fast rotor) SELALU maju 1 langkah pada setiap ketukan tombol.
        """
        mid_at_notch = (self.pos[1] == self.notches[1])
        right_at_notch = (self.pos[2] == self.notches[2])

        if mid_at_notch:
            # Double-stepping: rotor tengah melangkah lagi dan memajukan rotor kiri
            self.pos[1] = (self.pos[1] + 1) % 26
            self.pos[0] = (self.pos[0] + 1) % 26
        elif right_at_notch:
            # Turnover normal dari rotor kanan ke rotor tengah
            self.pos[1] = (self.pos[1] + 1) % 26

        # Rotor kanan selalu berputar 1 langkah
        self.pos[2] = (self.pos[2] + 1) % 26

    def encrypt_char(self, char: str, advance_rotor: bool = True) -> Tuple[str, Dict[str, Any]]:
        """
        Enkripsi satu karakter huruf melalui seluruh lintasan elektrik Enigma.
        
        Lintasan Sinyal:
        1. Tombol ditekan -> Rotor berputar terlebih dahulu (advance_rotor=True).
        2. Sinyal masuk ke Plugboard (substitusi awal).
        3. Lintasan Maju (Forward):
           - Rotor Kanan (Wheel 3) -> Rotor Tengah (Wheel 2) -> Rotor Kiri (Wheel 1).
        4. Reflektor (substitusi pantulan).
        5. Lintasan Balik (Backward):
           - Rotor Kiri (Wheel 1) -> Rotor Tengah (Wheel 2) -> Rotor Kanan (Wheel 3).
        6. Plugboard (substitusi akhir).
        7. Lampboard menyala (karakter ciphertext).
        """
        if len(char) != 1:
            raise ValueError("Masukkan tepat satu karakter.")
        if not ('A' <= char <= 'Z' or 'a' <= char <= 'z'):
            return char, {}

        char_upper = char.upper()

        # 1. Pergerakan mekanik rotor
        pos_before_step = self.get_positions_str()
        if advance_rotor:
            self.step()
        pos_active = self.get_positions_str()

        # Konversi huruf ke indeks 0..25
        signal = ord(char_upper) - ord('A')

        # 2. Masuk Plugboard
        pb_in = chr(self.plugboard[signal] + ord('A'))
        signal = self.plugboard[signal]

        # 3. Lintasan Maju: Wheel 3 (indeks 2) -> Wheel 2 (indeks 1) -> Wheel 1 (indeks 0)
        # Wheel 3 (Kanan)
        shift3 = (self.pos[2] - self.ring[2]) % 26
        signal = (signal + shift3) % 26
        signal = ord(self.rotors[2][signal]) - ord('A')
        signal = (signal - shift3) % 26
        w3_out = chr(signal + ord('A'))

        # Wheel 2 (Tengah)
        shift2 = (self.pos[1] - self.ring[1]) % 26
        signal = (signal + shift2) % 26
        signal = ord(self.rotors[1][signal]) - ord('A')
        signal = (signal - shift2) % 26
        w2_out = chr(signal + ord('A'))

        # Wheel 1 (Kiri)
        shift1 = (self.pos[0] - self.ring[0]) % 26
        signal = (signal + shift1) % 26
        signal = ord(self.rotors[0][signal]) - ord('A')
        signal = (signal - shift1) % 26
        w1_out = chr(signal + ord('A'))

        # 4. Reflektor
        signal = ord(self.reflector[signal]) - ord('A')
        ref_out = chr(signal + ord('A'))

        # 5. Lintasan Balik: Wheel 1 (indeks 0) -> Wheel 2 (indeks 1) -> Wheel 3 (indeks 2)
        # Wheel 1 Balik
        signal = (signal + shift1) % 26
        signal = self.rotors[0].index(chr(signal + ord('A')))
        signal = (signal - shift1) % 26
        w1_back = chr(signal + ord('A'))

        # Wheel 2 Balik
        signal = (signal + shift2) % 26
        signal = self.rotors[1].index(chr(signal + ord('A')))
        signal = (signal - shift2) % 26
        w2_back = chr(signal + ord('A'))

        # Wheel 3 Balik
        signal = (signal + shift3) % 26
        signal = self.rotors[2].index(chr(signal + ord('A')))
        signal = (signal - shift3) % 26
        w3_back = chr(signal + ord('A'))

        # 6. Plugboard Keluar
        signal = self.plugboard[signal]
        out_char = chr(signal + ord('A'))

        trace = {
            "input": char_upper,
            "pos_before": pos_before_step,
            "pos_active": pos_active,
            "plugboard_in": pb_in,
            "wheel3_fwd": w3_out,
            "wheel2_fwd": w2_out,
            "wheel1_fwd": w1_out,
            "reflector": ref_out,
            "wheel1_back": w1_back,
            "wheel2_back": w2_back,
            "wheel3_back": w3_back,
            "plugboard_out": out_char,
            "output": out_char
        }

        return out_char, trace

    def process_text(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """Memproses rangkaian teks huruf dan mengembalikan ciphertext beserta catatan tracing."""
        clean_text = [ch for ch in text.upper() if 'A' <= ch <= 'Z']
        result = []
        traces = []
        for ch in clean_text:
            out_ch, tr = self.encrypt_char(ch, advance_rotor=True)
            result.append(out_ch)
            traces.append(tr)
        return "".join(result), traces


def get_config_summary(enigma: EnigmaM3) -> str:
    """Mengembalikan teks ringkasan konfigurasi mesin Enigma."""
    init_str = "".join(chr(p + ord('A')) for p in enigma.init_positions)
    ring_str = " ".join(f"{r+1:02d}" for r in enigma.ring)
    pb_str = enigma.plugboard_pairs_str if enigma.plugboard_pairs_str else "(Tidak Ada)"
    lines = [
        f"  - Model Mesin       : Enigma M3 (Wehrmacht / Kriegsmarine)",
        f"  - Susunan Rotor     : Kiri={enigma.rotor_order[0]}, Tengah={enigma.rotor_order[1]}, Kanan={enigma.rotor_order[2]}",
        f"  - Reflektor         : UKW-{enigma.reflector_name}",
        f"  - Posisi Awal Rotor : {init_str} (Kiri={init_str[0]}, Tengah={init_str[1]}, Kanan={init_str[2]})",
        f"  - Pengaturan Cincin : {ring_str} (Kiri={enigma.ring[0]+1:02d}, Tengah={enigma.ring[1]+1:02d}, Kanan={enigma.ring[2]+1:02d})",
        f"  - Papan Steker (PB) : {pb_str}",
    ]
    return "\n".join(lines)


def run_single_demo_enigma(
    title: str,
    plaintext: str,
    rotor_order: Tuple[str, str, str] = ('I', 'II', 'III'),
    reflector: str = 'B',
    init_positions: Tuple[str, str, str] = ('A', 'A', 'A'),
    ring_settings: Tuple[Any, Any, Any] = (1, 1, 1),
    plugboard_pairs: str = ""
):
    """Mencetak demo eksekusi Enigma M3 lengkap (enkripsi, dekripsi dari kondisi awal, kecocokan)."""
    print("=" * 70)
    print(f" DEMO: {title}")
    print("=" * 70)
    
    # Inisialisasi Enigma untuk enkripsi
    enigma = EnigmaM3(
        rotor_order=rotor_order,
        reflector=reflector,
        init_positions=init_positions,
        ring_settings=ring_settings,
        plugboard_pairs=plugboard_pairs
    )

    print("Konfigurasi Parameter Mesin:")
    print(get_config_summary(enigma))
    print(f"\nPlaintext Input     : {plaintext}")

    # 1. Enkripsi
    ciphertext, traces = enigma.process_text(plaintext)
    print(f"Ciphertext Hasil    : {ciphertext}")

    # Tampilkan tabel lintasan per karakter
    print("\nTracing Lintasan Sinyal Elektrik per Karakter:")
    header = f"  {'In':<3} | {'Pos':<4} | {'PB_In':<5} | {'W3_F':<5} | {'W2_F':<5} | {'W1_F':<5} | {'Refl':<5} | {'W1_B':<5} | {'W2_B':<5} | {'W3_B':<5} | {'PB_Out':<6} | {'Out'}"
    print(header)
    print("  " + "-" * 75)
    for tr in traces:
        row = (
            f"  {tr['input']:<3} | {tr['pos_active']:<4} | {tr['plugboard_in']:<5} | "
            f"{tr['wheel3_fwd']:<5} | {tr['wheel2_fwd']:<5} | {tr['wheel1_fwd']:<5} | "
            f"{tr['reflector']:<5} | {tr['wheel1_back']:<5} | {tr['wheel2_back']:<5} | "
            f"{tr['wheel3_back']:<5} | {tr['plugboard_out']:<6} | {tr['output']}"
        )
        print(row)

    print(f"\nPosisi Akhir Rotor  : {enigma.get_positions_str()}")

    # 2. Dekripsi
    # Sesuai aturan: Dekripsi HARUS mengembalikan mesin ke posisi awal semula
    enigma.reset()
    pos_reset = enigma.get_positions_str()
    print(f"Posisi Rotor Direset: {pos_reset} (Kembali persis ke posisi awal sebelum enkripsi)")
    decrypted, _ = enigma.process_text(ciphertext)
    print(f"Hasil Dekripsi      : {decrypted}")
    print(f"Posisi Akhir Dekrip : {enigma.get_positions_str()}")

    # Evaluasi kecocokan
    clean_plain = "".join(ch for ch in plaintext.upper() if 'A' <= ch <= 'Z')
    match = (decrypted == clean_plain)
    assert match, "Dekripsi Enigma tidak sesuai plaintext terproses."
    print(f"Status Kecocokan    : {'COCOK (100% IDENTIK SEMPURNA)' if match else 'GAGAL'}")

    # 3. Uji Konsistensi Deterministik (Run Ulang dari Kondisi Awal yang Sama)
    enigma.reset()
    repeat_cipher, _ = enigma.process_text(plaintext)
    repeat_match = (repeat_cipher == ciphertext)
    assert repeat_match, "Hasil Enigma berbeda setelah reset."
    print(f"Uji Deterministik   : {'BERHASIL (Hasil selalu identik pada konfigurasi sama)' if repeat_match else 'GAGAL'}")
    print()


def run_slide79_verification_demo():
    """
    Demo Verifikasi Spesifik Slide 79 (Slide 3-Kriptografi Klasik (2) hal. 79).
    
    Pada slide 79:
    - Rotors: I, II, III (Reflektor B, Plugboard identitas).
    - Menampilkan langkah komputasi tepat saat rotor berada di posisi:
      1. Huruf 'P' pada posisi ABE -> menghasilkan 'G'.
      2. Huruf 'E' pada posisi ABM -> menghasilkan 'Q'.
      3. Huruf 'S' pada posisi ABG -> menghasilkan 'F'.
    """
    print("=" * 70)
    print(" DEMO VERIFIKASI LANGKAH ENKRIPSI SLIDE MATERI PERKULIAHAN (SLIDE 79)")
    print("=" * 70)
    print("Mencocokkan komputasi langkah per langkah dengan tabel pada Slide 79:\n")

    cases = [
        ('P', ('A', 'B', 'E'), 'G'),
        ('E', ('A', 'B', 'M'), 'Q'),
        ('S', ('A', 'B', 'G'), 'F'),
    ]

    for char, pos, expected_out in cases:
        enigma = EnigmaM3(
            rotor_order=('I', 'II', 'III'),
            reflector='B',
            init_positions=pos,
            ring_settings=(1, 1, 1),
            plugboard_pairs=""
        )
        # Enkripsi pada posisi statis persis seperti di slide
        out_char, tr = enigma.encrypt_char(char, advance_rotor=False)
        print(f"Input: {char}  |  Posisi Rotor: {''.join(pos)}")
        print(f"  - Keyboard Input         : {tr['input']}")
        print(f"  - Rotors Position        : {tr['pos_active']}")
        print(f"  - Plugboard Encryption   : {tr['plugboard_in']}")
        print(f"  - Wheel 3 (III) Fwd      : {tr['wheel3_fwd']}")
        print(f"  - Wheel 2 (II) Fwd       : {tr['wheel2_fwd']}")
        print(f"  - Wheel 1 (I) Fwd        : {tr['wheel1_fwd']}")
        print(f"  - Reflector (UKW-B)      : {tr['reflector']}")
        print(f"  - Wheel 1 (I) Back       : {tr['wheel1_back']}")
        print(f"  - Wheel 2 (II) Back      : {tr['wheel2_back']}")
        print(f"  - Wheel 3 (III) Back     : {tr['wheel3_back']}")
        print(f"  - Plugboard Encryption   : {tr['plugboard_out']}")
        print(f"  - Output (Lampboard)     : {tr['output']}")
        match_slide = (tr['output'] == expected_out)
        assert match_slide, "Hasil Enigma berbeda dari contoh slide 79."
        print(f"  => Hasil: {tr['output']} (Target Slide 79: {expected_out}) -> {'COCOK PERSIS 100%' if match_slide else 'BERBEDA'}")
        print()


def run_double_stepping_demo():
    """
    Demo Verifikasi Mekanisme Double-Stepping Rotor Tengah Enigma.
    
    Urutan uji:
    Posisi awal: ADU (Rotor I=A, Rotor II=D, Rotor III=U).
    Notch Rotor III adalah V.
    Notch Rotor II adalah E.
    
    Langkah:
    1. Ketukan 1: U -> V (Rotor kanan mencapai notch V) -> Posisi: ADV
    2. Ketukan 2: V -> W, memajukan Rotor Tengah dari D -> E (Rotor II mencapai notch E!) -> Posisi: AEW
    3. Ketukan 3: W -> X. Rotor tengah yang berada pada notch E mengalami DOUBLE STEPPING:
       ia melangkah maju E -> F dan memajukan Rotor Kiri dari A -> B! -> Posisi: BFX
    4. Ketukan 4: X -> Y -> Posisi: BFY
    """
    print("=" * 70)
    print(" DEMO VERIFIKASI MEKANISME DOUBLE-STEPPING PADA ROTOR TENGAH")
    print("=" * 70)
    print("Posisi Awal: ADU (Rotor I=A, Rotor II=D, Rotor III=U)")
    print("Notch: Rotor III = 'V', Rotor II = 'E', Rotor I = 'Q'\n")

    enigma = EnigmaM3(
        rotor_order=('I', 'II', 'III'),
        reflector='B',
        init_positions=('A', 'D', 'U'),
        ring_settings=(1, 1, 1)
    )

    steps_description = [
        "Ketukan 1: Rotor Kanan maju ke posisi V (posisi notch Rotor III).",
        "Ketukan 2: Rotor Kanan melewati notch V, memicu Rotor Tengah maju ke E (notch Rotor II).",
        "Ketukan 3: ANOMALI DOUBLE STEPPING! Rotor Tengah pada notch E memajukan dirinya (E->F) DAN Rotor Kiri (A->B).",
        "Ketukan 4: Rotor Kanan melangkah normal (X->Y).",
    ]

    for idx, desc in enumerate(steps_description, start=1):
        pos_before = enigma.get_positions_str()
        enigma.encrypt_char('A', advance_rotor=True)
        pos_after = enigma.get_positions_str()
        assert pos_after == ['ADV', 'AEW', 'BFX', 'BFY'][idx - 1], "Urutan stepping tidak sesuai."
        print(f"Langkah {idx}: {pos_before} -> {pos_after} | {desc}")
    print()


def main():
    print("#" * 70)
    print(f"# PROGRAM SIMULASI MESIN ENIGMA (MODEL ENIGMA M3)")
    print(f"# Kelompok : {GROUP_NAME}")
    for name, npm in GROUP_MEMBERS:
        print(f"# Anggota  : {name} ({npm})")
    print("#" * 70)
    print()

    # 1. Demo Utama Kelompok: Plaintext STREAMING
    run_single_demo_enigma(
        title="UJI 1 — STREAMING (Demo Utama Kelompok)",
        plaintext="STREAMING",
        rotor_order=('I', 'II', 'III'),
        reflector='B',
        init_positions=('A', 'A', 'A'),
        ring_settings=(1, 1, 1),
        plugboard_pairs="BQ CR"
    )

    # 2. Demo Verifikasi Slide 79 Materi Perkuliahan
    run_slide79_verification_demo()

    # 3. Demo Verifikasi Mekanisme Double-Stepping Otentik
    run_double_stepping_demo()


if __name__ == "__main__":
    main()
