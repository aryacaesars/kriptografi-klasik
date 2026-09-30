"""Antarmuka Streamlit untuk mencoba lima implementasi cipher kelompok."""

from pathlib import Path
import sys

import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import affine
import enigma
import hill
import playfair
import vigenere


st.set_page_config(page_title="Lab Cipher", page_icon="🔐", layout="wide")
st.markdown("""
<style>
.stApp {background: radial-gradient(ellipse at 85% -15%, #243b4a 0, transparent 36%), #10151e;}
[data-testid="stHeader"] {background: transparent;}
[data-testid="stMetric"] {background:#171f2a;border:1px solid #303b4d;padding:14px;border-radius:14px;}
.hero {padding: 1.2rem 0 .6rem;}
.hero h1 {font-size: clamp(2.7rem, 6vw, 4.2rem); line-height:1; letter-spacing:-.05em; margin:.5rem 0;}
.hero p,.muted {color:#a1aec0;}
code {color:#9fe4c5 !important;}
</style>
<div class="hero"><div class="muted">INTERACTIVE CIPHER LAB · TUGAS 1</div>
<h1>Lima cipher.<br>Hitung langsung.</h1>
<p>Ubah plaintext dan kuncinya untuk melihat ciphertext, hasil dekripsi, serta langkah pentingnya.</p></div>
""", unsafe_allow_html=True)

left, right = st.columns([1, 1.15], gap="large")
with left:
    st.subheader("Konfigurasi demo")
    cipher = st.selectbox("Pilih cipher", ["Vigenere", "Playfair", "Affine", "Hill", "Enigma"])
    with st.form("cipher-demo"):
        plaintext = st.text_area("Plaintext", "STREAMING", height=95, max_chars=2000)
        settings = {}
        if cipher == "Vigenere":
            settings["key"] = st.text_input("Kunci", "BAGUS")
            st.caption("Kunci diulang sepanjang pesan; spasi dan tanda baca tetap dipertahankan.")
        elif cipher == "Playfair":
            settings["key"] = st.text_input("Kunci", "BAGUS")
            st.caption("J dibuang dari tabel, J pada pesan diubah menjadi I, dan pesan diproses berpasangan.")
        elif cipher == "Affine":
            a_col, b_col = st.columns(2)
            settings["a"] = a_col.number_input("Parameter a", value=17, step=1)
            settings["b"] = b_col.number_input("Parameter b", value=9, step=1)
            st.caption("a harus relatif prima terhadap 26 agar dekripsi dapat dilakukan.")
        elif cipher == "Hill":
            st.markdown("**Matriks kunci 2 × 2**")
            row1 = st.columns(2)
            row2 = st.columns(2)
            settings["key"] = [
                [row1[0].number_input("Baris 1 · kolom 1", value=3, step=1),
                 row1[1].number_input("Baris 1 · kolom 2", value=3, step=1)],
                [row2[0].number_input("Baris 2 · kolom 1", value=2, step=1),
                 row2[1].number_input("Baris 2 · kolom 2", value=5, step=1)],
            ]
            st.caption("Determinan harus relatif prima terhadap 26. Panjang ganjil ditambah padding X.")
        else:
            r1, r2 = st.columns(2)
            settings["rotors"] = [
                r1.selectbox("Rotor kiri", ["I", "II", "III", "IV", "V"], index=0),
                r2.selectbox("Rotor tengah", ["I", "II", "III", "IV", "V"], index=1),
            ]
            settings["rotors"].append(st.selectbox("Rotor kanan", ["I", "II", "III", "IV", "V"], index=2))
            settings["reflector"] = st.selectbox("Reflector", ["B", "C"])
            settings["positions"] = st.text_input("Posisi awal · kiri–tengah–kanan", "AAA", max_chars=3)
            rings = st.columns(3)
            settings["rings"] = [rings[i].number_input(f"Ring {i+1}", min_value=1, max_value=26, value=1) for i in range(3)]
            settings["plugboard"] = st.text_input("Plugboard", "BQ CR", help="Masukkan pasangan dua huruf, misalnya BQ CR.")

        submitted = st.form_submit_button("Jalankan enkripsi dan dekripsi", type="primary", use_container_width=True)


def calculate(name, plain, config):
    if name == "Vigenere":
        key = config["key"]
        ciphertext = vigenere.encrypt_vigenere(plain, key)
        decrypted = vigenere.decrypt_vigenere(ciphertext, key)
        return {"ciphertext": ciphertext, "decrypted": decrypted,
                "matches": decrypted == plain.upper(), "processed": plain.upper(),
                "key": key}

    if name == "Playfair":
        key = config["key"]
        encrypted = playfair.playfair_encrypt(plain, key)
        ciphertext = encrypted["ciphertext"]
        decrypted = playfair.playfair_decrypt(ciphertext, key)["raw_decrypted"]
        return {"ciphertext": ciphertext, "decrypted": decrypted,
                "matches": decrypted == encrypted["processed_plain"],
                "processed": encrypted["processed_plain"], "key": key,
                "matrix": encrypted["matrix"],
                "bigrams": [a + b for a, b in encrypted["bigrams"]]}

    if name == "Affine":
        a, b = config["a"], config["b"]
        ciphertext = affine.encrypt_affine(plain, a, b)
        decrypted = affine.decrypt_affine(ciphertext, a, b)
        return {"ciphertext": ciphertext, "decrypted": decrypted,
                "matches": decrypted == plain.upper(), "processed": plain.upper(),
                "key": f"a = {a}, b = {b}"}

    if name == "Hill":
        key = config["key"]
        processed = hill.normalize_plaintext(plain)
        padding = len(processed) % 2
        prepared = processed + ("X" if padding else "")
        ciphertext = hill.encrypt_hill(plain, key)
        decrypted = hill.decrypt_hill(ciphertext, key)
        recovered = decrypted[:-padding] if padding else decrypted
        return {"ciphertext": ciphertext, "decrypted": decrypted,
                "matches": recovered == processed, "processed": prepared,
                "key": key, "padding": padding, "recovered": recovered,
                "blocks": [prepared[i:i+2] for i in range(0, len(prepared), 2)]}

    rotors, rings = config["rotors"], config["rings"]
    machine = enigma.EnigmaM3(rotor_order=tuple(rotors), reflector=config["reflector"],
        init_positions=tuple(config["positions"].upper()), ring_settings=tuple(rings),
        plugboard_pairs=config["plugboard"])
    ciphertext, traces = machine.process_text(plain)
    final_positions = machine.get_positions_str()
    machine.reset()
    reset_positions = machine.get_positions_str()
    decrypted, _ = machine.process_text(ciphertext)
    processed = "".join(c for c in plain.upper() if "A" <= c <= "Z")
    return {"ciphertext": ciphertext, "decrypted": decrypted,
            "matches": decrypted == processed, "processed": processed,
            "key": {"rotors": rotors, "reflector": config["reflector"],
                    "positions": config["positions"].upper(), "rings": rings,
                    "plugboard": config["plugboard"] or "(kosong)"},
            "final_positions": final_positions, "reset_positions": reset_positions,
            "traces": traces}


with right:
    st.subheader("Hasil perhitungan")
    st.caption("Hasil ini dihitung ulang oleh fungsi Python cipher yang sama dengan demo console.")
    if submitted:
        try:
            result = calculate(cipher, plaintext, settings)
            if result["matches"]:
                st.success("Dekripsi cocok dengan plaintext terproses.")
            else:
                st.error("Hasil dekripsi tidak cocok. Periksa input dan konfigurasi.")
            st.metric("Ciphertext", result["ciphertext"] or "(kosong)")
            st.text_area("Hasil dekripsi", result["decrypted"] or "(kosong)", disabled=True, height=80)

            with st.expander("Parameter dan teks yang diproses", expanded=True):
                st.write("**Plaintext:**", plaintext or "(kosong)")
                st.write("**Kunci / konfigurasi:**", result["key"])
                if result["processed"] != plaintext.upper():
                    st.write("**Plaintext diproses:**", result["processed"])
                if "matrix" in result:
                    st.write("**Matriks Playfair:**")
                    st.table(result["matrix"])
                    st.write("**Pasangan huruf:**", " · ".join(result["bigrams"]))
                if "blocks" in result:
                    st.write("**Blok Hill:**", " · ".join(result["blocks"]))
                    st.write("**Padding:**", f'{result["padding"]} X')
                    st.write("**Setelah padding demo dilepas:**", result["recovered"])
                if "final_positions" in result:
                    st.write("**Posisi rotor akhir:**", result["final_positions"])
                    st.write("**Posisi awal dekripsi:**", result["reset_positions"])

            if "traces" in result and result["traces"]:
                with st.expander("Trace sinyal Enigma per huruf"):
                    columns = ["input", "pos_active", "plugboard_in", "wheel3_fwd", "wheel2_fwd",
                               "wheel1_fwd", "reflector", "wheel1_back", "wheel2_back",
                               "wheel3_back", "plugboard_out", "output"]
                    st.dataframe([{key: trace[key] for key in columns} for trace in result["traces"]],
                                 hide_index=True, use_container_width=True)
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            st.error(str(exc))
    else:
        st.info("Pilih cipher, atur plaintext dan kunci, lalu tekan tombol untuk melihat hasilnya.")

st.divider()
st.caption("Kelompok Kriptografi · Python + Streamlit · A = 0 sampai Z = 25")
