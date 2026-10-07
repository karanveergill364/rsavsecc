"""
RSA vs ECC  --  "speed basics" benchmark (extra experiments beyond the base paper)

Measures at equal NIST security levels:
  1. Key generation time
  2. Signature generation time   (RSA PKCS#1 v1.5  vs  ECDSA)
  3. Signature verification time
  4. Throughput (operations / second)
  5. Key, signature and ciphertext sizes
  6. Speed-up factor (how many times faster ECC is, or slower)

Both algorithms use the SAME library (pycryptodome, C-backed) so the
comparison is fair -- unlike pure-Python ECC vs built-in pow() RSA.

Install:  pip install pycryptodome matplotlib pandas
Run:      python rsa_vs_ecc_speed.py
Quick test (small levels, few repeats):  QUICK=1 python rsa_vs_ecc_speed.py
"""
import os
import statistics as st
import time

import matplotlib.pyplot as plt
import pandas as pd
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pkcs1_15

QUICK = os.environ.get("QUICK") == "1"

# security bits -> (RSA key bits, ECC curve name, ECC field size in bits)
# (NIST SP 800-57, same as Table 1 of the paper; P-192 is the closest to 80-bit)
LEVELS = {
    80:  (1024, "P-192", 192),
    112: (2048, "P-224", 224),
    128: (3072, "P-256", 256),
    192: (7680, "P-384", 384),   # RSA-7680 key generation is slow (minutes)
}
KEYGEN_REPEATS = {80: 10, 112: 10, 128: 5, 192: 2}   # RSA keygen is slow
OP_REPEATS = 20                                       # sign / verify repeats

if QUICK:
    LEVELS = {k: v for k, v in LEVELS.items() if k in (80, 112)}
    KEYGEN_REPEATS = {80: 3, 112: 3}
    OP_REPEATS = 5


def time_it(func, repeats):
    """Return (mean, std) of the wall-clock time of func() over `repeats` runs."""
    ts = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        func()
        ts.append(time.perf_counter() - t0)
    return st.mean(ts), (st.stdev(ts) if len(ts) > 1 else 0.0)


def run():
    rows = []
    digest = SHA256.new(b"the quick brown fox" * 4)
    for sec, (rsa_bits, curve, ecc_bits) in LEVELS.items():
        print(f"\n=== {sec}-bit security | RSA-{rsa_bits} vs ECC {curve} ===")
        kg_rep = KEYGEN_REPEATS[sec]

        # ---- key generation
        rsa_kg = time_it(lambda: RSA.generate(rsa_bits), kg_rep)
        ecc_kg = time_it(lambda: ECC.generate(curve=curve), kg_rep)

        rsa_key = RSA.generate(rsa_bits)
        ecc_key = ECC.generate(curve=curve)

        # ---- signing
        rsa_signer = pkcs1_15.new(rsa_key)
        ecc_signer = DSS.new(ecc_key, "fips-186-3")
        rsa_sig = rsa_signer.sign(digest)
        ecc_sig = ecc_signer.sign(digest)
        rsa_sign = time_it(lambda: rsa_signer.sign(digest), OP_REPEATS)
        ecc_sign = time_it(lambda: ecc_signer.sign(digest), OP_REPEATS)

        # ---- verification
        rsa_ver = pkcs1_15.new(rsa_key.publickey())
        ecc_ver = DSS.new(ecc_key.public_key(), "fips-186-3")
        rsa_verify = time_it(lambda: rsa_ver.verify(digest, rsa_sig), OP_REPEATS)
        ecc_verify = time_it(lambda: ecc_ver.verify(digest, ecc_sig), OP_REPEATS)

        coord = (ecc_bits + 7) // 8   # bytes per curve coordinate
        row = {
            "security_bits": sec, "rsa_key_bits": rsa_bits, "ecc_curve": curve,
            "RSA_keygen": rsa_kg[0], "RSA_keygen_std": rsa_kg[1],
            "ECC_keygen": ecc_kg[0], "ECC_keygen_std": ecc_kg[1],
            "RSA_sign": rsa_sign[0], "RSA_sign_std": rsa_sign[1],
            "ECC_sign": ecc_sign[0], "ECC_sign_std": ecc_sign[1],
            "RSA_verify": rsa_verify[0], "RSA_verify_std": rsa_verify[1],
            "ECC_verify": ecc_verify[0], "ECC_verify_std": ecc_verify[1],
            # sizes in bytes
            "RSA_sig_bytes": len(rsa_sig), "ECC_sig_bytes": len(ecc_sig),
            "RSA_pubkey_bytes": rsa_bits // 8, "ECC_pubkey_bytes": 2 * coord,
            "RSA_ciphertext_bytes": rsa_bits // 8,
            # EC ElGamal ciphertext = two uncompressed points (x,y each)
            "ECC_ciphertext_bytes": 4 * coord,
        }
        for op in ("sign", "verify"):
            row[f"RSA_{op}_ops"] = 1 / row[f"RSA_{op}"]
            row[f"ECC_{op}_ops"] = 1 / row[f"ECC_{op}"]
        rows.append(row)
        print(f"  keygen  RSA {rsa_kg[0]:.4f}s  ECC {ecc_kg[0]:.4f}s")
        print(f"  sign    RSA {rsa_sign[0]:.5f}s  ECC {ecc_sign[0]:.5f}s")
        print(f"  verify  RSA {rsa_verify[0]:.5f}s  ECC {ecc_verify[0]:.5f}s")

    df = pd.DataFrame(rows)
    df.to_csv("speed_results.csv", index=False)
    return df


# ------------------------------------------------------------------ plots
def line_plot(df, ecc_col, rsa_col, title, ylabel, fname,
              err=True, log=False, marker="o"):
    plt.figure(figsize=(8, 5))
    x = df.security_bits
    if err:
        plt.errorbar(x, df[ecc_col], yerr=df[ecc_col + "_std"], color="blue",
                     marker=marker, capsize=3, label=f"ECC {title}")
        plt.errorbar(x, df[rsa_col], yerr=df[rsa_col + "_std"], color="green",
                     marker=marker, capsize=3, label=f"RSA {title}")
    else:
        plt.plot(x, df[ecc_col], color="blue", marker=marker, label=f"ECC {title}")
        plt.plot(x, df[rsa_col], color="green", marker=marker, label=f"RSA {title}")
    if log:
        plt.yscale("log")
    plt.title(f"{title} (ECC vs RSA)")
    plt.xlabel("Security Bit level")
    plt.ylabel(ylabel)
    plt.xticks(list(x))
    plt.grid(True, alpha=0.4, which="both")
    plt.legend()
    plt.tight_layout()
    plt.savefig(fname, dpi=200)
    plt.close()


def make_graphs(df):
    line_plot(df, "ECC_keygen", "RSA_keygen", "Key Generation Time",
              "Time in second (log scale)", "keygen_time.png", log=True, marker="o")
    line_plot(df, "ECC_sign", "RSA_sign", "Signature Generation Time",
              "Time in second (log scale)", "sign_time.png", log=True, marker="s")
    line_plot(df, "ECC_verify", "RSA_verify", "Signature Verification Time",
              "Time in second (log scale)", "verify_time.png", log=True, marker="^")
    line_plot(df, "ECC_sign_ops", "RSA_sign_ops", "Signing Throughput",
              "Operations per second (log scale)", "throughput_sign.png",
              err=False, log=True, marker="d")
    line_plot(df, "ECC_verify_ops", "RSA_verify_ops", "Verification Throughput",
              "Operations per second (log scale)", "throughput_verify.png",
              err=False, log=True, marker="d")

    # sizes (bytes)
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.5))
    for ax, (e, r, t) in zip(axes, [
            ("ECC_pubkey_bytes", "RSA_pubkey_bytes", "Public key size"),
            ("ECC_sig_bytes", "RSA_sig_bytes", "Signature size"),
            ("ECC_ciphertext_bytes", "RSA_ciphertext_bytes", "Ciphertext size")]):
        ax.plot(df.security_bits, df[e], color="blue", marker="o", label="ECC")
        ax.plot(df.security_bits, df[r], color="green", marker="o", label="RSA")
        ax.set_title(t); ax.set_xlabel("Security Bit level"); ax.set_ylabel("Bytes")
        ax.set_xticks(list(df.security_bits)); ax.grid(True, alpha=0.4); ax.legend()
    plt.tight_layout(); plt.savefig("sizes.png", dpi=200); plt.close()

    # speed-up factor: >1 means ECC is faster, <1 means RSA is faster
    plt.figure(figsize=(8, 5))
    width, xs = 0.25, range(len(df))
    for i, op in enumerate(["keygen", "sign", "verify"]):
        speedup = df[f"RSA_{op}"] / df[f"ECC_{op}"]
        plt.bar([x + i * width for x in xs], speedup, width, label=op)
    plt.axhline(1, color="black", linestyle="--", linewidth=1)
    plt.yscale("log")
    plt.xticks([x + width for x in xs], [str(s) for s in df.security_bits])
    plt.xlabel("Security Bit level")
    plt.ylabel("RSA time / ECC time  (>1 = ECC faster)")
    plt.title("Speed-up of ECC over RSA")
    plt.grid(True, alpha=0.4, axis="y", which="both")
    plt.legend(); plt.tight_layout()
    plt.savefig("speedup.png", dpi=200); plt.close()


if __name__ == "__main__":
    results = run()
    make_graphs(results)
    print("\nDone. See speed_results.csv, keygen_time.png, sign_time.png, "
          "verify_time.png, throughput_*.png, sizes.png, speedup.png")
