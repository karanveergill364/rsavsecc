"""
RSA vs EC-ElGamal benchmark  (timing + CPU utilization + paper-style graphs)

Install:
    pip install pycryptodome tinyec matplotlib pandas

Run:
    python rsa_vs_ecc_benchmark.py

Outputs:
    results.csv                      -> all numbers (use these to make your tables)
    <msgbits>bit_encryption.png      -> like Fig 5, 8, 11, 14 of the paper
    <msgbits>bit_decryption.png      -> like Fig 6, 9, 12, 15
    <msgbits>bit_total.png           -> like Fig 7, 10, 13, 16
    <msgbits>bit_cpu.png             -> extra: CPU utilization graph
"""
import random
import time

import matplotlib.pyplot as plt
import pandas as pd
from Crypto.PublicKey import RSA          # pycryptodome
from tinyec import registry               # elliptic curve arithmetic
from tinyec.ec import Point

# ---------------------------------------------------------------- settings
# NIST SP 800-57 mapping (same as Table 1 in the paper):
# security bits -> (RSA key size, ECC curve)
# NOTE: tinyec has no 160-bit curve, so 80-bit uses secp192r1 (closest).
#       512-bit ECC = secp521r1 (closest). RSA-15360 keygen takes very long,
#       so 256-bit level is left out by default.
LEVELS = {
    80:  (1024, "secp192r1"),
    112: (2048, "secp224r1"),
    128: (3072, "secp256r1"),
    192: (7680, "secp384r1"),
    # 256: (15360, "secp521r1"),   # uncomment if you have lots of patience
}
MESSAGE_BITS = [8, 64, 256, 512]   # same 4 inputs as the paper
REPEATS = 5                        # average over several runs -> stable graphs


# ---------------------------------------------------------------- measuring
def measure(func, *args):
    """Run func(*args) once; return (result, wall_seconds, cpu_seconds)."""
    w0, c0 = time.perf_counter(), time.process_time()
    result = func(*args)
    w1, c1 = time.perf_counter(), time.process_time()
    return result, w1 - w0, c1 - c0


# ---------------------------------------------------------------- RSA
# Textbook RSA exactly as in the paper:  C = M^e mod n ,  M = C^d mod n
def rsa_encrypt(m, e, n):
    return pow(m, e, n)


def rsa_decrypt(c, d, n):
    return pow(c, d, n)


# ---------------------------------------------------------------- EC ElGamal
# Setup: curve E, base point G, order n.  Private key nB, public key PB = nB*G
# Encrypt: pick random k ->  Cm = (k*G , Pm + k*PB)
# Decrypt: Pm = (Pm + k*PB) - nB*(k*G)
def ec_keygen(curve):
    priv = random.randrange(1, curve.field.n)
    pub = priv * curve.g
    return priv, pub


def ec_encode(m, curve):
    """Map integer message to a curve point Pm = m*G (simple encoding used
    in benchmarks; real systems use Koblitz encoding)."""
    return (m % curve.field.n or 1) * curve.g


def ec_encrypt(Pm, pub, curve):
    k = random.randrange(1, curve.field.n)
    C1 = k * curve.g
    C2 = Pm + k * pub
    return C1, C2


def ec_decrypt(C1, C2, priv, curve):
    S = priv * C1                                   # nB * (k*G)
    S_neg = Point(curve, S.x, (-S.y) % curve.field.p)   # -S
    return C2 + S_neg


# ---------------------------------------------------------------- benchmark
def run():
    rows = []
    for sec, (rsa_bits, curve_name) in LEVELS.items():
        print(f"\n=== security {sec} bit | RSA-{rsa_bits} vs {curve_name} ===")
        rsa_key = RSA.generate(rsa_bits)
        curve = registry.get_curve(curve_name)
        priv, pub = ec_keygen(curve)

        for mbits in MESSAGE_BITS:
            acc = {k: [] for k in
                   ["rsa_enc", "rsa_dec", "rsa_enc_cpu", "rsa_dec_cpu",
                    "ecc_enc", "ecc_dec", "ecc_enc_cpu", "ecc_dec_cpu"]}
            for _ in range(REPEATS):
                m = random.getrandbits(mbits) | 1
                # ---- RSA
                c, w, cpu = measure(rsa_encrypt, m, rsa_key.e, rsa_key.n)
                acc["rsa_enc"].append(w); acc["rsa_enc_cpu"].append(cpu)
                p, w, cpu = measure(rsa_decrypt, c, rsa_key.d, rsa_key.n)
                acc["rsa_dec"].append(w); acc["rsa_dec_cpu"].append(cpu)
                assert p == m, "RSA decrypt mismatch"
                # ---- EC ElGamal
                Pm = ec_encode(m, curve)
                (C1, C2), w, cpu = measure(ec_encrypt, Pm, pub, curve)
                acc["ecc_enc"].append(w); acc["ecc_enc_cpu"].append(cpu)
                P2, w, cpu = measure(ec_decrypt, C1, C2, priv, curve)
                acc["ecc_dec"].append(w); acc["ecc_dec_cpu"].append(cpu)
                assert (P2.x, P2.y) == (Pm.x, Pm.y), "ECC decrypt mismatch"

            avg = {k: sum(v) / len(v) for k, v in acc.items()}
            row = {
                "message_bits": mbits, "security_bits": sec,
                "rsa_key_bits": rsa_bits, "ecc_curve": curve_name,
                "ECC_enc": avg["ecc_enc"], "RSA_enc": avg["rsa_enc"],
                "ECC_dec": avg["ecc_dec"], "RSA_dec": avg["rsa_dec"],
                "ECC_total": avg["ecc_enc"] + avg["ecc_dec"],
                "RSA_total": avg["rsa_enc"] + avg["rsa_dec"],
                # CPU utilization % = CPU time / wall time
                "ECC_cpu_%": 100 * (avg["ecc_enc_cpu"] + avg["ecc_dec_cpu"]) /
                             (avg["ecc_enc"] + avg["ecc_dec"]),
                "RSA_cpu_%": 100 * (avg["rsa_enc_cpu"] + avg["rsa_dec_cpu"]) /
                             (avg["rsa_enc"] + avg["rsa_dec"]),
            }
            rows.append(row)
            print(f"  msg {mbits:>3} bit | ECC total {row['ECC_total']:.4f}s"
                  f" | RSA total {row['RSA_total']:.4f}s")
    df = pd.DataFrame(rows)
    df.to_csv("results.csv", index=False)
    return df


# ---------------------------------------------------------------- plotting
def plot(df, mbits, ecc_col, rsa_col, title, ylabel, fname, ecc_mark, rsa_mark):
    d = df[df.message_bits == mbits]
    plt.figure(figsize=(8, 5))
    plt.plot(d.security_bits, d[ecc_col], color="blue", marker=ecc_mark,
             label=f"ECC {title}")
    plt.plot(d.security_bits, d[rsa_col], color="green", marker=rsa_mark,
             label=f"RSA {title}")
    plt.title(f"{title} for {mbits} bit (ECC vs RSA)")
    plt.xlabel("Security Bit level")
    plt.ylabel(ylabel)
    plt.grid(True, alpha=0.4)
    plt.legend()
    plt.tight_layout()
    plt.savefig(fname, dpi=200)
    plt.close()


def make_graphs(df):
    for mbits in MESSAGE_BITS:
        plot(df, mbits, "ECC_enc", "RSA_enc", "Encryption Time",
             "Time in second", f"{mbits}bit_encryption.png", "o", "o")
        plot(df, mbits, "ECC_dec", "RSA_dec", "Decryption Time",
             "Time in second", f"{mbits}bit_decryption.png", "s", "s")
        plot(df, mbits, "ECC_total", "RSA_total", "Total Time",
             "Time in second", f"{mbits}bit_total.png", "^", "^")
        plot(df, mbits, "ECC_cpu_%", "RSA_cpu_%", "CPU Utilization",
             "CPU utilization (%)", f"{mbits}bit_cpu.png", "d", "d")


if __name__ == "__main__":
    results = run()
    make_graphs(results)
    print("\nDone. See results.csv and the *.png files.")
