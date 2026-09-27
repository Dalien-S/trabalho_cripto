from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

# ==========================================================
# HARDCODED BENCHMARK DATA
# (algorithm, operation, size_bytes, time_ns)
# ==========================================================

DATA = [
    ("AES", "Encrypt", 916, 681),
    ("AES", "Decrypt", 916, 672),
    ("RSA", "Encrypt", 916, 194803),
    ("RSA", "Decrypt", 916, 2692168),
    ("DGEnc", "Encrypt", 916, 452),
    ("DGEnc", "Decrypt", 916, 444),
    ("VecDGEnc", "Encrypt", 916, 450),
    ("VecDGEnc", "Decrypt", 916, 446),
    ("AES", "Encrypt", 28391, 3482),
    ("AES", "Decrypt", 28391, 3490),
    ("RSA", "Encrypt", 28391, 5757237),
    ("RSA", "Decrypt", 28391, 79717567),
    ("DGEnc", "Encrypt", 28391, 3461),
    ("DGEnc", "Decrypt", 28391, 3048),
    ("VecDGEnc", "Encrypt", 28391, 997),
    ("VecDGEnc", "Decrypt", 28391, 907),
    ("AES", "Encrypt", 327626, 35976),
    ("AES", "Decrypt", 327626, 35849),
    ("RSA", "Encrypt", 327626, 66247957),
    ("RSA", "Decrypt", 327626, 918715567),
    ("DGEnc", "Encrypt", 327626, 66492),
    ("DGEnc", "Decrypt", 327626, 59031),
    ("VecDGEnc", "Encrypt", 327626, 7380),
    ("VecDGEnc", "Decrypt", 327626, 6174),
    ("AES", "Encrypt", 3369207, 365772),
    ("AES", "Decrypt", 3369207, 365470),
    ("RSA", "Encrypt", 3369207, 683323135),
    ("RSA", "Decrypt", 3369207, 9459991612),
    ("DGEnc", "Encrypt", 3369207, 687925),
    ("DGEnc", "Decrypt", 3369207, 615017),
    ("VecDGEnc", "Encrypt", 3369207, 71292),
    ("VecDGEnc", "Decrypt", 3369207, 60187),
]

# ==========================================================
# OUTPUT
# ==========================================================

OUT = Path("plots")
OUT.mkdir(exist_ok=True)

# ==========================================================
# Helpers
# ==========================================================

def filter_data(data, operations=None):
    if operations is None:
        return data
    return [r for r in data if r[1] in operations]


def line_plot(data, title, filename, log=False):
    plt.figure(figsize=(10, 6))

    groups = {}
    for alg, op, size, t in data:
        groups.setdefault((alg, op), []).append((size, t))

    for (alg, op), values in sorted(groups.items()):
        values.sort()
        x = [v[0] for v in values]
        y = [v[1] for v in values]
        plt.plot(x, y, marker="o", linewidth=2, label=f"{alg} — {op}")

    plt.title(title)
    plt.xlabel("Input size (bytes)")
    plt.ylabel("Time (ns)")
    plt.grid(True, which="both", linestyle="--", alpha=0.35)

    if log:
        plt.yscale("log")

    plt.legend()
    plt.tight_layout()
    plt.savefig(OUT / filename, dpi=220)
    plt.close()


def bar_plot(data, title, filename, log=False):
    # Unique sizes (x-axis)
    sizes = sorted(set(size for _, _, size, _ in data))

    # Unique algorithm/operation pairs
    series = sorted(set((alg, op) for alg, op, _, _ in data))

    width = 0.8 / len(series)
    x = np.arange(len(sizes))

    plt.figure(figsize=(12, 6))

    for idx, (alg, op) in enumerate(series):
        vals = []
        for size in sizes:
            match = next(
                (t for a, o, s, t in data if a == alg and o == op and s == size),
                np.nan,
            )
            vals.append(match)

        plt.bar(
            x + idx * width,
            vals,
            width=width,
            label=f"{alg} — {op}",
        )

    plt.xticks(x + width * (len(series) - 1) / 2, sizes)
    plt.xlabel("Input size (bytes)")
    plt.ylabel("Time (ns)")
    plt.title(title)
    plt.grid(axis="y", linestyle="--", alpha=0.35)

    if log:
        plt.yscale("log")

    plt.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(OUT / filename, dpi=220)
    plt.close()


# ==========================================================
# DATASETS
# ==========================================================

NO_RSA = [r for r in DATA if "RSA" not in r[0]]
NO_AES = [r for r in DATA if "AES" not in r[0]]

# ==========================================================
# LINE CHARTS
# ==========================================================

line_plot(DATA, "All Benchmarks — Linear", "line_all_linear.png")
line_plot(DATA, "All Benchmarks — Log", "line_all_log.png", log=True)

line_plot(NO_RSA, "Without RSA — Linear", "line_no_rsa_linear.png")
line_plot(NO_RSA, "Without RSA — Log", "line_no_rsa_log.png", log=True)

# ==========================================================
# BAR CHARTS
# ==========================================================

bar_plot(DATA, "All Benchmarks — Linear Bars", "bar_all_linear.png")
bar_plot(DATA, "All Benchmarks — Log Bars", "bar_all_log.png", log=True)

bar_plot(NO_RSA, "Without RSA — Linear Bars", "bar_no_rsa_linear.png")
bar_plot(NO_RSA, "Without RSA — Log Bars", "bar_no_rsa_log.png", log=True)

# ==========================================================
# ENCRYPT / DECRYPT ONLY (WITHOUT RSA)
# ==========================================================

line_plot(filter_data(NO_RSA, {"Encrypt"}),
          "Encryption Only — Linear",
          "line_encrypt_no_rsa_linear.png")

line_plot(filter_data(NO_RSA, {"Decrypt"}),
          "Decryption Only — Linear",
          "line_decrypt_no_rsa_linear.png")

bar_plot(filter_data(NO_RSA, {"Encrypt"}),
         "Encryption Only — Linear Bars",
         "bar_encrypt_no_rsa_linear.png")

bar_plot(filter_data(NO_RSA, {"Decrypt"}),
         "Decryption Only — Linear Bars",
         "bar_decrypt_no_rsa_linear.png")

# ==========================================================
# ENCRYPT / DECRYPT ONLY (WITHOUT AES)
# ==========================================================

line_plot(filter_data(NO_AES, {"Encrypt"}),
          "Encryption Only — Linear",
          "line_encrypt_no_aes_log.png", log=True)

line_plot(filter_data(NO_AES, {"Decrypt"}),
          "Decryption Only — Linear",
          "line_decrypt_no_aes_log.png", log=True)

bar_plot(filter_data(NO_AES, {"Encrypt"}),
         "Encryption Only — Linear Bars",
         "bar_encrypt_no_aes_log.png", log=True)

bar_plot(filter_data(NO_AES, {"Decrypt"}),
         "Decryption Only — Linear Bars",
         "bar_decrypt_no_aes_log.png", log=True)
print(f"Saved {len(list(OUT.glob('*.png')))} plots to {OUT.resolve()}")
