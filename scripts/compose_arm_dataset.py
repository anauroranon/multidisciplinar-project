#!/usr/bin/env python3
"""
move_arm_samples.py

Cerca ricorsivamente nelle directory sorgente e sposta nella dest_dir
solo i file ELF che sembrano essere ARM (32-bit) o AArch64 (ARM64).

Uso:
    python3 scripts/move_arm_samples.py
"""

import subprocess
import os
import shutil
from pathlib import Path

# --- CONFIGURA QUI ---
SRC_DIRS = [
    "/home/kali/Desktop/Lucca/Lucca_samples/samples",
    "/home/kali/Desktop/Lucca/Lucca_samples/samples_mb",
    "/home/kali/Desktop/Lucca/Lucca_samples/samples_ms",
]
DEST_DIR = "/home/kali/Desktop/Lucca/multidisciplinar-project/examples"
# ----------------------

def detect_arch_via_file(path: str):
    """
    Usa il comando `file` per ottenere una descrizione. Ritorna:
      - "arm32" se ELF 32-bit ARM
      - "arm64" se ELF 64-bit AArch64/ARM64
      - None altrimenti
    """
    try:
        out = subprocess.check_output(["file", "-b", path], stderr=subprocess.DEVNULL)
        txt = out.decode(errors="ignore").lower()
    except Exception:
        return None

    # deve essere ELF
    if "elf" not in txt:
        return None

    # cerca aarch64/arm64
    if "aarch64" in txt or "arm64" in txt or "arm aarch64" in txt:
        return "arm64"

    # cerca ARM (32-bit): presenza di 'arm' + '32-bit' o 'elf32'
    if ("arm" in txt or "armeabi" in txt) and ("32-bit" in txt or "elf32" in txt):
        return "arm32"

    # talvolta file dice "elf 64-bit ... arm" (rare), cogliere anche questo
    if "arm" in txt and "64-bit" in txt:
        # se contiene aarch64 preferiamo arm64, altrimenti tenta di interpretare:
        if "aarch64" in txt or "arm64" in txt:
            return "arm64"
        # se è "arm" + "64-bit" potrebbe essere AArch64 descriptive - consideralo arm64
        return "arm64"

    return None

def safe_move(src_path: Path, dest_dir: Path):
    """
    Sposta src_path dentro dest_dir evitando sovrascritture; ritorna il percorso di destinazione finale.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    base = src_path.name
    candidate = dest_dir / base
    if not candidate.exists():
        shutil.move(str(src_path), str(candidate))
        return candidate
    # se esiste, aggiungi suffix numerico
    stem = src_path.stem
    suffix = src_path.suffix
    i = 1
    while True:
        newname = f"{stem}_{i}{suffix}"
        candidate = dest_dir / newname
        if not candidate.exists():
            shutil.move(str(src_path), str(candidate))
            return candidate
        i += 1

def main():
    dest = Path(DEST_DIR)
    moved = []
    skipped = []
    errors = []

    print("Starting scan...")
    for src in SRC_DIRS:
        p = Path(src)
        if not p.exists():
            print(f"[!] Source dir not found: {src} — skipping")
            continue
        # walk recursively
        for root, dirs, files in os.walk(p):
            for fname in files:
                fpath = Path(root) / fname
                try:
                    arch = detect_arch_via_file(str(fpath))
                    if arch in ("arm32", "arm64"):
                        newpath = safe_move(fpath, dest)
                        moved.append((str(fpath), arch, str(newpath)))
                        print(f"[MOVED] {fpath} -> {newpath} [{arch}]")
                    else:
                        skipped.append((str(fpath), arch))
                except Exception as e:
                    errors.append((str(fpath), str(e)))
                    print(f"[ERROR] {fpath}: {e}")

    # report
    print("\n--- Report ---")
    print(f"Total moved: {len(moved)}")
    if moved:
        # print sample moved (up to 20)
        for old, arch, new in moved[:20]:
            print(f"  {arch:6} {old} -> {new}")
        if len(moved) > 20:
            print(f"  ... ({len(moved)-20} other files moved)")

    print(f"Total skipped (non-ARM or non-ELF): {len(skipped)}")
    print(f"Total errors: {len(errors)}")
    if errors:
        print("Errors (first 10):")
        for p, msg in errors[:10]:
            print(f"  {p}: {msg}")

    print("\nDone.")

if __name__ == "__main__":
    main()
