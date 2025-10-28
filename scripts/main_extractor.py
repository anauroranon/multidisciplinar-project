#!/usr/bin/env python3
# scripts/run_minimal.py
import os
import subprocess
import argparse
from pathlib import Path

SCRIPTS = [
    "scripts/extract_fcg.py",
    "scripts/extract_icfg.py",
    "scripts/extract_import_graph.py",
]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--src", required=True, help="source dir with samples (recursive)")
    p.add_argument("--outdir", default="outputs/dataset", help="base output dir")
    p.add_argument("--ext", nargs="*", default=None, help="optional extensions filter, e.g. .elf .bin")
    args = p.parse_args()

    src = Path(args.src)
    outbase = Path(args.outdir)
    outbase.mkdir(parents=True, exist_ok=True)

    files = [f for f in src.rglob("*") if f.is_file()]
    if args.ext:
        exts = [e.lower() for e in args.ext]
        files = [f for f in files if f.suffix.lower() in exts]

    for f in files:
        stem = f.stem
        dest = outbase / stem
        os.makedirs(dest, exist_ok=True)
        for s in SCRIPTS:
            # EXACT command you requested
            cmd = ["python3", s, "--binary", str(f), "--outdir", str(dest)]
            subprocess.run(cmd)

if __name__ == "__main__":
    main()
