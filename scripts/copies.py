#!/usr/bin/env python3
"""
copy_binaries.py

Copia una lista di binari dalla directory sorgente alla directory di destinazione.
Mantiene metadata (shutil.copy2) e permessi. Log delle operazioni su stdout e su copy_log.txt.

Esempio:
    python3 copy_binaries.py
    python3 copy_binaries.py --dry-run
"""

import argparse
import os
import shutil
import stat
from pathlib import Path
from datetime import datetime

# --- CONFIGURAZIONE ---
SRC_DIR = Path("/home/kali/Desktop/Lucca/multidisciplinar-project/samples/dataset")
DST_DIR = Path("/home/kali/Desktop/Pipeline/Emulix/MalwareTestLucca")
LOG_FILE = Path("copy_log.txt")

# Lista file (prendi la lista che hai fornito; i prefissi './' verranno rimossi)
FILES = [
"523a12384d5cee63b2efe00cf339c3b3faaecabae1856aec70c24ae5f17d228d",
"a8ea42d4697524b705fe3e7f4e2763fb8284a9e7d5ca14aa0601b466c3eec663.elf",
"fe9a5117526681f8c5c0b73d9ebca60f64b3c534c000374b1fe3f70dbc462a27.elf",
"52450ef60f45875618617577b58721fd0717d0a0338546466e4bdc4a6abfbc74.elf",
"a907ac4296193739f1b46741755796e0754d752177ba864a39f19f54fe48d585",
"fead5edb8d30c8d00485ba670e2dc4cbba9fdb50d9a263e91f6c3903166964d8",
"5255ea080acd85ad274c48d1c4254c285c24f5ea67787666005c9a47c62ceb70.elf",
"a90c09ca384feaa4b7e111549bdafddbc778314257606ef61a6822c1cedb25cf.elf",
"fead8c91d255098845ec9d2f64aa4d83551a67982e835057942d8332fbff5846.elf",
"5262023234a81b543a4ba941d9823aa317af3f356104e0bccd401d48c48c0cbd.elf",
"a9136ba336d6aa712c9d5d8debda8c8213c5cbe8c97873d3ced547a17777d936",
"feb14ef81281b00924d0c78d9d43e1aa42aab6022ee3a32f058833d545c201e2.elf",
"526f2ae091dbc13503477f5864561ab3b7853e79626cf59895c14460048c488c",
"a91a6d2e12fe026387307c61b69e5bc1ce76ec13b6edc3956857761e6e862d91.elf",
"fecd44787ca06f8f15164603d237ea94887b33eafe701d4a25095bb53d7a2ccb",
"5279de675901f8872c7b1330cfd01d48fc48d734bf7a40dcd2a285e36950827f",
"a91f60d34f0dc2d8b87120c8a7afb1138c3ba704e1ef541692febf3efbedb68d.elf",
"fed296a0bfecf663b856e305b871d5a1e90ece630cf3a890f1c6f95f87fedb14.elf",
"52a336b80fde5c6905c8c3d50aca68413c31b4674788eb60cea6d1e288abc55f.elf",
"a9417c769d5a91ea0bb7aefcf731027b6514c49f443493eae9b36a3fc8017ab2.elf",
"fee4ec3f6688219882ffe2ea0d3dfc6e34fcbb438d8ed9870ece123542a0a46b.elf",
"52ae50d4e05b6d896ca802af127a20ee53586e28fcef528cc894497fdbde1cb4",
"a95bf8d7a623a3c6d94344895d16e823644b276b8491c9916c6dd8f5652832b4",
"feec14ab9c4fe8cdb71d6a762178a491581be4ab3ac43e42d7608c3b0dc8a50e.elf",
"52e7e5a3f3567ae544c1850b9fa8cdccab2ba12a54d80407c68706a9e98ea0d2",
"a9a71e3ce8eb2eec7292e3b332909e6df43954374d7fbc432d0591070cae3821.elf",
"ff072a837e69357cb2a83aff93b0bdc760f0f9f61bceca15acdd98bc64aa8307",
"52e8a4647623af431a0a384f7d7b31a142f3195a1366288dba78a10564640bc8.elf",
"a9ba2816c2d182434c1c7dbc8beea4d36c423ac8d684da36ab3efde12e46bcca.elf",
"ff0d4706c3c1b974c12936a07e5a36bdb466078b519ec6c0e432f9c81fdb7f3c",
"52ecac9df01575997255c814321ee1484390511e7d3f365b87b2d8023d65605c.elf",
"a9bf56ac1ce2100de39523f67b6d5a6ba5394808efab8173247d1e16ed17f631",
"ff4f1c690384b581cb3bdea7d006ef9d68836591d6f5c5397a3b760ffd2c0696.elf",
"52fca1acdfa27599d218a1a04383ac3842aa1a4b48dfdb346e8659fefdff8230.elf",
"a9d077838d4a99f51cf56e2d2a05c4ca3e1606daabf8c3f798969a54afdb66a3.elf",
"ff5629ee5b6856b8727c164dda0721772c3b46c4a0e547ea29f2365fcd81201b",
"533785389f1a0495bd43e79bc8e46b2dac167de5846240be2b20c342fd657924.elf",
"a9dc4c5b13ad831a6f2ef940a70c1eb9a1d3cfc21357488f689baf9b24e0667e.elf",
"ff6ec368a763d9b81e7a820aacbf1dbefcb725d9d90cb047e8dcf254f12dbc7e.elf",
]

# --- FUNZIONI ---
def is_executable(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except Exception:
        return False

def copy_file(src: Path, dst: Path, dry_run: bool=False) -> bool:
    """Copia src -> dst, mantenendo metadata. Restituisce True se copiato con successo."""
    if not src.exists():
        return False
    if dry_run:
        return True
    # assicura cartella destinazione esista
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    # prova a preservare bit eseguibile (se lo era)
    try:
        if is_executable(src):
            st = src.stat()
            os.chmod(dst, st.st_mode)
    except Exception:
        pass
    return True

def log(msg: str):
    timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
    line = f"[{timestamp}] {msg}"
    print(line)
    with LOG_FILE.open("a") as f:
        f.write(line + "\n")

# --- MAIN ---
def main():
    parser = argparse.ArgumentParser(description="Copia binari da SRC_DIR a DST_DIR (lista incorporata)")
    parser.add_argument("--dry-run", action="store_true", help="Non copiare nulla, mostra solo cosa verrebbe copiato")
    parser.add_argument("--src", type=str, default=str(SRC_DIR), help="Directory sorgente")
    parser.add_argument("--dst", type=str, default=str(DST_DIR), help="Directory destinazione")
    args = parser.parse_args()

    src_dir = Path(args.src)
    dst_dir = Path(args.dst)

    log(f"Avvio copia: src={src_dir} -> dst={dst_dir} (dry_run={args.dry_run})")
    copied = 0
    missing = []

    for name in FILES:
        clean_name = name.lstrip("./")  # rimuove eventuale prefisso ./ nella lista
        src_path = src_dir / clean_name
        dst_path = dst_dir / clean_name

        if src_path.exists():
            if args.dry_run:
                log(f"[DRY] Presente: {src_path} -> {dst_path}")
                copied += 1
            else:
                try:
                    copy_file(src_path, dst_path, dry_run=False)
                    log(f"Copiato: {src_path} -> {dst_path}")
                    copied += 1
                except Exception as e:
                    log(f"ERRORE copiando {src_path}: {e}")
        else:
            log(f"MANCANTE: {src_path}")
            missing.append(str(src_path))

    log(f"Operazione completata. Copiati: {copied}. Mancanti: {len(missing)}.")
    if missing:
        log("Elenco file mancanti (vedi sopra):")
        for m in missing:
            log(f"  - {m}")

if __name__ == "__main__":
    main()
