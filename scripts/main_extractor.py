#!/usr/bin/env python3
# scripts/run_minimal.py
import os
import argparse
from pathlib import Path
import multiprocessing as mp
import traceback
import time
import signal

# importa i tuoi script principali come funzioni
from extract_fcg import build_fcg_and_features
from extract_icfg import extract_icfg

CFG_FCG_TIMEOUT = 600    # 10 minuti per FCG/CFG-heavy function (esempio)
ICFG_TIMEOUT    = 1200   # 20 minuti per ICFG (se preferisci separare)

SCRIPTS = [
    "scripts/extract_fcg.py",
    "scripts/extract_icfg.py",
]

def _target_wrapper(func, args, kwargs, result_queue):
    """
    Wrapper eseguito nel processo figlio. Chiama func(*args, **kwargs).
    Scrive sul result_queue una tupla (True, None) se OK, o (False, errstr) se eccezione.
    NOTA: func deve essere definita a livello di modulo (importable), non lambda locale.
    """
    try:
        func(*args, **(kwargs or {}))
        result_queue.put((True, None))
        
    except Exception:
        tb = traceback.format_exc()
        result_queue.put((False, tb))

def run_with_timeout(func, args=(), kwargs=None, timeout_seconds=600):
    """
    Esegue func(*args, **kwargs) in un processo separato.
    - Se termina entro timeout: ritorna (True, None).
    - Se solleva eccezione: ritorna (False, traceback_string).
    - Se non termina entro timeout: uccide il processo e ritorna (None, "timeout").
    Importante: func deve essere un callable top-level (non lambda, non closure).
    """
    
    q = mp.Queue()
    p = mp.Process(target=_target_wrapper, args=(func, args, kwargs, q))
    p.start()
    p.join(timeout_seconds)
    if p.is_alive():
        try:
            # prova a terminare ordinatamente, poi forzatamente
            p.terminate()
            time.sleep(0.5)
            if p.is_alive():
                os.kill(p.pid, signal.SIGKILL)
        except Exception:
            pass
        return (None, f"timeout after {timeout_seconds}s")
    # processo terminato: leggo risultato
    try:
        ok, payload = q.get_nowait()
        if ok:
            return (True, None)
        else:
            return (False, payload)
    except Exception:
        # niente messaggi: può succedere se il figlio è terminato brutalmente
        return (False, "no-result-from-child")


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

    # timeout (in secondi)
    FCG_TIMEOUT = 600        # 10 minuti per call graph
    ICFG_TIMEOUT = 900       # 15 minuti per ICFG

    for f in files:
        stem = f.stem
        dest = outbase / stem
        os.makedirs(dest, exist_ok=True)

        print(f"\n=== Processing {f} ===")

        # 1. FUNCTION CALL GRAPH (FCG)
        status, info = run_with_timeout(
            build_fcg_and_features, args=(str(f), str(dest)),
            kwargs={"load_options": None},
            timeout_seconds=FCG_TIMEOUT
        )
        if status is True:
            print(f"[+] build_fcg_and_features OK for {f}")
        elif status is None:
            print(f"[!] build_fcg_and_features TIMEOUT for {f}: {info}")
        else:
            print(f"[!] build_fcg_and_features ERROR for {f}: {info}")

        # 2. INTERPROCEDURAL CONTROL FLOW GRAPH (ICFG)
        status, info = run_with_timeout(
            extract_icfg, args=(str(f), str(dest)),
            timeout_seconds=ICFG_TIMEOUT
        )
        if status is True:
            print(f"[+] extract_icfg OK for {f}")
        elif status is None:
            print(f"[!] extract_icfg TIMEOUT for {f}: {info}")
        else:
            print(f"[!] extract_icfg ERROR for {f}: {info}")

    print("\n=== All files processed ===")

if __name__ == "__main__":
    main()
