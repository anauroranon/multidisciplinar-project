#!/usr/bin/env python3
"""
extract_features.py

Estrae un Function Call Graph (FCG) di base e alcune feature per funzione
da un ELF ARM/Linux usando angr. Salva i grafi in NetworkX + JSON.

Uso:
    python3 extract_features.py --binary ../examples/test_bin --outdir ../outputs/graphs
"""

import angr
import networkx as nx
import os
import json
import math
import argparse
from tqdm import tqdm
import numpy as np

def shannon_entropy(data_bytes: bytes) -> float:
    if not data_bytes:
        return 0.0
    counts = np.bincount(np.frombuffer(data_bytes, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / float(len(data_bytes))
    return -float(np.sum(probs * np.log2(probs)))

def func_to_dict(func, proj):
    """
    Calcola feature semplici per una funzione angr.Function
    """
    feats = {}
    # indirizzo funzione
    feats['addr'] = func.addr
    feats['name'] = func.name if hasattr(func, 'name') else hex(func.addr)
    # basic block addresses (set)
    try:
        block_addrs = list(func.block_addrs_set)
    except Exception:
        # fallback: empty
        block_addrs = []
    feats['n_blocks'] = len(block_addrs)

    total_bytes = 0
    total_inst = 0
    svc_count = 0         # syscall-like (ARM: svc)
    bl_count = 0          # call-like (ARM BL/BLX)
    block_entropies = []

    for baddr in block_addrs:
        try:
            blk = proj.factory.block(baddr)
        except Exception:
            continue
        bbytes = blk.bytes
        total_bytes += len(bbytes)
        block_entropies.append(shannon_entropy(bbytes))

        # cerca istruzioni BL/BLX/SVC via capstone (capstone wrapper in angr block)
        try:
            for insn in blk.capstone.insns:
                mnem = insn.mnemonic.lower()
                total_inst += 1
                if mnem.startswith('bl'):    # bl, blx, blx+ etc.
                    bl_count += 1
                if mnem == 'svc':           # syscall in ARM
                    svc_count += 1
        except Exception:
            # se capstone non disponibile, fai best-effort contando bytes
            pass

    feats['total_bytes'] = total_bytes
    feats['avg_block_entropy'] = float(np.mean(block_entropies)) if block_entropies else 0.0
    feats['std_block_entropy'] = float(np.std(block_entropies)) if block_entropies else 0.0
    feats['bl_count'] = bl_count
    feats['svc_count'] = svc_count
    feats['avg_bytes_per_block'] = float(total_bytes) / (len(block_addrs) + 1e-9)
    feats['instr_count_est'] = total_inst

    return feats

def build_fcg_and_features(binary_path, outdir, load_options=None):
    print(f"[+] Loading {binary_path} with angr...")
    proj = angr.Project(binary_path, auto_load_libs=False, load_options=load_options or {})

    print("[+] Building CFG (CFGFast) — questo può richiedere tempo...")
    cfg = proj.analyses.CFGFast(normalize=True)  # cfg_fast
    kb = cfg.kb

    print("[+] Estrazione funzioni e feature...")
    functions = list(kb.functions.values())
    # mappa address -> function object
    addr2func = {f.addr: f for f in functions}

    # costruisco un grafo directed: nodo = funzione (address), bordo = chiamata (se facilmente risolvibile)
    G = nx.DiGraph()

    # prima: crea nodi con feature
    for f in tqdm(functions, desc="funzioni"):
        feats = func_to_dict(f, proj)
        G.add_node(feats['addr'], **feats)

    # poi: cerca chiamate BL/BLX nelle funzioni e prova a risolvere target a funzione nota
    print("[+] Costruzione archi chiamata (tentativo statico usando BL/BLX immediate)...")
    for f in tqdm(functions, desc="edge-building"):
        try:
            block_addrs = list(f.block_addrs_set)
        except Exception:
            block_addrs = []
        for baddr in block_addrs:
            try:
                blk = proj.factory.block(baddr)
            except Exception:
                continue
            try:
                for insn in blk.capstone.insns:
                    mnem = insn.mnemonic.lower()
                    # BL/BLX tipicamente hanno un immediate verso target
                    if mnem.startswith('bl'):
                        # prova a leggere l'operando immediato
                        try:
                            target = None
                            # capstone operand extraction (best-effort)
                            if len(insn.operands) >= 1:
                                op0 = insn.operands[0]
                                # capstone representazione: imm in op0.imm
                                target = getattr(op0, 'imm', None)
                            if target is None:
                                # fallback: prova op_str parsing
                                if insn.op_str:
                                    s = insn.op_str.split()[0]
                                    try:
                                        target = int(s, 16)
                                    except Exception:
                                        target = None
                            if target:
                                # trova funzione che contiene target (best-effort)
                                if target in addr2func:
                                    G.add_edge(f.addr, target)
                                else:
                                    # cerca funzione la cui range include target
                                    for cand in functions:
                                        try:
                                            if cand.addr <= target < cand.addr + max(1, cand.size):
                                                G.add_edge(f.addr, cand.addr)
                                                break
                                        except Exception:
                                            continue
                        except Exception:
                            continue
            except Exception:
                continue

    # salva grafo come GraphML e JSON node-feats (leggibile)
    os.makedirs(outdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(binary_path))[0]
    graphml_path = os.path.join(outdir, f"{base}_fcg.graphml")
    json_path = os.path.join(outdir, f"{base}_nodes.json")

    print(f"[+] Salvando graphml -> {graphml_path}")
    nx.write_graphml(G, graphml_path)

    print(f"[+] Salvando nodo-features JSON -> {json_path}")
    nodes = {}
    for n, d in G.nodes(data=True):
        # json-serializable
        nodes[str(n)] = {k: (float(v) if isinstance(v, (int, float, np.floating, np.integer)) else v) for k, v in d.items()}
    with open(json_path, 'w') as f:
        json.dump({
            "binary": binary_path,
            "n_nodes": G.number_of_nodes(),
            "n_edges": G.number_of_edges(),
            "nodes": nodes
        }, f, indent=2)

    print("[+] Done.")
    return graphml_path, json_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract FCG + basic features from ARM ELF using angr")
    parser.add_argument("--binary", required=True, help="percorso al binario ELF (ARM)")
    parser.add_argument("--outdir", required=True, help="directory di output")
    args = parser.parse_args()

    build_fcg_and_features(args.binary, args.outdir)
