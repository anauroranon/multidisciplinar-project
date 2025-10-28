#!/usr/bin/env python3
"""
extract_features.py

Estrae un Function Call Graph (FCG) di base e alcune feature per funzione
da un ELF ARM/Linux usando angr. Salva i grafi in NetworkX + JSON.

Uso:
    python3 scripts/extract_features.py --binary ../examples/test_bin --outdir ../outputs/graphs
"""
import argparse
import json
import math
import os
from tqdm import tqdm

import angr
import networkx as nx
import numpy as np

# try optional capstone import for fallback disassembly
try:
    import capstone  # type: ignore
    HAS_CAPSTONE = True
except Exception:
    HAS_CAPSTONE = False


def shannon_entropy(data_bytes: bytes) -> float:
    if not data_bytes:
        return 0.0
    counts = np.bincount(np.frombuffer(data_bytes, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / float(len(data_bytes))
    return -float(np.sum(probs * np.log2(probs)))


def try_get_insns_from_block(proj, blk):
    """
    Return a list-like of lightweight insn objects with attributes:
      - mnemonic (str)
      - operands (list-like or empty)  (may not have imm)
      - op_str (str)  (string operands)
    Prefer angr's capstone wrapper (blk.capstone.insns). If not available,
    try capstone python binding to disassemble the bytes as fallback.
    If nothing works, return None.
    """
    # 1) prefer angr's capstone wrapper
    try:
        if hasattr(blk, "capstone") and getattr(blk.capstone, "insns", None):
            return blk.capstone.insns
    except Exception:
        pass

    # 2) fallback: try python-capstone if available
    if not HAS_CAPSTONE:
        return None

    archname = proj.arch.name.lower() if hasattr(proj, "arch") else ""
    cs = None
    try:
        if "aarch64" in archname or "arm64" in archname or "aarch" in archname:
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        elif "arm" in archname:
            # simple choice: ARM mode (not Thumb). This is a best-effort fallback.
            cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM + capstone.CS_MODE_LITTLE_ENDIAN)
        else:
            # unsupported architecture for this fallback
            return None
    except Exception:
        return None

    # create lightweight wrappers from capstone disasm results
    try:
        insns = []
        for insn in cs.disasm(blk.bytes, blk.addr):
            # build a tiny object similar to angr.capstone insn
            class I:
                pass

            i = I()
            i.mnemonic = insn.mnemonic
            i.op_str = insn.op_str
            # create a simple operands list with possible imm attribute if op_str contains hex
            # this is best-effort; not as rich as angr.capstone
            i.operands = []
            # try to extract a single immediate value if present like "0x401000" or "#0x401000"
            op_imm = None
            if insn.op_str:
                s = insn.op_str.split(',')[0].strip()
                # remove leading '#' or other chars
                s2 = s.lstrip('#')
                if s2.startswith("0x"):
                    try:
                        op_imm = int(s2, 16)
                    except Exception:
                        op_imm = None
            if op_imm is not None:
                class Op: pass
                o = Op()
                o.imm = op_imm
                i.operands = [o]
            insns.append(i)
        return insns
    except Exception:
        return None


def analyze_insns_list(insns):
    """
    Given an iterable of insn-like objects (with .mnemonic, .operands, .op_str),
    return (total_inst, bl_direct, bl_indirect, svc_count).
    """
    total_inst = 0
    bl_direct = 0
    bl_indirect = 0
    svc_count = 0

    for insn in insns:
        try:
            total_inst += 1
            mnem = insn.mnemonic.lower()
            # direct branch-with-link: bl, blx (immediate)
            if mnem in ("bl", "blx"):
                # try operand imm
                imm = None
                try:
                    if getattr(insn, "operands", None):
                        op0 = insn.operands[0]
                        imm = getattr(op0, "imm", None)
                except Exception:
                    imm = None
                # fallback: try parse op_str hex
                if imm is None:
                    op_str = getattr(insn, "op_str", "")
                    if op_str:
                        s = op_str.split()[0].lstrip('#')
                        if s.startswith("0x"):
                            try:
                                imm = int(s, 16)
                            except Exception:
                                imm = None
                if imm is not None:
                    bl_direct += 1
                else:
                    bl_indirect += 1
            # register indirect calls: blr (AArch64), bx (ARM)
            elif mnem in ("blr", "bx"):
                bl_indirect += 1
            # syscall detection: svc (both ARM and AArch64), swi (older ARM)
            elif mnem in ("svc", "swi"):
                svc_count += 1
        except Exception:
            continue

    return total_inst, bl_direct, bl_indirect, svc_count


def extract_function_features(func, proj):
    """
    Compute per-function features using angr.Function and project.
    Returns a dict of features.
    """
    feats = {}
    feats["addr"] = func.addr
    feats["name"] = getattr(func, "name", hex(func.addr))
    try:
        block_addrs = list(func.block_addrs_set)
    except Exception:
        block_addrs = []
    feats["n_blocks"] = len(block_addrs)

    total_bytes = 0
    instr_count_est = 0
    bl_count = 0
    bl_indirect_count = 0
    svc_count = 0
    block_entropies = []

    for baddr in block_addrs:
        try:
            blk = proj.factory.block(baddr)
        except Exception:
            continue
        bbytes = blk.bytes or b""
        total_bytes += len(bbytes)
        block_entropies.append(shannon_entropy(bbytes))

        insns = try_get_insns_from_block(proj, blk)
        if insns is not None:
            tinst, bl_d, bl_i, svc_c = analyze_insns_list(insns)
            instr_count_est += int(tinst)
            bl_count += int(bl_d)
            bl_indirect_count += int(bl_i)
            svc_count += int(svc_c)
        else:
            # fallback: cannot disassemble -> leave zeros / best-effort
            pass

    feats["total_bytes"] = total_bytes
    feats["avg_block_entropy"] = float(np.mean(block_entropies)) if block_entropies else 0.0
    feats["std_block_entropy"] = float(np.std(block_entropies)) if block_entropies else 0.0
    feats["bl_count"] = int(bl_count)
    feats["bl_indirect_count"] = int(bl_indirect_count)
    feats["svc_count"] = int(svc_count)
    feats["avg_bytes_per_block"] = float(total_bytes) / (len(block_addrs) + 1e-9)
    feats["instr_count_est"] = int(instr_count_est)

    return feats


def build_fcg_and_features(binary_path, outdir, load_options=None):
    print(f"[+] Loading {binary_path} with angr...")
    proj = angr.Project(binary_path, auto_load_libs=False, load_options=load_options or {})

    # print detected architecture (helpful)
    archname = proj.arch.name if hasattr(proj, "arch") else "unknown"
    print(f"[+] Detected architecture: {archname}")

    print("[+] Building CFG (CFGFast) — questo può richiedere tempo...")
    cfg = proj.analyses.CFGFast(normalize=True)
    kb = cfg.kb

    print("[+] Estrazione funzioni e feature...")
    functions = list(kb.functions.values())
    addr2func = {f.addr: f for f in functions}

    G = nx.DiGraph()

    # create nodes with features
    for f in tqdm(functions, desc="funzioni"):
        feats = extract_function_features(f, proj)
        G.add_node(feats["addr"], **feats)

    # build edges: attempt resolving BL/BLX immediates to functions
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
            insns = try_get_insns_from_block(proj, blk)
            if insns is None:
                continue
            for insn in insns:
                try:
                    mnem = insn.mnemonic.lower()
                except Exception:
                    continue
                if mnem in ("bl", "blx"):
                    # try operand imm first
                    target = None
                    try:
                        if getattr(insn, "operands", None):
                            op0 = insn.operands[0]
                            target = getattr(op0, "imm", None)
                    except Exception:
                        target = None
                    # fallback: parse op_str hex
                    if target is None:
                        op_str = getattr(insn, "op_str", "")
                        if op_str:
                            s = op_str.split()[0].lstrip("#")
                            if s.startswith("0x"):
                                try:
                                    target = int(s, 16)
                                except Exception:
                                    target = None
                    if target:
                        # map target to function
                        if target in addr2func:
                            G.add_edge(f.addr, target)
                        else:
                            for cand in functions:
                                try:
                                    if cand.addr <= target < cand.addr + max(1, getattr(cand, "size", 0)):
                                        G.add_edge(f.addr, cand.addr)
                                        break
                                except Exception:
                                    continue

    # save outputs
    os.makedirs(outdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(binary_path))[0]
    graphml_path = os.path.join(outdir, f"{base}_fcg.graphml")
    json_path = os.path.join(outdir, f"{base}_fcg.json")

    print(f"[+] Salvando graphml -> {graphml_path}")
    nx.write_graphml(G, graphml_path)

    print(f"[+] Salvando nodo-features JSON -> {json_path}")
    nodes = {}
    for n, d in G.nodes(data=True):
        # json-serializable
        nodes[str(n)] = {
            k: (float(v) if isinstance(v, (int, float, np.floating, np.integer)) else v)
            for k, v in d.items()
        }
    with open(json_path, "w") as f:
        json.dump({"binary": binary_path, "n_nodes": G.number_of_nodes(), "n_edges": G.number_of_edges(), "nodes": nodes}, f, indent=2)

    print("[+] Done.")
    return graphml_path, json_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract FCG + basic features from ARM ELF using angr")
    parser.add_argument("--binary", required=True, help="percorso al binario ELF (ARM)")
    parser.add_argument("--outdir", required=True, help="directory di output")
    args = parser.parse_args()

    build_fcg_and_features(args.binary, args.outdir)
