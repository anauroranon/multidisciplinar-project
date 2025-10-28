#!/usr/bin/env python3
# scripts/extract_icfg.py
import argparse, os, json
import networkx as nx
import angr
from tqdm import tqdm
import numpy as np
from pathlib import Path
import json

def shannon_entropy(data_bytes: bytes) -> float:
    if not data_bytes:
        return 0.0
    counts = np.bincount(np.frombuffer(data_bytes, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / float(len(data_bytes))
    return -float((probs * np.log2(probs)).sum())

def extract_icfg(binary, outdir):
    proj = angr.Project(binary, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    G = nx.DiGraph()
    # cfg.graph nodes are CFGNode objects
    for node in tqdm(list(cfg.graph.nodes()), desc="adding nodes"):
        try:
            addr = node.addr
        except Exception:
            continue
        size = getattr(node, "size", None) or 0
        # try block bytes via proj.factory.block (best-effort)
        try:
            blk = proj.factory.block(addr)
            bbytes = blk.bytes
            ent = shannon_entropy(bbytes)
        except Exception:
            ent = 0.0
            size = size or 0
        G.add_node(str(addr), addr=addr, size=size, entropy=float(ent))
    # edges: use cfg.graph edges (node->succ_node)
    for src, dst in tqdm(cfg.graph.edges(), desc="adding edges"):
        try:
            sa = str(src.addr)
            da = str(dst.addr)
            G.add_edge(sa, da)
        except Exception:
            continue
    os.makedirs(outdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(binary))[0]
    gpath = os.path.join(outdir, base + "_icfg.graphml")
    nx.write_graphml(G, gpath)
    print("[+] Saved ICFG ->", gpath)
        # Create json file
    graphml_path = os.path.join(outdir, f"{base}_icfg.graphml")
    nodes_json_path = Path(graphml_path).with_name(Path(graphml_path).stem + "_icfg.json")
    
    nodes = {}
    
    for n, d in G.nodes(data=True):
        # serializzabile: converti eventuali numpy types ecc.
        serial = {}
        for k, v in d.items():
            try:
                # prova a forzare numeri a float/int
                if hasattr(v, "item"):
                    v = v.item()
            except Exception:
                pass
            serial[k] = v
        nodes[str(n)] = serial
    with open(nodes_json_path, "w") as f:
        json.dump({"binary": binary, "n_nodes": len(nodes), "nodes": nodes}, f, indent=2)
        
    return gpath

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True)
    p.add_argument("--outdir", required=True)
    args = p.parse_args()
    extract_icfg(args.binary, args.outdir)
