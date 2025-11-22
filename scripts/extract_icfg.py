#!/usr/bin/env python3
# scripts/extract_icfg.py
""""
    Extract the ICFG with angr.
    *A basic block is the atomic chunk of machine code angr extracts from the binary. 
    A block is literally defined by raw bytes until the next terminator instruction. The finest static unit before individual instruction *


"""

import argparse, os, json
import networkx as nx
import angr
from tqdm import tqdm
import numpy as np
from pathlib import Path
import json
from cg_saver import PartialSaver

"""
    Computer the Shannon entropy on a byte sequence.
    Calcola la Shannon entropy su una sequenza di byte.
    La usiamo come proxy veloce per capire quanto un basic block
    sembri casuale / compresso / offuscato.
"""
def shannon_entropy(data_bytes: bytes) -> float:
    # Checks if are bytes (the entropy is calculated on bytes sequences
    if not data_bytes:
        return 0.0
    
    # Istogramma dei valori da 0 a 255
    counts = np.bincount(np.frombuffer(data_bytes, dtype=np.uint8), minlength=256) 
    probs = counts[counts > 0] / float(len(data_bytes))
    return -float((probs * np.log2(probs)).sum())

def extract_icfg(binary, outdir):
    """
    Costruisce un Interprocedural Control Flow Graph (ICFG) per `binary`.

    - carica il binario in angr (senza librerie condivise)
    - esegue CFGFast per ottenere il CFG globale a livello di basic block
    - per ogni nodo del CFG:
        * ricava indirizzo, dimensione e bytes del basic block
        * calcola la entropia dei bytes
        * aggiunge un nodo al grafo NetworkX con questi attributi
    - per ogni edge del CFG:
        * aggiunge un arco diretto nel grafo NetworkX (src -> dst)
    - serializza:
        * <outdir>/<nome>_icfg.graphml  (struttura del grafo)
        * <outdir>/<nome>_icfg.json     (lista dei nodi + attributi)

    Ritorna il percorso al file .graphml.
    """
    ### MAIN COMPUTATION OF ANGR
    proj = angr.Project(binary, auto_load_libs=False) # Loading su angr del binario. no librerie condivise.
    cfg = proj.analyses.CFGFast(normalize=True) # extracts Control Flow Graph
    
    G = nx.DiGraph() # Initializes the graph to be filled with cfg info

    # --- Partial saver ---
    sample_id = Path(binary).stem
    saver = PartialSaver(out_dir=outdir, sample_id=sample_id, flush_every=200)

    ### WORKING ON THE NODES
    for node in tqdm(list(cfg.graph.nodes()), desc="adding nodes"): # Iterates the nodes of the extracted graph (basic block)
        try:
            addr = node.addr # Takes the virtual address
        except Exception:
            continue
        size = getattr(node, "size", None) or 0 # Takes the size of the block (number of bytes)
        # try block bytes via proj.factory.block (best-effort)
        try:
            blk = proj.factory.block(addr) # instructs angr to build a BasicBlock object starting at the given address. It decodes the next basic block, find its size, and give both the instructions and the underlying bytes.
            bbytes = blk.bytes #byte sequence of the block as it is in the binary
            ent = shannon_entropy(bbytes) # calucaltes the shannon entropy of the bytes of the block (node)
        except Exception:
            ent = 0.0 # If fails, the entropy is set to 0
            size = size or 0

        G.add_node(str(addr), addr=addr, size=size, entropy=float(ent)) #Adding the node with extracted features

        # --- append parziale del nodo ---
        try:
            saver.append("icfg", {
                "kind": "node",
                "addr": int(addr),
                "size": int(size),
                "entropy": float(ent)
            })
        except Exception:
            pass  # mai bloccare l’analisi per il salvataggio parziale

    ### WORKING ON THE EDGES
    for src, dst in tqdm(cfg.graph.edges(), desc="adding edges"): # Iterates the edges of the extracted graph (jumps)
        try:
            source_addr = str(src.addr)
            dest_addr = str(dst.addr)
            G.add_edge(source_addr, dest_addr) #adding it in the graph
            # --- NEW: append parziale dell’arco ---
            try:
                saver.append("icfg", {
                    "kind": "edge",
                    "src": int(src.addr),
                    "dst": int(dst.addr)
                })
            except Exception:
                pass
        except Exception:
            continue

    ### OUTPUT  
    # Graph file
    os.makedirs(outdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(binary))[0]
    gpath = os.path.join(outdir, base + "_icfg.graphml")
    nx.write_graphml(G, gpath)
    print("[+] Saved ICFG ->", gpath)

    # JSON file
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
    
    p.add_argument("--binary", required=True) # Binary from which extract the ICFG
    p.add_argument("--outdir", required=True) # Target output directory
    
    args = p.parse_args()
    
    extract_icfg(args.binary, args.outdir)
