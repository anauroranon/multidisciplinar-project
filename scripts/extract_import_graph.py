#!/usr/bin/env python3
# scripts/extract_import_graph.py
import argparse, os
import networkx as nx
import lief
from pathlib import Path
import json

def extract_import_graph(binary, outdir):
    b = lief.parse(binary)
    G = nx.DiGraph()
    base = os.path.basename(binary)
    # add node for binary
    G.add_node(base, type="binary")
    try:
        for lib in b.libraries:
            # lib is string name; add edge binary -> lib
            G.add_node(lib, type="lib")
            G.add_edge(base, lib)
        # imports: b.imported_functions or b.pltgot?
        # LIEF: use imported_symbols (ELF)
        for sym in b.imported_functions:
            # sym is a string "libc:printf" sometimes; create node per import
            G.add_node(sym, type="import")
            G.add_edge(base, sym)
    except Exception:
        pass
    os.makedirs(outdir, exist_ok=True)
    nx.write_graphml(G, os.path.join(outdir, os.path.splitext(base)[0] + "_imports.graphml"))
    
    # Create json file
    graphml_path = os.path.join(outdir, f"{base}_imports.graphml")
    nodes_json_path = Path(graphml_path).with_name(Path(graphml_path).stem + "_imports.json")
    
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

    return True

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True)
    p.add_argument("--outdir", required=True)
    args = p.parse_args()
    extract_import_graph(args.binary, args.outdir)
