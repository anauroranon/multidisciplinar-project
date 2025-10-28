#!/usr/bin/env python3
# scripts/strace_to_sysgraph.py
import argparse, re, os
import networkx as nx
from pathlib import Path

# parsing molto semplice: linea like: open("file", O_RDONLY) = 3
RE_SYSCALL = re.compile(r'^\s*\d+\s+([a-z0-9_]+)\((.*)\)\s+=\s+([0-9\-x]+)')

def parse_strace_file(fn):
    seq = []
    with open(fn, errors='ignore') as f:
        for line in f:
            m = RE_SYSCALL.search(line)
            if not m:
                # try simple syscall at line start
                parts = line.strip().split(None, 1)
                if not parts: continue
                name = parts[0]
                args = parts[1] if len(parts)>1 else ""
                seq.append((name,args))
                continue
            name, args, ret = m.groups()
            seq.append((name, args))
    return seq

def build_graph_from_trace(seq):
    G = nx.DiGraph()
    prev = None
    for name, args in seq:
        # canonicalize interesting syscalls
        node_label = name
        # enrich nodes for file/network
        if name in ("open","openat","creat","stat","statx"):
            # try extract filename
            f = args.split(',',1)[0].strip()
            node_label = f'file:{f}'
        if name in ("connect","sendto","send","sendmsg","recvfrom"):
            node_label = f'net:{args.split(",")[0] if args else "?"}'
        # add node
        if not G.has_node(node_label):
            G.add_node(node_label, syscall=name)
        if prev is not None:
            G.add_edge(prev, node_label)
        prev = node_label
    return G

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--strace", required=True, help="file strace output (from sandboxed run)")
    parser.add_argument("--outdir", required=True)
    args = parser.parse_args()
    seq = parse_strace_file(args.strace)
    G = build_graph_from_trace(seq)
    os.makedirs(args.outdir, exist_ok=True)
    b = Path(args.strace).stem
    nx.write_graphml(G, os.path.join(args.outdir, f"{b}_syscall.graphml"))
    print("Saved syscall graph")
