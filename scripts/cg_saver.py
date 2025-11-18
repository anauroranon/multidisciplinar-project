# scripts/cg_saver.py
import json, os, tempfile, signal, atexit
from contextlib import contextmanager
from typing import Any, Iterable, Optional

def _atomic_write(path: str, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=os.path.dirname(path), delete=False) as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    os.replace(tmp_path, path)

class PartialSaver:
    """
    Scrive file parziali .partial.jsonl durante l’esecuzione.
    Non modifica i tuoi .json finali: restano quelli che già scrivi tu.
    """
    def __init__(self, out_dir: str, sample_id: str, flush_every: int = 200):
        self.out_dir = out_dir
        self.sample_id = sample_id
        self.flush_every = max(1, flush_every)
        self._counters = {}
        self._files = {}
        self._paths = {}
        self._opened = set()

        atexit.register(self._flush_all)
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._on_signal)
            except Exception:
                pass  # ambienti che non permettono set di signal

    def _on_signal(self, signum, frame):
        self._flush_all()

    def _open_if_needed(self, name: str):
        if name in self._opened:
            return
        base = os.path.join(self.out_dir, f"{self.sample_id}_{name}")
        os.makedirs(os.path.dirname(base), exist_ok=True)
        fpath = base + ".partial.jsonl"
        fh = open(fpath, "a", encoding="utf-8")
        self._files[name] = fh
        self._paths[name] = base
        self._counters[name] = 0
        self._opened.add(name)

    def append(self, name: str, obj: Any):
        self._open_if_needed(name)
        line = json.dumps(obj, ensure_ascii=False) + "\n"
        self._files[name].write(line)
        self._counters[name] += 1
        if self._counters[name] >= self.flush_every:
            self._files[name].flush()
            os.fsync(self._files[name].fileno())
            self._counters[name] = 0

    def append_many(self, name: str, objs: Iterable[Any]):
        for o in objs:
            self.append(name, o)

    def save_graph_snapshot(self, name: str, graph_json_obj: Any):
        base = self._paths.get(name) or os.path.join(self.out_dir, f"{self.sample_id}_{name}")
        path = base + ".partial.graph.json"
        _atomic_write(path, json.dumps(graph_json_obj, ensure_ascii=False).encode("utf-8"))

    def _flush_all(self):
        for _, fh in list(self._files.items()):
            try:
                fh.flush()
                os.fsync(fh.fileno())
            except Exception:
                pass

    @contextmanager
    def stage(self, stage_name: str, error_name: Optional[str] = "errors"):
        try:
            yield
        except Exception as e:
            self.append(error_name, {"stage": stage_name, "exception": repr(e)})
            # non rilanciamo: lasciamo proseguire lo script
