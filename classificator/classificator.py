from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Tuple
import warnings
warnings.filterwarnings("ignore")

# ===============================
# Config
# ===============================
DATASET_DIR = Path("dataset")
INDEX_CSV_PATH = "fcg_index.csv"
FEATURES_CSV_PATH = "features.csv"
FINAL_MODEL_PATH = "xgb_fcg_model.json"   
FALLBACK_MODEL_PATH = "rf_fcg_model.pkl" 
FEATURE_ORDER_PATH = "feature_order.txt"
N_SPLITS = 5
RANDOM_SEED = 42
USE_GPU = True  

# Label: try to infer the label base on the name of the folder (malware/benign).
LABEL_FROM_FOLDER = {
    "malware": 1,
    "benign":  0,
}

# ===============================
# Imports
# ===============================
import pandas as pd
import numpy as np
from tqdm import tqdm
import networkx as nx

from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score, average_precision_score, f1_score, confusion_matrix

from sklearn.ensemble import RandomForestClassifier
import joblib

# IMPORT XGBoost
_XGB_AVAILABLE = False
try:
    import xgboost as xgb
    _XGB_AVAILABLE = True
except Exception:
    _XGB_AVAILABLE = False


def numeric_node_attrs(G: nx.DiGraph) -> List[str]:
    """
    Identify numeric node attributes that are common across most nodes in the graph.

    This function samples up to 50 nodes and finds the intersection of all numeric
    attributes (int, float, np.floating) appearing in their node dictionaries.
    Only attributes that are numeric and shared by the majority of nodes are kept.

    Args:
        G (nx.DiGraph): Input directed graph.

    Returns:
        List[str]: Sorted list of numeric attribute names common to the sampled nodes.
    """
    n = G.number_of_nodes()
    if n == 0:
        return []
    sample = list(G.nodes())[: min(50, n)]
    cand = None
    for node in sample:
        attrs = [k for k, v in G.nodes[node].items() if isinstance(v, (int, float, np.floating))]
        cand = set(attrs) if cand is None else cand.intersection(attrs)
    return sorted(list(cand or []))


def safe_stat(arr, name_prefix: str, feats: Dict[str, Any]) -> None:
    """
    Compute basic descriptive statistics safely and store them in a dictionary.

    This helper avoids runtime errors when the array is empty or contains NaN values.
    It calculates the mean, standard deviation, minimum, maximum, and 90th percentile.

    Args:
        arr (Iterable[float]): Numeric values to summarize.
        name_prefix (str): Prefix to use for naming the generated features.
        feats (Dict[str, Any]): Dictionary where the results are stored.
    """
    arr = np.asarray(arr, dtype=float)
    arr = arr[np.isnan(arr)]
    if arr.size == 0:
        for suf in ("mean", "std", "min", "max", "p90"):
            feats[f"{name_prefix}_{suf}"] = 0.0
        return
    feats[f"{name_prefix}_mean"] = float(arr.mean())
    feats[f"{name_prefix}_std"]  = float(arr.std())
    feats[f"{name_prefix}_min"]  = float(arr.min())
    feats[f"{name_prefix}_max"]  = float(arr.max())
    feats[f"{name_prefix}_p90"]  = float(np.percentile(arr, 90))


def graph_features(G: nx.DiGraph) -> Dict[str, Any]:
    """
    Extract structural and statistical features from a directed graph.

    This function summarizes both the topology of the graph (nodes, edges, connectivity,
    clustering, path lengths, etc.) and the distribution of numeric node attributes
    (e.g., entropy, byte size, instruction count).

    The output is a fixed-size feature vector

    Args:
        G (nx.DiGraph): Directed graph (e.g., a Function Call Graph or an ICFG).

    Returns:
        Dict[str, Any]: Dictionary of computed graph-level features.
    """

    feats: Dict[str, Any] = {}
    n = G.number_of_nodes()
    m = G.number_of_edges()
    feats["n_nodes"] = n
    feats["n_edges"] = m
    feats["density_dir"] = (m / (n * (n - 1))) if n > 1 else 0.0

    
    indeg = np.array([d for _, d in G.in_degree()], dtype=float) if n else np.array([0.0])
    outdeg = np.array([d for _, d in G.out_degree()], dtype=float) if n else np.array([0.0])
    safe_stat(indeg, "in_deg", feats)
    safe_stat(outdeg, "out_deg", feats)

    
    feats["n_sources"] = int((indeg == 0).sum())
    feats["n_sinks"]   = int((outdeg == 0).sum())
    feats["ratio_sources"] = (feats["n_sources"] / n) if n else 0.0
    feats["ratio_sinks"]   = (feats["n_sinks"] / n) if n else 0.0

    
    scc_sizes = [len(c) for c in nx.strongly_connected_components(G)] if n else []
    feats["n_scc"]   = len(scc_sizes)
    feats["scc_max"] = max(scc_sizes) if scc_sizes else 0
    wcc_sizes = [len(c) for c in nx.weakly_connected_components(G)] if n else []
    feats["n_wcc"]   = len(wcc_sizes)
    feats["wcc_max"] = max(wcc_sizes) if wcc_sizes else 0

    try:
        UG = G.to_undirected()
        clust = nx.clustering(UG)
        safe_stat(list(clust.values()), "clust", feats)
    except Exception:
        for k in ["clust_mean", "clust_std", "clust_min", "clust_max", "clust_p90"]:
            feats[k] = 0.0

    try:
        if n > 0:
            biggest = max(nx.weakly_connected_components(G), key=len)
            H = G.subgraph(biggest).to_undirected()
            if H.number_of_nodes() <= 500:
                ecc = nx.eccentricity(H)
                safe_stat(list(ecc.values()), "ecc", feats)
                feats["diameter"] = float(nx.diameter(H))
                # all pairs shortest path (non orientato)
                dists = []
                for _, dd in nx.all_pairs_shortest_path_length(H):
                    dists.extend([v for v in dd.values() if v > 0])
                safe_stat(dists, "sp_len", feats)
            else:
                for k in ["ecc_mean","ecc_std","ecc_min","ecc_max","ecc_p90",
                          "sp_len_mean","sp_len_std","sp_len_min","sp_len_max","sp_len_p90"]:
                    feats[k] = 0.0
                feats["diameter"] = 0.0
        else:
            feats["diameter"] = 0.0
    except Exception:
        for k in ["ecc_mean","ecc_std","ecc_min","ecc_max","ecc_p90",
                  "sp_len_mean","sp_len_std","sp_len_min","sp_len_max","sp_len_p90","diameter"]:
            feats[k] = 0.0

    # attributi numerici dei nodi (es. avg_block_entropy, total_bytes, instr_count_est, ...)
    attrs = numeric_node_attrs(G)
    for a in attrs:
        vals = [G.nodes[v].get(a, np.nan) for v in G.nodes()]
        safe_stat(vals, f"node_{a}", feats)

    return feats


# ===============================
# Dataset building
# ===============================
def infer_label_from_path(p: Path) -> int:
    """
    Try to infer the label from the name of the directory immediately under DATASET_DIR.
    Example:
        malware_dataset/malware/xxxx_fcg.graphml -> 1
        malware_dataset/benign/xxxx_fcg.graphml  -> 0
    If no match is found, return -1 (so we can detect and handle it).
    """
    try:
        """
        parts = p.relative_to(DATASET_DIR).parts
        parent = parts[0].lower() if parts else 
        return LABEL_FROM_FOLDER.get(parent, -1) """

        folder = parts[0].lower() if parts else ""

        if folder == "malware":
            return 1
        elif folder == "benign":
            return 0
        #return LABEL_FROM_FOLDER.get(parent, -1)
    except Exception:
        return -1


def read_graph_as_digraph(path: Path) -> nx.DiGraph:
    G = nx.read_graphml(path)
    if not isinstance(G, (nx.DiGraph, nx.MultiDiGraph)):
        G = nx.DiGraph(G)
    if isinstance(G, nx.MultiDiGraph):
        # converto perdendo multiarco (accettabile per FCG); se vuoi sommarli come peso, qui è il posto giusto
        G = nx.DiGraph(G)
    return G


def build_fcg_features(dataset_dir: Path) -> Tuple[pd.DataFrame, pd.DataFrame]:
    fcg_paths = sorted(dataset_dir.rglob("*_fcg.graphml"))

    records: List[Dict[str, Any]] = []
    rows: List[Dict[str, Any]] = []

    print(f"[Scan] Trovati {len(fcg_paths)} FCG .graphml")

    count = 0
    for p in tqdm(fcg_paths, desc="Estrazione feature FCG"):
        count = count + 1 
        label = infer_label_from_path(p)
        #label = 0 if count % 2 == 0 else 1
        if label == -1:
            # fallback: alterna True/False (non consigliato)
            # meglio lanciare un warning così correggi la struttura/fonte etichette
            print(f"[WARN] Etichetta non dedotta da path: {p}. Imposto label=0 temporaneo.")
            label = 0

        program_id = p.stem.replace("_fcg", "")  # ID più robusto del solo top folder
        records.append({"program_id": program_id, "path": str(p), "label": label})

        try:
            G = read_graph_as_digraph(p)
            feats = graph_features(G)
            feats["program_id"] = program_id
            feats["path"] = str(p)
            feats["label"] = label
            rows.append(feats)
        except Exception as e:
            print(f"[WARN] errore su {p}: {e}")

    index_df = pd.DataFrame(records)
    feats_df = pd.DataFrame(rows).fillna(0)

    # Salvataggi
    index_df.to_csv(INDEX_CSV_PATH, index=False)
    feats_df.to_csv(FEATURES_CSV_PATH, index=False)
    print(f"[OK] Salvati:\n - {INDEX_CSV_PATH} (indice)\n - {FEATURES_CSV_PATH} (feature)  shape={feats_df.shape}")

    return index_df, feats_df


# ===============================
# Training (+ CV) con GPU se disponibile
# ===============================
def split_X_y(features_df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray, List[str]]:
    if "label" not in features_df.columns:
        raise RuntimeError("Manca la colonna 'label' nelle feature.")
    y = features_df["label"].astype(int).values
    drop_cols = {"program_id", "path", "label"}
    X = features_df.drop(columns=[c for c in drop_cols if c in features_df.columns], errors="ignore")

    # tieni solo le numeriche
    num_cols = [c for c in X.columns if np.issubdtype(X[c].dtype, np.number)]
    X = X[num_cols].astype(float)
    return X, y, num_cols


def check_binary_labels(y: np.ndarray) -> None:
    classes = np.unique(y)
    if classes.size < 2:
        raise RuntimeError(f"Serve almeno una istanza per ciascuna classe. Classi trovate: {classes}.")


def train_with_xgboost_cv(X: pd.DataFrame, y: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
    """
    Allenamento + CV con XGBoost (GPU se disponibile). Restituisce metriche aggregate e il modello finale.
    """
    device = "cuda" if USE_GPU and _XGB_AVAILABLE else "cpu"
    print(f"[Train] Backend: XGBoost su {device.upper()}")

    params = dict(
        n_estimators=800,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.8,
        random_state=RANDOM_SEED,
        n_jobs=-1,
        eval_metric="logloss",
        tree_method="gpu_hist" if device == "cuda" else "hist",
        predictor="gpu_predictor" if device == "cuda" else "auto",
        reg_alpha=0.0,
        reg_lambda=1.0,
    )
    model = xgb.XGBClassifier(**params)

    cv = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_SEED)
    aucs, aps, f1s = [], [], []
    importances = np.zeros(X.shape[1], dtype=float)

    for tr, va in cv.split(X, y):
        model.fit(X.iloc[tr], y[tr])
        proba = model.predict_proba(X.iloc[va])[:, 1]
        pred = (proba >= 0.5).astype(int)

        aucs.append(roc_auc_score(y[va], proba))
        aps.append(average_precision_score(y[va], proba))
        f1s.append(f1_score(y[va], pred))
        # importance dal modello corrente
        importances += model.feature_importances_

    print(f"\n=== CV ({N_SPLITS}-fold) XGBoost ===")
    print(f"ROC-AUC: {np.mean(aucs):.3f} ± {np.std(aucs):.3f}")
    print(f"PR-AUC : {np.mean(aps):.3f} ± {np.std(aps):.3f}")
    print(f"F1     : {np.mean(f1s):.3f} ± {np.std(f1s):.3f}")

    # Top 20 feature
    imp_df = pd.DataFrame({"feature": feature_names, "gain": importances / N_SPLITS})
    imp_df = imp_df.sort_values("gain", ascending=False)
    print("\nTop 20 feature per importanza (XGB):")
    print(imp_df.head(20).to_string(index=False))

    # Confusion matrix media
    cm_sum = np.zeros((2, 2), dtype=float)
    for tr, va in cv.split(X, y):
        model.fit(X.iloc[tr], y[tr])
        pred = (model.predict_proba(X.iloc[va])[:, 1] >= 0.5).astype(int)
        cm = confusion_matrix(y[va], pred, labels=[0, 1]).astype(float)
        cm_sum += cm
    cm_avg = (cm_sum / N_SPLITS).round(1)
    print("\nConfusion matrix media sui fold (righe=verità [0,1], colonne=pred):")
    print(cm_avg)

    # Modello finale su tutto il dataset
    final_model = xgb.XGBClassifier(**params)
    final_model.fit(X, y)

    # Salvataggi artefatti
    final_model.save_model(FINAL_MODEL_PATH)
    with open(FEATURE_ORDER_PATH, "w") as f:
        for c in feature_names:
            f.write(str(c) + "\n")
    print(f"\n[OK] Salvati:\n - {FINAL_MODEL_PATH}\n - {FEATURE_ORDER_PATH}")

    return {
        "imp_df": imp_df,
        "cm_avg": cm_avg,
        "final_model": final_model,
    }


def train_with_rf_cpu_cv(X: pd.DataFrame, y: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
    """
    Fallback CPU: RandomForest (scikit-learn).
    """
    print("[Train] Fallback: RandomForest su CPU")
    cv = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_SEED)
    aucs, aps, f1s = [], [], []
    importances = np.zeros(X.shape[1], dtype=float)

    for tr, va in cv.split(X, y):
        model = RandomForestClassifier(
            n_estimators=500,
            max_depth=10,
            class_weight="balanced",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
        model.fit(X.iloc[tr], y[tr])
        proba = model.predict_proba(X.iloc[va])[:, 1]
        pred = (proba >= 0.5).astype(int)

        aucs.append(roc_auc_score(y[va], proba))
        aps.append(average_precision_score(y[va], proba))
        f1s.append(f1_score(y[va], pred))
        importances += model.feature_importances_

    print(f"\n=== CV ({N_SPLITS}-fold) RandomForest ===")
    print(f"ROC-AUC: {np.mean(aucs):.3f} ± {np.std(aucs):.3f}")
    print(f"PR-AUC : {np.mean(aps):.3f} ± {np.std(aps):.3f}")
    print(f"F1     : {np.mean(f1s):.3f} ± {np.std(f1s):.3f}")

    imp_df = pd.DataFrame({"feature": feature_names, "gain": importances / N_SPLITS})
    imp_df = imp_df.sort_values("gain", ascending=False)
    print("\nTop 20 feature per importanza (RF):")
    print(imp_df.head(20).to_string(index=False))

    # Confusion matrix media
    cm_sum = np.zeros((2, 2), dtype=float)
    for tr, va in cv.split(X, y):
        m = RandomForestClassifier(
            n_estimators=500,
            max_depth=10,
            class_weight="balanced",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
        m.fit(X.iloc[tr], y[tr])
        pred = (m.predict_proba(X.iloc[va])[:, 1] >= 0.5).astype(int)
        cm = confusion_matrix(y[va], pred, labels=[0, 1]).astype(float)
        cm_sum += cm
    cm_avg = (cm_sum / N_SPLITS).round(1)
    print("\nConfusion matrix media sui fold (righe=verità [0,1], colonne=pred):")
    print(cm_avg)

    # Modello finale
    final_model = RandomForestClassifier(
        n_estimators=500,
        max_depth=10,
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    final_model.fit(X, y)

    # Salvataggi
    joblib.dump(final_model, FALLBACK_MODEL_PATH)
    with open(FEATURE_ORDER_PATH, "w") as f:
        for c in feature_names:
            f.write(str(c) + "\n")
    print(f"\n[OK] Salvati:\n - {FALLBACK_MODEL_PATH}\n - {FEATURE_ORDER_PATH}")

    return {
        "imp_df": imp_df,
        "cm_avg": cm_avg,
        "final_model": final_model,
    }


# ===============================
# Main
# ===============================
def main() -> None:
    # 1) Costruzione dataset (FCG) + salvataggi CSV
    index_df, features_df = build_fcg_features(DATASET_DIR)

    # 2) Preparazione X/y
    X, y, feature_names = split_X_y(features_df)
    check_binary_labels(y)

    print("\n[Dataset]")
    print(f"  X shape: {X.shape}")
    print(f"  #positivi (label=1): {int(y.sum())}")
    print(f"  #negativi (label=0): {int((y == 0).sum())}")

    # 2.b) Elenco colonne usate per l'allenamento (salvo anche un csv)
    used_cols_df = pd.DataFrame({"feature": feature_names})
    used_cols_df.to_csv("training_features_used.csv", index=False)
    print("\n[Info] Colonne usate per l'allenamento: salvate in training_features_used.csv")
    print("Prime 30 colonne:")
    print(used_cols_df.head(30).to_string(index=False))

    # 3) Training + CV (preferibilmente GPU tramite XGBoost)
    if USE_GPU and _XGB_AVAILABLE:
        _ = train_with_xgboost_cv(X, y, feature_names)
    else:
        print("[Info] XGBoost non disponibile o GPU disabilitata: uso RandomForest CPU.")
        _ = train_with_rf_cpu_cv(X, y, feature_names)


if __name__ == "__main__":
    main()
