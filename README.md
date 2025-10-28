# multidisciplinar-project

Starter project per estrarre feature da binari ARM/Linux.
Usa `angr` e qualche script di utilità per produrre grafici e JSON da dare in pasto a modelli ML/GNN.

> ⚠️ **ATTENZIONE:** questi script fanno unicamente analisi statica sui file. Non eseguire i binari sul tuo host se sono sospetti ( :) ). Usa una VM o una sandbox se hai bisogno di eseguire. Nota bene che lo script per estrarre le syscalls è DINAMICO e va eseguito in una sandbox. La main pipeline, per ora, esclude l'esecuzione di questo script.

---

## Preparazione 

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Estrazioni nello specifico

* `scripts/extract_features.py`
  Estrae il **Function Call Graph (FCG)** e calcola feature per ogni funzione (numero di blocchi, entropia, conteggio chiamate `bl`, syscall-like, dimensione, ecc.). Rappresenta la struttura ad alto livello del programma con sequenza di funzioni.

* `scripts/extract_icfg.py`
  Estrae l'**ICFG / basic-block graph** (nodi = basic-block, archi = salti/controlli). Cattura il flusso interno (sequenze di istruzioni e decisioni).

* `scripts/extract_import_graph.py`
  Estrae il **grafo delle importazioni / PLT** (quali funzioni di libreria il binario usa). Segnala uso di API di rete/crypto (es. `curl`, `SSL_write`) fornendo forte indizio semantico.

* `scripts/main_extractor.py`
  Orchestratore minimale che esegue gli script di estrazione feature per ogni file in una cartella specificata. Automatizza la produzione per tanti sample (utile nel nostro caso)

---

## Esempi di esecuzione
Assicurarsi sempre di essere nel root del progetto e di aver attivato il venv

* Eseguire singolo extractor (FCG + feature per un binario):

```bash
python3 scripts/extract_features.py --binary examples/test_bin --outdir outputs/graphs
```

* Estrarre ICFG:

```bash
python3 scripts/extract_icfg.py --binary examples/test_bin --outdir outputs/graphs
```

* Estrarre import graph:

```bash
python3 scripts/extract_import_graph.py --binary examples/test_bin --outdir outputs/graphs
```

* Eseguire su tutti i sample (runner minimale) — dalla root del progetto:

```bash
python3 scripts/run_minimal.py --src ./dataset --outdir outputs/dataset
```

Questo creerà per ogni file in `./dataset` una cartella `outputs/dataset/<basename>/` con i file generati dagli extractor (GraphML, nodes.json, ...).

---

## Output

* `.graphml` — grafi (apribili in Gephi o NetworkX)
* `*_nodes.json` — feature per-nodo (JSON), quello da trasformare in CSV per la classificazione.

---

* Se un extractor fallisce per qualche sample, controlla il file generato nello stesso output-folder o riesegui lo script manualmente per leggere l'errore.
* Non eseguire i binari sospetti sul host: l'analisi qui è statica e sicura.


