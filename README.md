# multidisciplinar-project
Starter project to extract function call graphs for ARM/Linux binaries.

Using angr.

The goal is to perform early experiments for malware classification.

<pre>
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python3 scripts/extract_features.py \
  --binary examples/test_bin \
  --outdir outputs/graphs
</pre>


