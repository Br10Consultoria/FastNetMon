#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src
python3 -m unittest discover -s tests -v
python3 -m fmn_filters --rules rules/example-rules.json --validate
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
python3 -m fmn_filters --rules rules/demo-rules.json   --input samples/flows.ndjson --input samples/http.ndjson > "$TMP_DIR/alerts.ndjson"
python3 -m fmn_filters.incidents --db "$TMP_DIR/incidents.db" --tenant isp-demo --input "$TMP_DIR/alerts.ndjson"
python3 -m fmn_filters.incidents --db "$TMP_DIR/incidents.db" --tenant isp-demo --input "$TMP_DIR/alerts.ndjson"
python3 -m fmn_filters.incidents --db "$TMP_DIR/incidents.db" --tenant isp-demo --list
python3 - "$TMP_DIR/incidents.db" <<'PY'
import sys
from fmn_filters.incidents import IncidentStore
s=IncidentStore(sys.argv[1])
try:
    incidents=s.list('isp-demo')
    assert len(incidents)==2, f'esperados 2 incidentes, encontrados {len(incidents)}'
    assert sorted(i['rule'] for i in incidents)==['DNS-demo','PHP-demo']
    assert all(i['alert_count']==1 for i in incidents), 'replay duplicou alertas'
    print('RESULTADO: 2 incidentes DNS/PHP; replay idempotente; nenhum bloqueio executado')
finally:
    s.close()
PY
