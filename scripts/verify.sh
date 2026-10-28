#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m fmn_filters --rules rules/example-rules.json --validate
PYTHONPATH=src python3 -m fmn_filters --rules rules/demo-rules.json --input samples/flows.ndjson --input samples/http.ndjson
