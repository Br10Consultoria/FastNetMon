"""OrbyMon read-only incident correlation store.

Consumes alert-only NDJSON produced by fmn_filters and creates deduplicated,
persistent incidents. Does NOT access routers or issue mitigation commands.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import math
from pathlib import Path
import os
import sqlite3
import sys
import time
from urllib.parse import parse_qs, urlsplit


def _dump(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


class IncidentStore:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA busy_timeout=10000')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                tenant TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                rule TEXT NOT NULL,
                kind TEXT NOT NULL,
                target TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                alert_count INTEGER NOT NULL DEFAULT 0,
                peak_pps REAL NOT NULL DEFAULT 0,
                peak_mbps REAL NOT NULL DEFAULT 0,
                peak_rps REAL NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                resolved_at REAL
            );
            CREATE INDEX IF NOT EXISTS ix_incidents_recent
                ON incidents(tenant, status, last_seen DESC);
            CREATE INDEX IF NOT EXISTS ix_incidents_identity
                ON incidents(tenant, fingerprint, last_seen DESC);
            CREATE TABLE IF NOT EXISTS observations (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL REFERENCES incidents(id),
                event_at REAL NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_observations_incident
                ON observations(incident_id, event_at);
        ''')
        self.db.commit()

    def close(self):
        self.db.close()

    def ingest(self, alert, tenant='default', quiet_seconds=300):
        if not isinstance(alert, dict) or alert.get('action') != 'alert_only':
            raise ValueError('apenas alertas action=alert_only são aceitos')
        if not isinstance(tenant, str) or not tenant or len(tenant) > 64:
            raise ValueError('tenant inválido')
        if not isinstance(quiet_seconds, int) or not 1 <= quiet_seconds <= 86400:
            raise ValueError('quiet_seconds deve estar entre 1 e 86400')
        group = alert.get('group')
        metrics = alert.get('metrics_estimated', {})
        if not isinstance(group, dict) or not isinstance(metrics, dict):
            raise ValueError('group/metrics_estimated inválidos')
        rule = alert.get('rule')
        kind = alert.get('kind')
        if not isinstance(rule, str) or not rule or len(rule) > 160 or kind not in ('flow', 'http'):
            raise ValueError('rule ou kind inválido')
        try:
            at = float(alert['time_unix'])
            if not 0 < at < 4102444800:  # reject unreasonable future years
                raise ValueError()
        except (TypeError, KeyError, ValueError) as exc:
            raise ValueError('time_unix inválido') from exc
        severity = str(alert.get('severity', 'warning'))[:30]
        target = str(group.get('dst_ip', '') or group.get('src_ip', '') or 'sem-destino')
        if len(target) > 128:
            raise ValueError('target inválido')
        # Keep dst-only grouping when a destination is known. Otherwise preserve
        # the entire group to avoid silently merging unrelated alerts.
        identity = [kind, rule, group.get('dst_ip'), group.get('dst_port'), group.get('protocol')]
        if not group.get('dst_ip'):
            identity.append(group)
        fingerprint = hashlib.sha256(_dump(identity).encode()).hexdigest()
        observation_id = hashlib.sha256(_dump([tenant, alert]).encode()).hexdigest()
        values = {}
        for metric in ('pps', 'mbps', 'rps'):
            try:
                value = float(metrics.get(metric, 0))
                if not math.isfinite(value) or value < 0:
                    raise ValueError('métrica inválida')
                values[metric] = value
            except (TypeError, ValueError) as exc:
                raise ValueError('métrica inválida') from exc
        with self.db:
            existing = self.db.execute('SELECT incident_id FROM observations WHERE id=?', (observation_id,)).fetchone()
            if existing:
                return {'incident_id': existing['incident_id'], 'created': False, 'duplicate': True}
            previous = self.db.execute('''
                SELECT id FROM incidents
                WHERE tenant=? AND fingerprint=? AND status='open'
                  AND first_seen <= ? AND last_seen >= ?
                ORDER BY last_seen DESC LIMIT 1''',
                (tenant, fingerprint, at + quiet_seconds, at - quiet_seconds)).fetchone()
            new = previous is None
            if new:
                inc_id = hashlib.sha256(_dump([tenant, fingerprint, observation_id]).encode()).hexdigest()[:24]
                self.db.execute('''INSERT INTO incidents
                    (id,tenant,fingerprint,rule,kind,target,severity,status,first_seen,last_seen,
                     alert_count,peak_pps,peak_mbps,peak_rps,created_at)
                    VALUES (?,?,?,?,?,?,?,'open',?,?,1,?,?,?,?)''',
                    (inc_id, tenant, fingerprint, rule, kind, target, severity,
                     at, at, values['pps'], values['mbps'], values['rps'], time.time()))
            else:
                inc_id = previous['id']
                self.db.execute('''UPDATE incidents SET last_seen=MAX(last_seen,?),
                    first_seen=MIN(first_seen,?), alert_count=alert_count+1,
                    peak_pps=MAX(peak_pps,?), peak_mbps=MAX(peak_mbps,?),
                    peak_rps=MAX(peak_rps,?) WHERE id=?''',
                    (at, at, values['pps'], values['mbps'], values['rps'], inc_id))
            self.db.execute('INSERT INTO observations(id,incident_id,event_at,payload) VALUES(?,?,?,?)',
                            (observation_id, inc_id, at, _dump(alert)))
        return {'incident_id': inc_id, 'created': new, 'duplicate': False}

    def list(self, tenant='default', status=None, limit=50):
        if status not in (None, 'open', 'resolved') or not 1 <= limit <= 500:
            raise ValueError('status/limit inválido')
        query = 'SELECT * FROM incidents WHERE tenant=?'
        params = [tenant]
        if status:
            query += ' AND status=?'
            params.append(status)
        query += ' ORDER BY last_seen DESC, id DESC LIMIT ?'
        params.append(limit)
        return [dict(r) for r in self.db.execute(query, params)]

    def detail(self, inc_id, tenant='default'):
        row = self.db.execute('SELECT * FROM incidents WHERE id=? AND tenant=?', (inc_id, tenant)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item['observations'] = [json.loads(r['payload']) for r in self.db.execute(
            'SELECT payload FROM observations WHERE incident_id=? ORDER BY event_at DESC LIMIT 100', (inc_id,))]
        return item

    def resolve(self, inc_id, tenant='default'):
        with self.db:
            cur = self.db.execute('''UPDATE incidents SET status='resolved',resolved_at=?
                WHERE id=? AND tenant=? AND status='open' ''', (time.time(), inc_id, tenant))
        return cur.rowcount == 1

    def metrics(self, tenant='default'):
        rows = self.db.execute('SELECT status,COUNT(*) AS n FROM incidents WHERE tenant=? GROUP BY status', (tenant,))
        states = {'open': 0, 'resolved': 0}
        for r in rows:
            states[r['status']] = r['n']
        return states


def serve(store, token, port=8765, tenant='default'):
    if not token or len(token) < 16:
        raise ValueError('ORBYMON_API_TOKEN precisa ter pelo menos 16 caracteres')
    if not 1 <= port <= 65535:
        raise ValueError('porta HTTP inválida')

    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status, body):
            data = json.dumps(body, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            route = urlsplit(self.path)
            if route.path == '/healthz':
                self.send_json(200, {'service': 'orbymon', 'status': 'ok', 'mode': 'alert_only'})
                return
            if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + token):
                self.send_json(401, {'error': 'unauthorized'})
                return
            try:
                if route.path == '/api/v1/incidents':
                    q = parse_qs(route.query)
                    status = q.get('status', [None])[0]
                    limit = int(q.get('limit', ['50'])[0])
                    self.send_json(200, {'items': store.list(tenant, status=status, limit=limit)})
                elif route.path.startswith('/api/v1/incidents/'):
                    item = store.detail(route.path.rsplit('/', 1)[-1], tenant)
                    self.send_json(200 if item else 404, item or {'error': 'not_found'})
                elif route.path == '/metrics':
                    self.send_json(200, {'incidents': store.metrics(tenant)})
                else:
                    self.send_json(404, {'error': 'not_found'})
            except (ValueError, TypeError):
                self.send_json(400, {'error': 'invalid_query'})

        def log_message(self, *_args):
            return

    # Loopback only. Use authenticated reverse proxy with TLS for remote clients.
    server = HTTPServer(('127.0.0.1', port), Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv=None):
    ap = argparse.ArgumentParser(description='OrbyMon Incident Workspace (somente alertas)')
    ap.add_argument('--db', default='state/incidents.sqlite3')
    ap.add_argument('--tenant', default='default')
    ap.add_argument('--quiet-seconds', type=int, default=300)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--input', help='arquivo NDJSON de alertas, ou - para stdin')
    mode.add_argument('--list', action='store_true')
    mode.add_argument('--resolve', metavar='INCIDENT_ID')
    mode.add_argument('--serve', action='store_true')
    ap.add_argument('--status', choices=['open', 'resolved'])
    ap.add_argument('--port', type=int, default=8765)
    ns = ap.parse_args(argv)
    store = IncidentStore(ns.db)
    try:
        if ns.serve:
            serve(store, os.environ.get('ORBYMON_API_TOKEN', ''), ns.port, ns.tenant)
        elif ns.list:
            print(json.dumps({'items': store.list(ns.tenant, ns.status)}, ensure_ascii=False))
        elif ns.resolve:
            if not store.resolve(ns.resolve, ns.tenant):
                ap.error('incidente não encontrado ou já resolvido')
            print(json.dumps({'resolved': ns.resolve}))
        else:
            stream = sys.stdin if ns.input == '-' else open(ns.input, encoding='utf-8')
            try:
                for i, line in enumerate(stream, 1):
                    if not line.strip():
                        continue
                    if len(line) > 1048576:
                        raise ValueError(f'linha {i} excede 1 MiB')
                    result = store.ingest(json.loads(line), ns.tenant, ns.quiet_seconds)
                    print(json.dumps(result))
            finally:
                if stream is not sys.stdin:
                    stream.close()
    finally:
        store.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
