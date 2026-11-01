import asyncio
import json
from pathlib import Path
import tempfile
import unittest

from fmn_filters.a10_nat import (EventLog, NatEvent, NatService, NatTable, StreamSplitter,
                                 _parse_time, handle_lookup, handle_stream, lookup_many,
                                 parse_events, parse_message, replay_log, replay_rsyslog_spool)
import gzip
from fmn_filters.bidir_config import build_scopes, validate_config

ROOT = Path(__file__).resolve().parent.parent
PROFILE = json.loads((ROOT / "rules/cgnat-profiles.a10.json").read_text())
CFG = validate_config(json.loads((ROOT / "rules/bidir.example.json").read_text()))
SCOPES = build_scopes(CFG, json.loads(json.dumps(PROFILE)))


def msg(kind="Allocated", proto="TCP", inside="100.64.64.5", ip_port=40000,
        public="45.238.170.70", pub_port=20000, when="2026-10-30T12:00:00-03:00"):
    return ("<134>1 %s A10-CGN acos - - - LSN:Port%s:%s [%s %d %s %d - -]"
            % (when, kind, proto, inside, ip_port, public, pub_port))


def stream(n=50):
    return "".join(msg(inside="100.64.64.%d" % (n % 200 + 1), ip_port=1000 + n,
                       pub_port=2000 + n) for n in range(n))


class SplitterTests(unittest.TestCase):
    def collect(self, text, size):
        splitter = StreamSplitter()
        out = []
        for n in range(0, len(text), size):
            out.extend(splitter.feed(text[n:n + size]))
        return out, splitter

    def test_concatenated_without_delimiter_any_chunk_size(self):
        text = stream(60)
        for size in (1, 3, 7, 13, 64, 500, 8096, len(text)):
            out, _ = self.collect(text, size)
            events = [parse_message(m, SCOPES, received=1.0) for m in out]
            self.assertEqual(len(events), 60, size)
            self.assertTrue(all(events), size)
            self.assertEqual([e.public_port for e in events], [2000 + n for n in range(60)], size)

    def test_start_in_the_middle_of_an_event_is_discarded(self):
        text = stream(3)
        out, splitter = self.collect(text[40:], 50)
        self.assertEqual(len(out), 2)
        self.assertGreater(splitter.discarded_prefix, 0)

    def test_incomplete_last_event_waits(self):
        splitter = StreamSplitter()
        full = msg()
        self.assertEqual(splitter.feed(full[:-10]), [])
        self.assertEqual(len(splitter.feed(full[-10:])), 1)

    def test_marker_in_garbage_without_header_is_not_emitted(self):
        splitter = StreamSplitter()
        self.assertEqual(splitter.feed("LSN:PortAllocated:TCP [100.64.64.5 1 45.238.170.70 2 - -]"), [])


class ParseTests(unittest.TestCase):
    def parse(self, text, **kw):
        return parse_message(text, SCOPES, received=5.0, **kw)

    def test_fields_and_time_sources(self):
        ev = self.parse(msg(kind="Freed", proto="UDP"))
        self.assertEqual((ev.kind, ev.protocol, ev.inside_ip, ev.public_port),
                         ("freed", "udp", "100.64.64.5", 20000))
        self.assertEqual(ev.ts, 5.0)
        ev = self.parse(msg(), time_source="a10")
        self.assertEqual(ev.ts, ev.a10_ts)
        self.assertAlmostEqual(_parse_time("2026-10-30T12:00:00.5-03:00"),
                               _parse_time("2026-10-30T15:00:00.500000Z"))

    def test_rejects_outside_declared_networks_and_bad_ports(self):
        self.assertIsNone(self.parse(msg(inside="10.0.0.5")))
        self.assertIsNone(self.parse(msg(public="45.238.170.10")))    # dedicado, nao pool
        self.assertIsNone(self.parse(msg(public="8.8.8.8")))
        self.assertIsNone(self.parse(msg(pub_port=0)))
        self.assertIsNone(self.parse(msg(ip_port=70000)))
        self.assertIsNone(self.parse("<134>1 2026-10-30T12:00:00Z h - - - - sem mapeamento"))


class TableTests(unittest.TestCase):
    def ev(self, kind, ts, inside="100.64.64.5", ip_port=4000, pub="45.238.170.70", pp=20000):
        return NatEvent(ts, ts, kind, "tcp", inside, ip_port, pub, pp)

    def test_active_closed_and_slack(self):
        t = NatTable(retention_seconds=3600, slack_seconds=60)
        t.apply(self.ev("allocated", 1000))
        self.assertEqual(t.lookup("45.238.170.70", 20000, "tcp", 1500), ("100.64.64.5", 4000))
        self.assertIsNone(t.lookup("45.238.170.70", 20000, "udp", 1500))
        self.assertIsNone(t.lookup("45.238.170.70", 20001, "tcp", 1500))
        t.apply(self.ev("freed", 2000))
        self.assertEqual(t.lookup("45.238.170.70", 20000, "tcp", 1999), ("100.64.64.5", 4000))
        self.assertEqual(t.lookup("45.238.170.70", 20000, "tcp", 2050), ("100.64.64.5", 4000))
        self.assertIsNone(t.lookup("45.238.170.70", 20000, "tcp", 2100))

    def test_port_reuse_returns_owner_at_that_time(self):
        t = NatTable(slack_seconds=10)
        t.apply(self.ev("allocated", 1000, inside="100.64.64.5"))
        t.apply(self.ev("freed", 1100, inside="100.64.64.5"))
        t.apply(self.ev("allocated", 1200, inside="100.64.64.9", ip_port=7000))
        self.assertEqual(t.lookup("45.238.170.70", 20000, "tcp", 1050)[0], "100.64.64.5")
        self.assertEqual(t.lookup("45.238.170.70", 20000, "tcp", 1300), ("100.64.64.9", 7000))

    def test_missed_free_and_orphan_free_and_gauge(self):
        t = NatTable()
        t.apply(self.ev("freed", 500))
        self.assertEqual(t.orphan_frees, 1)
        t.apply(self.ev("allocated", 1000, inside="100.64.64.5"))
        t.apply(self.ev("allocated", 1100, inside="100.64.64.9", ip_port=1))
        self.assertEqual(t.missed_frees, 1)
        self.assertEqual(dict(t.users), {"100.64.64.9": 1})

    def test_prune(self):
        t = NatTable(retention_seconds=100)
        t.apply(self.ev("allocated", 1000))
        t.apply(self.ev("freed", 1010))
        t.prune(1050)
        self.assertEqual(t.sizes()["historico"], 1)
        t.prune(2000)
        self.assertEqual(t.sizes(), {"ativos": 0, "historico": 0})


class ServiceTests(unittest.TestCase):
    def test_minute_aggregates_and_log_replay(self):
        with tempfile.TemporaryDirectory() as d:
            svc = NatService(SCOPES, allowed_sources=["127.0.0.1"], log_dir=d)
            sp = StreamSplitter()
            svc.ingest_text(msg(pub_port=1) + msg(pub_port=2) + msg(kind="Freed", pub_port=1) + msg(pub_port=3), sp, now=600.0)
            svc.ingest_text(msg(pub_port=9, inside="100.64.64.9"), sp, now=660.5)
            svc.log.close()
            rows = svc.drain_minutes(now=720.0)
            by_ip = {r[1]: r for r in rows}
            self.assertEqual(by_ip["100.64.64.5"][2:4], (3, 1))
            self.assertEqual(by_ip["100.64.64.5"][4], 2)           # 3 alocadas - 1 liberada
            self.assertEqual(svc.drain_minutes(now=720.0), [])
            table = NatTable()
            n = replay_log(next(Path(d).glob("nat-events-*.tsv")), table, since=0)
            self.assertEqual(n, 5)
            self.assertEqual(table.lookup("45.238.170.70", 2, "tcp", 600.0), ("100.64.64.5", 40000))

    def test_replay_rsyslog_spool_stitches_8096_blocks(self):
        text = stream(400)
        blocks = [text[n:n + 8096] for n in range(0, len(text), 8096)]
        self.assertGreater(len(blocks), 3)
        with tempfile.TemporaryDirectory() as d:
            spool = Path(d) / "a10-current.ndjson"
            spool.write_text("".join(json.dumps({"raw": b, "source_ip": "10.100.10.10"}) + "\n" for b in blocks))
            result = replay_rsyslog_spool(spool, SCOPES)
        self.assertEqual(result["eventos"]["eventos_allocated"], 400)
        self.assertNotIn("mensagens_ignoradas", result["eventos"])


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_tcp_ingest_unix_lookup_and_source_allowlist(self):
        with tempfile.TemporaryDirectory() as d:
            svc = NatService(SCOPES, allowed_sources=["127.0.0.1"])
            sock = str(Path(d) / "nat.sock")
            tcp = await asyncio.start_server(lambda r, w: handle_stream(svc, r, w), "127.0.0.1", 0)
            unix = await asyncio.start_unix_server(lambda r, w: handle_lookup(svc, r, w), sock)
            port = tcp.sockets[0].getsockname()[1]
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            data = stream(30).encode()
            for n in range(0, len(data), 97):          # cortes arbitrarios no meio dos eventos
                writer.write(data[n:n + 97])
                await writer.drain()
            writer.close()
            await writer.wait_closed()
            for _ in range(50):
                if svc.stats["eventos_allocated"] == 30:
                    break
                await asyncio.sleep(0.05)
            self.assertEqual(svc.stats["eventos_allocated"], 30)
            import time
            keys = [["45.238.170.70", 2005, "tcp", time.time()], ["45.238.170.70", 59999, "tcp", time.time()]]
            res = await asyncio.get_running_loop().run_in_executor(None, lookup_many, sock, keys)
            self.assertEqual(res[0], ["100.64.64.6", 1005])
            self.assertIsNone(res[1])
            tcp.close()
            unix.close()

    async def test_unlisted_source_is_refused(self):
        svc = NatService(SCOPES, allowed_sources=["10.100.10.10"])
        tcp = await asyncio.start_server(lambda r, w: handle_stream(svc, r, w), "127.0.0.1", 0)
        _, writer = await asyncio.open_connection("127.0.0.1", tcp.sockets[0].getsockname()[1])
        writer.write(msg().encode())
        await writer.drain()
        await asyncio.sleep(0.2)
        self.assertEqual(svc.stats["conexoes_recusadas"], 1)
        self.assertEqual(svc.stats.get("eventos_allocated", 0), 0)
        writer.close()
        tcp.close()


class ReasonAndReplayTests(unittest.TestCase):
    def test_reasons(self):
        def reason(text):
            return parse_events(text, SCOPES, received=1.0)[1]
        self.assertEqual(reason("sem cabecalho LSN:PortAllocated"), "sem_cabecalho")
        self.assertEqual(reason("<134>1 2026-10-30T12:00:00Z A10 acos - - - LSN:UserQuotaExceeded x"),
                         "sem_marcador_nat")
        self.assertEqual(reason(msg(inside="10.9.9.9")), "interno_fora_da_rede")
        self.assertEqual(reason(msg(public="187.87.201.50")), "publico_fora_dos_pools")
        self.assertEqual(reason(msg(pub_port=0)), "porta_invalida")
        self.assertIsNone(reason(msg()))

    def test_several_mappings_after_one_header_are_all_kept(self):
        text = msg(pub_port=1) + " LSN:PortFreed:UDP [100.64.64.9 5 45.238.171.70 7 - -]"
        events, reason = parse_events(text, SCOPES, received=1.0)
        self.assertIsNone(reason)
        self.assertEqual([(e.kind, e.public_port) for e in events], [("allocated", 1), ("freed", 7)])

    def write_spool(self, path, text, opener=open):
        blocks = [text[n:n + 4000] for n in range(0, len(text), 4000)]
        with opener(path, "wt") as fh:
            for b in blocks:
                fh.write(json.dumps({"raw": b, "source_ip": "10.100.10.10"}) + "\n")

    def test_gz_replay_reports_period_matches_and_no_subscriber_data(self):
        parts = []
        for n in range(100):
            sec = n
            parts.append(msg(pub_port=3000 + n, ip_port=n + 1, when="2026-10-30T12:00:%02d-03:00" % (sec % 60)
                             if sec < 60 else "2026-10-30T12:01:%02d-03:00" % (sec - 60)))
        for n in range(50):                                      # liberacoes das 50 primeiras
            parts.append(msg(kind="Freed", pub_port=3000 + n, ip_port=n + 1, when="2026-10-30T12:01:50-03:00"))
        parts.append(msg(kind="Freed", pub_port=9999, when="2026-10-30T12:01:51-03:00"))  # alocada antes
        parts.append("<134>1 2026-10-30T12:01:52-03:00 A10 acos - - - LSN:UserQuotaExceeded [100.64.64.5]")
        parts.append(msg(public="187.87.201.50", when="2026-10-30T12:01:53-03:00"))
        with tempfile.TemporaryDirectory() as d:
            spool = Path(d) / "a10-current.ndjson-20261030-12.gz"
            self.write_spool(spool, "".join(parts), gzip.open)
            res = replay_rsyslog_spool(spool, SCOPES)
        self.assertEqual(res["eventos"], {"eventos_allocated": 100, "eventos_freed": 51})
        self.assertEqual(res["liberacoes_casadas_com_alocacao"], 50)
        self.assertEqual(res["liberacoes_sem_alocacao"], 1)
        self.assertEqual(res["alocacoes_ainda_ativas_no_fim"], 50)
        self.assertEqual(res["periodo_a10_segundos"], 111.0)
        self.assertEqual(res["mensagens_ignoradas_por_motivo"],
                         {"ignorado_sem_marcador_nat": 1, "ignorado_publico_fora_dos_pools": 1})
        self.assertEqual(res["detalhe_ignoradas_top"],
                         {"tipo:LSN:UserQuotaExceeded": 1, "publico_fora:187.87.201.0/24": 1})
        dumped = json.dumps(res)
        self.assertNotIn("100.64.64.5", dumped)
        self.assertNotIn("45.238.170.70", dumped)


if __name__ == "__main__":
    unittest.main()
