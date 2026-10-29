import json
from datetime import datetime, timezone
from pathlib import Path
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from fmn_filters.ingest_nfcapd import candidates, decode_file, save_file, pending_files, run


class FakeCursor:
    def __init__(self, db):
        self.db = db
        self.rowcount = 0
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def execute(self, sql, args):
        if "INSERT IGNORE INTO orby_ingested_files" in sql:
            self.rowcount = int((args[0], args[1]) not in self.db.saved)
            if self.rowcount:
                self.db.pending = (args[0], args[1], args[2], args[3])
        elif "SELECT file_size" in sql:
            self.db.selected = self.db.saved.get(tuple(args))
        elif "SELECT file_name,file_size,file_mtime_ns" in sql:
            self.db.selected_many = [
                (name, size, mtime)
                for (source, name), (size, mtime) in self.db.saved.items()
                if source == args[0] and name in args[1:]
            ]
    def fetchone(self):
        return self.db.selected
    def fetchall(self):
        return self.db.selected_many
    def executemany(self, sql, args):
        self.db.pending_rows.extend(args)


class FakeDB:
    def __init__(self):
        self.saved = {}
        self.pending = None
        self.selected = None
        self.pending_rows = []
        self.rows = []
        self.selected_many = []
    def cursor(self):
        return FakeCursor(self)
    def commit(self):
        if self.pending:
            self.saved[self.pending[:2]] = self.pending[2:]
        self.rows.extend(self.pending_rows)
        self.pending = None
        self.pending_rows = []
    def rollback(self):
        self.pending = None
        self.pending_rows = []


class PipelineTests(unittest.TestCase):
    def test_only_recent_rotated(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            a = folder / "nfcapd.20261029160300"
            b = folder / "nfcapd.current"
            a.write_text("x")
            b.write_text("x")
            now = time.time()
            os.utime(a, (now - 90, now - 90))
            self.assertEqual(candidates(folder, now), [a])

    def test_utc_and_sampling_not_multiplied(self):
        now = datetime(2026, 10, 29, 19, 7, tzinfo=timezone.utc).timestamp()
        flow = dict(type="FLOW", first="2026-10-29T19:04:57.000",
                    last="2026-10-29T19:04:57.000",
                    src4_addr="8.8.8.8", dst4_addr="1.1.1.1",
                    proto=6, dst_port=443, src_as=15169,
                    in_packets=2048, in_bytes=143360, sampled=1)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "nfcapd.20261029160600"
            path.write_text("file")
            def capture(argv, **kwargs):
                self.assertEqual(kwargs["env"]["TZ"], "UTC")
                return type("P", (), {"stdout": json.dumps([flow])})()
            with patch("fmn_filters.ingest_nfcapd.subprocess.run", side_effect=capture):
                st, records, count = decode_file(path, now)
            self.assertEqual(count, 1)
            db = FakeDB()
            self.assertTrue(save_file(db, "huawei", path, st, records, count))
            self.assertFalse(save_file(db, "huawei", path, st, records, count))
            self.assertEqual(len(db.rows), 1)
            self.assertEqual(db.rows[0][8:10], (2048, 143360))

    def test_skips_processed_files_before_batch_limit(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            now = time.time()
            paths = []
            for number in range(25):
                path = folder / ("nfcapd.2026102916%04d" % number)
                path.write_text(str(number))
                os.utime(path, (now - 200 + number, now - 200 + number))
                paths.append(path)
            db = FakeDB()
            for path in paths[:20]:
                st = path.stat()
                db.saved[("huawei", path.name)] = (st.st_size, st.st_mtime_ns)
            remaining = pending_files(db, "huawei", paths)
            self.assertEqual(remaining, paths[20:])
            self.assertEqual(len(remaining[:20]), 5)
            # A primeira rodada importou 20; a proxima deve processar novos arquivos.
            st = paths[19].stat()
            paths[19].write_text("alterado")
            with self.assertRaisesRegex(ValueError, "mudou"):
                pending_files(db, "huawei", paths)

    def test_reject_future(self):
        now = datetime(2026, 10, 29, 19, 7, tzinfo=timezone.utc).timestamp()
        flow = dict(type="FLOW", first="2026-10-30T02:44:00.000",
                    last="2026-10-30T02:44:00.000", src4_addr="8.8.8.8",
                    dst4_addr="1.1.1.1", proto=6, in_packets=1, in_bytes=40)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "nfcapd.20261029160600"
            path.write_text("x")
            with patch("fmn_filters.ingest_nfcapd.subprocess.run",
                       return_value=type("P", (), {"stdout": json.dumps([flow])})()):
                with self.assertRaises(ValueError):
                    decode_file(path, now)


if __name__ == "__main__":
    unittest.main()
