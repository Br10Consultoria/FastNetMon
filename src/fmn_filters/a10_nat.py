"""Receptor NAT do A10 (LSN:PortAllocated/PortFreed) com framing correto.

Problema que resolve: o A10 envia mensagens RFC 5424 por TCP sem delimitador
(sem LF e sem octet-counting). O rsyslog entao corta o stream em 8096 bytes e
fragmenta eventos. Aqui o stream e separado pelo proprio cabecalho
``<PRI>1 timestamp`` e cada evento so e aceito quando o ``[...]`` fecha.

Estado mantido em memoria (3 mil eventos/s inviabilizam uma linha SQL por
evento): tabela de mapeamentos ativos + historico recente, consultavel por
socket Unix local, e agregados por assinante/minuto gravados no MariaDB.
Um log compacto em TSV preserva os eventos para reconstrucao e retencao.

NAO altera o A10, o rsyslog nem o firewall. IPs e portas de assinantes nunca
sao impressos no console; use as tabelas/ferramentas com acesso restrito.
"""
from __future__ import annotations

import argparse
import asyncio
import codecs
import gzip
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import sys
import time

from .a10_syslog_audit import HEADER
from .a10_syslog_inspect import MAPPING as _PUBLISHED_MAPPING

# Variante ampliada do formato publicado: qualquer protocolo (ICMP etc.) e ate 4 campos
# extras apos as portas (ex. destino quando o A10 registra o destino em vez de "- -").
_pattern = _PUBLISHED_MAPPING.pattern
assert "(?P<protocol>TCP|UDP)" in _pattern and r"(?:\s+-\s+-)?" in _pattern
MAPPING = re.compile(
    _pattern.replace("(?P<protocol>TCP|UDP)", "(?P<protocol>[A-Za-z0-9]{2,10})")
            .replace(r"(?:\s+-\s+-)?", r"(?:\s+[^\s\]]+){0,4}"),
    re.I)
IPV4 = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
from .scopes import SCOPE_POOL, SCOPE_PRIVATE, ScopeMap

MAX_TAIL = 65536
LOOKUP_LIMIT = 64 * 1024 * 1024
FRACTION = re.compile(r"\.(\d+)")


@dataclass(frozen=True)
class NatEvent:
    ts: float          # tempo efetivo (recebimento ou relogio do A10, conforme time_source)
    a10_ts: float      # tempo informado no cabecalho do A10
    kind: str          # allocated | freed
    protocol: str      # tcp | udp
    inside_ip: str
    inside_port: int
    public_ip: str
    public_port: int


def _parse_time(text: str) -> float:
    text = text.replace("Z", "+00:00").replace("z", "+00:00")
    text = FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
    return datetime.fromisoformat(text).timestamp()


class StreamSplitter:
    """Separa mensagens RFC 5424 coladas, mesmo cortadas em qualquer byte."""

    def __init__(self):
        self.buffer = ""
        self.discarded_prefix = 0     # bytes antes do primeiro cabecalho (inicio no meio do evento)
        self.discarded_tail = 0       # cauda enorme sem cabecalho

    def feed(self, text: str) -> list[str]:
        self.buffer += text
        heads = list(HEADER.finditer(self.buffer))
        if not heads:
            if len(self.buffer) > MAX_TAIL:
                self.discarded_tail += len(self.buffer) - MAX_TAIL
                self.buffer = self.buffer[-MAX_TAIL:]
            return []
        if heads[0].start() > 0:
            self.discarded_prefix += heads[0].start()
        out = [self.buffer[heads[i].start():heads[i + 1].start()] for i in range(len(heads) - 1)]
        tail = self.buffer[heads[-1].start():]
        if tail.rstrip().endswith("]") and MAPPING.search(tail):
            out.append(tail)           # evento completo: nao precisa esperar o proximo cabecalho
            self.buffer = ""
        elif len(tail) > MAX_TAIL:
            self.discarded_tail += len(tail)
            self.buffer = ""
        else:
            self.buffer = tail
        return out


MARKER = re.compile(r"LSN:([A-Za-z]+)")


def parse_events(message: str, scopes: ScopeMap, *, received: float,
                 time_source: str = "received"):
    """Retorna (eventos, motivo_do_descarte). Cada mapeamento e validado individualmente.

    Motivos: sem_cabecalho, sem_marcador_nat, horario_invalido, porta_invalida,
    interno_fora_da_rede, publico_fora_dos_pools. Uma mensagem pode ter varios mapeamentos.
    """
    head = HEADER.search(message)
    if head is None:
        return [], "sem_cabecalho"
    try:
        a10_ts = _parse_time(head.group("time"))
    except ValueError:
        return [], "horario_invalido"
    events, reason = [], None
    for mapping in MAPPING.finditer(message):
        inside_port = int(mapping.group("inside_port"))
        public_port = int(mapping.group("public_port"))
        # Porta 0 e valida (ICMP id 0 e trafego de ataque com porta 0); so rejeita fora de 0..65535.
        if not (0 <= inside_port <= 65535 and 0 <= public_port <= 65535):
            reason = "porta_invalida"
            continue
        inside_ip, public_ip = mapping.group("inside"), mapping.group("public")
        if scopes.scope(inside_ip) != SCOPE_PRIVATE:
            reason = "interno_fora_da_rede"
            continue
        if scopes.scope(public_ip) != SCOPE_POOL:
            reason = "publico_fora_dos_pools"
            continue
        kind = "allocated" if mapping.group("event").lower() in ("allocated", "allocation") else "freed"
        events.append(NatEvent(ts=received if time_source == "received" else a10_ts, a10_ts=a10_ts,
                               kind=kind, protocol=mapping.group("protocol").lower(),
                               inside_ip=inside_ip, inside_port=inside_port,
                               public_ip=public_ip, public_port=public_port))
    if events:
        return events, None
    return [], reason or "sem_marcador_nat"


def parse_message(message: str, scopes: ScopeMap, *, received: float,
                  time_source: str = "received") -> NatEvent | None:
    """Compatibilidade: primeiro evento valido da mensagem, ou None."""
    events, _ = parse_events(message, scopes, received=received, time_source=time_source)
    return events[0] if events else None


def _diagnose(message: str, reason: str, diag: Counter):
    """Agrega o motivo sem expor IP/porta de assinante (somente tipo, /24 publico, /16 interno)."""
    if reason == "sem_marcador_nat":
        found = MARKER.search(message)
        diag["tipo:" + (found.group(0) if found else "sem_LSN")] += 1
        if found and found.group(1) in ("PortAllocated", "PortAllocation", "PortFreed"):
            # Forma do registro sem dados: IPs -> IP, numeros -> N. Mostra o formato nao reconhecido.
            shape = re.sub(r"\d+", "N", IPV4.sub("IP", message[found.start():found.start() + 90]))
            diag["forma:" + " ".join(shape.split())] += 1
    elif reason in ("interno_fora_da_rede", "publico_fora_dos_pools"):
        for m in MAPPING.finditer(message):
            if reason == "publico_fora_dos_pools":
                diag["publico_fora:" + ".".join(m.group("public").split(".")[:3]) + ".0/24"] += 1
            else:
                diag["interno_fora:" + ".".join(m.group("inside").split(".")[:2]) + ".0.0/16"] += 1


class NatTable:
    """Mapeamentos ativos e historico fechado por (IP publico, porta publica, protocolo)."""

    def __init__(self, retention_seconds: int = 3600, slack_seconds: int = 120):
        self.retention = retention_seconds
        self.slack = slack_seconds
        self.active: dict[tuple, tuple] = {}
        self.closed: dict[tuple, list] = {}
        self._order: deque = deque()
        self.users: dict[str, int] = defaultdict(int)   # inside_ip -> portas ativas (gauge)
        self.orphan_frees = 0
        self.missed_frees = 0

    def apply(self, ev: NatEvent):
        key = (ev.public_ip, ev.public_port, ev.protocol)
        if ev.kind == "allocated":
            old = self.active.get(key)
            if old is not None:
                self.missed_frees += 1       # liberacao perdida: fecha o anterior agora
                self._close(key, old, ev.ts)
            self.active[key] = (ev.inside_ip, ev.inside_port, ev.ts)
            self.users[ev.inside_ip] += 1
        else:
            old = self.active.pop(key, None)
            if old is None:
                self.orphan_frees += 1       # liberacao sem alocacao conhecida (ex. antes do inicio)
                return
            self.users[old[0]] -= 1
            if self.users[old[0]] <= 0:
                self.users.pop(old[0], None)
            self._store(key, old, ev.ts)

    def _close(self, key, old, end):
        self.users[old[0]] -= 1
        if self.users[old[0]] <= 0:
            self.users.pop(old[0], None)
        self._store(key, old, end)

    def _store(self, key, old, end):
        self.closed.setdefault(key, []).append((old[2], end, old[0], old[1]))
        self._order.append((end, key))

    def lookup(self, public_ip: str, public_port: int, protocol: str, ts: float):
        """Retorna (inside_ip, inside_port) valido em ts (com tolerancia) ou None."""
        key = (public_ip, public_port, protocol)
        cur = self.active.get(key)
        if cur is not None and cur[2] - self.slack <= ts:
            return cur[0], cur[1]
        for start, end, ip, port in reversed(self.closed.get(key, ())):
            if start - self.slack <= ts <= end + self.slack:
                return ip, port
        return None

    def prune(self, now: float):
        cutoff = now - self.retention
        while self._order and self._order[0][0] < cutoff:
            _, key = self._order.popleft()
            kept = [x for x in self.closed.get(key, ()) if x[1] >= cutoff]
            if kept:
                self.closed[key] = kept
            else:
                self.closed.pop(key, None)

    def sizes(self):
        return {"ativos": len(self.active), "historico": sum(map(len, self.closed.values()))}


class EventLog:
    """Log compacto em TSV por hora: ts, kind, proto, inside, in_port, public, pub_port, a10_ts."""

    def __init__(self, directory):
        self.dir = Path(directory) if directory else None
        self._day = None
        self._fh = None

    def write(self, ev: NatEvent):
        if self.dir is None:
            return
        day = datetime.fromtimestamp(ev.ts, timezone.utc).strftime("%Y%m%d%H")   # um arquivo por hora
        if day != self._day:
            self.close()
            self.dir.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.dir / ("nat-events-%s.tsv" % day),
                         os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            self._fh, self._day = os.fdopen(fd, "a", encoding="utf-8"), day
        self._fh.write("%.3f\t%s\t%s\t%s\t%d\t%s\t%d\t%.3f\n" % (
            ev.ts, ev.kind[0], ev.protocol, ev.inside_ip, ev.inside_port,
            ev.public_ip, ev.public_port, ev.a10_ts))

    def flush(self):
        if self._fh:
            self._fh.flush()

    def close(self):
        if self._fh:
            self._fh.close()
            self._fh = None


def replay_log(path, table: NatTable, since: float, max_bytes=512 * 1024 * 1024) -> int:
    """Reconstroi o estado em memoria a partir do log compacto (cauda limitada)."""
    path = Path(path)
    if not path.exists():
        return 0
    count = 0
    with path.open("rb") as stream:
        size = stream.seek(0, 2)
        if size > max_bytes:
            stream.seek(size - max_bytes)
            stream.readline()
        else:
            stream.seek(0)
        for raw in stream:
            parts = raw.decode("utf-8", "replace").rstrip("\n").split("\t")
            if len(parts) != 8:
                continue
            try:
                ts = float(parts[0])
                if ts < since:
                    continue
                table.apply(NatEvent(ts=ts, a10_ts=float(parts[7]),
                                     kind="allocated" if parts[1] == "a" else "freed",
                                     protocol=parts[2], inside_ip=parts[3], inside_port=int(parts[4]),
                                     public_ip=parts[5], public_port=int(parts[6])))
                count += 1
            except ValueError:
                continue
    return count


class NatService:
    def __init__(self, scopes: ScopeMap, *, allowed_sources, time_source="received",
                 log_dir=None, retention_seconds=900, slack_seconds=120):
        if time_source not in ("received", "a10"):
            raise ValueError("time_source deve ser received ou a10")
        self.scopes = scopes
        self.allowed = frozenset(allowed_sources)
        self.time_source = time_source
        self.table = NatTable(retention_seconds, slack_seconds)
        self.log = EventLog(log_dir)
        self.minutes: dict[tuple, list] = {}
        self.stats = defaultdict(int)
        self.diag = None          # Counter de diagnostico (somente no replay)
        self.span = None          # [primeiro, ultimo] horario do A10 (somente no replay)

    def ingest_text(self, text: str, splitter: StreamSplitter, now: float | None = None):
        received = time.time() if now is None else now
        for message in splitter.feed(text):
            events, reason = parse_events(message, self.scopes, received=received,
                                          time_source=self.time_source)
            if not events:
                self.stats["ignorado_" + reason] += 1
                if self.diag is not None:
                    _diagnose(message, reason, self.diag)
                continue
            for ev in events:
                self.stats["eventos_" + ev.kind] += 1
                self.table.apply(ev)
                self.log.write(ev)
                slot = self.minutes.setdefault((int(ev.ts // 60), ev.inside_ip), [0, 0])
                slot[0 if ev.kind == "allocated" else 1] += 1
                if self.span is not None:
                    self.span[0] = min(self.span[0], ev.a10_ts)
                    self.span[1] = max(self.span[1], ev.a10_ts)

    def drain_minutes(self, now: float):
        """Linhas de minutos ja completos para orby_nat_user_minute."""
        current = int(now // 60)
        done = [k for k in self.minutes if k[0] < current]
        rows = []
        for key in done:
            allocs, frees = self.minutes.pop(key)
            bucket = datetime.fromtimestamp(key[0] * 60, timezone.utc).replace(tzinfo=None)
            rows.append((bucket, key[1], allocs, frees, int(self.table.users.get(key[1], 0))))
        return rows

    def lookup_many(self, keys):
        out = []
        for item in keys:
            try:
                ip, port, proto, ts = item
                found = self.table.lookup(str(ip), int(port), str(proto).lower(), float(ts))
            except (TypeError, ValueError):
                found = None
            out.append(list(found) if found else None)
        return out


NAT_MINUTE_SQL = """INSERT INTO orby_nat_user_minute
(bucket_utc,inside_ip,allocs,frees,active_ports) VALUES (%s,%s,%s,%s,%s)
ON DUPLICATE KEY UPDATE allocs=allocs+VALUES(allocs),frees=frees+VALUES(frees),
active_ports=GREATEST(active_ports,VALUES(active_ports))"""


def save_minutes(rows):
    from .mysql_sink import connection_from_env
    db = connection_from_env()
    try:
        with db.cursor() as cur:
            for n in range(0, len(rows), 500):
                cur.executemany(NAT_MINUTE_SQL, rows[n:n + 500])
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


async def handle_stream(service: NatService, reader, writer):
    peer = (writer.get_extra_info("peername") or ("?",))[0]
    if peer not in service.allowed:
        service.stats["conexoes_recusadas"] += 1
        writer.close()
        return
    service.stats["conexoes_aceitas"] += 1
    splitter = StreamSplitter()
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    try:
        while True:
            data = await reader.read(262144)
            if not data:
                break
            service.ingest_text(decoder.decode(data), splitter)
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        service.stats["bytes_descartados_inicio"] += splitter.discarded_prefix
        writer.close()


async def handle_lookup(service: NatService, reader, writer):
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=10)
        keys = json.loads(line)["keys"]
        if not isinstance(keys, list) or len(keys) > 200000:
            raise ValueError("keys invalido")
        writer.write((json.dumps({"results": service.lookup_many(keys)}) + "\n").encode())
        await writer.drain()
    except (ValueError, KeyError, TypeError, asyncio.TimeoutError, ConnectionError):
        service.stats["consultas_invalidas"] += 1
    finally:
        writer.close()


def lookup_many(path: str, keys, timeout=10.0, chunk=20000):
    """Cliente sincrono. Retorna lista com [inside_ip, inside_port] ou None por chave."""
    out = []
    for n in range(0, len(keys), chunk):
        payload = (json.dumps({"keys": keys[n:n + chunk]}) + "\n").encode()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(path)
            sock.sendall(payload)
            data = b""
            while not data.endswith(b"\n"):
                part = sock.recv(1 << 20)
                if not part:
                    break
                data += part
        out.extend(json.loads(data)["results"])
    return out


class ConfigWatcher:
    """Recarrega escopos e origens aceitas quando a configuracao muda (painel web, sem reinicio)."""

    def __init__(self, paths, loader):
        self.paths = [Path(p) for p in paths]
        self.loader = loader
        self.stamp = self._stamp()

    def _stamp(self):
        out = []
        for p in self.paths:
            try:
                st = p.stat()
                out.append((st.st_mtime_ns, st.st_size))
            except OSError:
                out.append(None)
        return tuple(out)

    def check(self, service):
        stamp = self._stamp()
        if stamp == self.stamp:
            return False
        self.stamp = stamp
        try:
            scopes, allowed = self.loader()
        except Exception as exc:                 # configuracao invalida: mantem a anterior
            print("AVISO configuracao nova invalida, mantida a anterior: %s" % exc, file=sys.stderr, flush=True)
            return False
        service.scopes = scopes
        if allowed:
            service.allowed = frozenset(allowed)
        print("configuracao recarregada (origens aceitas: %s)" % ",".join(sorted(service.allowed)), flush=True)
        return True


async def serve(service: NatService, host, port, socket_path, *, use_db=True, watcher=None):
    tcp = await asyncio.start_server(lambda r, w: handle_stream(service, r, w), host, port)
    Path(socket_path).parent.mkdir(parents=True, exist_ok=True)
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    # Uma consulta traz milhares de chaves numa unica linha JSON: o limite padrao (64 KiB) a rejeitava.
    unix = await asyncio.start_unix_server(lambda r, w: handle_lookup(service, r, w), socket_path,
                                           limit=LOOKUP_LIMIT)
    os.chmod(socket_path, 0o660)
    print("receptor NAT A10 em %s:%d, consulta em %s, fonte de tempo=%s" %
          (host, port, socket_path, service.time_source), flush=True)
    loop = asyncio.get_running_loop()
    last = time.time()
    try:
        while True:
            await asyncio.sleep(5)
            now = time.time()
            service.log.flush()
            if now - last >= 60:
                last = now
                if watcher is not None:
                    watcher.check(service)
                service.table.prune(now)
                rows = service.drain_minutes(now)
                if rows and use_db:
                    try:
                        await loop.run_in_executor(None, save_minutes, rows)
                    except Exception as exc:
                        service.stats["falhas_mariadb"] += 1
                        print("ERRO gravando agregados NAT: %s" % exc, file=sys.stderr, flush=True)
                print("NAT estado=%s contadores=%s" % (service.table.sizes(), dict(service.stats)), flush=True)
    finally:
        tcp.close()
        unix.close()
        service.log.close()


def replay_rsyslog_spool(path, scopes: ScopeMap, *, max_bytes=2_000_000_000, progress=False,
                         max_lines=None):
    """Reprocessa o spool NDJSON do rsyslog (texto ou .gz) juntando blocos consecutivos.

    O rsyslog dividiu o stream em blocos sem descartar bytes: concatenar na ordem
    recupera os eventos, exceto nas fronteiras entre conexoes TCP diferentes.
    Retorna apenas contagens agregadas (nunca IP/porta de assinante).
    """
    service = NatService(scopes, allowed_sources=(), time_source="a10")
    service.diag = Counter()
    service.span = [float("inf"), 0.0]
    splitters = defaultdict(StreamSplitter)
    lines = 0
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as stream:
        if path.suffix != ".gz":
            size = stream.seek(0, 2)
            stream.seek(max(0, size - max_bytes))
            if size > max_bytes:
                stream.readline()
        for raw in stream:
            try:
                item = json.loads(raw)
                text, source = item["raw"], item["source_ip"]
            except (ValueError, KeyError, TypeError):
                service.stats["linhas_invalidas"] += 1
                continue
            lines += 1
            service.ingest_text(text, splitters[source], now=0.0)
            if max_lines and lines >= max_lines:
                break
            if lines % 200 == 0 and service.span[1]:
                service.table.prune(service.span[1])      # memoria limitada em arquivos de 1 h
            if progress and lines % 2000 == 0:
                done = service.stats.get("eventos_allocated", 0) + service.stats.get("eventos_freed", 0)
                print("... linhas=%d eventos=%d (aguarde, 1 h de log leva alguns minutos)" % (lines, done),
                      file=sys.stderr, flush=True)
    freed = service.stats.get("eventos_freed", 0)
    first, last = service.span
    period = max(0.0, last - first) if last else 0.0
    ignored = {k: v for k, v in service.stats.items() if k.startswith("ignorado_")}
    total = service.stats.get("eventos_allocated", 0) + freed
    return {
        "linhas": lines,
        "periodo_a10_segundos": round(period, 1),
        "inicio_a10_utc": (datetime.fromtimestamp(first, timezone.utc).isoformat() if last else None),
        "fim_a10_utc": (datetime.fromtimestamp(last, timezone.utc).isoformat() if last else None),
        "eventos": {k: v for k, v in service.stats.items() if k.startswith("eventos_")},
        "eventos_por_segundo": round(total / period, 1) if period else None,
        "mensagens_ignoradas_por_motivo": ignored,
        "detalhe_ignoradas_top": dict(service.diag.most_common(25)),
        "liberacoes_casadas_com_alocacao": freed - service.table.orphan_frees,
        "liberacoes_sem_alocacao": service.table.orphan_frees,
        "alocacoes_ainda_ativas_no_fim": service.table.sizes()["ativos"],
        "realocacao_sem_liberacao": service.table.missed_frees,
        "bytes_descartados_inicio": sum(s.discarded_prefix for s in splitters.values()),
        "observacao": ("liberacoes_sem_alocacao altas sao esperadas em janelas curtas: a alocacao "
                       "ocorreu antes do inicio do arquivo. Compare com periodo_a10_segundos."),
    }


def main(argv=None):
    from .bidir_config import DEFAULT_CONFIG, build_scopes, read_config
    ap = argparse.ArgumentParser(description="OrbyMon: receptor NAT do A10 (CGNAT)")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--listen", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5515)
    ap.add_argument("--allow", action="append", default=None,
                    help="IP de origem aceito (repetivel); padrao 10.100.10.10")
    ap.add_argument("--log-dir", default="/var/log/orbymon/a10nat")
    ap.add_argument("--replay-max-lines", type=int, default=None,
                    help="limita o replay as primeiras N linhas (teste rapido)")
    ap.add_argument("--time-source", choices=("received", "a10"), default="received",
                    help="use 'a10' somente depois de NTP confirmado no A10")
    ap.add_argument("--retention-seconds", type=int, default=900,
                    help="historico de mapeamentos fechados em memoria (~450 B cada)")
    ap.add_argument("--no-db", action="store_true")
    ap.add_argument("--replay-rsyslog", type=Path,
                    help="reprocessa o spool NDJSON do rsyslog (ou .gz rotacionado) e imprime so contagens")
    args = ap.parse_args(argv)
    try:
        cfg = read_config(args.config)
        scopes = build_scopes(cfg)
        if args.replay_rsyslog:
            print(json.dumps(replay_rsyslog_spool(args.replay_rsyslog, scopes, progress=True,
                                                 max_lines=args.replay_max_lines),
                             ensure_ascii=False, indent=2))
            return 0
        service = NatService(scopes, allowed_sources=cfg["a10_sources"] or args.allow or ["10.100.10.10"],
                             time_source=args.time_source, log_dir=args.log_dir,
                             retention_seconds=args.retention_seconds)
        now = time.time()
        restored = 0
        for hour in (now - 3600, now):                    # hora anterior e hora atual
            name = "nat-events-%s.tsv" % datetime.fromtimestamp(hour, timezone.utc).strftime("%Y%m%d%H")
            restored += replay_log(Path(args.log_dir) / name, service.table,
                                   now - args.retention_seconds)
        print("estado restaurado do log: %d eventos" % restored, flush=True)
        def reload():
            new_cfg = read_config(args.config)
            return build_scopes(new_cfg), new_cfg["a10_sources"]
        watcher = ConfigWatcher([args.config, cfg["cgnat_profile_path"]], reload)
        asyncio.run(serve(service, args.listen, args.port, cfg["nat_socket"], use_db=not args.no_db,
                          watcher=watcher))
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print("FALHA receptor NAT: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
