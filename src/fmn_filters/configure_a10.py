"""Apply *known* A10 public NAT pool config without destroying local custom roles.

Runs as root from setup-cgnat-baseline.sh. No A10, NE8000 or firewall API.
"""
from __future__ import annotations

import argparse
import copy
import grp
import json
import os
from pathlib import Path
import shutil
import tempfile
from datetime import datetime, timezone

from .cgnat_baseline import validate_config


def merge_profiles(existing, incoming):
    prev = validate_config(copy.deepcopy(existing))
    target = validate_config(copy.deepcopy(incoming))
    old_pools = set(prev["cgnat_pools"])
    new_pools = set(target["cgnat_pools"])
    if old_pools and old_pools != new_pools:
        raise ValueError("Pools CGNAT anteriores divergentes: nao substituir classificacao existente automaticamente")
    old_inside = set(prev.get("inside_private_cidrs", []))
    new_inside = set(target["inside_private_cidrs"])
    if old_inside and old_inside != new_inside:
        raise ValueError("Rede interna CGNAT existente e diferente: revisao manual exigida")
    old_meta = prev.get("cgnat_pool_metadata", {})
    if old_meta and old_meta != target["cgnat_pool_metadata"]:
        raise ValueError("Metadados de pool anteriores diferentes: revisao manual exigida")
    merged = dict(prev)
    merged["cgnat_pools"] = list(target["cgnat_pools"])
    merged["inside_private_cidrs"] = list(target["inside_private_cidrs"])
    merged["cgnat_pool_metadata"] = dict(target["cgnat_pool_metadata"])
    # Preserve role classifications, lookback, row caps, min samples and exclusions.
    return validate_config(merged)


def apply(current_path, incoming_path):
    incoming=json.loads(Path(incoming_path).read_text(encoding="utf-8"))
    target=Path(current_path)
    if target.exists():
        previous=json.loads(target.read_text(encoding="utf-8"))
        final=merge_profiles(previous,incoming)
        if previous == final:
            print("CGNAT: configuracao A10 ja atualizada, nenhuma alteracao.")
            return False
    else:
        final=validate_config(incoming)
    rendered=json.dumps(final,indent=2,ensure_ascii=False)+"\n"
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists():
        backup=target.with_name(target.name + ".backup-a10-" +
             datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
        shutil.copy2(target,backup)
        os.chmod(backup,0o600)
        print("Backup configuracao CGNAT: " + str(backup))
    fd,temp=tempfile.mkstemp(prefix=".cgnat-",dir=str(target.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temp,0,grp.getgrnam("orbymon").gr_gid)
        os.chmod(temp,0o640)
        os.replace(temp,target)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    print("CGNAT: A10 NAT-POOL-08/09/10/11 e rede interna registrados.")
    return True


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--file",default="/etc/orbymon/cgnat-profiles.json")
    parser.add_argument("--a10-template",required=True)
    args=parser.parse_args()
    apply(args.file,args.a10_template)


if __name__=="__main__":
    main()
