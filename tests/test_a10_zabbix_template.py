"""Ensure opt-in Zabbix 7.4 template matches the offline metric exporter."""
import json
from pathlib import Path
import unittest

from fmn_filters.a10_zabbix_sender import METRIC_NAMES


class A10ZabbixTemplateTests(unittest.TestCase):
    def test_keys_and_types_consistent_with_sender(self):
        root = Path(__file__).resolve().parents[1]
        file = root / "zabbix/templates/orbymon-a10-receiver-7.4.json"
        data = json.loads(file.read_text(encoding="utf-8"))
        self.assertEqual(data["zabbix_export"]["version"], "7.4")
        templates = data["zabbix_export"]["templates"]
        self.assertEqual(len(templates), 1)
        items = templates[0]["items"]
        keys = {item["key"] for item in items}
        self.assertEqual(
            keys, {"orbymon.a10." + suffix for suffix in METRIC_NAMES}
        )
        self.assertEqual(len(items), len(keys))
        uuids = (
            [x["uuid"] for x in data["zabbix_export"]["template_groups"]]
            + [templates[0]["uuid"]]
            + [x["uuid"] for x in items]
            + [x["uuid"] for item in items for x in item.get("triggers", [])]
        )
        self.assertEqual(len(uuids), len(set(uuids)))
        self.assertTrue(all(len(u) == 32 for u in uuids))
        self.assertTrue(all(item["type"] == "TRAP" for item in items))
        self.assertTrue(all(item.get("history") == "14d" for item in items))
        self.assertTrue(all(item.get("trends") == "90d" for item in items))
        self.assertEqual(len(items[0]["triggers"]), 4)

    def test_no_natural_language_dynamic_output_in_template_items(self):
        root = Path(__file__).resolve().parents[1]
        data = json.loads((root / "zabbix/templates/orbymon-a10-receiver-7.4.json").read_text())
        for item in data["zabbix_export"]["templates"][0]["items"]:
            self.assertNotIn("NAT:", item["key"])
            self.assertNotIn("192.168.", item["key"])
            self.assertNotIn("password", item["key"].lower())


if __name__ == "__main__":
    unittest.main()
