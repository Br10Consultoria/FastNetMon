import importlib
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent.parent
UNITS = ["orbymon-a10-nat", "orbymon-flow-rollup-huawei", "orbymon-bidir-huawei"]


class DeployTests(unittest.TestCase):
    def test_service_modules_exist_and_have_main(self):
        for unit in UNITS:
            text = (ROOT / "deploy/systemd" / (unit + ".service")).read_text()
            module = re.search(r"-m (fmn_filters\.\w+)", text).group(1)
            self.assertTrue(callable(importlib.import_module(module).main), unit)
            self.assertIn("NoNewPrivileges=true", text)
            self.assertIn("User=orbymon", text)

    def test_timers_point_to_existing_services(self):
        for timer in (ROOT / "deploy/systemd").glob("orbymon-*.timer"):
            unit = re.search(r"^Unit=(.+)$", timer.read_text(), re.M).group(1)
            self.assertTrue((ROOT / "deploy/systemd" / unit).exists(), timer.name)

    def test_installer_is_valid_bash_and_installs_every_unit(self):
        script = ROOT / "scripts/setup-bidir.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        text = script.read_text()
        for name in ("orbymon-a10-nat.service", "orbymon-flow-rollup-huawei.timer",
                     "orbymon-bidir-huawei.timer", "orbymon-a10nat-compress.timer"):
            self.assertIn(name, text)
            self.assertTrue((ROOT / "deploy/systemd" / name).exists())

    def test_receiver_only_accepts_the_a10_by_default(self):
        text = (ROOT / "deploy/systemd/orbymon-a10-nat.service").read_text()
        self.assertIn("--allow 10.100.10.10", text)


if __name__ == "__main__":
    unittest.main()
