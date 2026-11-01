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
                     "orbymon-bidir-huawei.timer", "orbymon-retention.timer",
                     "orbymon-retention.service", "orbymon-calibrate.timer",
                     "orbymon-calibrate.service"):
            self.assertIn(name, text)
            self.assertTrue((ROOT / "deploy/systemd" / name).exists())

    def test_receiver_only_accepts_the_a10_by_default(self):
        text = (ROOT / "deploy/systemd/orbymon-a10-nat.service").read_text()
        self.assertIn("--allow 10.100.10.10", text)

    def test_operational_scripts_are_valid_bash(self):
        for name in ("orbymon-retention.sh", "a10-receiver-cutover.sh", "tune-mariadb.sh", "calibrate.sh"):
            subprocess.run(["bash", "-n", str(ROOT / "scripts" / name)], check=True)
        cut = (ROOT / "scripts/a10-receiver-cutover.sh").read_text()
        self.assertIn("--rollback", cut)
        self.assertIn("rsyslogd -N1", cut)

    def test_retention_service_runs_the_script_with_limited_write_paths(self):
        unit = (ROOT / "deploy/systemd/orbymon-retention.service").read_text()
        self.assertIn("/opt/orbymon/scripts/orbymon-retention.sh", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("ReadWritePaths=", unit)

    def test_installer_grants_delete_only_on_retention_tables(self):
        text = (ROOT / "scripts/setup-bidir.sh").read_text()
        self.assertIn("GRANT DELETE ON orbymon.$table", text)
        self.assertNotIn("GRANT ALL", text)

    def test_daily_calibration_never_applies(self):
        unit = (ROOT / "deploy/systemd/orbymon-calibrate.service").read_text()
        self.assertNotIn("--apply", unit)
        self.assertIn("User=orbymon", unit)
        self.assertIn("ReadWritePaths=/var/lib/orbymon/calibration", unit)


if __name__ == "__main__":
    unittest.main()
