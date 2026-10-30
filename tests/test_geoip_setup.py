import pathlib
import shutil
import subprocess
import unittest

ROOT=pathlib.Path(__file__).resolve().parent.parent

class GeoIPSetupTests(unittest.TestCase):
    def test_bash_syntax(self):
        if not shutil.which("bash"):
            self.skipTest("bash ausente")
        for path in ("scripts/setup-geoip.sh","scripts/update-geoip.sh","scripts/repair-geoip-python.sh"):
            p=subprocess.run(["bash","-n",str(ROOT/path)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)

    def test_config_is_private_and_does_not_modify_db(self):
        s=(ROOT/"scripts/setup-geoip.sh").read_text()
        self.assertIn("chmod 0600 /etc/GeoIP.conf",s)
        self.assertIn("GeoLite2-ASN",s)
        self.assertIn("GeoLite2-City",s)
        self.assertNotIn("mariadb orbymon",s)
        self.assertNotIn("DELETE FROM",s)

    def test_scheduled_refresh_keeps_private_permissions(self):
        s=(ROOT/"scripts/update-geoip.sh").read_text()
        self.assertIn('geoipupdate -d "$GEOIP_DIR"',s)
        self.assertIn('chown root:orbymon "$path"',s)
        self.assertIn('chmod 0640 "$path"',s)
        t=(ROOT/"deploy/systemd/orbymon-geoip-update.timer").read_text()
        self.assertIn("OnCalendar=*-*-*",t)

if __name__=="__main__":
    unittest.main()
