import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parent.parent

class GeoIPRuntimePermissionTests(unittest.TestCase):
    def test_installer_pip_not_executed_under_restrictive_umask(self):
        source=(ROOT/"scripts/setup-geoip.sh").read_text()
        self.assertIn('umask 022',source)
        self.assertIn('runuser -u orbymon',source)
        self.assertIn('import geoip2.database',source)
        self.assertIn('import fmn_filters.enrichment',source)

    def test_repair_uses_exact_venv_and_not_reimport_db(self):
        source=(ROOT/"scripts/repair-geoip-python.sh").read_text()
        self.assertIn('pip install --force-reinstall -e "$BASE[geo]"',source)
        self.assertIn('umask 022',source)
        self.assertIn('runuser -u orbymon',source)
        self.assertNotIn('geoipupdate',source)
        self.assertNotIn('mariadb',source.split('echo "[INFO] Bases e registros')[0])
        self.assertNotIn('chmod -R 777',source)

if __name__=="__main__":
    unittest.main()
