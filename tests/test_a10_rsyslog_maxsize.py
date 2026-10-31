"""Safe rsyslog message-size change tests, no host modifications."""
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parent.parent
mod = runpy.run_path(str(ROOT / "scripts" / "prepare-a10-rsyslog-maxsize.py"))


class A10Rsyslog64kTests(unittest.TestCase):
    def test_setting_precedes_inputs(self):
        config = mod["add_setting"]('# Comment\nmodule(load="imuxsock")\n')
        self.assertTrue(config.startswith('global(maxMessageSize="64k")\n'))
        self.assertEqual(config.count("maxMessageSize"), 1)

    def test_does_not_overwrite_existing_setting(self):
        for config in ('global(maxMessageSize="128k")\n', '$MaxMessageSize 64k\n'):
            with self.subTest(config=config):
                with self.assertRaises(ValueError):
                    mod["add_setting"](config)

    def test_comments_are_ignored_but_includes_detected(self):
        self.assertEqual(mod["find_settings"]("# $MaxMessageSize 8k\n"), [])
        found = mod["find_settings"](
            "# none\n",
            [("/etc/rsyslog.d/05-test.conf", 'global(maxMessageSize="32k")\n')])
        self.assertEqual(found, [("/etc/rsyslog.d/05-test.conf", 1)])

    def test_script_does_not_restart(self):
        contents = (ROOT / "scripts" / "prepare-a10-rsyslog-maxsize.py").read_text()
        self.assertNotIn('subprocess.run(["systemctl"', contents)
        self.assertIn('shutil.copy2(MAIN, backup)', contents)
        self.assertIn('validate_rsyslog()', contents)


if __name__ == "__main__":
    unittest.main()
