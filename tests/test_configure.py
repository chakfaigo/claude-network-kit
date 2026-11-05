import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('configure', Path(__file__).resolve().parents[1] / 'portable/src/configure.py')
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)
NODE = {'server': 'proxy.example.test', 'port': 1080, 'username': 'fixture-user', 'password': 'fixture-only', 'expected_ip': '93.184.216.34'}


class ConfigureTests(unittest.TestCase):
    def test_private_permissions_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            path = configure.save_node(Path(root), NODE)
            self.assertEqual(json.loads(path.read_text()), NODE)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(FileExistsError):
                configure.save_node(Path(root), dict(NODE, password='replacement'))
            self.assertEqual(json.loads(path.read_text()), NODE)

    def test_invalid_input_creates_no_private_directory(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                configure.save_node(Path(root), dict(NODE, expected_ip='127.0.0.1'))
            self.assertFalse((Path(root) / 'private').exists())

    def test_symlink_directory_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)
            (p / 'other').mkdir()
            (p / 'private').symlink_to(p / 'other')
            with self.assertRaises(ValueError):
                configure.save_node(p, NODE)
            self.assertFalse((p / 'other/node.json').exists())

    def test_symlink_file_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)
            (p / 'private').mkdir()
            (p / 'other.json').write_text('preserve')
            (p / 'private/node.json').symlink_to(p / 'other.json')
            with self.assertRaises(FileExistsError):
                configure.save_node(p, NODE)
            self.assertEqual((p / 'other.json').read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
