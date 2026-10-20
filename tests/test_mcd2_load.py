"""Map a synthetic rewritten module. The bytes are not from a game."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tests')]
from test_mcd2_probe import DIALOGUE, MARKER, SLOT, memory_image

NATIVE = ROOT / 'games' / 'mcd2' / 'build' / 'mcd2-native'
CHECK = ROOT / 'games' / 'mcd2' / 'build' / 'image_check'


def build_tools():
    subprocess.run(
        ['make', '-C', str(ROOT / 'games' / 'mcd2'), 'build/mcd2-native', 'build/image_check'],
        check=True)


class Load(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_tools()

    def rewritten(self, root):
        directory = root / 'rewritten'
        directory.mkdir()
        (directory / 'main.patched.bin').write_bytes(memory_image())
        (directory / 'main.fixups.tsv').write_text(
            '# PATCH_OFF\t0x1000\n'
            '# KEY_PAGE_OFF\t0x500\n'
            '# TEXT_END\t0x100\n'
            '# RO_OFF\t0x100\n'
            '# DATA_OFF\t0x200\n')
        return directory

    def run_native(self, directory, mode):
        return subprocess.run([str(NATIVE), str(directory), mode], capture_output=True, text=True)

    def test_map_resolves_entry_without_calling_or_printing_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = self.rewritten(Path(tmp))
            result = self.run_native(directory, 'map')
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, output)
            self.assertIn('[mcd2] mapped main size=1280 symbols=3', output)
            self.assertIn('[mcd2] relocated main relative=1 symbolic=1 unresolved=1', output)
            self.assertIn('[mcd2] unresolved main _import_missing', output)
            self.assertIn('[mcd2] entry nnMain main+0x8', output)
            self.assertNotIn('[mcd2] ENTER nnMain', output)
            self.assertNotIn(MARKER.decode(), output)
            self.assertNotIn(DIALOGUE.decode(), output)

    def test_load_on_this_host_does_not_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = self.rewritten(Path(tmp))
            result = self.run_native(directory, 'load')
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, output)
            self.assertIn('not calling (this host is not Apple silicon)', output)
            self.assertNotIn('[mcd2] ENTER nnMain', output)
            self.assertNotIn('[mcd2] ENTER nn::init::Start', output)

    def test_relative_reloc_points_at_the_addend(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = self.rewritten(Path(tmp))
            result = subprocess.run(
                [str(CHECK), str(directory / 'main.patched.bin'), str(directory / 'main.fixups.tsv'),
                 hex(SLOT), '8'],
                capture_output=True, text=True)
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, output)
            self.assertIn('[mcd2] relative reloc ok', output)
            self.assertNotIn(MARKER.decode(), output)

    def test_prepare_refuses_a_build_dir_without_a_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = subprocess.run(
                [sys.executable, str(ROOT / 'games/mcd2/scripts/prepare_load.py'), '--build-dir', str(root)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('run the probe first', result.stderr)
            self.assertEqual(list(root.iterdir()), [])
