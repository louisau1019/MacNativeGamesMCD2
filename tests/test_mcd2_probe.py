"""Synthetic NSP and NSO fixtures for the Minecraft Dungeons 2 probe. No game bytes."""
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import lz4.block
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'games' / 'mcd2' / 'scripts'), str(ROOT / 'games' / 'totk' / 'scripts')]
import probe_metadata
from nso_meta import parse_nso
from prepare_modules import prepare

TITLE = 0x0100A7C01B792000
HEADER = bytes(range(32))
AREA = bytes(range(32, 48))
CONTENT = bytes(range(64, 80))
BUILD_ID = bytes((0xA0 + i) & 0xFF for i in range(32))
MARKER = b'MCD2CODEMARKER'
DIALOGUE = b'Hello copyrighted dialogue'

TEXT_SIZE = 0x100
RO_SIZE = 0x100
DATA_SIZE = 0x300
RO_OFF = 0x100
DATA_OFF = 0x200
DYNSTR_AT = RO_OFF + 0x20
DYNSYM = DATA_OFF + 0x100
RELA = DATA_OFF + 0x160
HASH_AT = DATA_OFF + 0x1C0
SLOT = DATA_OFF + 0x1E0


def _encrypt(key, mode, data):
    enc = Cipher(algorithms.AES(key), mode).encryptor()
    return enc.update(data) + enc.finalize()


def _partition(files):
    strings = b''
    table = bytearray()
    payload = b''
    for name, data in files:
        table.extend(struct.pack('<QQII', len(payload), len(data), len(strings), 0))
        strings += name.encode() + b'\0'
        payload += data
    return b'PFS0' + struct.pack('<III', len(files), len(strings), 0) + table + strings + payload


def memory_image():
    image = bytearray(DATA_OFF + DATA_SIZE)
    struct.pack_into('<I', image, 4, 0x20)
    image[0x20:0x24] = b'MOD0'
    struct.pack_into('<i', image, 0x24, DATA_OFF - 0x20)
    struct.pack_into('<I', image, 8, 0xD65F03C0)
    image[0x40:0x40 + len(MARKER)] = MARKER
    image[RO_OFF:RO_OFF + 4] = b'main'
    dynstr = bytearray(b'\0')

    def add(text):
        offset = len(dynstr)
        dynstr.extend(text + b'\0')
        return offset

    nnmain = add(b'nnMain')
    missing = add(b'_import_missing')
    image[DYNSTR_AT:DYNSTR_AT + len(dynstr)] = dynstr
    extra = b'sdk_version: 99.1.2\0fsp-srv\0nvdrv\0' + DIALOGUE + b'\0'
    extra_at = DYNSTR_AT + len(dynstr) + 1
    assert extra_at + len(extra) <= RO_OFF + RO_SIZE
    image[extra_at:extra_at + len(extra)] = extra
    entries = [
        (5, DYNSTR_AT), (10, len(dynstr)), (6, DYNSYM), (11, 24), (4, HASH_AT),
        (7, RELA), (8, 48), (9, 24), (0, 0),
    ]
    blob = b''.join(struct.pack('<qQ', tag, value) for tag, value in entries)
    assert len(blob) <= 0x100
    image[DATA_OFF:DATA_OFF + len(blob)] = blob
    image[DYNSYM:DYNSYM + 72] = b''.join((
        struct.pack('<IBBHQQ', 0, 0, 0, 0, 0, 0),
        struct.pack('<IBBHQQ', nnmain, 0x12, 0, 1, 8, 0),
        struct.pack('<IBBHQQ', missing, 0x12, 0, 0, 0, 0),
    ))
    image[RELA:RELA + 48] = struct.pack('<QQq', SLOT, 1027, 8) + struct.pack('<QQq', SLOT + 8, (2 << 32) | 1025, 0)
    struct.pack_into('<II', image, HASH_AT, 1, 3)
    return bytes(image)


def nso_file(compress_text=False):
    image = memory_image()
    text, ro, data = image[:TEXT_SIZE], image[RO_OFF:RO_OFF + RO_SIZE], image[DATA_OFF:]
    stored = lz4.block.compress(text, store_size=False) if compress_text else text
    header = bytearray(0x100)
    header[:4] = b'NSO0'
    flags = (1 if compress_text else 0) | 8 | 16 | 32
    struct.pack_into('<I', header, 0x0C, flags)
    ro_file = 0x100 + len(stored)
    data_file = ro_file + len(ro)
    struct.pack_into('<IIII', header, 0x10, 0x100, 0, TEXT_SIZE, 0)
    struct.pack_into('<IIII', header, 0x20, ro_file, RO_OFF, RO_SIZE, 4)
    struct.pack_into('<IIII', header, 0x30, data_file, DATA_OFF, DATA_SIZE, 0x20)
    header[0x40:0x60] = BUILD_ID
    struct.pack_into('<III', header, 0x60, len(stored), len(ro), len(data))
    struct.pack_into('<IIII', header, 0x90, 0, 0, DYNSYM - RO_OFF, 72)
    for index, segment in enumerate((text, ro, data)):
        header[0xA0 + 32 * index:0xC0 + 32 * index] = hashlib.sha256(segment).digest()
    return header + stored + ro + data


def _nca(program):
    pfs = _partition([('main', program), ('main.npdm', b'META' + bytes(12))])
    block = 4096
    hashes = b''.join(hashlib.sha256(pfs[i:i + block]).digest() for i in range(0, len(pfs), block))
    pfsoff = (len(hashes) + 15) & ~15
    section = bytearray(pfsoff + len(pfs))
    section[:len(hashes)] = hashes
    section[pfsoff:pfsoff + len(pfs)] = pfs
    fs = bytearray(512)
    fs[2:5] = bytes([1, 2, 3])
    fs[8:40] = hashlib.sha256(hashes).digest()
    struct.pack_into('<IIQQQQ', fs, 0x28, block, 2, 0, len(hashes), pfsoff, len(pfs))
    media = bytes(section).ljust((len(section) + 511) // 512 * 512, b'\0')
    hdr = bytearray(0xC00)
    hdr[0x200:0x204] = b'NCA3'
    hdr[0x205] = 0
    hdr[0x206] = 1
    struct.pack_into('<Q', hdr, 0x210, TITLE)
    hdr[0x300:0x340] = _encrypt(AREA, modes.ECB(), bytes(32) + CONTENT + bytes(16))
    start = 0xC00
    struct.pack_into('<II', hdr, 0x240, start // 512, (start + len(media)) // 512)
    hdr[0x400:0x600] = fs
    hdr[0x280:0x2A0] = hashlib.sha256(fs).digest()
    body = _encrypt(CONTENT, modes.CTR(bytes(8) + (start // 16).to_bytes(8, 'big')), media)
    struct.pack_into('<Q', hdr, 0x208, len(hdr) + len(body))
    encrypted = b''.join(
        _encrypt(HEADER, modes.XTS(i.to_bytes(16, 'big')), hdr[i * 512:(i + 1) * 512]) for i in range(6))
    return encrypted + body


def nsp_bytes(compress_text=False):
    return _partition([('program.nca', _nca(nso_file(compress_text)))])


class Probe(unittest.TestCase):
    def test_parser_matches_prepare_and_hides_code(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                raw = nso_file(compressed)
                report = parse_nso(raw, 'main')
                self.assertNotIn('data', report['segments'][0])
                self.assertEqual(report['build_id'], BUILD_ID.hex())
                self.assertEqual(report['module_name'], 'main')
                self.assertEqual(report['sdk_version'], '99.1.2')
                self.assertEqual(report['imports'], ['_import_missing'])
                self.assertEqual(report['exports'], ['nnMain'])
                self.assertEqual(report['services'], ['fsp-srv', 'nvdrv'])
                self.assertEqual(report['symbol_count'], 3)
                self.assertTrue(report['segments'][0]['compressed'] is compressed)
                blob = json.dumps(report)
                self.assertNotIn(MARKER.decode(), blob)
                self.assertNotIn('copyrighted', blob)
                with tempfile.TemporaryDirectory() as tmp:
                    source = Path(tmp) / 'main'
                    source.write_bytes(raw)
                    prepared = prepare(source, Path(tmp) / 'main.elf')
                self.assertEqual(prepared['build_id'], report['build_id'])
                self.assertEqual(
                    [row['name'] for row in prepared['imports']], report['imports'])
                self.assertEqual(
                    [row['name'] for row in prepared['exports']], report['exports'])

    def test_cli_rejects_wrong_nsp_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp = root / 'game.nsp'
            keys = root / 'prod.keys'
            build = root / 'MCD2_build'
            nsp.write_bytes(b'not a game')
            keys.write_text(f'header_key = {HEADER.hex()}\n')
            result = subprocess.run(
                [sys.executable, str(ROOT / 'games/mcd2/scripts/probe_metadata.py'),
                 '--nsp', str(nsp), '--keys', str(keys), '--build-dir', str(build)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(probe_metadata.NSP_SHA256, result.stderr)
            self.assertNotIn(HEADER.hex(), result.stdout + result.stderr)
            self.assertFalse(build.exists())
            self.assertEqual(result.stdout, '')

    def test_cli_rejects_a_build_dir_inside_the_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp = root / 'game.nsp'
            keys = root / 'prod.keys'
            nsp.write_bytes(nsp_bytes())
            keys.write_text('\n'.join(f'{name} = {value.hex()}' for name, value in (
                ('header_key', HEADER), ('key_area_key_application_00', AREA))))
            inside = ROOT / 'games' / 'mcd2' / 'build'
            result = subprocess.run(
                [sys.executable, str(ROOT / 'games/mcd2/scripts/probe_metadata.py'),
                 '--nsp', str(nsp), '--keys', str(keys), '--build-dir', str(inside)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('outside this repository', result.stderr)
            self.assertFalse(inside.exists())

    def test_probe_writes_only_under_the_build_dir_and_prints_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp = root / 'game.nsp'
            keys = root / 'prod.keys'
            build = root / 'MCD2_build'
            payload = nsp_bytes()
            nsp.write_bytes(payload)
            keys.write_text('\n'.join(f'{name} = {value.hex()}' for name, value in (
                ('header_key', HEADER), ('key_area_key_application_00', AREA))))
            text = probe_metadata.probe(nsp, keys, build, expected_sha256=hashlib.sha256(payload).hexdigest())
            self.assertIn('status: ok', text)
            self.assertIn(f'title_id: {TITLE:016X}', text)
            self.assertIn('import: _import_missing', text)
            self.assertIn('export: nnMain', text)
            self.assertIn('service: fsp-srv', text)
            self.assertIn('service: nvdrv', text)
            self.assertIn('sdk_version: 99.1.2', text)
            self.assertIn(f'build_id: {BUILD_ID.hex()}', text)
            self.assertNotIn(MARKER.decode(), text)
            self.assertNotIn(DIALOGUE.decode(), text)
            self.assertNotIn(HEADER.hex(), text)
            self.assertNotIn(CONTENT.hex(), text)
            written = sorted(path.relative_to(build).as_posix() for path in build.rglob('*') if path.is_file())
            self.assertEqual(written, ['exefs/main', 'exefs/main.npdm', 'meta/main.json'])
            meta = json.loads((build / 'meta' / 'main.json').read_text())
            self.assertNotIn(MARKER.decode(), json.dumps(meta))
            self.assertEqual((build / 'exefs' / 'main').read_bytes()[:4], b'NSO0')


if __name__ == '__main__':
    unittest.main()
