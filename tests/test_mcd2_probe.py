"""Synthetic NSP and NSO fixtures for the Minecraft Dungeons 2 probe. No game bytes."""
import contextlib
import hashlib
import io
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


def _nca(program=None, content=0, rights=None, past_end_section=False, encryption=3, body='ctr', indirect_size=0, files=None):
    if files is None:
        pfs = _partition([('main', program), ('main.npdm', b'META' + bytes(12))])
    else:
        pfs = _partition(files)
    block = 4096
    hashes = b''.join(hashlib.sha256(pfs[i:i + block]).digest() for i in range(0, len(pfs), block))
    pfsoff = (len(hashes) + 15) & ~15
    section = bytearray(pfsoff + len(pfs))
    section[:len(hashes)] = hashes
    section[pfsoff:pfsoff + len(pfs)] = pfs
    fs = bytearray(512)
    fs[2:4] = bytes((1, 2))
    fs[4] = encryption
    fs[8:40] = hashlib.sha256(hashes).digest()
    struct.pack_into('<IIQQQQ', fs, 0x28, block, 2, 0, len(hashes), pfsoff, len(pfs))
    struct.pack_into('<Q', fs, 0x108, indirect_size)
    media = bytes(section).ljust((len(section) + 511) // 512 * 512, b'\0')
    hdr = bytearray(0xC00)
    hdr[0x200:0x204] = b'NCA3'
    hdr[0x205] = content
    hdr[0x206] = 1
    struct.pack_into('<Q', hdr, 0x210, TITLE)
    if rights is None:
        key_head = bytes(range(32)) if body == 'xts' else bytes(32)
        hdr[0x300:0x340] = _encrypt(AREA, modes.ECB(), key_head + CONTENT + bytes(16))
    else:
        hdr[0x230:0x240] = rights
    start = 0xC00
    struct.pack_into('<II', hdr, 0x240, start // 512, (start + len(media)) // 512)
    if past_end_section:
        sectors = (0xC00 + len(media) + 511) // 512
        struct.pack_into('<II', hdr, 0x250, sectors + 1, sectors + 8)
    hdr[0x400:0x600] = fs
    hdr[0x280:0x2A0] = hashlib.sha256(fs).digest()
    if body == 'plain':
        stored = media
    elif body == 'xts':
        stored = b''.join(
            _encrypt(bytes(range(32)), modes.XTS(sector.to_bytes(16, 'big')), media[sector * 512:(sector + 1) * 512])
            for sector in range(len(media) // 512))
    elif body == 'skip':
        stored = bytearray(_encrypt(CONTENT, modes.CTR(bytes(8) + (start // 16).to_bytes(8, 'big')), media))
        stored[:pfsoff] = media[:pfsoff]
        stored = bytes(stored)
    else:
        stored = _encrypt(CONTENT, modes.CTR(bytes(8) + (start // 16).to_bytes(8, 'big')), media)
    struct.pack_into('<Q', hdr, 0x208, len(hdr) + len(stored))
    encrypted = b''.join(
        _encrypt(HEADER, modes.XTS(i.to_bytes(16, 'big')), hdr[i * 512:(i + 1) * 512]) for i in range(6))
    return encrypted + stored


def nsp_bytes(compress_text=False):
    return _partition([('program.nca', _nca(nso_file(compress_text)))])


TITLEKEK = bytes(range(48, 64))
RIGHTS = TITLE.to_bytes(8, 'little') + bytes(8)


def _ticket(key_generation=0, personalized=False):
    data = bytearray(704)
    struct.pack_into('<I', data, 0, 0x10004)
    data[0x180:0x190] = _encrypt(TITLEKEK, modes.ECB(), CONTENT)
    data[0x281] = int(personalized)
    data[0x285] = key_generation
    data[0x2A0:0x2B0] = RIGHTS
    return bytes(data)


def _shell_nca(content, media_start, media_end, pfs=False):
    header = bytearray(0xC00)
    header[0x200:0x204] = b'NCA3'
    header[0x205] = content
    header[0x206] = 1
    struct.pack_into('<Q', header, 0x210, TITLE)
    header[0x300:0x340] = _encrypt(AREA, modes.ECB(), bytes(32) + CONTENT + bytes(16))
    struct.pack_into('<II', header, 0x240, media_start, media_end)
    if pfs:
        header[0x402:0x405] = bytes((1, 2, 3))
    struct.pack_into('<Q', header, 0x208, len(header))
    return b''.join(
        _encrypt(HEADER, modes.XTS(i.to_bytes(16, 'big')), header[i * 512:(i + 1) * 512])
        for i in range(6))


def _sha_pfs(files, block=4096):
    pfs = _partition(files)
    hashes = b''.join(hashlib.sha256(pfs[i:i + block]).digest() for i in range(0, len(pfs), block))
    pfsoff = (len(hashes) + 15) & ~15
    body = bytearray(pfsoff + len(pfs))
    body[:len(hashes)] = hashes
    body[pfsoff:pfsoff + len(pfs)] = pfs
    media = bytes(body).ljust((len(body) + 511) // 512 * 512, b'\0')
    fs = bytearray(512)
    fs[2:4] = bytes((1, 2))
    fs[4] = 3
    fs[8:40] = hashlib.sha256(hashes).digest()
    struct.pack_into('<IIQQQQ', fs, 0x28, block, 2, 0, len(hashes), pfsoff, len(pfs))
    return media, bytes(fs)


def _encrypt_nca_header(header):
    return b''.join(
        _encrypt(HEADER, modes.XTS(i.to_bytes(16, 'big')), bytes(header[i * 512:(i + 1) * 512]))
        for i in range(6))


def _hash_prefixed(prefix, total):
    digest = hashlib.sha256()
    digest.update(prefix)
    remaining = total - len(prefix)
    chunk = b'\0' * (8 << 20)
    while remaining:
        take = chunk if remaining >= len(chunk) else chunk[:remaining]
        digest.update(take)
        remaining -= len(take)
    return digest.digest()


def _shell_prefix(content, size):
    header = bytearray(0xC00)
    header[0x200:0x204] = b'NCA3'
    header[0x205] = content
    header[0x206] = 1
    struct.pack_into('<Q', header, 0x210, TITLE)
    header[0x300:0x340] = _encrypt(AREA, modes.ECB(), bytes(32) + CONTENT + bytes(16))
    struct.pack_into('<Q', header, 0x208, size)
    return _encrypt_nca_header(header)


def _ctr_section(files):
    media, fs = _sha_pfs(files)
    start = 0xC00
    stored = _encrypt(CONTENT, modes.CTR(bytes(8) + (start // 16).to_bytes(8, 'big')), media)
    return stored, fs, start // 512, (start + len(stored)) // 512


def reported_nsp(path):
    """Sparse NSP with the sizes and offsets from the Mac run, plus an in-range logo PFS0.

    Section 0 of the Program NCA is the reported ExeFS range, which ends past the file.
    Section 1 is a PartitionFS that fits and has no main.npdm. The old probe treated that
    logo as proof an ExeFS was present, then aborted with 'no in-range ExeFS'.
    """
    program_id = bytes.fromhex('a1cb976a3d212c3f2bc940f9ca153bff')
    control_id = bytes.fromhex('6a7937b1e1713f271a73dca10739f50d')
    logo, logo_fs, logo_start, logo_end = _ctr_section([('logo', b'LOGO')])
    program_size = 1661878272
    far = bytearray(512)
    far[2:5] = bytes((1, 2, 3))
    program = bytearray(0xC00)
    program[0x200:0x204] = b'NCA3'
    program[0x206] = 1
    struct.pack_into('<Q', program, 0x208, program_size)
    struct.pack_into('<Q', program, 0x210, TITLE)
    program[0x300:0x340] = _encrypt(AREA, modes.ECB(), bytes(32) + CONTENT + bytes(16))
    struct.pack_into('<II', program, 0x240, 8024096, 8208160)
    struct.pack_into('<II', program, 0x250, logo_start, logo_end)
    program[0x280:0x2A0] = hashlib.sha256(far).digest()
    program[0x2A0:0x2C0] = hashlib.sha256(logo_fs).digest()
    program[0x400:0x600] = far
    program[0x600:0x800] = logo_fs
    program_prefix = _encrypt_nca_header(program) + logo
    program_hash = _hash_prefixed(program_prefix, program_size)
    control_size = 541696
    control_prefix = _shell_prefix(2, control_size)
    control_hash = _hash_prefixed(control_prefix, control_size)
    published = hashlib.sha256(b'published-program').digest()
    cnmt_header = bytearray(0x20)
    struct.pack_into('<Q', cnmt_header, 0, TITLE)
    cnmt_header[0xC] = 0x80
    extended = bytes(0x10)
    struct.pack_into('<H', cnmt_header, 0x0E, len(extended))
    struct.pack_into('<HH', cnmt_header, 0x10, 2, 0)
    blob = bytes(cnmt_header) + extended
    for digest, content_id, size, content_type in (
        (published, program_id, 4202577920, 0),
        (control_hash, control_id, control_size, 2),
    ):
        rec = bytearray(0x38)
        rec[:0x20] = digest
        rec[0x20:0x30] = content_id
        rec[0x30:0x36] = size.to_bytes(6, 'little')
        rec[0x36] = content_type
        blob += bytes(rec)
    cnmt = blob + hashlib.sha256(blob).digest()
    meta_body, meta_fs, meta_start, meta_end = _ctr_section([(f'Application_{TITLE:016x}.cnmt', cnmt)])
    meta_size = 3584
    if 0xC00 + len(meta_body) > meta_size:
        raise AssertionError(f'meta section is {0xC00 + len(meta_body)} bytes')
    meta = bytearray(0xC00)
    meta[0x200:0x204] = b'NCA3'
    meta[0x205] = 1
    meta[0x206] = 1
    struct.pack_into('<Q', meta, 0x208, meta_size)
    struct.pack_into('<Q', meta, 0x210, TITLE)
    meta[0x300:0x340] = _encrypt(AREA, modes.ECB(), bytes(32) + CONTENT + bytes(16))
    struct.pack_into('<II', meta, 0x240, meta_start, meta_end)
    meta[0x280:0x2A0] = hashlib.sha256(meta_fs).digest()
    meta[0x400:0x600] = meta_fs
    meta_prefix = _encrypt_nca_header(meta) + meta_body
    manual = _shell_prefix(3, 155648)
    legal = _shell_prefix(3, 16384)
    files = [
        ('0100a7c01b7920000000000000000016.cert', 1792, b'C' * 1792),
        ('0100a7c01b7920000000000000000016.tik', 704, _ticket()),
        ('4ba1c4cde60bf3d5756a5bbeef5bc37c.nca', 155648, manual),
        ('5d93dc5bc32c5724a18c498d7c3d9552.cnmt.nca', 3584, meta_prefix),
        ('5d93dc5bc32c5724a18c498d7c3d9552.cnmt.xml', 1666, b'x' * 1666),
        ('6a7937b1e1713f271a73dca10739f50d.nca', control_size, control_prefix),
        ('a1cb976a3d212c3f2bc940f9ca153bff.nca', program_size, program_prefix),
        ('d934a48b90c733e24497a360cc4d456d.nca', 16384, legal),
    ]
    strings = b''.join(name.encode() + b'\0' for name, _size, _prefix in files)
    strings = strings.ljust(320, b'\0')
    table = bytearray()
    data_off = 0
    for name, size, _prefix in files:
        table += struct.pack('<QQII', data_off, size, strings.find(name.encode() + b'\0'), 0)
        data_off += size
    header = b'PFS0' + struct.pack('<III', len(files), len(strings), 0) + bytes(table) + strings
    if len(header) != 528:
        raise AssertionError(f'PFS0 header is {len(header)} bytes')
    total = len(header) + data_off
    with path.open('wb') as handle:
        handle.truncate(total)
        handle.seek(0)
        handle.write(header)
        cursor = len(header)
        for _name, size, prefix in files:
            handle.seek(cursor)
            handle.write(prefix)
            cursor += size
    return program_hash, published, control_hash, cnmt


def retail_layout_nsp():
    """Cert, common ticket, an NCA whose section ends past the file, then the program.

    File sizes follow the reported PFS0 shape: the first NCA is not 512-byte aligned,
    and a later NCA follows an odd-sized XML file. No game bytes.
    """
    program = _nca(nso_file(), rights=RIGHTS, past_end_section=True)
    return _partition([
        ('0100a7c01b7920000000000000000016.cert', b'C' * 1792),
        ('0100a7c01b7920000000000000000016.tik', _ticket()),
        ('control.nca', _shell_nca(2, 6, 8)),
        ('meta.cnmt.nca', _shell_nca(1, 0, 0)),
        ('meta.cnmt.xml', b'x' * 1666),
        ('program.nca', program),
    ])


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
            inside = ROOT / 'games' / 'mcd2' / 'probe-out'
            result = subprocess.run(
                [sys.executable, str(ROOT / 'games/mcd2/scripts/probe_metadata.py'),
                 '--nsp', str(nsp), '--keys', str(keys), '--build-dir', str(inside)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('outside this repository', result.stderr)
            self.assertFalse(inside.exists())
            host = ROOT / 'games' / 'mcd2' / 'build'
            result = subprocess.run(
                [sys.executable, str(ROOT / 'games/mcd2/scripts/probe_metadata.py'),
                 '--nsp', str(nsp), '--keys', str(keys), '--build-dir', str(host)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse((host / 'exefs').exists())
            self.assertFalse((host / 'meta').exists())

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

    def test_unaligned_ticket_nsp_skips_a_section_past_the_file(self):
        payload = retail_layout_nsp()
        _kind, entries = probe_metadata.container_entries(io.BytesIO(payload), len(payload))
        located = {name: (offset, size) for name, offset, size in entries}
        data_start = min(offset for offset, _size in located.values())
        control_off, _control_size = located['control.nca']
        program_off, _program_size = located['program.nca']
        self.assertNotEqual((control_off - data_start) % 512, 0)
        self.assertNotEqual(program_off % 512, 0)
        self.assertIn('0100a7c01b7920000000000000000016.tik', located)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp = root / 'game.nsp'
            keys = root / 'prod.keys'
            build = root / 'MCD2_build'
            nsp.write_bytes(payload)
            keys.write_text('\n'.join(f'{name} = {value.hex()}' for name, value in (
                ('header_key', HEADER),
                ('key_area_key_application_00', AREA),
                ('titlekek_00', TITLEKEK),
            )))
            text = probe_metadata.probe(
                nsp, keys, build, expected_sha256=hashlib.sha256(payload).hexdigest())
            self.assertIn('status: ok', text)
            self.assertIn(f'title_id: {TITLE:016X}', text)
            self.assertIn('nca: control.nca content_type=2', text)
            self.assertIn('nca: program.nca content_type=0', text)
            self.assertIn('section_skipped: control.nca section 0 media_start 6 media_end 8 byte_start 3072 byte_end 4096', text)
            self.assertIn('section_skipped: program.nca section 1', text)
            self.assertIn('import: _import_missing', text)
            self.assertIn('export: nnMain', text)
            self.assertNotIn(MARKER.decode(), text)
            self.assertNotIn(DIALOGUE.decode(), text)
            self.assertNotIn(HEADER.hex(), text)
            self.assertNotIn(CONTENT.hex(), text)
            self.assertNotIn(TITLEKEK.hex(), text)
            written = sorted(path.relative_to(build).as_posix() for path in build.rglob('*') if path.is_file())
            self.assertEqual(written, ['exefs/main', 'exefs/main.npdm', 'meta/main.json'])

    def test_exefs_section_past_the_file_names_offsets_and_writes_nothing(self):
        program = _shell_nca(0, 6, 8, pfs=True)
        payload = _partition([('program.nca', program)])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp = root / 'game.nsp'
            keys = root / 'prod.keys'
            build = root / 'MCD2_build'
            nsp.write_bytes(payload)
            keys.write_text(f'header_key = {HEADER.hex()}\nkey_area_key_application_00 = {AREA.hex()}\n')
            with self.assertRaises(probe_metadata.ProbeError) as caught:
                probe_metadata.probe(
                    nsp, keys, build, expected_sha256=hashlib.sha256(payload).hexdigest())
            message = str(caught.exception)
            self.assertIn('file appears truncated: expected >= 4096 bytes', message)
            self.assertNotIn('no in-range ExeFS', message)
            self.assertIn('program.nca section 0', message)
            self.assertIn('media_start 6', message)
            self.assertIn('media_end 8', message)
            self.assertIn('byte_start 3072', message)
            self.assertIn('byte_end 4096', message)
            self.assertIn('nca_size 3072', message)
            self.assertIn('nca_offset ', message)
            self.assertNotIn(MARKER.decode(), message)
            self.assertNotIn(HEADER.hex(), message)
            self.assertNotIn(CONTENT.hex(), message)
            self.assertEqual([path for path in build.rglob('*') if path.is_file()], [])

    def _keys(self):
        return '\n'.join(f'{name} = {value.hex()}' for name, value in (
            ('header_key', HEADER),
            ('key_area_key_application_00', AREA),
            ('titlekek_00', TITLEKEK),
        ))

    def _read(self, payload):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp = root / 'game.nsp'
            keys = root / 'prod.keys'
            build = root / 'MCD2_build'
            nsp.write_bytes(payload)
            keys.write_text(self._keys())
            return probe_metadata.probe(
                nsp, keys, build, expected_sha256=hashlib.sha256(payload).hexdigest())

    def test_exefs_accepts_auto_none_xts_and_skip_layer(self):
        cases = ((0, 'ctr'), (1, 'plain'), (2, 'xts'), (4, 'ctr'), (5, 'skip'), (6, 'skip'))
        for encryption, body in cases:
            with self.subTest(encryption=encryption, body=body):
                payload = _partition([('program.nca', _nca(nso_file(), encryption=encryption, body=body))])
                text = self._read(payload)
                self.assertIn('status: ok', text)
                self.assertIn('export: nnMain', text)
                self.assertIn('service: fsp-srv', text)
                self.assertNotIn(MARKER.decode(), text)
                self.assertNotIn(DIALOGUE.decode(), text)
                self.assertNotIn(CONTENT.hex(), text)
                self.assertNotIn(HEADER.hex(), text)

    def test_bktr_exefs_prints_nca_lines_then_the_section_types(self):
        payload = _partition([
            ('control.nca', _shell_nca(2, 6, 8)),
            ('program.nca', _nca(nso_file(), rights=RIGHTS, encryption=4, indirect_size=16)),
            ('0100a7c01b7920000000000000000016.tik', _ticket(key_generation=9)),
        ])
        digest = hashlib.sha256(payload).hexdigest()
        old = probe_metadata.NSP_SHA256
        probe_metadata.NSP_SHA256 = digest
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                nsp = root / 'game.nsp'
                keys = root / 'prod.keys'
                build = root / 'MCD2_build'
                nsp.write_bytes(payload)
                keys.write_text(self._keys())
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    status = probe_metadata.main([
                        '--nsp', str(nsp), '--keys', str(keys), '--build-dir', str(build)])
                text = err.getvalue()
                self.assertEqual(status, 2, text)
                self.assertLess(text.index('nca: control.nca'), text.index('probe:'))
                self.assertLess(text.index('nca: program.nca'), text.index('probe:'))
                self.assertIn(
                    'program.nca section 0 fs_type 1 hash_type 2 encryption_type 4 '
                    'ticket_key_generation 9 titlekey_type common',
                    text)
                self.assertIn('bktr_indirect_size 16', text)
                self.assertNotIn(MARKER.decode(), text)
                self.assertNotIn(CONTENT.hex(), text)
                self.assertNotIn(TITLEKEK.hex(), text)
                self.assertNotIn(HEADER.hex(), text)
                self.assertEqual([path for path in build.rglob('*') if path.is_file()], [])
        finally:
            probe_metadata.NSP_SHA256 = old

    def test_personalized_ticket_is_named_and_not_decrypted(self):
        payload = _partition([
            ('program.nca', _nca(nso_file(), rights=RIGHTS, encryption=3)),
            ('game.tik', _ticket(key_generation=4, personalized=True)),
        ])
        with self.assertRaises(probe_metadata.ProbeError) as caught:
            self._read(payload)
        message = str(caught.exception)
        self.assertIn('titlekey_type personalized', message)
        self.assertIn('ticket_key_generation 4', message)
        self.assertIn('encryption_type 3', message)
        self.assertTrue(any(line.startswith('nca: program.nca') for line in caught.exception.inventory))
        self.assertNotIn(CONTENT.hex(), message)
        self.assertNotIn(TITLEKEK.hex(), message)
        self.assertNotIn(MARKER.decode(), message)

    def test_cnmt_attribute_byte_is_not_a_size_bit(self):
        body = bytearray(0x20 + 0x38)
        struct.pack_into('<HHH', body, 0x0E, 0, 1, 0)
        body[0x20 + 0x30:0x20 + 0x36] = (100).to_bytes(6, 'little')
        body[0x20 + 0x35] = 1
        rows, listed, actual = probe_metadata.packaged_contents(bytes(body))
        self.assertEqual(rows[0]['listed_size'], 100)
        self.assertIsNone(listed)
        self.assertIsNone(actual)
        plain = bytearray(body)
        plain[0x20 + 0x35] = 0
        plain[0x20 + 0x30:0x20 + 0x36] = (100).to_bytes(6, 'little')
        rows, _listed, _actual = probe_metadata.packaged_contents(bytes(plain))
        self.assertEqual(rows[0]['listed_size'], 100)

    def test_short_program_nca_prints_truncation_and_cnmt_hashes(self):
        program_id = bytes.fromhex('a1cb976a3d212c3f2bc940f9ca153bff')
        control_id = bytes.fromhex('6a7937b1e1713f271a73dca10739f50d')
        meta_id = bytes.fromhex('5d93dc5bc32c5724a18c498d7c3d9552')
        program = _shell_nca(0, 6, 8, pfs=True)
        control = _shell_nca(2, 0, 0)
        published = hashlib.sha256(b'published-program').digest()
        control_hash = hashlib.sha256(control).digest()
        header = bytearray(0x20)
        struct.pack_into('<Q', header, 0, TITLE)
        header[0xC] = 0x80
        extended = bytes(0x10)
        struct.pack_into('<H', header, 0x0E, len(extended))
        struct.pack_into('<HH', header, 0x10, 2, 0)
        blob = bytes(header) + extended
        for digest, content_id, size, content_type in (
            (published, program_id, 4096, 0),
            (control_hash, control_id, len(control), 2),
        ):
            rec = bytearray(0x38)
            rec[:0x20] = digest
            rec[0x20:0x30] = content_id
            rec[0x30:0x36] = size.to_bytes(6, 'little')
            rec[0x36] = content_type
            blob += bytes(rec)
        cnmt = blob + hashlib.sha256(blob).digest()
        meta = _nca(content=1, files=[(f'Application_{TITLE:016x}.cnmt', cnmt)])
        payload = _partition([
            (program_id.hex() + '.nca', program),
            (control_id.hex() + '.nca', control),
            (meta_id.hex() + '.cnmt.nca', meta),
        ])
        digest = hashlib.sha256(payload).hexdigest()
        program_hash = hashlib.sha256(program).hexdigest()
        old = probe_metadata.NSP_SHA256
        probe_metadata.NSP_SHA256 = digest
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                nsp = root / 'game.nsp'
                keys = root / 'prod.keys'
                build = root / 'MCD2_build'
                nsp.write_bytes(payload)
                keys.write_text(self._keys())
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    status = probe_metadata.main([
                        '--nsp', str(nsp), '--keys', str(keys), '--build-dir', str(build)])
                text = err.getvalue()
                self.assertEqual(status, 2, text)
                self.assertLess(text.index('nca:'), text.index('section_end:'))
                self.assertLess(text.index('section_end:'), text.index('section_header:'))
                self.assertLess(text.index('section_header:'), text.index('cnmt:'))
                self.assertLess(text.index('cnmt:'), text.index('probe:'))
                self.assertIn('file appears truncated: expected >= 4096 bytes', text)
                self.assertIn(
                    f'cnmt: {program_id.hex()} content_type=0 listed_size=4096 '
                    f'actual_size={len(program)} listed_sha256={published.hex()} '
                    f'actual_sha256={program_hash}',
                    text)
                self.assertIn(
                    f'cnmt: {control_id.hex()} content_type=2 listed_size={len(control)} '
                    f'actual_size={len(control)} listed_sha256={control_hash.hex()} '
                    f'actual_sha256={control_hash.hex()}',
                    text)
                self.assertIn('cnmt_digest:', text)
                self.assertNotIn('no in-range ExeFS', text)
                self.assertNotIn(MARKER.decode(), text)
                self.assertNotIn(HEADER.hex(), text)
                self.assertNotIn(CONTENT.hex(), text)
                self.assertNotIn(TITLEKEK.hex(), text)
                self.assertNotIn(cnmt.hex(), text)
                self.assertEqual([path for path in build.rglob('*') if path.is_file()], [])
        finally:
            probe_metadata.NSP_SHA256 = old

    def test_reported_layout_logo_used_to_hide_the_short_program_section(self):
        old_probe = (
            'probe: no in-range ExeFS; a1cb976a3d212c3f2bc940f9ca153bff.nca section 0 '
            'media_start 8024096 media_end 8208160 byte_start 4108337152 byte_end 4202577920 '
            'nca_offset 705618 nca_size 1661878272 fstype 1 hashtype 2 crypt 3'
        )
        nca_lines = [
            'nca: 4ba1c4cde60bf3d5756a5bbeef5bc37c.nca content_type=3 title_id=0100A7C01B792000 size=155648 offset=3024',
            'nca: 5d93dc5bc32c5724a18c498d7c3d9552.cnmt.nca content_type=1 title_id=0100A7C01B792000 size=3584 offset=158672',
            'nca: 6a7937b1e1713f271a73dca10739f50d.nca content_type=2 title_id=0100A7C01B792000 size=541696 offset=163922',
            'nca: a1cb976a3d212c3f2bc940f9ca153bff.nca content_type=0 title_id=0100A7C01B792000 size=1661878272 offset=705618',
            'nca: d934a48b90c733e24497a360cc4d456d.nca content_type=3 title_id=0100A7C01B792000 size=16384 offset=1662583890',
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp = root / 'game.nsp'
            program_hash, published, control_hash, cnmt = reported_nsp(nsp)
            digest = hashlib.sha256()
            with nsp.open('rb') as handle:
                while chunk := handle.read(8 << 20):
                    digest.update(chunk)
            digest = digest.hexdigest()
            keys = root / 'prod.keys'
            build = root / 'MCD2_build'
            keys.write_text(self._keys())
            old = probe_metadata.NSP_SHA256
            probe_metadata.NSP_SHA256 = digest
            try:
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    status = probe_metadata.main([
                        '--nsp', str(nsp), '--keys', str(keys), '--build-dir', str(build)])
                text = err.getvalue()
                self.assertEqual(status, 2, text)
                lines = text.splitlines()
                self.assertEqual(lines[:5], nca_lines)
                self.assertLess(text.index('nca:'), text.index('section_end:'))
                self.assertLess(text.index('section_end:'), text.index('section_header:'))
                self.assertLess(text.index('section_header:'), text.index('cnmt:'))
                self.assertLess(text.index('cnmt:'), text.index('probe:'))
                self.assertNotIn('no in-range ExeFS', text)
                self.assertIn('file appears truncated: expected >= 4202577920 bytes', text)
                self.assertIn(old_probe.split('no in-range ExeFS; ', 1)[1], text)
                self.assertIn(
                    'cnmt: a1cb976a3d212c3f2bc940f9ca153bff content_type=0 '
                    f'listed_size=4202577920 actual_size=1661878272 '
                    f'listed_sha256={published.hex()} actual_sha256={program_hash.hex()}',
                    text)
                self.assertIn(
                    'cnmt: 6a7937b1e1713f271a73dca10739f50d content_type=2 '
                    f'listed_size=541696 actual_size=541696 '
                    f'listed_sha256={control_hash.hex()} actual_sha256={control_hash.hex()}',
                    text)
                self.assertNotIn(MARKER.decode(), text)
                self.assertNotIn(b'LOGO'.decode(), text)
                self.assertNotIn(HEADER.hex(), text)
                self.assertNotIn(CONTENT.hex(), text)
                self.assertNotIn(TITLEKEK.hex(), text)
                self.assertNotIn(cnmt.hex(), text)
                self.assertEqual([path for path in build.rglob('*') if path.is_file()], [])
            finally:
                probe_metadata.NSP_SHA256 = old


if __name__ == '__main__':
    unittest.main()
