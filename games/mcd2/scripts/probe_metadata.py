#!/usr/bin/env python3
"""Print Minecraft Dungeons 2 module metadata from a local base NSP.

Decrypted ExeFS members are written only under --build-dir. The build dir must
sit outside this repository. Stdout is names, sizes, ids, and hashes.

  python3 games/mcd2/scripts/probe_metadata.py \\
      --nsp /path/to/base.nsp --keys /path/to/prod.keys --build-dir /path/to/MCD2_build
"""
import argparse
import hashlib
import io
import json
import shutil
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / 'games' / 'totk' / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from extract_exefs import (  # noqa: E402
    container_entries, load_keys, nca_ctr_key,
    partition_entries, read_at, require,
)
from extract_exefs import decrypt  # noqa: E402
from cryptography.hazmat.primitives.ciphers import modes  # noqa: E402

from nso_meta import parse_nso  # noqa: E402

EXPECTED = json.loads((REPO / 'games' / 'mcd2' / 'assets' / 'expected-base.json').read_text())
TITLE_ID = EXPECTED['title_id']
NSP_SHA256 = EXPECTED['nsp_sha256']


class ProbeError(Exception):
    def __init__(self, message, inventory=()):
        super().__init__(message)
        self.inventory = tuple(inventory)


def _fail(message, inventory=()):
    raise ProbeError(message, inventory)


_TICKET_BODIES = {
    0x10000: 0x240, 0x10001: 0x140, 0x10002: 0x80,
    0x10003: 0x240, 0x10004: 0x140, 0x10005: 0x80,
}


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while chunk := handle.read(8 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def outside_repo(path):
    resolved = path.resolve()
    if resolved == Path('/') or len(resolved.parts) < 3:
        return False
    if resolved == REPO or REPO in resolved.parents:
        return False
    return True


def inside_build(build, path):
    root = build.resolve()
    resolved = path.resolve()
    return resolved == root or root in resolved.parents


def decrypt_nca_header(handle, name, offset, size, keys):
    if size < 0xC00:
        _fail(f'{name} truncated header: nca_offset {offset} nca_size {size}')
    if 'header_key' not in keys:
        _fail('Missing header_key in prod.keys')
    raw = read_at(handle, offset, 0xC00)
    header = b''.join(
        decrypt(keys['header_key'], modes.XTS(sector.to_bytes(16, 'big')), raw[sector * 512:(sector + 1) * 512])
        for sector in range(6))
    if header[0x200:0x204] != b'NCA3':
        _fail(f'{name} is not NCA3 at nca_offset {offset} nca_size {size}')
    content_size = struct.unpack_from('<Q', header, 0x208)[0]
    if content_size != size:
        _fail(
            f'{name} content_size {content_size} != nca_size {size} at nca_offset {offset}')
    return header


def section_rows(header):
    rows = []
    for index in range(4):
        start, end = struct.unpack_from('<II', header, 0x240 + 16 * index)
        if start == 0 and end == 0:
            continue
        rows.append((index, start, end))
    return rows


def section_in_file(start, end, size):
    if start == 0 or start >= end:
        return False
    byte_start = start * 512
    byte_end = end * 512
    return 0xC00 <= byte_start < byte_end <= size


def describe_section(name, offset, size, index, start, end, header):
    fs = header[0x400 + 512 * index:0x400 + 512 * index + 5]
    return (
        f'{name} section {index} media_start {start} media_end {end} '
        f'byte_start {start * 512} byte_end {end * 512} '
        f'nca_offset {offset} nca_size {size} '
        f'fstype {fs[2]} hashtype {fs[3]} crypt {fs[4]}'
    )


def nca_records(handle, entries, keys):
    records = []
    for name, offset, length in entries:
        if not name.lower().endswith('.nca'):
            continue
        header = decrypt_nca_header(handle, name, offset, length, keys)
        record = dict(
            name=name, nca_offset=offset, size=length, content_type=header[0x205],
            title_id=f'{struct.unpack_from("<Q", header, 0x210)[0]:016X}')
        records.append((record, header))
    return records


def skipped_sections(records):
    notes = []
    for record, header in records:
        for index, start, end in section_rows(header):
            if section_in_file(start, end, record['size']):
                continue
            notes.append(describe_section(
                record['name'], record['nca_offset'], record['size'], index, start, end, header))
    return notes


def program_record(records):
    programs = [(record, hdr) for record, hdr in records if record['content_type'] == 0]
    if len(programs) != 1:
        _fail(f'expected one Program NCA, found {len(programs)}')
    record, hdr = programs[0]
    if record['title_id'] != TITLE_ID:
        _fail(f"program title {record['title_id']} is not {TITLE_ID}")
    metadata = [item for item, _hdr in records if item['content_type'] == 1]
    if any(item['title_id'] != TITLE_ID for item in metadata):
        _fail('metadata NCA title does not match the program')
    return record, hdr


def read_tickets(handle, entries):
    found = []
    for _name, offset, size in entries:
        if not _name.lower().endswith('.tik'):
            continue
        if size < 4:
            _fail('Truncated NSP ticket')
        signature = struct.unpack('<I', read_at(handle, offset, 4))[0]
        if signature not in _TICKET_BODIES:
            _fail('Unsupported NSP ticket signature type')
        body = _TICKET_BODIES[signature]
        if size < body + 0x180:
            _fail('Truncated NSP ticket body')
        data = read_at(handle, offset + body, 0x180)
        kind_byte = data[0x141]
        if kind_byte == 0:
            kind = 'common'
        elif kind_byte == 1:
            kind = 'personalized'
        else:
            kind = str(kind_byte)
        found.append({
            'rights': data[0x160:0x170],
            'enc_key': data[0x40:0x50] if kind == 'common' else None,
            'titlekey_type': kind,
            'key_generation': data[0x145],
        })
    return found


def ticket_for(header, tickets):
    rights = header[0x230:0x240]
    if rights == bytes(16):
        return None
    matches = [item for item in tickets if item['rights'] == rights]
    if not matches:
        return None
    first = matches[0]
    if any(item['titlekey_type'] != first['titlekey_type'] or item['key_generation'] != first['key_generation']
           or item['enc_key'] != first['enc_key'] for item in matches[1:]):
        _fail('Conflicting NSP tickets')
    return first


def ticket_fields(ticket):
    if ticket is None:
        return 'ticket_key_generation absent titlekey_type absent'
    return f"ticket_key_generation {ticket['key_generation']} titlekey_type {ticket['titlekey_type']}"


def section_crypto_line(name, index, fs, ticket):
    return (
        f'{name} section {index} fs_type {fs[2]} hash_type {fs[3]} '
        f'encryption_type {fs[4]} {ticket_fields(ticket)}'
    )


def key_area_plain(header, keys):
    generation = max(max(header[0x206], header[0x220]) - 1, 0)
    if header[0x207] >= 3:
        _fail('Unsupported NCA key area')
    area = ('application', 'ocean', 'system')[header[0x207]]
    keyname = f'key_area_key_{area}_{generation:02x}'
    if keyname not in keys:
        _fail(f'Missing {keyname} in prod.keys')
    return decrypt(keys[keyname], modes.ECB(), header[0x300:0x340])


def content_key(header, keys, ticket, line):
    rights = header[0x230:0x240]
    try:
        if rights != bytes(16):
            if ticket is None or ticket['titlekey_type'] != 'common':
                _fail(line)
            return nca_ctr_key(header, keys, {rights: ticket['enc_key']})
        return nca_ctr_key(header, keys, {})
    except ValueError as error:
        _fail(f'{line} {error}')


def xts_key(header, keys, line):
    if header[0x230:0x240] != bytes(16):
        _fail(f'{line} aes-xts section uses a rights id')
    plain = key_area_plain(header, keys)
    if plain[0:16] == plain[16:32]:
        _fail(f'{line} aes-xts key halves are equal')
    return plain[0:32]


def nca_lines(records):
    return [
        f"nca: {record['name']} content_type={record['content_type']} "
        f"title_id={record['title_id']} size={record['size']} offset={record['nca_offset']}"
        for record, _header in records
    ]


def exefs_members(game, keys, record, hdr, tickets):
    """ExeFS walk for the program NCA. Sections that do not fit in the file are skipped."""
    offset = record['nca_offset']
    ticket = ticket_for(hdr, tickets)
    skipped = []
    with game.open('rb') as handle:
        for index, start, end in section_rows(hdr):
            fs = hdr[0x400 + 512 * index:0x600 + 512 * index]
            if not section_in_file(start, end, record['size']):
                if fs[2:4] == b'\x01\x02':
                    skipped.append(describe_section(
                        record['name'], offset, record['size'], index, start, end, hdr))
                continue
            if fs[2:4] != b'\x01\x02':
                continue
            line = section_crypto_line(record['name'], index, fs, ticket)
            require(hashlib.sha256(fs).digest() == hdr[0x280 + 32 * index:0x2A0 + 32 * index],
                    f'{line} FS header hash mismatch')
            crypt = fs[4]
            indirect_size = struct.unpack_from('<Q', fs, 0x108)[0]
            ex_size = struct.unpack_from('<Q', fs, 0x128)[0]
            if crypt == 0:
                crypt = 3
            elif crypt in (4, 6):
                if indirect_size or ex_size:
                    _fail(f'{line} bktr_indirect_size {indirect_size} bktr_ex_size {ex_size}')
                crypt = 5 if crypt == 6 else 3
            if crypt not in (1, 2, 3, 5):
                _fail(line)
            blocksize, levels = struct.unpack_from('<II', fs, 0x28)
            hashoff, hashsize, pfsoff, pfssize = struct.unpack_from('<QQQQ', fs, 0x30)
            secstart, secsize = start * 512, (end - start) * 512
            require(levels == 2 and blocksize > 0 and pfssize <= 512 * 1024 * 1024,
                    f'{line} Unsupported ExeFS hash layout')
            key = None
            if crypt == 2:
                key = xts_key(hdr, keys, line)
            elif crypt in (3, 5):
                key = content_key(hdr, keys, ticket, line)

            def section_read(relative, size, crypt=crypt, key=key, secstart=secstart, secsize=secsize):
                require(0 <= relative and relative + size <= secsize, f'{line} Section read out of bounds')
                absolute = secstart + relative

                def raw_at(origin, length):
                    return read_at(handle, offset + origin, length)

                def read_ctr(origin, length):
                    aligned = origin & ~15
                    iv = fs[0x140:0x148][::-1] + (aligned // 16).to_bytes(8, 'big')
                    data = raw_at(aligned, length + origin - aligned)
                    return decrypt(key, modes.CTR(iv), data)[origin - aligned:]

                def read_xts(origin, length):
                    start_sector = origin & ~511
                    end = (origin + length + 511) & ~511
                    blob = raw_at(secstart + start_sector, end - start_sector)
                    plain = b''.join(
                        decrypt(key, modes.XTS(((start_sector // 512) + sector).to_bytes(16, 'big')),
                                blob[sector * 512:(sector + 1) * 512])
                        for sector in range((end - start_sector) // 512))
                    return plain[origin - start_sector:origin - start_sector + length]

                if crypt == 1:
                    return raw_at(absolute, size)
                if crypt == 2:
                    return read_xts(relative, size)
                if crypt != 5 or relative >= pfsoff:
                    return read_ctr(absolute, size)
                if relative + size <= pfsoff:
                    return raw_at(absolute, size)
                head = pfsoff - relative
                return raw_at(absolute, head) + read_ctr(absolute + head, size - head)

            hashes = section_read(hashoff, hashsize)
            require(hashlib.sha256(hashes).digest() == fs[8:40], f'{line} ExeFS hash-table mismatch')
            pfs = section_read(pfsoff, pfssize)
            for block, pos in enumerate(range(0, pfssize, blocksize)):
                expected = hashes[block * 32:(block + 1) * 32]
                require(hashlib.sha256(pfs[pos:pos + blocksize]).digest() == expected,
                        f'{line} ExeFS block hash mismatch: {block}')
            try:
                members = partition_entries(io.BytesIO(pfs), 0, len(pfs))
            except ValueError as error:
                _fail(f'{line} {error}')
            files = [(member, pfs[off:off + size]) for member, off, size in members]
            if any(member == 'main.npdm' for member, _payload in files):
                return files
    if skipped:
        _fail('no in-range ExeFS; ' + '; '.join(skipped))
    _fail('No ExeFS section found')


def format_report(nsp_digest, expected_sha256, members, records, skipped):
    lines = [
        'status: ok',
        f'nsp_sha256: {nsp_digest}',
        f'expected_nsp_sha256: {expected_sha256}',
        f'title_id: {TITLE_ID}',
        f'modules: {sum(1 for item in members if item.get("segments"))}',
    ]
    for record, _header in records:
        lines.append(
            f"nca: {record['name']} content_type={record['content_type']} "
            f"title_id={record['title_id']} size={record['size']} offset={record['nca_offset']}"
        )
    for note in skipped:
        lines.append(f'section_skipped: {note}')
    for item in members:
        lines.append(f"module: {item['module']}")
        lines.append(f"file_size: {item['file_size']}")
        lines.append(f"file_sha256: {item['file_sha256']}")
        if 'segments' not in item:
            lines.append('kind: exefs')
            continue
        lines.append(f"build_id: {item['build_id']}")
        lines.append(f"module_name: {item['module_name'] or 'absent'}")
        lines.append(f"sdk_version: {item['sdk_version'] or 'absent'}")
        lines.append(f"symbol_count: {item['symbol_count']}")
        for seg in item['segments']:
            lines.append(
                f"segment: {seg['name']} memory=0x{seg['memory']:x} size=0x{seg['size']:x} "
                f"bss=0x{seg['bss']:x} compressed={int(seg['compressed'])} sha256={seg['sha256']}"
            )
        for needed in item['needed']:
            lines.append(f'needed: {needed}')
        for symbol in item['imports']:
            lines.append(f'import: {symbol}')
        for symbol in item['exports']:
            lines.append(f'export: {symbol}')
        for service in item['services']:
            lines.append(f'service: {service}')
    return '\n'.join(lines) + '\n'


def probe(nsp, keys_path, build, expected_sha256=None):
    """Decrypt into build and return the metadata report. The CLI always passes the pinned hash."""
    expected_sha256 = NSP_SHA256 if expected_sha256 is None else expected_sha256
    if not outside_repo(build):
        _fail('build dir must be a directory outside this repository')
    if not nsp.is_file():
        _fail('NSP path is not a file')
    if not keys_path.is_file():
        _fail('keys path is not a file')
    digest = file_sha256(nsp)
    if digest != expected_sha256:
        _fail(f'nsp sha256 {digest} is not the pinned base NSP {expected_sha256}')
    build.mkdir(parents=True, exist_ok=True)
    staging = build / 'exefs.partial'
    meta_dir = build / 'meta.partial'
    if staging.exists():
        shutil.rmtree(staging)
    if meta_dir.exists():
        shutil.rmtree(meta_dir)
    staging.mkdir()
    meta_dir.mkdir()
    if not inside_build(build, staging) or not inside_build(build, meta_dir):
        _fail('refusing to write outside the build dir')
    try:
        keys = load_keys(keys_path)
        with nsp.open('rb') as handle:
            kind, entries = container_entries(handle, nsp.stat().st_size)
        if kind != 'nsp':
            _fail(f'{kind} is not the pinned NSP container')
        with nsp.open('rb') as handle:
            records = nca_records(handle, entries, keys)
        try:
            with nsp.open('rb') as handle:
                tickets = read_tickets(handle, entries)
            record, hdr = program_record(records)
            files = exefs_members(nsp, keys, record, hdr, tickets)
        except Exception as error:
            inventory = error.inventory if isinstance(error, ProbeError) and error.inventory else nca_lines(records)
            raise ProbeError(str(error), inventory) from None
        skipped = skipped_sections(records)
        reports = []
        for name, data in files:
            destination = staging / name
            if not inside_build(build, destination):
                _fail('refusing to write outside the build dir')
            destination.write_bytes(data)
            if data[:4] == b'NSO0':
                report = parse_nso(data, name)
                (meta_dir / f'{name}.json').write_text(json.dumps(report, indent=2) + '\n')
                reports.append(report)
            else:
                reports.append({
                    'module': name,
                    'file_size': len(data),
                    'file_sha256': hashlib.sha256(data).hexdigest(),
                })
        final_exefs = build / 'exefs'
        final_meta = build / 'meta'
        if final_exefs.exists():
            shutil.rmtree(final_exefs)
        if final_meta.exists():
            shutil.rmtree(final_meta)
        staging.rename(final_exefs)
        meta_dir.rename(final_meta)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(meta_dir, ignore_errors=True)
        raise
    return format_report(digest, expected_sha256, reports, records, skipped)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nsp', required=True, type=Path)
    parser.add_argument('--keys', required=True, type=Path)
    parser.add_argument('--build-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        sys.stdout.write(probe(args.nsp, args.keys, args.build_dir))
    except (ProbeError, ValueError, OSError) as error:
        for line in getattr(error, 'inventory', ()):
            print(line, file=sys.stderr)
        print(f'probe: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
