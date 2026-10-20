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
    common_tickets, container_entries, load_keys, nca_ctr_key, nca_inventory,
    partition_entries, read_at, require,
)
from extract_exefs import decrypt  # noqa: E402
from cryptography.hazmat.primitives.ciphers import modes  # noqa: E402

from nso_meta import parse_nso  # noqa: E402

EXPECTED = json.loads((REPO / 'games' / 'mcd2' / 'assets' / 'expected-base.json').read_text())
TITLE_ID = EXPECTED['title_id']
NSP_SHA256 = EXPECTED['nsp_sha256']


class ProbeError(Exception):
    pass


def _fail(message):
    raise ProbeError(message)


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


def exefs_members(game, keys, record, hdr, tickets):
    """Same ExeFS section walk as extract_exefs.main, for TITLE_ID, returning bytes."""
    ctr_key = nca_ctr_key(hdr, keys, tickets)
    offset = record['nca_offset']
    with game.open('rb') as handle:
        for index in range(4):
            start, end = struct.unpack_from('<II', hdr, 0x240 + 16 * index)
            if not start:
                continue
            fs = hdr[0x400 + 512 * index:0x600 + 512 * index]
            require(hashlib.sha256(fs).digest() == hdr[0x280 + 32 * index:0x2A0 + 32 * index],
                    'FS header hash mismatch')
            if fs[2:4] != b'\x01\x02':
                continue
            require(fs[4] == 3, 'Only AES-CTR ExeFS is supported')
            blocksize, levels = struct.unpack_from('<II', fs, 0x28)
            hashoff, hashsize, pfsoff, pfssize = struct.unpack_from('<QQQQ', fs, 0x30)
            secstart, secsize = start * 512, (end - start) * 512
            require(levels == 2 and blocksize > 0 and pfssize <= 512 * 1024 * 1024,
                    'Unsupported ExeFS hash layout')

            def section_read(relative, size):
                require(relative >= 0 and relative + size <= secsize, 'Section read out of bounds')
                absolute = secstart + relative
                aligned = absolute & ~15
                iv = fs[0x140:0x148][::-1] + (aligned // 16).to_bytes(8, 'big')
                data = read_at(handle, offset + aligned, size + absolute - aligned)
                return decrypt(ctr_key, modes.CTR(iv), data)[absolute - aligned:]

            hashes = section_read(hashoff, hashsize)
            require(hashlib.sha256(hashes).digest() == fs[8:40], 'ExeFS hash-table mismatch')
            pfs = section_read(pfsoff, pfssize)
            for block, pos in enumerate(range(0, pfssize, blocksize)):
                expected = hashes[block * 32:(block + 1) * 32]
                require(hashlib.sha256(pfs[pos:pos + blocksize]).digest() == expected,
                        f'ExeFS block hash mismatch: {block}')
            files = [(member, pfs[off:off + size]) for member, off, size in
                     partition_entries(io.BytesIO(pfs), 0, len(pfs))]
            require(any(member == 'main.npdm' for member, _payload in files), 'PFS0 is not ExeFS')
            return files
    _fail('No ExeFS section found')


def format_report(nsp_digest, expected_sha256, members):
    lines = [
        'status: ok',
        f'nsp_sha256: {nsp_digest}',
        f'expected_nsp_sha256: {expected_sha256}',
        f'title_id: {TITLE_ID}',
        f'modules: {sum(1 for item in members if item.get("segments"))}',
    ]
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
            tickets = common_tickets(handle, entries)
            records = nca_inventory(handle, entries, keys)
        record, hdr = program_record(records)
        files = exefs_members(nsp, keys, record, hdr, tickets)
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
    return format_report(digest, expected_sha256, reports)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nsp', required=True, type=Path)
    parser.add_argument('--keys', required=True, type=Path)
    parser.add_argument('--build-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        sys.stdout.write(probe(args.nsp, args.keys, args.build_dir))
    except (ProbeError, ValueError, OSError) as error:
        print(f'probe: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
