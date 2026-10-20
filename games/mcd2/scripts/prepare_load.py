#!/usr/bin/env python3
"""Rewrite probed ExeFS modules with the native NSO ruleset.

Output stays under --build-dir/rewritten. The rewriter is games/totk/third_party/d2r/patch_nso.py
with DM_RULESET=native. This does not copy TOTK addresses into the image.

  python3 games/mcd2/scripts/prepare_load.py --build-dir /path/to/MCD2_build
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PATCH = REPO / 'games' / 'totk' / 'third_party' / 'd2r' / 'patch_nso.py'
HEX_RUN = re.compile(r'[0-9a-fA-F]{64,}')


def fail(message):
    print(f'prepare: {message}', file=sys.stderr)
    return 2


def safe_tail(text):
    lines = []
    for line in text.splitlines()[-20:]:
        if len(line) > 240:
            line = line[:240] + ' ...'
        lines.append(HEX_RUN.sub('<hex>', line))
    return '\n'.join(lines)


def prepare(build):
    exefs = build / 'exefs'
    meta = build / 'meta'
    rewritten = build / 'rewritten'
    if not exefs.is_dir() or not meta.is_dir():
        raise SystemExit(fail('run the probe first so exefs/ and meta/ exist in the build dir'))
    rewritten.mkdir(exist_ok=True)
    logs = build / 'logs'
    logs.mkdir(exist_ok=True)
    def is_nso(path):
        with path.open('rb') as handle:
            return handle.read(4) == b'NSO0'

    modules = sorted(path for path in exefs.iterdir() if path.is_file() and is_nso(path))
    if not modules:
        raise SystemExit(fail('no NSO modules in exefs'))
    env = os.environ.copy()
    env['DM_RULESET'] = 'native'
    env['DM_PRIVATE_GATES'] = '0'
    for module in modules:
        log_path = logs / f'patch-{module.name}.log'
        result = subprocess.run(
            [sys.executable, str(PATCH), str(module), str(rewritten), module.name],
            env=env, cwd=REPO, capture_output=True, text=True)
        log_path.write_text(result.stdout + result.stderr)
        tail = safe_tail(result.stdout + result.stderr)
        if result.returncode != 0:
            print(tail, file=sys.stderr)
            raise SystemExit(fail(f'{module.name} rewrite failed; log {log_path.name}'))
        report = json.loads((meta / f'{module.name}.json').read_text())
        fixups = rewritten / f'{module.name}.fixups.tsv'
        text = fixups.read_text()
        if 'SYMBOL_COUNT' not in text:
            fixups.write_text(text + f"# SYMBOL_COUNT\t{report['symbol_count']}\n")
        if tail:
            print(tail)
        print(f"rewrote {module.name}")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        return prepare(args.build_dir)
    except (OSError, json.JSONDecodeError, KeyError) as error:
        return fail(str(error))


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
