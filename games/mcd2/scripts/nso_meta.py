"""NSO header and dynamic-symbol metadata. The returned dict never contains segment bytes."""
import hashlib
import re
import struct

_SERVICE = re.compile(
    r'(?:[a-z][a-z0-9]{0,12}-srv|nvdrv(?::[a-z])?|[a-z][a-z0-9]{0,16}:[a-z][a-z0-9]{0,3})'
)
_SDK = re.compile(rb'sdk_version: ([0-9.]+)')


def _need(ok, message):
    if not ok:
        raise ValueError(message)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _decompress(payload, size):
    import lz4.block
    data = lz4.block.decompress(payload, uncompressed_size=size)
    _need(len(data) == size, 'NSO decompression size mismatch')
    return data


def _services(blob):
    found = []
    for raw in blob.split(b'\0'):
        if not raw or len(raw) > 32 or not raw.isascii() or any(b < 0x21 or b > 0x7e for b in raw):
            continue
        text = raw.decode('ascii')
        if _SERVICE.fullmatch(text):
            found.append(text)
    return sorted(set(found))


def _sdk_version(blob):
    match = _SDK.search(blob)
    if not match:
        return None
    return match.group(1).decode('ascii')


def parse_nso(raw, name):
    """Return module metadata for one NSO0 file. raw stays with the caller."""
    _need(raw[:4] == b'NSO0' and len(raw) >= 0x100, f'{name}: expected NSO0')
    flags = struct.unpack_from('<I', raw, 0x0C)[0]
    compressed = struct.unpack_from('<III', raw, 0x60)
    segments = []
    image_size = 0
    for index, seg_name in enumerate(('text', 'rodata', 'data')):
        fileoff, address, size, extra = struct.unpack_from('<IIII', raw, 0x10 + 16 * index)
        stored = compressed[index] if flags & (1 << index) else size
        _need(fileoff + stored <= len(raw) and size <= 256 * 1024 * 1024, f'{name}: invalid {seg_name} segment')
        payload = raw[fileoff:fileoff + stored]
        data = _decompress(payload, size) if flags & (1 << index) else payload
        _need(len(data) == size, f'{name}: {seg_name} size mismatch')
        digest = hashlib.sha256(data).digest()
        if flags & (8 << index):
            _need(digest == raw[0xA0 + 32 * index:0xC0 + 32 * index], f'{name}: {seg_name} hash mismatch')
        image_size = max(image_size, address + size)
        segments.append({
            'name': seg_name,
            'memory': address,
            'size': size,
            'extra': extra,
            'sha256': digest.hex(),
            'compressed': bool(flags & (1 << index)),
            'data': data,
        })
    _need(image_size <= 512 * 1024 * 1024, f'{name}: image too large')
    image = bytearray(image_size)
    for seg in segments:
        image[seg['memory']:seg['memory'] + seg['size']] = seg['data']

    def span(address, size):
        _need(0 <= address and address + size <= len(image), f'{name}: metadata outside the image')
        return bytes(image[address:address + size])

    modoff = struct.unpack_from('<I', image, 4)[0]
    _need(span(modoff, 4) == b'MOD0', f'{name}: expected MOD0')
    dynoff = modoff + struct.unpack_from('<i', image, modoff + 4)[0]
    dynamic = []
    for _ in range(4096):
        tag, value = struct.unpack('<qQ', span(dynoff + 16 * len(dynamic), 16))
        dynamic.append((tag, value))
        if tag == 0:
            break
    else:
        raise ValueError(f'{name}: unterminated dynamic table')
    tags = dict(dynamic)
    _need(5 in tags and 6 in tags and 10 in tags and 11 in tags, f'{name}: dynamic table lacks symbols')
    _need(tags[11] == 24, f'{name}: expected ELF64 symbols')
    strings = span(tags[5], tags[10])

    def string_at(offset):
        _need(0 <= offset < len(strings), f'{name}: invalid dynstr offset')
        end = strings.find(b'\0', offset)
        _need(end >= 0, f'{name}: unterminated dynstr')
        return strings[offset:end].decode('utf-8', 'replace')

    symoff = tags[6]
    if 4 in tags:
        _nbucket, nchain = struct.unpack('<II', span(tags[4], 8))
        symcount = nchain
    else:
        _a, _b, syms_offset, syms_size = struct.unpack_from('<IIII', raw, 0x90)
        ro = segments[1]['memory']
        _need(ro + syms_offset == symoff and syms_size % 24 == 0, f'{name}: cannot establish symbol count')
        symcount = syms_size // 24
    imports = []
    exports = []
    for index in range(symcount):
        name_off, info, _other, section, _value, _size = struct.unpack('<IBBHQQ', span(symoff + 24 * index, 24))
        symbol = string_at(name_off)
        if not symbol:
            continue
        if section == 0:
            imports.append(symbol)
        else:
            exports.append(symbol)

    ro = next(seg for seg in segments if seg['name'] == 'rodata')
    name_off = segments[0]['extra']
    name_size = segments[1]['extra']
    module_name = None
    if name_size and name_off + name_size <= ro['size']:
        module_name = ro['data'][name_off:name_off + name_size].split(b'\0', 1)[0].decode('utf-8', 'replace') or None
    needed = [string_at(value) for tag, value in dynamic if tag == 1]
    report = {
        'module': name,
        'file_size': len(raw),
        'file_sha256': _sha256(raw),
        'build_id': raw[0x40:0x60].hex(),
        'module_name': module_name,
        'sdk_version': _sdk_version(ro['data']),
        'symbol_count': symcount,
        'segments': [{
            'name': seg['name'],
            'memory': seg['memory'],
            'size': seg['size'],
            'bss': seg['extra'] if seg['name'] == 'data' else 0,
            'sha256': seg['sha256'],
            'compressed': seg['compressed'],
        } for seg in segments],
        'needed': needed,
        'imports': imports,
        'exports': exports,
        'services': _services(ro['data']),
    }
    return report
