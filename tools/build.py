"""Build browser packages using the Python standard library only."""
from pathlib import Path
import hashlib
import json
import shutil
import struct
import zlib
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def icon(size):
    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            a, b = x / size, y / size
            color = (25, 36, 46, 255)
            if .12 < a < .88 and .12 < b < .88:
                color = (189, 233, 137, 255)
            chevron = .28 < a < .48 and abs(abs(b - .47) - (a - .28)) < .045
            underline = .53 < a < .73 and .62 < b < .68
            if chevron or underline:
                color = (25, 43, 21, 255)
            rows.extend(color)
    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data) & 0xffffffff)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!2I5B', size, size, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(bytes(rows))) + chunk(b'IEND', b'')

def build():
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    version = json.loads((ROOT / 'package.json').read_text())['version']
    for browser, manifest in [('chrome-edge', 'chromium'), ('firefox', 'firefox')]:
        target = dist / browser
        # Only remove the verified build subdirectory, never an arbitrary input path.
        if target.exists():
            assert target.resolve().parent == dist.resolve()
            shutil.rmtree(target)
        shutil.copytree(ROOT / 'extension', target)
        (target / 'icons').mkdir(exist_ok=True)
        for size in [16, 32, 48, 128]:
            (target / 'icons' / f'{size}.png').write_bytes(icon(size))
        (target / 'manifest.json').write_bytes((ROOT / f'manifest.{manifest}.json').read_bytes())
        manifest_data=json.loads((target/'manifest.json').read_text())
        assert manifest_data['version']==version, 'Manifest and package versions differ'
        required=[manifest_data['options_ui']['page'],'terminal.template.php']
        required += [manifest_data['background']['service_worker']] if 'service_worker' in manifest_data['background'] else manifest_data['background']['scripts']
        assert all((target/name).is_file() for name in required), 'Extension entry point is missing'
        name = f'harbor-terminal-{browser}-{version}.zip'
        with zipfile.ZipFile(dist / name, 'w', zipfile.ZIP_DEFLATED) as archive:
            for file in sorted(target.rglob('*')):
                if file.is_file():
                    info = zipfile.ZipInfo(file.relative_to(target).as_posix(), (2026, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = 0o644 << 16
                    archive.writestr(info, file.read_bytes())
        print(name)
    sums = []
    for file in sorted(dist.glob(f'harbor-terminal-*-{version}.zip')):
        sums.append(hashlib.sha256(file.read_bytes()).hexdigest() + '  ' + file.name)
    (dist / 'SHA256SUMS.txt').write_text('\n'.join(sums) + '\n')

if __name__ == '__main__':
    build()
