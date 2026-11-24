#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/windows build/linux dist
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w -H=windowsgui' -o build/windows/PrivetAntigravity.exe ./cmd/privetantigravity
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o build/linux/PrivetAntigravity ./cmd/privetantigravity
cp assets/icon.svg build/linux/icon.svg
cp scripts/install.sh build/linux/install.sh
chmod +x build/linux/install.sh
cp LICENSE THIRD_PARTY_NOTICES.txt build/windows/
cp LICENSE THIRD_PARTY_NOTICES.txt build/linux/
python3 - <<'PY'
from pathlib import Path
import zipfile, tarfile, hashlib
text=Path('INSTRUCTION.md').read_text()
Path('build/windows/INSTRUCTION.txt').write_text(text,encoding='utf-8-sig')
Path('build/linux/INSTRUCTION.txt').write_text(text)
with zipfile.ZipFile('dist/PrivetAntigravity-Windows-x64.zip','w',zipfile.ZIP_DEFLATED) as z:
 for p in sorted(Path('build/windows').iterdir()): z.write(p,p.name)
with tarfile.open('dist/PrivetAntigravity-ArchLinux-x86_64.tar.gz','w:gz') as t:
 for p in sorted(Path('build/linux').iterdir()):t.add(p,arcname='PrivetAntigravity/'+p.name)
Path('dist/SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(Path('dist').iterdir()) if p.name!='SHA256SUMS.txt'))
PY
