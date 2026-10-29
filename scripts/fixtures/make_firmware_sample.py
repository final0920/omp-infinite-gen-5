"""Write a small nested firmware image (U-Boot gzip kernel + xz SquashFS + cpio) for the tool-level tests. Usage: make_firmware_sample.py OUT_FILE"""
import gzip
import lzma
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fw_builder as build

rng = random.Random(3)
files = [
    {'path': 'etc/passwd', 'data': b'root:x:0:0:root:/root:/bin/sh\n' * 3},
    {'path': 'bin/busybox', 'data': b'\x7fELF\x01\x01\x01' + bytes(9) + b'\x02\x00\x28\x00' + bytes(44) + b'BusyBox v1.31.1 multi-call binary' + bytes(rng.randrange(256) for _ in range(6000)), 'mode': 0o755},
    {'path': 'bin/sh', 'symlink': 'busybox'},
    {'path': 'www/index.html', 'data': b'<html>' * 400},
    {'path': '../../outside.txt', 'data': b'hostile name'},
]
kernel = b'Linux version 4.14.180 (builder@host) (gcc 7.5) #1 SMP' + bytes(rng.randrange(256) for _ in range(2000))
squash = build.build_squashfs([f for f in files if not f['path'].startswith('..')], compression='xz')
image = (build.build_uimage(gzip.compress(kernel, mtime=0), comp=1) + bytes(100) + lzma.compress(squash) + bytes(37) +
         build.build_cpio([{'path': 'init', 'data': b'#!/bin/sh\n'}, {'path': '../../outside.txt', 'data': b'hostile name'}]))
Path(sys.argv[1]).write_bytes(image)
