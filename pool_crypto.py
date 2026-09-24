#!/usr/bin/env python3
"""Crypto for pool persistence — tokens/accounts NEVER hit git in plaintext.

GitHub secret scanning auto-revokes ghp_ tokens committed even to private repos.
So we keep an encrypted blob (Fernet) in the repo; key lives in GH Actions secret.

Usage:
  python pool_crypto.py encrypt <infile> <outfile>   # env POOL_KEY required
  python pool_crypto.py decrypt <infile> <outfile>
"""
import os
import sys
from cryptography.fernet import Fernet


def key() -> bytes:
    k = os.environ.get('POOL_KEY', '')
    if not k:
        raise SystemExit('POOL_KEY env var required')
    return k.encode()


def encrypt(src: str, dst: str):
    data = open(src, 'rb').read()
    out = Fernet(key()).encrypt(data)
    open(dst, 'wb').write(out)
    print(f'encrypted {len(data)} -> {len(out)} bytes')


def decrypt(src: str, dst: str):
    data = open(src, 'rb').read()
    out = Fernet(key()).decrypt(data)
    open(dst, 'wb').write(out)
    print(f'decrypted {len(data)} -> {len(out)} bytes')


if __name__ == '__main__':
    op, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    {'encrypt': encrypt, 'decrypt': decrypt}[op](src, dst)
