#!/usr/bin/env python3
"""Post-build fingerprint renamer for the magic frida gadget.

Same-length in-place byte replacements so the ELF stays valid:
  - known marker strings -> random letters
  - every remaining 'frida' substring -> 'kqzmv', EXCEPT the wire
    protocol tokens 're.frida' / 're/frida' (client compatibility)

Run:  python3 rename.py <gadget.so>
"""
import random
import sys


def main():
    path = sys.argv[1]
    data = bytearray(open(path, 'rb').read())
    assert data[:4] == b'\x7fELF', 'not an ELF'

    random.seed(0x31415)

    def rnd(n):
        return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz')
                       for _ in range(n)).encode()

    # exact-string renames (same length)
    targets = [
        b'FridaScriptEngine', b'GLib-GIO', b'GDBusProxy', b'GumScript',
        b'gum-js-loop', b'gmain', b'gdbus', b'frida-gadget',
        b'./lib/android', b'gadget', b'Binder:worker',
        b'art::JavaVMExt::AddGlobalRef',
        b'art::ClassLinker::VisitClassLoaders',
        b'pool_spawner', b'pool_spoiler', b'frida-inject', b'libfrida-agent',
    ]
    for old in targets:
        n = data.count(old)
        if n:
            new = rnd(len(old))
            data = bytearray(data.replace(old, new))
            print(f'  {old.decode("latin1"):36} -> {new.decode():20} x{n}')

    # every remaining 'frida' substring -> 'kqzmv', keep protocol tokens
    n = kept = 0
    i = 0
    while True:
        i = data.find(b'frida', i)
        if i < 0:
            break
        pre = bytes(data[i - 3:i])
        if pre in (b're.', b're/'):
            kept += 1
            i += 5
            continue
        data[i:i + 5] = b'kqzmv'
        n += 1
        i += 5
    print(f'  frida substrings -> kqzmv x{n} (protocol kept x{kept})')

    assert data[:4] == b'\x7fELF' and len(data) == len(open(path, 'rb').read())
    with open(path, 'wb') as f:
        f.write(bytes(data))
    print('OK, written', path, len(data))


if __name__ == '__main__':
    main()
