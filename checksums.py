import os
import ctypes
import hashlib
import argparse
from os import path
from fnmatch import fnmatch
from typing import Iterable

SUMFILE_NAME = '.checksums.sha256'
SUMFILE_DELIMITER = '  '

EXCLUDED_DIRS = frozenset({
    '$RECYCLE.BIN',
    'System Volume Information'
})

EXCLUDED_FILES = frozenset({
    'desktop.ini',
    '*.sha256'
})

def is_excluded(name: str, patterns: Iterable) -> bool:
    return any(fnmatch(name, p) for p in patterns)

def set_attributes(fpath: str, value: int):
    ret = ctypes.windll.kernel32.SetFileAttributesW(fpath, value)

    if not ret:
        raise IOError('failed to set file attributes')

def get_attributes(fpath: str) -> int:
    attrs = ctypes.windll.kernel32.GetFileAttributesW(fpath)

    if attrs == -1:
        raise FileNotFoundError(fpath)

    return attrs

def is_hidden(fpath: str) -> bool:
    attrs = get_attributes(fpath)
    return bool(attrs & 0x02 != 0)

def protect_file(fpath: str):
    attrs = get_attributes(fpath)
    set_attributes(fpath, attrs | 0x03)

def unprotect_file(fpath: str):
    attrs = get_attributes(fpath)
    set_attributes(fpath, attrs & ~0x03)

def get_checksum(fpath: str) -> str:
    value = hashlib.sha256()

    with open(fpath, 'rb') as file:
        while chunk := file.read(8192):
            value.update(chunk)

    return value.hexdigest()

def read_sumfile(sumfile: str) -> dict:
    dpath = path.dirname(sumfile)
    checksums = {}

    with open(sumfile, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()

            if not line or line[0] in {'#', ';'}:
                continue

            parts = line.split(SUMFILE_DELIMITER, 1)
            if len(parts) == 2:
                checksum, fname = parts

                if not path.exists(path.join(dpath, fname)):
                    continue

                checksums[fname] = checksum

    return checksums

def write_sumfile(sumfile: str, data: dict):
    if path.exists(sumfile):
        unprotect_file(sumfile)

    with open(sumfile, 'w', encoding='utf-8', newline='\n') as file:
        for fname, checksum in data.items():
            file.write(f"{checksum}{SUMFILE_DELIMITER}{fname}\n")

    protect_file(sumfile)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manage sumfiles recursively')
    parser.add_argument('--include-hidden', action='store_true', dest='hidden',
                        help="Include hidden items")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('-c', '--create', action='store_true', dest='create',
                        help="Create checksums")
    action.add_argument('-v', '--verify', action='store_true', dest='verify',
                        help="Verify checksums")
    action.add_argument('-r', '--reset', action='store_true', dest='reset',
                        help="Reset checksums")
    parser.add_argument('root', help='The starting directory')

    args = parser.parse_args()

    for (root, dirs, files) in os.walk(args.root, topdown=True):
        if not files:
            continue

        if not args.hidden and is_hidden(root):
            continue

        if is_excluded(root, EXCLUDED_DIRS):
            continue

        sumfile = path.join(root, SUMFILE_NAME)
        checksums = {}

        if path.isfile(sumfile) and not args.reset:
            try:
                checksums = read_sumfile(sumfile)
            except PermissionError:
                print(f'! {sumfile}')
                continue

        if args.create or args.reset:
            write = False

            for fname in files:
                fpath = path.join(root, fname)

                if not args.hidden and is_hidden(fpath):
                    continue

                if fname in checksums or is_excluded(fname, EXCLUDED_FILES):
                    continue

                try:
                    checksums[fname] = get_checksum(path.join(root, fname))
                except FileNotFoundError:
                    print(f'? {fpath}')
                    continue
                except PermissionError:
                    print(f'! {fpath}')
                    continue

                write = True
                print(f'+ {fpath}')

            if write and checksums:
                try:
                    write_sumfile(sumfile, checksums)
                except PermissionError:
                    print(f'! {fpath}')
        elif args.verify:
            for fname, oldsum in checksums.items():
                fpath = path.join(root, fname)

                try:
                    newsum = get_checksum(fpath)
                except FileNotFoundError:
                    print(f'? {fpath}')
                except PermissionError:
                    print(f'! {fpath}')

                if oldsum != newsum:
                    print(f'X {fpath}')
