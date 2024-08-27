import os
import re
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

def set_attributes(filepath: str, value: int):
    ret = ctypes.windll.kernel32.SetFileAttributesW(filepath, value)

    if not ret:
        raise IOError('failed to set file attributes')

def get_attributes(filepath: str) -> int:
    attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)

    if attrs == -1:
        raise FileNotFoundError(filepath)

    return attrs

def is_hidden(filepath: str) -> bool:
    attrs = get_attributes(filepath)
    return bool(attrs & 0x02 != 0)

def protect_file(filepath: str):
    attrs = get_attributes(filepath)
    set_attributes(filepath, attrs | 0x03)

def unprotect_file(filepath: str):
    attrs = get_attributes(filepath)
    set_attributes(filepath, attrs & ~0x03)

def get_checksum(filepath: str) -> str:
    value = hashlib.sha256()

    with open(filepath, 'rb') as file:
        while chunk := file.read(8192):
            value.update(chunk)

    return value.hexdigest()

def read_sumfile(sumfile: str) -> dict:
    dpath = path.dirname(sumfile)
    checksums = {}

    re_sumfile_gnu = re.compile(
        r'(?P<checksum>[a-fA-F0-9]{64})'
        r'(\s{2}|\s\*)'
        r'(?P<filename>.+)'
    )
    re_sumfile_bsd = re.compile(
        r'SHA256\s'
        r'\((?P<filename>.+)\)\s=\s'
        r'(?P<checksum>[a-fA-F0-9]{64})'
    )

    with open(sumfile, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()

            if not line or line[0] in {'#', ';'}:
                continue

            if match := re_sumfile_gnu.match(line):
                filename = match.group('filename')
                checksum = match.group('checksum')
            elif match := re_sumfile_bsd.match(line):
                filename = match.group('filename')
                checksum = match.group('checksum')
            else:
                raise ValueError('could not parse sumfile')

            if not path.exists(path.join(dpath, filename)):
                continue

            checksums[filename] = checksum

    return checksums

def write_sumfile(sumfile: str, data: dict):
    if path.exists(sumfile):
        unprotect_file(sumfile)

    with open(sumfile, 'w', encoding='utf-8', newline='\n') as file:
        for filename, checksum in data.items():
            file.write(f"{checksum}{SUMFILE_DELIMITER}{filename}\n")

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
    extra = parser.add_mutually_exclusive_group(required=False)
    extra.add_argument('--reset', action='store_true', dest='reset',
                        help="Reset checksums")
    extra.add_argument('--refresh', action='store_true', dest='refresh',
                        help="Refresh checksums")
    parser.add_argument('root', help='The starting directory')
    args = parser.parse_args()

    for (root, dirs, files) in os.walk(args.root, topdown=True):
        if not files or '.nochecksums' in files:
            continue

        if is_excluded(root, EXCLUDED_DIRS):
            continue

        if not args.hidden and is_hidden(root):
            continue

        if args.create:
            sumfile = path.join(root, SUMFILE_NAME)
            checksums = {}
            checksums_mtime = 0.0
            write = False

            if path.isfile(sumfile) and not args.reset:
                try:
                    checksums = read_sumfile(sumfile)
                    checksums_mtime = path.getmtime(sumfile)
                except (PermissionError, ValueError):
                    print(f'! {sumfile}')
                    continue

            for filename in files:
                filepath = path.join(root, filename)

                if (
                    (not args.refresh and filename in checksums) or
                    (not args.hidden and is_hidden(filepath)) or
                    is_excluded(filename, EXCLUDED_FILES)
                ):
                    continue

                # With --refresh
                # Skip files that are older than the sumfile
                # Only if a checksum exists in the sumfile
                if (
                    args.refresh and
                    checksums_mtime >= path.getmtime(filepath) and
                    filename in checksums
                ):
                    continue

                try:
                    checksums[filename] = get_checksum(path.join(root, filename))
                except FileNotFoundError:
                    print(f'? {filepath}')
                    continue
                except PermissionError:
                    print(f'! {filepath}')
                    continue

                write = True
                print(f'+ {filepath}')

            if write and checksums:
                try:
                    write_sumfile(sumfile, checksums)
                except PermissionError:
                    print(f'! {filepath}')
        elif args.verify:
            for f in files:
                if not f.endswith('.sha256'):
                    continue

                sumfile = path.join(root, f)

                if not path.isfile(sumfile):
                    continue

                try:
                    checksums = read_sumfile(sumfile)
                except (PermissionError, ValueError):
                    print(f'! {sumfile}')
                    continue

                for filename, checksum_old in checksums.items():
                    filepath = path.join(root, filename)

                    try:
                        checksum_new = get_checksum(filepath)
                    except FileNotFoundError:
                        print(f'? {filepath}')
                    except PermissionError:
                        print(f'! {filepath}')

                    if checksum_new.casefold() != checksum_old.casefold():
                        print(f'X {filepath}')
