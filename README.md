# README

## Overview

This script manages checksums for files in a directory tree. It can create, verify, and reset checksum files (`.checksums.sha256`) for files in the specified directory and its subdirectories. The checksums are generated using the SHA-256 algorithm.

## Features

- **Create Checksums**: Generates SHA-256 checksums for files in the directory tree and stores them in a checksum file.
- **Verify Checksums**: Verifies the checksums of files against those stored in the checksum file.
- **Reset Checksums**: Regenerates and updates the checksums for files in the directory tree.

## Usage

### Command Line Arguments

- `--include-hidden`: Include hidden files and directories in the operations.
- `-c`, `--create`: Create checksums for files in the directory tree.
- `-v`, `--verify`: Verify the checksums of files against the checksum file.
- `-r`, `--reset`: Reset (regenerate) checksums for files in the directory tree.
- `root`: The starting directory for the operations.

### Running the Script

```sh
python script.py [options] <root>
