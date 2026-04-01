# authinfo-gpg

Read GPG-encrypted `.authinfo.gpg` credential files in Python.

## Features

- Read encrypted `.authinfo.gpg` files (netrc format)
- Cross-platform GPG binary auto-detection
- Support for passphrase input or gpg-agent
- Simple, pythonic API
- No hardcoded paths or version dependencies
- Type-annotated

## Installation

```bash
pip install authinfo-gpg
```

## Requirements

- Python 3.7+
- GnuPG installed on your system

## Quick Start

```python
from authinfo_gpg import get_entry
from getpass import getpass

# Get passphrase from user
passphrase = getpass("Enter your GPG passphrase: ")

# Retrieve credentials
entry = get_entry(machine='example.com', login='myuser', passphrase=passphrase)

if entry:
    print(f"Username: {entry.login}")
    print(f"Password: {entry.password}")
```

## Usage

### Using the convenience function

```python
from authinfo_gpg import get_entry

entry = get_entry('ollama.com', login='default', passphrase='my-gpg-pass')
if entry:
    api_key = entry.password
```

### Using the class interface

```python
from authinfo_gpg import AuthInfoGPG
from getpass import getpass

# Initialize
auth = AuthInfoGPG()

# Get a specific entry
passphrase = getpass()
entry = auth.get_entry('example.com', passphrase=passphrase)

# Get all entries
all_entries = auth.get_all_entries(passphrase=passphrase)
for entry in all_entries:
    print(f"{entry.machine}: {entry.login}")
```

### Custom authinfo file location

```python
from authinfo_gpg import AuthInfoGPG

auth = AuthInfoGPG(authinfo_path='/custom/path/to/.authinfo.gpg')
entry = auth.get_entry('example.com', passphrase='...')
```

## File Format

The `.authinfo.gpg` file uses netrc format:

```
machine example.com login myuser password mypassword
machine api.service.com login admin password secret123 port 8080
```

## Why authinfo-gpg?

The original `authinfo` package is unmaintained (last updated 2013, Python 2 only) and has compatibility issues with modern GnuPG installations. This package:

- Uses `subprocess` to call GPG directly (more reliable)
- Auto-detects GPG binary location (no hardcoded paths)
- Supports Python 3.7+
- Handles pinentry correctly with `--pinentry-mode=loopback`
- Actively maintained

## Security Considerations

**⚠️ Decrypted credentials and the GPG passphrase are held as plain Python strings in process memory until garbage-collected — Python provides no built-in mechanism to zero memory on deallocation.** Avoid long-lived references to `AuthEntry.password` or the passphrase; retrieve credentials as close to their point of use as possible, and avoid storing them in module-level variables, caches, or data structures with unbounded lifetimes. On shared or multi-tenant systems, consider whether your threat model requires a language or runtime with explicit secure memory primitives.

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please open an issue or submit a pull request on GitHub.

## Author

Armin Monecke <authinfo-gpg@mnck.ai>
