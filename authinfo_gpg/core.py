"""
Core functionality for reading GPG-encrypted authinfo files.
"""

import os
import subprocess
import shutil
from typing import Optional, Dict, List  # noqa: F401 — List used in get_all_entries return hint
from dataclasses import dataclass

_GPG_TIMEOUT = 30  # seconds — prevents a hung GPG process from holding decrypted data indefinitely


@dataclass(repr=False)
class AuthEntry:
    """Represents a credential entry from an authinfo file."""
    machine: str
    login: Optional[str] = None
    password: Optional[str] = None
    port: Optional[str] = None

    def __repr__(self) -> str:
        # Never expose password or port in repr — safe for logs and tracebacks
        return f"AuthEntry(machine={self.machine!r}, login={self.login!r})"

    def __str__(self) -> str:
        return self.__repr__()


class AuthInfoGPG:
    """Read and parse GPG-encrypted authinfo files."""
    
    def __init__(self, gpg_binary: Optional[str] = None, authinfo_path: Optional[str] = None):
        """
        Initialize AuthInfoGPG reader.
        
        Args:
            gpg_binary: Path to gpg binary. Auto-detected if not provided.
            authinfo_path: Path to .authinfo.gpg file. Defaults to ~/.authinfo.gpg
        """
        self.gpg_binary = gpg_binary or self._find_gpg_binary()
        self.authinfo_path = authinfo_path or os.path.expanduser('~/.authinfo.gpg')
        
    def _find_gpg_binary(self) -> str:
        """Find the gpg binary in system PATH."""
        for binary_name in ['gpg', 'gpg2']:
            binary_path = shutil.which(binary_name)
            if binary_path:
                return binary_path
        
        # Fallback to common installation paths
        common_paths = [
            '/opt/homebrew/bin/gpg',
            '/usr/local/bin/gpg',
            '/usr/bin/gpg',
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        raise RuntimeError("GPG binary not found in PATH or common locations")
    
    def decrypt(self, passphrase: Optional[str] = None) -> str:
        """
        Decrypt the authinfo file and return its contents.
        
        Args:
            passphrase: GPG passphrase. If None, uses gpg-agent.
            
        Returns:
            Decrypted file contents as string.
            
        Raises:
            ValueError: If decryption fails.
            FileNotFoundError: If authinfo file doesn't exist.
        """
        if not os.path.exists(self.authinfo_path):
            raise FileNotFoundError(f"Authinfo file not found: {self.authinfo_path}")
        
        # Build command — loopback pinentry only when feeding passphrase via stdin.
        # When relying on gpg-agent, omitting --pinentry-mode keeps the agent flow
        # intact and prevents GPG from reading an unexpected passphrase from stdin.
        cmd = [self.gpg_binary, '--batch', '--decrypt', self.authinfo_path]

        try:
            if passphrase:
                # Insert before --decrypt: --batch --pinentry-mode --passphrase-fd --decrypt
                cmd.insert(1, '--pinentry-mode=loopback')
                cmd.insert(2, '--passphrase-fd=0')
                result = subprocess.run(
                    cmd,
                    input=passphrase.encode(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    timeout=_GPG_TIMEOUT,
                )
            else:
                # No passphrase supplied — use gpg-agent.
                # stdin=DEVNULL prevents accidental reads from the parent's stdin pipe.
                result = subprocess.run(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    timeout=_GPG_TIMEOUT,
                )
            return result.stdout.decode('utf-8')
        except subprocess.TimeoutExpired:
            raise ValueError(f"GPG decryption timed out after {_GPG_TIMEOUT}s")
        except subprocess.CalledProcessError:
            # Intentionally omit GPG's stderr — it may contain key IDs or system
            # paths that should not appear in tracebacks or application logs.
            raise ValueError(f"GPG decryption failed for: {self.authinfo_path}")
    
    def _parse_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a single line from authinfo file."""
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        
        # Parse key-value pairs
        parts = line.split()
        entry = {}
        
        i = 0
        while i < len(parts):
            key = parts[i]
            if i + 1 < len(parts):
                value = parts[i + 1]
                entry[key] = value
                i += 2
            else:
                i += 1
        
        return entry if entry else None
    
    def get_entry(self, machine: str, login: Optional[str] = None, 
                  passphrase: Optional[str] = None) -> Optional[AuthEntry]:
        """
        Get credentials for a specific machine.
        
        Args:
            machine: Machine/host name to look up
            login: Optional login name to match
            passphrase: GPG passphrase. If None, uses gpg-agent.
            
        Returns:
            AuthEntry if found, None otherwise.
        """
        decrypted_text = self.decrypt(passphrase)
        
        for line in decrypted_text.split('\n'):
            entry_dict = self._parse_line(line)
            if not entry_dict:
                continue
            
            # Check if this entry matches
            if entry_dict.get('machine') == machine:
                if login is None or entry_dict.get('login') == login:
                    return AuthEntry(
                        machine=entry_dict.get('machine', ''),
                        login=entry_dict.get('login'),
                        password=entry_dict.get('password'),
                        port=entry_dict.get('port')
                    )
        
        return None
    
    def get_all_entries(self, passphrase: Optional[str] = None) -> list:
        """
        Get all credential entries from the authinfo file.
        
        Args:
            passphrase: GPG passphrase. If None, uses gpg-agent.
            
        Returns:
            List of all AuthEntry objects found in the file.
        """
        decrypted_text = self.decrypt(passphrase)
        entries = []
        
        for line in decrypted_text.split('\n'):
            entry_dict = self._parse_line(line)
            if not entry_dict or 'machine' not in entry_dict:
                continue
            
            entries.append(AuthEntry(
                machine=entry_dict.get('machine', ''),
                login=entry_dict.get('login'),
                password=entry_dict.get('password'),
                port=entry_dict.get('port')
            ))
        
        return entries


# Convenience functions
def get_entry(machine: str, login: Optional[str] = None, 
              passphrase: Optional[str] = None,
              authinfo_path: Optional[str] = None) -> Optional[AuthEntry]:
    """
    Convenience function to get a single credential entry.
    
    Args:
        machine: Machine/host name to look up
        login: Optional login name to match
        passphrase: GPG passphrase. If None, uses gpg-agent.
        authinfo_path: Path to .authinfo.gpg file. Defaults to ~/.authinfo.gpg
        
    Returns:
        AuthEntry if found, None otherwise.
    """
    auth = AuthInfoGPG(authinfo_path=authinfo_path)
    return auth.get_entry(machine, login, passphrase)


def find_gpg_binary() -> str:
    """
    Find the GPG binary in system PATH.
    
    Returns:
        Path to GPG binary.
        
    Raises:
        RuntimeError: If GPG binary not found.
    """
    auth = AuthInfoGPG()
    return auth.gpg_binary
