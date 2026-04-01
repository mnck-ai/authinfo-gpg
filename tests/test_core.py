"""
Tests for authinfo_gpg
"""

import shutil
import pytest
from unittest.mock import patch, MagicMock
from authinfo_gpg import AuthEntry, AuthInfoGPG, get_entry, find_gpg_binary


SAMPLE_AUTHINFO = """\
## Test authinfo file
machine api.example.com login apikey password secret-token-123
machine smtp.example.com login user@example.com password smtp-pass port 587
machine api.other.com login admin password other-secret
"""


# ---------------------------------------------------------------------------
# AuthEntry unit tests
# ---------------------------------------------------------------------------

def test_auth_entry_creation():
    """Test creating an AuthEntry."""
    entry = AuthEntry(machine='example.com', login='user', password='pass')
    assert entry.machine == 'example.com'
    assert entry.login == 'user'
    assert entry.password == 'pass'


def test_auth_entry_repr_no_password():
    """Test that repr doesn't expose password."""
    entry = AuthEntry(machine='example.com', login='user', password='secret')
    repr_str = repr(entry)
    assert 'secret' not in repr_str
    assert 'example.com' in repr_str
    assert 'user' in repr_str


def test_auth_entry_optional_fields():
    """Test AuthEntry with only required field."""
    entry = AuthEntry(machine='example.com')
    assert entry.machine == 'example.com'
    assert entry.login is None
    assert entry.password is None
    assert entry.port is None


def test_find_gpg_binary():
    """Test that GPG binary can be found."""
    try:
        binary = find_gpg_binary()
        assert binary is not None
        assert 'gpg' in binary.lower()
    except RuntimeError:
        pytest.skip("GPG not installed on test system")


# ---------------------------------------------------------------------------
# Integration tests — subprocess mocked, no real GPG calls
# ---------------------------------------------------------------------------

def _make_auth(tmp_path):
    """Helper: AuthInfoGPG pointed at a fake .authinfo.gpg file."""
    fake_file = tmp_path / ".authinfo.gpg"
    fake_file.write_bytes(b"encrypted-placeholder")
    gpg = shutil.which('gpg') or shutil.which('gpg2') or '/usr/bin/gpg'
    return AuthInfoGPG(gpg_binary=gpg, authinfo_path=str(fake_file))


def _mock_run(content: str):
    """Return a mock subprocess.CompletedProcess with given stdout."""
    mock = MagicMock()
    mock.stdout = content.encode('utf-8')
    return mock


@patch('subprocess.run')
def test_decrypt_returns_string(mock_run, tmp_path):
    """decrypt() returns decrypted text as a string."""
    mock_run.return_value = _mock_run(SAMPLE_AUTHINFO)
    auth = _make_auth(tmp_path)
    result = auth.decrypt()
    assert isinstance(result, str)
    assert 'api.example.com' in result
    assert 'secret-token-123' in result


@patch('subprocess.run')
def test_decrypt_raises_on_missing_file(mock_run):
    """decrypt() raises FileNotFoundError when authinfo file is absent."""
    auth = AuthInfoGPG(gpg_binary='/opt/homebrew/bin/gpg',
                       authinfo_path='/nonexistent/.authinfo.gpg')
    with pytest.raises(FileNotFoundError):
        auth.decrypt()
    mock_run.assert_not_called()


@patch('subprocess.run')
def test_decrypt_raises_on_gpg_failure(mock_run, tmp_path):
    """decrypt() raises ValueError when GPG exits non-zero."""
    import subprocess
    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=2, cmd=['gpg'], stderr=b'decryption failed'
    )
    auth = _make_auth(tmp_path)
    with pytest.raises(ValueError, match='GPG decryption failed'):
        auth.decrypt()


@patch('subprocess.run')
def test_get_entry_found(mock_run, tmp_path):
    """get_entry() returns the correct AuthEntry for a matching machine."""
    mock_run.return_value = _mock_run(SAMPLE_AUTHINFO)
    auth = _make_auth(tmp_path)
    entry = auth.get_entry('api.example.com')
    assert entry is not None
    assert entry.machine == 'api.example.com'
    assert entry.login == 'apikey'
    assert entry.password == 'secret-token-123'


@patch('subprocess.run')
def test_get_entry_with_login_filter(mock_run, tmp_path):
    """get_entry() respects the login filter."""
    mock_run.return_value = _mock_run(SAMPLE_AUTHINFO)
    auth = _make_auth(tmp_path)
    entry = auth.get_entry('smtp.example.com', login='user@example.com')
    assert entry is not None
    assert entry.password == 'smtp-pass'
    assert entry.port == '587'


@patch('subprocess.run')
def test_get_entry_login_mismatch_returns_none(mock_run, tmp_path):
    """get_entry() returns None when login doesn't match."""
    mock_run.return_value = _mock_run(SAMPLE_AUTHINFO)
    auth = _make_auth(tmp_path)
    entry = auth.get_entry('api.example.com', login='wrong-user')
    assert entry is None


@patch('subprocess.run')
def test_get_entry_not_found(mock_run, tmp_path):
    """get_entry() returns None for an unknown machine."""
    mock_run.return_value = _mock_run(SAMPLE_AUTHINFO)
    auth = _make_auth(tmp_path)
    entry = auth.get_entry('no.such.host')
    assert entry is None


@patch('subprocess.run')
def test_get_all_entries(mock_run, tmp_path):
    """get_all_entries() returns all machine entries, skipping comments."""
    mock_run.return_value = _mock_run(SAMPLE_AUTHINFO)
    auth = _make_auth(tmp_path)
    entries = auth.get_all_entries()
    assert len(entries) == 3
    machines = [e.machine for e in entries]
    assert 'api.example.com' in machines
    assert 'smtp.example.com' in machines
    assert 'api.other.com' in machines


@patch('subprocess.run')
def test_get_all_entries_empty_file(mock_run, tmp_path):
    """get_all_entries() returns empty list for a file with only comments."""
    mock_run.return_value = _mock_run("## just a comment\n\n")
    auth = _make_auth(tmp_path)
    entries = auth.get_all_entries()
    assert entries == []


@patch('subprocess.run')
def test_convenience_get_entry(mock_run, tmp_path):
    """Module-level get_entry() convenience function works correctly."""
    mock_run.return_value = _mock_run(SAMPLE_AUTHINFO)
    fake_file = str(tmp_path / ".authinfo.gpg")
    (tmp_path / ".authinfo.gpg").write_bytes(b"placeholder")
    entry = get_entry('api.other.com', authinfo_path=fake_file)
    assert entry is not None
    assert entry.password == 'other-secret'
