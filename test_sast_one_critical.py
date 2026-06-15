"""
Tests for the /ping endpoint in sast_one_critical.py.

Focus: verify that the Command Injection vulnerability (CWE-77) is correctly
remediated — specifically that user-controlled input cannot cause shell command
injection, while legitimate domain lookups still work.
"""

import subprocess
import pytest
from unittest.mock import patch, MagicMock

from sast_one_critical import app


@pytest.fixture
def client():
    """Flask test client with testing mode enabled."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


# ---------------------------------------------------------------------------
# 1. Functional tests — legitimate domain names must be accepted
# ---------------------------------------------------------------------------

class TestValidDomains:
    """The endpoint must process well-formed domain names without error."""

    def test_simple_domain(self, client):
        """A plain domain name is accepted and subprocess is invoked safely."""
        mock_result = MagicMock()
        mock_result.stdout = 'PING example.com ...'
        mock_result.returncode = 0

        with patch('sast_one_critical.subprocess.run', return_value=mock_result) as mock_run:
            response = client.get('/ping?domain=example.com')

        assert response.status_code == 200
        data = response.get_json()
        assert data['domain'] == 'example.com'

        # Verify subprocess was called as a list (shell=False), NOT a shell string
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[0][0]  # first positional argument
        assert isinstance(cmd, list), "Command must be passed as a list (shell=False)"
        assert cmd[0] == 'ping'
        assert 'example.com' in cmd
        # Confirm shell=False is set
        assert call_args[1].get('shell') is False or call_args[1].get('shell', False) is False

    def test_subdomain(self, client):
        """Subdomains with multiple labels are accepted."""
        mock_result = MagicMock()
        mock_result.stdout = 'PING sub.example.com ...'
        mock_result.returncode = 0

        with patch('sast_one_critical.subprocess.run', return_value=mock_result) as mock_run:
            response = client.get('/ping?domain=sub.example.com')

        assert response.status_code == 200
        data = response.get_json()
        assert data['domain'] == 'sub.example.com'

    def test_domain_with_hyphen(self, client):
        """Domain labels containing hyphens are accepted."""
        mock_result = MagicMock()
        mock_result.stdout = 'PING my-host.example.com ...'
        mock_result.returncode = 0

        with patch('sast_one_critical.subprocess.run', return_value=mock_result):
            response = client.get('/ping?domain=my-host.example.com')

        assert response.status_code == 200

    def test_domain_with_numbers(self, client):
        """Domains with numeric labels are accepted."""
        mock_result = MagicMock()
        mock_result.stdout = 'PING host1.example2.com ...'
        mock_result.returncode = 0

        with patch('sast_one_critical.subprocess.run', return_value=mock_result):
            response = client.get('/ping?domain=host1.example2.com')

        assert response.status_code == 200

    def test_response_contains_stdout_and_returncode(self, client):
        """Response JSON includes stdout and returncode from the subprocess."""
        mock_result = MagicMock()
        mock_result.stdout = 'ping output here'
        mock_result.returncode = 0

        with patch('sast_one_critical.subprocess.run', return_value=mock_result):
            response = client.get('/ping?domain=example.com')

        data = response.get_json()
        assert 'stdout' in data
        assert 'returncode' in data
        assert data['stdout'] == 'ping output here'
        assert data['returncode'] == 0


# ---------------------------------------------------------------------------
# 2. Security tests — command injection payloads must be rejected
# ---------------------------------------------------------------------------

class TestCommandInjectionBlocked:
    """
    Verify that classic command injection payloads are rejected at the
    validation boundary, never reaching subprocess.run.
    """

    INJECTION_PAYLOADS = [
        # Shell metacharacter injection
        'example.com; ls -la',
        'example.com && cat /etc/passwd',
        'example.com || id',
        'example.com | whoami',
        # Backtick / $() command substitution
        '`id`',
        '$(id)',
        # Newline injection
        'example.com\nid',
        'example.com\r\nid',
        # Null byte
        'example.com\x00id',
        # Space with arbitrary command
        'example.com id',
        # Leading/trailing special chars
        '-example.com',
        'example-.com',
        # Path traversal attempt
        '../etc/passwd',
        '/etc/passwd',
        # Quotes
        "example.com'--",
        'example.com"--',
        # Ampersand background execution
        'example.com &',
    ]

    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_injection_payload_rejected(self, client, payload):
        """Each injection payload must return 400 and subprocess must NOT be called."""
        with patch('sast_one_critical.subprocess.run') as mock_run:
            response = client.get(f'/ping?domain={payload}')

        # Must be rejected before reaching the shell sink
        assert response.status_code == 400, (
            f"Injection payload was not blocked: {payload!r}"
        )
        mock_run.assert_not_called(), (
            f"subprocess.run was called despite malicious payload: {payload!r}"
        )

    def test_empty_domain_rejected(self, client):
        """An empty domain parameter must return 400."""
        with patch('sast_one_critical.subprocess.run') as mock_run:
            response = client.get('/ping?domain=')

        assert response.status_code == 400
        mock_run.assert_not_called()

    def test_missing_domain_rejected(self, client):
        """A missing domain parameter must return 400."""
        with patch('sast_one_critical.subprocess.run') as mock_run:
            response = client.get('/ping')

        assert response.status_code == 400
        mock_run.assert_not_called()

    def test_error_response_json(self, client):
        """The 400 error response must be valid JSON with an 'error' key."""
        response = client.get('/ping?domain=; rm -rf /')
        assert response.status_code == 400
        data = response.get_json()
        assert data is not None, "Response must be valid JSON"
        assert 'error' in data


# ---------------------------------------------------------------------------
# 3. Shell=False enforcement test
# ---------------------------------------------------------------------------

class TestShellFalseEnforced:
    """
    Ensure subprocess.run is always invoked with shell=False (the primary
    mitigation for CWE-77) and with a list, not a string.
    """

    def test_subprocess_called_with_list_not_string(self, client):
        """subprocess.run must receive a list as its first argument."""
        mock_result = MagicMock()
        mock_result.stdout = ''
        mock_result.returncode = 0

        with patch('sast_one_critical.subprocess.run', return_value=mock_result) as mock_run:
            client.get('/ping?domain=example.com')

        assert mock_run.called
        cmd_arg = mock_run.call_args[0][0]
        assert isinstance(cmd_arg, list), (
            "subprocess.run must be called with a list to prevent shell injection"
        )
        assert not isinstance(cmd_arg, str), (
            "subprocess.run must NOT be called with a string command"
        )

    def test_subprocess_shell_false(self, client):
        """subprocess.run must be called with shell=False (or shell not set, defaulting to False)."""
        mock_result = MagicMock()
        mock_result.stdout = ''
        mock_result.returncode = 0

        with patch('sast_one_critical.subprocess.run', return_value=mock_result) as mock_run:
            client.get('/ping?domain=example.com')

        call_kwargs = mock_run.call_args[1]
        # shell must not be True
        assert call_kwargs.get('shell', False) is False, (
            "subprocess.run must not use shell=True"
        )

    def test_user_input_passed_as_separate_argv_element(self, client):
        """The domain must appear as its own element in the argv list, not concatenated."""
        mock_result = MagicMock()
        mock_result.stdout = ''
        mock_result.returncode = 0

        domain = 'testhost.example.com'
        with patch('sast_one_critical.subprocess.run', return_value=mock_result) as mock_run:
            client.get(f'/ping?domain={domain}')

        cmd = mock_run.call_args[0][0]
        # The domain should be a standalone list element, not embedded in a larger string
        assert domain in cmd, "Domain must appear in the command argv list"
        for element in cmd:
            if domain in element:
                assert element == domain, (
                    f"Domain must be its own argv element, not concatenated into: {element!r}"
                )
