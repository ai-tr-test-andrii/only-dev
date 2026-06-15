"""
Tests for the Command Injection fix in sast_one_critical.py (CWE-77).

The original vulnerability: `os.system("ping " + domain)` allowed an attacker
to append arbitrary shell commands via the `domain` query parameter (e.g.,
`domain=x; rm -rf /`).

The fix replaces the shell-string invocation with
`subprocess.run(["ping", "-c", "1", domain], shell=False)`, which passes
the domain as a discrete argv element so the OS never interprets it as shell
syntax.

These tests verify:
1. The /ping endpoint still works correctly for valid input.
2. Shell-injection payloads are NOT executed as shell commands.
3. subprocess.run is called with shell=False and an argv list (not a string).
"""

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from sast_one_critical import app


class TestPingEndpointFunctionality(unittest.TestCase):
    """Positive tests — the endpoint should work for well-formed domains."""

    def setUp(self):
        app.testing = True
        self.client = app.test_client()

    def _make_completed_process(self, stdout="PING output", stderr="", returncode=0):
        mock_cp = MagicMock(spec=subprocess.CompletedProcess)
        mock_cp.stdout = stdout
        mock_cp.stderr = stderr
        mock_cp.returncode = returncode
        return mock_cp

    @patch("sast_one_critical.subprocess.run")
    def test_valid_domain_returns_200(self, mock_run):
        """A valid domain name should produce an HTTP 200 response."""
        mock_run.return_value = self._make_completed_process(stdout="pong")
        response = self.client.get("/ping?domain=example.com")
        self.assertEqual(response.status_code, 200)

    @patch("sast_one_critical.subprocess.run")
    def test_valid_domain_response_contains_output(self, mock_run):
        """Response JSON should include the subprocess stdout."""
        mock_run.return_value = self._make_completed_process(stdout="PING example.com")
        response = self.client.get("/ping?domain=example.com")
        data = response.get_json()
        self.assertIn("output", data)
        self.assertEqual(data["output"], "PING example.com")

    @patch("sast_one_critical.subprocess.run")
    def test_response_json_schema(self, mock_run):
        """Response JSON must contain output, error, and returncode keys."""
        mock_run.return_value = self._make_completed_process(stdout="ok", stderr="", returncode=0)
        response = self.client.get("/ping?domain=localhost")
        data = response.get_json()
        self.assertIn("output", data)
        self.assertIn("error", data)
        self.assertIn("returncode", data)

    @patch("sast_one_critical.subprocess.run")
    def test_missing_domain_parameter_does_not_raise(self, mock_run):
        """Omitting the domain query parameter should not crash the endpoint."""
        mock_run.return_value = self._make_completed_process()
        response = self.client.get("/ping")
        self.assertEqual(response.status_code, 200)


class TestCommandInjectionPrevention(unittest.TestCase):
    """Security tests — injection payloads must NOT be treated as shell commands."""

    def setUp(self):
        app.testing = True
        self.client = app.test_client()

    def _make_completed_process(self, stdout="", stderr="bad address", returncode=2):
        mock_cp = MagicMock(spec=subprocess.CompletedProcess)
        mock_cp.stdout = stdout
        mock_cp.stderr = stderr
        mock_cp.returncode = returncode
        return mock_cp

    # ------------------------------------------------------------------
    # Tests that verify subprocess.run is called correctly (argv + shell=False)
    # ------------------------------------------------------------------

    @patch("sast_one_critical.subprocess.run")
    def test_subprocess_called_with_list_not_string(self, mock_run):
        """subprocess.run MUST be called with a list (argv), not a shell string."""
        mock_run.return_value = self._make_completed_process()
        self.client.get("/ping?domain=example.com")
        call_args = mock_run.call_args
        # First positional argument is the command
        cmd = call_args[0][0]
        self.assertIsInstance(
            cmd,
            list,
            "subprocess.run must receive a list, not a string, to prevent shell injection",
        )

    @patch("sast_one_critical.subprocess.run")
    def test_subprocess_called_with_shell_false(self, mock_run):
        """subprocess.run MUST be called with shell=False."""
        mock_run.return_value = self._make_completed_process()
        self.client.get("/ping?domain=example.com")
        call_kwargs = mock_run.call_args[1]
        self.assertFalse(
            call_kwargs.get("shell", True),
            "shell=False is required to prevent command injection",
        )

    @patch("sast_one_critical.subprocess.run")
    def test_domain_passed_as_separate_argv_element(self, mock_run):
        """The domain must appear as a discrete argv element, not embedded in a string."""
        mock_run.return_value = self._make_completed_process()
        self.client.get("/ping?domain=example.com")
        cmd = mock_run.call_args[0][0]
        # The domain should be the last element of the argv list
        self.assertEqual(cmd[-1], "example.com")

    # ------------------------------------------------------------------
    # Tests that injection payloads are treated as literal argv data
    # ------------------------------------------------------------------

    @patch("sast_one_critical.subprocess.run")
    def test_semicolon_injection_is_not_expanded(self, mock_run):
        """Payload 'x; id' must be forwarded as a single argv value, not a shell command."""
        mock_run.return_value = self._make_completed_process()
        self.client.get("/ping?domain=x; id")
        cmd = mock_run.call_args[0][0]
        # The entire payload must be a single element — semicolon is not a separator
        self.assertIn("x; id", cmd)
        self.assertFalse(
            mock_run.call_args[1].get("shell", True),
            "shell must be False even with shell-metacharacter payloads",
        )

    @patch("sast_one_critical.subprocess.run")
    def test_backtick_injection_is_not_executed(self, mock_run):
        """Backtick command substitution must not be evaluated."""
        mock_run.return_value = self._make_completed_process()
        self.client.get("/ping?domain=`id`")
        cmd = mock_run.call_args[0][0]
        self.assertIn("`id`", cmd)
        self.assertFalse(mock_run.call_args[1].get("shell", True))

    @patch("sast_one_critical.subprocess.run")
    def test_pipe_injection_is_not_executed(self, mock_run):
        """Pipe metacharacter must not be interpreted by a shell."""
        mock_run.return_value = self._make_completed_process()
        self.client.get("/ping?domain=x|cat /etc/passwd")
        cmd = mock_run.call_args[0][0]
        self.assertIn("x|cat /etc/passwd", cmd)
        self.assertFalse(mock_run.call_args[1].get("shell", True))

    @patch("sast_one_critical.subprocess.run")
    def test_ampersand_injection_is_not_executed(self, mock_run):
        """Ampersand command chaining must not be interpreted by a shell."""
        mock_run.return_value = self._make_completed_process()
        self.client.get("/ping?domain=x && whoami")
        cmd = mock_run.call_args[0][0]
        self.assertIn("x && whoami", cmd)
        self.assertFalse(mock_run.call_args[1].get("shell", True))

    @patch("sast_one_critical.subprocess.run")
    def test_dollar_substitution_is_not_executed(self, mock_run):
        """Shell variable substitution via $(...) must not be evaluated."""
        mock_run.return_value = self._make_completed_process()
        self.client.get("/ping?domain=$(id)")
        cmd = mock_run.call_args[0][0]
        self.assertIn("$(id)", cmd)
        self.assertFalse(mock_run.call_args[1].get("shell", True))

    @patch("sast_one_critical.subprocess.run")
    def test_newline_injection_is_not_executed(self, mock_run):
        """Newline characters in the domain must be passed literally, not as new commands."""
        mock_run.return_value = self._make_completed_process()
        self.client.get("/ping?domain=x%0Aid")  # %0A = newline
        cmd = mock_run.call_args[0][0]
        # domain value with newline is a single argv element
        self.assertIsInstance(cmd, list)
        self.assertFalse(mock_run.call_args[1].get("shell", True))

    # ------------------------------------------------------------------
    # Regression guard: the original dangerous pattern must not be present
    # ------------------------------------------------------------------

    def test_os_system_not_used(self):
        """The codebase must not use os.system (the original vulnerable sink)."""
        import ast
        import inspect

        import sast_one_critical

        source = inspect.getsource(sast_one_critical)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "system":
                    if isinstance(func.value, ast.Name) and func.value.id == "os":
                        self.fail(
                            "os.system() is the original vulnerable sink and must not be used"
                        )

    def test_shell_string_concatenation_not_used(self):
        """The codebase must not build a shell command by string concatenation with user input."""
        import ast
        import inspect

        import sast_one_critical

        source = inspect.getsource(sast_one_critical)
        tree = ast.parse(source)
        # Look for calls to subprocess.run/call/Popen where the first arg is a BinOp (string concat)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                is_subprocess_call = (
                    isinstance(func, ast.Attribute)
                    and func.attr in ("run", "call", "check_output", "check_call", "Popen")
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "subprocess"
                )
                if is_subprocess_call and node.args:
                    first_arg = node.args[0]
                    self.assertNotIsInstance(
                        first_arg,
                        ast.BinOp,
                        "subprocess must not be called with a BinOp (string concatenation) as first arg",
                    )


if __name__ == "__main__":
    unittest.main()
