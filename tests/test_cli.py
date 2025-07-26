"""
Tests for CLI functionality.
"""

import pytest
from click.testing import CliRunner
from pathlib import Path
import tempfile
import json

from sbom_visualizer.cli import cli


class TestCLI:
    """Test CLI commands."""

    @pytest.fixture
    def runner(self):
        """Create a CLI runner for testing."""
        return CliRunner()

    @pytest.fixture
    def sample_spdx_file(self):
        """Create a sample SPDX file for testing."""
        spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "documentName": "Sample SPDX Document",
            "documentNamespace": "https://example.com/spdx",
            "creationInfo": {
                "creators": ["Tool: SBOM Visualizer"],
                "created": "2024-01-01T00:00:00Z",
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-1",
                    "name": "sample-package",
                    "versionInfo": "1.0.0",
                    "description": "A sample package for testing",
                    "licenseDeclared": "MIT",
                    "supplier": "Sample Supplier",
                }
            ],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(spdx_data, f)
            return Path(f.name)

    def test_cli_help(self, runner):
        """Test CLI help command."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "SBOM Visualizer" in result.output

    def test_cli_version(self, runner):
        """Test CLI version command."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_analyze_command_help(self, runner):
        """Test analyze command help."""
        result = runner.invoke(cli, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "Analyze an SBOM file" in result.output

    def test_verify_command_help(self, runner):
        """Test verify command help."""
        result = runner.invoke(cli, ["verify", "--help"])
        assert result.exit_code == 0
        assert "Verify an SBOM file" in result.output

    def test_dep_command_help(self, runner):
        """Test dep command help."""
        result = runner.invoke(cli, ["dep", "--help"])
        assert result.exit_code == 0
        assert "Show the dependency tree" in result.output

    def test_check_pkg_command_help(self, runner):
        """Test check-pkg command help."""
        result = runner.invoke(cli, ["check-pkg", "--help"])
        assert result.exit_code == 0
        assert "Get detailed information" in result.output

    def test_scan_command_help(self, runner):
        """Test scan command help."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan the SBOM for potential CVEs" in result.output

    def test_analyze_with_nonexistent_file(self, runner):
        """Test analyze command with nonexistent file."""
        result = runner.invoke(cli, ["analyze", "nonexistent.json"])
        assert result.exit_code == 2  # Click returns 2 for file not found
        assert "does not exist" in result.output

    def test_verify_with_nonexistent_file(self, runner):
        """Test verify command with nonexistent file."""
        result = runner.invoke(cli, ["verify", "nonexistent.json"])
        assert result.exit_code == 2  # Click returns 2 for file not found
        assert "does not exist" in result.output

    def test_dep_with_nonexistent_file(self, runner):
        """Test dep command with nonexistent file."""
        result = runner.invoke(cli, ["dep", "nonexistent.json"])
        assert result.exit_code == 2  # Click returns 2 for file not found
        assert "does not exist" in result.output

    def test_check_pkg_with_nonexistent_file(self, runner):
        """Test check-pkg command with nonexistent file."""
        result = runner.invoke(cli, ["check-pkg", "nonexistent.json", "package"])
        assert result.exit_code == 2  # Click returns 2 for file not found
        assert "does not exist" in result.output

    def test_scan_with_nonexistent_file(self, runner):
        """Test scan command with nonexistent file."""
        result = runner.invoke(cli, ["scan", "nonexistent.json"])
        assert result.exit_code == 2  # Click returns 2 for file not found
        assert "does not exist" in result.output

    def test_verbose_flag(self, runner):
        """Test verbose flag."""
        result = runner.invoke(cli, ["--verbose", "--help"])
        assert result.exit_code == 0

    def test_quiet_flag(self, runner):
        """Test quiet flag."""
        result = runner.invoke(cli, ["--quiet", "--help"])
        assert result.exit_code == 0
