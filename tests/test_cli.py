"""Tests for CLI commands."""

from click.testing import CliRunner

from bountyhound.cli import main, doctor, target, status


def test_main_shows_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Bug bounty automation CLI" in result.output


def test_doctor_command_runs():
    runner = CliRunner()
    result = runner.invoke(doctor)
    assert result.exit_code == 0
    # Should show tool check results
    assert "subfinder" in result.output.lower() or "checking" in result.output.lower()


def test_target_add_command():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(target, ["add", "example.com"])
        assert result.exit_code == 0
        assert "example.com" in result.output


def test_status_command_runs():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(status)
        assert result.exit_code == 0
