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


def test_recon_command_requires_target():
    runner = CliRunner()
    result = runner.invoke(main, ["recon"])
    # Should error without domain argument
    assert result.exit_code != 0


def test_pipeline_command_requires_target():
    runner = CliRunner()
    result = runner.invoke(main, ["pipeline"])
    assert result.exit_code != 0


def test_campaign_command_shows_in_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "campaign" in result.output


def test_campaign_command_requires_url():
    runner = CliRunner()
    result = runner.invoke(main, ["campaign"])
    # Should error without URL argument
    assert result.exit_code != 0


def test_campaign_command_has_browser_option():
    runner = CliRunner()
    result = runner.invoke(main, ["campaign", "--help"])
    assert result.exit_code == 0
    assert "--browser" in result.output


def test_campaign_command_has_max_targets_option():
    runner = CliRunner()
    result = runner.invoke(main, ["campaign", "--help"])
    assert result.exit_code == 0
    assert "--max-targets" in result.output


def test_campaign_command_has_batch_option():
    runner = CliRunner()
    result = runner.invoke(main, ["campaign", "--help"])
    assert result.exit_code == 0
    assert "--batch" in result.output