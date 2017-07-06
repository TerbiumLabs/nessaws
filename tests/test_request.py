"""Unit tests."""
from click.testing import CliRunner
from moto import mock_ec2, mock_rds

from nessaws.cli import main
from nessaws.excel import write_excel_output


def test_non_yaml_config():
    """Test running with an invalid config file."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/bad_yaml.yml', 'pentest-request',
         '-t', 'weekly', '-t', 'monthly'], catch_exceptions=False)
    assert result.exit_code == -1


@mock_ec2
@mock_rds
def test_no_instances():
    """Test running with no EC2/RDS instances."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.testing', 'pentest-request',
         '-t', 'weekly', '-t', 'monthly'], catch_exceptions=False)
    assert result.exit_code == -1


def test_pentest_request_dryrun(mocked_smtp, aws_instances, mocked_open):
    """Test penetration test request dry run."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.testing', 'pentest-request',
         '-t', 'weekly', '-t', 'monthly', '--dry-run'], catch_exceptions=False)
    assert result.exit_code == 0


def test_pentest_request(mocked_smtp, aws_instances, mocked_open):
    """Test submitting a penetration test request."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.testing', 'pentest-request',
         '-t', 'weekly', '-t', 'monthly'], catch_exceptions=False)
    assert result.exit_code == 0


def test_invalid_state_file(mocker, mocked_smtp, aws_instances,
                            mocked_open_io_error):
    """Test loading a malformed state file."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.testing', 'pentest-request',
         '-t', 'weekly', '-t', 'monthly'], catch_exceptions=False)
    assert result.exit_code == 0

    mocked_input = mocker.patch('nessaws.cli.input')
    mocked_input.side_effect = ['yes']

    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.testing', 'perform-scan'],
        catch_exceptions=False)
    assert result.exit_code == -1

    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.testing', 'perform-scan'],
        catch_exceptions=True)
    assert result.exit_code == -1


def test_decline_scan_outside_dates(mocker, mocked_smtp, aws_instances,
                                    mocked_open):
    """Test declining scan when outside the request dates."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.past_dates', 'pentest-request',
         '-t', 'weekly', '-t', 'monthly'], catch_exceptions=False)
    assert result.exit_code == 0

    mocked_input = mocker.patch('nessaws.cli.input')
    mocked_input.side_effect = ['dfjgkldfng', 'no']

    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.past_dates', 'perform-scan'],
        catch_exceptions=False)
    assert 'Please respond with "yes" or "no"' in result.output


def test_perform_scan_outside_dates(mocker, mocked_smtp, aws_instances,
                                    nessus_mock, mocked_open, mocked_excel):
    """Test performing a scan when outside the request dates."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.past_dates', 'pentest-request',
         '-t', 'weekly', '-t', 'monthly'], catch_exceptions=False)
    assert result.exit_code == 0

    mocked_input = mocker.patch('nessaws.cli.input')
    mocked_input.side_effect = ['yes']

    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.past_dates', 'perform-scan'],
        catch_exceptions=False)
    assert result.exit_code == 0


def test_missing_report_file(mocked_excel):
    """Test outputting Excel report when missing Nessus CSV."""
    config_object = {
        'account_names': [
            'test1',
            'test2'
        ],
        'tag_values': [
            'weekly',
            'monthly'
        ],
        'start_date': 'Tue, 07 Mar 2017 17:27:40 GMT',
        'end_date': 'Fri, 10 Mar 2017 17:27:40 GMT',
        'scans': [
            {
                'scan_name': 'test_scan',
                'status': 'completed',
                'result_file': 'test.csv',
                'targets': [
                    {
                        'name': 'target1',
                        'id': 1,
                    }
                ]
            }
        ]
    }
    write_excel_output(config_object)


def test_perform_scan_bad_nessus(mocker, aws_instances, mocked_smtp,
                                 bad_nessus_mock, mocked_open):
    """Test performing a scan with invalid Nessus credentials."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.past_dates', 'pentest-request',
         '-t', 'weekly', '-t', 'monthly'], catch_exceptions=False)
    assert result.exit_code == 0

    mocked_input = mocker.patch('nessaws.cli.input')
    mocked_input.side_effect = ['yes']

    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.past_dates', 'perform-scan'],
        catch_exceptions=False)
    assert result.exit_code == -1


def test_no_successful_scans(mocker, nessus_mock):
    """Test scenario where no scans were completed successfully."""
    mocked_input = mocker.patch('nessaws.cli.input')
    mocked_input.side_effect = ['yes']

    mock_open = mocker.patch('nessaws.config.open', create=True)
    mock_open.side_effect = [
        mocker.mock_open(
            read_data='nessus_url: "https://localhost:8834"\n'
            'nessus_username: "nessus"\n'
            'nessus_password: "password"\n'
            'nessus_secure: True\n'
            'nessus_source: 1.2.3.4\n'
            'aws_accounts:\n'
            '  - aws_access_key_id: ""\n'
            '    aws_secret_access_key: ""\n'
            '    region: "us-east-1"\n'
            '    root_email: "pentest@terbiumlabs.com"\n'
            '    tag_key: "NessAWS"\n'
            '    account_name: "Terbium Labs"\n'
            '    account_number: 1234567890\n'
            'smtp_host: "email-host.com"\n'
            'smtp_port: 587\n'
            'smtp_username: "root"\n'
            'smtp_password: "password"\n'
            'smtp_sendas: "pentest@test.com"\n'
            'smtp_to: "aws-pentest-email@aws.com"\n'
            'smtp_cc: "test@example.com"\n'
            'smtp_subject: "AWS Pentest Request"\n'
            'smtp_tls: True\n'
            'comments: "Nothing to see here"\n'
            'start_date: "Wed, 01 Mar 1969 17:27:40 GMT"\n'
            'end_date: "Mon, 20 Mar 1969 17:27:40 GMT"').return_value,
        mocker.mock_open(
            read_data='start_date: "Wed, 01 Mar 1969 17:27:40 GMT"\n'
            'end_date: "Mon, 20 Mar 1969 17:27:40 GMT"\n'
            'tag_values:\n- test1\n- test2\n'
            'account_names:\n- "test"\n'
            'scans:\n'
            '- scan_name: fake_scan\n'
            '  targets:\n'
            '  - id: i-dfbhu2aw\n'
            '    private_ip: 10.10.10.10\n'
            '    type: ec2\n').return_value
    ]

    runner = CliRunner()
    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.past_dates', 'perform-scan'],
        catch_exceptions=False)
    assert result.exit_code == -1


def test_perform_scan_inside_dates(mocked_smtp, aws_instances, nessus_mock,
                                   mocked_open_inside_dates, mocked_excel):
    """Test performing a scan when inside the request dates."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.good_dates', 'pentest-request',
         '-t', 'weekly', '-t', 'monthly'], catch_exceptions=False)
    assert result.exit_code == 0

    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.good_dates', 'perform-scan'],
        catch_exceptions=False)
    assert result.exit_code == 0


def test_perform_scan_raw_csv(
        mocker, mocked_smtp, aws_instances, nessus_mock,
        mocked_raw_csv_config):
    """Test performing a scan with raw CSV output."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.raw_csv', 'pentest-request',
         '-t', 'weekly', '-t', 'monthly'], catch_exceptions=False)
    assert result.exit_code == 0

    mocker.patch('nessaws.nessus.open', create=True)

    result = runner.invoke(
        main,
        ['--config', 'tests/fixtures/config.yml.raw_csv', 'perform-scan'],
        catch_exceptions=False)
    assert result.exit_code == 0
