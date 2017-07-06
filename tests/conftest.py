"""py.test fixtures used in unit tests."""
import boto3
from moto import mock_ec2, mock_rds2
import pytest
import requests_mock


@pytest.fixture
def mocked_smtp(mocker):
    """Setup mocked SMTP connection."""
    mocked_smtplib = mocker.patch('nessaws.mailer.smtplib')
    mocked_smtplib.return_value.starttls.return_value = True
    mocked_smtplib.return_value.login.return_value = True
    mocked_smtplib.return_value.sendmail.return_value = True


@pytest.fixture
def mocked_open(mocker):
    """Mock file reads/writes."""
    mocked_config_open = mocker.patch('nessaws.config.open', create=True)
    mocked_config_open.side_effect = [
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
            'tag_values:\n- weekly\n- monthly\n'
            'account_names:\n- "Terbium Labs"\n'
            'scans:\n'
            '- scan_name: test_scan1\n'
            '  targets:\n'
            '  - id: i-45s6fd23\n'
            '    name: test instance 1\n'
            '    private_ip: 192.168.1.2\n'
            '    public_ip: 54.204.59.201\n'
            '    type: ec2\n'
            '  - id: i-sdf23r13\n'
            '    private_ip: 192.168.0.1\n'
            '    type: ec2\n'
            '  - endpoint: db-master-1.111111111.us-east-1.rds.amazonaws.com\n'
            '    id: db-master-1\n'
            '    type: rds\n'
            '- scan_name: test_scan2\n'
            '  targets:\n'
            '  - id: i-cdgdt3df\n'
            '    name: test instance 2\n'
            '    private_ip: 192.168.1.3\n'
            '    public_ip: 54.204.59.202\n'
            '    type: ec2\n'
            '- scan_name: test_scan3\n'
            '  targets:\n'
            '  - id: i-dfgnjas3\n'
            '    private_ip: 192.168.1.4\n'
            '    public_ip: 54.204.59.203\n'
            '    type: ec2\n'
            '- scan_name: test_scan4\n'
            '  targets:\n'
            '  - id: i-sf2fgh45\n'
            '    private_ip: 192.168.1.5\n'
            '    public_ip: 54.204.59.204\n'
            '    type: ec2\n').return_value
    ]
    mocker.patch('nessaws.cli.open', mocker.mock_open(), create=True)


@pytest.fixture
def mocked_open_io_error(mocker):
    """Mock IO errors on file open."""
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
            'start_date: "Wed, 01 Mar 2017 17:27:40 GMT"\n'
            'end_date: "Fri, 20 Mar 2017 17:27:40 GMT"').return_value,
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
            'start_date: "Wed, 01 Mar 2017 17:27:40 GMT"\n'
            'end_date: "Fri, 20 Mar 2017 17:27:40 GMT"').return_value,
        mocker.mock_open(
            read_data='test: test\n-test: test\n  -test:').return_value,
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
            'start_date: "Wed, 01 Mar 2017 17:27:40 GMT"\n'
            'end_date: "Fri, 20 Mar 2017 17:27:40 GMT"').return_value,
        IOError
    ]
    mocker.patch('nessaws.cli.open', mocker.mock_open(), create=True)


@pytest.fixture
def mocked_open_inside_dates(mocker):
    """Mock file reads/writes when using good dates for scan."""
    mocked_config_open = mocker.patch('nessaws.config.open', create=True)
    mocked_config_open.side_effect = [
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
            'always_use_private_ip: True\n'
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
            'end_date: "Mon, 20 Mar 2069 17:27:40 GMT"\n'
            'output: "none"').return_value,
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
            'always_use_private_ip: True\n'
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
            'end_date: "Mon, 20 Mar 2069 17:27:40 GMT"\n'
            'output: "none"').return_value,
        mocker.mock_open(
            read_data='start_date: "Wed, 01 Mar 1969 17:27:40 GMT"\n'
            'end_date: "Mon, 20 Mar 2069 17:27:40 GMT"\n'
            'tag_values:\n- weekly\n- monthly\n'
            'account_names:\n- "Terbium Labs"\n'
            'scans:\n'
            '- scan_name: test_scan1\n'
            '  targets:\n'
            '  - id: i-45s6fd23\n'
            '    name: test instance 1\n'
            '    private_ip: 192.168.1.2\n'
            '    public_ip: 54.204.59.201\n'
            '    type: ec2\n'
            '  - id: i-sdf23r13\n'
            '    private_ip: 192.168.0.1\n'
            '    type: ec2\n'
            '  - endpoint: db-master-1.111111111.us-east-1.rds.amazonaws.com\n'
            '    id: db-master-1\n'
            '    type: rds\n'
            '- scan_name: test_scan2\n'
            '  targets:\n'
            '  - id: i-cdgdt3df\n'
            '    name: test instance 2\n'
            '    private_ip: 192.168.1.3\n'
            '    public_ip: 54.204.59.202\n'
            '    type: ec2\n'
            '- scan_name: test_scan3\n'
            '  targets:\n'
            '  - id: i-dfgnjas3\n'
            '    private_ip: 192.168.1.4\n'
            '    public_ip: 54.204.59.203\n'
            '    type: ec2\n'
            '- scan_name: test_scan4\n'
            '  targets:\n'
            '  - id: i-sf2fgh45\n'
            '    private_ip: 192.168.1.5\n'
            '    public_ip: 54.204.59.204\n'
            '    type: ec2\n').return_value
    ]
    mocker.patch('nessaws.cli.open', mocker.mock_open(), create=True)


@pytest.fixture
def mocked_raw_csv_config(mocker):
    """Mock file reads/writes when using raw_csv for output."""
    mocked_config_open = mocker.patch('nessaws.config.open', create=True)
    mocked_config_open.side_effect = [
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
            'always_use_private_ip: True\n'
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
            'end_date: "Mon, 20 Mar 2069 17:27:40 GMT"\n'
            'output: "raw_csv"').return_value,
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
            'always_use_private_ip: True\n'
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
            'end_date: "Mon, 20 Mar 2069 17:27:40 GMT"\n'
            'output: "raw_csv"').return_value,
        mocker.mock_open(
            read_data='start_date: "Wed, 01 Mar 1969 17:27:40 GMT"\n'
            'end_date: "Mon, 20 Mar 2069 17:27:40 GMT"\n'
            'tag_values:\n- weekly\n- monthly\n'
            'account_names:\n- "Terbium Labs"\n'
            'scans:\n'
            '- scan_name: test_scan1\n'
            '  targets:\n'
            '  - id: i-45s6fd23\n'
            '    name: test instance 1\n'
            '    private_ip: 192.168.1.2\n'
            '    public_ip: 54.204.59.201\n'
            '    type: ec2\n'
            '  - id: i-sdf23r13\n'
            '    private_ip: 192.168.0.1\n'
            '    type: ec2\n'
            '  - endpoint: db-master-1.111111111.us-east-1.rds.amazonaws.com\n'
            '    id: db-master-1\n'
            '    type: rds\n'
            '- scan_name: test_scan2\n'
            '  targets:\n'
            '  - id: i-cdgdt3df\n'
            '    name: test instance 2\n'
            '    private_ip: 192.168.1.3\n'
            '    public_ip: 54.204.59.202\n'
            '    type: ec2\n'
            '- scan_name: test_scan3\n'
            '  targets:\n'
            '  - id: i-dfgnjas3\n'
            '    private_ip: 192.168.1.4\n'
            '    public_ip: 54.204.59.203\n'
            '    type: ec2\n'
            '- scan_name: test_scan4\n'
            '  targets:\n'
            '  - id: i-sf2fgh45\n'
            '    private_ip: 192.168.1.5\n'
            '    public_ip: 54.204.59.204\n'
            '    type: ec2\n').return_value
    ]
    mocker.patch('nessaws.cli.open', mocker.mock_open(), create=True)


@pytest.fixture(scope='module')
def aws_instances():
    """Setup mocked EC2 instances."""
    mocked_ec2 = mock_ec2()
    mocked_rds = mock_rds2()
    mocked_ec2.start()
    mocked_rds.start()

    ec2_conn = boto3.client('ec2', region_name='us-east-1')
    instances = ec2_conn.run_instances(
        ImageId='ami-0b33d91d', MinCount=3, MaxCount=3)['Instances']

    instance_ids = []
    for instance in instances:
        instance_ids.append(instance['InstanceId'])

    ec2_conn.create_tags(
        Resources=[instance_ids[0]],
        Tags=[
            {
                'Key': 'Name',
                'Value': 'test instance 1',
            },
            {
                'Key': 'NessAWS',
                'Value': 'weekly : test_scan1',
            },
        ]
    )
    ec2_conn.create_tags(
        Resources=[instance_ids[1]],
        Tags=[
            {
                'Key': 'Name',
                'Value': 'test instance 2',
            },
            {
                'Key': 'NessAWS',
                'Value': 'weekly : test_scan2',
            },
        ]
    )
    ec2_conn.create_tags(
        Resources=[instance_ids[2]],
        Tags=[
            {
                'Key': 'NessAWS',
                'Value': 'monthly : test_scan4',
            },
        ]
    )

    instance_id = ec2_conn.run_instances(
        ImageId='ami-0b33d91d', MinCount=1, MaxCount=1,
        PrivateIpAddress='192.168.0.1')['Instances'][0]['InstanceId']
    ec2_conn.create_tags(
        Resources=[instance_id],
        Tags=[
            {
                'Key': 'NessAWS',
                'Value': 'monthly : test_scan1',
            },
        ]
    )

    instance_id = ec2_conn.run_instances(
        ImageId='ami-0b33d91d', MinCount=1,
        MaxCount=1)['Instances'][0]['InstanceId']
    ec2_conn.create_tags(
        Resources=[instance_id],
        Tags=[
            {
                'Key': 'NessAWS',
                'Value': 'weekly : test_scan3',
            },
        ]
    )

    rds_conn = boto3.client('rds', region_name='us-east-1')
    rds_conn.create_db_instance(
        DBInstanceIdentifier='db-master-1',
        AllocatedStorage=10,
        DBInstanceClass='db.m1.xlarge',
        Engine='postgres',
        MasterUsername='root',
        MasterUserPassword='hunter2',
        Port=1234,
        Tags=[
            {
                'Key': 'NessAWS',
                'Value': 'monthly : test_scan1'
            },
        ])


@pytest.fixture
def nessus_mock():
    """Mocked Nessus fixture."""
    mock_request = requests_mock.Mocker()
    mock_request.register_uri(
        'POST', 'https://localhost:8834/session', json={'token': 'test123'})
    mock_request.register_uri(
        'POST', 'https://localhost:8834/scans/5/launch', json={
            'scan_uuid': '20369832-9460-48e9-8ae5-3f53bc526db9'})
    mock_request.register_uri(
        'POST', 'https://localhost:8834/scans/6/launch', json={
            'scan_uuid': '42d7478f-b9c6-4415-b46b-254cd30a731a'})
    mock_request.register_uri(
        'POST', 'https://localhost:8834/scans/7/launch', json={
            'scan_uuid': 'ea2d823c-2ae0-480d-9b82-a33e5e83959e'})
    mock_request.register_uri(
        'GET', 'https://localhost:8834/scans',
        [
            {
                'json': {
                    'scans': [
                        {
                            'name': 'test_scan1',
                            'id': 5,
                            'uuid': '20369832-9460-48e9-8ae5-3f53bc526db9',
                            'status': 'running',
                        },
                        {
                            'name': 'test_scan2',
                            'id': 6,
                            'uuid': '42d7478f-b9c6-4415-b46b-254cd30a731a',
                            'status': 'running'
                        },
                        {
                            'name': 'test_scan3',
                            'id': 7,
                            'uuid': 'ea2d823c-2ae0-480d-9b82-a33e5e83959e',
                            'status': 'running'
                        }
                    ]
                }
            },
            {
                'json': {
                    'scans': [
                        {
                            'name': 'test_scan1',
                            'id': 5,
                            'uuid': '20369832-9460-48e9-8ae5-3f53bc526db9',
                            'status': 'running',
                        },
                        {
                            'name': 'test_scan2',
                            'id': 6,
                            'uuid': '42d7478f-b9c6-4415-b46b-254cd30a731a',
                            'status': 'running'
                        },
                        {
                            'name': 'test_scan3',
                            'id': 7,
                            'uuid': 'ea2d823c-2ae0-480d-9b82-a33e5e83959e',
                            'status': 'running'
                        }
                    ]
                }
            },
            {
                'json': {
                    'scans': [
                        {
                            'name': 'test_scan1',
                            'id': 5,
                            'uuid': '20369832-9460-48e9-8ae5-3f53bc526db9',
                            'status': 'running',
                        },
                        {
                            'name': 'test_scan2',
                            'id': 6,
                            'uuid': '42d7478f-b9c6-4415-b46b-254cd30a731a',
                            'status': 'running'
                        },
                        {
                            'name': 'test_scan3',
                            'id': 7,
                            'uuid': 'ea2d823c-2ae0-480d-9b82-a33e5e83959e',
                            'status': 'running'
                        }
                    ]
                }
            },
            {
                'json': {
                    'scans': [
                        {
                            'name': 'test_scan1',
                            'id': 5,
                            'uuid': '20369832-9460-48e9-8ae5-3f53bc526db9',
                            'status': 'running',
                        },
                        {
                            'name': 'test_scan2',
                            'id': 6,
                            'uuid': '42d7478f-b9c6-4415-b46b-254cd30a731a',
                            'status': 'running'
                        },
                        {
                            'name': 'test_scan3',
                            'id': 7,
                            'uuid': 'ea2d823c-2ae0-480d-9b82-a33e5e83959e',
                            'status': 'running'
                        }
                    ]
                }
            },
            {
                'json': {
                    'scans': [
                        {
                            'name': 'test_scan1',
                            'id': 5,
                            'uuid': '20369832-9460-48e9-8ae5-3f53bc526db9',
                            'status': 'running',
                        },
                        {
                            'name': 'test_scan2',
                            'id': 6,
                            'uuid': '42d7478f-b9c6-4415-b46b-254cd30a731a',
                            'status': 'running'
                        },
                        {
                            'name': 'test_scan3',
                            'id': 7,
                            'uuid': 'ea2d823c-2ae0-480d-9b82-a33e5e83959e',
                            'status': 'running'
                        }
                    ]
                }
            },
            {
                'json': {
                    'scans': [
                        {
                            'name': 'test_scan1',
                            'id': 5,
                            'uuid': '20369832-9460-48e9-8ae5-3f53bc526db9',
                            'status': 'completed',
                        },
                        {
                            'name': 'test_scan2',
                            'id': 6,
                            'uuid': '42d7478f-b9c6-4415-b46b-254cd30a731a',
                            'status': 'completed'
                        },
                        {
                            'name': 'test_scan3',
                            'id': 7,
                            'uuid': 'ea2d823c-2ae0-480d-9b82-a33e5e83959e',
                            'status': 'canceled'
                        }
                    ]
                }
            }
        ])
    mock_request.register_uri(
        'GET', 'https://localhost:8834/scans/5', json={
            'history': [
                {
                    'uuid': '20369832-9460-48e9-8ae5-3f53bc526db9',
                    'history_id': 1,
                }

            ]})
    # throw in a random session timeout
    mock_request.register_uri(
        'GET', 'https://localhost:8834/scans/6', [
            {
                'status_code': 401,
                'json': {'error': 'Invalid Credentials'}
            },
            {
                'json': {
                    'history': [
                        {
                            'uuid': '42d7478f-b9c6-4415-b46b-254cd30a731a',
                            'history_id': 1,
                        }
                    ]
                }
            }
        ])
    mock_request.register_uri(
        'GET', 'https://localhost:8834/scans/5?history_id=1', json={
            'hosts': [
                {
                    'host_id': 1,
                    'hostname': '192.168.0.3',
                },
                {
                    'host_id': 2,
                    'hostname': '192.168.0.2',
                }
            ]})
    mock_request.register_uri(
        'GET', 'https://localhost:8834/scans/6?history_id=1', json={
            'hosts': [
                {
                    'host_id': 1,
                    'hostname': '192.168.0.3',
                }
            ]})
    mock_request.register_uri(
        'GET',
        'https://localhost:8834/scans/5/hosts/1/plugins/19506?history_id=1',
        json={
            'outputs': [
                {
                    'plugin_output': 'Credentialed checks : yes',
                }
            ]})
    mock_request.register_uri(
        'GET',
        'https://localhost:8834/scans/5/hosts/2/plugins/19506?history_id=1',
        json={
            'outputs': [
                {
                    'plugin_output': 'Credentialed checks : no',
                }
            ]})
    mock_request.register_uri(
        'GET',
        'https://localhost:8834/scans/6/hosts/1/plugins/19506?history_id=1',
        json={
            'outputs': [
                {
                    'plugin_output': 'Credentialed checks : yes',
                }
            ]})
    mock_request.register_uri(
        'POST', 'https://localhost:8834/scans/5/export?history_id=1', json={
            'file': 1})
    mock_request.register_uri(
        'POST', 'https://localhost:8834/scans/6/export?history_id=1', json={
            'file': 1})
    mock_request.register_uri(
        'GET', 'https://localhost:8834/scans/5/export/1/status',
        [
            {
                'json': {
                    'status': 'not ready'
                }
            },
            {
                'json': {
                    'status': 'ready'
                }
            }
        ])
    mock_request.register_uri(
        'GET', 'https://localhost:8834/scans/6/export/1/status',
        [
            {
                'json': {
                    'status': 'not ready'
                }
            },
            {
                'json': {
                    'status': 'ready'
                }
            }
        ])
    mock_request.register_uri(
        'GET', 'https://localhost:8834/scans/5/export/1/download',
        content=b'Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,'
        b'Description,Solution,See Also,Plugin Output\r\n'
        b'"10107","","","Critical","192.168.0.1","tcp","443","HTTP Server Type'
        b' and Version","A web server is running on the remote host.","This '
        b'plugin attempts to determine the type and the version of the\nremote'
        b' web server.","n/a","","The remote web server type is :\n\n'
        b'nginx/1.4.6 (Ubuntu)"\r\n"10114","CVE-1999-0524","","High",'
        b'"192.168.0.2","icmp","0","ICMP Timestamp Request Remote Date '
        b'Disclosure","It is possible to determine the exact time set on the'
        b' remote host.","The remote host answers to an ICMP timestamp '
        b'request.  This allows an\nattacker to know the date that is set '
        b'on the targeted machine, which\nmay assist an unauthenticated, '
        b'remote attacker in defeating time-based\n'
        b'authentication protocols.\n\nTimestamps returned from machines '
        b'running Windows Vista / 7 / 2008 /\n2008 R2 are deliberately '
        b'incorrect, but usually within 1000 seconds of\nthe actual system '
        b'time.","Filter out the ICMP timestamp requests (13), and the '
        b'outgoing ICMP\ntimestamp replies (14).","","The remote clock is '
        b'synchronized with the local clock.\n"\r\nb"10267",""'
        b',"","Medium","192.168.0.1","tcp","22","SSH Server Type'
        b' and Version Information","An SSH server is listening on this port.'
        b'","It is possible to obtain information about the remote SSH server'
        b' by\nsending an empty authentication request.","n/a","","\nSSH '
        b'version : SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8\nSSH supported'
        b' authentication : publickey\n"\r\nb"10287","","","Low","192.168.0.2"'
        b',"udp","0","Traceroute Information","It was possible to obtain '
        b'traceroute information.","Makes a traceroute to the remote host.",'
        b'"n/a","","For your information, here is the traceroute from '
        b'192.168.0.1 to 192.168.0.253 : \n192.168.0.1\n192.168.0.253\n"\r\n'
        b'"10881","","","None","192.168.0.2","tcp","22","SSH Protocol'
        b' Versions Supported","A SSH server is running on the remote host.",'
        b'"This plugin determines the versions of the SSH protocol supported '
        b'by\nthe remote SSH daemon.","n/a","","The remote SSH daemon '
        b'supports the following versions of the\nSSH protocol :\n\n  - '
        b'1.99\n  - 2.0\n"\r\n')
    mock_request.register_uri(
        'GET', 'https://localhost:8834/scans/6/export/1/download',
        content=b'Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,'
        b'Description,Solution,See Also,Plugin Output\r\n'
        b'"10107","","","Critical","192.168.0.3","tcp","443","HTTP Server Type'
        b' and Version","A web server is running on the remote host.","This '
        b'plugin attempts to determine the type and the version of the\nremote'
        b' web server.","n/a","","The remote web server type is :\n\n'
        b'nginx/1.4.6 (Ubuntu)"\r\n"10114","CVE-1999-0524","","High",'
        b'"192.168.0.3","icmp","0","ICMP Timestamp Request Remote Date '
        b'Disclosure","It is possible to determine the exact time set on the'
        b' remote host.","The remote host answers to an ICMP timestamp '
        b'request.  This allows an\nattacker to know the date that is set '
        b'on the targeted machine, which\nmay assist an unauthenticated, '
        b'remote attacker in defeating time-based\n'
        b'authentication protocols.\n\nTimestamps returned from machines '
        b'running Windows Vista / 7 / 2008 /\n2008 R2 are deliberately '
        b'incorrect, but usually within 1000 seconds of\nthe actual system '
        b'time.","Filter out the ICMP timestamp requests (13), and the '
        b'outgoing ICMP\ntimestamp replies (14).","","The remote clock is '
        b'synchronized with the local clock.\n"\r\nb"10267",""'
        b',"","Medium","192.168.0.3","tcp","22","SSH Server Type'
        b' and Version Information","An SSH server is listening on this port.'
        b'","It is possible to obtain information about the remote SSH server'
        b' by\nsending an empty authentication request.","n/a","","\nSSH '
        b'version : SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8\nSSH supported'
        b' authentication : publickey\n"\r\nb"10287","","","Low","192.168.0.3"'
        b',"udp","0","Traceroute Information","It was possible to obtain '
        b'traceroute information.","Makes a traceroute to the remote host.",'
        b'"n/a","","For your information, here is the traceroute from '
        b'192.168.0.3 to 192.168.0.253 : \n192.168.0.3\n192.168.0.253\n"\r\n'
        b'"10881","","","None","192.168.0.3","tcp","22","SSH Protocol'
        b' Versions Supported","A SSH server is running on the remote host.",'
        b'"This plugin determines the versions of the SSH protocol supported '
        b'by\nthe remote SSH daemon.","n/a","","The remote SSH daemon '
        b'supports the following versions of the\nSSH protocol :\n\n  - '
        b'1.99\n  - 2.0\n"\r\n')
    mock_request.start()


@pytest.fixture
def bad_nessus_mock():
    """Mocked Nessus fixture that returns errors."""
    mock_request = requests_mock.Mocker()
    mock_request.register_uri(
        'POST', 'https://localhost:8834/session', json={'token': 'test123'})
    mock_request.register_uri(
        'GET', 'https://localhost:8834/scans', status_code=500)
    mock_request.start()


@pytest.fixture
def mocked_excel(mocker):
    """Mock Excel workbook."""
    mocked_workbook = mocker.patch('nessaws.excel.Workbook', create=True)
    mocked_workbook.return_value.save.return_value = True
    mocked_workbook.encoding = 'utf-8'
    mocked_workbook.return_value.create_sheet.return_value = mocked_workbook
