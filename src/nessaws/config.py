"""Configuration file parsing and data validation."""
import logging
import sys

import botocore.session
import colander
from colander_tools.netaddr import IPAddressType
import yaml


logger = logging.getLogger('nessaws.config')


def get_aws_regions():
    """Return a list of possible AWS regions.

    Returns:
        A list of possible AWS regions.

    """
    session = botocore.session.get_session()
    return session.get_available_regions('ec2')


def load_state():
    """Load the hidden state file (in YAML) and deserialize with Colander.

    Returns:
        A dict of the loaded state.

    """
    try:
        with open('.nessaws_state', 'r') as state_file:
            try:
                yaml_state = yaml.load(state_file)
            except yaml.YAMLError as e:
                logger.critical(
                    'State file could not be parsed! ({})'.format(e))
                sys.exit(-1)
            schema = StateConfig()
            deserialized = schema.deserialize(yaml_state)
            return deserialized
    except (OSError, IOError) as e:
        logger.critical(
            'State could not be loaded, did you forget to run '
            '"pentest-request"?'.format(e))
        sys.exit(-1)


def parse_config(location):
    """Load configuration file and deserialize with Colander.

    Args:
        location (str): Filesystem location to configuration file.

    Returns:
        A dict of the configuration options.

    """
    with open(location, 'r') as config_file:
        try:
            yaml_config = yaml.load(config_file)
        except yaml.YAMLError as e:
            logger.critical(
                'Configuration file could not be parsed! ({})'.format(e))
            sys.exit(-1)
        schema = AppConfig()
        deserialized = schema.deserialize(yaml_config)
        return deserialized


class AWSAccount(colander.MappingSchema):
    """Colander Mapping Schema for AWS Account configuration."""

    aws_access_key_id = colander.SchemaNode(colander.String(), missing=None)
    aws_secret_access_key = colander.SchemaNode(
        colander.String(), missing=None)
    region = colander.SchemaNode(
        colander.String(), validator=colander.OneOf(get_aws_regions()),
        default='us-east-1')
    root_email = colander.SchemaNode(
        colander.String(), validator=colander.Email())
    tag_key = colander.SchemaNode(colander.String(), default='NessAWS')
    account_name = colander.SchemaNode(colander.String())
    account_number = colander.SchemaNode(
        colander.Int(), validator=colander.Range(1, 999999999999))


class AWSAccounts(colander.SequenceSchema):
    """Colander Sequence Schema for multiple AWS Accounts."""

    aws_account = AWSAccount()


class AppConfig(colander.MappingSchema):
    """Colander Mapping Schema for the overall configuration object."""

    nessus_url = colander.SchemaNode(
        colander.String(), missing='https://localhost:8834')
    nessus_username = colander.SchemaNode(colander.String())
    nessus_password = colander.SchemaNode(colander.String())
    nessus_secure = colander.SchemaNode(colander.Bool(), missing=True)
    nessus_source = colander.SchemaNode(colander.String())
    aws_accounts = AWSAccounts()
    always_use_private_ip = colander.SchemaNode(colander.Bool(), missing=False)
    smtp_host = colander.SchemaNode(colander.String())
    smtp_port = colander.SchemaNode(
        colander.Int(), validator=colander.Range(1, 65535), missing=25)
    smtp_username = colander.SchemaNode(colander.String(), missing=None)
    smtp_password = colander.SchemaNode(colander.String(), missing=None)
    smtp_tls = colander.SchemaNode(colander.Bool(), missing=False)
    smtp_to = colander.SchemaNode(
        colander.String(), missing='aws-security-cust-pen-test@amazon.com')
    smtp_cc = colander.SchemaNode(colander.String(), missing=None)
    smtp_sendas = colander.SchemaNode(colander.String())
    smtp_subject = colander.SchemaNode(
        colander.String(), missing='AWS Pentest Request')
    comments = colander.SchemaNode(colander.String(), missing=None)
    start_date = colander.SchemaNode(colander.String())
    end_date = colander.SchemaNode(colander.String())
    output = colander.SchemaNode(
        colander.String(), validator=colander.OneOf(
            ['excel', 'raw_csv', 'none']),
        missing='excel')


class Target(colander.MappingSchema):
    """Colander Mapping Schema for the scan target object."""

    id = colander.SchemaNode(colander.String())  # noqa: B001
    name = colander.SchemaNode(colander.String(), missing=colander.drop)
    public_ip = colander.SchemaNode(IPAddressType(), missing=colander.drop)
    private_ip = colander.SchemaNode(IPAddressType(), missing=colander.drop)
    type = colander.SchemaNode(colander.String())  # noqa: B001
    endpoint = colander.SchemaNode(colander.String(), missing=None)


class Targets(colander.SequenceSchema):
    """Colander Sequence Schema for scan targets."""

    targets = Target()


class Scan(colander.MappingSchema):
    """Colander Mapping Schema for a Nessus scan."""

    scan_name = colander.SchemaNode(colander.String())
    targets = Targets()


class Scans(colander.SequenceSchema):
    """Colander Sequence Schema for Nessus scans."""

    scan = Scan()


class AccountNames(colander.SequenceSchema):
    """Colander Sequence Schema for AWS account names."""

    account_name = colander.SchemaNode(colander.String())


class TagValues(colander.SequenceSchema):
    """Colander Sequence Schema for tag values."""

    value = colander.SchemaNode(colander.String())


class StateConfig(colander.MappingSchema):
    """Colander Mapping Schema for the state file object."""

    start_date = colander.SchemaNode(colander.String())
    end_date = colander.SchemaNode(colander.String())
    tag_values = TagValues()
    account_names = AccountNames()
    scans = Scans()
