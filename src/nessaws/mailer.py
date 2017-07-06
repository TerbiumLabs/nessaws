"""Pen-test request email functions."""
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import math
import os
import smtplib
from string import Template

import pkg_resources


TEMPLATE_DIR = pkg_resources.resource_filename('nessaws', 'templates')
logger = logging.getLogger('nessaws.mailer')


def send_pentest_request(config, state, dry_run=False):
    """Send an email to AWS with required information.

    Required pentest information is taken from here:
    http://docs.aws.amazon.com/govcloud-us/latest/UserGuide/pen-testing.html

    Args:
        config (dict): The configuration dict loaded in `pen_test_request`.
        state (dict): The generated state after querying EC2 instances.
        dry_run (Optional bool): If enabled, send the request to the configured
            `smtp_cc` addresses.

    """
    ip_addresses = []
    instance_ids = []
    for scan in state['scans']:
        for target in scan['targets']:
            if target['type'] == 'ec2':
                ip_addresses.append(str(target['private_ip']))
                instance_ids.append(target['id'])
            if target['type'] == 'rds':
                instance_ids.append(target['endpoint'])

    account_numbers = []
    root_emails = []
    regions = []
    for account in config['aws_accounts']:
        account_numbers.append(str(account['account_number']))
        root_emails.append(account['root_email'])
        regions.append(account['region'])

    request_text = open(
        os.path.join(TEMPLATE_DIR, 'request-template.html'), 'r').read()

    # Full Nessus scan results in 32 MB worth of traffic
    # Average Nessus scan ~ 15 min per host
    # .032 GB / 900 seconds = .0003, round up to nearest whole number
    bandwidth = math.ceil(.00003 * len(instance_ids))

    # Substitute placeholders in template file with actual values.
    final_email = Template(request_text).safe_substitute(
        account_name=', '.join(state['account_names']),
        account_number=', '.join(account_numbers),
        root_email=', '.join(root_emails),
        recipients=config.get('smtp_cc'),
        region=', '.join(regions),
        comments=config.get('comments'),
        start_date=config.get('start_date'),
        end_date=config.get('end_date'),
        private_ips=', '.join(ip_addresses),
        nessus=config.get('nessus_source'),
        instance_ids=', '.join(instance_ids),
        bandwidth=bandwidth,
    )

    mailmsg = MIMEMultipart()
    mailmsg['Subject'] = config.get('smtp_subject')

    if dry_run:
        send_to = config.get('smtp_cc')
    else:
        send_to = config.get('smtp_to')
    mailmsg['To'] = send_to
    mailmsg['CC'] = config.get('smtp_cc')
    mailmsg['From'] = config.get('smtp_sendas')
    mime_text = MIMEText(final_email, 'html')
    mailmsg.attach(mime_text)

    smtp = smtplib.SMTP(config.get('smtp_host'), config.get('smtp_port'))

    if config.get('smtp_tls'):
        smtp.starttls()

    # send email according to smtp information provided
    if config.get('smtp_username'):
        smtp.login(config.get('smtp_username'), config.get('smtp_password'))

    smtp.sendmail(
        config.get('smtp_sendas'), config.get('smtp_cc'), mailmsg.as_string())
    smtp.quit()

    logger.info('Sent emails to "{}"'.format(send_to))
