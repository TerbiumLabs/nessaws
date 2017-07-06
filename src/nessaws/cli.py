"""Provides the nessaws command line interface."""
from builtins import input
import datetime
import logging
import sys
import time

import click
from progress.spinner import MoonSpinner
import yaml

from nessaws.aws import get_ec2_instances, get_rds_instances
from nessaws.config import load_state, parse_config
from nessaws.excel import write_excel_output
from nessaws.mailer import send_pentest_request
from nessaws.nessus import NessusConnection


logger = logging.getLogger('nessaws')
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
file_handler = logging.FileHandler(filename='nessaws.log', mode='w')
console_handler.setLevel(logging.DEBUG)
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s | %(name)s | %(levelname)s | %(message)s')
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)
logger.addHandler(console_handler)
logger.addHandler(file_handler)


@click.group()
@click.option('-c', '--config', default='config.yml',
              help=('Provide the path to the configuration file.'),
              type=click.Path(exists=True))
@click.pass_context
def main(ctx, config):
    """Automate Nessus scans against AWS EC2 endpoints."""
    global_config = parse_config(config)
    ctx.obj = {
        'config': global_config,
    }


@main.command('pentest-request')
@click.option(
    '-t', '--tags', help=(
        'Tag values to determine applicable EC2/RDS instances. '
        'Multiple tag values supported.'), multiple=True, required=True)
@click.option('--dry-run', is_flag=True,
              help='Generates state file without sending a pentest request.')
@click.pass_obj
@click.pass_context
def pen_test_request(ctx, options, tags, dry_run):
    """Create/send the penetration test request for the tagged instances."""
    logger.info('Performing pentest-request with following tag '
                'values "{}" and dry-run={}'.format(', '.join(tags), dry_run))
    ec2_scans = get_ec2_instances(
        tag_values=tags,
        aws_accounts=options['config']['aws_accounts'])
    rds_scans = get_rds_instances(
        tag_values=tags,
        aws_accounts=options['config']['aws_accounts'])
    config_values = options['config']

    # combine ec2_scans and rds_scans into a single dict
    scans = rds_scans
    for scan in ec2_scans:
        if scans.get(scan):
            scans[scan]['targets'] += ec2_scans[scan]['targets']
        else:
            scans[scan] = ec2_scans[scan]

    if scans == {}:
        logger.critical('No EC2/RDS instances with the tag values "{}" were '
                        'found.'.format(', '.join(tags)))
        sys.exit(-1)

    aws_account_names = []
    for account in options['config']['aws_accounts']:
        aws_account_names.append(account['account_name'])

    state = {
        'start_date': config_values['start_date'],
        'end_date': config_values['end_date'],
        'tag_values': tags,
        'account_names': aws_account_names,
        'scans': [],
    }

    for scan_name in scans:
        state['scans'].append(
            {
                'scan_name': scan_name,
                'targets': scans[scan_name]['targets'],
            })

    # construct state yaml file with given parameters
    with open('.nessaws_state', 'w') as state_file:
        yaml.safe_dump(state, state_file, default_flow_style=False)

    send_pentest_request(
        config=options['config'], state=state, dry_run=dry_run)


@main.command('perform-scan')
@click.pass_obj
@click.pass_context
def perform_scan(ctx, options):
    """Perform the Nessus scan against the tagged instances."""
    state_object = load_state()
    configuration = options['config']

    # check if current date is between the start and end date, print warning
    # and require user 'yes' to continue
    start_datetime = datetime.datetime.strptime(
        state_object['start_date'], '%a, %d %b %Y %H:%M:%S GMT')
    end_datetime = datetime.datetime.strptime(
        state_object['end_date'], '%a, %d %b %Y %H:%M:%S GMT')
    now = datetime.datetime.utcnow()
    if now > end_datetime or now < start_datetime:
        while True:
            print('The current system time is not within the submitted '
                  'start time and end time. Are you sure you want to '
                  'continue?\n\nType "yes" or "no":')
            choice = input().lower()
            if choice == 'yes':
                break
            elif choice == 'no':
                sys.exit(1)
            else:
                print('Please respond with "yes" or "no"')

    logger.info('Performing Nessus scans with authorization between '
                '{} - {}'.format(state_object['start_date'], state_object[
                                 'end_date']))
    nessus_conn = NessusConnection(
        configuration['nessus_url'], configuration['nessus_username'],
        configuration['nessus_password'],
        configuration['nessus_secure'])

    #  we will run all scans and put their UUIDs into the state to poll them
    #  until completion
    for scan in state_object['scans']:
        scan_name = scan['scan_name']
        instance_ips = []
        # get list of IPs to update on the nessus scan
        for target in scan['targets']:
            if target['type'] == 'ec2':
                if configuration['always_use_private_ip']:
                    instance_ips.append(str(target['private_ip']))
                else:
                    instance_ips.append(str(target['public_ip']) if target.get(
                        'public_ip') else str(target['private_ip']))
            if target['type'] == 'rds':
                instance_ips.append(target['endpoint'])

        # launch scan with the IPs of the scans
        logger.info('Launching scan {}'.format(scan_name))
        scan_uuid = nessus_conn.launch_scan(scan_name, instance_ips)
        if scan_uuid:
            #  put all scans into a list and wait for them all to be
            #  complete
            scan['uuid'] = scan_uuid
        else:
            logger.warning(
                'Unable to find a Nessus scan with name "{}", the '
                'following instances will not be scanned:\n\n {}'.format(
                    scan_name, ', '.join(instance_ips)))

    #  poll scans for completion
    successful_scan = False
    done_count = 0
    spinner = MoonSpinner()
    scans_count = len(state_object['scans'])
    logger.debug('Polling {} scans'.format(scans_count))
    while done_count != scans_count:
        #  keep count of number of scans done so we know when to stop
        spinner.next()
        for scan in state_object['scans']:
            scan_name = scan['scan_name']
            scan_uuid = scan.get('uuid')
            scan_status = nessus_conn.get_scan_status(scan_uuid)
            logger.debug('Got status "{}" from scan "{}"'.format(
                scan_status, scan_name))
            #  only check the scan if the status has changed from what is
            #  cached
            if scan_status != scan.get('status'):
                scan['status'] = scan_status
                #  if scan is no longer running, increment done count
                if scan_status != 'running' and scan_status != 'pending':
                    done_count += 1
                    logger.debug(
                        'Scan {} is no longer running'.format(scan_name))
                    #  log & record successful scans
                    if scan_status == 'completed':
                        successful_scan = True
                        logger.info('Scan "{}" completed successfully'.format(
                            scan_name))
                        #  update with un/credentialed hosts
                        logger.info(
                            'Updating credentialed/uncredentialed hosts '
                            'in "{}" ...'.format(scan_name))
                        scan.update(nessus_conn.get_credentialed_hosts(
                            scan_name, scan_uuid))
                        #  export if needed
                        if configuration['output'] != 'none':
                            logger.info('Exporting scan csv {}-{}'.format(
                                scan_name, scan_uuid))
                            result_filename = nessus_conn.export_scan_csv(
                                scan_name, scan_uuid)
                            scan['result_file'] = result_filename
                    else:
                        logger.warning(
                            'Nessus scan "{}" was not completed '
                            'successfully, the following instances may not '
                            'have been scanned:\n\n {}'.format(
                                scan_name, ', '.join(instance_ips)))
                else:
                    logger.info(
                        'Waiting for scan "{}" to be completed...'.format(
                            scan_name))
        time.sleep(5)

    # check if no scans were successful
    if not successful_scan:
        logger.critical(
            'None of the Nessus scans completed successfully. Please check '
            'your Nessus scans configurations and try again.')
        sys.exit(-1)

    logger.info('Scans completed, determining output...')
    if configuration['output'] == 'excel':
        logger.info('Excel was selected for output, writing xlsx...')
        output_filename = write_excel_output(state_object)
        logger.info('Exported result file is named: "{}"'.format(
            output_filename))
    elif configuration['output'] == 'raw_csv':
        logger.info(
            'Raw CSV output configured, Nessus report CSVs are located in'
            ' the current directory.')
    else:
        logger.info(
            'No output configured, exiting successfully...')
