"""AWS instance lookup functions."""
import boto3


def get_ec2_instances(tag_values, aws_accounts):
    """Filter EC2 instances for each AWS account looking for tag values.

    Args:
        tag_values (list): A list of tag values to filter for all instances on.
        aws_accounts (list): A list of dictionaries consisting of AWS
            Account credentials to use for looking up EC2 instances.

    Returns:
        A dict of the EC2 instances associated with each tag value found.

    """
    result_dict = {}
    for account in aws_accounts:
        aws_access_key_id = account['aws_access_key_id']
        aws_secret_access_key = account['aws_secret_access_key']
        tag_key = account['tag_key']
        region = account['region']
        ec2_conn = boto3.client(
            'ec2', aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key, region_name=region)
        paginator = ec2_conn.get_paginator('describe_instances')
        page_iterator = paginator.paginate(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running']},
                {'Name': 'tag:{}'.format(tag_key),
                 'Values': ['{} : *'.format(value) for value in tag_values]},
            ])
        for page in page_iterator:
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    if (instance['InstanceType'] != 'm1.small' or
                            instance['InstanceType'] != 't1.micro' or
                            instance['InstanceType'] != 't2.nano'):
                        nessus_scan_name = None
                        instance_name = None
                        for tag in instance['Tags']:
                            if tag['Key'] == tag_key:
                                nessus_scan_name = tag['Value'].split(
                                    ':')[1].strip()
                            if tag['Key'] == 'Name' and len(tag['Value']) > 0:
                                instance_name = tag['Value']
                        if nessus_scan_name:
                            scan_target = {
                                'type': 'ec2',
                                'id': instance['InstanceId'],
                                'private_ip': instance.get(
                                    'PrivateIpAddress'),
                            }
                            if instance.get('PublicIpAddress'):
                                scan_target.update(
                                    {'public_ip': instance['PublicIpAddress']})
                            if instance_name:
                                scan_target.update({'name': instance_name})
                            result_dict.setdefault(
                                nessus_scan_name, {}).setdefault(
                                    'targets', []).append(scan_target)
    return result_dict


def get_rds_instances(tag_values, aws_accounts):
    """Filter RDS instances for each AWS account looking for tag values.

    Args:
        tag_values (list): A list of tag values to filter for all instances on.
        aws_accounts (list): A list of dictionaries consisting of AWS
            Account credentials to use for looking up RDS instances.

    Returns:
        A dict of the RDS instances associated with each tag value found.

    """
    result_dict = {}
    for account in aws_accounts:
        aws_access_key_id = account['aws_access_key_id']
        aws_secret_access_key = account['aws_secret_access_key']
        tag_key = account['tag_key']
        region = account['region']
        rds_conn = boto3.client(
            'rds', aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key, region_name=region)
        paginator = rds_conn.get_paginator('describe_db_instances')
        page_iterator = paginator.paginate()
        for page in page_iterator:
            for instance in page['DBInstances']:
                if (not instance['DBInstanceClass'].endswith('.small') and
                        not instance['DBInstanceClass'].endswith('.micro')):
                    nessus_scan_name = None
                    for tag in rds_conn.list_tags_for_resource(
                            ResourceName=instance['DBInstanceArn'])['TagList']:
                        if (tag['Key'] == tag_key and
                                tag['Value'].split(':')[0].strip() in
                                tag_values):
                            nessus_scan_name = tag['Value'].split(
                                ':')[1].strip()
                            break
                    if nessus_scan_name:
                        result_dict.setdefault(
                            nessus_scan_name, {}).setdefault(
                                'targets', []).append({
                                    'type': 'rds',
                                    'id': instance['DBInstanceIdentifier'],
                                    'endpoint': instance.get('Endpoint').get(
                                        'Address'),
                                })
    return result_dict
