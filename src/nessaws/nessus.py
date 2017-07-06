"""Nessus API functions."""
import json
import logging
import sys
import time

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from slugify import slugify


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logger = logging.getLogger('nessaws.nessus')


class NessusConnection(object):
    """Nessus connection object."""

    url = 'https://localhost:8834'
    headers = {
        'Content-type': 'application/json',
        'Accept': 'text/plain',
    }
    secure = True

    def __init__(self, url, username, password, secure=True):
        """Create a `NessusConnection` object.

        Args:
            url (str): The URL to the Nessus instance.
            username (str): The username for authentication to Nessus.
            password (str): The password for authentication to Nessus.
            secure (bool): Whether to enforce SSL certificate checks when
                connecting to Nessus.

        """
        self.url = url
        self.secure = secure
        self.username = username
        self.password = password
        self._login()

    def _login(self):
        """Authenticate to the Nessus API."""
        token = self._action('POST', 'session', {
            'username': self.username,
            'password': self.password,
        })['token']
        self.headers.update({'X-Cookie': 'token={}'.format(token)})

    def _action(self, method, endpoint, parameters=None, download=False):
        """Perform the API call against the Nessus instance and handle errors.

        Performs retries and handles authentication errors that may occur if
        the session expires.

        Args:
            method (str): The HTTP method to perform.
            endpoint (str): The API endpoint to call.
            parameters (Optional dict): Additional parameters to pass to the
                API endpoint.
            download (Optional bool): If True, return the `content` attribute
                of the request rather than the `json()`.

        Returns:
            A dict of the response if the API call was successful, exits the
            program on failure.

        """
        retry_total = 4
        retry_count = 1
        while retry_count <= retry_total:
            response = requests.request(
                method, '{}/{}'.format(self.url, endpoint),
                data=json.dumps(parameters), verify=self.secure,
                headers=self.headers)

            # handle session timeouts
            if response.status_code == 401 and endpoint != 'session':
                self._login()
            # retry other failures
            elif response.status_code != 200 and response.status_code != 401:
                logger.warning(
                    'Received a non-success status code ({code}) when '
                    'accessing the "{endpoint}" Nessus API endpoint (retry '
                    '{retry}/{retry_total}).\n\nResponse: {response}'.format(
                        code=response.status_code, endpoint=endpoint,
                        retry=retry_count, retry_total=retry_total,
                        response=response.text))
                retry_count += 1
                time.sleep(5)
            else:
                if download:
                    return response.content
                return response.json()
        sys.exit(-1)

    def get_scan_id(self, scan_name):
        """Get a Nessus scan's ID if the scan name exists.

        Args:
            scan_name (str): The scan name to lookup.

        Returns:
            The scan ID if a scan was found, else None.

        """
        response = self._action('GET', 'scans')
        for scan in response.get('scans', []):
            if scan['name'] == scan_name:
                return scan['id']

    def launch_scan(self, scan_name, scan_targets):
        """Launch a Nessus scan.

        Args:
            scan_name (str): The scan name to start.
            scan_targets (list): A list of scan targets.

        Returns:
            The UUID of the scan if it was started successfully, None if not.

        """
        scan_id = self.get_scan_id(scan_name)
        if scan_id:
            scan_uuid = self._action(
                'POST', 'scans/{}/launch'.format(scan_id), {
                    'alt_targets': scan_targets,
                }).get('scan_uuid')
            return scan_uuid

    def export_scan_csv(self, scan_name, scan_uuid):
        """Export scan result files in CSV format.

        Args:
            scan_name (str): The name of the Nessus scan to verify.
            scan_uuid (str): The UUID of the scan run to verify.

        Returns:
            The filename if export was successful, else None.

        """
        scan_id = self.get_scan_id(scan_name)
        scan_history = self._action(
            'GET', 'scans/{}'.format(scan_id)).get('history', []) or []
        scan_history_id = None
        for scan in scan_history:
            if scan['uuid'] == scan_uuid:
                scan_history_id = scan['history_id']
                break
        if scan_history_id:
            file_id = self._action(
                'POST', 'scans/{}/export?history_id={}'.format(
                    scan_id, scan_history_id), {'format': 'csv'})['file']
            while True:
                file_status = self._action(
                    'GET', 'scans/{}/export/{}/status'.format(
                        scan_id, file_id))['status']
                if file_status == 'ready':
                    break
                time.sleep(5)
            csv_output = self._action(
                'GET', 'scans/{}/export/{}/download'.format(
                    scan_id, file_id), download=True)
            filename = '{}_{}.csv'.format(
                slugify(scan_name, max_length=15), scan_uuid)
            csv_file = open(filename, 'wb')
            csv_file.write(csv_output)
            csv_file.close()
            return filename

    def get_credentialed_hosts(self, scan_name, scan_uuid):
        """Verify that Plugin 19506 indicates a credentialed scan for all hosts.

        Args:
            scan_name (str): The name of the Nessus scan to verify.
            scan_uuid (str): The UUID of the scan run to verify.

        Returns:
            A dict of two lists consisting of uncredentialed hosts and
            credentialed hosts.

        """
        result_dict = {
            'uncredentialed_hosts': [],
            'credentialed_hosts': [],
        }
        scan_id = self.get_scan_id(scan_name)
        scan_history = self._action(
            'GET', 'scans/{}'.format(scan_id)).get('history', [])
        for scan in scan_history:
            if scan['uuid'] == scan_uuid:
                scan_history_id = scan['history_id']
                scan_hosts = self._action(
                    'GET', 'scans/{}?history_id={}'.format(
                        scan_id, scan_history_id)).get('hosts', [])
                for scan_host in scan_hosts:
                    plugin_output = self._action(
                        'GET', 'scans/{}/hosts/{}/plugins/19506'
                        '?history_id={}'.format(
                            scan_id, scan_host['host_id'],
                            scan_history_id)).get('outputs', [{}])[0].get(
                                'plugin_output', '')
                    if 'Credentialed checks : yes' in plugin_output:
                        result_dict['credentialed_hosts'].append(
                            scan_host['hostname'])
                    else:
                        result_dict['uncredentialed_hosts'].append(
                            scan_host['hostname'])
        return result_dict

    def get_scan_status(self, scan_uuid):
        """Return the status of a Nessus scan.

        Args:
            scan_uuid (str): The UUID of a Nessus scan.

        Returns:
            A string of the scan status.

        """
        scans_list = self._action('GET', 'scans').get('scans', [])
        for scan in scans_list:
            if scan['uuid'] == scan_uuid:
                return scan['status']
        return 'not_found'
