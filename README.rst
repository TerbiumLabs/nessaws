=======
nessaws
=======

.. image:: https://img.shields.io/pypi/v/nessaws.svg
   :target: https://pypi.python.org/pypi/nessaws

.. image:: https://img.shields.io/pypi/pyversions/nessaws.svg
   :target: https://pypi.python.org/pypi/nessaws

.. image:: https://travis-ci.org/TerbiumLabs/nessaws.svg?branch=master
   :target: https://travis-ci.org/TerbiumLabs/nessaws

.. image:: https://img.shields.io/coveralls/TerbiumLabs/nessaws.svg
   :target: https://coveralls.io/github/TerbiumLabs/nessaws

Automate Nessus scans against AWS EC2/RDS endpoints.

Introduction
------------

Want to automate scanning multiple AWS accounts with a single Nessus Professional license?
This is the tool for you!

**nessaws** is a small Python package that automates Nessus scans against AWS EC2/RDS
instances. It can also submit the `penetration test request to AWS`_
for you!

All you need to do is tag your EC2/RDS instances with a desired value and a Nessus scan name
to execute. **nessaws** will query EC2/RDS instances with the tagged values, get the IP
addresses of each instance, and submit a penetration testing request to AWS (via email).
After the request has been approved, **nessaws** can be launched again to start the
desired Nessus scans against the discovered instances.

After each scan is complete, **nessaws** can combine all scan results into a
single Microsoft Excel (.xlsx) file. As an added bonus, each host in the scan will
be checked to ensure authenticated checks have succeeded.

Installation & Configuration
----------------------------

To install directly from `PyPi`_, run:

::

  $ pip install nessaws

Alternatively, clone from source and install via setup.py:

::

  $ python setup.py install

After installation, a configuration file must be initialized. See `config.yml.sample`_
for an example. The following options are configurable:

- **nessus_url** (Optional str): The URL to your Nessus scanner (including \https:// and the port). Defaults to *\https://localhost:8834*.
- **nessus_username** (Required str): The username used to authenticate to the Nessus scanner.
- **nessus_password** (Required str): The password used to authenticate to the Nessus scanner.
- **nessus_secure** (Optional bool): Whether to enable SSL certificate checks when communicating with the Nessus scanner. If using self-signed certificates on your Nessus scanner, this should be set to *False*. Defaults to *True*.
- **nessus_source** (Required str): The IP address of the Nessus scanner as it will be seen across the AWS network, used for submitting the penetration test request. If using a Nessus scannner launched as an EC2 instance, include the instance identifier.
- **aws_accounts** (Required str): A list of AWS accounts that will be scanned. Configurable options for each account are documented below:
    - **aws_access_key_id** (Optional str): An AWS access key that has permissions to query EC2/RDS instances. Defaults to *None*, which will require a valid IAM role or other boto configuration to ensure proper authentication.
    - **aws_secret_access_key** (Optional str): An AWS secret access key that has permissions to query EC2/RDS instances. Defaults to *None*, which will require a valid IAM role or other boto configuration to ensure proper authentication.
    - **region** (Optional str): The AWS region to authenticate to. Defaults to *us-east-1*.
    - **root_email** (Required str): The AWS account's root email address, used for submitting the penetration test request.
    - **tag_key** (Optional str): The EC2/RDS tag key to query on each instance. Defaults to *NessAWS*.
    - **account_name** (Required str): The name of the AWS account, used for submitting the penetration test request and included in the final report.
    - **account_number** (Required int): The AWS account number, used for submitting the penetration test request.
- **always_use_private_ip** (Optional bool): Whether to always use the private IP address when scanning EC2 instances. This option should be set to True if your Nessus scanner is located in a private subnet. Defaults to *False*.
- **smtp_host** (Required str): The hostname of the SMTP server to send outgoing mail through.
- **smtp_port** (Optional int): The port of the SMTP server to send outgoing mail. Defaults to *25*.
- **smtp_username** (Optional str): The username (if required) to authenticate to the SMTP server. Defaults to *None*.
- **smtp_password** (Optional str): The password (if required) to authenticate to the SMTP server. Defaults to *None*.
- **smtp_sendas** (Required str): The email address to send the penetration request email as.
- **smtp_to** (Optional str): The email address to send the penetration request email to. Defaults to *aws-pentest-email@aws.com*.
- **smtp_tls** (Optional bool): Whether or not the SMTP server should use TLS to connect. Defaults to *False*.
- **smtp_cc** (Required str): A comma separated string of email addresses to CC on the penetration test request email.
- **smtp_subject** (Optional str): The subject line of the email to send with the penetration test request. Defaults to *AWS Pentest Request*.
- **comments** (Optional str): Additional comments to attach with the penetration test request. Defaults to *None*.
- **start_date** (Required str): The RFC 1123 datetime that the scan will begin, used for submitting the penetration test request.
- **end_date** (Required str): The RFC 1123 datetime that the scan will complete, used for submitting the penetration test request.
- **output** (Optional str): Specify one output option. Currently supported options are *excel*, *raw_csv*, or *none*. Specifying *excel* will export and combine all scans into one Microsoft Excel spreadsheet. Specifying *raw_csv* will export the scan files to CSV in the location where **nessaws** is ran. Specifying *none* will only run the Nessus scans but perform no exporting. Defaults to *excel*.

EC2/RDS instances that you wish to be scanned must be tagged appropriately. Tags should
configured like:

+-------------------+-----------------------------------------+
| Key               | Value                                   |
+===================+=========================================+
|   <tag key>       |     <tag value> : <nessus scan name>    |
+-------------------+-----------------------------------------+

The <tag key> corresponds to the **tag_key** specified in the configuration
file above (defaults to *NessAWS*). The <tag value> should be set by the user, and
may be a scan cadence (such as weekly, monthly, etc.) or an instance role (such
as webserver, database, etc.). The **tag values** will be specified explicitly by
the user when running the **pentest-request** command. The <nessus scan name>
should correspond to an existing Nessus scan already configured (with proper
credentials and settings). The scan targets will be updated on-the-fly as instances
are discovered.

Thus, tags may look like:

+---------+-----------------------+
| Key     | Value                 |
+=========+=======================+
| NessAWS |  weekly : test_scan   |
+---------+-----------------------+

or

+---------+-----------------------+
| Key     | Value                 |
+=========+=======================+
| NessAWS | database : mysql_scan |
+---------+-----------------------+


Running nessaws
---------------

Penetration test request
~~~~~~~~~~~~~~~~~~~~~~~~

After installing **nessaws**, setting up the configuration file, and tagging EC2/RDS
instances appropriately, you will first need to submit a penetration test request.
**nessaws** automates this process for you by finding EC2/RDS instances with specified
tag values, filtering out any nano, micro, or small instance types, and sending an email
to AWS from the root account's email address.

The following command will submit a penetration test request for instances tagged
with the value "weekly":

::

  $ nessaws --config config.yml pentest-request -t weekly

Multiple tags can be specified simultaneously. The following command will submit
a penetration test request for instances tagged with the value "weekly" OR "daily":

::

  $ nessaws --config config.yml pentest-request -t weekly -t daily

If you would like to preview the penetration test request that will be sent, you
can pass the *--dry-run* option. This will send a copy of the email to the
addresses in the **smtp_cc** configuration detailed above.

If you wish to edit the contents of the penetration test email, see the *templates/request-template.html*
file.

Performing Nessus scans
~~~~~~~~~~~~~~~~~~~~~~~~

After the penetration test request has been approved by AWS, you can perform the
Nessus scans by executing the **perform-scan** command. This command reads from
a "state file" that is populated from the **pentest-request** command. Thus,
no additional options are required, as the instances to scan have already been
cataloged.

::

  $ nessaws --config config.yml perform-scan

This command will also check to see that the current date on the system is within
the start and end dates configured in the penetration test request. This can be
bypassed if necessary:

::

  $ nessaws --config config.yml perform-scan

  The current system time is not within the submitted start time and end time. Are you sure you want to continue?

  Type "yes" or "no":
  yes

If *excel* was entered in the output configuration, a Microsoft Excel report
(.xlsx) will be output at the completion of all scans. This
report contains a summary sheet that includes each scan that was performed, its
outcome, and the targets that were scanned. A results sheet containing the output
from all scans is also included. The results are colored based on risk, and also
mapped back to the EC2/RDS instance IDs or Name tags.

If you wish to run the scan again (perhaps after remediation), simply run the
`perform-scan` command again. There is no need to submit another penetration test
request as long as the date is within the requested time period.


Scanning without a Penetration Test Request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you wish to perform a scan without submitting a penetration test request
through **nessaws** (for example, if you prefer to do this manually or another
automated process), you will need to use the `--dry-run` option in the
`pentest-request` command. This command will won't send the email to AWS, but
is needed to populate a "state file" that inventories the AWS instances to scan.
You don't need a valid SMTP server, even if the email does not send, the state
will be populated successfully.

Required IAM Permissions
------------------------

The following IAM permissions are required for operation:

::

    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstances",
                    "rds:DescribeDBInstances",
                    "rds:ListTagsForResource"
                ],
                "Resource": "*"
            }
        ]
    }


Contributing
------------

Bug reports and pull requests are welcome. If you would like to
contribute, please create a pull request against master. Include unit
tests if necessary, and ensure that your code passes all linters (see
`tox.ini`_).

.. _penetration test request to AWS: https://aws.amazon.com/security/penetration-testing/
.. _PyPi: https://pypi.python.org/pypi/nessaws
.. _config.yml.sample: https://github.com/TerbiumLabs/nessaws/blob/master/config.yml.sample
.. _tox.ini: https://github.com/TerbiumLabs/nessaws/blob/master/tox.ini
