"""nessaws: Automate Nessus scans against AWS EC2/RDS endpoints."""
from __future__ import absolute_import

import io
import sys

import setuptools


__all__ = ('setup',)


def readme():
    try:
        with io.open('README.rst') as fp:
            return fp.read()
    except OSError:
        return ''


def setup():
    """Package setup entrypoint."""
    install_requirements = [
        'boto3 >= 1.4.4',
        'botocore',
        'click',
        'colander-tools',
        'colander',
        'docutils',
        'et-xmlfile',
        'future',
        'futures',
        'iso8601',
        'jdcal',
        'jmespath',
        'netaddr',
        'openpyxl',
        'progress',
        'python-dateutil',
        'python-slugify',
        'pytz',
        'PyYAML',
        'requests',
        's3transfer',
        'six',
        'translationstring',
    ]
    setup_requirements = ['six', 'setuptools>=17.1', 'setuptools_scm']
    needs_sphinx = {
        'build_sphinx',
        'docs',
        'upload_docs',
    }.intersection(sys.argv)
    if needs_sphinx:
        setup_requirements.append('sphinx')
    setuptools.setup(
        author='Terbium Labs',
        author_email='infrastructure@terbiumlabs.com',
        classifiers=[
            'Development Status :: 2 - Pre-Alpha',
            'Environment :: Console',
            'Intended Audience :: Developers',
            'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
            'Operating System :: MacOS',
            'Operating System :: Microsoft :: Windows',
            'Operating System :: POSIX :: Linux',
            'Operating System :: Unix',
            'Programming Language :: Python :: 2',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.3',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
            'Programming Language :: Python :: Implementation :: PyPy',
            'Programming Language :: Python',
            'Topic :: Software Development :: Libraries :: Python Modules',
            'Topic :: Software Development :: Libraries',
            'Topic :: Utilities',
        ],
        description=__doc__,
        discover_requirements=True,
        entry_points={
            'console_scripts': [
                'nessaws = nessaws.cli:main',
            ],
        },
        include_package_data=True,
        install_requires=install_requirements,
        long_description=readme(),
        name='nessaws',
        package_dir={'': 'src'},
        package_data={
            '': ['LICENSE'],
            'nessaws': ['nessaws/templates/*.html'],
        },
        packages=setuptools.find_packages('./src'),
        setup_requires=setup_requirements,
        url='https://github.com/TerbiumLabs/nessaws',
        use_scm_version=True,
        zip_safe=False,
    )


if __name__ == '__main__':
    setup()
