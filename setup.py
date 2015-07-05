# Minimal Object Storage Library, (C) 2015 Minio, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Minio Python
-------------------

Minio Python is a library for accessing S3 compatible object storage servers.

It is designed to be easy to use and minimal, exposing only the most used functionality.
"""

import re
import os
import sys

from setuptools import setup, find_packages

ROOT = os.path.dirname(__file__)
VERSION_RE = re.compile(r'''__version__ = ['"]([0-9.]+)['"]''')

def get_version():
    init = open(os.path.join(ROOT, 'minio', '__init__.py')).read()
    return VERSION_RE.search(init).group(1)

setup(
    name='minio',
    description='Minimal Object Storage Library for Python',
    author='Minio, Inc.',
    url='https://github.com/minio/minio-py',
    long_description=open('README.md').read(),
    download_url='https://github.com/minio/minio-py',
    author_email='dev@minio.io',
    version=get_version(),
    install_requires=['requests', 'pytz'],
    tests_require=['nose', 'mock'],
    packages=find_packages(exclude=['tests*']),
    scripts=[],
    setup_requires=['nose>=1.0'],
    test_suite='tests',
    use_2to3=True,
    license='Apache License 2.0',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
