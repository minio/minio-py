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

from setuptools import setup

setup(
    name='minio',
    description='Minimal Object Storage Library for Python',
    author='Minio Inc.',
    url='https://github.com/minio/minio-py',
    download_url='https://github.com/minio/minio-py.git',
    author_email='dev@minio.io',
    version='0.0.2',
    install_requires=['requests', 'pytz'],
    tests_require=['nose', 'mock'],
    packages=['minio', 'tests'],
    py_modules=['minio', 'tests'],
    scripts=[],
    setup_requires=['nose>=1.0'],
    test_suite='tests',
    use_2to3=True,
    license='ALv2'
)
