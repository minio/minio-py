# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015 MinIO, Inc.
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

import codecs
import re
import sys

from setuptools import setup

if sys.argv[-1] == "publish":
    sys.argv = sys.argv[:-1] + ["sdist", "upload"]

with codecs.open("minio/__init__.py") as file:
    version = re.search(
        r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
        file.read(),
        re.MULTILINE,
    ).group(1)

with codecs.open("README.md", encoding="utf-8") as file:
    readme = file.read()

setup(
    name="minio",
    description="MinIO Python SDK for Amazon S3 Compatible Cloud Storage",
    author="MinIO, Inc.",
    url="https://github.com/minio/minio-py",
    download_url="https://github.com/minio/minio-py/releases",
    author_email="dev@min.io",
    version=version,
    long_description_content_type="text/markdown",
    package_dir={"minio": "minio"},
    packages=["minio", "minio.credentials"],
    install_requires=["certifi", "urllib3"],
    tests_require=["mock", "nose"],
    license="Apache License 2.0",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    long_description=readme,
    package_data={"": ["LICENSE", "README.md"]},
    include_package_data=True,
)
