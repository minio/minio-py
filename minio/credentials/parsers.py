# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2020 MinIO, Inc.
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

from xml.etree import ElementTree

from .credentials import Value
from ..helpers import _iso8601_to_utc_datetime

_XML_NS = {
    's3': 'http://s3.amazonaws.com/doc/2006-03-01/',
    'sts': 'https://sts.amazonaws.com/doc/2011-06-15/'
}


def parse_iam_credentials(data):
    """
    Parser for IAM Instance Metadata Security Credentials.

    https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html

    :param data: Dict containing the json response.
    :return: A 2-tuple containing:
        - a :class:`~minio.credentials.Value` instance with the temporary credentials.
        - A :class:`DateTime` instance of when the credentials expire.
    """
    expiration = _iso8601_to_utc_datetime(data['Expiration'])
    return Value(
        access_key=data['AccessKeyId'],
        secret_key=data['SecretAccessKey'],
        session_token=data['Token']
    ), expiration


def parse_assume_role(data):
    """
    Parser for assume role response.

    :param data: XML response data for STS assume role as a string.
    :return: A 2-tuple containing:
        - a :class:`~minio.credentials.Value` instance with the temporary credentials.
        - A :class:`DateTime` instance of when the credentials expire.
    """
    root = ElementTree.fromstring(data)
    credentials_elem = root.find("sts:AssumeRoleResult", _XML_NS).find(
        "sts:Credentials", _XML_NS)

    access_key = credentials_elem.find("sts:AccessKeyId", _XML_NS).text
    secret_key = credentials_elem.find("sts:SecretAccessKey", _XML_NS).text
    session_token = credentials_elem.find("sts:SessionToken", _XML_NS).text

    expiry_str = credentials_elem.find("sts:Expiration", _XML_NS).text
    expiry = _iso8601_to_utc_datetime(expiry_str)

    return Value(access_key, secret_key, session_token), expiry
