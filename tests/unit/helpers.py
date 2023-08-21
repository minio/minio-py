# -*- coding: utf-8 -*-
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

from collections import namedtuple
from unittest import TestCase
from urllib.parse import urlunsplit

from minio.helpers import BaseURL


def generate_error(code, message, request_id, host_id,
                   resource, bucket_name, object_name):
    return '''
    <Error>
      <Code>{0}</Code>
      <Message>{1}</Message>
      <RequestId>{2}</RequestId>
      <HostId>{3}</HostId>
      <Resource>{4}</Resource>
      <BucketName>{5}</BucketName>
      <Key>{6}</Key>
    </Error>
    '''.format(code, message, request_id, host_id,
               resource, bucket_name, object_name)


class BaseURLTests(TestCase):
    def test_aws_new_baseurl_error(self):
        cases = [
            # invalid Amazon AWS host error
            "https://z3.amazonaws.com",
            "https://1234567890.s3.amazonaws.com",
            "https://1234567890.s3-accelerate.amazonaws.com",
            "https://1234567890.abcdefgh.s3-control.amazonaws.com",
            "https://s3fips.amazonaws.com",
            "https://s3-fips.s3.amazonaws.com",
            "https://s3-fips.s3accelerate.amazonaws.com",
            "https://s3-fips.s3-accelerate.amazonaws.com",
            "https://bucket.vpce.s3.us-east-1.vpce.amazonaws.com",
            "https://bucket.bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1."
            "vpce.amazonaws.com",
            "https://accesspoint.accesspoint.vpce-1a2b3c4d-5e6f.s3.us-east-1."
            "vpce.amazonaws.com",
            "https://accesspoint.vpce-1123.vpce-xyz.s3.amazonaws.com",
            # use HTTPS scheme for host error
            "http://s3-accesspoint.amazonaws.com",
            # region missing in Amazon S3 China endpoint error
            "https://s3.amazonaws.com.cn",
        ]
        for endpoint in cases:
            self.assertRaises(ValueError, BaseURL, endpoint, None)

    def test_aws_new_baseurl(self):
        Case = namedtuple("Case", ["args", "result"])
        cases = [
            Case(
                ("https://s3.amazonaws.com", None),
                {
                    "s3_prefix": "s3.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3.amazonaws.com", "ap-south-1a"),
                {
                    "s3_prefix": "s3.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3.us-gov-east-1.amazonaws.com", None),
                {
                    "s3_prefix": "s3.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3.me-south-1.amazonaws.com", "cn-northwest-1"),
                {
                    "s3_prefix": "s3.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": False,
                },
            ),
            ###
            Case(
                ("https://s3.dualstack.amazonaws.com", None),
                {
                    "s3_prefix": "s3.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3.dualstack.amazonaws.com", "ap-south-1a"),
                {
                    "s3_prefix": "s3.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3.dualstack.us-gov-east-1.amazonaws.com", None),
                {
                    "s3_prefix": "s3.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3.dualstack.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                {
                    "s3_prefix": "s3.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": True,
                },
            ),
            ###
            Case(
                ("https://s3-accelerate.amazonaws.com", None),
                {
                    "s3_prefix": "s3-accelerate.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-accelerate.amazonaws.com", "ap-south-1a"),
                {
                    "s3_prefix": "s3-accelerate.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-accelerate.us-gov-east-1.amazonaws.com", None),
                {
                    "s3_prefix": "s3-accelerate.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-accelerate.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                {
                    "s3_prefix": "s3-accelerate.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": False,
                },
            ),
            ###
            Case(
                ("https://s3-accelerate.dualstack.amazonaws.com", None),
                {
                    "s3_prefix": "s3-accelerate.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3-accelerate.dualstack.amazonaws.com",
                 "ap-south-1a"),
                {
                    "s3_prefix": "s3-accelerate.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3-accelerate.dualstack.us-gov-east-1.amazonaws.com",
                 None),
                {
                    "s3_prefix": "s3-accelerate.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3-accelerate.dualstack.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                {
                    "s3_prefix": "s3-accelerate.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": True,
                },
            ),
            ###
            Case(
                ("https://s3-fips.amazonaws.com", None),
                {
                    "s3_prefix": "s3-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-fips.amazonaws.com", "ap-south-1a"),
                {
                    "s3_prefix": "s3-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-fips.us-gov-east-1.amazonaws.com", None),
                {
                    "s3_prefix": "s3-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-fips.me-south-1.amazonaws.com", "cn-northwest-1"),
                {
                    "s3_prefix": "s3-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": False,
                },
            ),
            ###
            Case(
                ("https://s3-fips.dualstack.amazonaws.com", None),
                {
                    "s3_prefix": "s3-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3-fips.dualstack.amazonaws.com", "ap-south-1a"),
                {
                    "s3_prefix": "s3-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3-fips.dualstack.us-gov-east-1.amazonaws.com", None),
                {
                    "s3_prefix": "s3-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3-fips.dualstack.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                {
                    "s3_prefix": "s3-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": True,
                },
            ),
            ###
            Case(
                ("https://s3-external-1.amazonaws.com", None),
                {
                    "s3_prefix": "s3-external-1.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-east-1",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-us-gov-west-1.amazonaws.com", None),
                {
                    "s3_prefix": "s3-us-gov-west-1.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-west-1",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-fips-us-gov-west-1.amazonaws.com", None),
                {
                    "s3_prefix": "s3-fips-us-gov-west-1.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-west-1",
                    "dualstack": False,
                },
            ),
            ###
            Case(
                ("https://bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                 "vpce.amazonaws.com", None),
                {
                    "s3_prefix": "bucket.vpce-1a2b3c4d-5e6f.s3.",
                    "domain_suffix": "vpce.amazonaws.com",
                    "region": "us-east-1",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://accesspoint.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                 "vpce.amazonaws.com", None),
                {
                    "s3_prefix": "accesspoint.vpce-1a2b3c4d-5e6f.s3.",
                    "domain_suffix": "vpce.amazonaws.com",
                    "region": "us-east-1",
                    "dualstack": False,
                },
            ),
            ###
            Case(
                ("https://012345678901.s3-control.amazonaws.com", None),
                {
                    "s3_prefix": "012345678901.s3-control.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": False,
                },
            ),
            Case(
                ("https://012345678901.s3-control.amazonaws.com",
                 "ap-south-1a"),
                {
                    "s3_prefix": "012345678901.s3-control.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://012345678901.s3-control.us-gov-east-1.amazonaws.com",
                 None),
                {
                    "s3_prefix": "012345678901.s3-control.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://012345678901.s3-control.us-gov-east-1.amazonaws.com",
                 "cn-northwest-1"),
                {
                    "s3_prefix": "012345678901.s3-control.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": False,
                },
            ),
            ###
            Case(
                ("https://012345678901.s3-control.dualstack.amazonaws.com",
                 None),
                {
                    "s3_prefix": "012345678901.s3-control.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": True,
                },
            ),
            Case(
                ("https://012345678901.s3-control.dualstack.amazonaws.com",
                 "ap-south-1a"),
                {
                    "s3_prefix": "012345678901.s3-control.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://012345678901.s3-control.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                {
                    "s3_prefix": "012345678901.s3-control.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://012345678901.s3-control.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                {
                    "s3_prefix": "012345678901.s3-control.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": True,
                },
            ),
            ###
            Case(
                ("https://012345678901.s3-control-fips.amazonaws.com", None),
                {
                    "s3_prefix": "012345678901.s3-control-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": False,
                },
            ),
            Case(
                ("https://012345678901.s3-control-fips.amazonaws.com",
                 "ap-south-1a"),
                {
                    "s3_prefix": "012345678901.s3-control-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://012345678901.s3-control-fips.us-gov-east-1."
                 "amazonaws.com",
                 None),
                {
                    "s3_prefix": "012345678901.s3-control-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://012345678901.s3-control-fips.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                {
                    "s3_prefix": "012345678901.s3-control-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": False,
                },
            ),
            ###
            Case(
                ("https://012345678901.s3-control-fips.dualstack.amazonaws.com",
                 None),
                {
                    "s3_prefix": "012345678901.s3-control-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": True,
                },
            ),
            Case(
                ("https://012345678901.s3-control-fips.dualstack.amazonaws.com",
                 "ap-south-1a"),
                {
                    "s3_prefix": "012345678901.s3-control-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://012345678901.s3-control-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                {
                    "s3_prefix": "012345678901.s3-control-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://012345678901.s3-control-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                {
                    "s3_prefix": "012345678901.s3-control-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": True,
                },
            ),
            ###
            Case(
                ("https://s3-accesspoint.amazonaws.com", None),
                {
                    "s3_prefix": "s3-accesspoint.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-accesspoint.amazonaws.com",
                 "ap-south-1a"),
                {
                    "s3_prefix": "s3-accesspoint.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-accesspoint.us-gov-east-1.amazonaws.com",
                 None),
                {
                    "s3_prefix": "s3-accesspoint.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-accesspoint.us-gov-east-1.amazonaws.com",
                 "cn-northwest-1"),
                {
                    "s3_prefix": "s3-accesspoint.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": False,
                },
            ),
            ###
            Case(
                ("https://s3-accesspoint.dualstack.amazonaws.com",
                 None),
                {
                    "s3_prefix": "s3-accesspoint.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3-accesspoint.dualstack.amazonaws.com",
                 "ap-south-1a"),
                {
                    "s3_prefix": "s3-accesspoint.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3-accesspoint.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                {
                    "s3_prefix": "s3-accesspoint.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3-accesspoint.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                {
                    "s3_prefix": "s3-accesspoint.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": True,
                },
            ),
            ###
            Case(
                ("https://s3-accesspoint-fips.amazonaws.com", None),
                {
                    "s3_prefix": "s3-accesspoint-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-accesspoint-fips.amazonaws.com",
                 "ap-south-1a"),
                {
                    "s3_prefix": "s3-accesspoint-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-accesspoint-fips.us-gov-east-1."
                 "amazonaws.com",
                 None),
                {
                    "s3_prefix": "s3-accesspoint-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": False,
                },
            ),
            Case(
                ("https://s3-accesspoint-fips.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                {
                    "s3_prefix": "s3-accesspoint-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": False,
                },
            ),
            ###
            Case(
                ("https://s3-accesspoint-fips.dualstack.amazonaws.com",
                 None),
                {
                    "s3_prefix": "s3-accesspoint-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": None,
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3-accesspoint-fips.dualstack.amazonaws.com",
                 "ap-south-1a"),
                {
                    "s3_prefix": "s3-accesspoint-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "ap-south-1a",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3-accesspoint-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                {
                    "s3_prefix": "s3-accesspoint-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "us-gov-east-1",
                    "dualstack": True,
                },
            ),
            Case(
                ("https://s3-accesspoint-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                {
                    "s3_prefix": "s3-accesspoint-fips.",
                    "domain_suffix": "amazonaws.com",
                    "region": "cn-northwest-1",
                    "dualstack": True,
                },
            ),
            ###
            Case(
                ("https://my-load-balancer-1234567890.us-west-2.elb."
                 "amazonaws.com", "us-west-2"),
                None,
            ),
        ]

        for case in cases:
            url = BaseURL(*case.args)
            self.assertEqual(url._aws_info, case.result)

    def test_aws_list_buckets_build(self):
        Case = namedtuple("Case", ["args", "result"])
        cases = [
            Case(
                ("https://s3.amazonaws.com", None),
                "https://s3.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3.amazonaws.com", "ap-south-1a"),
                "https://s3.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3.us-gov-east-1.amazonaws.com", None),
                "https://s3.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3.me-south-1.amazonaws.com", "cn-northwest-1"),
                "https://s3.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3.dualstack.amazonaws.com", None),
                "https://s3.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3.dualstack.amazonaws.com", "ap-south-1a"),
                "https://s3.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3.dualstack.us-gov-east-1.amazonaws.com", None),
                "https://s3.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3.dualstack.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://s3.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-accelerate.amazonaws.com", None),
                "https://s3.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accelerate.amazonaws.com", "ap-south-1a"),
                "https://s3.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3-accelerate.us-gov-east-1.amazonaws.com", None),
                "https://s3.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accelerate.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://s3.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-accelerate.dualstack.amazonaws.com", None),
                "https://s3.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accelerate.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://s3.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3-accelerate.dualstack.us-gov-east-1.amazonaws.com",
                 None),
                "https://s3.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accelerate.dualstack.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://s3.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-fips.amazonaws.com", None),
                "https://s3.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-fips.amazonaws.com", "ap-south-1a"),
                "https://s3.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3-fips.us-gov-east-1.amazonaws.com", None),
                "https://s3.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-fips.me-south-1.amazonaws.com", "cn-northwest-1"),
                "https://s3.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-fips.dualstack.amazonaws.com", None),
                "https://s3.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-fips.dualstack.amazonaws.com", "ap-south-1a"),
                "https://s3.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3-fips.dualstack.us-gov-east-1.amazonaws.com", None),
                "https://s3.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-fips.dualstack.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://s3.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-external-1.amazonaws.com", None),
                "https://s3-external-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-us-gov-west-1.amazonaws.com", None),
                "https://s3-us-gov-west-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-fips-us-gov-west-1.amazonaws.com", None),
                "https://s3-fips-us-gov-west-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                 "vpce.amazonaws.com", None),
                "https://bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                "vpce.amazonaws.com/",
            ),
            Case(
                ("https://accesspoint.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                 "vpce.amazonaws.com", None),
                "https://accesspoint.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                "vpce.amazonaws.com/",
            ),
            ###
            Case(
                ("https://012345678901.s3-control.amazonaws.com", None),
                "https://012345678901.s3-control.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control.amazonaws.com",
                 "ap-south-1a"),
                "https://012345678901.s3-control.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control.us-gov-east-1.amazonaws.com",
                 None),
                "https://012345678901.s3-control.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control.us-gov-east-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://012345678901.s3-control.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://012345678901.s3-control.dualstack.amazonaws.com",
                 None),
                "https://012345678901.s3-control.us-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://012345678901.s3-control.ap-south-1a."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://012345678901.s3-control.us-gov-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://012345678901.s3-control.cn-northwest-1."
                "amazonaws.com/",
            ),
            ###
            Case(
                ("https://012345678901.s3-control-fips.amazonaws.com", None),
                "https://012345678901.s3-control-fips.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control-fips.amazonaws.com",
                 "ap-south-1a"),
                "https://012345678901.s3-control-fips.ap-south-1a."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control-fips.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://012345678901.s3-control-fips.us-gov-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control-fips.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://012345678901.s3-control-fips.cn-northwest-1."
                "amazonaws.com/",
            ),
            ###
            Case(
                ("https://012345678901.s3-control-fips.dualstack.amazonaws.com",
                 None),
                "https://012345678901.s3-control-fips.us-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control-fips.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://012345678901.s3-control-fips.ap-south-1a."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://012345678901.s3-control-fips.us-gov-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://012345678901.s3-control-fips.cn-northwest-1."
                "amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-accesspoint.amazonaws.com", None),
                "https://s3.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint.amazonaws.com",
                 "ap-south-1a"),
                "https://s3.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint.us-gov-east-1.amazonaws.com",
                 None),
                "https://s3.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint.us-gov-east-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://s3.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-accesspoint.dualstack.amazonaws.com",
                 None),
                "https://s3.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://s3.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://s3.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://s3.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-accesspoint-fips.amazonaws.com", None),
                "https://s3.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint-fips.amazonaws.com",
                 "ap-south-1a"),
                "https://s3.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint-fips.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://s3.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint-fips.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://s3.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-accesspoint-fips.dualstack.amazonaws.com",
                 None),
                "https://s3.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint-fips.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://s3.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://s3.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://s3.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://my-load-balancer-1234567890.us-west-2.elb."
                 "amazonaws.com", "us-west-2"),
                "https://my-load-balancer-1234567890.us-west-2.elb."
                "amazonaws.com/",
            ),
        ]

        for case in cases:
            base_url = BaseURL(*case.args)
            url = urlunsplit(base_url.build(
                "GET", base_url.region or "us-east-1"))
            self.assertEqual(str(url), case.result)

    def test_aws_bucket_build(self):
        Case = namedtuple("Case", ["args", "result"])
        cases = [
            Case(
                ("https://s3.amazonaws.com", None),
                "https://my-bucket.s3.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3.amazonaws.com", "ap-south-1a"),
                "https://my-bucket.s3.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3.us-gov-east-1.amazonaws.com", None),
                "https://my-bucket.s3.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3.me-south-1.amazonaws.com", "cn-northwest-1"),
                "https://my-bucket.s3.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3.dualstack.amazonaws.com", None),
                "https://my-bucket.s3.dualstack.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3.dualstack.amazonaws.com", "ap-south-1a"),
                "https://my-bucket.s3.dualstack.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3.dualstack.us-gov-east-1.amazonaws.com", None),
                "https://my-bucket.s3.dualstack.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3.dualstack.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3.dualstack.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-accelerate.amazonaws.com", None),
                "https://my-bucket.s3-accelerate.amazonaws.com/",
            ),
            Case(
                ("https://s3-accelerate.amazonaws.com", "ap-south-1a"),
                "https://my-bucket.s3-accelerate.amazonaws.com/",
            ),
            Case(
                ("https://s3-accelerate.us-gov-east-1.amazonaws.com", None),
                "https://my-bucket.s3-accelerate.amazonaws.com/",
            ),
            Case(
                ("https://s3-accelerate.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-accelerate.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-accelerate.dualstack.amazonaws.com", None),
                "https://my-bucket.s3-accelerate.dualstack.amazonaws.com/",
            ),
            Case(
                ("https://s3-accelerate.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.s3-accelerate.dualstack.amazonaws.com/",
            ),
            Case(
                ("https://s3-accelerate.dualstack.us-gov-east-1.amazonaws.com",
                 None),
                "https://my-bucket.s3-accelerate.dualstack.amazonaws.com/",
            ),
            Case(
                ("https://s3-accelerate.dualstack.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-accelerate.dualstack.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-fips.amazonaws.com", None),
                "https://my-bucket.s3-fips.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-fips.amazonaws.com", "ap-south-1a"),
                "https://my-bucket.s3-fips.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3-fips.us-gov-east-1.amazonaws.com", None),
                "https://my-bucket.s3-fips.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-fips.me-south-1.amazonaws.com", "cn-northwest-1"),
                "https://my-bucket.s3-fips.cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-fips.dualstack.amazonaws.com", None),
                "https://my-bucket.s3-fips.dualstack.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-fips.dualstack.amazonaws.com", "ap-south-1a"),
                "https://my-bucket.s3-fips.dualstack.ap-south-1a."
                "amazonaws.com/",
            ),
            Case(
                ("https://s3-fips.dualstack.us-gov-east-1.amazonaws.com", None),
                "https://my-bucket.s3-fips.dualstack.us-gov-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://s3-fips.dualstack.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-fips.dualstack.cn-northwest-1."
                "amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-external-1.amazonaws.com", None),
                "https://my-bucket.s3-external-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-us-gov-west-1.amazonaws.com", None),
                "https://my-bucket.s3-us-gov-west-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-fips-us-gov-west-1.amazonaws.com", None),
                "https://my-bucket.s3-fips-us-gov-west-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                 "vpce.amazonaws.com", None),
                "https://my-bucket.bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                "vpce.amazonaws.com/",
            ),
            Case(
                ("https://accesspoint.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                 "vpce.amazonaws.com", None),
                "https://my-bucket.accesspoint.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                "vpce.amazonaws.com/",
            ),
            ###
            Case(
                ("https://012345678901.s3-control.amazonaws.com", None),
                "https://my-bucket.012345678901.s3-control.us-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.012345678901.s3-control.ap-south-1a."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control.us-gov-east-1.amazonaws.com",
                 None),
                "https://my-bucket.012345678901.s3-control.us-gov-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control.us-gov-east-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.012345678901.s3-control.cn-northwest-1."
                "amazonaws.com/",
            ),
            ###
            Case(
                ("https://012345678901.s3-control.dualstack.amazonaws.com",
                 None),
                "https://my-bucket.012345678901.s3-control.dualstack.us-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.012345678901.s3-control.dualstack."
                "ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://my-bucket.012345678901.s3-control.dualstack."
                "us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.012345678901.s3-control.dualstack."
                "cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://012345678901.s3-control-fips.amazonaws.com", None),
                "https://my-bucket.012345678901.s3-control-fips.us-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control-fips.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.012345678901.s3-control-fips.ap-south-1a."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control-fips.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://my-bucket.012345678901.s3-control-fips.us-gov-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control-fips.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.012345678901.s3-control-fips.cn-northwest-1."
                "amazonaws.com/",
            ),
            ###
            Case(
                ("https://012345678901.s3-control-fips.dualstack.amazonaws.com",
                 None),
                "https://my-bucket.012345678901.s3-control-fips.dualstack."
                "us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control-fips.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.012345678901.s3-control-fips.dualstack."
                "ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://my-bucket.012345678901.s3-control-fips.dualstack."
                "us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://012345678901.s3-control-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.012345678901.s3-control-fips.dualstack."
                "cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-accesspoint.amazonaws.com", None),
                "https://my-bucket.s3-accesspoint.us-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.s3-accesspoint.ap-south-1a.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint.us-gov-east-1.amazonaws.com",
                 None),
                "https://my-bucket.s3-accesspoint.us-gov-east-1.amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint.us-gov-east-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-accesspoint.cn-northwest-1."
                "amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-accesspoint.dualstack.amazonaws.com",
                 None),
                "https://my-bucket.s3-accesspoint.dualstack.us-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.s3-accesspoint.dualstack.ap-south-1a."
                "amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://my-bucket.s3-accesspoint.dualstack.us-gov-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-accesspoint.dualstack.cn-northwest-1."
                "amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-accesspoint-fips.amazonaws.com", None),
                "https://my-bucket.s3-accesspoint-fips.us-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint-fips.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.s3-accesspoint-fips.ap-south-1a."
                "amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint-fips.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://my-bucket.s3-accesspoint-fips.us-gov-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint-fips.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-accesspoint-fips.cn-northwest-1."
                "amazonaws.com/",
            ),
            ###
            Case(
                ("https://s3-accesspoint-fips.dualstack.amazonaws.com",
                 None),
                "https://my-bucket.s3-accesspoint-fips.dualstack.us-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint-fips.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.s3-accesspoint-fips.dualstack.ap-south-1a."
                "amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://my-bucket.s3-accesspoint-fips.dualstack.us-gov-east-1."
                "amazonaws.com/",
            ),
            Case(
                ("https://s3-accesspoint-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-accesspoint-fips.dualstack."
                "cn-northwest-1.amazonaws.com/",
            ),
            ###
            Case(
                ("https://my-load-balancer-1234567890.us-west-2.elb."
                 "amazonaws.com", "us-west-2"),
                "https://my-load-balancer-1234567890.us-west-2.elb."
                "amazonaws.com/my-bucket",
            ),
        ]

        for case in cases:
            base_url = BaseURL(*case.args)
            url = urlunsplit(base_url.build(
                "GET", base_url.region or "us-east-1", bucket_name="my-bucket"))
            self.assertEqual(str(url), case.result)

    def test_aws_object_build(self):
        Case = namedtuple("Case", ["args", "result"])
        cases = [
            Case(
                ("https://s3.amazonaws.com", None),
                "https://my-bucket.s3.us-east-1.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3.amazonaws.com", "ap-south-1a"),
                "https://my-bucket.s3.ap-south-1a.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3.us-gov-east-1.amazonaws.com", None),
                "https://my-bucket.s3.us-gov-east-1.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3.me-south-1.amazonaws.com", "cn-northwest-1"),
                "https://my-bucket.s3.cn-northwest-1.amazonaws.com/"
                "path/to/my/object",
            ),
            ###
            Case(
                ("https://s3.dualstack.amazonaws.com", None),
                "https://my-bucket.s3.dualstack.us-east-1.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3.dualstack.amazonaws.com", "ap-south-1a"),
                "https://my-bucket.s3.dualstack.ap-south-1a.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3.dualstack.us-gov-east-1.amazonaws.com", None),
                "https://my-bucket.s3.dualstack.us-gov-east-1.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3.dualstack.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3.dualstack.cn-northwest-1.amazonaws.com/"
                "path/to/my/object",
            ),
            ###
            Case(
                ("https://s3-accelerate.amazonaws.com", None),
                "https://my-bucket.s3-accelerate.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-accelerate.amazonaws.com", "ap-south-1a"),
                "https://my-bucket.s3-accelerate.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-accelerate.us-gov-east-1.amazonaws.com", None),
                "https://my-bucket.s3-accelerate.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-accelerate.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-accelerate.amazonaws.com/"
                "path/to/my/object",
            ),
            ###
            Case(
                ("https://s3-accelerate.dualstack.amazonaws.com", None),
                "https://my-bucket.s3-accelerate.dualstack.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-accelerate.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.s3-accelerate.dualstack.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-accelerate.dualstack.us-gov-east-1.amazonaws.com",
                 None),
                "https://my-bucket.s3-accelerate.dualstack.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-accelerate.dualstack.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-accelerate.dualstack.amazonaws.com/"
                "path/to/my/object",
            ),
            ###
            Case(
                ("https://s3-fips.amazonaws.com", None),
                "https://my-bucket.s3-fips.us-east-1.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-fips.amazonaws.com", "ap-south-1a"),
                "https://my-bucket.s3-fips.ap-south-1a.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-fips.us-gov-east-1.amazonaws.com", None),
                "https://my-bucket.s3-fips.us-gov-east-1.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-fips.me-south-1.amazonaws.com", "cn-northwest-1"),
                "https://my-bucket.s3-fips.cn-northwest-1.amazonaws.com/"
                "path/to/my/object",
            ),
            ###
            Case(
                ("https://s3-fips.dualstack.amazonaws.com", None),
                "https://my-bucket.s3-fips.dualstack.us-east-1.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-fips.dualstack.amazonaws.com", "ap-south-1a"),
                "https://my-bucket.s3-fips.dualstack.ap-south-1a."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://s3-fips.dualstack.us-gov-east-1.amazonaws.com", None),
                "https://my-bucket.s3-fips.dualstack.us-gov-east-1."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://s3-fips.dualstack.me-south-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-fips.dualstack.cn-northwest-1."
                "amazonaws.com/path/to/my/object",
            ),
            ###
            Case(
                ("https://s3-external-1.amazonaws.com", None),
                "https://my-bucket.s3-external-1.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-us-gov-west-1.amazonaws.com", None),
                "https://my-bucket.s3-us-gov-west-1.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-fips-us-gov-west-1.amazonaws.com", None),
                "https://my-bucket.s3-fips-us-gov-west-1.amazonaws.com/"
                "path/to/my/object",
            ),
            ###
            Case(
                ("https://bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                 "vpce.amazonaws.com", None),
                "https://my-bucket.bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                "vpce.amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://accesspoint.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                 "vpce.amazonaws.com", None),
                "https://my-bucket.accesspoint.vpce-1a2b3c4d-5e6f.s3.us-east-1."
                "vpce.amazonaws.com/path/to/my/object",
            ),
            ###
            Case(
                ("https://012345678901.s3-control.amazonaws.com", None),
                "https://my-bucket.012345678901.s3-control.us-east-1."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://012345678901.s3-control.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.012345678901.s3-control.ap-south-1a."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://012345678901.s3-control.us-gov-east-1.amazonaws.com",
                 None),
                "https://my-bucket.012345678901.s3-control.us-gov-east-1."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://012345678901.s3-control.us-gov-east-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.012345678901.s3-control.cn-northwest-1."
                "amazonaws.com/path/to/my/object",
            ),
            ###
            Case(
                ("https://012345678901.s3-control.dualstack.amazonaws.com",
                 None),
                "https://my-bucket.012345678901.s3-control.dualstack.us-east-1."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://012345678901.s3-control.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.012345678901.s3-control.dualstack."
                "ap-south-1a.amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://012345678901.s3-control.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://my-bucket.012345678901.s3-control.dualstack."
                "us-gov-east-1.amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://012345678901.s3-control.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.012345678901.s3-control.dualstack."
                "cn-northwest-1.amazonaws.com/path/to/my/object",
            ),
            ###
            Case(
                ("https://012345678901.s3-control-fips.amazonaws.com", None),
                "https://my-bucket.012345678901.s3-control-fips.us-east-1."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://012345678901.s3-control-fips.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.012345678901.s3-control-fips.ap-south-1a."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://012345678901.s3-control-fips.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://my-bucket.012345678901.s3-control-fips.us-gov-east-1."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://012345678901.s3-control-fips.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.012345678901.s3-control-fips.cn-northwest-1."
                "amazonaws.com/path/to/my/object",
            ),
            ###
            Case(
                ("https://012345678901.s3-control-fips.dualstack.amazonaws.com",
                 None),
                "https://my-bucket.012345678901.s3-control-fips.dualstack."
                "us-east-1.amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://012345678901.s3-control-fips.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.012345678901.s3-control-fips.dualstack."
                "ap-south-1a.amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://012345678901.s3-control-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://my-bucket.012345678901.s3-control-fips.dualstack."
                "us-gov-east-1.amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://012345678901.s3-control-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.012345678901.s3-control-fips.dualstack."
                "cn-northwest-1.amazonaws.com/path/to/my/object",
            ),
            ###
            Case(
                ("https://s3-accesspoint.amazonaws.com", None),
                "https://my-bucket.s3-accesspoint.us-east-1.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-accesspoint.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.s3-accesspoint.ap-south-1a.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-accesspoint.us-gov-east-1.amazonaws.com",
                 None),
                "https://my-bucket.s3-accesspoint.us-gov-east-1.amazonaws.com/"
                "path/to/my/object",
            ),
            Case(
                ("https://s3-accesspoint.us-gov-east-1.amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-accesspoint.cn-northwest-1."
                "amazonaws.com/path/to/my/object",
            ),
            ###
            Case(
                ("https://s3-accesspoint.dualstack.amazonaws.com",
                 None),
                "https://my-bucket.s3-accesspoint.dualstack.us-east-1."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://s3-accesspoint.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.s3-accesspoint.dualstack.ap-south-1a."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://s3-accesspoint.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://my-bucket.s3-accesspoint.dualstack.us-gov-east-1."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://s3-accesspoint.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-accesspoint.dualstack.cn-northwest-1."
                "amazonaws.com/path/to/my/object",
            ),
            ###
            Case(
                ("https://s3-accesspoint-fips.amazonaws.com", None),
                "https://my-bucket.s3-accesspoint-fips.us-east-1."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://s3-accesspoint-fips.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.s3-accesspoint-fips.ap-south-1a."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://s3-accesspoint-fips.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://my-bucket.s3-accesspoint-fips.us-gov-east-1."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://s3-accesspoint-fips.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-accesspoint-fips.cn-northwest-1."
                "amazonaws.com/path/to/my/object",
            ),
            ###
            Case(
                ("https://s3-accesspoint-fips.dualstack.amazonaws.com",
                 None),
                "https://my-bucket.s3-accesspoint-fips.dualstack.us-east-1."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://s3-accesspoint-fips.dualstack.amazonaws.com",
                 "ap-south-1a"),
                "https://my-bucket.s3-accesspoint-fips.dualstack.ap-south-1a."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://s3-accesspoint-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 None),
                "https://my-bucket.s3-accesspoint-fips.dualstack.us-gov-east-1."
                "amazonaws.com/path/to/my/object",
            ),
            Case(
                ("https://s3-accesspoint-fips.dualstack.us-gov-east-1."
                 "amazonaws.com",
                 "cn-northwest-1"),
                "https://my-bucket.s3-accesspoint-fips.dualstack."
                "cn-northwest-1.amazonaws.com/path/to/my/object",
            ),
            ###
            Case(
                ("https://my-load-balancer-1234567890.us-west-2.elb."
                 "amazonaws.com", "us-west-2"),
                "https://my-load-balancer-1234567890.us-west-2.elb."
                "amazonaws.com/my-bucket/path/to/my/object",
            ),
        ]

        for case in cases:
            base_url = BaseURL(*case.args)
            url = urlunsplit(base_url.build(
                "GET", base_url.region or "us-east-1",
                bucket_name="my-bucket", object_name="path/to/my/object"))
            self.assertEqual(str(url), case.result)
