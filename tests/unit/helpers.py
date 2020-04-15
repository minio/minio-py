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
