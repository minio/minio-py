# -*- coding: utf-8 -*-
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

class InvalidBucketError(Exception):
    pass

class InvalidArgumentError(Exception):
    pass

class ResponseError(Exception):
    def __init__(self, code, message, request_id, host_id, resource, xml=None,
                 **kwargs):
        super(ResponseError, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.request_id = request_id
        self.host_id = host_id
        self.resource = resource
        self.xml = xml

    def __str__(self):
        return 'ResponseError: code: {0}, message: {1}, request_id: {2},' \
            'host_id: {3}, resource: {4}, xml: {5}'.format(self.code,
                                                           self.message,
                                                           self.request_id,
                                                           self.host_id,
                                                           self.resource,
                                                           self.xml)
