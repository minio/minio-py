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
import os

__author__ = 'minio'

import json


class Credentials(object):
    def __init__(self, json_file=None):
        if json_file is None:
            json_file = os.getenv('HOME') + '/credentials.json'
        with open(json_file) as json_file:
            self._json = json.load(json_file)

    def url(self):
        return self._json['host']

    def access_key(self):
        if 'accesskey' in self._json:
            return self._json['accesskey']
        return None

    def secret_key(self):
        if 'secretkey' in self._json:
            return self._json['secretkey']
        return None
