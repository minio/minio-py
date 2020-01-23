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

import os
import configparser

from .credentials import Provider, Value

class FileAWSCredentials(Provider):
    def __init__(self, filename=None, profile=None, retrieved=False):
        super(Provider, self).__init__()
        self._filename = filename
        self._profile = profile
        self._retrieved = retrieved

    def retrieve(self):

        if self._filename == "" or self._filename is None:
            self._filename = os.environ.get('AWS_SHARED_CREDENTIALS_FILE')
            if self._filename == "" or self._filename is None:
                home_dir = os.environ.get('HOME')
                self._filename = os.path.join(home_dir, '.aws', 'credentials')

        if self._profile == "" or self._profile is None:
            self._profile = os.environ.get('AWS_PROFILE')
            if self._profile == "" or self._profile is None:
                self._profile = 'default'

        self._retrieved = False
        ini_profile = configparser.ConfigParser()
        ini_profile.read(self._filename)
        access_key = secret = session_token = ''
        try:
            access_key = ini_profile.get(self._profile, 'aws_access_key_id')
            secret = ini_profile.get(self._profile, 'aws_secret_access_key')
            session_token = ini_profile.get(self._profile, 'aws_session_token')
        except:
            pass

        if access_key == '' or secret == '':
            return Value()

        self._retrieved = True
        return Value(
            access_key=access_key,
            secret_key=secret,
            session_token=session_token)

    def is_expired(self):
        return not self._retrieved
