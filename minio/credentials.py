# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C) 2016, 2017 Minio, Inc.
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
minio.credentials
~~~~~~~~~~~~~~~

This module contains :class:` credentials` implementation.

:copyright: (c) 2016, 2017 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from abc import ABCMeta, abstractmethod

import os, json, urllib3, datetime
import ConfigParser

from .error import MinioError


# credentials class
class credentials(object):

    def __init__(self, access_key, secret_key, session_token):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token

# credentials_provider class
class credentials_provider(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def is_expired(): pass

    @abstractmethod
    def retrieve(): pass 

    def __init__(self):
        self._force_refresh = False
        self._cached_creds = None

    def get(self):
        if self._force_refresh or self.is_expired():
            self._cached_creds = self.retrieve()
            self._force_refresh = False
        return self._cached_creds

    def expire(self):
        self._force_refresh = True

# static_credentials
class static_credentials(credentials_provider):

    def __init__(self, access_key, secret_key, session_token=""):
        super(static_credentials, self).__init__()
        self._access_key = access_key
        self._secret_key = secret_key
        if session_token == None:
            session_token = ""
        self._session_token = session_token

    def retrieve(self):
        return credentials(self._access_key,
            self._secret_key,
            self._session_token)

    def is_expired(self):
        return True

# env_aws_credentials
class env_aws_credentials(credentials_provider):

    def __init__(self):
        super(env_aws_credentials, self).__init__()
        self._retrieved = False

    def is_expired(self):
        return not self._retrieved

    def retrieve(self):
        self._retrieved = False
        access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        if access_key == '' or access_key is None:
            access_key = os.environ.get('AWS_ACCESS_KEY')
        secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        if secret_key == '' or secret_key is None:
            secret_key = os.environ['AWS_SECRET_KEY']
        self._retrieved = True
        return credentials(access_key, secret_key, "")

# env_minio_credentials
class env_minio_credentials(credentials_provider):

    def __init__(self):
        super(env_minio_credentials, self).__init__()
        self._retrieved = False

    def is_expired(self):
        return not self._retrieved

    def retrieve(self):
        self._retrieved = False
        access_key = os.environ.get('MINIO_ACCESS_KEY')
        secret_key = os.environ.get('MINIO_SECRET_KEY')
        self._retrieved = True
        return credentials(access_key, secret_key, '')

# file_minio_credentials
class file_minio_credentials(credentials_provider):

    def __init__(self, alias, filename=''):
        super(file_minio_credentials, self).__init__()
        self._retrieved = False
        self._filename = filename 
        self._alias = alias
        if self._filename == '' or self._filename is None:
            self._filename = os.environ.get('MINIO_SHARED_CREDENTIALS_FILE')
            if self._filename == '' or self._filename is None:
                homeDir = os.getenv('HOME')
                self._filename = os.path.join(homeDir, '.mc', 'config.json')
        if self._alias == '' or self._alias is None:
            self._alias = os.environ.get('MINIO_ALIAS')
            if self._alias == '' or self._alias is None:
                self._alias = 'play'

    def is_expired(self):
        return not self._retrieved

    def retrieve(self):
        self._retrieved = False
        f = open(self._filename, 'r')
        doc = json.load(f)
        creds = doc['hosts'][self._alias]
        access_key = creds['accessKey']
        secret_key = creds['secretKey']
        self._retrieved = True
        return credentials(access_key, secret_key, '')

# file_aws_credentials
class file_aws_credentials(credentials_provider):

    def __init__(self, profile='', filename=''):
        super(file_aws_credentials, self).__init__()
        self._retrieved = False
        self._filename = filename 
        self._profile = profile
        if self._filename == '' or self._filename is None:
            self._filename = os.environ.get('AWS_SHARED_CREDENTIALS_FILE')
            if self._filename == '' or self._filename is None:
                homeDir = os.getenv('HOME')
                self._filename = os.path.join(homeDir, '.aws', 'credentials')
        if self._profile == '' or self._profile is None:
            self._profile = os.environ.get('AWS_PROFILE')
            if self._profile == '' or self._profile is None:
                self._profile = 'default'

    def is_expired(self):
        return not self._retrieved

    def retrieve(self):
        self._retrieved = False
        ini_config = ConfigParser.ConfigParser()
        ini_config.read(self._filename)
        access_key = secret_key = session_token = ''
        try:
            access_key = ini_config.get(self._profile, 'aws_access_key_id')
            secret_key = ini_config.get(self._profile, 'aws_secret_access_key')
            session_token = ini_config.get(self._profile, 'aws_session_token')
        except:
            pass
        self._retrieved = True
        return credentials(access_key, secret_key, session_token)

class IAM_ResponseError(MinioError):
    """
    IAM_ResponseError is raised when IAM webservice returns an error.
    """
    pass

# iam_aws_credentials
class iam_aws_credentials(credentials_provider):

    iam_security_creds_path = '/latest/meta-data/iam/security-credentials'

    def __init__(self, endpoint='', role_name='', timeout=None):
        super(iam_aws_credentials, self).__init__()
        if endpoint == '' or endpoint == None:
            # endpoint = 'http://169.254.169.254'
            endpoint = 'http://127.0.0.1:8080'
        self._endpoint = endpoint
        self._role_name = role_name
        self._expiry_window = None
        self._conn_timeout = urllib3.Timeout.DEFAULT_TIMEOUT if not timeout \
                else urllib3.Timeout(timeout)
        self._http = urllib3.PoolManager(
                timeout=self._conn_timeout,
                # cert_reqs='CERT_REQUIRED',
                # ca_certs=certificate_bundle,
                retries=urllib3.Retry(
                    total=5,
                    backoff_factor=0.2,
                    status_forcelist=[500, 502, 503, 504]
                    )
                )

    def request_cred_list(self):
        url = self._endpoint + self.iam_security_creds_path
        response = self._http.urlopen('GET', url)
        if response.status != 200:
            raise ResponseError(method, path, response.status).get_exception()
        creds = response.data.split('\n')
        return creds

    def request_cred(self, creds_name):
        method = 'GET'
        url = self._endpoint + self.iam_security_creds_path + "/" + creds_name
        response = self._http.urlopen(method, url)
        print(url, response.status)
        if response.status != 200:
            raise IAM_ResponseError().get_exception()
        respCreds = json.loads(response.data)
        if respCreds['Code'] != 'Success':
            raise ResponseError(response, method, url).get_exception()
        return respCreds

    def is_expired(self):
        if self._expiry_window is None:
            return True
        return self._expiry_window < datetime.datetime.now()

    def retrieve(self):
        creds_list = self.request_cred_list()
        role_creds = self.request_cred(self._role_name)
        access_key = role_creds['AccessKeyId']
        secret_key = role_creds['SecretAccessKey']
        session_token = role_creds['Token']
        parsed_expiration = datetime.datetime.strptime(role_creds['Expiration'], '%Y-%m-%dT%H:%M:%SZ')
        self._expiry_window = parsed_expiration
        return credentials(access_key, secret_key, session_token)

