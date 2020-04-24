# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2020 MinIO, Inc.
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

"""Credential module."""

from .credentials import Credentials  # pylint: disable=unused-import
from .credentials import Value  # pylint: disable=unused-import
from .providers import AssumeRoleProvider  # pylint: disable=unused-import
from .providers import Chain  # pylint: disable=unused-import
from .providers import EnvAWS  # pylint: disable=unused-import
from .providers import EnvMinio  # pylint: disable=unused-import
from .providers import FileAWSCredentials  # pylint: disable=unused-import
from .providers import FileMinioClient  # pylint: disable=unused-import
from .providers import IAMProvider  # pylint: disable=unused-import
from .providers import Static  # pylint: disable=unused-import
