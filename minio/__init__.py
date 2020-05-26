# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016, 2017 MinIO, Inc.
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
minio - MinIO Python Library for Amazon S3 Compatible Cloud Storage
~~~~~~~~~~~~~~~~~~~~~

   >>> import minio
   >>> minio = Minio('https://s3.amazonaws.com')
   >>> for bucket in minio.list_buckets():
   ...     print(bucket.name)

:copyright: (c) 2015, 2016, 2017 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.
"""

__title__ = 'minio-py'
__author__ = 'MinIO, Inc.'
__version__ = '6.0.0'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright 2015, 2016, 2017, 2018, 2019, 2020 MinIO, Inc.'

from .api import Minio  # pylint: disable=unused-import
from .copy_conditions import CopyConditions  # pylint: disable=unused-import
from .definitions import Bucket, Object  # pylint: disable=unused-import
from .error import ResponseError  # pylint: disable=unused-import
from .post_policy import PostPolicy  # pylint: disable=unused-import
