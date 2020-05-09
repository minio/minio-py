# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2019 MinIO, Inc.
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
:copyright: (c) 2019 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.
"""

__title__ = 'minio-py'
__author__ = 'MinIO, Inc.'
__version__ = '0.1.0'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright 2019 MinIO, Inc.'

# pylint: disable=unused-import
from .errors import SelectCRCValidationError, SelectMessageError
from .helpers import (byte_int, calculate_crc,  # pylint: disable=unused-import
                      validate_crc)
from .options import (CSVInput, CSVOutput,  # pylint: disable=unused-import
                      InputSerialization, JSONInput, JSONOutput,
                      OutputSerialization, ParquetInput, RequestProgress,
                      SelectObjectOptions)
from .reader import SelectObjectReader  # pylint: disable=unused-import
