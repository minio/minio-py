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
from minio.minio import Minio

__author__ = 'minio'

client = Minio('https://s3.amazonaws.com')

# Drop incomplete uploads for a given bucket and key
client.drop_incomplete_upload('my_bucket', 'my_key')

# Drop incomplete uploads for the entire bucket
client.drop_all_incomplete_uploads('my_bucket')
