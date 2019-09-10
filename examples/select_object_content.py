# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
#  2019 MinIO, Inc.
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


from minio import Minio
from minio.error import ResponseError
from minio.select.errors import SelectCRCValidationError, SelectMessageError
from minio.select.options import (SelectObjectOptions, CSVInput,
                                  JSONInput, RequestProgress,
                                  ParquetInput, InputSerialization,
                                  OutputSerialization, CSVOutput,
                                  JsonOutput)

client = Minio('s3.amazonaws.com',
               access_key='YOUR-ACCESSKEY',
               secret_key='YOUR-SECRETKEY')

options = SelectObjectOptions(
    expression="select * from s3object",
    input_serialization=InputSerialization(
        compression_type="NONE",
        csv=CSVInput(FileHeaderInfo="USE",
                     RecordDelimiter="\n",
                     FieldDelimiter=",",
                     QuoteCharacter='"',
                     QuoteEscapeCharacter='"',
                     Comments="#",
                     AllowQuotedRecordDelimiter="FALSE",
                     ),
        # If input is JSON
        # json=JSONInput(Type="DOCUMENT",)
        ),

    output_serialization=OutputSerialization(
        csv=CSVOutput(QuoteFields="ASNEEDED",
                      RecordDelimiter="\n",
                      FieldDelimiter=",",
                      QuoteCharacter='"',
                      QuoteEscapeCharacter='"',)

        # json = JsonOutput(
        #     RecordDelimiter="\n",
        #     )
        ),
    request_progress=RequestProgress(
        enabled="False"
        )
    )

try:
    data = client.select_object_content('your-bucket', 'your-object', options)

    # Get the records
    with open('my-record-file', 'w') as record_data:
        for d in data.stream(10*1024):
            record_data.write(d)

    # Get the stats
    print(data.stats())

except SelectMessageError as err:
    print(err)

except SelectCRCValidationError as err:
    print(err)

except ResponseError as err:
    print(err)
