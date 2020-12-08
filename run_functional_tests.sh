#!/usr/bin/env bash
#
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C) 2020 MinIO, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

function run_minio_server() {
    if [ -f tests/functional/minio ]; then
        rm -f tests/functional/minio
    fi
    wget --quiet --output-document tests/functional/minio https://dl.min.io/server/minio/release/linux-amd64/minio
    chmod +x tests/functional/minio

    export MINIO_ACCESS_KEY=minio
    export MINIO_SECRET_KEY=minio123
    export MINIO_KMS_KES_ENDPOINT=https://play.min.io:7373
    export MINIO_KMS_KES_KEY_FILE=tests/functional/play.min.io.kes.root.key
    export MINIO_KMS_KES_CERT_FILE=tests/functional/play.min.io.kes.root.cert
    export MINIO_KMS_KES_KEY_NAME=my-minio-key
    export MINIO_NOTIFY_WEBHOOK_ENABLE_miniopytest=on
    export MINIO_NOTIFY_WEBHOOK_ENDPOINT_miniopytest=http://example.org/
    export SQS_ARN="arn:minio:sqs::miniopytest:webhook"
    tests/functional/minio server --config-dir tests/functional/.cfg tests/functional/.d{1...4} >tests/functional/minio.log 2>&1 &
}

run_minio_server
sleep 3

pip install --user .
SECRET_KEY=minio123 ACCESS_KEY=minio SERVER_ENDPOINT=localhost:9000 ENABLE_HTTPS=0 MINT_MODE=full PYTHONPATH=$PWD python tests/functional/tests.py
pkill -9 minio
