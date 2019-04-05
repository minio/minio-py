#!/usr/bin/env bash
#
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C) 2017 MinIO, Inc.
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

# Flag to set python2 / python3
py2flag=0

build() {
    echo "building..."
    cd ../
    if [[ $py2flag = 1 ]]; then
	python2 setup.py install --prefix ${HOME}/.local
    else
	python3 setup.py install --prefix ${HOME}/.local
    fi
    cd tests
}

run() {
    echo "running..."
    if [[ $py2flag = 1 ]]; then
	python2 ./functional/tests.py
    else
	python3 ./functional/tests.py
    fi
}

main () {
    if [[ $# -lt 1 ]]; then
	echo "Usage: ./functional_test.sh [py2|py3|all]"
    fi
    # Build test file binary
    if [[ $1 == "py2" || $1 == "all" ]]; then
	py2flag=1
	echo "Running python2 tests..."
	build
	run
    fi
    if [[ $1 == "py3" || $1 == "all" ]]; then
	py2flag=0
	echo "Running python3 tests..."
	build
	run
    fi

}

# invoke the script
# Move to the directory which contains this script and invoke it
cd $(dirname $(realpath $0)) ; \
main "$@"
