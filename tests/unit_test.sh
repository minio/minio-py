#!/usr/bin/env bash
#!/usr/bin/expect -f
#
#  Minio Cloud Storage, (C) 2017 Minio, Inc.
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

#Make sure following packages are installed on your computer:
#pip install nosetests
#pip install mock
#pip3 install nosetests
#pip3 install mock

echo "Running unit tests on python2... " && nosetests 
echo "Running unit tests on python3... " && nosetests3 
