# Copyright 2021 Google LLC
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
FROM python:3.12@sha256:cdbf01c1193924245582e3484d8de0c9d9a08b411a0e0a1217ac76136b18aa43

EXPOSE 9000
WORKDIR /opt/storage-testbench

COPY . /opt/storage-testbench/

RUN python3 -m pip install -e .

CMD ["python3", \
      "testbench_run.py", \
      "0.0.0.0", \
      "9000", \
      "10"]
