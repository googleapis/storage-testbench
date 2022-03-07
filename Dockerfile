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
FROM python:3.10@sha256:c90e15c86e2ebe71244a2a51bc7f094554422c159ce309a6faadb6debd5a6df0

EXPOSE 9000
WORKDIR /opt/storage-testbench

COPY . /opt/storage-testbench/

RUN python3 -m pip install -e .

CMD ["gunicorn", \
      "--bind", "0.0.0.0:9000", \
      "--worker-class", "sync", \
      "--threads", "10", \
      "--access-logfile", "-", \
      "testbench:run()"]
