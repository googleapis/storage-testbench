#!/usr/bin/env bash
#
# Copyright 2024 Google LLC
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

set -euo pipefail

if [[ $# -eq 0 ]]; then
  readonly GOOGLEAPIS_ROOT=".googleapis"
elif [[ $# -eq 1 ]]; then
  readonly GOOGLEAPIS_ROOT="$1"
else
  echo "Usage: $(basename "$0") [googleapis-root-directory]"
  exit 1
fi

readonly PROGRAM_PATH="$0"
readonly INPUTS=(
    google/iam/v1/iam_policy.proto
    google/iam/v1/options.proto
    google/iam/v1/policy.proto
    google/storage/v2/storage.proto
)
readonly INPUTS

if [[ ! -d "${GOOGLEAPIS_ROOT}" ]]; then
  git clone https://github.com/googleapis/googleapis.git "${GOOGLEAPIS_ROOT}"
else
  git -C "${GOOGLEAPIS_ROOT}" clean -f -d -x
  git -C "${GOOGLEAPIS_ROOT}" restore google/storage
  git -C "${GOOGLEAPIS_ROOT}" checkout master
  git -C "${GOOGLEAPIS_ROOT}" pull
fi
env -C "${GOOGLEAPIS_ROOT}" patch -p1 <$PWD/bidi-streaming-read.patch
env -C "${GOOGLEAPIS_ROOT}" patch -p1 <$PWD/bidi-appendable-write.patch

for input in "${INPUTS[@]}"; do
  python -m grpc_tools.protoc -I"${GOOGLEAPIS_ROOT}" \
      --python_out=. --grpc_python_out=. "${GOOGLEAPIS_ROOT}/${input}"
done

mapfile -t OUTPUTS < <(find google -name '*.py' -print)
readonly OUTPUTS

for output in "${OUTPUTS[@]}"; do
  (
    sed -n '1,1p' "${output}"
    sed -n '3,/^$/p' "${PROGRAM_PATH}"
    sed -n '2,$p' "${output}"
  ) | sponge "${output}"
done
