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

import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="googleapis-storage-testbench",
    version="0.22.0",
    author="Google LLC",
    author_email="googleapis-packages@google.com",
    description="A testbench for Google Cloud Storage client libraries",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/googleapis/storage-testbench",
    project_urls={
        "Bug Tracker": "https://github.com/googleapis/storage-testbench/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache-2.0",
        "Operating System :: OS Independent",
    ],
    packages=[
        "google/storage/v2",
        "google/iam/v1",
        "testbench",
        "testbench/servers",
        "gcs",
    ],
    python_requires=">=3.6",
    install_requires=[
        "grpcio==1.46.1",
        "googleapis-common-protos==1.56.0",
        "protobuf==4.21.0",
        "flask==2.1.2",
        "requests-toolbelt==0.9.1",
        "scalpl==0.4.2",
        "crc32c==2.2",
        "gunicorn==20.1.0",
    ],
)
