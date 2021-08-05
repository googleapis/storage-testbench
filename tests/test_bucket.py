#!/usr/bin/env python3
#
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

"""Tests for the Bucket class (see gcs/bucket.py)."""

import json
import unittest

from google.cloud.storage_v1.proto import storage_pb2 as storage_pb2
from google.cloud.storage_v1.proto.storage_resources_pb2 import CommonEnums
from google.protobuf import json_format

import gcs
import testbench


class TestBucket(unittest.TestCase):
    def test_init_simple(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket"}),
        )
        bucket, projection = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(bucket.metadata.name, "bucket")

    def test_init_validates_names(self):
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "short.names.for.domain.buckets.example.com"}),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.assertEqual(
            bucket.metadata.name, "short.names.for.domain.buckets.example.com"
        )
        invalid_names = [
            "goog-is-not-a-valid-prefix",
            "hiding-google-is-not-valid",
            "hiding-g00gl3-is-not-valid",
            "name-too-long-" + ("a" * 63),
            (".a" * 64) + ".part-too-long.com",
            ("a" * 222) + ".domain-name-too-long.com",
        ]
        for name in invalid_names:
            request = testbench.common.FakeRequest(
                args={},
                data=json.dumps({"name": "goog-is-not-a-valid-prefix"}),
            )
            with self.assertRaises(testbench.error.RestException) as rest:
                bucket, _ = gcs.bucket.Bucket.init(request, None)
            self.assertEqual(rest.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
