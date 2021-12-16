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

"""Tests for the Rewrite helper (see gcs/rewrite.py)."""

import json
import unittest
import unittest.mock

from werkzeug.test import create_environ
from werkzeug.wrappers import Request

import gcs
import testbench


class TestRewrite(unittest.TestCase):
    def test_rewrite_rest(self):
        request = testbench.common.FakeRequest(
            args={}, data=json.dumps({"name": "bucket"})
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        bucket = bucket.metadata
        data = json.dumps({"name": "a"})
        environ = create_environ(
            base_url="http://localhost:8080",
            query_string={"maxBytesRewrittenPerCall": 512 * 1024},
        )
        upload = gcs.rewrite.Rewrite.init_rest(
            Request(environ),
            "source-bucket",
            "source-object",
            "destination-bucket",
            "destination-object",
        )
        self.assertEqual(512 * 1024, upload.max_bytes_rewritten_per_call)


if __name__ == "__main__":
    unittest.main()
