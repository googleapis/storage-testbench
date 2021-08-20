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

"""Unit test for the root paths in emulator.py."""

import os
import unittest

import emulator


class TestEmulatorRoot(unittest.TestCase):
    def setUp(self):
        emulator.db.clear()
        self.client = emulator.server.test_client()
        # Avoid magic buckets in the test
        os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)

    def test_root(self):
        response = self.client.get("/")
        self.assertEqual(response.data, b"OK")

    def test_raise_default(self):
        response = self.client.get("/raise_error", query_string={"msg": "test-only"})
        self.assertNotEqual(response.status_code, 200)
        self.assertIn("test-only", response.data.decode("utf-8"))

    def test_raise_type_error(self):
        response = self.client.get(
            "/raise_error", query_string={"etype": "type", "msg": "test-only"}
        )
        self.assertNotEqual(response.status_code, 200)
        self.assertIn("test-only", response.data.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
