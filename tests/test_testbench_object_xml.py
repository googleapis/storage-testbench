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

"""Unit test for Object XML operations in the testbench."""

import json
import os
import unittest

from testbench import rest_server


class TestTestbenchObjectXML(unittest.TestCase):
    def setUp(self):
        rest_server.db.clear()
        rest_server.server.config["PREFERRED_URL_SCHEME"] = "https"
        rest_server.server.config["SERVER_NAME"] = "storage.googleapis.com"
        rest_server.root.config["PREFERRED_URL_SCHEME"] = "https"
        rest_server.root.config["SERVER_NAME"] = "storage.googleapis.com"
        self.client = rest_server.server.test_client(allow_subdomain_redirects=True)
        # Avoid magic buckets in the test
        os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)

    def test_object_xml_put_get_with_subdomain(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.put(
            "/fox.txt",
            base_url="https://bucket-name.storage.googleapis.com",
            content_type="text/plain",
            data="The quick brown fox jumps over the lazy dog",
        )
        self.assertEqual(response.status_code, 200, msg=response.data)

        response = self.client.get(
            "/fox.txt", base_url="https://bucket-name.storage.googleapis.com"
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertEqual(response.data, b"The quick brown fox jumps over the lazy dog")

    def test_object_xml_put_get_with_bucket(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.put(
            "/bucket-name/fox.txt",
            content_type="text/plain",
            data="The quick brown fox jumps over the lazy dog",
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.get("/bucket-name/fox.txt")
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertEqual(response.data, b"The quick brown fox jumps over the lazy dog")


if __name__ == "__main__":
    unittest.main()
