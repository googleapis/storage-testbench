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

"""Unit test for "retry" (should be "fault injection") operations in emulator.py."""

import json
import os
import re
import unittest
from unittest.mock import MagicMock, patch

import emulator
import testbench

UPLOAD_QUANTUM = 256 * 1024


class TestEmulatorRetry(unittest.TestCase):
    def setUp(self):
        emulator.db.clear()
        self.client = emulator.server.test_client()
        # Avoid magic buckets in the test
        os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)

    def test_root(self):
        response = self.client.get("/")
        self.assertEqual(response.data, b"OK")

    def test_retry_test_crud(self):
        self.assertIn("storage.buckets.list", emulator.db.supported_methods)
        response = self.client.post(
            "/retry_test",
            data=json.dumps({"instructions": {"storage.buckets.list": ["return-429"]}}),
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        create_rest = json.loads(response.data)
        self.assertIn("id", create_rest)

        response = self.client.get("/retry_test/" + create_rest.get("id"))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(get_rest, create_rest)

        response = self.client.get("/retry_tests")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        list_rest = json.loads(response.data)
        ids = [test.get("id") for test in list_rest.get("retry_test", [])]
        self.assertEqual(ids, [create_rest.get("id")], msg=response.data)

        response = self.client.delete("/retry_test/" + create_rest.get("id"))
        self.assertEqual(response.status_code, 200)
        # Once deleted, getting the test should fail.
        response = self.client.get("/retry_test/" + create_rest.get("id"))
        self.assertEqual(response.status_code, 404)

    def test_retry_test_create_invalid(self):
        response = self.client.post("/retry_test", data=json.dumps({}))
        self.assertEqual(response.status_code, 400)

    def test_retry_test_get_notfound(self):
        response = self.client.get("/retry_test/invalid-id")
        self.assertEqual(response.status_code, 404)

    def test_retry_test_return_error(self):
        response = self.client.post(
            "/retry_test",
            data=json.dumps({"instructions": {"storage.buckets.list": ["return-429"]}}),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        create_rest = json.loads(response.data)
        self.assertIn("id", create_rest)

        list_response = self.client.get(
            "/storage/v1/b",
            query_string={"project": "test-project-unused"},
            headers={"x-retry-test-id": create_rest.get("id")},
        )
        self.assertEqual(list_response.status_code, 429, msg=list_response.data)

    @staticmethod
    def _create_block(desired_kib):
        line = "A" * 127 + "\n"
        return int(desired_kib / len(line)) * line

    def test_retry_test_return_reset_connection(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)
        # Use the XML API to inject an object with some data.
        media = self._create_block(256)
        response = self.client.put(
            "/bucket-name/256k.txt",
            content_type="text/plain",
            data=media,
        )
        self.assertEqual(response.status_code, 200)

        # Setup a failure for reading back the object.
        response = self.client.post(
            "/retry_test",
            data=json.dumps(
                {"instructions": {"storage.objects.get": ["return-reset-connection"]}}
            ),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        create_rest = json.loads(response.data)
        self.assertIn("id", create_rest)
        id = create_rest.get("id")

        mock_exit = MagicMock(name="exit", side_effect=Exception("sys.exit called"))
        with patch("sys.exit", mock_exit):
            response = self.client.get(
                "/storage/v1/b/bucket-name/o/256k.txt",
                query_string={"alt": "media"},
                headers={"x-retry-test-id": id},
            )
        self.assertEqual(response.status_code, 500)
        error = json.loads(response.data)
        self.assertIn("sys.exit called", error.get("message"))

    def test_retry_test_return_broken_stream(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)
        # Use the XML API to inject an object with some data.
        media = self._create_block(256)
        response = self.client.put(
            "/bucket-name/256k.txt",
            content_type="text/plain",
            data=media,
        )
        self.assertEqual(response.status_code, 200)

        # Setup a failure for reading back the object.
        response = self.client.post(
            "/retry_test",
            data=json.dumps(
                {"instructions": {"storage.objects.get": ["return-broken-stream"]}}
            ),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        create_rest = json.loads(response.data)
        self.assertIn("id", create_rest)
        id = create_rest.get("id")

        mock_exit = MagicMock(name="exit", side_effect=Exception("sys.exit called"))
        response = self.client.get(
            "/storage/v1/b/bucket-name/o/256k.txt",
            query_string={"alt": "media"},
            headers={"x-retry-test-id": id},
        )
        with patch("sys.exit", mock_exit):
            with self.assertRaises(Exception) as ex:
                _ = len(response.data)
        self.assertIn("sys.exit called", ex.exception.args)

    def test_retry_test_return_error_after_bytes(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)
        # Use the XML API to inject an object with some data.
        media = self._create_block(256)
        response = self.client.put(
            "/bucket-name/256k.txt",
            content_type="text/plain",
            data=media,
        )
        self.assertEqual(response.status_code, 200)

        # Setup a failure for reading back the object.
        response = self.client.post(
            "/retry_test",
            data=json.dumps(
                {"instructions": {"storage.objects.insert": ["return-504-after-256K"]}}
            ),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        create_rest = json.loads(response.data)
        self.assertIn("id", create_rest)
        id = create_rest.get("id")

        response = self.client.post(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"uploadType": "resumable", "name": "will-fail"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        location = response.headers.get("location")
        self.assertIn("upload_id=", location)
        match = re.search("[&?]upload_id=([^&]+)", location)
        self.assertIsNotNone(match, msg=location)
        upload_id = match.group(1)

        chunk = self._create_block(UPLOAD_QUANTUM)
        self.assertEqual(len(chunk), UPLOAD_QUANTUM)

        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={
                "content-range": "bytes 0-{len:d}/*".format(len=UPLOAD_QUANTUM - 1),
                "x-retry-test-id": id,
            },
            data=chunk,
        )
        self.assertEqual(response.status_code, 308, msg=response.data)
        self.assertIn("range", response.headers)
        self.assertEqual(
            response.headers.get("range"), "bytes=0-%d" % (UPLOAD_QUANTUM - 1)
        )

        response = self.client.put(
            "/upload/storage/v1/b/bucket-name/o",
            query_string={"upload_id": upload_id},
            headers={
                "content-range": "bytes {beg:d}-{end:d}/*".format(
                    beg=UPLOAD_QUANTUM, end=2 * UPLOAD_QUANTUM - 1
                ),
                "x-retry-test-id": id,
            },
            data=chunk,
        )
        self.assertEqual(response.status_code, 504, msg=response.data)


if __name__ == "__main__":
    unittest.main()
