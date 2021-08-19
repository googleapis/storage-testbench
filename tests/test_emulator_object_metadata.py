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

"""Unit test for Object Metadata operations in emulator.py."""

import json
import os
import unittest
from werkzeug.test import create_environ

import emulator
import gcs
import testbench


class TestEmulatorObjectMetadata(unittest.TestCase):
    def setUp(self):
        emulator.db.clear()
        self.client = emulator.server.test_client()
        # Avoid magic buckets in the test
        os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)

    def test_object_crud(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        payload = "The quick brown fox jumps over the lazy dog"
        response = self.client.put(
            "/bucket-name/fox.txt",
            content_type="text/plain",
            data=payload,
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.get("/storage/v1/b/bucket-name/o/fox.txt")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        expected_fields = {
            "bucket": "bucket-name",
            "name": "fox.txt",
            "size": "%d" % len(payload),
        }
        self.assertEqual(get_rest, get_rest | expected_fields)

        response = self.client.get(
            "/storage/v1/b/bucket-name/o/fox.txt", query_string={"alt": "media"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode("utf-8"), payload)

        response = self.client.get(
            "/storage/v1/b/bucket-name/o/fox.txt", query_string={"alt": "invalid"}
        )
        self.assertEqual(response.status_code, 500)

        # Test PATCH by adding some metadata
        metadata = {"key0": "label0"}
        response = self.client.patch(
            "/storage/v1/b/bucket-name/o/fox.txt",
            data=json.dumps({"metadata": metadata}),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        patch_rest = json.loads(response.data)
        self.assertEqual(
            patch_rest.get("metadata"), patch_rest.get("metadata") | metadata
        )

        update = patch_rest.copy()
        update["metadata"]["key0"] = "updated-label0"
        modifiable_fields = set(gcs.object.Object.modifiable_fields)
        for fixed in [k for k in update.keys() if k not in modifiable_fields]:
            update.pop(fixed, None)
        for acl in update.get("acl", []):
            acl.pop("kind", None)
        response = self.client.put(
            "/storage/v1/b/bucket-name/o/fox.txt", data=json.dumps(update)
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        update_rest = json.loads(response.data)
        self.assertEqual(
            update_rest.get("metadata"),
            update_rest.get("metadata") | {"key0": "updated-label0"},
        )

        response = self.client.get("/storage/v1/b/bucket-name/o")
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        list_rest = json.loads(response.data)
        self.assertEqual(list_rest.get("kind"), "storage#objects")
        names = [o.get("name") for o in list_rest.get("items")]
        self.assertIn("fox.txt", names)

        response = self.client.delete("/storage/v1/b/bucket-name/o/fox.txt")
        self.assertEqual(response.status_code, 200, msg=response.data)
        response = self.client.get("/storage/v1/b/bucket-name/o/fox.txt")
        self.assertEqual(response.status_code, 404)

    def test_object_acl_crud(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        # Use the XML API to insert an object, as the JSON API is not yet ready.
        payload = "How vexingly quick daft zebras jump!"
        response = self.client.put(
            "/bucket-name/zebra",
            content_type="text/plain",
            data=payload,
        )
        self.assertEqual(response.status_code, 200)

        insert_data = {"entity": "allAuthenticatedUsers", "role": "READER"}
        response = self.client.post(
            "/storage/v1/b/bucket-name/o/zebra/acl", data=json.dumps(insert_data)
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)
        self.assertEqual(insert_rest, insert_rest | insert_data)

        response = self.client.get(
            "/storage/v1/b/bucket-name/o/zebra/acl/allAuthenticatedUsers"
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(get_rest, insert_rest)

        response = self.client.patch(
            "/storage/v1/b/bucket-name/o/zebra/acl/allAuthenticatedUsers",
            data=json.dumps({"role": "OWNER"}),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        patch_rest = json.loads(response.data)
        self.assertEqual(patch_rest.get("role", None), "OWNER")

        update_data = patch_rest.copy()
        update_data["role"] = "READER"
        response = self.client.put(
            "/storage/v1/b/bucket-name/o/zebra/acl/allAuthenticatedUsers",
            data=json.dumps(update_data),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        update_rest = json.loads(response.data)
        self.assertEqual(update_rest.get("role", None), "READER")

        response = self.client.get("/storage/v1/b/bucket-name/o/zebra/acl")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        list_rest = json.loads(response.data)
        self.assertIn(
            "allAuthenticatedUsers", [a.get("entity") for a in list_rest.get("items")]
        )

        response = self.client.delete(
            "/storage/v1/b/bucket-name/o/zebra/acl/allAuthenticatedUsers"
        )
        self.assertEqual(response.status_code, 200)
        # After delete, get should fail
        response = self.client.get(
            "/storage/v1/b/bucket-name/o/zebra/allAuthenticatedUsers"
        )
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
