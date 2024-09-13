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

"""Unit test for Object Metadata operations in the testbench."""

import json
import os
import unittest

import gcs
from testbench import rest_server


class TestTestbenchObjectMetadata(unittest.TestCase):
    def setUp(self):
        rest_server.db.clear()
        self.client = rest_server.server.test_client()
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
        self.assertEqual(get_rest, {**get_rest, **expected_fields})

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
            patch_rest.get("metadata"), {**patch_rest.get("metadata"), **metadata}
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
            {**update_rest.get("metadata"), **{"key0": "updated-label0"}},
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

    def test_delete_with_generation(self):
        # Create a bucket and object
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
        rest = json.loads(response.data)

        # Delete the object using a generation number
        response = self.client.delete(
            "/storage/v1/b/bucket-name/o/fox.txt?generation=%s" % rest.get("generation")
        )
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

        response = self.client.get("/storage/v1/b/bucket-name/o/zebra")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        rest = json.loads(response.data)
        generation = rest.get("generation", "")

        insert_data = {"entity": "allAuthenticatedUsers", "role": "READER"}
        response = self.client.post(
            "/storage/v1/b/bucket-name/o/zebra/acl", data=json.dumps(insert_data)
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)
        self.assertEqual(insert_rest, {**insert_rest, **insert_data})

        additional_fields = {
            "kind": "storage#objectAccessControl",
            "bucket": "bucket-name",
            "object": "zebra",
            "generation": generation,
        }
        self.assertEqual(insert_rest, {**insert_rest, **additional_fields})

        response = self.client.get(
            "/storage/v1/b/bucket-name/o/zebra/acl/allAuthenticatedUsers"
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(get_rest, {**get_rest, **additional_fields})

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
        self.assertEqual(patch_rest, {**patch_rest, **additional_fields})

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
        self.assertEqual(update_rest, {**update_rest, **additional_fields})

        response = self.client.get("/storage/v1/b/bucket-name/o/zebra/acl")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        list_rest = json.loads(response.data)
        self.assertIn(
            "allAuthenticatedUsers", [a.get("entity") for a in list_rest.get("items")]
        )
        for a in list_rest.get("items"):
            self.assertEqual(a, {**a, **additional_fields})

        response = self.client.delete(
            "/storage/v1/b/bucket-name/o/zebra/acl/allAuthenticatedUsers"
        )
        self.assertEqual(response.status_code, 200)
        # After delete, get should fail
        response = self.client.get(
            "/storage/v1/b/bucket-name/o/zebra/allAuthenticatedUsers"
        )
        self.assertEqual(response.status_code, 404)

    def test_list_with_soft_deleted(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.get("/storage/v1/b/bucket-name/o?softDeleted=true")
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/storage/v1/b",
            data=json.dumps(
                {
                    "name": "sd-bucket-name",
                    "softDeletePolicy": {"retentionDurationSeconds": 7 * 24 * 60 * 60},
                }
            ),
        )
        self.assertEqual(response.status_code, 200)

        payload = "The quick brown fox jumps over the lazy dog"
        response = self.client.put(
            "/sd-bucket-name/fox.txt",
            content_type="text/plain",
            data=payload,
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.delete("/storage/v1/b/sd-bucket-name/o/fox.txt")
        self.assertEqual(response.status_code, 200)

        response = self.client.get(
            "/storage/v1/b/sd-bucket-name/o?softDeleted=true&versions=true"
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.get("/storage/v1/b/sd-bucket-name/o?softDeleted=true")
        self.assertEqual(response.status_code, 200)

    def test_get_with_soft_deleted(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.get("/storage/v1/b/bucket-name/o/some-object?softDeleted=true")
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/storage/v1/b",
            data=json.dumps(
                {
                    "name": "sd-bucket-name",
                    "softDeletePolicy": {"retentionDurationSeconds": 7 * 24 * 60 * 60},
                }
            ),
        )
        self.assertEqual(response.status_code, 200)

        payload = "The quick brown fox jumps over the lazy dog"
        response = self.client.put(
            "/sd-bucket-name/fox.txt",
            content_type="text/plain",
            data=payload,
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.get(
            "/storage/v1/b/sd-bucket-name/o/fox.txt"
        )
        self.assertEqual(response.status_code, 200)
        generation = json.loads(response.data).get("generation")

        response = self.client.delete("/storage/v1/b/sd-bucket-name/o/fox.txt")
        self.assertEqual(response.status_code, 200)

        response = self.client.get(
            "/storage/v1/b/sd-bucket-name/o/fox.txt?softDeleted=true&alt=media"
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.get("/storage/v1/b/sd-bucket-name/o/fox.txt?softDeleted=true")
        self.assertEqual(response.status_code, 400)

        response = self.client.get("/storage/v1/b/sd-bucket-name/o/fox.txt?softDeleted=true&generation=" + generation)
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
