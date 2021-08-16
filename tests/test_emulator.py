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

"""Unit test for emulator."""

import json
import os
from testbench import database
from testbench.common import rest_adjust
import unittest

import emulator


class TestEmulator(unittest.TestCase):
    def setUp(self):
        supported_methods = emulator.db.supported_methods.copy()
        emulator.db = database.Database.init()
        emulator.db.insert_supported_methods(supported_methods)
        self.client = emulator.server.test_client()
        # Avoid magic buckets in the test
        os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)

    def test_root(self):
        response = self.client.get("/")
        self.assertEqual(response.data, b"OK")

    def test_retry_test_crud(self):
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

    def test_retry_test_return_error_after(self):
        response = self.client.post(
            "/retry_test",
            data=json.dumps(
                {"instructions": {"storage.buckets.list": ["return-429-after-128K"]}}
            ),
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
        self.assertEqual(list_response.status_code, 200)

    def test_bucket_crud(self):
        insert_response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(insert_response.status_code, 200)
        self.assertEqual(
            insert_response.headers.get("content-type"), "application/json"
        )
        insert_rest = json.loads(insert_response.data)
        self.assertEqual(insert_rest.get("name"), "bucket-name")

        get_response = self.client.get("/storage/v1/b/bucket-name")
        self.assertEqual(get_response.status_code, 200)
        self.assertEqual(get_response.headers.get("content-type"), "application/json")
        get_rest = json.loads(get_response.data)
        self.assertEqual(insert_rest, get_rest)

        patch_response = self.client.patch(
            "/storage/v1/b/bucket-name", data=json.dumps({"labels": {"key": "value"}})
        )
        self.assertEqual(patch_response.status_code, 200)
        self.assertEqual(patch_response.headers.get("content-type"), "application/json")
        patch_rest = json.loads(patch_response.data)
        self.assertEqual(patch_rest.get("labels"), {"key": "value"})

        # This is a bit terrible, but we need to send only the fields that are updatable with any update request.
        modifiable_fields = {
            "acl",
            "default_object_acl",
            "lifecycle",
            "cors",
            "storage_class",
            "default_event_based_hold",
            "labels",
            "website",
            "versioning",
            "logging",
            "encryption",
            "billing",
            "retention_policy",
            "location_type",
            "iam_configuration",
        }
        update_request = patch_rest.copy()
        for fixed in [k for k in update_request.keys() if k not in modifiable_fields]:
            update_request.pop(fixed, None)
        for acl in update_request.get("acl", []):
            acl.pop("kind", None)
        for acl in update_request.get("defaultObjectAcl", []):
            acl.pop("kind", None)
        patch_rest["labels"]["key"] = "new-value"
        update_response = self.client.put(
            "/storage/v1/b/bucket-name", data=json.dumps(update_request)
        )
        self.assertEqual(update_response.status_code, 200, msg=update_response.data)
        self.assertEqual(
            update_response.headers.get("content-type"), "application/json"
        )
        update_rest = json.loads(update_response.data)
        self.assertEqual(update_rest.get("labels"), {"key": "new-value"})

        list_response = self.client.get(
            "/storage/v1/b", query_string={"project": "test-project-unused"}
        )
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(list_response.headers.get("content-type"), "application/json")
        list_rest = json.loads(list_response.data)
        names = [b.get("name") for b in list_rest.get("items")]
        self.assertEqual(names, ["bucket-name"])

        delete_response = self.client.delete("/storage/v1/b/bucket-name")
        self.assertEqual(delete_response.status_code, 200)

        list_response = self.client.get(
            "/storage/v1/b", query_string={"project": "test-project-unused"}
        )
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(list_response.headers.get("content-type"), "application/json")
        list_rest = json.loads(list_response.data)
        names = [b.get("name") for b in list_rest.get("items")]
        self.assertEqual(names, [])


if __name__ == "__main__":
    unittest.main()
