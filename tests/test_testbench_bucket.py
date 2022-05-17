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

"""Unit test for bucket operations in the testbench."""

import json
import os
import unittest

from testbench import rest_server


class TestTestbenchBucket(unittest.TestCase):
    def setUp(self):
        rest_server.db.clear()
        self.client = rest_server.server.test_client()
        # Avoid magic buckets in the test
        os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)

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
            "iam_config",
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

    def test_bucket_acl_crud(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        additional_fields = {
            "kind": "storage#bucketAccessControl",
            "bucket": "bucket-name",
        }
        insert_data = {"entity": "allAuthenticatedUsers", "role": "READER"}
        response = self.client.post(
            "/storage/v1/b/bucket-name/acl", data=json.dumps(insert_data)
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)
        self.assertEqual(insert_rest, {**insert_rest, **insert_data})
        self.assertEqual(insert_rest, {**insert_rest, **additional_fields})
        self.assertIn("etag", insert_rest)

        response = self.client.get(
            "/storage/v1/b/bucket-name/acl/allAuthenticatedUsers"
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(get_rest, insert_rest)
        self.assertEqual(get_rest, {**get_rest, **additional_fields})
        self.assertIn("etag", get_rest)

        response = self.client.patch(
            "/storage/v1/b/bucket-name/acl/allAuthenticatedUsers",
            data=json.dumps({"role": "OWNER"}),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        patch_rest = json.loads(response.data)
        self.assertEqual(patch_rest.get("role", None), "OWNER")
        self.assertEqual(patch_rest, {**patch_rest, **additional_fields})
        self.assertIn("etag", patch_rest)

        update_data = patch_rest.copy()
        update_data["role"] = "READER"
        response = self.client.put(
            "/storage/v1/b/bucket-name/acl/allAuthenticatedUsers",
            data=json.dumps(update_data),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        update_rest = json.loads(response.data)
        self.assertEqual(update_rest.get("role", None), "READER")
        self.assertEqual(update_rest, {**update_rest, **additional_fields})
        self.assertIn("etag", update_rest)

        response = self.client.get("/storage/v1/b/bucket-name/acl")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        list_rest = json.loads(response.data)
        self.assertIn(
            "allAuthenticatedUsers", [a.get("entity") for a in list_rest.get("items")]
        )
        self.assertNotEqual(len(list_rest.get("items")), 0)
        front = list_rest.get("items")[0]
        self.assertEqual(front, {**front, **additional_fields})
        self.assertIn("etag", front)

        response = self.client.delete(
            "/storage/v1/b/bucket-name/acl/allAuthenticatedUsers"
        )
        self.assertEqual(response.status_code, 200)
        # After delete, get should fail
        response = self.client.get(
            "/storage/v1/b/bucket-name/acl/allAuthenticatedUsers"
        )
        self.assertEqual(response.status_code, 404)

    def test_bucket_default_object_acl_crud(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        additional_fields = {
            "kind": "storage#objectAccessControl",
            "bucket": "bucket-name",
        }
        insert_data = {"entity": "allAuthenticatedUsers", "role": "READER"}
        response = self.client.post(
            "/storage/v1/b/bucket-name/defaultObjectAcl", data=json.dumps(insert_data)
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)
        self.assertEqual(insert_rest, {**insert_rest, **insert_data})
        self.assertEqual(insert_rest, {**insert_rest, **additional_fields})
        self.assertIn("etag", insert_rest)

        response = self.client.get(
            "/storage/v1/b/bucket-name/defaultObjectAcl/allAuthenticatedUsers"
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(get_rest, insert_rest)
        self.assertEqual(get_rest, {**get_rest, **additional_fields})
        self.assertIn("etag", get_rest)

        response = self.client.patch(
            "/storage/v1/b/bucket-name/defaultObjectAcl/allAuthenticatedUsers",
            data=json.dumps({"role": "OWNER"}),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        patch_rest = json.loads(response.data)
        self.assertEqual(patch_rest.get("role", None), "OWNER")
        self.assertEqual(patch_rest, {**patch_rest, **additional_fields})
        self.assertIn("etag", patch_rest)

        update_data = patch_rest.copy()
        update_data["role"] = "READER"
        response = self.client.put(
            "/storage/v1/b/bucket-name/defaultObjectAcl/allAuthenticatedUsers",
            data=json.dumps(update_data),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        update_rest = json.loads(response.data)
        self.assertEqual(update_rest.get("role", None), "READER")
        self.assertEqual(update_rest, {**update_rest, **additional_fields})
        self.assertIn("etag", update_rest)

        response = self.client.get("/storage/v1/b/bucket-name/defaultObjectAcl")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        list_rest = json.loads(response.data)
        self.assertIn(
            "allAuthenticatedUsers", [a.get("entity") for a in list_rest.get("items")]
        )
        front = list_rest.get("items")[0]
        self.assertEqual(update_rest, {**update_rest, **additional_fields})
        self.assertIn("etag", update_rest)

        response = self.client.delete(
            "/storage/v1/b/bucket-name/defaultObjectAcl/allAuthenticatedUsers"
        )
        self.assertEqual(response.status_code, 200)
        # After delete, get should fail
        response = self.client.get(
            "/storage/v1/b/bucket-name/defaultObjectAcl/allAuthenticatedUsers"
        )
        self.assertEqual(response.status_code, 404)

    def test_bucket_notifications_crud(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            "/storage/v1/b/bucket-name/notificationConfigs",
            data=json.dumps(
                {"missing-topic": "test-topic", "payload_format": "JSON_API_V1"}
            ),
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/storage/v1/b/bucket-name/notificationConfigs",
            data=json.dumps(
                {
                    "topic": "test-topic",
                    "payload_format": "JSON_API_V1",
                    "custom_attributes": {"key": "value"},
                }
            ),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)
        self.assertIn("id", insert_rest)

        response = self.client.get(
            "/storage/v1/b/bucket-name/notificationConfigs/" + insert_rest.get("id")
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(insert_rest, get_rest)

        response = self.client.get("/storage/v1/b/bucket-name/notificationConfigs")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        list_rest = json.loads(response.data)
        ids = [n.get("id") for n in list_rest.get("items")]
        self.assertIn(get_rest.get("id"), ids)

        response = self.client.delete(
            "/storage/v1/b/bucket-name/notificationConfigs/" + insert_rest.get("id")
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.get(
            "/storage/v1/b/bucket-name/notificationConfigs/" + insert_rest.get("id")
        )
        self.assertEqual(response.status_code, 404)

    def test_bucket_iam(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.get("/storage/v1/b/bucket-name/iam")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(get_rest.get("kind", None), "storage#policy")

        # We only expect the legacy roles for a freshly created bucket
        legacy_roles = {
            "roles/storage.legacyBucketOwner",
            "roles/storage.legacyBucketWriter",
            "roles/storage.legacyBucketReader",
        }
        self.assertEqual(
            {b.get("role") for b in get_rest.get("bindings")}, legacy_roles
        )
        set_request = get_rest.copy()
        set_request.pop("kind")
        set_request["bindings"].append(
            {"role": "roles/storage.admin", "members": ["user:user-name@test-only"]}
        )
        response = self.client.put(
            "/storage/v1/b/bucket-name/iam", data=json.dumps(set_request)
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        set_rest = json.loads(response.data)
        self.assertEqual(set_rest.get("kind", None), "storage#policy")
        self.assertNotEqual(set_rest.get("etag"), get_rest.get("etag"))

        set_rest.pop("etag")
        set_rest.pop("kind")
        set_request.pop("etag")
        self.assertEqual(set_rest, set_request)

        response = self.client.get(
            "/storage/v1/b/bucket-name/iam/testPermissions",
            query_string={"permissions": "storage.object.create"},
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        permissions_rest = json.loads(response.data)
        self.assertEqual(
            permissions_rest.get("kind"), "storage#testIamPermissionsResponse"
        )
        self.assertIn("storage.object.create", permissions_rest.get("permissions"))

    def test_bucket_lock(self):
        response = self.client.post(
            "/storage/v1/b",
            data=json.dumps(
                {
                    "name": "bucket-name",
                    "retentionPolicy": {
                        "retentionPeriod": 90 * 24 * 3600,
                    },
                }
            ),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        insert_rest = json.loads(response.data)
        self.assertIn("retentionPolicy", insert_rest)
        insert_policy = insert_rest.get("retentionPolicy")
        self.assertEqual(insert_policy.get("isLocked", False), False)

        response = self.client.post("/storage/v1/b/bucket-name/lockRetentionPolicy")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        lock_rest = json.loads(response.data)
        self.assertEqual(lock_rest.get("kind", None), "storage#bucket")
        self.assertIn("retentionPolicy", lock_rest)
        policy = lock_rest.get("retentionPolicy")
        self.assertIn("isLocked", policy)
        self.assertEqual(policy.get("isLocked"), True)


if __name__ == "__main__":
    unittest.main()
