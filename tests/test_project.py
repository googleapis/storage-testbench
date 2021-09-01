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

"""Unit test for gcs.project."""

import json
import unittest

import gcs.project
import testbench


class TestProject(unittest.TestCase):
    def setUp(self):
        db = testbench.database.Database.init()
        _, app = gcs.project.get_projects_app(db)
        self.client = app.test_client()

    def test_projects_get(self):
        project = gcs.project.get_project("test-project-id")
        project_number = project.project_number
        response = self.client.get("/test-project-id/serviceAccount")
        payload = json.loads(response.data)
        self.assertDictEqual(
            payload,
            {
                "kind": "storage#serviceAccount",
                "email_address": "service-%d@gs-project-accounts.iam.gserviceaccount.com"
                % project_number,
            },
        )

    def test_hmac_crud(self):
        access_ids = []
        for account in ["test-sa1", "test-sa2"]:
            insert_response = self.client.post(
                path="/test-project-id/hmacKeys",
                query_string={
                    "serviceAccountEmail": account
                    + "@test-project-2.iam.gserviceaccount.com",
                },
            )
            payload = json.loads(insert_response.data)
            self.assertIn("kind", payload)
            self.assertIn("secret", payload)
            self.assertIn("metadata", payload)
            metadata = payload.get("metadata")
            self.assertIn("accessId", metadata)
            access_ids.append(metadata.get("accessId"))

        get_response = self.client.get(
            path="/test-project-id/hmacKeys/" + access_ids[0]
        )
        payload = json.loads(get_response.data)
        self.assertIn("kind", payload)
        self.assertNotIn("secret", payload)
        self.assertIn("accessId", payload)
        self.assertEqual(access_ids[0], payload["accessId"])

        update_response = self.client.put(
            path="/test-project-id/hmacKeys/" + access_ids[0],
            data=json.dumps(
                {
                    "state": "INACTIVE",
                }
            ),
        )
        payload = json.loads(update_response.data)
        _ = self.client.delete(path="/test-project-id/hmacKeys/" + access_ids[0])

        list_response = self.client.get(path="/test-project-id/hmacKeys")
        payload = json.loads(list_response.data)
        self.assertIn("kind", payload)
        self.assertIn("items", payload)

        list_response = self.client.get(
            path="/test-project-id/hmacKeys",
            query_string={
                "serviceAccountEmail": "test-sa2"
                + "@test-project-2.iam.gserviceaccount.com",
                "deleted": "true",
            },
        )
        payload = json.loads(list_response.data)
        self.assertIn("kind", payload)
        self.assertIn("items", payload)

    def test_hmac_insert_error(self):
        response = self.client.post(
            path="/test-project-id/hmacKeys",
            query_string={
                # missing "serviceAccountEmail"
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_hmac_delete_not_found(self):
        response = self.client.delete(
            path="/test-project-id/hmacKeys/test-only-invalid:key-id"
        )
        self.assertEqual(response.status_code, 404)
        response = self.client.post(
            path="/test-project-id/hmacKeys",
            query_string={"serviceAccountEmail": "test-only@example.com"},
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.delete(
            path="/test-project-id/hmacKeys/test-only@example.com:invalid-key"
        )
        self.assertEqual(response.status_code, 404)

    def test_hmac_get_not_found(self):
        response = self.client.get(
            path="/test-project-id/hmacKeys/test-only-invalid:key-id"
        )
        self.assertEqual(response.status_code, 404)
        response = self.client.post(
            path="/test-project-id/hmacKeys",
            query_string={"serviceAccountEmail": "test-only@example.com"},
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.get(
            path="/test-project-id/hmacKeys/test-only@example.com:invalid-key"
        )
        self.assertEqual(response.status_code, 404)

    def test_hmac_update_not_found(self):
        response = self.client.put(
            path="/test-project-id/hmacKeys/test-only-invalid:key-id",
            data=json.dumps({"state": "INACTIVE"}),
        )
        self.assertEqual(response.status_code, 404, msg=response.data)
        response = self.client.post(
            path="/test-project-id/hmacKeys",
            query_string={"serviceAccountEmail": "test-only@example.com"},
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.put(
            path="/test-project-id/hmacKeys/test-only@example.com:invalid-key",
            data=json.dumps({"state": "INACTIVE"}),
        )
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
