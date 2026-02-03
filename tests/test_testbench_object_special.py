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

"""Unit test for special object operations in the testbench."""

import json
import os
import unittest

from testbench import rest_server


class TestTestbenchObjectSpecial(unittest.TestCase):
    def setUp(self):
        rest_server.db.clear()
        self.client = rest_server.server.test_client()
        # Avoid magic buckets in the test
        os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)

    def test_object_compose(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        payloads = {
            "fox": "The quick brown fox jumps over the lazy dog\n",
            "zebra": "How vexingly quick daft zebras jump!\n",
        }
        sources = []
        for object_name, payload in payloads.items():
            # Use the XML API to insert an object, as the JSON API is not yet ready.
            response = self.client.put(
                "/bucket-name/" + object_name,
                content_type="text/plain",
                data=payload,
            )
            self.assertEqual(response.status_code, 200)

            # Get the metadata so we can include the metageneration in the compose request.
            response = self.client.get("/storage/v1/b/bucket-name/o/" + object_name)
            self.assertEqual(response.status_code, 200)
            o = json.loads(response.data)
            sources.append(
                {
                    "name": object_name,
                    "generation": o.get("generation"),
                    "objectPreconditions": {"ifGenerationMatch": o.get("generation")},
                }
            )

        self.assertEqual(response.status_code, 200)
        response = self.client.post(
            "/storage/v1/b/bucket-name/o/both/compose",
            data=json.dumps({"sourceObjects": sources}),
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        compose_rest = json.loads(response.data)
        compose_rest.pop("acl")
        compose_rest.pop("owner")

        response = self.client.get("/storage/v1/b/bucket-name/o/both")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)
        self.assertEqual(get_rest, compose_rest)

        response = self.client.get("/bucket-name/both")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data.decode("utf-8"), payloads["fox"] + payloads["zebra"]
        )

    def test_object_compose_invalid_requests(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            "/storage/v1/b/bucket-name/o/both/compose",
            data=json.dumps({"invalid-sourceObjects": []}),
        )
        self.assertEqual(response.status_code, 400)

        sources = []
        for i in range(0, 64):
            sources.extend({"name": "test-only-invalid-object"})
        response = self.client.post(
            "/storage/v1/b/bucket-name/o/both/compose",
            data=json.dumps({"sourceObjects": sources}),
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/storage/v1/b/bucket-name/o/both/compose",
            data=json.dumps({"sourceObjects": [{"invalid-name": "unused"}]}),
        )
        self.assertEqual(response.status_code, 400)

    def test_object_compose_delete_source_objects(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        payloads = {
            "fox": "The quick brown fox jumps over the lazy dog\n",
            "zebra": "How vexingly quick daft zebras jump!\n",
        }
        sources = []
        for object_name, payload in payloads.items():
            # Use the XML API to insert an object, as the JSON API is not yet ready.
            response = self.client.put(
                "/bucket-name/" + object_name,
                content_type="text/plain",
                data=payload,
            )
            self.assertEqual(response.status_code, 200)

            # Get the metadata to form the compose request
            response = self.client.get("/storage/v1/b/bucket-name/o/" + object_name)
            self.assertEqual(response.status_code, 200)
            o = json.loads(response.data)
            sources.append(
                {
                    "name": object_name,
                    "generation": o.get("generation"),
                }
            )

        response = self.client.post(
            "/storage/v1/b/bucket-name/o/composed-object/compose?delete_source_objects=true",
            data=json.dumps({"sourceObjects": sources}),
        )
        self.assertEqual(response.status_code, 200, msg=response.data)

        for object_name in payloads.keys():
            response = self.client.get("/storage/v1/b/bucket-name/o/" + object_name)
            self.assertEqual(
                response.status_code,
                404,
                msg=f"Source object {object_name} should have been deleted.",
            )

    def test_object_copy(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        payload = "The quick brown fox jumps over the lazy dog"
        response = self.client.put(
            "/bucket-name/fox",
            content_type="text/plain",
            data=payload,
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            "/storage/v1/b/bucket-name/o/fox/copyTo/b/bucket-name/o/fox2"
        )
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        copy_rest = json.loads(response.data)
        copy_rest.pop("acl")
        copy_rest.pop("owner")

        response = self.client.get("/storage/v1/b/bucket-name/o/fox2")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)

        self.assertEqual(get_rest, copy_rest)

        response = self.client.get("/bucket-name/fox")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data.decode("utf-8"), "The quick brown fox jumps over the lazy dog"
        )

    def test_object_move(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        payload = "The quick brown fox jumps over the lazy dog"
        response = self.client.put(
            "/bucket-name/fox",
            content_type="text/plain",
            data=payload,
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.post("/storage/v1/b/bucket-name/o/fox/moveTo/o/fox2")
        self.assertEqual(response.status_code, 200, msg=response.data)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        move_rest = json.loads(response.data)
        move_rest.pop("acl")
        move_rest.pop("owner")

        response = self.client.get("/storage/v1/b/bucket-name/o/fox2")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)

        self.assertEqual(get_rest, move_rest)

    def test_object_copy_with_metadata(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        payload = "The quick brown fox jumps over the lazy dog"
        response = self.client.put(
            "/bucket-name/fox",
            content_type="text/plain",
            data=payload,
        )
        self.assertEqual(response.status_code, 200)

        metadata = {"key0": "label0"}
        response = self.client.post(
            "/storage/v1/b/bucket-name/o/fox/copyTo/b/bucket-name/o/fox2",
            data=json.dumps({"metadata": metadata}),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        copy_rest = json.loads(response.data)
        copy_rest.pop("acl")
        copy_rest.pop("owner")

        response = self.client.get("/storage/v1/b/bucket-name/o/fox2")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)

        self.assertEqual(get_rest, copy_rest)
        self.assertEqual(get_rest["metadata"], {**get_rest["metadata"], **metadata})

        response = self.client.get("/bucket-name/fox2")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data.decode("utf-8"), "The quick brown fox jumps over the lazy dog"
        )

    def test_object_rewrite(self):
        response = self.client.post(
            "/storage/v1/b", data=json.dumps({"name": "bucket-name"})
        )
        self.assertEqual(response.status_code, 200)

        # We need a large enough payload to make sure the first rewrite does
        # not complete.  The minimum is 1 MiB
        payload = "The quick brown fox jumps over the lazy dog\n" * 1024 * 1024
        response = self.client.put(
            "/bucket-name/fox",
            content_type="text/plain",
            data=payload,
        )
        self.assertEqual(response.status_code, 200)

        metadata = {"key0": "label0"}
        response = self.client.post(
            "/storage/v1/b/bucket-name/o/fox/rewriteTo/b/bucket-name/o/fox2",
            data=json.dumps({"metadata": metadata}),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        rewrite_rest = json.loads(response.data)
        expected_fields = {
            "kind",
            "totalBytesRewritten",
            "objectSize",
            "done",
            "rewriteToken",
        }
        actual_fields = set(rewrite_rest.keys())
        self.assertEqual(actual_fields, actual_fields | expected_fields)
        self.assertEqual(rewrite_rest.get("done"), False)

        token = rewrite_rest.get("rewriteToken")
        while not rewrite_rest.get("done"):
            response = self.client.post(
                "/storage/v1/b/bucket-name/o/fox/rewriteTo/b/bucket-name/o/fox2",
                query_string={"maxBytesRewrittenPerCall": 10, "rewriteToken": token},
                data=json.dumps({"metadata": metadata}),
            )
            self.assertEqual(response.status_code, 200, msg=response.data)
            self.assertTrue(
                response.headers.get("content-type").startswith("application/json")
            )
            rewrite_rest = json.loads(response.data)

        # Once done, a rewrite returns the new object metadata
        self.assertIn("resource", rewrite_rest)
        resource = rewrite_rest.get("resource")
        # TODO(#27) - I do not understand why the rewrite always returns the full projection
        resource.pop("acl")
        resource.pop("owner")

        response = self.client.get("/storage/v1/b/bucket-name/o/fox2")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers.get("content-type").startswith("application/json")
        )
        get_rest = json.loads(response.data)

        self.assertEqual(get_rest, resource)
        self.assertEqual(get_rest["metadata"], {**get_rest["metadata"], **metadata})

        response = self.client.get("/bucket-name/fox2")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data.decode("utf-8")), len(payload))

    def test_object_restore(self):
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

        response = self.client.put(
            "/sd-bucket-name/sd-restore-obj",
            content_type="text/plain",
            data="The quick brown fox jumps over the lazy dog\n",
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.get("/storage/v1/b/sd-bucket-name/o/sd-restore-obj")
        self.assertEqual(response.status_code, 200)
        blob = json.loads(response.data)

        response = self.client.delete("/storage/v1/b/sd-bucket-name/o/sd-restore-obj")
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            "/storage/v1/b/sd-bucket-name/o/sd-restore-obj/restore?generation="
            + blob.get("generation")
        )
        self.assertEqual(response.status_code, 200)
        restored_blob = json.loads(response.data)
        self.assertNotEqual(blob.get("generation"), restored_blob.get("generation"))

    def test_object_restore_no_generation(self):
        response = self.client.post(
            "/storage/v1/b/sd-bucket-name/o/sd-restore-obj/restore"
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
