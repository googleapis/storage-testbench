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

"""Unit test for testbench.database."""

import json
import os
import unittest

from werkzeug.test import create_environ
from werkzeug.wrappers import Request

import gcs
import testbench


class TestDatabaseBucket(unittest.TestCase):
    def test_bucket_crud(self):
        database = testbench.database.Database.init()
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket-name"}),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        database.insert_bucket(request, bucket, None)
        get_result = database.get_bucket(request, "bucket-name", None)
        self.assertEqual(bucket.metadata, get_result.metadata)
        list_result = database.list_bucket(request, "test-project-id", None)
        names = {b.metadata.bucket_id for b in list_result}
        self.assertEqual(names, {"bucket-name"})
        database.delete_bucket(request, "bucket-name", None)
        list_result = database.list_bucket(request, "test-project-id", None)
        names = {b.metadata.name for b in list_result}
        self.assertEqual(names, set())

    def test_bucket_not_found(self):
        database = testbench.database.Database.init()
        with self.assertRaises(testbench.error.RestException) as rest:
            request = testbench.common.FakeRequest(
                args={},
                data=json.dumps({"name": "bucket-name"}),
            )
            database.get_bucket(request, "bucket-name", None)
        self.assertEqual(rest.exception.code, 404)

    def test_list_bucket_invalid(self):
        database = testbench.database.Database.init()
        with self.assertRaises(testbench.error.RestException) as rest:
            request = testbench.common.FakeRequest(
                args={},
                data=json.dumps({}),
            )
            database.list_bucket(request, "invalid-project-id-", None)
        self.assertEqual(rest.exception.code, 400)

    def test_delete_not_empty(self):
        database = testbench.database.Database.init()
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket-name"}),
        )
        bucket, _ = gcs.bucket.Bucket.init(request, None)
        database.insert_bucket(request, bucket, None)
        request = testbench.common.FakeRequest(
            args={"name": "object"}, data=b"12345678", headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, bucket.metadata)
        database.insert_object(request, "bucket-name", blob, None)
        with self.assertRaises(testbench.error.RestException) as rest:
            request = testbench.common.FakeRequest(
                args={},
                data=json.dumps({}),
            )
            database.delete_bucket(request, "bucket-name", None)
        self.assertEqual(rest.exception.code, 400)

    def test_insert_test_bucket(self):
        database = testbench.database.Database.init()
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({}),
        )
        os.environ.pop("GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", None)
        database.insert_test_bucket()
        names = {b.metadata.name for b in database.list_bucket(request, "", None)}
        self.assertEqual(names, set())

        os.environ["GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME"] = "test-bucket-1"
        database.insert_test_bucket()
        get_result = database.get_bucket(request, "test-bucket-1", None)
        self.assertEqual(get_result.metadata.bucket_id, "test-bucket-1")


class TestDatabaseObject(unittest.TestCase):
    def setUp(self):
        self.database = testbench.database.Database.init()
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket-name"}),
        )
        self.bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.database.insert_bucket(request, self.bucket, None)

    def test_object_crud(self):
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=b"12345678", headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.database.insert_object(request, "bucket-name", blob, None)
        get_result = self.database.get_object(
            testbench.common.FakeRequest(args={}),
            "bucket-name",
            "object-name",
            is_source=True,
            context=None,
        )
        self.assertEqual(get_result.metadata, blob.metadata)
        items, _ = self.database.list_object(
            Request(create_environ(query_string={})), "bucket-name", None
        )
        names = {o.name for o in items}
        self.assertEqual(names, {"object-name"})

        self.bucket.metadata.versioning.enabled = True
        for name in [
            "abc",
            "obaaa",
            "obzzz",
            "zzz",
            "object-name",
            "object-name/",
            "object-name/qux",
            "object-name/foo/bar/baz",
            "object-name/foo/bar/",
            "object-name/foo/bar",
            "object-name/foo///",
        ]:
            request = testbench.common.FakeRequest(
                args={"name": name}, data=b"12345678", headers={}, environ={}
            )
            blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
            self.database.insert_object(request, "bucket-name", blob, None)

        items, _ = self.database.list_object(
            Request(
                create_environ(
                    query_string={
                        "prefix": "ob",
                        "startOffset": "obc",
                        "endOffset": "obr",
                        "delimiter": "/",
                        "versions": "true",
                    }
                )
            ),
            "bucket-name",
            None,
        )
        names = {o.name for o in items}
        self.assertEqual(names, {"object-name"})

        # Delete the latest version, listing without versions should not include the just deleted object.
        self.database.delete_object(
            testbench.common.FakeRequest(args={}), "bucket-name", "object-name", None
        )
        items, _ = self.database.list_object(
            Request(create_environ(query_string={})), "bucket-name", None
        )
        names = {o.name for o in items}
        self.assertNotIn("object-name", names)

        # Delete all versions of all objects.
        items, _ = self.database.list_object(
            Request(create_environ(query_string={"versions": "true"})),
            "bucket-name",
            None,
        )
        for o in items:
            self.database.delete_object(
                testbench.common.FakeRequest(args={"generation": o.generation}),
                "bucket-name",
                o.name,
                None,
            )
        items, _ = self.database.list_object(
            Request(create_environ(query_string={"versions": "true"})),
            "bucket-name",
            None,
        )
        self.assertEqual(set(), {o.name for o in items})

    def test_get_object_not_found(self):
        with self.assertRaises(testbench.error.RestException) as rest:
            _ = self.database.get_object(
                testbench.common.FakeRequest(args={}),
                "bucket-name",
                "object-name",
                is_source=False,
                context=None,
            )
        self.assertEqual(rest.exception.code, 404)

        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=b"12345678", headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.database.insert_object(request, "bucket-name", blob, None)
        with self.assertRaises(testbench.error.RestException) as rest:
            _ = self.database.get_object(
                testbench.common.FakeRequest(
                    args={"generation": blob.metadata.generation + 1}
                ),
                "bucket-name",
                "object-name",
                is_source=False,
                context=None,
            )
        self.assertEqual(rest.exception.code, 404)

    def test_list_object_bucket_not_found(self):
        with self.assertRaises(testbench.error.RestException) as rest:
            _, _, _ = self.database.list_object(
                Request(create_environ(query_string={})),
                "invalid-bucket-name",
                None,
            )
        self.assertEqual(rest.exception.code, 404)


class TestDatabaseTemporaryResources(unittest.TestCase):
    """Test the Database class handling of uploads and rewrites."""

    def setUp(self):
        self.database = testbench.database.Database.init()
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket-name"}),
        )
        self.bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.database.insert_bucket(request, self.bucket, None)

    def test_upload_crud(self):
        environ = create_environ(
            base_url="http://localhost:8080",
            data=json.dumps({}),
            query_string={"name": "test-object"},
            content_type="application/json",
            method="POST",
        )
        upload = gcs.upload.Upload.init_resumable_rest(
            Request(environ), self.bucket.metadata
        )
        self.database.insert_upload(upload)
        get_result = self.database.get_upload(upload.upload_id, None)
        self.assertEqual(upload, get_result)

        self.database.delete_upload(upload.upload_id, None)
        # get_upload() should fail after a delete.
        with self.assertRaises(testbench.error.RestException) as rest:
            _ = self.database.get_upload(upload.upload_id, None)
        self.assertEqual(rest.exception.code, 404)

    def test_rewrite_crud(self):
        environ = create_environ(
            base_url="http://localhost:8080",
            query_string={},
        )
        rewrite = gcs.rewrite.Rewrite.init_rest(
            Request(environ),
            "bucket-name",
            "source-object",
            "bucket-name",
            "destination-object",
        )
        self.database.insert_rewrite(rewrite)
        get_result = self.database.get_rewrite(rewrite.token, None)
        self.assertEqual(rewrite, get_result)

        self.database.delete_rewrite(rewrite.token, None)
        # get_rewrite() should fail after a delete.
        with self.assertRaises(testbench.error.RestException) as rest:
            _ = self.database.get_rewrite(rewrite.token, None)
        self.assertEqual(rest.exception.code, 404)


class TestDatabaseRetryTest(unittest.TestCase):
    def test_retry_test_crud(self):
        database = testbench.database.Database.init()
        database.insert_supported_methods(["storage.buckets.list"])

        test = database.insert_retry_test({"storage.buckets.list": ["return-503"]})
        self.assertLessEqual({"id", "instructions", "completed"}, set(test.keys()))
        self.assertFalse(test.get("completed"))
        get_result = database.get_retry_test(test.get("id"))
        self.assertEqual(test, get_result)

        self.assertTrue(
            database.has_instructions_retry_test(test.get("id"), "storage.buckets.list")
        )
        self.assertFalse(
            database.has_instructions_retry_test(
                test.get("id"), "storage.buckets.delete"
            )
        )

        self.assertEqual(
            "return-503",
            database.peek_next_instruction(test.get("id"), "storage.buckets.list"),
        )
        self.assertIsNone(
            database.peek_next_instruction(test.get("id"), "storage.buckets.delete")
        )

        self.assertEqual(
            "return-503",
            database.dequeue_next_instruction(test.get("id"), "storage.buckets.list"),
        )
        get_result = database.get_retry_test(test.get("id"))
        self.assertTrue(get_result.get("completed"))

        ids = {r.get("id") for r in database.list_retry_tests()}
        self.assertEqual({test.get("id")}, ids)

        database.delete_retry_test(test.get("id"))
        ids = {r.get("id") for r in database.list_retry_tests()}
        self.assertEqual(set(), ids)

    def test_get_retry_test_not_found(self):
        database = testbench.database.Database.init()
        with self.assertRaises(testbench.error.RestException) as rest:
            _ = database.get_retry_test("test-invalid")
        self.assertEqual(rest.exception.code, 404)

    def test_insert_retry_test_invalid_instruction(self):
        database = testbench.database.Database.init()
        database.insert_supported_methods(["storage.buckets.list"])

        with self.assertRaises(testbench.error.RestException) as rest:
            _ = database.insert_retry_test(
                {"storage.buckets.list": ["invalid-instruction"]}
            )
        self.assertEqual(rest.exception.code, 400)

    def test_insert_retry_test_invalid_operation(self):
        database = testbench.database.Database.init()
        database.insert_supported_methods(["storage.buckets.list"])

        with self.assertRaises(testbench.error.RestException) as rest:
            _ = database.insert_retry_test({"storage.buckets.get": ["return-429"]})
        self.assertEqual(rest.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
