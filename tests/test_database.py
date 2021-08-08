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
import unittest
import os

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
        names = {b.metadata.name for b in list_result}
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
        database.insert_test_bucket(None)
        names = {b.metadata.name for b in database.list_bucket(request, "", None)}
        self.assertEqual(names, set())

        os.environ["GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME"] = "test-bucket-1"
        database.insert_test_bucket(None)
        get_result = database.get_bucket(request, "test-bucket-1", None)
        self.assertEqual(get_result.metadata.name, "test-bucket-1")


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
        items, _, _ = self.database.list_object(
            Request(create_environ(query_string={})), "bucket-name", None
        )
        names = {o.name for o in items}
        self.assertEqual(names, {"object-name"})

        self.bucket.metadata.versioning.enabled = True
        for name in ["abc", "obaaa", "obzzz", "zzz", "object-name/qux", "object-name"]:
            request = testbench.common.FakeRequest(
                args={"name": name}, data=b"12345678", headers={}, environ={}
            )
            blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
            self.database.insert_object(request, "bucket-name", blob, None)

        items, _, _ = self.database.list_object(
            Request(
                create_environ(
                    query_string={
                        "prefix": "ob",
                        "startOffset": "obc",
                        "endOffset": "obr",
                        "delimiter": "/",
                        "includeTrailingDelimiter": "false",
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
        items, _, _ = self.database.list_object(
            Request(create_environ(query_string={})), "bucket-name", None
        )
        names = {o.name for o in items}
        self.assertNotIn("object-name", names)

        # Delete all versions of all objects.
        items, _, _ = self.database.list_object(
            Request(create_environ(query_string={"versions": "true"})),
            "bucket-name",
            None,
        )
        for o in items:
            self.database.delete_object(
                testbench.common.FakeRequest(args={"generation": o.generation}),
                o.bucket,
                o.name,
                None,
            )
        items, _, _ = self.database.list_object(
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


if __name__ == "__main__":
    unittest.main()
