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

"""Tests for the Rewrite helper (see gcs/rewrite.py)."""

import unittest
import unittest.mock

import grpc
from werkzeug.test import create_environ
from werkzeug.wrappers import Request

import gcs
from google.storage.v2 import storage_pb2


class TestRewrite(unittest.TestCase):

    MIN_REWRITE_BYTES = 1024 * 1024

    def test_rewrite_rest(self):
        environ = create_environ(
            base_url="http://localhost:8080",
            query_string={},
        )
        rewrite = gcs.rewrite.Rewrite.init_rest(
            Request(environ),
            "source-bucket",
            "source-object",
            "destination-bucket",
            "destination-object",
        )
        self.assertEqual("source-bucket", rewrite.src_bucket_name)
        self.assertEqual("source-object", rewrite.src_object_name)
        self.assertEqual("destination-bucket", rewrite.dst_bucket_name)
        self.assertEqual("destination-object", rewrite.dst_object_name)
        self.assertEqual(
            TestRewrite.MIN_REWRITE_BYTES, rewrite.max_bytes_rewritten_per_call
        )

    def test_rewrite_rest_with_low_bytes(self):
        environ = create_environ(
            base_url="http://localhost:8080",
            query_string={
                "maxBytesRewrittenPerCall": int(TestRewrite.MIN_REWRITE_BYTES / 2)
            },
        )
        rewrite = gcs.rewrite.Rewrite.init_rest(
            Request(environ),
            "source-bucket",
            "source-object",
            "destination-bucket",
            "destination-object",
        )
        self.assertEqual(
            TestRewrite.MIN_REWRITE_BYTES, rewrite.max_bytes_rewritten_per_call
        )

    def test_rewrite_rest_with_high_bytes(self):
        environ = create_environ(
            base_url="http://localhost:8080",
            query_string={
                "maxBytesRewrittenPerCall": TestRewrite.MIN_REWRITE_BYTES * 2
            },
        )
        rewrite = gcs.rewrite.Rewrite.init_rest(
            Request(environ),
            "source-bucket",
            "source-object",
            "destination-bucket",
            "destination-object",
        )
        self.assertEqual(
            2 * TestRewrite.MIN_REWRITE_BYTES, rewrite.max_bytes_rewritten_per_call
        )

    def test_rewrite_grpc(self):
        request = storage_pb2.RewriteObjectRequest(
            destination_bucket="projects/_/buckets/destination-bucket",
            destination_name="destination-object",
            destination=storage_pb2.Object(
                metadata={"key": "value"},
            ),
            source_bucket="projects/_/buckets/source-bucket",
            source_object="source-object",
        )
        context = unittest.mock.Mock()
        rewrite = gcs.rewrite.Rewrite.init_grpc(request, context)
        self.assertEqual("source-bucket", rewrite.src_bucket_name)
        self.assertEqual("source-object", rewrite.src_object_name)
        self.assertEqual("destination-bucket", rewrite.dst_bucket_name)
        self.assertEqual("destination-object", rewrite.dst_object_name)
        self.assertEqual(
            TestRewrite.MIN_REWRITE_BYTES, rewrite.max_bytes_rewritten_per_call
        )

    def test_rewrite_grpc_no_destination_object(self):
        request = storage_pb2.RewriteObjectRequest(
            destination_bucket="projects/_/buckets/destination-bucket",
            destination_name="destination-object",
            source_bucket="projects/_/buckets/source-bucket",
            source_object="source-object",
        )
        context = unittest.mock.Mock()
        rewrite = gcs.rewrite.Rewrite.init_grpc(request, context)
        self.assertEqual("source-bucket", rewrite.src_bucket_name)
        self.assertEqual("source-object", rewrite.src_object_name)
        self.assertEqual("destination-bucket", rewrite.dst_bucket_name)
        self.assertEqual("destination-object", rewrite.dst_object_name)
        self.assertEqual(
            TestRewrite.MIN_REWRITE_BYTES, rewrite.max_bytes_rewritten_per_call
        )

    def test_rewrite_grpc_low_bytes(self):
        request = storage_pb2.RewriteObjectRequest(
            destination_bucket="projects/_/buckets/destination-bucket",
            destination_name="destination-object",
            source_bucket="projects/_/buckets/source-bucket",
            source_object="source-object",
            max_bytes_rewritten_per_call=int(TestRewrite.MIN_REWRITE_BYTES / 2),
        )
        context = unittest.mock.Mock()
        rewrite = gcs.rewrite.Rewrite.init_grpc(request, context)
        self.assertEqual(
            TestRewrite.MIN_REWRITE_BYTES, rewrite.max_bytes_rewritten_per_call
        )

    def test_rewrite_grpc_high_bytes(self):
        request = storage_pb2.RewriteObjectRequest(
            destination_bucket="projects/_/buckets/destination-bucket",
            destination_name="destination-object",
            source_bucket="projects/_/buckets/source-bucket",
            source_object="source-object",
            max_bytes_rewritten_per_call=int(2 * TestRewrite.MIN_REWRITE_BYTES),
        )
        context = unittest.mock.Mock()
        rewrite = gcs.rewrite.Rewrite.init_grpc(request, context)
        self.assertEqual(
            2 * TestRewrite.MIN_REWRITE_BYTES, rewrite.max_bytes_rewritten_per_call
        )

    def test_rewrite_bad_requests(self):
        cases = {
            "missing destination": storage_pb2.RewriteObjectRequest(
                source_bucket="projects/_/buckets/source-bucket",
                source_object="source-object",
            ),
            "bad destination.bucket [1]": storage_pb2.RewriteObjectRequest(
                destination_bucket="destination-bucket",
                destination_name="destination-object",
                destination=storage_pb2.Object(
                    metadata={"key": "value"},
                ),
                source_bucket="projects/_/buckets/source-bucket",
                source_object="source-object",
            ),
            "bad destination.bucket [2]": storage_pb2.RewriteObjectRequest(
                destination_bucket="projects/_/buckets/",
                destination_name="destination-object",
                destination=storage_pb2.Object(
                    metadata={"key": "value"},
                ),
                source_bucket="projects/_/buckets/source-bucket",
                source_object="source-object",
            ),
            "missing destination.name": storage_pb2.RewriteObjectRequest(
                destination_bucket="projects/_/buckets/destination-bucket",
                destination=storage_pb2.Object(
                    metadata={"key": "value"},
                ),
                source_bucket="projects/_/buckets/source-bucket",
                source_object="source-object",
            ),
            "bad source bucket [1]": storage_pb2.RewriteObjectRequest(
                destination_bucket="projects/_/buckets/destination-bucket",
                destination_name="destination-object",
                destination=storage_pb2.Object(
                    metadata={"key": "value"},
                ),
                source_bucket="source-bucket",
                source_object="source-object",
            ),
            "bad source_bucket [2]": storage_pb2.RewriteObjectRequest(
                destination_bucket="projects/_/buckets/destination-bucket",
                destination_name="destination-object",
                destination=storage_pb2.Object(
                    metadata={"key": "value"},
                ),
                source_bucket="projects/_/buckets/",
                source_object="source-object",
            ),
            "missing source_object": storage_pb2.RewriteObjectRequest(
                destination_bucket="projects/_/buckets/destination-bucket",
                destination_name="destination-object",
                destination=storage_pb2.Object(
                    metadata={"key": "value"},
                ),
                source_bucket="projects/_/buckets/source-bucket",
            ),
            "inconsistent object name": storage_pb2.RewriteObjectRequest(
                destination_bucket="projects/_/buckets/destination-bucket",
                destination_name="destination-object",
                destination=storage_pb2.Object(
                    name="inconsistent-object-name",
                    metadata={"key": "value"},
                ),
                source_bucket="projects/_/buckets/source-bucket",
            ),
            "inconsistent bucket name": storage_pb2.RewriteObjectRequest(
                destination_bucket="projects/_/buckets/destination-bucket",
                destination_name="destination-object",
                destination=storage_pb2.Object(
                    bucket="inconsistent-bucket-name",
                    metadata={"key": "value"},
                ),
                source_bucket="projects/_/buckets/source-bucket",
            ),
        }
        for case, request in cases.items():
            context = unittest.mock.Mock(name=case)
            rewrite = gcs.rewrite.Rewrite.init_grpc(request, context)
            self.assertIsNone(rewrite, msg=case)
            context.abort.assert_called_once_with(
                grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
            )


if __name__ == "__main__":
    unittest.main()
