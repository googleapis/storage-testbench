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

"""Tests for the gRPC functions in the Bucket class (see gcs/bucket.py)."""

import unittest
import unittest.mock

from google.storage.v2 import storage_pb2
import grpc

import gcs


class TestBucketGrpc(unittest.TestCase):
    @classmethod
    def _raise_grpc_error():
        raise Exception("grpc error")

    def test_init_grpc_simple(self):
        request = storage_pb2.CreateBucketRequest(
            parent="projects/test-project",
            bucket_id="test-bucket-name",
            bucket=storage_pb2.Bucket(storage_class="REGIONAL"),
        )
        context = unittest.mock.Mock()
        bucket, _ = gcs.bucket.Bucket.init_grpc(request, context)
        self.assertEqual(bucket.metadata.name, "projects/_/buckets/test-bucket-name")
        self.assertEqual(bucket.metadata.bucket_id, "test-bucket-name")
        self.assertEqual(bucket.metadata.storage_class, "REGIONAL")
        self.assertLess(0, bucket.metadata.metageneration)

    def test_init_validates_names(self):
        request = storage_pb2.CreateBucketRequest(
            parent="projects/test-project",
            bucket_id="short.names.for.domain.buckets.example.com",
            bucket=storage_pb2.Bucket(),
        )
        context = unittest.mock.Mock()
        bucket, _ = gcs.bucket.Bucket.init_grpc(request, context)
        self.assertEqual(
            bucket.metadata.name,
            "projects/_/buckets/short.names.for.domain.buckets.example.com",
        )
        invalid_ids = [
            "goog-is-not-a-valid-prefix",
            "hiding-google-is-not-valid",
            "hiding-g00gl3-is-not-valid",
            "name-too-long-" + ("a" * 63),
            ("a" * 64) + ".part-too-long.com",
            ("a" * 222) + ".domain-name-too-long.com",
        ]
        for id in invalid_ids:
            request = storage_pb2.CreateBucketRequest(
                parent="projects/test-project",
                bucket_id=id,
                bucket=storage_pb2.Bucket(),
            )
            context = unittest.mock.Mock()
            context.abort.side_effect = TestBucketGrpc._raise_grpc_error
            with self.assertRaises(Exception, msg=id) as _:
                _, _ = gcs.bucket.Bucket.init_grpc(request, context)
            context.abort.assert_called_once_with(
                grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
            )

    def test_init_validates_project(self):
        invalid_projects = ["projects/", "pr/test-project", "projects/foo/bar/baz"]
        for project in invalid_projects:
            request = storage_pb2.CreateBucketRequest(
                parent=project,
                bucket_id="test-bucket-name",
                bucket=storage_pb2.Bucket(),
            )
            context = unittest.mock.Mock()
            context.abort.side_effect = TestBucketGrpc._raise_grpc_error
            with self.assertRaises(Exception, msg="project <%s>" % project) as _:
                _, _ = gcs.bucket.Bucket.init_grpc(request, context)
            context.abort.assert_called_once_with(
                grpc.StatusCode.INVALID_ARGUMENT, unittest.mock.ANY
            )

    def test_init_grpc_pap(self):
        cases = {
            "inherited": storage_pb2.Bucket.IamConfig.INHERITED,
            "enforced": storage_pb2.Bucket.IamConfig.ENFORCED,
        }
        for rest_value, grpc_value in cases.items():
            request = storage_pb2.CreateBucketRequest(
                parent="projects/test-project",
                bucket_id="test-bucket-name",
                bucket=storage_pb2.Bucket(
                    iam_config=storage_pb2.Bucket.IamConfig(
                        public_access_prevention=grpc_value
                    )
                ),
            )
            context = unittest.mock.Mock()
            bucket, _ = gcs.bucket.Bucket.init_grpc(request, context)
            bucket_rest = bucket.rest()
            self.assertEqual("storage#bucket", bucket_rest.get("kind"))
            self.assertEqual("test-bucket-name", bucket_rest.get("name"))
            self.assertEqual(
                {"publicAccessPrevention": rest_value},
                bucket_rest.get("iamConfiguration"),
            )


if __name__ == "__main__":
    unittest.main()
