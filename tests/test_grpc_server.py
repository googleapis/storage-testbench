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

"""Unit test for testbench.grpc."""

import crc32c
import json
import unittest
from google.storage.v2 import storage_pb2

import gcs
import testbench


class TestGrpc(unittest.TestCase):
    def setUp(self):
        self.db = testbench.database.Database.init()
        request = testbench.common.FakeRequest(
            args={},
            data=json.dumps({"name": "bucket-name"}),
        )
        self.bucket, _ = gcs.bucket.Bucket.init(request, None)
        self.db.insert_bucket(request, self.bucket, None)
        self.grpc = testbench.grpc_server.StorageServicer(self.db)

    @staticmethod
    def _create_block(desired_kib):
        line = "A" * 127 + "\n"
        return 1024 * int(desired_kib / len(line)) * line

    def test_read_object(self):
        media = TestGrpc._create_block(5 * 1024).encode("utf-8")
        request = testbench.common.FakeRequest(
            args={"name": "object-name"}, data=media, headers={}, environ={}
        )
        blob, _ = gcs.object.Object.init_media(request, self.bucket.metadata)
        self.db.insert_object(request, "bucket-name", blob, None)
        response = self.grpc.ReadObject(
            storage_pb2.ReadObjectRequest(
                bucket="projects/_/buckets/bucket-name", object="object-name"
            ),
            "fake-context",
        )
        chunks = [r for r in response]
        for i, c in enumerate(chunks):
            self.assertIsNotNone(c.checksummed_data, msg=i)
            self.assertEqual(
                crc32c.crc32c(c.checksummed_data.content),
                c.checksummed_data.crc32c,
                msg=i,
            )
        expected_sizes = [2 * 1024 * 1024, 2 * 1024 * 1024, 1 * 1024 * 1024]
        self.assertEqual(
            expected_sizes, [len(c.checksummed_data.content) for c in chunks]
        )
        self.assertEqual(
            crc32c.crc32c(media),
            crc32c.crc32c(b"".join([c.checksummed_data.content for c in chunks])),
        )


if __name__ == "__main__":
    unittest.main()
