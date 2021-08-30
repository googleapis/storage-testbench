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
import unittest.mock
import grpc
from google.storage.v2 import storage_pb2, storage_pb2_grpc

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
    def _create_block(desired_bytes):
        line = "A" * 127 + "\n"
        return int(desired_bytes / len(line)) * line

    def test_read_object(self):
        media = TestGrpc._create_block(5 * 1024 * 1024).encode("utf-8")
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

    def test_object_write(self):
        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM + QUANTUM / 2).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={
                    "name": "object-name",
                    "bucket": "projects/_/buckets/bucket-name",
                },
            ),
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        offset = QUANTUM
        content = media[QUANTUM : 2 * QUANTUM]
        r2 = storage_pb2.WriteObjectRequest(
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        offset = 2 * QUANTUM
        content = media[QUANTUM:]
        r3 = storage_pb2.WriteObjectRequest(
            write_offset=QUANTUM,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=True,
        )

        write = self.grpc.WriteObject([r1, r2, r3], "fake-context")
        self.assertIsNotNone(write)
        self.assertIsNotNone(write.resource)
        blob = write.resource
        self.assertEqual(blob.name, "object-name", msg=write)
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_object_write_invalid_request(self):
        context = unittest.mock.Mock()
        context.abort = unittest.mock.MagicMock()
        write = self.grpc.WriteObject([], context)
        context.abort.assert_called_once()
        self.assertIsNone(write)

    def test_object_write_incomplete(self):
        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM + QUANTUM / 2).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.WriteObjectRequest(
            write_object_spec=storage_pb2.WriteObjectSpec(
                resource={
                    "name": "object-name",
                    "bucket": "projects/_/buckets/bucket-name",
                },
            ),
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        context = unittest.mock.Mock()
        context.abort = unittest.mock.MagicMock()
        write = self.grpc.WriteObject([r1], context)
        context.abort.assert_called_once()
        self.assertIsNone(write)

    def test_resumable_write(self):
        start = self.grpc.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
            context="fake-context",
        )
        self.assertIsNotNone(start.upload_id)

        def streamer():
            media = TestGrpc._create_block(517 * 1024).encode("utf-8")
            id = start.upload_id
            step = storage_pb2.ServiceConstants.Values.MAX_READ_CHUNK_BYTES
            for offset in range(0, len(media), step):
                upload_id = id
                id = None
                end = min(offset + step, len(media))
                content = media[offset:end]
                yield storage_pb2.WriteObjectRequest(
                    upload_id=upload_id,
                    write_offset=offset,
                    checksummed_data=storage_pb2.ChecksummedData(
                        content=content, crc32c=crc32c.crc32c(content)
                    ),
                    finish_write=(end == len(media)),
                )

        write = self.grpc.WriteObject(streamer(), "fake-context")
        self.assertIsNotNone(write)
        self.assertIsNotNone(write.resource)
        blob = write.resource
        self.assertEqual(blob.name, "object-name", msg=write)
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_resumable_resumes(self):
        start = self.grpc.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
            context=unittest.mock.MagicMock(),
        )
        self.assertIsNotNone(start.upload_id)

        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM + QUANTUM / 2).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.WriteObjectRequest(
            upload_id=start.upload_id,
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )
        write = self.grpc.WriteObject([r1], "fake-context")
        self.assertIsNotNone(write)
        self.assertEqual(write.committed_size, QUANTUM)

        status = self.grpc.QueryWriteStatus(
            storage_pb2.QueryWriteStatusRequest(upload_id=start.upload_id),
            "fake-context",
        )
        self.assertEqual(status.committed_size, QUANTUM)

        offset = QUANTUM
        content = media[QUANTUM : 2 * QUANTUM]
        r2 = storage_pb2.WriteObjectRequest(
            upload_id=start.upload_id,
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        offset = 2 * QUANTUM
        content = media[2 * QUANTUM:]
        r3 = storage_pb2.WriteObjectRequest(
            write_offset=QUANTUM,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=True,
        )
        write = self.grpc.WriteObject([r2, r3], "fake-context")
        self.assertIsNotNone(write)
        blob = write.resource
        self.assertEqual(blob.name, "object-name")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

    def test_resumable_query_completed(self):
        start = self.grpc.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
            context=unittest.mock.MagicMock(),
        )
        self.assertIsNotNone(start.upload_id)

        QUANTUM = 256 * 1024
        media = TestGrpc._create_block(2 * QUANTUM).encode("utf-8")

        offset = 0
        content = media[0:QUANTUM]
        r1 = storage_pb2.WriteObjectRequest(
            upload_id=start.upload_id,
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=False,
        )

        offset = QUANTUM
        content = media[QUANTUM:]
        r2 = storage_pb2.WriteObjectRequest(
            write_offset=offset,
            checksummed_data=storage_pb2.ChecksummedData(
                content=content, crc32c=crc32c.crc32c(content)
            ),
            finish_write=True,
        )
        write = self.grpc.WriteObject([r1, r2], "fake-context")
        self.assertIsNotNone(write)
        blob = write.resource
        self.assertEqual(blob.name, "object-name")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")

        # If the application crashes before checkpointing the upload status, it
        # may query the upload status on restart.  The testbench should return
        # the full object metadata.

        status = self.grpc.QueryWriteStatus(
            storage_pb2.QueryWriteStatusRequest(upload_id=start.upload_id),
            "fake-context",
        )
        self.assertTrue(status.HasField("resource"))
        blob = status.resource
        self.assertEqual(blob.name, "object-name")
        self.assertEqual(blob.bucket, "projects/_/buckets/bucket-name")
        self.assertEqual(blob.size, len(media))

    def test_run(self):
        port, server = testbench.grpc_server.run(0, self.db)
        self.assertNotEqual(port, 0)
        self.assertIsNotNone(server)

        stub = storage_pb2_grpc.StorageStub(
            grpc.insecure_channel("localhost:%d" % port)
        )
        start = stub.StartResumableWrite(
            storage_pb2.StartResumableWriteRequest(
                write_object_spec=storage_pb2.WriteObjectSpec(
                    resource=storage_pb2.Object(
                        name="object-name", bucket="projects/_/buckets/bucket-name"
                    )
                )
            ),
        )
        self.assertIsNotNone(start.upload_id)
        self.assertNotEqual(start.upload_id, "")
        server.stop(grace=0)


if __name__ == "__main__":
    unittest.main()
